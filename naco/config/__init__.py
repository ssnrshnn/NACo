"""NACo configuration loader.

Loads `config.yaml` (path resolved via `NACO_CONFIG` env var, then a list of
default locations) and validates it through Pydantic models. Validation is
strict-but-tolerant: extra keys are ignored, but every section is type-checked.
"""
from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Pydantic models — every section of config.yaml has a typed model
# ---------------------------------------------------------------------------

class RadiusClientConfig(BaseModel):
    name: str
    address: str
    secret: str
    require_message_authenticator: bool = True  # RFC 3579 / BlastRADIUS mitigation


class RadiusConfig(BaseModel):
    enabled: bool = True
    host: str = "0.0.0.0"
    auth_port: int = 1812
    acct_port: int = 1813
    coa_port: int = 3799
    clients: list[RadiusClientConfig] = []
    default_vlan: int = 10
    guest_vlan: int = 20
    reject_vlan: int = 99
    # When true, every Access-Request must carry a valid Message-Authenticator
    # attribute (RFC 3579). Mitigates CVE-2024-3596 (BlastRADIUS).
    require_message_authenticator: bool = True
    # When a policy is created/updated/deleted, send RFC 5176
    # Disconnect-Requests to the NASes of affected active sessions so they
    # re-authenticate under the new rules immediately.
    coa_on_policy_change: bool = True


class TacacsClientConfig(BaseModel):
    address: str
    key: str


class TacacsConfig(BaseModel):
    enabled: bool = True
    host: str = "0.0.0.0"
    port: int = 49
    key: str = "tacacs_secret"
    clients: list[TacacsClientConfig] = []
    # Connection caps — see ``naco.tacacs.server.run_tacacs_server`` for the
    # rationale. Default ceilings are sized for a typical 200-switch
    # campus; raise for hyperscale deployments, lower if NACo is sharing
    # a small VM with other services.
    max_connections: int = 256
    max_connections_per_peer: int = 32


class PortalConfig(BaseModel):
    enabled: bool = True
    redirect_url: str = "http://example.com"
    session_hours: int = 8
    guest_ssid: str = "NACo-Guest"
    guest_psk: str = "guest_password"


class ProfilerConfig(BaseModel):
    enabled: bool = True
    listen_interface: str = "eth0"
    oui_db: str = "/var/lib/naco/oui.csv"


_KNOWN_ROLES = frozenset({"api", "radius", "tacacs", "profiler", "workers"})


class ServerConfig(BaseModel):
    name: str = "NACo-01"
    host: str = "0.0.0.0"
    port: int = 8080
    # Which subsystems this process runs. "all" (the default) is the classic
    # all-in-one deployment. Splitting NACo into horizontally-scalable roles:
    #   api      – HTTP UI/REST/portal/EAP hooks (always served for probes)
    #   radius   – RADIUS auth/acct/CoA UDP server
    #   tacacs   – TACACS+ server
    #   profiler – passive device profiler (needs host networking)
    #   workers  – singleton maintenance loops (guest expiry, log retention,
    #              stale-session cleanup, webhook dispatch) — run on ONE replica
    # The HTTP server, metrics collector, and policy-invalidation subscriber
    # run on every replica regardless of role.
    roles: list[str] = ["all"]
    # Shared secret used to sign the browser session cookie (HS256).
    session_secret: str = "change_me_session_secret"
    # Independent secret used to sign API JWT bearer tokens.
    api_secret: str = "change_me_api_secret"
    # Random key used to sign captive-portal CSRF cookies.
    csrf_secret: str = "change_me_csrf_secret"
    # Initial admin credentials (used only when seeding an empty database).
    admin_username: str = "admin"
    admin_password: str = "NACo@admin1"
    # API JWT lifetime (also used for the session cookie).
    token_expire_minutes: int = 60
    # Comma-separated CIDRs trusted to set X-Forwarded-For. Defaults to the
    # docker bridge + loopback so Caddy can hand us the real client IP.
    trusted_proxies: list[str] = ["127.0.0.1/32", "::1/128", "172.16.0.0/12"]
    debug: bool = False
    log_level: str = "INFO"
    log_file: str = "/var/log/naco/naco.log"

    def has_role(self, role: str) -> bool:
        """True if this process should run *role* (``all`` implies every role)."""
        wanted = {r.strip().lower() for r in self.roles if r.strip()} or {"all"}
        return "all" in wanted or role in wanted


class LogSyslogConfig(BaseModel):
    enabled: bool = False
    address: str = "/dev/log"
    facility: str = "local0"
    protocol: str = "udp"
    port: int = 514


class LogWebhookConfig(BaseModel):
    enabled: bool = False
    url: str = ""
    level: str = "WARNING"
    timeout_seconds: float = 3.0
    headers: dict[str, str] = {}
    batch_size: int = 10
    batch_interval_seconds: float = 5.0


class LogGraylogConfig(BaseModel):
    enabled: bool = False
    host: str = "127.0.0.1"
    port: int = 12201
    protocol: str = "udp"


class LogForwardingConfig(BaseModel):
    syslog: LogSyslogConfig = Field(default_factory=LogSyslogConfig)
    webhook: LogWebhookConfig = Field(default_factory=LogWebhookConfig)
    graylog: LogGraylogConfig = Field(default_factory=LogGraylogConfig)


class LdapConfig(BaseModel):
    enabled: bool = False
    # Single server (legacy). Ignored when `servers` is set.
    server: str = "ldap://dc.example.com"
    # Failover pool: tried in order, first reachable server wins. Each entry
    # is a URI ("ldap://dc1.example.com" or "ldaps://dc1.example.com:636").
    servers: list[str] = []
    port: int = 389
    use_ssl: bool = False
    # Upgrade a plain connection with StartTLS before binding (mutually
    # exclusive with use_ssl/ldaps).
    start_tls: bool = False
    # Seconds before an unreachable server is skipped for the next in pool.
    connect_timeout: int = 5
    bind_dn: str = ""
    bind_password: str = ""
    base_dn: str = ""
    user_filter: str = "(sAMAccountName={username})"
    group_attribute: str = "memberOf"
    # Resolve nested group membership via the AD matching rule
    # LDAP_MATCHING_RULE_IN_CHAIN (memberOf only lists direct groups).
    nested_groups: bool = False
    # Map of group DN → NACo group name. Order sets provisioning priority:
    # the first matching entry becomes the user's group. Matching is
    # case-insensitive (DNs are).
    group_map: dict[str, str] = {}


class EventWebhookTarget(BaseModel):
    url: str
    events: list[str] = []
    headers: dict[str, str] = {}
    timeout: float = 5.0


class SecurityConfig(BaseModel):
    """Knobs that don't fit anywhere else but materially affect security.

    * ``webhook_allowlist`` — CIDRs that ``naco.core.netutils`` should consider
      safe to dial out to, overriding the default RFC 1918 / loopback /
      cloud-metadata denylist. Use for legitimate intranet integrations
      (e.g. an internal SIEM at ``10.42.0.50``). **Empty by default.**
    """
    webhook_allowlist: list[str] = []


class CacheConfig(BaseModel):
    # Redis URL used for rate limiting, session revocation, and caches.
    # Falls back to an in-memory implementation when unreachable (dev only).
    url: str = "redis://redis:6379/0"


class DatabaseConfig(BaseModel):
    # Default points at the docker-compose `postgres` service. For local
    # development without containers, set `database.url` to
    # `sqlite+aiosqlite:///./naco-dev.db`.
    url: str = "postgresql+asyncpg://naco:naco@postgres:5432/naco"

    # Connection-pool tuning (PostgreSQL only; ignored for SQLite). When
    # running N API replicas, keep pool_size + max_overflow small enough that
    # N × (pool_size + max_overflow) stays under Postgres `max_connections`,
    # or front the database with PgBouncer (see `pgbouncer` below).
    pool_size: int = 10
    max_overflow: int = 20
    pool_timeout: int = 30       # seconds to wait for a free connection
    pool_recycle: int = 1800     # recycle connections older than this (seconds)
    pool_pre_ping: bool = True   # validate connections before use

    # Set true when connecting through PgBouncer (or another server-side
    # transaction pooler). This switches SQLAlchemy to NullPool — PgBouncer
    # owns the pooling — and disables asyncpg's prepared-statement cache with
    # unique statement names, which is required for transaction-pooling mode.
    pgbouncer: bool = False


class EapConfig(BaseModel):
    """Pre-shared bearer token used by FreeRADIUS to call /api/v1/eap/*."""
    enabled: bool = False
    bearer_token: str = ""


class OidcConfig(BaseModel):
    """OIDC single sign-on for the admin UI (Keycloak / Authentik / Okta …).

    Standard authorization-code flow. NACo discovers endpoints from
    ``issuer``/.well-known/openid-configuration and verifies ID tokens
    against the provider's JWKS. Local username/password login stays
    available as a fallback unless ``local_login`` is false.
    """
    enabled: bool = False
    issuer: str = ""                # e.g. https://keycloak.example.com/realms/acme
    client_id: str = ""
    client_secret: str = ""
    scopes: list[str] = ["openid", "profile", "email"]
    # Claim carrying the username for the NACo admin account.
    username_claim: str = "preferred_username"
    # Claim (string or list) inspected for role mapping.
    role_claim: str = "groups"
    # Map of claim value → NACo role (SUPERUSER / OPERATOR / VIEWER).
    role_map: dict[str, str] = {}
    # Role granted when nothing in role_map matches. Empty string = deny.
    default_role: str = ""
    # Keep the local login form usable alongside SSO.
    local_login: bool = True


class OtelConfig(BaseModel):
    """OpenTelemetry tracing (optional — needs the `naco[otel]` extra).

    Spans cover HTTP requests (FastAPI), SQL statements (SQLAlchemy) and
    the RADIUS/TACACS+ authentication handlers. Export is OTLP/HTTP.
    """
    enabled: bool = False
    # OTLP/HTTP collector endpoint, e.g. "http://otel-collector:4318".
    endpoint: str = ""
    # Head sampling ratio, 0.0–1.0. 1.0 traces everything.
    sample_ratio: float = 1.0


class AppConfig(BaseModel):
    server: ServerConfig = Field(default_factory=ServerConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    cache: CacheConfig = Field(default_factory=CacheConfig)
    radius: RadiusConfig = Field(default_factory=RadiusConfig)
    tacacs: TacacsConfig = Field(default_factory=TacacsConfig)
    portal: PortalConfig = Field(default_factory=PortalConfig)
    profiler: ProfilerConfig = Field(default_factory=ProfilerConfig)
    eap: EapConfig = Field(default_factory=EapConfig)
    otel: OtelConfig = Field(default_factory=OtelConfig)
    oidc: OidcConfig = Field(default_factory=OidcConfig)
    log_forwarding: LogForwardingConfig = Field(default_factory=LogForwardingConfig)
    ldap: LdapConfig = Field(default_factory=LdapConfig)
    event_webhooks: list[EventWebhookTarget] = []
    security: SecurityConfig = Field(default_factory=SecurityConfig)


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

_DEFAULT_PATHS = [
    Path("config.yaml"),
    Path("config/config.yaml"),
    Path("/etc/naco/config.yaml"),
]


def _load_yaml(path: Path) -> dict[str, Any]:
    with path.open() as f:
        return yaml.safe_load(f) or {}


@lru_cache(maxsize=1)
def get_config() -> AppConfig:
    """Load config from the first found YAML file, then env overrides."""
    env_path = os.environ.get("NACO_CONFIG")
    data: dict[str, Any] = {}

    if env_path:
        data = _load_yaml(Path(env_path))
    else:
        for p in _DEFAULT_PATHS:
            if p.exists():
                data = _load_yaml(p)
                break

    # Allow `server.session_secret`/`api_secret`/`csrf_secret` to come from env.
    server = data.setdefault("server", {})
    for env_var, key in (
        ("NACO_SESSION_SECRET", "session_secret"),
        ("NACO_API_SECRET", "api_secret"),
        ("NACO_CSRF_SECRET", "csrf_secret"),
        ("NACO_ADMIN_PASSWORD", "admin_password"),
        ("NACO_HOST", "host"),
        ("NACO_PORT", "port"),
    ):
        val = os.environ.get(env_var)
        if val:
            server[key] = int(val) if key == "port" else val

    # Role selection: NACO_ROLES="api,radius" (comma-separated). Blank/unset
    # keeps whatever the YAML says (default: all-in-one).
    roles_env = os.environ.get("NACO_ROLES")
    if roles_env:
        parsed = [r.strip() for r in roles_env.split(",") if r.strip()]
        if parsed:
            server["roles"] = parsed

    db_url = os.environ.get("NACO_DB_URL")
    if db_url:
        data.setdefault("database", {})["url"] = db_url

    # Connection-pool tuning via env (handy for per-replica sizing in k8s).
    for env_var, key in (
        ("NACO_DB_POOL_SIZE", "pool_size"),
        ("NACO_DB_MAX_OVERFLOW", "max_overflow"),
        ("NACO_DB_POOL_TIMEOUT", "pool_timeout"),
        ("NACO_DB_POOL_RECYCLE", "pool_recycle"),
    ):
        val = os.environ.get(env_var)
        if val:
            data.setdefault("database", {})[key] = int(val)

    pgbouncer = os.environ.get("NACO_DB_PGBOUNCER")
    if pgbouncer:
        data.setdefault("database", {})["pgbouncer"] = pgbouncer.lower() in (
            "1", "true", "yes", "on"
        )

    cache_url = os.environ.get("NACO_REDIS_URL")
    if cache_url:
        data.setdefault("cache", {})["url"] = cache_url

    # An OTLP endpoint in the environment implies a collector is deployed —
    # enable tracing unless YAML says otherwise.
    otel_endpoint = os.environ.get("NACO_OTEL_ENDPOINT")
    if otel_endpoint:
        otel = data.setdefault("otel", {})
        otel["endpoint"] = otel_endpoint
        otel.setdefault("enabled", True)

    # A bearer token in the environment implies the FreeRADIUS sidecar is in
    # play — enable the /api/v1/eap/* endpoints unless YAML says otherwise.
    eap_token = os.environ.get("NACO_EAP_BEARER_TOKEN")
    if eap_token:
        eap = data.setdefault("eap", {})
        eap["bearer_token"] = eap_token
        eap.setdefault("enabled", True)

    return AppConfig.model_validate(data)


# ---------------------------------------------------------------------------
# Production-secret validation
# ---------------------------------------------------------------------------

# Known placeholder values from the model defaults / .env.example. Any of
# these in a non-debug deployment means the operator skipped quickstart.sh
# and never rotated the secret.
_PLACEHOLDER_VALUES = {
    "change_me_session_secret",
    "change_me_api_secret",
    "change_me_csrf_secret",
    "NACo@admin1",
    "tacacs_secret",
    "guest_password",
}

# Prefixes used by the shipped config.yaml / .env.example placeholders. Matched
# case-insensitively so "CHANGE_ME_…", "change_me_…", and "REPLACE_ME_…" are all
# caught — a real deployment must rotate every one of these.
_PLACEHOLDER_PREFIXES = ("replace_me", "change_me")


def _is_placeholder(value: str) -> bool:
    if value in _PLACEHOLDER_VALUES:
        return True
    return value.lower().startswith(_PLACEHOLDER_PREFIXES)


def check_production_secrets(cfg: AppConfig) -> list[str]:
    """Return a list of placeholder-secret problems (empty = all good).

    Callers decide severity: ``naco.main`` refuses to start when
    ``server.debug`` is false; ``nacoctl check-config`` prints warnings.
    """
    problems: list[str] = []
    for name, value in (
        ("server.session_secret", cfg.server.session_secret),
        ("server.api_secret", cfg.server.api_secret),
        ("server.csrf_secret", cfg.server.csrf_secret),
        ("server.admin_password", cfg.server.admin_password),
    ):
        if _is_placeholder(value):
            problems.append(f"{name} is still the placeholder default")
    if cfg.tacacs.enabled and _is_placeholder(cfg.tacacs.key):
        problems.append("tacacs.key is still the placeholder default")
    for tac_client in cfg.tacacs.clients if cfg.tacacs.enabled else []:
        if _is_placeholder(tac_client.key):
            problems.append(f"tacacs.clients[{tac_client.address}].key is a placeholder")
    for rad_client in cfg.radius.clients if cfg.radius.enabled else []:
        if _is_placeholder(rad_client.secret):
            problems.append(f"radius.clients[{rad_client.name}].secret is a placeholder")
    return problems


def check_weak_secrets(cfg: AppConfig) -> list[str]:
    """Return non-fatal secret-hygiene warnings (empty = all good).

    Unlike :func:`check_production_secrets`, these do **not** block startup: a
    placeholder here weakens a single feature (e.g. the guest Wi-Fi PSK) rather
    than compromising the integrity of the whole NAC, so the service still
    boots but the operator is warned loudly.
    """
    warnings: list[str] = []
    if cfg.portal.enabled and _is_placeholder(cfg.portal.guest_psk):
        warnings.append("portal.guest_psk is still the placeholder default")
    return warnings
