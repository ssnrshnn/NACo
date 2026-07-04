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


class ServerConfig(BaseModel):
    name: str = "NACo-01"
    host: str = "0.0.0.0"
    port: int = 8080
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
    server: str = "ldap://dc.example.com"
    port: int = 389
    use_ssl: bool = False
    bind_dn: str = ""
    bind_password: str = ""
    base_dn: str = ""
    user_filter: str = "(sAMAccountName={username})"
    group_attribute: str = "memberOf"
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


class EapConfig(BaseModel):
    """Pre-shared bearer token used by FreeRADIUS to call /api/v1/eap/*."""
    enabled: bool = False
    bearer_token: str = ""


class AppConfig(BaseModel):
    server: ServerConfig = Field(default_factory=ServerConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    cache: CacheConfig = Field(default_factory=CacheConfig)
    radius: RadiusConfig = Field(default_factory=RadiusConfig)
    tacacs: TacacsConfig = Field(default_factory=TacacsConfig)
    portal: PortalConfig = Field(default_factory=PortalConfig)
    profiler: ProfilerConfig = Field(default_factory=ProfilerConfig)
    eap: EapConfig = Field(default_factory=EapConfig)
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

    db_url = os.environ.get("NACO_DB_URL")
    if db_url:
        data.setdefault("database", {})["url"] = db_url

    cache_url = os.environ.get("NACO_REDIS_URL")
    if cache_url:
        data.setdefault("cache", {})["url"] = cache_url

    # A bearer token in the environment implies the FreeRADIUS sidecar is in
    # play — enable the /api/v1/eap/* endpoints unless YAML says otherwise.
    eap_token = os.environ.get("NACO_EAP_BEARER_TOKEN")
    if eap_token:
        eap = data.setdefault("eap", {})
        eap["bearer_token"] = eap_token
        eap.setdefault("enabled", True)

    return AppConfig.model_validate(data)
