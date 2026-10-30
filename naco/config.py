"""Configuration and secrets.

Two sources, deliberately kept apart:

* ``config.yaml`` — behaviour only (timezone, limits, LDAP servers, …). It never
  holds a secret, so it can be mounted read-only and committed to an ops repo.
  Unknown keys are rejected: a typo must fail loudly, not be ignored.
* the environment — secrets only. Each one may also come from a file named by
  ``<NAME>_FILE`` (Docker secrets), which takes precedence.

Startup refuses missing, short, or placeholder secrets. ``NACO_DEV=1`` fills in
fixed development values instead, with a loud warning; it never relaxes
validation of values that *are* supplied.
"""
from __future__ import annotations

import base64
import binascii
import contextlib
import hashlib
import ipaddress
import logging
import os
from collections.abc import Mapping
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

log = logging.getLogger(__name__)

DEFAULT_CONFIG_PATH = "/etc/naco/config.yaml"


class ConfigError(RuntimeError):
    """Invalid configuration or secrets — the process must not start."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


# ---------------------------------------------------------------------------
# config.yaml schema
# ---------------------------------------------------------------------------

class ServerConfig(_Strict):
    name: str = "NACo"
    timezone: str = "UTC"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    log_format: Literal["text", "json"] = "text"
    host: str = "0.0.0.0"
    http_port: int = Field(8080, ge=1, le=65535)
    internal_port: int = Field(8081, ge=1, le=65535)
    # Peers allowed to set X-Forwarded-For (the Caddy container). Plain IPs are
    # normalised to /32 or /128 networks.
    trusted_proxies: list[str] = []

    @field_validator("timezone")
    @classmethod
    def _valid_timezone(cls, v: str) -> str:
        try:
            ZoneInfo(v)
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise ValueError(f"unknown timezone {v!r}") from exc
        return v

    @field_validator("trusted_proxies")
    @classmethod
    def _valid_networks(cls, v: list[str]) -> list[str]:
        out = []
        for item in v:
            try:
                out.append(str(ipaddress.ip_network(item.strip(), strict=False)))
            except ValueError as exc:
                raise ValueError(f"invalid address or network {item!r}") from exc
        return out


class DatabaseConfig(_Strict):
    path: str = "/var/lib/naco/naco.db"


class SecurityConfig(_Strict):
    require_totp: bool = True
    session_idle_minutes: int = Field(30, ge=5, le=24 * 60)
    session_max_hours: int = Field(12, ge=1, le=7 * 24)
    login_max_attempts: int = Field(10, ge=3, le=1000)
    login_window_seconds: int = Field(300, ge=30, le=86400)


class RadiusConfig(_Strict):
    coa_timeout_seconds: float = Field(2.0, gt=0, le=30)
    coa_retries: int = Field(3, ge=1, le=10)
    stale_session_hours: int = Field(24, ge=1, le=24 * 30)
    nas_secret_min_length: int = Field(16, ge=8, le=128)


class TacacsConfig(_Strict):
    enabled: bool = True
    port: int = Field(4949, ge=1, le=65535)
    max_connections: int = Field(256, ge=1, le=10000)
    max_connections_per_client: int = Field(32, ge=1, le=1000)
    idle_timeout_seconds: int = Field(30, ge=5, le=3600)


class PortalConfig(_Strict):
    enabled: bool = True
    organization: str = "NACo"
    terms: str = (
        "By using this network you agree to use it lawfully and responsibly. "
        "Activity may be logged."
    )
    # Optional shared code guests must enter; empty = click-through.
    access_code: str = ""
    session_hours: int = Field(8, ge=1, le=24 * 30)
    # How recently the guest's RADIUS session must have been updated for the
    # portal to trust its Framed-IP → MAC mapping.
    match_window_minutes: int = Field(15, ge=1, le=24 * 60)


class LdapGroupMapping(_Strict):
    ldap_group: str
    group: str


class LdapConfig(_Strict):
    enabled: bool = False
    servers: list[str] = []
    ca_file: str = ""
    start_tls: bool = False
    allow_insecure: bool = False
    bind_dn: str = ""
    base_dn: str = ""
    user_filter: str = "(sAMAccountName={username})"
    group_attribute: str = "memberOf"
    nested_groups: bool = False
    # Ordered: the first mapping whose LDAP group the user belongs to wins.
    group_map: list[LdapGroupMapping] = []
    timeout_seconds: int = Field(5, ge=1, le=60)

    @field_validator("user_filter")
    @classmethod
    def _has_placeholder(cls, v: str) -> str:
        if "{username}" not in v:
            raise ValueError("user_filter must contain the {username} placeholder")
        return v

    @model_validator(mode="after")
    def _transport(self) -> LdapConfig:
        if self.enabled and not self.servers:
            raise ValueError("ldap.enabled requires at least one entry in servers")
        for uri in self.servers:
            scheme = uri.split("://", 1)[0].lower() if "://" in uri else ""
            if scheme not in ("ldap", "ldaps"):
                raise ValueError(f"{uri!r}: servers must be ldap:// or ldaps:// URIs")
            if scheme == "ldaps" and self.start_tls:
                raise ValueError(f"{uri!r}: start_tls cannot be combined with ldaps://")
            if scheme == "ldap" and not self.start_tls and not self.allow_insecure:
                raise ValueError(
                    f"{uri!r} sends passwords in clear text — use ldaps://, start_tls: true, "
                    "or set allow_insecure: true deliberately"
                )
        return self


class SyslogConfig(_Strict):
    enabled: bool = False
    host: str = ""
    port: int = Field(514, ge=1, le=65535)
    protocol: Literal["udp", "tcp"] = "udp"
    facility: str = "local0"

    @model_validator(mode="after")
    def _enabled_needs_host(self) -> SyslogConfig:
        if self.enabled and not self.host:
            raise ValueError("syslog.enabled requires a host")
        return self


class RetentionConfig(_Strict):
    auth_log_days: int = Field(90, ge=1, le=3650)
    tacacs_log_days: int = Field(90, ge=1, le=3650)
    audit_log_days: int = Field(365, ge=1, le=3650)


class AppConfig(_Strict):
    server: ServerConfig = Field(default_factory=ServerConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    radius: RadiusConfig = Field(default_factory=RadiusConfig)
    tacacs: TacacsConfig = Field(default_factory=TacacsConfig)
    portal: PortalConfig = Field(default_factory=PortalConfig)
    ldap: LdapConfig = Field(default_factory=LdapConfig)
    syslog: SyslogConfig = Field(default_factory=SyslogConfig)
    retention: RetentionConfig = Field(default_factory=RetentionConfig)


def _format_validation_error(exc: ValidationError) -> str:
    parts = []
    for err in exc.errors():
        loc = ".".join(str(p) for p in err["loc"])
        parts.append(f"{loc}: {err['msg']}")
    return "; ".join(parts)


def load_config(path: str | None = None, env: Mapping[str, str] | None = None) -> AppConfig:
    """Load ``config.yaml`` (if any) and apply the non-secret env overrides."""
    env = os.environ if env is None else env
    explicit = path or env.get("NACO_CONFIG")
    data: dict[str, Any] = {}
    if explicit:
        p = Path(explicit)
        if not p.is_file():
            raise ConfigError(f"config file not found: {explicit}")
        data = _read_yaml(p)
    elif Path(DEFAULT_CONFIG_PATH).is_file():
        data = _read_yaml(Path(DEFAULT_CONFIG_PATH))

    if db_path := env.get("NACO_DATABASE_PATH"):
        data.setdefault("database", {})["path"] = db_path
    if proxies := env.get("NACO_TRUSTED_PROXIES"):
        data.setdefault("server", {})["trusted_proxies"] = [
            p.strip() for p in proxies.split(",") if p.strip()
        ]

    try:
        return AppConfig.model_validate(data)
    except ValidationError as exc:
        raise ConfigError(f"invalid configuration — {_format_validation_error(exc)}") from exc


def _read_yaml(path: Path) -> dict[str, Any]:
    try:
        loaded = yaml.safe_load(path.read_text()) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc
    if not isinstance(loaded, dict):
        raise ConfigError(f"{path}: top level must be a mapping")
    return loaded


# ---------------------------------------------------------------------------
# Secrets (environment only)
# ---------------------------------------------------------------------------

class Secrets(BaseModel):
    model_config = ConfigDict(frozen=True)

    master_key: bytes
    internal_token: str
    ldap_bind_password: str = ""
    admin_password: str | None = None


_PLACEHOLDER_PREFIXES = ("replace_me", "change_me")
_DEV_MASTER_KEY = hashlib.sha256(b"naco-development-master-key").digest()
_DEV_INTERNAL_TOKEN = "naco-development-internal-token-not-for-production"  # noqa: S105 — NACO_DEV only


def _read_secret(env: Mapping[str, str], name: str) -> str | None:
    file_var = f"{name}_FILE"
    if file_path := env.get(file_var):
        try:
            return Path(file_path).read_text().strip()
        except OSError as exc:
            raise ConfigError(f"{file_var}: cannot read {file_path}: {exc}") from exc
    value = env.get(name)
    return value.strip() if value else None


def _reject_placeholder(name: str, value: str) -> None:
    if value.lower().startswith(_PLACEHOLDER_PREFIXES):
        raise ConfigError(f"{name} is still a placeholder — run ./quickstart.sh or set a real value")


def parse_master_key(material: str) -> bytes:
    """Decode a 32-byte key given as base64 or hex."""
    material = material.strip()
    candidates: list[bytes] = []
    for decode in (base64.b64decode, base64.urlsafe_b64decode, bytes.fromhex):
        with contextlib.suppress(binascii.Error, ValueError):
            candidates.append(decode(material))
    for key in candidates:
        if len(key) == 32:
            return key
    raise ConfigError("NACO_MASTER_KEY must be 32 bytes, base64 or hex encoded (openssl rand -base64 32)")


def load_secrets(env: Mapping[str, str] | None = None, *, dev: bool | None = None) -> Secrets:
    env = os.environ if env is None else env
    if dev is None:
        dev = env.get("NACO_DEV", "").lower() in ("1", "true", "yes", "on")

    raw_key = _read_secret(env, "NACO_MASTER_KEY")
    if raw_key:
        _reject_placeholder("NACO_MASTER_KEY", raw_key)
        master_key = parse_master_key(raw_key)
    elif dev:
        log.warning("NACO_DEV: using a fixed development master key — never do this in production")
        master_key = _DEV_MASTER_KEY
    else:
        raise ConfigError("NACO_MASTER_KEY is not set")

    token = _read_secret(env, "NACO_INTERNAL_TOKEN")
    if token:
        _reject_placeholder("NACO_INTERNAL_TOKEN", token)
        if len(token) < 32:
            raise ConfigError("NACO_INTERNAL_TOKEN must be at least 32 characters")
    elif dev:
        log.warning("NACO_DEV: using a fixed development internal token — never do this in production")
        token = _DEV_INTERNAL_TOKEN
    else:
        raise ConfigError("NACO_INTERNAL_TOKEN is not set")

    ldap_pw = _read_secret(env, "NACO_LDAP_BIND_PASSWORD") or ""
    if ldap_pw:
        _reject_placeholder("NACO_LDAP_BIND_PASSWORD", ldap_pw)
    admin_pw = _read_secret(env, "NACO_ADMIN_PASSWORD")
    if admin_pw:
        _reject_placeholder("NACO_ADMIN_PASSWORD", admin_pw)

    return Secrets(
        master_key=master_key,
        internal_token=token,
        ldap_bind_password=ldap_pw,
        admin_password=admin_pw or None,
    )


# ---------------------------------------------------------------------------
# Process-wide accessors
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def get_config() -> AppConfig:
    return load_config()


@lru_cache(maxsize=1)
def get_secrets() -> Secrets:
    return load_secrets()


def reset_caches() -> None:
    """Forget cached config/secrets (tests, `nacoctl` subcommands)."""
    get_config.cache_clear()
    get_secrets.cache_clear()
