"""
NACo Database Models
=======================
Full SQLAlchemy ORM models covering every entity in the system.
"""
from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from naco.db.database import Base
from naco.db.types import EncryptedString


def _utcnow() -> datetime:
    return datetime.now(UTC)


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class AuthResult(StrEnum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    CHALLENGE = "CHALLENGE"


class AuthMethod(StrEnum):
    PAP       = "PAP"
    CHAP      = "CHAP"
    PEAP      = "PEAP"
    EAP_TLS   = "EAP_TLS"
    MAB       = "MAB"
    WEB_AUTH  = "WEB_AUTH"
    PAP_CHAP  = "PAP/CHAP"


class PolicyAction(StrEnum):
    PERMIT = "PERMIT"
    DENY   = "DENY"
    GUEST  = "GUEST"


class TacacsPacketType(StrEnum):
    AUTHEN = "AUTHEN"
    AUTHOR = "AUTHOR"
    ACCTING = "ACCTING"


class AdminRole(StrEnum):
    """Role-based access control for admin accounts.

    Roles are ordered: a route that requires ``OPERATOR`` is satisfied by an
    ``OPERATOR`` or ``SUPERUSER`` but not by a ``VIEWER``. See
    ``naco.api.auth.require_role`` for the dependency that enforces this.

    * ``SUPERUSER`` – everything: manage admins, rotate secrets, edit YAML
      settings, delete policies/NAS clients.
    * ``OPERATOR``  – day-to-day: CRUD users/groups/devices/policies/sessions,
      revoke admin TOTP, view audit logs. *Cannot* create or delete admins,
      change secrets, or save the YAML config.
    * ``VIEWER``    – read-only: GET endpoints, log/inventory pages, no
      mutating actions at all.
    """
    SUPERUSER = "SUPERUSER"
    OPERATOR  = "OPERATOR"
    VIEWER    = "VIEWER"


# ---------------------------------------------------------------------------
# Users & Groups
# ---------------------------------------------------------------------------

class Group(Base):
    __tablename__ = "groups"

    id: Mapped[int]           = mapped_column(Integer, primary_key=True)
    name: Mapped[str]         = mapped_column(String(64), unique=True, nullable=False)
    description: Mapped[str]  = mapped_column(String(255), default="")
    command_set_id: Mapped[int | None] = mapped_column(
        ForeignKey("command_sets.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, server_default=func.now()
    )

    users: Mapped[list[User]] = relationship("User", back_populates="group")
    policies: Mapped[list[Policy]] = relationship("Policy", back_populates="group")
    command_set: Mapped[CommandSet | None] = relationship("CommandSet", back_populates="groups")


class User(Base):
    __tablename__ = "users"

    id: Mapped[int]            = mapped_column(Integer, primary_key=True)
    username: Mapped[str]      = mapped_column(String(64), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    email: Mapped[str]         = mapped_column(String(128), default="")
    full_name: Mapped[str]     = mapped_column(String(128), default="")
    group_id: Mapped[int | None] = mapped_column(ForeignKey("groups.id", ondelete="SET NULL"), nullable=True)
    enabled: Mapped[bool]      = mapped_column(Boolean, default=True)
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, server_default=func.now()
    )
    last_login: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow,
        server_default=func.now(), nullable=True,
    )

    group: Mapped[Group | None] = relationship("Group", back_populates="users")
    auth_logs: Mapped[list[AuthLog]] = relationship("AuthLog", back_populates="user")


# ---------------------------------------------------------------------------
# Devices / Inventory
# ---------------------------------------------------------------------------

class Device(Base):
    __tablename__ = "devices"

    id: Mapped[int]             = mapped_column(Integer, primary_key=True)
    mac_address: Mapped[str]    = mapped_column(String(17), unique=True, nullable=False, index=True)
    ip_address: Mapped[str]     = mapped_column(String(45), default="")
    hostname: Mapped[str]       = mapped_column(String(128), default="")
    vendor: Mapped[str]         = mapped_column(String(128), default="")  # OUI lookup
    device_type: Mapped[str]    = mapped_column(String(64), default="unknown")
    os_type: Mapped[str]        = mapped_column(String(64), default="unknown")
    user_agent: Mapped[str]     = mapped_column(String(512), default="")
    dhcp_fingerprint: Mapped[str] = mapped_column(String(256), default="")
    authorized: Mapped[bool]    = mapped_column(Boolean, default=False, nullable=False)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, server_default=func.now()
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow,
        server_default=func.now(),
    )
    notes: Mapped[str]          = mapped_column(Text, default="")

    auth_logs: Mapped[list[AuthLog]] = relationship("AuthLog", back_populates="device")


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------

class Policy(Base):
    """
    A policy rule evaluated by the policy engine.

    conditions (JSON text):
        [
          {"type": "group",       "op": "in",         "value": ["employees"]},
          {"type": "mac",         "op": "startswith",  "value": "aa:bb:cc"},
          {"type": "time",        "op": "between",     "start": "08:00", "end": "18:00"},
          {"type": "device_type", "op": "in",          "value": ["laptop"]},
          {"type": "username",    "op": "equals",      "value": "alice"}
        ]

    All conditions in a rule are AND-ed together.
    Rules are evaluated in ascending priority order; first match wins.
    """
    __tablename__ = "policies"

    id: Mapped[int]           = mapped_column(Integer, primary_key=True)
    name: Mapped[str]         = mapped_column(String(128), unique=True, nullable=False)
    description: Mapped[str]  = mapped_column(String(512), default="")
    priority: Mapped[int]     = mapped_column(Integer, default=100)
    conditions: Mapped[list]  = mapped_column(JSON, default=list)  # JSONB on Postgres, JSON-as-text on SQLite
    action: Mapped[str]       = mapped_column(
        Enum(PolicyAction), default=PolicyAction.PERMIT, nullable=False
    )
    vlan: Mapped[int | None]  = mapped_column(Integer, nullable=True)
    # Extra RADIUS attributes for the Access-Accept, e.g.
    # {"Aruba-User-Role": "employee", "Cisco-AVPair": ["url-redirect=..."]}.
    # Names must exist in naco/radius/dictionary; values are str/int or lists.
    reply_attributes: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    group_id: Mapped[int | None] = mapped_column(ForeignKey("groups.id", ondelete="SET NULL"), nullable=True)
    enabled: Mapped[bool]     = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, server_default=func.now()
    )
    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow,
        server_default=func.now(), nullable=True,
    )

    group: Mapped[Group | None] = relationship("Group", back_populates="policies")

    __table_args__ = (
        CheckConstraint("vlan IS NULL OR (vlan >= 1 AND vlan <= 4094)", name="ck_policy_vlan_range"),
    )


# ---------------------------------------------------------------------------
# Authentication Logs
# ---------------------------------------------------------------------------

class AuthLog(Base):
    __tablename__ = "auth_logs"

    # Non-persisted UI tag set when auth/tacacs rows are merged for the logs
    # view. Unannotated on purpose so SQLAlchemy does not treat it as a column.
    _source = ""

    id: Mapped[int]             = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, server_default=func.now(), index=True
    )
    username: Mapped[str]       = mapped_column(String(64), default="", index=True)
    mac_address: Mapped[str]    = mapped_column(String(17), default="", index=True)
    ip_address: Mapped[str]     = mapped_column(String(45), default="")
    nas_ip: Mapped[str]         = mapped_column(String(45), default="")
    nas_port: Mapped[str]       = mapped_column(String(64), default="")
    auth_method: Mapped[str]    = mapped_column(Enum(AuthMethod), default=AuthMethod.PAP)
    result: Mapped[str]         = mapped_column(Enum(AuthResult), nullable=False)
    reason: Mapped[str]         = mapped_column(String(255), default="")
    policy_name: Mapped[str]    = mapped_column(String(128), default="")
    vlan: Mapped[int | None]    = mapped_column(Integer, nullable=True)
    session_id: Mapped[str]     = mapped_column(String(64), default="")

    user_id: Mapped[int | None]   = mapped_column(ForeignKey("users.id"), nullable=True)
    device_id: Mapped[int | None] = mapped_column(ForeignKey("devices.id"), nullable=True)

    user:   Mapped[User | None]   = relationship("User",   back_populates="auth_logs")
    device: Mapped[Device | None] = relationship("Device", back_populates="auth_logs")


# ---------------------------------------------------------------------------
# Active Sessions (RADIUS Accounting)
# ---------------------------------------------------------------------------

class ActiveSession(Base):
    __tablename__ = "active_sessions"

    id: Mapped[int]              = mapped_column(Integer, primary_key=True)
    session_id: Mapped[str]      = mapped_column(String(64), unique=True, nullable=False, index=True)
    username: Mapped[str]        = mapped_column(String(64), nullable=False)
    mac_address: Mapped[str]     = mapped_column(String(17), default="")
    ip_address: Mapped[str]      = mapped_column(String(45), default="")
    nas_ip: Mapped[str]          = mapped_column(String(45), default="")
    nas_port: Mapped[str]        = mapped_column(String(64), default="")
    vlan: Mapped[int | None]     = mapped_column(Integer, nullable=True)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow,
        server_default=func.now(),
    )
    # BigInteger: RFC 2869 Gigawords roll 32-bit octet counters past 4 GiB.
    bytes_in: Mapped[int]        = mapped_column(BigInteger, default=0)
    bytes_out: Mapped[int]       = mapped_column(BigInteger, default=0)


# ---------------------------------------------------------------------------
# Guest / Captive Portal Sessions
# ---------------------------------------------------------------------------

class GuestSession(Base):
    __tablename__ = "guest_sessions"

    id: Mapped[int]             = mapped_column(Integer, primary_key=True)
    token: Mapped[str]          = mapped_column(String(64), unique=True, nullable=False, index=True)
    email: Mapped[str]          = mapped_column(String(128), default="")
    full_name: Mapped[str]      = mapped_column(String(128), default="")
    mac_address: Mapped[str]    = mapped_column(String(17), default="", index=True)
    ip_address: Mapped[str]     = mapped_column(String(45), default="")
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, server_default=func.now()
    )
    active: Mapped[bool]        = mapped_column(Boolean, default=True)


# ---------------------------------------------------------------------------
# TACACS+ Logs
# ---------------------------------------------------------------------------

class TacacsLog(Base):
    __tablename__ = "tacacs_logs"

    # Non-persisted UI tag (see AuthLog._source).
    _source = ""

    id: Mapped[int]              = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[datetime]  = mapped_column(
        DateTime(timezone=True), default=_utcnow, server_default=func.now(), index=True
    )
    packet_type: Mapped[str]     = mapped_column(Enum(TacacsPacketType), nullable=False)
    username: Mapped[str]        = mapped_column(String(64), default="", index=True)
    remote_ip: Mapped[str]       = mapped_column(String(45), default="")
    nas_port: Mapped[str]        = mapped_column(String(64), default="")
    privilege_level: Mapped[int] = mapped_column(Integer, default=1)
    command: Mapped[str]         = mapped_column(Text, default="")
    result: Mapped[str]          = mapped_column(String(16), default="PASS")
    reason: Mapped[str]          = mapped_column(String(255), default="")


# ---------------------------------------------------------------------------
# Admin Users (Web UI / REST API login — separate from network users)
# ---------------------------------------------------------------------------

class AdminUser(Base):
    __tablename__ = "admin_users"

    # Non-persisted marker: set on transient principals minted from a static
    # API token so token-management routes can refuse token-minted callers.
    # Unannotated on purpose so SQLAlchemy does not map it as a column.
    via_api_token = False

    id: Mapped[int]             = mapped_column(Integer, primary_key=True)
    username: Mapped[str]       = mapped_column(String(64), unique=True, nullable=False)
    password_hash: Mapped[str]  = mapped_column(String(128), nullable=False)
    email: Mapped[str]          = mapped_column(String(128), default="")
    # ``is_superuser`` is kept for back-compat (older alembic baselines and the
    # bootstrap seed flag this on the first admin) but is no longer the
    # source of truth — ``role`` is. ``is_superuser`` is True iff
    # ``role == AdminRole.SUPERUSER``; we keep both in sync on writes.
    is_superuser: Mapped[bool]  = mapped_column(Boolean, default=False)
    role: Mapped[str]           = mapped_column(
        Enum(AdminRole), default=AdminRole.OPERATOR, nullable=False,
        server_default=AdminRole.OPERATOR.value,
    )
    enabled: Mapped[bool]       = mapped_column(Boolean, default=True)
    totp_secret: Mapped[str | None] = mapped_column(
        EncryptedString(512), nullable=True, default=None,
    )
    # Provisioning secret before the user confirms the first TOTP code.
    # Never send this in URL query params (Phase 0) — only read server-side
    # in ``POST /auth/totp/verify`` after ``POST /auth/totp/setup`` stored it.
    pending_totp_secret: Mapped[str | None] = mapped_column(
        EncryptedString(512), nullable=True, default=None,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, server_default=func.now()
    )
    last_login: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow,
        server_default=func.now(), nullable=True,
    )


# ---------------------------------------------------------------------------
# RADIUS NAS Clients (editable via Web UI)
# ---------------------------------------------------------------------------

class NasClient(Base):
    __tablename__ = "nas_clients"

    id: Mapped[int]           = mapped_column(Integer, primary_key=True)
    name: Mapped[str]         = mapped_column(String(64), unique=True, nullable=False)
    ip_address: Mapped[str]   = mapped_column(String(45), nullable=False, index=True)
    secret: Mapped[str]       = mapped_column(EncryptedString(512), nullable=False)
    description: Mapped[str]  = mapped_column(String(255), default="")
    enabled: Mapped[bool]     = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, server_default=func.now()
    )
    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow,
        server_default=func.now(), nullable=True,
    )


# ---------------------------------------------------------------------------
# TACACS+ Device Clients (editable via Web UI)
# ---------------------------------------------------------------------------

class TacacsClient(Base):
    __tablename__ = "tacacs_clients"

    id: Mapped[int]           = mapped_column(Integer, primary_key=True)
    name: Mapped[str]         = mapped_column(String(64), unique=True, nullable=False)
    ip_address: Mapped[str]   = mapped_column(String(45), nullable=False, index=True)
    key: Mapped[str]          = mapped_column(EncryptedString(512), nullable=False)
    description: Mapped[str]  = mapped_column(String(255), default="")
    enabled: Mapped[bool]     = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, server_default=func.now()
    )
    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow,
        server_default=func.now(), nullable=True,
    )


# ---------------------------------------------------------------------------
# VLAN Assignments (group → VLAN mapping, editable via Web UI)
# ---------------------------------------------------------------------------

class VlanMapping(Base):
    __tablename__ = "vlan_mappings"

    id: Mapped[int]          = mapped_column(Integer, primary_key=True)
    name: Mapped[str]        = mapped_column(String(64), unique=True, nullable=False)
    vlan_id: Mapped[int]     = mapped_column(Integer, nullable=False)
    description: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, server_default=func.now()
    )

    __table_args__ = (
        CheckConstraint("vlan_id >= 1 AND vlan_id <= 4094", name="ck_vlan_mapping_range"),
    )


# ---------------------------------------------------------------------------
# TACACS+ Command Sets
# ---------------------------------------------------------------------------

class CommandRuleAction(StrEnum):
    PERMIT = "PERMIT"
    DENY   = "DENY"


class CommandSet(Base):
    __tablename__ = "command_sets"

    id: Mapped[int]           = mapped_column(Integer, primary_key=True)
    name: Mapped[str]         = mapped_column(String(64), unique=True, nullable=False)
    description: Mapped[str]  = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, server_default=func.now()
    )

    rules: Mapped[list[CommandRule]] = relationship(
        "CommandRule", back_populates="command_set",
        cascade="all, delete-orphan", order_by="CommandRule.priority",
    )
    groups: Mapped[list[Group]] = relationship("Group", back_populates="command_set")


class CommandRule(Base):
    """A single permit/deny rule within a CommandSet.

    Rules are evaluated in priority order (ascending). First match wins.
    If no rule matches, the default action is DENY.

    command_pattern: glob-like pattern matched against the command, e.g.
                     "show *", "configure terminal", "interface *"
    args_pattern:    optional pattern for command arguments (empty = match any)
    """
    __tablename__ = "command_rules"

    id: Mapped[int]              = mapped_column(Integer, primary_key=True)
    command_set_id: Mapped[int]  = mapped_column(ForeignKey("command_sets.id", ondelete="CASCADE"), nullable=False)
    priority: Mapped[int]        = mapped_column(Integer, default=100)
    action: Mapped[str]          = mapped_column(Enum(CommandRuleAction), default=CommandRuleAction.PERMIT)
    command_pattern: Mapped[str] = mapped_column(String(256), nullable=False)
    args_pattern: Mapped[str]    = mapped_column(String(256), default="")

    command_set: Mapped[CommandSet] = relationship("CommandSet", back_populates="rules")


# ---------------------------------------------------------------------------
# Admin Audit Log (tracks changes made via Web UI and REST API)
# ---------------------------------------------------------------------------

class AdminAuditLog(Base):
    __tablename__ = "admin_audit_logs"

    id: Mapped[int]              = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[datetime]  = mapped_column(
        DateTime(timezone=True), default=_utcnow, server_default=func.now(), index=True
    )
    admin_username: Mapped[str]  = mapped_column(String(64), nullable=False, index=True)
    action: Mapped[str]          = mapped_column(String(32), nullable=False)  # CREATE, UPDATE, DELETE, LOGIN
    resource_type: Mapped[str]   = mapped_column(String(64), nullable=False)  # user, policy, device, ...
    resource_id: Mapped[str]     = mapped_column(String(64), default="")
    detail: Mapped[str]          = mapped_column(Text, default="")


# ---------------------------------------------------------------------------
# API tokens (long-lived bearer credentials for automation)
# ---------------------------------------------------------------------------

class ApiToken(Base):
    """Long-lived API bearer token, scoped to a role ceiling.

    Only a SHA-256 digest of the token is stored — the raw value
    (``naco_…``) is shown exactly once, at creation. The ``role`` acts as
    the token's permission ceiling through the same ``require_role``
    checks the admin UI uses.
    """
    __tablename__ = "api_tokens"

    id: Mapped[int]              = mapped_column(Integer, primary_key=True)
    name: Mapped[str]            = mapped_column(String(64), unique=True, nullable=False)
    token_hash: Mapped[str]      = mapped_column(String(64), unique=True, nullable=False, index=True)
    # First characters of the raw token, for identification in listings.
    prefix: Mapped[str]          = mapped_column(String(16), nullable=False, default="")
    role: Mapped[str]            = mapped_column(
        Enum(AdminRole), default=AdminRole.VIEWER, nullable=False,
        server_default=AdminRole.VIEWER.value,
    )
    created_by: Mapped[str]      = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, server_default=func.now()
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    enabled: Mapped[bool]        = mapped_column(Boolean, default=True)
