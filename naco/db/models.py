"""NACo v3 schema.

Conventions: every timestamp is a timezone-aware UTC ``UTCDateTime``; enums are
stored as their string values with a CHECK constraint; secrets the server must
read back use ``EncryptedString`` bound to their column.
"""
from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    CheckConstraint,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy import Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship

from naco.db.engine import Base
from naco.db.types import EncryptedString, UTCDateTime


def utcnow() -> datetime:
    return datetime.now(UTC)


def _enum(cls: type[StrEnum], name: str) -> SAEnum:
    return SAEnum(
        cls, name=name, native_enum=False, create_constraint=True, length=16,
        values_callable=lambda e: [m.value for m in e], validate_strings=True,
    )


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class AdminRole(StrEnum):
    VIEWER = "VIEWER"
    OPERATOR = "OPERATOR"
    SUPERUSER = "SUPERUSER"

    @property
    def rank(self) -> int:
        return {"VIEWER": 0, "OPERATOR": 1, "SUPERUSER": 2}[self.value]

    def allows(self, required: AdminRole) -> bool:
        return self.rank >= required.rank


class UserSource(StrEnum):
    LOCAL = "LOCAL"
    LDAP = "LDAP"


class DeviceStatus(StrEnum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    BLOCKED = "BLOCKED"


class PolicyAction(StrEnum):
    PERMIT = "PERMIT"
    DENY = "DENY"


class CommandAction(StrEnum):
    PERMIT = "PERMIT"
    DENY = "DENY"


class AuthResult(StrEnum):
    ACCEPT = "ACCEPT"
    REJECT = "REJECT"


class TacacsKind(StrEnum):
    AUTHEN = "AUTHEN"
    AUTHOR = "AUTHOR"
    ACCT = "ACCT"


class ActorType(StrEnum):
    ADMIN = "ADMIN"
    TOKEN = "TOKEN"  # noqa: S105 — an actor kind, not a credential
    SYSTEM = "SYSTEM"
    CLI = "CLI"


# ---------------------------------------------------------------------------
# Administration
# ---------------------------------------------------------------------------

class AdminUser(Base):
    __tablename__ = "admin_users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    password_hash: Mapped[str] = mapped_column(String(128))
    role: Mapped[AdminRole] = mapped_column(_enum(AdminRole, "admin_role"), default=AdminRole.VIEWER)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=True)
    totp_secret: Mapped[str | None] = mapped_column(EncryptedString(256, aad="admin_users.totp_secret"))
    totp_pending_secret: Mapped[str | None] = mapped_column(
        EncryptedString(256, aad="admin_users.totp_pending_secret")
    )
    totp_last_step: Mapped[int | None] = mapped_column(Integer)
    # bcrypt hashes of unused one-time recovery codes.
    recovery_codes: Mapped[list[str]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    password_changed_at: Mapped[datetime | None] = mapped_column(UTCDateTime)

    sessions: Mapped[list[AdminSession]] = relationship(
        back_populates="admin", cascade="all, delete-orphan", passive_deletes=True
    )


class AdminSession(Base):
    __tablename__ = "admin_sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # SHA-256 of the cookie value; the raw value is never stored.
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    admin_id: Mapped[int] = mapped_column(ForeignKey("admin_users.id", ondelete="CASCADE"), index=True)
    csrf_token: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
    ip: Mapped[str] = mapped_column(String(45), default="")
    user_agent: Mapped[str] = mapped_column(String(256), default="")

    admin: Mapped[AdminUser] = relationship(back_populates="sessions")


class ApiToken(Base):
    __tablename__ = "api_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    prefix: Mapped[str] = mapped_column(String(16))
    role: Mapped[AdminRole] = mapped_column(_enum(AdminRole, "token_role"), default=AdminRole.VIEWER)
    created_by: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    last_used_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(64), index=True)
    actor_type: Mapped[ActorType] = mapped_column(_enum(ActorType, "actor_type"))
    ip: Mapped[str] = mapped_column(String(45), default="")
    action: Mapped[str] = mapped_column(String(64))
    target_type: Mapped[str] = mapped_column(String(32), default="")
    target_id: Mapped[str] = mapped_column(String(64), default="")
    target_name: Mapped[str] = mapped_column(String(128), default="")
    changes: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


# ---------------------------------------------------------------------------
# Identities
# ---------------------------------------------------------------------------

class CommandSet(Base):
    __tablename__ = "command_sets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    description: Mapped[str] = mapped_column(String(255), default="")
    default_action: Mapped[CommandAction] = mapped_column(
        _enum(CommandAction, "command_default_action"), default=CommandAction.DENY
    )
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)

    rules: Mapped[list[CommandRule]] = relationship(
        back_populates="command_set", cascade="all, delete-orphan",
        order_by="CommandRule.position", passive_deletes=True,
    )


class CommandRule(Base):
    __tablename__ = "command_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    command_set_id: Mapped[int] = mapped_column(ForeignKey("command_sets.id", ondelete="CASCADE"), index=True)
    position: Mapped[int] = mapped_column(Integer)
    action: Mapped[CommandAction] = mapped_column(_enum(CommandAction, "command_rule_action"))
    # Glob matched against the full command line ("show interfaces *").
    pattern: Mapped[str] = mapped_column(String(256))

    command_set: Mapped[CommandSet] = relationship(back_populates="rules")


class Group(Base):
    __tablename__ = "groups"
    __table_args__ = (
        CheckConstraint(
            "device_admin_privilege IS NULL OR device_admin_privilege BETWEEN 1 AND 15",
            name="privilege_range",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    description: Mapped[str] = mapped_column(String(255), default="")
    # Set → members may log in to network devices over TACACS+ up to this level.
    device_admin_privilege: Mapped[int | None] = mapped_column(Integer)
    command_set_id: Mapped[int | None] = mapped_column(ForeignKey("command_sets.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)

    users: Mapped[list[User]] = relationship(back_populates="group", passive_deletes=True)
    command_set: Mapped[CommandSet | None] = relationship()


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    source: Mapped[UserSource] = mapped_column(_enum(UserSource, "user_source"), default=UserSource.LOCAL)
    # NULL for LDAP users: every login is verified against the directory.
    password_hash: Mapped[str | None] = mapped_column(String(128))
    email: Mapped[str] = mapped_column(String(128), default="")
    full_name: Mapped[str] = mapped_column(String(128), default="")
    group_id: Mapped[int | None] = mapped_column(ForeignKey("groups.id", ondelete="SET NULL"), index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(UTCDateTime)

    group: Mapped[Group | None] = relationship(back_populates="users")


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    mac_address: Mapped[str] = mapped_column(String(17), unique=True)
    status: Mapped[DeviceStatus] = mapped_column(
        _enum(DeviceStatus, "device_status"), default=DeviceStatus.PENDING, index=True
    )
    device_type: Mapped[str] = mapped_column(String(64), default="")
    vendor: Mapped[str] = mapped_column(String(128), default="")
    description: Mapped[str] = mapped_column(String(255), default="")
    notes: Mapped[str] = mapped_column(Text, default="")
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_nas_ip: Mapped[str] = mapped_column(String(45), default="")
    last_username: Mapped[str] = mapped_column(String(64), default="")


class GuestRegistration(Base):
    __tablename__ = "guest_registrations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    mac_address: Mapped[str] = mapped_column(String(17), index=True)
    full_name: Mapped[str] = mapped_column(String(128), default="")
    email: Mapped[str] = mapped_column(String(128), default="")
    nas_ip: Mapped[str] = mapped_column(String(45), default="")
    client_ip: Mapped[str] = mapped_column(String(45), default="")
    created_by: Mapped[str] = mapped_column(String(64), default="portal")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime, index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime)


# ---------------------------------------------------------------------------
# Policy and network devices
# ---------------------------------------------------------------------------

class Policy(Base):
    __tablename__ = "policies"
    __table_args__ = (CheckConstraint("vlan IS NULL OR vlan BETWEEN 1 AND 4094", name="vlan_range"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    description: Mapped[str] = mapped_column(String(512), default="")
    # Lower runs first; ties are broken by id.
    priority: Mapped[int] = mapped_column(Integer, default=100)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    conditions: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    action: Mapped[PolicyAction] = mapped_column(_enum(PolicyAction, "policy_action"))
    vlan: Mapped[int | None] = mapped_column(Integer)
    reply_attributes: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)


class NasClient(Base):
    __tablename__ = "nas_clients"
    __table_args__ = (CheckConstraint("coa_port BETWEEN 1 AND 65535", name="coa_port_range"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    ip_address: Mapped[str] = mapped_column(String(45), unique=True)
    secret: Mapped[str] = mapped_column(EncryptedString(512, aad="nas_clients.secret"))
    coa_port: Mapped[int] = mapped_column(Integer, default=3799)
    require_message_authenticator: Mapped[bool] = mapped_column(Boolean, default=True)
    description: Mapped[str] = mapped_column(String(255), default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)


class TacacsClient(Base):
    __tablename__ = "tacacs_clients"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    ip_address: Mapped[str] = mapped_column(String(45), unique=True)
    key: Mapped[str] = mapped_column(EncryptedString(512, aad="tacacs_clients.key"))
    description: Mapped[str] = mapped_column(String(255), default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)


# ---------------------------------------------------------------------------
# Runtime state and logs
# ---------------------------------------------------------------------------

class RadiusSession(Base):
    __tablename__ = "radius_sessions"
    __table_args__ = (UniqueConstraint("nas_ip", "acct_session_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    nas_ip: Mapped[str] = mapped_column(String(45))
    acct_session_id: Mapped[str] = mapped_column(String(64))
    # Authenticated identity the policy saw (inner identity / certificate CN).
    username: Mapped[str] = mapped_column(String(64), default="")
    # Identifiers exactly as the NAS reported them — echoed back in CoA.
    acct_username: Mapped[str] = mapped_column(String(64), default="")
    calling_station_id: Mapped[str] = mapped_column(String(64), default="")
    mac_address: Mapped[str] = mapped_column(String(17), default="", index=True)
    framed_ip: Mapped[str] = mapped_column(String(45), default="", index=True)
    ssid: Mapped[str] = mapped_column(String(64), default="")
    auth_method: Mapped[str] = mapped_column(String(16), default="")
    policy_name: Mapped[str] = mapped_column(String(128), default="")
    vlan: Mapped[int | None] = mapped_column(Integer)
    decision_digest: Mapped[str] = mapped_column(String(64), default="")
    started_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    input_octets: Mapped[int] = mapped_column(BigInteger, default=0)
    output_octets: Mapped[int] = mapped_column(BigInteger, default=0)
    session_time: Mapped[int] = mapped_column(Integer, default=0)


class AuthLog(Base):
    __tablename__ = "auth_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    username: Mapped[str] = mapped_column(String(64), default="", index=True)
    mac_address: Mapped[str] = mapped_column(String(17), default="", index=True)
    nas_ip: Mapped[str] = mapped_column(String(45), default="")
    nas_name: Mapped[str] = mapped_column(String(64), default="")
    ssid: Mapped[str] = mapped_column(String(64), default="")
    auth_method: Mapped[str] = mapped_column(String(16), default="")
    result: Mapped[AuthResult] = mapped_column(_enum(AuthResult, "auth_result"))
    reason: Mapped[str] = mapped_column(String(255), default="")
    policy_name: Mapped[str] = mapped_column(String(128), default="")
    vlan: Mapped[int | None] = mapped_column(Integer)
    decision_digest: Mapped[str] = mapped_column(String(64), default="")


class TacacsLog(Base):
    __tablename__ = "tacacs_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    kind: Mapped[TacacsKind] = mapped_column(_enum(TacacsKind, "tacacs_kind"))
    username: Mapped[str] = mapped_column(String(64), default="", index=True)
    client_ip: Mapped[str] = mapped_column(String(45), default="")
    rem_addr: Mapped[str] = mapped_column(String(64), default="")
    port: Mapped[str] = mapped_column(String(64), default="")
    privilege: Mapped[int] = mapped_column(Integer, default=0)
    command: Mapped[str] = mapped_column(Text, default="")
    result: Mapped[str] = mapped_column(String(16), default="")
    reason: Mapped[str] = mapped_column(String(255), default="")
