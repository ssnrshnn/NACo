"""Verify network users (RADIUS PAP/TTLS/PEAP-GTC and TACACS+ logins).

Order of checks:
1. a disabled account is refused before any directory traffic;
2. local accounts are checked with bcrypt;
3. LDAP-sourced accounts — and unknown names when LDAP is enabled — are
   verified against the directory; first-time LDAP users are provisioned and,
   when ``ldap.group_map`` is configured, their group is refreshed on every
   login (no matching mapping → no group);
4. directory failures fail closed.

No database transaction is held across bcrypt or LDAP calls.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from naco.auth.ldap import LdapError, LdapUser, ldap_authenticate, map_group
from naco.config import get_config
from naco.core.passwords import verify_password
from naco.core.timeutil import utcnow
from naco.db.engine import session_factory
from naco.db.models import Group, User, UserSource

log = logging.getLogger(__name__)

MAX_USERNAME = 64


@dataclass(frozen=True)
class UserInfo:
    id: int
    username: str
    source: UserSource
    enabled: bool
    group_id: int | None
    group_name: str | None
    device_admin_privilege: int | None
    command_set_id: int | None
    device_admin_attributes: tuple[str, ...] = ()


@dataclass(frozen=True)
class IdentityResult:
    ok: bool
    reason: str
    username: str
    user: UserInfo | None = None


def canonical_username(raw: str | None) -> str:
    """Trim, drop a leading ``DOMAIN\\`` and lower-case; "" when unusable."""
    name = (raw or "").strip()
    if "\\" in name:
        name = name.rsplit("\\", 1)[1]
    name = name.lower()
    if not name or len(name) > MAX_USERNAME or any(ord(c) < 0x20 for c in name):
        return ""
    return name


async def load_user(db: AsyncSession, username: str) -> tuple[UserInfo, str | None] | None:
    row = (await db.execute(
        select(User, Group).outerjoin(Group, User.group_id == Group.id).where(User.username == username)
    )).first()
    if row is None:
        return None
    user, group = row
    info = UserInfo(
        id=user.id, username=user.username, source=user.source, enabled=user.enabled,
        group_id=user.group_id, group_name=group.name if group else None,
        device_admin_privilege=group.device_admin_privilege if group else None,
        command_set_id=group.command_set_id if group else None,
        device_admin_attributes=tuple(group.device_admin_attributes or ()) if group else (),
    )
    return info, user.password_hash


async def lookup_user(username: str) -> UserInfo | None:
    name = canonical_username(username)
    if not name:
        return None
    async with session_factory()() as db:
        found = await load_user(db, name)
    return found[0] if found else None


async def _record_login(user_id: int) -> None:
    async with session_factory()() as db:
        user = await db.get(User, user_id)
        if user is not None:
            user.last_login_at = utcnow()
            await db.commit()


_UNCHANGED = object()


async def _provision(username: str, entry: LdapUser) -> UserInfo | None:
    cfg = get_config().ldap
    mapped: object = map_group(cfg, entry.group_dns) if cfg.group_map else _UNCHANGED
    async with session_factory()() as db:
        group_id: int | None = None
        if isinstance(mapped, str):
            group_id = (await db.execute(select(Group.id).where(Group.name == mapped))).scalar_one_or_none()
            if group_id is None:
                log.warning("ldap.group_map points to group %r, which does not exist", mapped)
        user = (await db.execute(select(User).where(User.username == username))).scalar_one_or_none()
        if user is None:
            user = User(username=username, source=UserSource.LDAP, password_hash=None,
                        email=entry.email[:128], full_name=entry.full_name[:128], group_id=group_id)
            db.add(user)
        elif user.source is not UserSource.LDAP:
            return None  # a local account appeared concurrently; never let LDAP take it over
        else:
            user.email = entry.email[:128] or user.email
            user.full_name = entry.full_name[:128] or user.full_name
            if mapped is not _UNCHANGED:
                user.group_id = group_id
        user.last_login_at = utcnow()
        try:
            await db.commit()
        except IntegrityError:  # concurrent first login created it
            await db.rollback()
        found = await load_user(db, username)
    return found[0] if found else None


async def authenticate_user(username: str, password: str) -> IdentityResult:
    name = canonical_username(username)
    if not name or not password:
        await verify_password(password or "-", None)
        return IdentityResult(False, "missing or invalid credentials", name or (username or "")[:MAX_USERNAME])

    async with session_factory()() as db:
        found = await load_user(db, name)
    info, pw_hash = found if found else (None, None)

    if info is not None and not info.enabled:
        await verify_password(password, None)
        return IdentityResult(False, "user disabled", name, info)

    if info is not None and info.source is UserSource.LOCAL:
        if not await verify_password(password, pw_hash):
            return IdentityResult(False, "wrong password", name, info)
        await _record_login(info.id)
        return IdentityResult(True, "ok", name, info)

    if not get_config().ldap.enabled:
        await verify_password(password, None)
        return IdentityResult(False, "unknown user" if info is None else "directory disabled", name, info)

    try:
        entry = await ldap_authenticate(name, password)
    except LdapError as exc:
        log.error("LDAP authentication for %s failed: %s", name, exc)
        return IdentityResult(False, "directory unavailable", name, info)
    if entry is None:
        return IdentityResult(False, "unknown user" if info is None else "wrong password", name, info)

    provisioned = await _provision(name, entry)
    if provisioned is None or not provisioned.enabled:
        return IdentityResult(False, "user disabled", name, provisioned)
    return IdentityResult(True, "ok", name, provisioned)
