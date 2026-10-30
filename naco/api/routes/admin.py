"""Logs, the audit trail, administrators and API tokens."""
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, Query, Response
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from naco.api import sessions as admin_sessions
from naco.api.audit import AuditTrail, audit_trail, diff
from naco.api.common import Page, Paging, flush_or_conflict, get_or_404, like, snapshot
from naco.api.deps import TOKEN_PREFIX, Principal, operator, superuser, viewer
from naco.api.errors import ApiError
from naco.core.passwords import hash_password
from naco.core.timeutil import utcnow
from naco.db.engine import get_db
from naco.db.models import ActorType, AdminRole, AdminUser, ApiToken, AuditLog, AuthLog, AuthResult, TacacsLog

router = APIRouter(tags=["administration"])


# ── logs ───────────────────────────────────────────────────────────────────

class AuthLogOut(BaseModel):
    id: int
    timestamp: datetime
    username: str
    mac_address: str
    nas_ip: str
    nas_name: str
    ssid: str
    auth_method: str
    result: AuthResult
    reason: str
    policy_name: str
    vlan: int | None


class TacacsLogOut(BaseModel):
    id: int
    timestamp: datetime
    kind: str
    username: str
    client_ip: str
    rem_addr: str
    privilege: int
    command: str
    result: str
    reason: str


class AuditOut(BaseModel):
    id: int
    timestamp: datetime
    actor: str
    actor_type: ActorType
    ip: str
    action: str
    target_type: str
    target_id: str
    target_name: str
    changes: dict[str, Any]


def _window(query: Any, column: Any, since: datetime | None, until: datetime | None) -> Any:
    if since is not None:
        query = query.where(column >= since)
    if until is not None:
        query = query.where(column < until)
    return query


@router.get("/logs/auth", response_model=Page[AuthLogOut])
async def auth_logs(q: str = Query("", max_length=64), result: AuthResult | None = None,
                    method: str | None = Query(None, max_length=16), since: datetime | None = None,
                    until: datetime | None = None, paging: Paging = Depends(), _: Principal = Depends(viewer),
                    db: AsyncSession = Depends(get_db)) -> Page[AuthLogOut]:
    query = _window(select(AuthLog).order_by(AuthLog.id.desc()), AuthLog.timestamp, since, until)
    if q:
        term = like(q.lower())
        query = query.where(or_(AuthLog.username.ilike(term, escape="\\"), AuthLog.mac_address.ilike(term, escape="\\"),
                                AuthLog.nas_name.ilike(term, escape="\\"), AuthLog.reason.ilike(term, escape="\\"),
                                AuthLog.policy_name.ilike(term, escape="\\")))
    if result is not None:
        query = query.where(AuthLog.result == result)
    if method:
        query = query.where(AuthLog.auth_method == method)
    rows, total = await paging.fetch(db, query)
    return Page(items=[AuthLogOut.model_validate(r, from_attributes=True) for r in rows], total=total,
                page=paging.page, per_page=paging.per_page)


@router.get("/logs/tacacs", response_model=Page[TacacsLogOut])
async def tacacs_logs(q: str = Query("", max_length=64), since: datetime | None = None,
                      until: datetime | None = None, paging: Paging = Depends(), _: Principal = Depends(viewer),
                      db: AsyncSession = Depends(get_db)) -> Page[TacacsLogOut]:
    query = _window(select(TacacsLog).order_by(TacacsLog.id.desc()), TacacsLog.timestamp, since, until)
    if q:
        term = like(q.lower())
        query = query.where(or_(TacacsLog.username.ilike(term, escape="\\"), TacacsLog.command.ilike(term, escape="\\"),
                                TacacsLog.client_ip.ilike(term, escape="\\")))
    rows, total = await paging.fetch(db, query)
    return Page(items=[TacacsLogOut(kind=r.kind.value, **{k: getattr(r, k) for k in TacacsLogOut.model_fields
                                                          if k != "kind"}) for r in rows],
                total=total, page=paging.page, per_page=paging.per_page)


@router.get("/audit", response_model=Page[AuditOut])
async def audit_log(q: str = Query("", max_length=64), since: datetime | None = None, until: datetime | None = None,
                    paging: Paging = Depends(), _: Principal = Depends(operator),
                    db: AsyncSession = Depends(get_db)) -> Page[AuditOut]:
    query = _window(select(AuditLog).order_by(AuditLog.id.desc()), AuditLog.timestamp, since, until)
    if q:
        term = like(q.lower())
        query = query.where(or_(AuditLog.actor.ilike(term, escape="\\"), AuditLog.action.ilike(term, escape="\\"),
                                AuditLog.target_name.ilike(term, escape="\\")))
    rows, total = await paging.fetch(db, query)
    return Page(items=[AuditOut.model_validate(r, from_attributes=True) for r in rows], total=total,
                page=paging.page, per_page=paging.per_page)


# ── administrators ─────────────────────────────────────────────────────────

ADMIN_FIELDS = ["username", "role", "enabled"]


class AdminOut(BaseModel):
    id: int
    username: str
    role: AdminRole
    enabled: bool
    totp_enabled: bool
    must_change_password: bool
    last_login_at: datetime | None
    created_at: datetime


class AdminCreate(BaseModel):
    username: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9._-]*$")
    role: AdminRole


class AdminUpdate(BaseModel):
    role: AdminRole | None = None
    enabled: bool | None = None


class TemporaryPassword(BaseModel):
    admin: AdminOut
    temporary_password: str


def admin_out(a: AdminUser) -> AdminOut:
    return AdminOut(id=a.id, username=a.username, role=a.role, enabled=a.enabled, totp_enabled=bool(a.totp_secret),
                    must_change_password=a.must_change_password, last_login_at=a.last_login_at,
                    created_at=a.created_at)


async def _other_superusers(db: AsyncSession, admin_id: int) -> int:
    return (await db.execute(select(func.count()).select_from(AdminUser).where(
        AdminUser.role == AdminRole.SUPERUSER, AdminUser.enabled.is_(True), AdminUser.id != admin_id))).scalar_one()


def _not_self(principal: Principal, admin: AdminUser) -> None:
    if principal.admin_id == admin.id:
        raise ApiError(409, "ask another SUPERUSER to change your own account")


@router.get("/admins", response_model=list[AdminOut])
async def list_admins(_: Principal = Depends(superuser), db: AsyncSession = Depends(get_db)) -> list[AdminOut]:
    return [admin_out(a) for a in (await db.execute(select(AdminUser).order_by(AdminUser.username))).scalars()]


@router.post("/admins", response_model=TemporaryPassword, status_code=201)
async def create_admin(body: AdminCreate, _: Principal = Depends(superuser),
                       audit: AuditTrail = Depends(audit_trail)) -> TemporaryPassword:
    password = secrets.token_urlsafe(15)
    admin = AdminUser(username=body.username, role=body.role, password_hash=await hash_password(password),
                      must_change_password=True)
    audit.db.add(admin)
    await flush_or_conflict(audit.db, f"administrator {body.username} already exists")
    audit.record("admin.create", "admin", admin.id, admin.username, snapshot(admin, ADMIN_FIELDS))
    await audit.db.commit()
    return TemporaryPassword(admin=admin_out(admin), temporary_password=password)


@router.patch("/admins/{admin_id}", response_model=AdminOut)
async def update_admin(admin_id: int, body: AdminUpdate, principal: Principal = Depends(superuser),
                       audit: AuditTrail = Depends(audit_trail)) -> AdminOut:
    admin = await get_or_404(audit.db, AdminUser, admin_id, "administrator")
    _not_self(principal, admin)
    before = snapshot(admin, ADMIN_FIELDS)
    if body.role is not None:
        admin.role = body.role
    if body.enabled is not None:
        admin.enabled = body.enabled
    loses_superuser = before["role"] == AdminRole.SUPERUSER.value and (
        admin.role is not AdminRole.SUPERUSER or not admin.enabled)
    if loses_superuser and not await _other_superusers(audit.db, admin.id):
        raise ApiError(409, "this is the last enabled SUPERUSER")
    delta = diff(before, snapshot(admin, ADMIN_FIELDS))
    if delta:
        await admin_sessions.revoke_all(audit.db, admin.id)
    audit.record("admin.update", "admin", admin.id, admin.username, delta)
    await audit.db.commit()
    return admin_out(admin)


@router.post("/admins/{admin_id}/reset-password", response_model=TemporaryPassword)
async def reset_admin_password(admin_id: int, principal: Principal = Depends(superuser),
                               audit: AuditTrail = Depends(audit_trail)) -> TemporaryPassword:
    admin = await get_or_404(audit.db, AdminUser, admin_id, "administrator")
    _not_self(principal, admin)
    password = secrets.token_urlsafe(15)
    admin.password_hash = await hash_password(password)
    admin.must_change_password = True
    await admin_sessions.revoke_all(audit.db, admin.id)
    audit.record("admin.password_reset", "admin", admin.id, admin.username)
    await audit.db.commit()
    return TemporaryPassword(admin=admin_out(admin), temporary_password=password)


@router.post("/admins/{admin_id}/reset-totp", response_model=AdminOut)
async def reset_admin_totp(admin_id: int, principal: Principal = Depends(superuser),
                           audit: AuditTrail = Depends(audit_trail)) -> AdminOut:
    admin = await get_or_404(audit.db, AdminUser, admin_id, "administrator")
    _not_self(principal, admin)
    admin.totp_secret, admin.totp_pending_secret, admin.totp_last_step, admin.recovery_codes = None, None, None, []
    await admin_sessions.revoke_all(audit.db, admin.id)
    audit.record("admin.totp_reset", "admin", admin.id, admin.username)
    await audit.db.commit()
    return admin_out(admin)


@router.delete("/admins/{admin_id}", status_code=204)
async def delete_admin(admin_id: int, principal: Principal = Depends(superuser),
                       audit: AuditTrail = Depends(audit_trail)) -> Response:
    admin = await get_or_404(audit.db, AdminUser, admin_id, "administrator")
    _not_self(principal, admin)
    if admin.role is AdminRole.SUPERUSER and admin.enabled and not await _other_superusers(audit.db, admin.id):
        raise ApiError(409, "this is the last enabled SUPERUSER")
    await audit.db.delete(admin)
    audit.record("admin.delete", "admin", admin_id, admin.username)
    await audit.db.commit()
    return Response(status_code=204)


# ── API tokens ─────────────────────────────────────────────────────────────

class TokenOut(BaseModel):
    id: int
    name: str
    prefix: str
    role: AdminRole
    created_by: str
    created_at: datetime
    expires_at: datetime | None
    last_used_at: datetime | None
    revoked_at: datetime | None


class TokenCreate(BaseModel):
    name: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9 ._-]*$")
    role: AdminRole = AdminRole.VIEWER
    expires_days: int | None = Field(90, ge=1, le=3650)


class TokenCreated(BaseModel):
    token: TokenOut
    secret: str


def _session_only(principal: Principal) -> None:
    if principal.kind != "session":
        raise ApiError(403, "API tokens cannot manage API tokens")


@router.get("/tokens", response_model=list[TokenOut])
async def list_tokens(_: Principal = Depends(superuser), db: AsyncSession = Depends(get_db)) -> list[TokenOut]:
    rows = (await db.execute(select(ApiToken).order_by(ApiToken.created_at.desc()))).scalars()
    return [TokenOut.model_validate(t, from_attributes=True) for t in rows]


@router.post("/tokens", response_model=TokenCreated, status_code=201)
async def create_token(body: TokenCreate, principal: Principal = Depends(superuser),
                       audit: AuditTrail = Depends(audit_trail)) -> TokenCreated:
    _session_only(principal)
    raw = TOKEN_PREFIX + secrets.token_urlsafe(32)
    token = ApiToken(name=body.name, token_hash=hashlib.sha256(raw.encode()).hexdigest(), prefix=raw[:12],
                     role=body.role, created_by=principal.username,
                     expires_at=utcnow() + timedelta(days=body.expires_days) if body.expires_days else None)
    audit.db.add(token)
    await flush_or_conflict(audit.db, f"a token named {body.name} already exists")
    audit.record("token.create", "token", token.id, token.name,
                 {"role": body.role.value, "expires_days": body.expires_days})
    await audit.db.commit()
    return TokenCreated(token=TokenOut.model_validate(token, from_attributes=True), secret=raw)


@router.delete("/tokens/{token_id}", status_code=204)
async def revoke_token(token_id: int, principal: Principal = Depends(superuser),
                       audit: AuditTrail = Depends(audit_trail)) -> Response:
    _session_only(principal)
    token = await get_or_404(audit.db, ApiToken, token_id, "token")
    if token.revoked_at is None:
        token.revoked_at = utcnow()
        audit.record("token.revoke", "token", token.id, token.name)
        await audit.db.commit()
    return Response(status_code=204)
