"""Sign-in, account setup (password + TOTP) and one's own sessions."""
from __future__ import annotations

import asyncio
import math
from datetime import datetime

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from naco.api import sessions, totp
from naco.api.audit import AuditTrail, announce, audit_trail, write
from naco.api.deps import Principal, check_same_origin, client_ip, require, restriction
from naco.api.errors import ApiError
from naco.config import get_config
from naco.core.passwords import hash_password, validate_admin_password, verify_password, verify_password_sync
from naco.core.ratelimit import GuessGuard, SlidingWindow
from naco.core.timeutil import utcnow
from naco.db.engine import get_db, release
from naco.db.models import ActorType, AdminRole, AdminSession, AdminUser

router = APIRouter(prefix="/auth", tags=["auth"])
signed_in = require(AdminRole.VIEWER, setup_allowed=True)

_guesses = GuessGuard(free_attempts=3)  # per account and address
_per_ip: SlidingWindow | None = None


def reset_throttles() -> None:
    global _per_ip
    _per_ip = None
    _guesses.clear()


def _ip_window() -> SlidingWindow:
    global _per_ip
    if _per_ip is None:
        cfg = get_config().security
        _per_ip = SlidingWindow(cfg.login_max_attempts, cfg.login_window_seconds)
    return _per_ip


class Me(BaseModel):
    username: str
    role: AdminRole
    restricted: str | None
    totp_enabled: bool
    csrf_token: str


def _me(admin: AdminUser, csrf: str) -> Me:
    return Me(username=admin.username, role=admin.role, restricted=restriction(admin),
              totp_enabled=bool(admin.totp_secret), csrf_token=csrf)


async def _admin(db: AsyncSession, principal: Principal) -> AdminUser:
    if principal.kind != "session" or principal.admin_id is None:
        raise ApiError(403, "not available to API tokens")
    admin = await db.get(AdminUser, principal.admin_id)
    if admin is None:
        raise ApiError(401, "not signed in")
    return admin


async def _second_factor(db: AsyncSession, admin: AdminUser, code: str) -> bool:
    """Check and record a TOTP or recovery code. Runs after bcrypt, in a fresh
    transaction: concurrent sign-ins are serialized here, so a code works once."""
    await db.refresh(admin)
    if not admin.enabled or not admin.totp_secret:
        return not admin.totp_secret and admin.enabled
    step = totp.match(admin.totp_secret, code, admin.totp_last_step)
    if step is not None:
        admin.totp_last_step = step
        return True
    if not totp.looks_like_recovery_code(code):
        return False
    candidates = list(admin.recovery_codes)
    await release(db)
    code = code.strip().lower()
    used = None
    for hashed in candidates:
        if await asyncio.to_thread(verify_password_sync, code, hashed):
            used = hashed
            break
    if used is None:
        return False
    await db.refresh(admin)
    if used not in admin.recovery_codes:  # spent by a concurrent sign-in
        return False
    admin.recovery_codes = [h for h in admin.recovery_codes if h != used]
    return True


# ── sign in / out ──────────────────────────────────────────────────────────

class LoginIn(BaseModel):
    username: str = Field(max_length=64)
    password: str = Field(max_length=256)
    totp_code: str = Field("", max_length=16)


@router.post("/login", response_model=Me)
async def login(body: LoginIn, request: Request, response: Response, db: AsyncSession = Depends(get_db)) -> Me:
    if not request.headers.get("content-type", "").startswith("application/json"):
        raise ApiError(415, "send JSON")
    check_same_origin(request)
    ip = client_ip(request)
    name = body.username.strip().lower()
    if not _ip_window().hit(ip):
        raise ApiError(429, "too many sign-in attempts — try again later",
                       headers={"Retry-After": str(get_config().security.login_window_seconds)})
    wait = _guesses.delay_for(name, ip)
    if wait > 0:
        raise ApiError(429, f"too many failed attempts — wait {math.ceil(wait)} s",
                       headers={"Retry-After": str(math.ceil(wait))})

    admin = (await db.execute(select(AdminUser).where(AdminUser.username == name))).scalar_one_or_none()
    await release(db)
    ok = await verify_password(body.password, admin.password_hash if admin else None)
    ok = ok and admin is not None and admin.enabled
    if ok and admin is not None:
        ok = await _second_factor(db, admin, body.totp_code)

    if not ok or admin is None:
        _guesses.failure(name, ip)
        # A name that is no account is not recorded: it is often a password
        # typed into the wrong field.
        row = write(db, actor=name if admin is not None else "(unknown)", actor_type=ActorType.ADMIN, ip=ip,
                    action="auth.login_failed")
        await db.commit()
        announce(row)
        # One message for every failure: never reveal which factor was wrong.
        raise ApiError(401, "invalid username, password or code")

    _guesses.success(name, ip)
    raw, session = await sessions.create(db, admin, ip, request.headers.get("user-agent", ""))
    admin.last_login_at = utcnow()
    row = write(db, actor=admin.username, actor_type=ActorType.ADMIN, ip=ip, action="auth.login")
    await db.commit()
    announce(row)
    sessions.set_cookie(response, raw, secure=request.url.scheme == "https")
    return _me(admin, session.csrf_token)


@router.post("/logout", status_code=204)
async def logout(request: Request, response: Response, principal: Principal = Depends(signed_in),
                 audit: AuditTrail = Depends(audit_trail)) -> Response:
    if principal.session_id is not None:
        session = await audit.db.get(AdminSession, principal.session_id)
        if session is not None:
            await audit.db.delete(session)
    audit.record("auth.logout")
    await audit.db.commit()
    out = Response(status_code=204)
    sessions.clear_cookie(out, secure=request.url.scheme == "https")
    return out


@router.get("/me", response_model=Me)
async def me(principal: Principal = Depends(signed_in), db: AsyncSession = Depends(get_db)) -> Me:
    if principal.kind == "token":
        return Me(username=principal.username, role=principal.role, restricted=None,
                  totp_enabled=False, csrf_token="")
    return _me(await _admin(db, principal), principal.csrf_token)


# ── password ───────────────────────────────────────────────────────────────

class PasswordIn(BaseModel):
    current_password: str = Field(max_length=256)
    new_password: str = Field(max_length=256)


@router.post("/password", status_code=204)
async def change_password(body: PasswordIn, principal: Principal = Depends(signed_in),
                          audit: AuditTrail = Depends(audit_trail)) -> Response:
    admin = await _admin(audit.db, principal)
    await release(audit.db)
    if not await verify_password(body.current_password, admin.password_hash):
        raise ApiError(403, "current password is wrong")
    try:
        validate_admin_password(body.new_password)
    except ValueError as exc:
        raise ApiError(422, str(exc)) from exc
    if body.new_password == body.current_password:
        raise ApiError(422, "choose a password you have not used just now")
    new_hash = await hash_password(body.new_password)
    await audit.db.refresh(admin)
    admin.password_hash = new_hash
    admin.must_change_password = False
    admin.password_changed_at = utcnow()
    await sessions.revoke_all(audit.db, admin.id, keep_id=principal.session_id)
    audit.record("auth.password_changed", "admin", admin.id, admin.username)
    await audit.db.commit()
    return Response(status_code=204)


# ── two-factor authentication ──────────────────────────────────────────────

class ReauthIn(BaseModel):
    password: str = Field(max_length=256)


class TotpSetupOut(BaseModel):
    secret: str
    uri: str
    qr_svg: str


class CodeIn(BaseModel):
    code: str = Field(max_length=16)


class RecoveryOut(BaseModel):
    recovery_codes: list[str]


@router.post("/totp/setup", response_model=TotpSetupOut)
async def totp_setup(body: ReauthIn, principal: Principal = Depends(signed_in),
                     audit: AuditTrail = Depends(audit_trail)) -> TotpSetupOut:
    admin = await _admin(audit.db, principal)
    if admin.must_change_password:
        raise ApiError(403, "change your password first", "setup_required")
    await release(audit.db)
    if not await verify_password(body.password, admin.password_hash):
        raise ApiError(403, "password is wrong")
    await audit.db.refresh(admin)
    if admin.totp_secret:
        raise ApiError(409, "two-factor authentication is already enabled")
    secret = totp.new_secret()
    admin.totp_pending_secret = secret
    audit.record("auth.totp_setup_started", "admin", admin.id, admin.username)
    await audit.db.commit()
    uri, svg = totp.provisioning(secret, admin.username)
    return TotpSetupOut(secret=secret, uri=uri, qr_svg=svg)


@router.post("/totp/confirm", response_model=RecoveryOut)
async def totp_confirm(body: CodeIn, principal: Principal = Depends(signed_in),
                       audit: AuditTrail = Depends(audit_trail)) -> RecoveryOut:
    admin = await _admin(audit.db, principal)
    if not admin.totp_pending_secret:
        raise ApiError(409, "start the setup first")
    step = totp.match(admin.totp_pending_secret, body.code, None)
    if step is None:
        raise ApiError(422, "that code is not valid — check the time on your device")
    codes = totp.new_recovery_codes()
    pending = admin.totp_pending_secret
    await release(audit.db)
    hashes = list(await asyncio.gather(*(hash_password(c) for c in codes)))
    await audit.db.refresh(admin)
    if admin.totp_pending_secret != pending:
        raise ApiError(409, "the setup changed meanwhile — start again")
    admin.totp_secret, admin.totp_pending_secret, admin.totp_last_step = pending, None, step
    admin.recovery_codes = hashes
    await sessions.revoke_all(audit.db, admin.id, keep_id=principal.session_id)
    audit.record("auth.totp_enabled", "admin", admin.id, admin.username)
    await audit.db.commit()
    return RecoveryOut(recovery_codes=codes)


class DisableIn(BaseModel):
    password: str = Field(max_length=256)
    code: str = Field(max_length=16)


@router.post("/totp/disable", status_code=204)
async def totp_disable(body: DisableIn, principal: Principal = Depends(signed_in),
                       audit: AuditTrail = Depends(audit_trail)) -> Response:
    admin = await _admin(audit.db, principal)
    if not admin.totp_secret:
        raise ApiError(409, "two-factor authentication is not enabled")
    await release(audit.db)
    password_ok = await verify_password(body.password, admin.password_hash)
    await audit.db.refresh(admin)
    step = totp.match(admin.totp_secret, body.code, admin.totp_last_step) if admin.totp_secret else None
    if not password_ok or step is None:
        raise ApiError(403, "password or code is wrong")
    admin.totp_secret, admin.totp_last_step, admin.recovery_codes = None, None, []
    await sessions.revoke_all(audit.db, admin.id, keep_id=principal.session_id)
    audit.record("auth.totp_disabled", "admin", admin.id, admin.username)
    await audit.db.commit()
    return Response(status_code=204)


# ── my sessions ────────────────────────────────────────────────────────────

class SessionOut(BaseModel):
    id: int
    created_at: datetime
    last_seen_at: datetime
    ip: str
    user_agent: str
    current: bool


@router.get("/sessions", response_model=list[SessionOut])
async def my_sessions(principal: Principal = Depends(signed_in),
                      db: AsyncSession = Depends(get_db)) -> list[SessionOut]:
    admin = await _admin(db, principal)
    rows = (await db.execute(select(AdminSession).where(AdminSession.admin_id == admin.id)
                             .order_by(AdminSession.last_seen_at.desc()))).scalars()
    return [SessionOut(id=s.id, created_at=s.created_at, last_seen_at=s.last_seen_at, ip=s.ip,
                       user_agent=s.user_agent, current=s.id == principal.session_id) for s in rows]


@router.delete("/sessions/{session_id}", status_code=204)
async def end_session(session_id: int, principal: Principal = Depends(signed_in),
                      audit: AuditTrail = Depends(audit_trail)) -> Response:
    admin = await _admin(audit.db, principal)
    session = await audit.db.get(AdminSession, session_id)
    if session is None or session.admin_id != admin.id:
        raise ApiError(404, "no such session")
    await audit.db.delete(session)
    audit.record("auth.session_ended", "admin_session", session_id, admin.username)
    await audit.db.commit()
    return Response(status_code=204)
