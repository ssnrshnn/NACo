"""Server-side admin sessions.

The cookie holds 256 random bits; only their SHA-256 is stored, so a database
leak does not leak live sessions. Sessions expire after
``security.session_idle_minutes`` of inactivity and at most
``security.session_max_hours`` after login, and are deleted outright on
logout, password or role change, and when the account is disabled.
"""
from __future__ import annotations

import hashlib
import secrets
from datetime import timedelta

from fastapi import Response
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from naco.config import get_config
from naco.core.timeutil import utcnow
from naco.db.models import AdminSession, AdminUser

COOKIE = "naco_session"
_TOUCH_EVERY = timedelta(seconds=60)


def token_hash(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


async def create(db: AsyncSession, admin: AdminUser, ip: str, user_agent: str) -> tuple[str, AdminSession]:
    cfg = get_config().security
    raw = secrets.token_urlsafe(32)
    now = utcnow()
    session = AdminSession(
        token_hash=token_hash(raw), admin_id=admin.id, csrf_token=secrets.token_urlsafe(32),
        created_at=now, last_seen_at=now, expires_at=now + timedelta(hours=cfg.session_max_hours),
        ip=ip[:45], user_agent=user_agent[:256],
    )
    db.add(session)
    await db.flush()
    return raw, session


async def resolve(db: AsyncSession, raw: str | None) -> tuple[AdminSession, AdminUser] | None:
    if not raw or len(raw) > 128:
        return None
    row = (await db.execute(
        select(AdminSession, AdminUser).join(AdminUser, AdminSession.admin_id == AdminUser.id)
        .where(AdminSession.token_hash == token_hash(raw))
    )).first()
    if row is None:
        return None
    session, admin = row
    now = utcnow()
    idle = timedelta(minutes=get_config().security.session_idle_minutes)
    if session.expires_at <= now or session.last_seen_at + idle <= now or not admin.enabled:
        await db.delete(session)
        await db.commit()
        return None
    if now - session.last_seen_at >= _TOUCH_EVERY:
        session.last_seen_at = now
    return session, admin


async def revoke_all(db: AsyncSession, admin_id: int, keep_id: int | None = None) -> None:
    query = delete(AdminSession).where(AdminSession.admin_id == admin_id)
    if keep_id is not None:
        query = query.where(AdminSession.id != keep_id)
    await db.execute(query)


def set_cookie(response: Response, raw: str, *, secure: bool) -> None:
    response.set_cookie(
        COOKIE, raw, max_age=get_config().security.session_max_hours * 3600,
        httponly=True, secure=secure, samesite="lax", path="/",
    )


def clear_cookie(response: Response, *, secure: bool) -> None:
    response.delete_cookie(COOKIE, httponly=True, secure=secure, samesite="lax", path="/")
