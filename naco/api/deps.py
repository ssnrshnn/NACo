"""Who is calling, and may they? — the single place access is decided.

A caller is either an API token (``Authorization: Bearer naco_…``) or an
admin session cookie. Cookie-authenticated requests that change state must
also carry the session's CSRF token in ``X-CSRF-Token`` and must not come
from another origin. ``require(role)`` is the only role gate; every route
uses it (a test enumerates the routes and checks).
"""
from __future__ import annotations

import hashlib
import hmac
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import timedelta
from typing import Literal

from fastapi import Depends, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from naco.api import sessions
from naco.api.errors import ApiError
from naco.config import get_config
from naco.core.timeutil import utcnow
from naco.db.engine import get_db
from naco.db.models import AdminRole, AdminUser, ApiToken

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
TOKEN_PREFIX = "naco_"  # noqa: S105 — a public prefix, not a credential


@dataclass(frozen=True)
class Principal:
    kind: Literal["session", "token"]
    username: str
    role: AdminRole
    admin_id: int | None = None
    session_id: int | None = None
    token_id: int | None = None
    csrf_token: str = ""
    # "password" or "totp" while first-login setup is unfinished.
    restricted: str | None = None
    ip: str = ""


def client_ip(request: Request) -> str:
    # uvicorn already replaced the peer with X-Forwarded-For when — and only
    # when — the connection came from a trusted proxy.
    return request.client.host if request.client else ""


def restriction(admin: AdminUser) -> str | None:
    if admin.must_change_password:
        return "password"
    if get_config().security.require_totp and not admin.totp_secret:
        return "totp"
    return None


def own_origin(request: Request) -> str:
    return f"{request.url.scheme}://{request.headers.get('host', '')}"


def check_same_origin(request: Request) -> None:
    origin = request.headers.get("origin")
    if origin is not None and origin != own_origin(request):
        raise ApiError(403, "cross-origin request refused", "csrf")
    site = request.headers.get("sec-fetch-site")
    if site is not None and site not in ("same-origin", "none"):
        raise ApiError(403, "cross-site request refused", "csrf")


async def _token_principal(db: AsyncSession, raw: str, ip: str) -> Principal:
    if not raw.startswith(TOKEN_PREFIX) or len(raw) > 128:
        raise ApiError(401, "invalid API token")
    digest = hashlib.sha256(raw.encode()).hexdigest()
    token = (await db.execute(select(ApiToken).where(ApiToken.token_hash == digest))).scalar_one_or_none()
    now = utcnow()
    if token is None or token.revoked_at is not None or (token.expires_at and token.expires_at <= now):
        raise ApiError(401, "invalid API token")
    if token.last_used_at is None or now - token.last_used_at > timedelta(minutes=1):
        token.last_used_at = now
        await db.commit()
    return Principal(kind="token", username=f"token:{token.name}", role=token.role, token_id=token.id, ip=ip)


async def current_principal(request: Request, db: AsyncSession = Depends(get_db)) -> Principal:
    ip = client_ip(request)
    scheme, _, credential = request.headers.get("authorization", "").partition(" ")
    if scheme.lower() == "bearer" and credential:
        return await _token_principal(db, credential.strip(), ip)

    found = await sessions.resolve(db, request.cookies.get(sessions.COOKIE))
    if found is None:
        raise ApiError(401, "not signed in")
    session, admin = found
    if request.method not in SAFE_METHODS:
        sent = request.headers.get("x-csrf-token", "")
        if not sent or not hmac.compare_digest(sent.encode(), session.csrf_token.encode()):
            raise ApiError(403, "missing or invalid CSRF token", "csrf")
        check_same_origin(request)
    principal = Principal(
        kind="session", username=admin.username, role=admin.role, admin_id=admin.id,
        session_id=session.id, csrf_token=session.csrf_token, restricted=restriction(admin), ip=ip,
    )
    await db.commit()  # persists last_seen_at; the route starts a fresh transaction
    return principal


def require(role: AdminRole, *, setup_allowed: bool = False) -> Callable[..., Awaitable[Principal]]:
    async def dependency(principal: Principal = Depends(current_principal)) -> Principal:
        if principal.restricted and not setup_allowed:
            what = "change your password" if principal.restricted == "password" else "enroll two-factor authentication"
            raise ApiError(403, f"finish account setup first: {what}", "setup_required")
        if not principal.role.allows(role):
            raise ApiError(403, f"requires the {role.value} role")
        return principal

    dependency.naco_role = role  # type: ignore[attr-defined]
    dependency.naco_setup_allowed = setup_allowed  # type: ignore[attr-defined]
    return dependency


# Shorthands used by the routes.
viewer = require(AdminRole.VIEWER)
operator = require(AdminRole.OPERATOR)
superuser = require(AdminRole.SUPERUSER)
