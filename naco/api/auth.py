"""JWT-based authentication for the REST API and Admin UI.

Accepts either:
  • an ``Authorization: Bearer <jwt>`` header — for external API clients
    (signed with ``server.api_secret``), or
  • a ``naco_session`` HttpOnly cookie — for browser AJAX from the admin UI
    (signed with ``server.session_secret``).

Both tokens are HS256 JWTs whose ``sub`` claim is the admin username. The two
secrets are kept independent so leaking one does not leak the other (see
:func:`get_current_admin`).

Role-based access control
-------------------------
On top of authentication, the :func:`require_role` factory returns a FastAPI
dependency that also checks the calling admin's ``role`` against a minimum
rank. Routes that change state should declare the lowest acceptable role:

    @router.post("/policies",
                 dependencies=[Depends(require_role(AdminRole.OPERATOR))])
    async def create_policy(...): ...

See :class:`naco.db.models.AdminRole` for the rank ordering.
"""
from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

import bcrypt
import jwt
from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from naco.config import get_config
from naco.db import get_db
from naco.db.models import AdminRole, AdminUser, ApiToken

_ALGORITHM = "HS256"
_SESSION_COOKIE = "naco_session"

# Static API tokens (naco.db.models.ApiToken) are distinguishable from JWTs
# by this prefix, so `Authorization: Bearer` carries either interchangeably.
API_TOKEN_PREFIX = "naco_"


def hash_api_token(raw: str) -> str:
    """Deterministic digest for token lookup. SHA-256 (not bcrypt) is fine
    here: tokens are 256-bit random values, not human passwords."""
    return hashlib.sha256(raw.encode()).hexdigest()


# bcrypt cost factor for *new* hashes. Existing hashes keep working at
# whatever cost they were generated with — ``checkpw`` reads the cost from
# the stored hash. ``nacoctl rehash-passwords`` (Phase 1.10) upgrades old
# hashes on the next successful login.
_BCRYPT_ROUNDS = 13


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=_BCRYPT_ROUNDS)).decode()


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode(), hashed.encode())
    except ValueError:
        # Not a bcrypt hash — e.g. the "!oidc!…" unusable marker on
        # SSO-provisioned admins. Local login must simply fail, not 500.
        return False


async def verify_password_async(plain: str, hashed: str) -> bool:
    """Thread-offloaded :func:`verify_password`.

    bcrypt at cost 13 burns 300–500 ms of CPU. Async request handlers and the
    RADIUS/TACACS+ coroutines all share one event loop — verifying inline
    would freeze every other connection for the duration, and caps
    authentication throughput at ~2–3/s. Always use this variant from
    ``async def`` code.
    """
    import asyncio
    return await asyncio.to_thread(verify_password, plain, hashed)


async def dummy_verify_async(password: str = "") -> bool:
    """Thread-offloaded :func:`dummy_verify` — see :func:`verify_password_async`."""
    import asyncio
    return await asyncio.to_thread(dummy_verify, password)


def needs_rehash(hashed: str, target_cost: int = _BCRYPT_ROUNDS) -> bool:
    """Return True if *hashed* was generated at a cost below *target_cost*.

    Used for opportunistic re-hash on successful login — when this returns
    True, the caller has the cleartext password (since we just verified it)
    and can call :func:`hash_password` to upgrade the stored hash to the
    new baseline cost. The user never sees this happen.

    Format detail: bcrypt hashes look like ``$2b$NN$...`` where ``NN`` is
    the cost factor as two ASCII digits. Anything that doesn't match the
    format returns False so we never trigger a re-hash on a corrupt or
    non-bcrypt value (those need explicit operator attention).
    """
    if not hashed or len(hashed) < 7 or hashed[0] != "$":
        return False
    parts = hashed.split("$", 4)
    # parts == ['', '2b', 'NN', '<rest>'] when well-formed.
    if len(parts) < 4:
        return False
    try:
        cost = int(parts[2])
    except ValueError:
        return False
    return cost < target_cost


# ---------------------------------------------------------------------------
# Constant-time fallback for the "user not found" path
# ---------------------------------------------------------------------------
#
# Every authentication call site (TACACS+ ASCII login, EAP REST hook, REST
# ``/auth/login``, Web UI ``POST /login``) used to short-circuit when the
# username was unknown — returning instantly. Bcrypt verification on a real
# user takes ~250 ms at cost 13, which is a trivial username-enumeration
# oracle. ``dummy_verify`` performs an equivalent-cost bcrypt against a
# constant hash so the "user missing" path costs the same as the "user
# present, wrong password" path.
#
# The hash below is the bcrypt of the literal string ``"naco_dummy"`` at
# cost 13 — generated once at import time so we don't pay the cost on
# every call. ``__BOGUS_HASH`` is intentionally not a valid password for
# any account.
__BOGUS_HASH: str = ""


def _ensure_bogus_hash() -> str:
    """Return (lazily) a stable bcrypt hash used by :func:`dummy_verify`."""
    global __BOGUS_HASH
    if not __BOGUS_HASH:
        __BOGUS_HASH = bcrypt.hashpw(b"naco_dummy", bcrypt.gensalt(rounds=_BCRYPT_ROUNDS)).decode()
    return __BOGUS_HASH


def dummy_verify(password: str = "") -> bool:
    """Run a bcrypt comparison against a constant hash and always return False.

    Use this on the "user not found" branch of any auth path to keep the
    timing of "unknown user" and "known user, wrong password" indistinguishable
    to a remote attacker. The call is intentionally synchronous and CPU-bound
    so the timing matches a real :func:`verify_password` call exactly.
    """
    try:
        bcrypt.checkpw((password or "x").encode(), _ensure_bogus_hash().encode())
    except Exception:
        # Hardening: even if the bogus hash somehow fails to parse, never
        # let this function raise — the goal is timing parity, not correctness.
        pass
    return False


def create_access_token(subject: str, expire_minutes: int | None = None) -> str:
    """Issue a Bearer JWT signed with the API secret."""
    cfg = get_config()
    minutes = expire_minutes or cfg.server.token_expire_minutes
    expire  = datetime.now(UTC) + timedelta(minutes=minutes)
    payload = {"sub": subject, "exp": expire, "iat": datetime.now(UTC), "kind": "api"}
    return jwt.encode(payload, cfg.server.api_secret, algorithm=_ALGORITHM)


def _decode_with(secret: str, token: str) -> dict | None:
    try:
        return jwt.decode(token, secret, algorithms=[_ALGORITHM])
    except jwt.PyJWTError:
        return None


async def get_current_admin(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> AdminUser:
    """Authenticate via either an `Authorization: Bearer` JWT (signed with
    `api_secret`) OR the `naco_session` cookie (signed with `session_secret`).

    Splitting the two secrets means compromising the session cookie does NOT
    leak the ability to mint long-lived API tokens (and vice-versa).
    """
    cfg = get_config()
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    payload: dict | None = None
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        token = auth.split(" ", 1)[1].strip()
        if token.startswith(API_TOKEN_PREFIX):
            return await _admin_from_api_token(token, db, credentials_exception)
        if token:
            payload = _decode_with(cfg.server.api_secret, token)
    if payload is None:
        cookie = request.cookies.get(_SESSION_COOKIE)
        if cookie:
            payload = _decode_with(cfg.server.session_secret, cookie)

    if not payload:
        raise credentials_exception
    username = payload.get("sub")
    if not username:
        raise credentials_exception

    stmt = select(AdminUser).where(AdminUser.username == username, AdminUser.enabled)
    user = (await db.execute(stmt)).scalar_one_or_none()
    if user is None:
        raise credentials_exception
    return user


async def _admin_from_api_token(
    raw: str, db: AsyncSession, credentials_exception: HTTPException
) -> AdminUser:
    """Resolve a static ``naco_…`` token to a transient admin principal.

    The returned object is *not* persisted — it exists so ``require_role``
    and the audit trail (username ``token:<name>``) work unchanged. The
    ``via_api_token`` marker lets the token-management routes refuse
    tokens as a way to mint more tokens.
    """
    row = (await db.execute(
        select(ApiToken).where(ApiToken.token_hash == hash_api_token(raw), ApiToken.enabled)
    )).scalar_one_or_none()
    if row is None:
        raise credentials_exception

    now = datetime.now(UTC)
    if row.expires_at is not None:
        expires = row.expires_at
        if expires.tzinfo is None:  # SQLite returns naive datetimes
            expires = expires.replace(tzinfo=UTC)
        if expires <= now:
            raise credentials_exception

    # Stamp last_used_at at most once a minute — an audit aid, not a write
    # per request.
    last = row.last_used_at
    if last is not None and last.tzinfo is None:
        last = last.replace(tzinfo=UTC)
    if last is None or (now - last) > timedelta(minutes=1):
        row.last_used_at = now
        await db.commit()

    admin = AdminUser(
        username=f"token:{row.name}", password_hash="!",
        role=row.role, is_superuser=False, enabled=True,
    )
    admin.via_api_token = True
    return admin


# ---------------------------------------------------------------------------
# Role-based access control
# ---------------------------------------------------------------------------

# Numeric rank for role comparison — higher = more privileged. We don't use
# `Enum` ordering because Python's enum is unordered by default and we want
# to be explicit about the hierarchy.
_ROLE_RANK: dict[str, int] = {
    AdminRole.VIEWER.value:    1,
    AdminRole.OPERATOR.value:  2,
    AdminRole.SUPERUSER.value: 3,
}


def _rank(role: str | AdminRole | None) -> int:
    """Return the numeric rank of *role* (unknown roles get the lowest rank)."""
    if role is None:
        return 0
    if isinstance(role, AdminRole):
        role = role.value
    return _ROLE_RANK.get(role, 0)


def has_role(admin: AdminUser, minimum: AdminRole) -> bool:
    """Return ``True`` iff *admin* has at least the *minimum* role.

    Honours the back-compat ``is_superuser`` flag — a row migrated from
    pre-Phase-1 will have ``role=OPERATOR`` and ``is_superuser=True``; we
    treat such rows as ``SUPERUSER`` even before the next write rewrites
    the role.
    """
    if admin.is_superuser:
        return True
    return _rank(getattr(admin, "role", None)) >= _rank(minimum)


def require_role(minimum: AdminRole):
    """FastAPI dependency factory: require at least *minimum* role.

    Usage::

        @router.delete("/policies/{policy_id}",
                       dependencies=[Depends(require_role(AdminRole.OPERATOR))])
        async def delete_policy(...): ...

    On insufficient privilege, raises 403 with a clear message. Authentication
    failures still raise 401 from :func:`get_current_admin`.
    """
    async def _checker(
        admin: AdminUser = Depends(get_current_admin),
    ) -> AdminUser:
        if not has_role(admin, minimum):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient role: requires {minimum.value} or higher",
            )
        return admin

    return _checker


# Convenience handles for the most common decorations.
require_viewer    = require_role(AdminRole.VIEWER)
require_operator  = require_role(AdminRole.OPERATOR)
require_superuser = require_role(AdminRole.SUPERUSER)
