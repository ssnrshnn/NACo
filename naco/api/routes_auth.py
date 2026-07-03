"""Authentication endpoints: login, TOTP setup/verify/disable."""
from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from naco.api.auth import (
    create_access_token,
    dummy_verify_async,
    get_current_admin,
    hash_password,
    needs_rehash,
    verify_password_async,
)
from naco.api.schemas import LoginRequest, TokenResponse, TotpVerifyRequest
from naco.config import get_config
from naco.core.ratelimit import (
    check_account_lock,
    check_rate_limit,
    clear_account_failures,
    clear_failures,
    record_account_failure,
    record_failure,
)
from naco.core.utils import client_ip
from naco.db import get_db
from naco.db.models import AdminAuditLog, AdminUser

router = APIRouter(prefix="/api/v1", tags=["Auth"])


@router.post("/auth/login", response_model=TokenResponse)
async def login(body: LoginRequest, request: Request, db: AsyncSession = Depends(get_db)):
    """Authenticate an admin and issue a bearer JWT.

    Two abuse-resistance layers fire here:

    * **IP rate limit** — 5 failures per IP per 5 minutes; stops password
      sprays from a single source.
    * **Account lockout** — 10 failures per username per 5-minute window
      locks that account for 15 minutes regardless of source IP; stops
      distributed credential-stuffing.

    Both counters are cleared on a successful login. Both are checked
    *before* any DB / bcrypt work so a locked-out account can't be used to
    pin a worker to a 250 ms bcrypt cost.
    """
    ip = client_ip(request)
    if not check_rate_limit(ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed attempts. Try again in 5 minutes.",
        )
    if not check_account_lock(body.username):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Account temporarily locked due to repeated failed logins.",
        )

    cfg  = get_config()
    stmt = select(AdminUser).where(AdminUser.username == body.username, AdminUser.enabled)
    user = (await db.execute(stmt)).scalar_one_or_none()

    # Constant-time: run a bcrypt comparison on the "no such user" branch so
    # the response time of "unknown user" matches "known user, wrong password".
    if user is None:
        await dummy_verify_async(body.password)
        record_failure(ip)
        record_account_failure(body.username)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    if not await verify_password_async(body.password, user.password_hash):
        record_failure(ip)
        record_account_failure(body.username)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    # TOTP verification (if enabled for this user)
    if user.totp_secret:
        import pyotp
        if not body.totp_code:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="TOTP code required",
            )
        totp = pyotp.TOTP(user.totp_secret)
        if not totp.verify(body.totp_code, valid_window=1):
            record_failure(ip)
            record_account_failure(body.username)
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid TOTP code")

    clear_failures(ip)
    clear_account_failures(body.username)
    user.last_login = datetime.now(UTC)

    # Opportunistic re-hash: if this admin's stored hash is still at a cost
    # below the current baseline (e.g. someone bumped _BCRYPT_ROUNDS from
    # 12 → 13), upgrade it now while we have the cleartext. Silent to the
    # user; surfaces in the audit log under "password rehashed".
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(body.password)
        db.add(AdminAuditLog(
            admin_username=user.username, action="password.rehash",
            resource_type="admin_user", resource_id=str(user.id),
            detail="bcrypt cost upgrade",
        ))

    await db.commit()

    token = create_access_token(user.username)
    return TokenResponse(
        access_token=token,
        expires_in=cfg.server.token_expire_minutes * 60,
    )


@router.post("/auth/totp/setup")
async def totp_setup(
    db: AsyncSession = Depends(get_db),
    admin: AdminUser = Depends(get_current_admin),
):
    """Start TOTP enrollment: generate a secret, persist it as *pending*, return URI."""
    import pyotp

    secret = pyotp.random_base32()
    admin.pending_totp_secret = secret
    await db.commit()

    uri = pyotp.TOTP(secret).provisioning_uri(
        name=admin.username, issuer_name="NACo"
    )
    return {"provisioning_uri": uri}


@router.post("/auth/totp/verify")
async def totp_verify(
    body: TotpVerifyRequest,
    db: AsyncSession = Depends(get_db),
    admin: AdminUser = Depends(get_current_admin),
):
    """Verify a TOTP code and activate 2FA."""
    import pyotp

    pending = admin.pending_totp_secret
    if not pending:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "No pending TOTP enrollment — call POST /auth/totp/setup first",
        )
    totp = pyotp.TOTP(pending)
    if not totp.verify(body.code, valid_window=1):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Invalid TOTP code — scan the QR code and try again",
        )
    admin.totp_secret = pending
    admin.pending_totp_secret = None
    await db.commit()
    return {"status": "ok", "message": "TOTP enabled"}


@router.post("/auth/totp/disable")
async def totp_disable(
    db: AsyncSession = Depends(get_db),
    admin: AdminUser = Depends(get_current_admin),
):
    """Disable TOTP 2FA for the current admin."""
    admin.totp_secret = None
    admin.pending_totp_secret = None
    await db.commit()
    return {"status": "ok", "message": "TOTP disabled"}
