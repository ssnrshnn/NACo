"""Dashboard summary + guest session management endpoints."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from naco.api.auth import require_role
from naco.api.schemas import DashboardStats, GuestSessionCreate, GuestSessionOut
from naco.db import get_db
from naco.db.models import (
    ActiveSession,
    AdminRole,
    AdminUser,
    AuthLog,
    AuthResult,
    Device,
    GuestSession,
    User,
)

router = APIRouter(prefix="/api/v1")


@router.get("/dashboard", response_model=DashboardStats, tags=["Dashboard"])
async def dashboard_stats(
    db: AsyncSession = Depends(get_db),
    _:  AdminUser    = Depends(require_role(AdminRole.VIEWER)),
):
    today_start = datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)

    total_users    = (await db.execute(select(func.count()).select_from(User))).scalar_one()
    total_devices  = (await db.execute(select(func.count()).select_from(Device))).scalar_one()
    active_sess    = (await db.execute(select(func.count()).select_from(ActiveSession))).scalar_one()
    auth_today     = (await db.execute(
        select(func.count()).select_from(AuthLog).where(AuthLog.timestamp >= today_start)
    )).scalar_one()
    auth_success_today = (await db.execute(
        select(func.count()).select_from(AuthLog).where(
            AuthLog.timestamp >= today_start, AuthLog.result == AuthResult.SUCCESS
        )
    )).scalar_one()
    auth_fail_today = (await db.execute(
        select(func.count()).select_from(AuthLog).where(
            AuthLog.timestamp >= today_start, AuthLog.result == AuthResult.FAILURE
        )
    )).scalar_one()
    guest_active = (await db.execute(
        select(func.count()).select_from(GuestSession).where(
            GuestSession.active,
            GuestSession.expires_at > datetime.now(UTC),
        )
    )).scalar_one()

    return DashboardStats(
        total_users=total_users, total_devices=total_devices,
        active_sessions=active_sess, auth_today=auth_today,
        auth_success_today=auth_success_today, auth_failure_today=auth_fail_today,
        guest_sessions_active=guest_active,
    )


@router.post("/guests", response_model=GuestSessionOut, status_code=201, tags=["Guests"])
async def create_guest_session(
    body: GuestSessionCreate,
    db:   AsyncSession = Depends(get_db),
    _:    AdminUser    = Depends(require_role(AdminRole.OPERATOR)),
):
    from naco.core.utils import generate_token, normalise_mac, utcnow

    mac = ""
    if body.mac_address:
        try:
            mac = normalise_mac(body.mac_address)
        except ValueError:
            raise HTTPException(400, "Invalid MAC address format")

    expires_at = utcnow() + timedelta(hours=max(1, min(body.duration_hours, 168)))
    session = GuestSession(
        token       = generate_token(32),
        full_name   = body.full_name.strip()[:128],
        email       = (body.email or "").strip().lower()[:128],
        mac_address = mac,
        ip_address  = "",
        expires_at  = expires_at,
    )
    db.add(session)
    await db.commit()
    await db.refresh(session)
    return GuestSessionOut.model_validate(session)
