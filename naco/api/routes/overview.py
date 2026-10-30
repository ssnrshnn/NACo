"""Dashboard numbers, system status, the live event stream (SSE) and the
OpenAPI description of the API."""
from __future__ import annotations

import asyncio
import contextlib
import json
import os
from collections.abc import AsyncIterator
from datetime import datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from naco import __version__
from naco.api.deps import Principal, viewer
from naco.api.routes.admin import AuthLogOut
from naco.config import get_config
from naco.core import runtime
from naco.core.events import bus
from naco.core.timeutil import utcnow
from naco.db.engine import get_db, session_factory
from naco.db.models import (
    AdminSession,
    AdminUser,
    ApiToken,
    AuthLog,
    AuthResult,
    Device,
    DeviceStatus,
    GuestRegistration,
    NasClient,
    Policy,
    PolicyAction,
    RadiusSession,
    User,
)

router = APIRouter(tags=["overview"])


async def _count(db: AsyncSession, model: Any, *where: Any) -> int:
    return (await db.execute(select(func.count()).select_from(model).where(*where))).scalar_one()


class Counts(BaseModel):
    users: int
    devices: int
    pending_devices: int
    blocked_devices: int
    sessions: int
    guests: int


class HourBucket(BaseModel):
    hour: datetime
    accept: int
    reject: int


class ChecklistItem(BaseModel):
    key: str
    label: str
    done: bool


class Dashboard(BaseModel):
    counts: Counts
    last_24h: list[HourBucket]
    recent: list[AuthLogOut]
    checklist: list[ChecklistItem]


def _radius_status(now: datetime) -> str:
    last = runtime.aaa_last_request()
    if last is None:
        return "never"
    return "active" if now - last < timedelta(minutes=10) else "idle"


@router.get("/dashboard", response_model=Dashboard)
async def dashboard(principal: Principal = Depends(viewer), db: AsyncSession = Depends(get_db)) -> Dashboard:
    now = utcnow()
    start = (now - timedelta(hours=23)).replace(minute=0, second=0, microsecond=0)
    counts = Counts(
        users=await _count(db, User),
        devices=await _count(db, Device),
        pending_devices=await _count(db, Device, Device.status == DeviceStatus.PENDING),
        blocked_devices=await _count(db, Device, Device.status == DeviceStatus.BLOCKED),
        sessions=await _count(db, RadiusSession),
        guests=await _count(db, GuestRegistration, GuestRegistration.revoked_at.is_(None),
                            GuestRegistration.expires_at > now),
    )
    hour = func.strftime("%Y-%m-%d %H:00:00", AuthLog.timestamp)
    rows = (await db.execute(select(hour, AuthLog.result, func.count()).where(AuthLog.timestamp >= start)
                             .group_by(hour, AuthLog.result))).all()
    by_hour: dict[str, dict[str, int]] = {}
    for bucket, result, n in rows:
        by_hour.setdefault(bucket, {})[result.value if hasattr(result, "value") else str(result)] = n
    series = []
    for i in range(24):
        h = start + timedelta(hours=i)
        got = by_hour.get(h.strftime("%Y-%m-%d %H:00:00"), {})
        series.append(HourBucket(hour=h, accept=got.get(AuthResult.ACCEPT.value, 0),
                                 reject=got.get(AuthResult.REJECT.value, 0)))
    recent = (await db.execute(select(AuthLog).order_by(AuthLog.id.desc()).limit(15))).scalars()

    totp_done = True
    if principal.admin_id is not None:
        admin = await db.get(AdminUser, principal.admin_id)
        totp_done = bool(admin and admin.totp_secret)
    checklist = [
        ChecklistItem(key="nas", label="Add a switch or access point (NAS)",
                      done=await _count(db, NasClient) > 0),
        ChecklistItem(key="policy", label="Create a policy that permits access",
                      done=await _count(db, Policy, Policy.enabled.is_(True),
                                        Policy.action == PolicyAction.PERMIT) > 0),
        ChecklistItem(key="radius", label="Receive a first RADIUS request",
                      done=runtime.aaa_last_request() is not None or await _count(db, AuthLog) > 0),
        ChecklistItem(key="totp", label="Protect your account with two-factor authentication", done=totp_done),
    ]
    return Dashboard(counts=counts, last_24h=series,
                     recent=[AuthLogOut.model_validate(r, from_attributes=True) for r in recent],
                     checklist=checklist)


class SystemStatus(BaseModel):
    version: str
    started_at: datetime
    uptime_seconds: int
    timezone: str
    database_bytes: int
    radius: str
    radius_last_request: datetime | None
    settings: dict[str, Any]


@router.get("/openapi.json", include_in_schema=False)
async def openapi(request: Request, _: Principal = Depends(viewer)) -> JSONResponse:
    """The API description, for signed-in administrators and API tokens only."""
    return JSONResponse(request.app.openapi())


@router.get("/system", response_model=SystemStatus)
async def system(_: Principal = Depends(viewer)) -> SystemStatus:
    cfg = get_config()
    now = utcnow()
    size = 0
    for suffix in ("", "-wal"):
        with contextlib.suppress(OSError):
            size += os.path.getsize(cfg.database.path + suffix)
    settings = {  # behaviour only — the configuration file holds no secrets
        "server_name": cfg.server.name,
        "require_totp": cfg.security.require_totp,
        "session_idle_minutes": cfg.security.session_idle_minutes,
        "tacacs_enabled": cfg.tacacs.enabled,
        "portal_enabled": cfg.portal.enabled,
        "ldap_enabled": cfg.ldap.enabled,
        "ldap_servers": cfg.ldap.servers,
        "syslog": f"{cfg.syslog.protocol}://{cfg.syslog.host}:{cfg.syslog.port}" if cfg.syslog.enabled else None,
        "retention_days": cfg.retention.model_dump(),
    }
    return SystemStatus(version=__version__, started_at=runtime.STARTED_AT,
                        uptime_seconds=int((now - runtime.STARTED_AT).total_seconds()),
                        timezone=cfg.server.timezone, database_bytes=size, radius=_radius_status(now),
                        radius_last_request=runtime.aaa_last_request(), settings=settings)


async def _still_valid(principal: Principal) -> bool:
    async with session_factory()() as db:
        if principal.session_id is not None:
            row = (await db.execute(select(AdminSession.id).join(AdminUser, AdminSession.admin_id == AdminUser.id)
                                    .where(AdminSession.id == principal.session_id, AdminUser.enabled.is_(True),
                                           AdminSession.expires_at > utcnow()))).first()
            return row is not None
        if principal.token_id is not None:
            token = await db.get(ApiToken, principal.token_id)
            return token is not None and token.revoked_at is None
    return False


@router.get("/events")
async def events(request: Request, principal: Principal = Depends(viewer)) -> StreamingResponse:
    """Server-Sent Events: auth decisions, accounting, devices, audit."""
    async def stream() -> AsyncIterator[str]:
        async with bus.subscribe() as queue:
            yield "retry: 5000\n\n"
            checked = utcnow()
            while not await request.is_disconnected():
                if utcnow() - checked > timedelta(seconds=60):
                    if not await _still_valid(principal):
                        return
                    checked = utcnow()
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=15)
                except TimeoutError:
                    yield ": keep-alive\n\n"
                    continue
                payload = json.dumps({**event.data, "ts": event.ts.isoformat()}, default=str)
                yield f"event: {event.type.value}\ndata: {payload}\n\n"

    return StreamingResponse(stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})
