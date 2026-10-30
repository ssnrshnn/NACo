"""Periodic housekeeping: retention, expired admin sessions, stale RADIUS
sessions, guest expiry (handed to CoA re-evaluation) and session metrics."""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import delete, func, or_, select, text

from naco.config import get_config
from naco.core.metrics import REGISTRY
from naco.core.timeutil import utcnow
from naco.db.engine import session_factory
from naco.db.models import AdminSession, AuditLog, AuthLog, GuestRegistration, RadiusSession, TacacsLog
from naco.radius.reevaluate import reevaluator

log = logging.getLogger(__name__)

ACTIVE_SESSIONS = REGISTRY.gauge("naco_radius_sessions", "Active RADIUS sessions")
_CHUNK = 5000


@dataclass
class PassResult:
    pruned: int = 0
    guests_expired: int = 0


async def _prune(model: Any, column: Any, cutoff: datetime) -> int:
    """Delete in small transactions so RADIUS never waits behind retention."""
    total = 0
    while True:
        async with session_factory()() as db:
            ids = select(model.id).where(column < cutoff).limit(_CHUNK).scalar_subquery()
            result = await db.execute(delete(model).where(model.id.in_(ids)))
            await db.commit()
        removed: int = result.rowcount or 0  # type: ignore[attr-defined]
        total += removed
        if removed < _CHUNK:
            return total


async def maintenance_pass(since: datetime | None = None, now: datetime | None = None) -> PassResult:
    cfg = get_config()
    now = now or utcnow()
    result = PassResult()
    r = cfg.retention
    result.pruned += await _prune(AuthLog, AuthLog.timestamp, now - timedelta(days=r.auth_log_days))
    result.pruned += await _prune(TacacsLog, TacacsLog.timestamp, now - timedelta(days=r.tacacs_log_days))
    result.pruned += await _prune(AuditLog, AuditLog.timestamp, now - timedelta(days=r.audit_log_days))

    idle = timedelta(minutes=cfg.security.session_idle_minutes)
    async with session_factory()() as db:
        await db.execute(delete(AdminSession).where(
            or_(AdminSession.expires_at < now, AdminSession.last_seen_at < now - idle)))
        await db.execute(delete(RadiusSession).where(
            RadiusSession.updated_at < now - timedelta(hours=cfg.radius.stale_session_hours)))
        if since is not None:
            result.guests_expired = (await db.execute(select(func.count()).select_from(GuestRegistration).where(
                GuestRegistration.revoked_at.is_(None),
                GuestRegistration.expires_at > since, GuestRegistration.expires_at <= now,
            ))).scalar_one()
        ACTIVE_SESSIONS.set((await db.execute(select(func.count()).select_from(RadiusSession))).scalar_one())
        await db.execute(text("PRAGMA optimize"))
        await db.commit()

    if result.guests_expired:
        reevaluator.schedule("guest registrations expired")
    return result


async def run_maintenance(interval: float = 60.0) -> None:
    since: datetime | None = utcnow()
    while True:
        await asyncio.sleep(interval)
        now = utcnow()
        try:
            await maintenance_pass(since=since, now=now)
            since = now
        except Exception:
            log.exception("maintenance pass failed")
