"""Active session management + CoA disconnect endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, model_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from naco.api._audit import audit
from naco.api.auth import require_role
from naco.api.schemas import ActiveSessionOut, StatusResponse
from naco.config import get_config
from naco.core.utils import normalise_mac
from naco.db import get_db
from naco.db.models import ActiveSession, AdminRole, AdminUser, NasClient

router = APIRouter(prefix="/api/v1", tags=["Sessions"])


@router.get("/sessions", response_model=list[ActiveSessionOut])
async def active_sessions(
    skip: int = 0, limit: int = Query(100, le=500),
    db: AsyncSession = Depends(get_db),
    _:  AdminUser    = Depends(require_role(AdminRole.VIEWER)),
):
    rows = (await db.execute(
        select(ActiveSession).order_by(ActiveSession.started_at.desc()).offset(skip).limit(limit)
    )).scalars().all()
    return [ActiveSessionOut.model_validate(r) for r in rows]


@router.delete("/sessions/{session_id}", response_model=StatusResponse)
async def terminate_session(
    session_id: int,
    db: AsyncSession = Depends(get_db),
    _:  AdminUser    = Depends(require_role(AdminRole.OPERATOR)),
):
    sess = (await db.execute(select(ActiveSession).where(ActiveSession.id == session_id))).scalar_one_or_none()
    if not sess:
        raise HTTPException(404, "Session not found")

    # Send RADIUS Disconnect-Request (RFC 5176) to the NAS
    coa_msg = ""
    if sess.nas_ip and sess.session_id:
        nas_secret = await _get_nas_secret(sess.nas_ip, db)
        if nas_secret:
            from naco.radius.coa import disconnect_session
            result = await disconnect_session(
                session_id=str(sess.id),
                nas_ip=sess.nas_ip,
                acct_session_id=sess.session_id,
                username=sess.username,
                nas_secret=nas_secret,
            )
            coa_msg = f" CoA: {result['message']}"
        else:
            coa_msg = " CoA: no shared secret for NAS — disconnect not sent"

    await db.delete(sess)
    await db.commit()
    return StatusResponse(status="ok", message=f"Session removed.{coa_msg}")


class BulkDisconnect(BaseModel):
    """Filter for bulk CoA disconnect. At least one field must be set;
    ``all=true`` is the explicit opt-in for a full flush."""
    username: str | None = None
    mac_address: str | None = None
    nas_ip: str | None = None
    all: bool = False

    @model_validator(mode="after")
    def _at_least_one(self):
        if not (self.username or self.mac_address or self.nas_ip or self.all):
            raise ValueError(
                "set at least one of username / mac_address / nas_ip, "
                "or all=true to disconnect every session"
            )
        return self


@router.post("/sessions/disconnect", response_model=StatusResponse)
async def bulk_disconnect(
    body: BulkDisconnect,
    db: AsyncSession = Depends(get_db),
    admin: AdminUser = Depends(require_role(AdminRole.OPERATOR)),
):
    """Send RFC 5176 Disconnect-Requests to every session matching the filter.

    Session rows stay in the table — the NAS's Accounting-Stop clears them.
    """
    from naco.radius.coa_sync import disconnect_sessions

    stmt = select(ActiveSession)
    if body.username:
        stmt = stmt.where(ActiveSession.username == body.username)
    if body.mac_address:
        try:
            mac = normalise_mac(body.mac_address)
        except ValueError:
            raise HTTPException(422, "invalid MAC address")
        stmt = stmt.where(ActiveSession.mac_address == mac)
    if body.nas_ip:
        stmt = stmt.where(ActiveSession.nas_ip == body.nas_ip)

    sessions = (await db.execute(stmt)).scalars().all()
    if not sessions:
        return StatusResponse(status="ok", message="No matching active sessions")

    summary = await disconnect_sessions(list(sessions), db)
    await audit(
        db, admin, "DISCONNECT", "session", "bulk",
        f"filter={body.model_dump(exclude_none=True)} summary={summary}",
    )
    await db.commit()
    return StatusResponse(
        status="ok",
        message=(f"Disconnect sent to {summary['total']} session(s): "
                 f"{summary['acked']} acked, {summary['failed']} failed, "
                 f"{summary['skipped']} skipped"),
    )


async def _get_nas_secret(nas_ip: str, db: AsyncSession) -> str:
    """Look up the shared secret for a NAS IP from DB, then fall back to config."""
    c = (await db.execute(
        select(NasClient).where(NasClient.ip_address == nas_ip, NasClient.enabled)
    )).scalar_one_or_none()
    if c:
        return c.secret
    cfg = get_config()
    for client in cfg.radius.clients:
        if client.address == nas_ip:
            return client.secret
    return ""
