"""Live RADIUS sessions, guest registrations, and disconnecting them (CoA)."""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Query, Response
from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from naco.api.audit import AuditTrail, audit_trail
from naco.api.common import Page, Paging, get_or_404, like
from naco.api.deps import Principal, operator, viewer
from naco.api.errors import ApiError
from naco.core.netutils import normalize_mac, parse_ip
from naco.core.timeutil import utcnow
from naco.db.engine import get_db
from naco.db.models import GuestRegistration, NasClient, RadiusSession
from naco.radius.coa import Outcome
from naco.radius.reevaluate import reevaluator, send_disconnect

router = APIRouter(tags=["sessions & guests"])


# ── RADIUS sessions ────────────────────────────────────────────────────────

class SessionOut(BaseModel):
    id: int
    nas_ip: str
    nas_name: str
    acct_session_id: str
    username: str
    mac_address: str
    framed_ip: str
    ssid: str
    auth_method: str
    policy_name: str
    vlan: int | None
    started_at: datetime
    updated_at: datetime
    input_octets: int
    output_octets: int
    session_time: int


class DisconnectResult(BaseModel):
    requested: int
    acked: int
    failed: int
    skipped: int


class BulkDisconnect(BaseModel):
    username: str | None = Field(None, max_length=64)
    mac: str | None = None
    nas_ip: str | None = None
    all: bool = False

    @model_validator(mode="after")
    def _one_filter(self) -> BulkDisconnect:
        if not (self.all or self.username or self.mac or self.nas_ip):
            raise ValueError("give a username, mac or nas_ip — or all: true")
        return self


@router.get("/sessions", response_model=Page[SessionOut])
async def list_sessions(q: str = Query("", max_length=64), nas_ip: str | None = None,
                        paging: Paging = Depends(), _: Principal = Depends(viewer),
                        db: AsyncSession = Depends(get_db)) -> Page[SessionOut]:
    names = {n.ip_address: n.name for n in (await db.execute(select(NasClient))).scalars()}
    query = select(RadiusSession).order_by(RadiusSession.updated_at.desc())
    if nas_ip:
        query = query.where(RadiusSession.nas_ip == nas_ip)
    if q:
        term = like(normalize_mac(q) or q.lower())
        query = query.where(or_(RadiusSession.username.ilike(term, escape="\\"),
                                RadiusSession.mac_address.ilike(term, escape="\\"),
                                RadiusSession.framed_ip.ilike(term, escape="\\")))
    rows, total = await paging.fetch(db, query)
    return Page(items=[SessionOut(nas_name=names.get(s.nas_ip, ""), **{
        k: getattr(s, k) for k in SessionOut.model_fields if k != "nas_name"}) for s in rows],
        total=total, page=paging.page, per_page=paging.per_page)


async def _disconnect(audit: AuditTrail, sessions: list[RadiusSession]) -> DisconnectResult:
    nas_by_ip = {n.ip_address: n for n in (await audit.db.execute(select(NasClient))).scalars()}
    # End the transaction before waiting on NASes: SQLite transactions hold
    # the write lock, and CoA can take seconds per unreachable NAS.
    await audit.db.commit()
    result = DisconnectResult(requested=len(sessions), acked=0, failed=0, skipped=0)
    targets = []
    for s in sessions:
        nas = nas_by_ip.get(s.nas_ip)
        if nas is None:
            result.skipped += 1
        else:
            targets.append((s, nas))
    gate = asyncio.Semaphore(20)

    async def one(session: RadiusSession, nas: NasClient) -> Outcome:
        async with gate:
            return (await send_disconnect(session, nas)).outcome

    outcomes = await asyncio.gather(*(one(s, n) for s, n in targets))
    result.acked = sum(o is Outcome.ACK for o in outcomes)
    result.failed = len(outcomes) - result.acked
    return result


@router.post("/sessions/{session_id}/disconnect", response_model=DisconnectResult)
async def disconnect_one(session_id: int, _: Principal = Depends(operator),
                         audit: AuditTrail = Depends(audit_trail)) -> DisconnectResult:
    session = await get_or_404(audit.db, RadiusSession, session_id, "session")
    result = await _disconnect(audit, [session])
    audit.record("session.disconnect", "session", session.acct_session_id,
                 session.username or session.mac_address, result.model_dump())
    await audit.db.commit()
    return result


@router.post("/sessions/disconnect", response_model=DisconnectResult)
async def disconnect_many(body: BulkDisconnect, _: Principal = Depends(operator),
                          audit: AuditTrail = Depends(audit_trail)) -> DisconnectResult:
    query = select(RadiusSession)
    if body.username:
        query = query.where(RadiusSession.username == body.username.lower())
    if body.mac:
        mac = normalize_mac(body.mac)
        if mac is None:
            raise ApiError(422, "not a MAC address")
        query = query.where(RadiusSession.mac_address == mac)
    if body.nas_ip:
        query = query.where(RadiusSession.nas_ip == (parse_ip(body.nas_ip) or body.nas_ip))
    sessions = list((await audit.db.execute(query)).scalars())
    result = await _disconnect(audit, sessions)
    audit.record("session.bulk_disconnect", "session", "", "",
                 {"filter": body.model_dump(exclude_none=True), **result.model_dump()})
    await audit.db.commit()
    return result


# ── guests ─────────────────────────────────────────────────────────────────

class GuestOut(BaseModel):
    id: int
    mac_address: str
    full_name: str
    email: str
    nas_ip: str
    client_ip: str
    created_by: str
    created_at: datetime
    expires_at: datetime
    revoked_at: datetime | None
    active: bool


class GuestIn(BaseModel):
    mac_address: str
    hours: int = Field(8, ge=1, le=24 * 30)
    full_name: str = Field("", max_length=128)
    email: str = Field("", max_length=128)

    @field_validator("mac_address")
    @classmethod
    def _mac(cls, v: str) -> str:
        mac = normalize_mac(v)
        if mac is None:
            raise ValueError("not a MAC address")
        return mac


def guest_out(g: GuestRegistration, now: datetime) -> GuestOut:
    return GuestOut(**{k: getattr(g, k) for k in GuestOut.model_fields if k != "active"},
                    active=g.revoked_at is None and g.expires_at > now)


@router.get("/guests", response_model=Page[GuestOut])
async def list_guests(active: bool | None = None, paging: Paging = Depends(), _: Principal = Depends(viewer),
                      db: AsyncSession = Depends(get_db)) -> Page[GuestOut]:
    now = utcnow()
    query = select(GuestRegistration).order_by(GuestRegistration.created_at.desc())
    if active is True:
        query = query.where(GuestRegistration.revoked_at.is_(None), GuestRegistration.expires_at > now)
    elif active is False:
        query = query.where(or_(GuestRegistration.revoked_at.is_not(None), GuestRegistration.expires_at <= now))
    rows, total = await paging.fetch(db, query)
    return Page(items=[guest_out(g, now) for g in rows], total=total, page=paging.page, per_page=paging.per_page)


@router.post("/guests", response_model=GuestOut, status_code=201)
async def add_guest(body: GuestIn, principal: Principal = Depends(operator),
                    audit: AuditTrail = Depends(audit_trail)) -> GuestOut:
    now = utcnow()
    guest = GuestRegistration(mac_address=body.mac_address, full_name=body.full_name, email=body.email,
                              created_by=principal.username[:64], created_at=now,
                              expires_at=now + timedelta(hours=body.hours))
    audit.db.add(guest)
    await audit.db.flush()
    audit.record("guest.create", "guest", guest.id, guest.mac_address, {"hours": body.hours})
    await audit.db.commit()
    reevaluator.schedule(f"guest {guest.mac_address} registered")
    return guest_out(guest, now)


@router.delete("/guests/{guest_id}", status_code=204)
async def revoke_guest(guest_id: int, _: Principal = Depends(operator),
                       audit: AuditTrail = Depends(audit_trail)) -> Response:
    guest = await get_or_404(audit.db, GuestRegistration, guest_id, "guest registration")
    if guest.revoked_at is None:
        guest.revoked_at = utcnow()
        audit.record("guest.revoke", "guest", guest.id, guest.mac_address)
        await audit.db.commit()
        reevaluator.schedule(f"guest {guest.mac_address} revoked")
    return Response(status_code=204)
