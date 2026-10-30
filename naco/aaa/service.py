"""AAA decisions for FreeRADIUS.

FreeRADIUS owns the RADIUS protocol; NACo answers four questions:

* ``lookup_client`` — is this source IP a NAS, and with which secret?
* ``authenticate`` — are these credentials valid? (PAP, TTLS-PAP, PEAP-GTC)
* ``authorize`` — given who/what this is, accept and with which VLAN?
  Called for every method, after authentication, so EAP-TLS and MAB go
  through exactly the same rules.
* ``accounting`` — keep the session table in step with the NAS.

Every authorization writes one ``auth_logs`` row; failed credentials are
logged by ``authenticate`` (authorization never runs for them).
"""
from __future__ import annotations

import logging
import time
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import delete, exists, select
from sqlalchemy.ext.asyncio import AsyncSession

from naco.aaa.rlm import Attrs
from naco.aaa.subject import subject_context
from naco.auth.identity import UserInfo, authenticate_user, canonical_username, load_user
from naco.core.events import Event, EventType, bus
from naco.core.metrics import REGISTRY
from naco.core.netutils import normalize_mac, parse_called_station, parse_ip
from naco.core.oui import vendor_for
from naco.core.ratelimit import GuessGuard
from naco.core.timeutil import utcnow
from naco.db.engine import session_factory
from naco.db.models import (
    AuthLog,
    AuthResult,
    Device,
    GuestRegistration,
    NasClient,
    RadiusSession,
)
from naco.policy import engine as policy_engine
from naco.policy.context import AUTH_METHODS, Decision, deny

log = logging.getLogger(__name__)
trail = logging.getLogger("naco.trail")

DECISIONS = REGISTRY.counter("naco_radius_decisions_total", "Authorization decisions", ["method", "result"])
CREDENTIAL_FAILURES = REGISTRY.counter(
    "naco_radius_credential_failures_total", "Rejected credentials", ["reason"]
)
ACCOUNTING = REGISTRY.counter("naco_radius_accounting_total", "Accounting requests", ["status"])

# Slows password guessing through EAP/PAP per identity and station (see GuessGuard).
_guesses = GuessGuard()

# Password methods are authorized only for a name whose password NACo itself
# accepted moments before, from the same NAS and station. FreeRADIUS tells
# NACo which identity to decide on; this keeps a mistake in that hand-over
# (an inner method NACo never saw, a nested tunnel) from becoming an accept.
PASSWORD_METHODS = frozenset({"PAP", "EAP-TTLS", "PEAP"})
_VERIFIED_SECONDS = 120.0
_verified: OrderedDict[tuple[str, str, str], float] = OrderedDict()
_MAX_VERIFIED = 50_000


def reset_failure_tracking() -> None:
    _guesses.clear()
    _verified.clear()


def _verified_key(username: str, req: RequestInfo) -> tuple[str, str, str]:
    return username, req.nas_ip, req.mac or req.calling_station


def _remember_verified(key: tuple[str, str, str]) -> None:
    _verified[key] = time.monotonic()
    _verified.move_to_end(key)
    while len(_verified) > _MAX_VERIFIED:
        _verified.popitem(last=False)


def _recently_verified(key: tuple[str, str, str]) -> bool:
    at = _verified.get(key)
    return at is not None and time.monotonic() - at <= _VERIFIED_SECONDS


# ---------------------------------------------------------------------------
# Dynamic clients
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ClientDef:
    name: str
    ip: str
    secret: str
    require_message_authenticator: bool


async def lookup_client(ip: str) -> ClientDef | None:
    addr = parse_ip(ip)
    if addr is None:
        return None
    async with session_factory()() as db:
        nas = (await db.execute(
            select(NasClient).where(NasClient.ip_address == addr, NasClient.enabled.is_(True))
        )).scalar_one_or_none()
    if nas is None:
        return None
    return ClientDef(nas.name, addr, nas.secret, nas.require_message_authenticator)


# ---------------------------------------------------------------------------
# Request attributes
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RequestInfo:
    method: str | None
    nas_ip: str
    mac: str | None
    ssid: str | None
    calling_station: str


def _request_info(attrs: Attrs) -> RequestInfo:
    method = attrs.get("NACo-Auth-Method")
    calling = attrs.get("Calling-Station-Id") or ""
    _, ssid = parse_called_station(attrs.get("Called-Station-Id"))
    return RequestInfo(
        method=method if method in AUTH_METHODS else None,
        # Set by our FreeRADIUS config from the packet's source address;
        # NAS-IP-Address is only what the NAS claims and is not trusted.
        nas_ip=parse_ip(attrs.get("NACo-NAS-IP")) or "",
        mac=normalize_mac(calling),
        ssid=ssid,
        calling_station=calling[:64],
    )


def _identity(attrs: Attrs, method: str) -> str:
    if method == "EAP-TLS":
        raw = attrs.get("TLS-Client-Cert-Common-Name")
    elif method in ("EAP-TTLS", "PEAP"):
        raw = attrs.get("NACo-Inner-Identity")  # never the (anonymous) outer identity
    else:
        raw = attrs.get("User-Name")
    return canonical_username(raw)


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def _log_decision(db: AsyncSession, *, req: RequestInfo, method: str, username: str, nas_name: str,
                  result: AuthResult, reason: str, decision: Decision | None = None) -> AuthLog:
    row = AuthLog(
        username=username[:64], mac_address=req.mac or "", nas_ip=req.nas_ip, nas_name=nas_name[:64],
        ssid=(req.ssid or "")[:64], auth_method=method[:16], result=result, reason=reason[:255],
        policy_name=(decision.policy_name if decision else "")[:128],
        vlan=decision.vlan if decision and decision.accepted else None,
        decision_digest=decision.digest() if decision and decision.accepted else "",
    )
    db.add(row)
    return row


def _announce(row: AuthLog) -> None:
    data = {
        "result": row.result.value, "username": row.username, "mac": row.mac_address,
        "nas": row.nas_name or row.nas_ip, "ssid": row.ssid, "method": row.auth_method,
        "reason": row.reason, "policy": row.policy_name, "vlan": row.vlan,
    }
    bus.publish(Event(EventType.AUTH, data))
    DECISIONS.inc(method=row.auth_method or "unknown", result=row.result.value)
    trail.info(
        "radius %s user=%s mac=%s nas=%s ssid=%s method=%s policy=%s vlan=%s reason=%s",
        row.result.value, row.username or "-", row.mac_address or "-", row.nas_name or row.nas_ip or "-",
        row.ssid or "-", row.auth_method or "-", row.policy_name or "-", row.vlan or "-", row.reason,
    )


# ---------------------------------------------------------------------------
# Authentication (credentials only)
# ---------------------------------------------------------------------------

async def authenticate(attrs: Attrs) -> bool:
    req = _request_info(attrs)
    method = req.method or "PAP"
    raw_name = attrs.get("User-Name") or ""
    key = canonical_username(raw_name) or raw_name[:64]

    source = req.mac or req.calling_station or req.nas_ip
    if _guesses.delay_for(key, source) > 0:
        ok, reason, username = False, "too many failed attempts — slowed down", key
    else:
        result = await authenticate_user(raw_name, attrs.get("User-Password") or "")
        ok, reason, username = result.ok, result.reason, result.username
        if ok:
            _guesses.success(key, source)
        else:
            _guesses.failure(key, source)

    if ok:
        if verified := canonical_username(raw_name):
            _remember_verified(_verified_key(verified, req))
        return True
    CREDENTIAL_FAILURES.inc(reason=reason.split(" —")[0])
    async with session_factory()() as db:
        nas = await _nas(db, req.nas_ip)
        row = _log_decision(db, req=req, method=method, username=username, nas_name=nas.name if nas else "",
                            result=AuthResult.REJECT, reason=reason)
        await db.commit()
    _announce(row)
    return False


# ---------------------------------------------------------------------------
# Authorization (every method)
# ---------------------------------------------------------------------------

async def _nas(db: AsyncSession, ip: str) -> NasClient | None:
    if not ip:
        return None
    return (await db.execute(select(NasClient).where(NasClient.ip_address == ip))).scalar_one_or_none()


async def guest_active(db: AsyncSession, mac: str, now: datetime) -> bool:
    return bool((await db.execute(select(exists().where(
        GuestRegistration.mac_address == mac,
        GuestRegistration.revoked_at.is_(None),
        GuestRegistration.expires_at > now,
    )))).scalar())


async def _see_device(db: AsyncSession, mac: str, nas_ip: str, username: str, now: datetime) -> Device:
    device = (await db.execute(select(Device).where(Device.mac_address == mac))).scalar_one_or_none()
    if device is None:
        device = Device(mac_address=mac, vendor=vendor_for(mac), first_seen=now, last_seen=now,
                        last_nas_ip=nas_ip, last_username=username[:64])
        db.add(device)
        await db.flush()
        bus.publish(Event(EventType.DEVICE, {"mac": mac, "vendor": device.vendor, "new": True}))
    else:
        device.last_seen = now
        device.last_nas_ip = nas_ip
        if username:
            device.last_username = username[:64]
    return device


async def authorize(attrs: Attrs) -> Decision:
    req = _request_info(attrs)
    method = req.method or ""
    now = utcnow()
    async with session_factory()() as db:
        nas = await _nas(db, req.nas_ip)
        username = "" if method == "MAB" else (_identity(attrs, method) if method else "")
        decision = await _decide(db, attrs, req, nas, username, now)
        row = _log_decision(
            db, req=req, method=method, username=username, nas_name=nas.name if nas else "",
            result=AuthResult.ACCEPT if decision.accepted else AuthResult.REJECT,
            reason=decision.reason, decision=decision,
        )
        await db.commit()
    _announce(row)
    return decision


async def _decide(db: AsyncSession, attrs: Attrs, req: RequestInfo, nas: NasClient | None,
                  username: str, now: datetime) -> Decision:
    if req.method is None:
        return deny("unknown authentication method")
    if nas is None or not nas.enabled:
        return deny("unknown or disabled NAS")
    if req.method == "MAB" and (req.mac is None or normalize_mac(attrs.get("User-Name")) != req.mac):
        return deny("not a valid MAB request")

    user: UserInfo | None = None
    if req.method != "MAB" and username:
        found = await load_user(db, username)
        user = found[0] if found else None
    device = await _see_device(db, req.mac, req.nas_ip, username, now) if req.mac else None
    is_guest = req.mac is not None and await guest_active(db, req.mac, now)

    subject = subject_context(
        method=req.method, username=username, user=user, mac=req.mac, device=device, is_guest=is_guest,
        nas_name=nas.name, nas_ip=req.nas_ip, ssid=req.ssid, now=now,
    )
    if isinstance(subject, Decision):
        return subject
    if req.method in PASSWORD_METHODS and not _recently_verified(_verified_key(username, req)):
        return deny("password was not verified by NACo")
    return await policy_engine.evaluate(db, subject)


# ---------------------------------------------------------------------------
# Accounting
# ---------------------------------------------------------------------------

_STATUS = {
    "1": "start", "2": "stop", "3": "interim-update", "7": "accounting-on", "8": "accounting-off",
    "start": "start", "stop": "stop", "interim-update": "interim-update", "alive": "interim-update",
    "accounting-on": "accounting-on", "accounting-off": "accounting-off",
}


def _octets(attrs: Attrs, base: str, giga: str) -> int | None:
    low = attrs.int(base)
    if low is None:
        return None
    return (attrs.int(giga) or 0) * 2**32 + low


async def _latest_accept(db: AsyncSession, nas_ip: str, mac: str | None, username: str) -> AuthLog | None:
    query = select(AuthLog).where(AuthLog.nas_ip == nas_ip, AuthLog.result == AuthResult.ACCEPT,
                                  AuthLog.timestamp > utcnow() - timedelta(hours=24))
    if mac:
        query = query.where(AuthLog.mac_address == mac)
    elif username:
        query = query.where(AuthLog.username == username)
    else:
        return None
    return (await db.execute(query.order_by(AuthLog.id.desc()).limit(1))).scalar_one_or_none()


async def accounting(attrs: Attrs) -> None:
    status = _STATUS.get((attrs.get("Acct-Status-Type") or "").lower())
    req = _request_info(attrs)
    ACCOUNTING.inc(status=status or "other")
    if status is None or not req.nas_ip:
        return

    async with session_factory()() as db:
        if status in ("accounting-on", "accounting-off"):
            await db.execute(delete(RadiusSession).where(RadiusSession.nas_ip == req.nas_ip))
            await db.commit()
            bus.publish(Event(EventType.ACCOUNTING, {"nas": req.nas_ip, "status": status}))
            return

        sid = (attrs.get("Acct-Session-Id") or "")[:64]
        if not sid:
            return
        if status == "stop":
            await db.execute(delete(RadiusSession).where(
                RadiusSession.nas_ip == req.nas_ip, RadiusSession.acct_session_id == sid))
            await db.commit()
            bus.publish(Event(EventType.ACCOUNTING, {"nas": req.nas_ip, "status": status, "session": sid}))
            return

        now = utcnow()
        session = (await db.execute(select(RadiusSession).where(
            RadiusSession.nas_ip == req.nas_ip, RadiusSession.acct_session_id == sid))).scalar_one_or_none()
        session_time = attrs.int("Acct-Session-Time")
        if session is None:
            started = now - timedelta(seconds=session_time) if session_time else now
            session = RadiusSession(nas_ip=req.nas_ip, acct_session_id=sid, started_at=started)
            db.add(session)

        acct_user = (attrs.get("User-Name") or "")[:64]
        session.acct_username = acct_user or session.acct_username
        session.calling_station_id = req.calling_station or session.calling_station_id
        session.mac_address = req.mac or session.mac_address
        framed = parse_ip(attrs.get("Framed-IP-Address")) or parse_ip(attrs.get("Framed-IPv6-Address"))
        if framed:
            session.framed_ip = framed
        if req.ssid:
            session.ssid = req.ssid

        context = await _latest_accept(db, req.nas_ip, session.mac_address or None,
                                       canonical_username(acct_user))
        if context is not None:
            session.username = context.username or session.username
            session.auth_method = context.auth_method
            session.policy_name = context.policy_name
            session.vlan = context.vlan
            session.decision_digest = context.decision_digest
            session.ssid = session.ssid or context.ssid
        elif not session.username:
            session.username = canonical_username(acct_user) or acct_user

        if (octets := _octets(attrs, "Acct-Input-Octets", "Acct-Input-Gigawords")) is not None:
            session.input_octets = octets
        if (octets := _octets(attrs, "Acct-Output-Octets", "Acct-Output-Gigawords")) is not None:
            session.output_octets = octets
        if session_time is not None:
            session.session_time = session_time
        session.updated_at = now
        await db.commit()
    bus.publish(Event(EventType.ACCOUNTING, {"nas": req.nas_ip, "status": status, "session": sid}))
