"""Re-evaluate live sessions after a change and disconnect only what changed.

Each session remembers the digest of the decision the NAS received
(action, VLAN, attributes). After a policy, user, group or device change the
sessions are evaluated again with the same hard rules as live
authorization; a session is disconnected (RFC 5176) only if its decision is
now different. Editing a policy's name or description therefore disconnects
nobody.

If the policy set cannot be loaded, nothing is disconnected: a broken
configuration must not take the whole network down.
"""
from __future__ import annotations

import asyncio
import logging
from collections.abc import Iterable
from dataclasses import dataclass, field
from zoneinfo import ZoneInfo

from sqlalchemy import select

from naco.aaa.subject import subject_context
from naco.auth.identity import UserInfo
from naco.config import get_config
from naco.core.events import Event, EventType, bus
from naco.core.timeutil import utcnow
from naco.db.engine import session_factory
from naco.db.models import Device, Group, GuestRegistration, NasClient, RadiusSession, User
from naco.policy.context import AUTH_METHODS, Decision
from naco.policy.engine import PolicyLoadError, decide, load_policies
from naco.radius.coa import CoaResult, CoaTarget, Outcome, disconnect

log = logging.getLogger(__name__)
trail = logging.getLogger("naco.trail")


@dataclass
class ReevalSummary:
    checked: int = 0
    changed: int = 0
    disconnected: int = 0
    failed: int = 0
    reasons: list[str] = field(default_factory=list)


def _changed(decision: Decision, digest: str) -> bool:
    return not decision.accepted or decision.digest() != digest


async def send_disconnect(session: RadiusSession, nas: NasClient) -> CoaResult:
    cfg = get_config().radius
    result = await disconnect(
        CoaTarget(nas.ip_address, nas.coa_port, nas.secret), session.acct_session_id,
        username=session.acct_username, calling_station_id=session.calling_station_id,
        timeout=cfg.coa_timeout_seconds, retries=cfg.coa_retries,
    )
    trail.info("coa disconnect nas=%s session=%s user=%s mac=%s outcome=%s %s", nas.name,
               session.acct_session_id, session.username or "-", session.mac_address or "-",
               result.outcome.value, result.detail)
    bus.publish(Event(EventType.ACCOUNTING, {"nas": nas.ip_address, "status": "coa",
                                             "session": session.acct_session_id,
                                             "outcome": result.outcome.value}))
    return result


async def _load_world(sessions: list[RadiusSession]) -> tuple[dict[str, NasClient], dict[str, UserInfo],
                                                              dict[str, Device], set[str]]:
    usernames = {s.username for s in sessions if s.username}
    macs = {s.mac_address for s in sessions if s.mac_address}
    now = utcnow()
    async with session_factory()() as db:
        nas = {n.ip_address: n for n in (await db.execute(select(NasClient))).scalars()}
        users: dict[str, UserInfo] = {}
        if usernames:
            rows = await db.execute(select(User, Group).outerjoin(Group, User.group_id == Group.id)
                                    .where(User.username.in_(usernames)))
            for user, group in rows:
                users[user.username] = UserInfo(
                    id=user.id, username=user.username, source=user.source, enabled=user.enabled,
                    group_id=user.group_id, group_name=group.name if group else None,
                    device_admin_privilege=group.device_admin_privilege if group else None,
                    command_set_id=group.command_set_id if group else None)
        devices: dict[str, Device] = {}
        guests: set[str] = set()
        if macs:
            devices = {d.mac_address: d for d in (await db.execute(
                select(Device).where(Device.mac_address.in_(macs)))).scalars()}
            guests = set((await db.execute(select(GuestRegistration.mac_address).where(
                GuestRegistration.mac_address.in_(macs), GuestRegistration.revoked_at.is_(None),
                GuestRegistration.expires_at > now))).scalars())
    return nas, users, devices, guests


async def reevaluate(reasons: Iterable[str] = (), concurrency: int = 20) -> ReevalSummary:
    summary = ReevalSummary(reasons=list(reasons))
    async with session_factory()() as db:
        sessions = list((await db.execute(
            select(RadiusSession).where(RadiusSession.decision_digest != ""))).scalars())
        try:
            policies = await load_policies(db)
        except PolicyLoadError as exc:
            log.error("CoA re-evaluation skipped: %s", exc)
            return summary
    if not sessions:
        return summary

    nas_by_ip, users, devices, guests = await _load_world(sessions)
    tz = ZoneInfo(get_config().server.timezone)
    now = utcnow()
    targets: list[tuple[RadiusSession, NasClient]] = []
    for s in sessions:
        nas = nas_by_ip.get(s.nas_ip)
        if s.auth_method not in AUTH_METHODS or nas is None:
            continue
        summary.checked += 1
        mac = s.mac_address or None
        subject = subject_context(
            method=s.auth_method, username=s.username, user=users.get(s.username), mac=mac,
            device=devices.get(mac) if mac else None, is_guest=bool(mac and mac in guests),
            nas_name=nas.name, nas_ip=s.nas_ip, ssid=s.ssid or None, now=now,
        )
        decision = subject if isinstance(subject, Decision) else decide(policies, subject, tz)
        if _changed(decision, s.decision_digest):
            summary.changed += 1
            targets.append((s, nas))

    gate = asyncio.Semaphore(concurrency)

    async def one(session: RadiusSession, nas: NasClient) -> None:
        async with gate:
            result = await send_disconnect(session, nas)
        if result.outcome is Outcome.ACK:
            summary.disconnected += 1
        else:
            summary.failed += 1

    await asyncio.gather(*(one(s, n) for s, n in targets))
    if summary.changed:
        log.info("CoA re-evaluation (%s): %d checked, %d changed, %d disconnected, %d failed",
                 ", ".join(summary.reasons) or "manual", summary.checked, summary.changed,
                 summary.disconnected, summary.failed)
    return summary


class Reevaluator:
    """Coalesces bursts of changes into one re-evaluation run."""

    def __init__(self, delay: float = 2.0) -> None:
        self.delay = delay
        self._wake = asyncio.Event()
        self._reasons: list[str] = []

    def schedule(self, reason: str) -> None:
        self._reasons.append(reason)
        self._wake.set()

    async def run_forever(self) -> None:
        while True:
            await self._wake.wait()
            await asyncio.sleep(self.delay)
            self._wake.clear()
            reasons, self._reasons = self._reasons, []
            try:
                await reevaluate(reasons)
            except Exception:
                log.exception("CoA re-evaluation failed")


reevaluator = Reevaluator()
