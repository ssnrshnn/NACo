"""CoA session synchronisation — keep live sessions in step with policy.

When an operator changes a policy, sessions authorised under the old rules
keep their access until they happen to re-authenticate. This module closes
that gap: it finds the active sessions a policy's conditions apply to and
sends each NAS an RFC 5176 Disconnect-Request, forcing an immediate
re-authentication under the current rule set.

The same machinery backs the bulk-disconnect API
(``POST /api/v1/sessions/disconnect``).
"""
from __future__ import annotations

import asyncio
import json
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from naco.config import get_config
from naco.core.logger import get_logger
from naco.db.models import ActiveSession, Device, NasClient, User
from naco.policy.engine import AuthContext, _matches_all
from naco.radius.coa import send_disconnect_request

log = get_logger(__name__)

# Don't blast every NAS at once when a broad policy changes.
_MAX_CONCURRENT_DISCONNECTS = 10


def _normalise_conditions(raw: Any) -> list[dict] | None:
    """Policy.conditions is JSONB (list) on Postgres, JSON text on SQLite.

    Returns ``None`` for unparseable input. The distinction matters: an
    empty list means "match every session" (engine semantics), so mapping
    garbage to ``[]`` would turn corrupt data into a mass disconnect.
    """
    if raw is None:
        return []
    if isinstance(raw, str):
        try:
            raw = json.loads(raw or "[]")
        except json.JSONDecodeError:
            return None
    return raw if isinstance(raw, list) else None


async def sessions_matching_conditions(
    conditions: Any, db: AsyncSession
) -> list[ActiveSession]:
    """Active sessions whose auth context matches the given policy conditions.

    Rebuilds the same :class:`AuthContext` the RADIUS server used at auth
    time (group from the user record, device type from the inventory), so
    matching semantics are identical to the policy engine's.
    """
    conds = _normalise_conditions(conditions)
    if conds is None:
        log.warning("unparseable policy conditions %r — matching no sessions", conditions)
        return []
    sessions = (await db.execute(select(ActiveSession))).scalars().all()
    if not sessions:
        return []

    # Batch the context lookups instead of two queries per session.
    usernames = {s.username for s in sessions if s.username}
    macs = {s.mac_address for s in sessions if s.mac_address}
    group_by_user: dict[str, str] = {}
    if usernames:
        rows = (await db.execute(
            select(User.username, User.group_id).where(User.username.in_(usernames))
        )).all()
        gids = {gid for _, gid in rows if gid is not None}
        gnames: dict[int, str] = {}
        if gids:
            from naco.db.models import Group
            gnames = dict((await db.execute(
                select(Group.id, Group.name).where(Group.id.in_(gids))
            )).tuples().all())
        group_by_user = {u: gnames.get(gid, "") for u, gid in rows}
    devtype_by_mac: dict[str, str] = {}
    if macs:
        devtype_by_mac = dict((await db.execute(
            select(Device.mac_address, Device.device_type).where(Device.mac_address.in_(macs))
        )).tuples().all())

    matched: list[ActiveSession] = []
    for s in sessions:
        ctx = AuthContext(
            username=s.username or "",
            mac_address=s.mac_address or "",
            nas_ip=s.nas_ip or "",
            group_name=group_by_user.get(s.username, ""),
            device_type=devtype_by_mac.get(s.mac_address, "unknown") or "unknown",
        )
        if _matches_all(conds, ctx):
            matched.append(s)
    return matched


async def _nas_secret(nas_ip: str, db: AsyncSession) -> str:
    """Shared secret for a NAS IP: DB first, then static config clients."""
    c = (await db.execute(
        select(NasClient).where(NasClient.ip_address == nas_ip, NasClient.enabled)
    )).scalar_one_or_none()
    if c:
        return c.secret
    for client in get_config().radius.clients:
        if client.address == nas_ip:
            return client.secret
    return ""


async def disconnect_sessions(
    sessions: list[ActiveSession], db: AsyncSession
) -> dict[str, Any]:
    """Send Disconnect-Requests for the given sessions (bounded concurrency).

    Session rows are left in place — the NAS confirms the teardown with an
    Accounting-Stop, which is what normally clears the row. Returns a
    summary: ``{"total": n, "acked": n, "failed": n, "skipped": n}``.
    """
    sem = asyncio.Semaphore(_MAX_CONCURRENT_DISCONNECTS)
    secrets_cache: dict[str, str] = {}
    summary = {"total": len(sessions), "acked": 0, "failed": 0, "skipped": 0}

    async def _one(s: ActiveSession) -> None:
        if not s.nas_ip or not s.session_id:
            summary["skipped"] += 1
            return
        secret = secrets_cache.get(s.nas_ip, "")
        if not secret:
            log.warning("no shared secret for NAS %s — cannot disconnect session %s",
                        s.nas_ip, s.session_id)
            summary["skipped"] += 1
            return
        async with sem:
            result = await send_disconnect_request(
                nas_ip=s.nas_ip, session_id=s.session_id,
                username=s.username, secret=secret,
            )
        summary["acked" if result["success"] else "failed"] += 1

    # Resolve NAS secrets up front — one AsyncSession must not be used from
    # concurrently running tasks.
    for ip in {s.nas_ip for s in sessions if s.nas_ip}:
        secrets_cache[ip] = await _nas_secret(ip, db)

    await asyncio.gather(*(_one(s) for s in sessions))
    return summary


async def coa_after_policy_change(conditions_sets: list[Any]) -> dict[str, Any]:
    """Background task: disconnect sessions matching any of the condition sets.

    ``conditions_sets`` carries the policy's conditions before *and* after
    an update (both matter: sessions authorised under the old rule and
    sessions the new rule now covers). Opens its own DB session because the
    request-scoped one is gone by the time this runs.
    """
    from naco.db.database import AsyncSessionLocal

    async with AsyncSessionLocal() as db:
        affected: dict[int, ActiveSession] = {}
        for conds in conditions_sets:
            for s in await sessions_matching_conditions(conds, db):
                affected[s.id] = s
        if not affected:
            log.info("policy change: no active sessions affected")
            return {"total": 0, "acked": 0, "failed": 0, "skipped": 0}
        log.info("policy change: disconnecting %d affected session(s)", len(affected))
        summary = await disconnect_sessions(list(affected.values()), db)
        log.info("policy change CoA summary: %s", summary)
        return summary


def schedule_policy_coa(*conditions_sets: Any) -> None:
    """Fire-and-forget CoA sync after a policy change (if enabled)."""
    if not get_config().radius.coa_on_policy_change:
        return
    task = asyncio.get_running_loop().create_task(
        coa_after_policy_change(list(conditions_sets))
    )
    task.add_done_callback(_report_coa_task_failure)


def _report_coa_task_failure(task: asyncio.Task) -> None:
    """Surface exceptions in the log instead of "task exception never retrieved"."""
    if task.cancelled():
        return
    exc = task.exception()
    if exc is not None:
        log.error("policy CoA task failed: %s", exc)
