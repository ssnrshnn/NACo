"""The audit trail: who changed what, from where — written in the same
transaction as the change itself.

Every state-changing route depends on ``audit_trail``; a test enumerates the
routes and fails if one does not.
"""
from __future__ import annotations

import logging
from collections.abc import AsyncIterator, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from naco.api.deps import Principal, current_principal
from naco.core.events import Event, EventType, bus
from naco.db.engine import get_db
from naco.db.models import ActorType, AuditLog

trail_log = logging.getLogger("naco.trail")
MASK = "***"


def diff(before: Mapping[str, Any], after: Mapping[str, Any], secret_fields: Iterable[str] = ()) -> dict[str, Any]:
    secret = set(secret_fields)
    out: dict[str, Any] = {}
    for key in sorted(set(before) | set(after)):
        old, new = before.get(key), after.get(key)
        if old != new:
            out[key] = [MASK, MASK] if key in secret else [old, new]
    return out


def write(db: AsyncSession, *, actor: str, actor_type: ActorType, ip: str, action: str,
          target_type: str = "", target_id: object = "", target_name: str = "",
          changes: dict[str, Any] | None = None) -> AuditLog:
    row = AuditLog(actor=actor[:64], actor_type=actor_type, ip=ip[:45], action=action[:64],
                   target_type=target_type[:32], target_id=str(target_id)[:64],
                   target_name=target_name[:128], changes=changes or {})
    db.add(row)
    return row


def announce(row: AuditLog) -> None:
    bus.publish(Event(EventType.AUDIT, {"actor": row.actor, "action": row.action,
                                        "target": row.target_name or row.target_id}))
    trail_log.info("audit actor=%s ip=%s action=%s target=%s:%s %s", row.actor, row.ip or "-", row.action,
                   row.target_type or "-", row.target_name or row.target_id or "-", row.changes or "")


@dataclass
class AuditTrail:
    db: AsyncSession
    principal: Principal
    entries: list[AuditLog] = field(default_factory=list)

    def record(self, action: str, target_type: str = "", target_id: object = "", target_name: str = "",
               changes: dict[str, Any] | None = None) -> None:
        actor_type = ActorType.TOKEN if self.principal.kind == "token" else ActorType.ADMIN
        self.entries.append(write(
            self.db, actor=self.principal.username, actor_type=actor_type, ip=self.principal.ip,
            action=action, target_type=target_type, target_id=target_id, target_name=target_name,
            changes=changes,
        ))


async def audit_trail(db: AsyncSession = Depends(get_db),
                      principal: Principal = Depends(current_principal)) -> AsyncIterator[AuditTrail]:
    trail = AuditTrail(db, principal)
    yield trail
    for row in trail.entries:
        if row.id is not None:  # committed with the change
            announce(row)
