"""First-match policy evaluation, default deny.

Policies are read from the database on every decision. A policy that cannot
be compiled (it was validated on save, so this means tampering or a bad
migration) makes every decision a DENY until it is fixed: skipping it could
silently drop a DENY rule and open access.
"""
from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any
from zoneinfo import ZoneInfo

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from naco.db.models import Policy, PolicyAction
from naco.policy.attributes import validate_reply_attributes
from naco.policy.conditions import Condition, condition_matches, parse_conditions
from naco.policy.context import AuthContext, Decision, deny

log = logging.getLogger(__name__)

DEFAULT_DENY_REASON = "no policy matched"


class PolicyLoadError(RuntimeError):
    pass


@dataclass(frozen=True)
class CompiledPolicy:
    id: int
    name: str
    priority: int
    action: PolicyAction
    vlan: int | None
    reply_attributes: dict[str, Any]
    conditions: tuple[Condition, ...]


@dataclass(frozen=True)
class PolicyTrace:
    policy: CompiledPolicy
    matched: bool
    conditions: list[tuple[str, bool]] = field(default_factory=list)


def compile_policy(row: Policy) -> CompiledPolicy:
    try:
        return CompiledPolicy(
            id=row.id, name=row.name, priority=row.priority, action=PolicyAction(row.action),
            vlan=row.vlan,
            reply_attributes=validate_reply_attributes(row.reply_attributes),
            conditions=tuple(parse_conditions(row.conditions)),
        )
    except ValueError as exc:
        raise PolicyLoadError(f"policy {row.name!r} is invalid: {exc}") from exc


def _matches(policy: CompiledPolicy, ctx: AuthContext, tz: ZoneInfo) -> bool:
    return all(condition_matches(c, ctx, tz) for c in policy.conditions)


def decide(policies: Sequence[CompiledPolicy], ctx: AuthContext, tz: ZoneInfo) -> Decision:
    for policy in policies:
        if _matches(policy, ctx, tz):
            if policy.action is PolicyAction.DENY:
                return deny(f"denied by policy {policy.name}", policy.id, policy.name)
            return Decision(
                PolicyAction.PERMIT, policy.id, policy.name, f"permitted by policy {policy.name}",
                vlan=policy.vlan, reply_attributes=dict(policy.reply_attributes),
            )
    return deny(DEFAULT_DENY_REASON)


def explain(policies: Sequence[CompiledPolicy], ctx: AuthContext, tz: ZoneInfo) -> list[PolicyTrace]:
    """Per-policy, per-condition results in evaluation order (the simulator)."""
    traces = []
    for policy in policies:
        results = [(c.label(), condition_matches(c, ctx, tz)) for c in policy.conditions]
        traces.append(PolicyTrace(policy, all(ok for _, ok in results), results))
    return traces


async def load_policies(db: AsyncSession) -> list[CompiledPolicy]:
    rows = (await db.execute(
        select(Policy).where(Policy.enabled.is_(True)).order_by(Policy.priority, Policy.id)
    )).scalars().all()
    return [compile_policy(row) for row in rows]


def _zone() -> ZoneInfo:
    from naco.config import get_config
    return ZoneInfo(get_config().server.timezone)


async def evaluate(db: AsyncSession, ctx: AuthContext) -> Decision:
    try:
        policies = await load_policies(db)
    except PolicyLoadError as exc:
        log.error("%s — denying all requests until it is fixed", exc)
        return deny("policy configuration error")
    return decide(policies, ctx, _zone())
