"""
NACo Policy Engine
=====================
Evaluates access-control policies against an authentication request context.

A policy is a prioritised rule with JSON conditions.  The engine returns the
first matching policy's action (PERMIT / DENY / GUEST) plus an optional VLAN.

Condition types
---------------
  username    – "equals" | "startswith" | "endswith" | "contains" | "regex"
  group       – "in" (list of group names)
  mac         – "equals" | "startswith" (OUI prefix) | "in" (list)
  time        – "between" {"start": "HH:MM", "end": "HH:MM"}
  device_type – "in" (list of strings returned by the profiler)
  nas_ip      – "equals" | "in"
  always      – matches every request (used for catch-all rules)

Example rule JSON
-----------------
  [
    {"type": "group",       "op": "in",       "value": ["employees"]},
    {"type": "time",        "op": "between",  "start": "07:00", "end": "19:00"},
    {"type": "device_type", "op": "in",       "value": ["laptop", "workstation"]}
  ]
"""
from __future__ import annotations

import asyncio
import concurrent.futures
import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from functools import lru_cache
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from naco.core.logger import get_logger
from naco.core.utils import is_within_time_range, normalise_mac, utcnow
from naco.db.models import Policy, PolicyAction

log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Request context — passed to engine for every auth attempt
# ---------------------------------------------------------------------------

@dataclass
class AuthContext:
    username: str           = ""
    mac_address: str        = ""        # normalised lower-colon
    ip_address: str         = ""
    nas_ip: str             = ""
    nas_port: str           = ""
    auth_method: str        = ""
    group_name: str         = ""        # resolved from DB
    device_type: str        = "unknown" # from profiler
    os_type: str            = "unknown"
    timestamp: datetime     = field(default_factory=utcnow)


@dataclass
class PolicyDecision:
    action: PolicyAction
    vlan: int | None
    policy_name: str
    reason: str
    # Vendor/standard RADIUS attributes to attach to the Access-Accept,
    # e.g. {"Aruba-User-Role": "employee", "Cisco-AVPair": ["..."]}.
    reply_attributes: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Condition evaluators
# ---------------------------------------------------------------------------

def _eval_condition(cond: dict[str, Any], ctx: AuthContext) -> bool:
    ctype = cond.get("type", "")
    op    = cond.get("op",   "equals")
    val   = cond.get("value", "")

    if ctype == "always":
        return True

    if ctype == "username":
        return _string_match(ctx.username, op, val)

    if ctype == "group":
        groups = val if isinstance(val, list) else [val]
        return ctx.group_name in groups

    if ctype == "mac":
        try:
            mac = normalise_mac(ctx.mac_address)
        except ValueError:
            return False
        if op == "equals":
            return mac == normalise_mac(val)
        if op == "startswith":
            return mac.startswith(val.lower())
        if op == "in":
            norms = []
            for m in (val if isinstance(val, list) else [val]):
                try:
                    norms.append(normalise_mac(m))
                except ValueError:
                    pass
            return mac in norms

    if ctype == "time":
        start = cond.get("start", "00:00")
        end   = cond.get("end",   "23:59")
        return is_within_time_range(start, end, ctx.timestamp.time())

    if ctype == "device_type":
        device_types = val if isinstance(val, list) else [val]
        return ctx.device_type.lower() in [d.lower() for d in device_types]

    if ctype == "nas_ip":
        if op == "equals":
            return ctx.nas_ip == val
        if op == "startswith":
            return ctx.nas_ip.startswith(val)
        if op == "in":
            return ctx.nas_ip in (val if isinstance(val, list) else [val])

    log.warning("Unknown condition type %r — treating as no-match", ctype)
    return False


def _string_match(subject: str, op: str, pattern: str) -> bool:
    s = subject.lower()
    p = pattern.lower() if isinstance(pattern, str) else pattern
    if op == "equals":     return s == p
    if op == "startswith": return s.startswith(p)
    if op == "endswith":   return s.endswith(p)
    if op == "contains":   return p in s
    if op == "regex":
        try:
            # Reject patterns over 256 chars
            if len(pattern) > 256:
                log.warning("Regex pattern too long (%d chars) — treating as no-match", len(pattern))
                return False
            # Reject patterns with nested quantifiers (ReDoS vectors)
            # e.g. (a+)+, (a*)+, (a|b+)+, (\d+)+
            if re.search(r'\([^)]*[+*][^)]*\)[+*?]', pattern):
                log.warning("Regex pattern %r contains nested quantifiers (ReDoS risk) — treating as no-match", pattern)
                return False
            compiled = _compile_regex(pattern)
            future = _regex_executor.submit(compiled.search, subject[:1024])
            result = future.result(timeout=2.0)
            return bool(result)
        except concurrent.futures.TimeoutError:
            log.warning("Regex pattern %r timed out — treating as no-match", pattern)
            return False
        except re.error as exc:
            log.warning("Invalid regex pattern %r in policy condition: %s", pattern, exc)
            return False
    return False


# ---------------------------------------------------------------------------
# Regex helpers — module-level executor + compiled pattern cache
# ---------------------------------------------------------------------------

_regex_executor = concurrent.futures.ThreadPoolExecutor(
    max_workers=2, thread_name_prefix="naco-regex"
)


@lru_cache(maxsize=256)
def _compile_regex(pattern: str) -> re.Pattern:
    """Compile and cache regex patterns used in policy conditions."""
    return re.compile(pattern, re.IGNORECASE)


# ---------------------------------------------------------------------------
# Compiled-policy cache
# ---------------------------------------------------------------------------
#
# Every RADIUS / TACACS+ authentication used to issue a "SELECT * FROM policies
# WHERE enabled ORDER BY priority" and re-parse each row's JSON conditions. At
# a few thousand auth/s that is a lot of redundant round-trips and JSON work
# for a table that changes rarely.
#
# The cache holds pre-parsed, priority-ordered snapshots in process memory.
# It is refreshed either when a policy write calls
# :func:`invalidate_policy_cache` (immediate, exact) or when the soft TTL
# lapses (a safety net for out-of-band edits — direct SQL, a second process).
# NACo runs as a single Uvicorn process, so the in-process cache is coherent
# with the writers that live in the same process.

_POLICY_CACHE_TTL = 30.0  # seconds — upper bound on staleness for out-of-band edits


@dataclass(frozen=True)
class _CompiledPolicy:
    name: str
    action: PolicyAction
    vlan: int | None
    conditions: list[dict]
    reply_attributes: dict[str, Any]


class _PolicyCache:
    """Async-safe, TTL-bounded cache of compiled policies."""

    def __init__(self, ttl: float = _POLICY_CACHE_TTL) -> None:
        self._ttl = ttl
        self._lock = asyncio.Lock()
        self._compiled: list[_CompiledPolicy] | None = None
        self._loaded_at = 0.0

    def invalidate(self) -> None:
        """Drop the cached snapshot so the next evaluate() reloads from DB."""
        self._compiled = None

    async def get(self, db: AsyncSession) -> list[_CompiledPolicy]:
        cached = self._compiled
        if cached is not None and (time.monotonic() - self._loaded_at) < self._ttl:
            return cached
        async with self._lock:
            # Re-check under the lock: a concurrent caller may have just loaded.
            cached = self._compiled
            if cached is not None and (time.monotonic() - self._loaded_at) < self._ttl:
                return cached
            compiled = await self._load(db)
            self._compiled = compiled
            self._loaded_at = time.monotonic()
            return compiled

    async def _load(self, db: AsyncSession) -> list[_CompiledPolicy]:
        stmt = (
            select(Policy)
            .where(Policy.enabled)
            .order_by(Policy.priority.asc())
        )
        rows = list((await db.execute(stmt)).scalars().all())
        compiled: list[_CompiledPolicy] = []
        for policy in rows:
            try:
                raw = policy.conditions
                if isinstance(raw, str):
                    conditions: list[dict] = json.loads(raw or "[]")
                else:
                    conditions = raw if raw else []
            except (json.JSONDecodeError, TypeError):
                log.warning("Policy %r has invalid conditions JSON — skipping", policy.name)
                continue
            compiled.append(_CompiledPolicy(
                name=policy.name,
                action=PolicyAction(policy.action),
                vlan=policy.vlan,
                conditions=conditions,
                reply_attributes=_parse_reply_attributes(policy),
            ))
        log.debug("Policy cache refreshed: %d active policies compiled", len(compiled))
        return compiled


_policy_cache = _PolicyCache()

# Redis pub/sub channel used to broadcast "policies changed" across every
# replica. In a single-process deployment the local invalidate() below is
# enough; once NACo runs as multiple replicas, each one must drop its own
# in-process snapshot when *any* replica writes a policy.
_POLICY_INVALIDATION_CHANNEL = "naco:policy:invalidate"

# Keep strong references to in-flight broadcast tasks so the event loop does
# not garbage-collect them before they complete (see asyncio.create_task docs).
_pending_broadcasts: set[asyncio.Task] = set()


def invalidate_policy_cache() -> None:
    """Public hook: call after any create/update/delete of a policy so the
    next authentication sees the change immediately (config changes already
    propagate via CoA; this keeps the decision path itself in sync).

    Invalidates this process's snapshot immediately and — best-effort —
    broadcasts to other replicas via Redis pub/sub. Redis being unreachable is
    non-fatal: the per-snapshot TTL still bounds staleness everywhere.
    """
    _policy_cache.invalidate()
    _broadcast_invalidation_best_effort()


def _broadcast_invalidation_best_effort() -> None:
    """Schedule a fire-and-forget Redis publish if an event loop is running.

    Callers are async route handlers, so a loop is normally present; in sync
    contexts (CLI, tests) there is nothing to broadcast to and the local
    invalidation above already did the job."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    task = loop.create_task(_publish_invalidation())
    _pending_broadcasts.add(task)
    task.add_done_callback(_pending_broadcasts.discard)


async def _publish_invalidation() -> None:
    try:
        from naco.core.cache import get_redis
        redis = await get_redis()
        if redis is not None:
            await redis.publish(_POLICY_INVALIDATION_CHANNEL, "1")
    except Exception as exc:  # pragma: no cover - best effort
        log.debug("Policy-cache invalidation broadcast failed: %s", exc)


async def run_policy_invalidation_subscriber() -> None:
    """Long-lived task: drop the local policy snapshot whenever any replica
    publishes a change. Degrades gracefully when Redis is unavailable."""
    from naco.core.cache import get_redis

    while True:
        try:
            redis = await get_redis()
            if redis is None:
                await asyncio.sleep(30)
                continue
            pubsub = redis.pubsub()
            await pubsub.subscribe(_POLICY_INVALIDATION_CHANNEL)
            log.info("Subscribed to %s for cross-replica policy invalidation",
                     _POLICY_INVALIDATION_CHANNEL)
            async for message in pubsub.listen():
                if message.get("type") == "message":
                    _policy_cache.invalidate()
                    log.debug("Policy cache invalidated via Redis pub/sub")
        except asyncio.CancelledError:
            break
        except Exception as exc:
            log.warning("Policy-invalidation subscriber error: %s — retrying in 5s", exc)
            await asyncio.sleep(5)


# ---------------------------------------------------------------------------
# Policy Engine
# ---------------------------------------------------------------------------

class PolicyEngine:
    """
    Stateless engine; results depend only on DB policies + request context.
    Call evaluate() for each authentication request.
    """

    async def evaluate(
        self, ctx: AuthContext, db: AsyncSession
    ) -> PolicyDecision:
        """
        Evaluate cached, priority-ordered policies until one matches.
        Returns a DENY decision if no rule matches (default-deny).
        """
        for policy in await _policy_cache.get(db):
            if _matches_all(policy.conditions, ctx):
                log.debug(
                    "Policy match: [%s] → %s (vlan=%s) for user=%r mac=%r",
                    policy.name, policy.action, policy.vlan,
                    ctx.username, ctx.mac_address,
                )
                return PolicyDecision(
                    action=policy.action,
                    vlan=policy.vlan,
                    policy_name=policy.name,
                    reason=f"Matched policy: {policy.name}",
                    reply_attributes=policy.reply_attributes,
                )

        # No rule matched → default deny
        log.info("No policy matched for user=%r mac=%r → DEFAULT_DENY", ctx.username, ctx.mac_address)
        return PolicyDecision(
            action=PolicyAction.DENY,
            vlan=None,
            policy_name="DEFAULT_DENY",
            reason="No matching policy found",
        )


def _parse_reply_attributes(policy: Policy) -> dict[str, Any]:
    """Normalise ``Policy.reply_attributes`` to a dict (JSONB dict on
    Postgres, JSON-as-text on SQLite, or NULL)."""
    raw = getattr(policy, "reply_attributes", None)
    if not raw:
        return {}
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError:
            log.warning("Policy %r has invalid reply_attributes JSON — ignoring", policy.name)
            return {}
    return raw if isinstance(raw, dict) else {}


def _matches_all(conditions: list[dict], ctx: AuthContext) -> bool:
    """All conditions must match (logical AND)."""
    if not conditions:          # empty list = match everything
        return True
    return all(_eval_condition(c, ctx) for c in conditions)


# Module-level singleton
engine = PolicyEngine()
