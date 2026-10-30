"""Access policies, their order, and the simulator."""
from __future__ import annotations

from datetime import datetime
from typing import Any
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, Response
from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from naco.aaa.service import guest_active
from naco.aaa.subject import subject_context
from naco.api.audit import AuditTrail, audit_trail, diff
from naco.api.common import commit_or_conflict, flush_or_conflict, get_or_404, snapshot
from naco.api.deps import Principal, superuser, viewer
from naco.api.errors import ApiError
from naco.auth.identity import canonical_username, load_user
from naco.config import get_config
from naco.core.netutils import normalize_mac
from naco.core.timeutil import utcnow
from naco.db.engine import get_db
from naco.db.models import Device, NasClient, Policy, PolicyAction
from naco.policy.attributes import validate_reply_attributes
from naco.policy.conditions import dump_conditions, parse_conditions
from naco.policy.context import AUTH_METHODS, Decision
from naco.policy.engine import PolicyLoadError, decide, explain, load_policies
from naco.radius.reevaluate import reevaluator

router = APIRouter(prefix="/policies", tags=["policies"])
FIELDS = ["name", "description", "priority", "enabled", "conditions", "action", "vlan", "reply_attributes"]


class PolicyOut(BaseModel):
    id: int
    name: str
    description: str
    priority: int
    enabled: bool
    conditions: list[dict[str, Any]]
    action: PolicyAction
    vlan: int | None
    reply_attributes: dict[str, Any]
    updated_at: datetime


def _conditions(v: Any) -> list[dict[str, Any]]:
    return dump_conditions(parse_conditions(v))


def _attributes(v: Any) -> dict[str, Any]:
    return validate_reply_attributes(v)


class PolicyIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    description: str = Field("", max_length=512)
    priority: int = Field(100, ge=1, le=9999)
    enabled: bool = True
    conditions: list[dict[str, Any]] = Field(default_factory=list)
    action: PolicyAction
    vlan: int | None = Field(None, ge=1, le=4094)
    reply_attributes: dict[str, Any] = Field(default_factory=dict)

    @field_validator("conditions")
    @classmethod
    def _valid_conditions(cls, v: Any) -> list[dict[str, Any]]:
        return _conditions(v)

    @field_validator("reply_attributes")
    @classmethod
    def _valid_attributes(cls, v: Any) -> dict[str, Any]:
        return _attributes(v)

    @model_validator(mode="after")
    def _deny_has_no_reply(self) -> PolicyIn:
        if self.action is PolicyAction.DENY and (self.vlan is not None or self.reply_attributes):
            raise ValueError("a DENY policy cannot assign a VLAN or attributes")
        return self


class PolicyUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=128)
    description: str | None = Field(None, max_length=512)
    priority: int | None = Field(None, ge=1, le=9999)
    enabled: bool | None = None
    conditions: list[dict[str, Any]] | None = None
    action: PolicyAction | None = None
    vlan: int | None = Field(None, ge=1, le=4094)
    reply_attributes: dict[str, Any] | None = None

    @field_validator("conditions")
    @classmethod
    def _c(cls, v: Any) -> Any:
        return None if v is None else _conditions(v)

    @field_validator("reply_attributes")
    @classmethod
    def _a(cls, v: Any) -> Any:
        return None if v is None else _attributes(v)


def out(p: Policy) -> PolicyOut:
    return PolicyOut(id=p.id, name=p.name, description=p.description, priority=p.priority, enabled=p.enabled,
                     conditions=p.conditions, action=p.action, vlan=p.vlan,
                     reply_attributes=p.reply_attributes or {}, updated_at=p.updated_at)


@router.get("", response_model=list[PolicyOut])
async def list_policies(_: Principal = Depends(viewer), db: AsyncSession = Depends(get_db)) -> list[PolicyOut]:
    rows = (await db.execute(select(Policy).order_by(Policy.priority, Policy.id))).scalars()
    return [out(p) for p in rows]


@router.get("/{policy_id}", response_model=PolicyOut)
async def get_policy(policy_id: int, _: Principal = Depends(viewer), db: AsyncSession = Depends(get_db)) -> PolicyOut:
    return out(await get_or_404(db, Policy, policy_id, "policy"))


@router.post("", response_model=PolicyOut, status_code=201)
async def create_policy(body: PolicyIn, _: Principal = Depends(superuser),
                        audit: AuditTrail = Depends(audit_trail)) -> PolicyOut:
    policy = Policy(**body.model_dump())
    audit.db.add(policy)
    await flush_or_conflict(audit.db, f"a policy named {body.name} already exists")
    audit.record("policy.create", "policy", policy.id, policy.name, snapshot(policy, FIELDS))
    await commit_or_conflict(audit.db, f"a policy named {body.name} already exists")
    reevaluator.schedule(f"policy {policy.name} created")
    return out(policy)


@router.patch("/{policy_id}", response_model=PolicyOut)
async def update_policy(policy_id: int, body: PolicyUpdate, _: Principal = Depends(superuser),
                        audit: AuditTrail = Depends(audit_trail)) -> PolicyOut:
    policy = await get_or_404(audit.db, Policy, policy_id, "policy")
    before = snapshot(policy, FIELDS)
    changes = body.model_dump(exclude_unset=True)
    for key, value in changes.items():
        if value is None and key not in ("vlan",):
            continue
        setattr(policy, key, value)
    if policy.action is PolicyAction.DENY and (policy.vlan is not None or policy.reply_attributes):
        raise ApiError(422, "a DENY policy cannot assign a VLAN or attributes")
    audit.record("policy.update", "policy", policy.id, policy.name, diff(before, snapshot(policy, FIELDS)))
    await commit_or_conflict(audit.db, "a policy with that name already exists")
    reevaluator.schedule(f"policy {policy.name} changed")
    return out(policy)


@router.delete("/{policy_id}", status_code=204)
async def delete_policy(policy_id: int, _: Principal = Depends(superuser),
                        audit: AuditTrail = Depends(audit_trail)) -> Response:
    policy = await get_or_404(audit.db, Policy, policy_id, "policy")
    await audit.db.delete(policy)
    audit.record("policy.delete", "policy", policy_id, policy.name, snapshot(policy, FIELDS))
    await audit.db.commit()
    reevaluator.schedule(f"policy {policy.name} deleted")
    return Response(status_code=204)


class Reorder(BaseModel):
    ids: list[int] = Field(min_length=1, max_length=9999)


@router.post("/reorder", response_model=list[PolicyOut])
async def reorder(body: Reorder, _: Principal = Depends(superuser),
                  audit: AuditTrail = Depends(audit_trail)) -> list[PolicyOut]:
    policies = {p.id: p for p in (await audit.db.execute(select(Policy))).scalars()}
    if sorted(body.ids) != sorted(policies) or len(set(body.ids)) != len(body.ids):
        raise ApiError(422, "send every policy id exactly once, in the new order")
    for index, ident in enumerate(body.ids):
        policies[ident].priority = (index + 1) * 10
    audit.record("policy.reorder", "policy", "", "", {"order": [policies[i].name for i in body.ids]})
    await audit.db.commit()
    reevaluator.schedule("policy order changed")
    return [out(policies[i]) for i in body.ids]


# ── simulator ──────────────────────────────────────────────────────────────

class SimulateIn(BaseModel):
    auth_method: str
    username: str = Field("", max_length=128)
    mac: str = Field("", max_length=32)
    nas: str = Field("", max_length=64)
    ssid: str = Field("", max_length=64)
    at: datetime | None = None

    @field_validator("auth_method")
    @classmethod
    def _method(cls, v: str) -> str:
        if v not in AUTH_METHODS:
            raise ValueError(f"one of {', '.join(AUTH_METHODS)}")
        return v


class ConditionResult(BaseModel):
    label: str
    matched: bool


class TraceOut(BaseModel):
    policy_id: int
    policy: str
    action: PolicyAction
    matched: bool
    conditions: list[ConditionResult]


class SimulateOut(BaseModel):
    accepted: bool
    reason: str
    policy: str
    vlan: int | None
    reply_attributes: dict[str, Any]
    context: dict[str, Any]
    trace: list[TraceOut]


@router.post("/simulate", response_model=SimulateOut)
async def simulate(body: SimulateIn, _: Principal = Depends(viewer), db: AsyncSession = Depends(get_db)) -> SimulateOut:
    """What would happen if this request arrived now (read-only)."""
    now = body.at or utcnow()
    mac = normalize_mac(body.mac) if body.mac else None
    if body.mac and mac is None:
        raise ApiError(422, "not a MAC address")
    username = canonical_username(body.username) if body.auth_method != "MAB" else ""
    found = await load_user(db, username) if username else None
    device = (await db.execute(select(Device).where(Device.mac_address == mac))).scalar_one_or_none() if mac else None
    nas = (await db.execute(select(NasClient).where(NasClient.name == body.nas))).scalar_one_or_none() if body.nas else None
    subject = subject_context(
        method=body.auth_method, username=username, user=found[0] if found else None, mac=mac, device=device,
        is_guest=bool(mac and await guest_active(db, mac, now)), nas_name=nas.name if nas else body.nas,
        nas_ip=nas.ip_address if nas else "", ssid=body.ssid or None, now=now,
    )
    try:
        policies = await load_policies(db)
    except PolicyLoadError as exc:
        raise ApiError(409, str(exc)) from exc
    tz = ZoneInfo(get_config().server.timezone)
    traces = [] if isinstance(subject, Decision) else explain(policies, subject, tz)
    decision = subject if isinstance(subject, Decision) else decide(policies, subject, tz)
    context = {} if isinstance(subject, Decision) else {
        "auth_method": subject.auth_method, "username": subject.username, "group": subject.group,
        "mac": subject.mac, "device_status": subject.device_status, "device_type": subject.device_type,
        "vendor": subject.vendor, "nas": subject.nas_name, "ssid": subject.ssid, "time": now.isoformat(),
    }
    return SimulateOut(
        accepted=decision.accepted, reason=decision.reason, policy=decision.policy_name, vlan=decision.vlan,
        reply_attributes=decision.reply_attributes, context=context,
        trace=[TraceOut(policy_id=t.policy.id, policy=t.policy.name, action=t.policy.action, matched=t.matched,
                        conditions=[ConditionResult(label=label, matched=ok) for label, ok in t.conditions])
               for t in traces],
    )
