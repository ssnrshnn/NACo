"""Policy CRUD endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from naco.api._audit import audit
from naco.api.auth import require_role
from naco.api.schemas import PolicyCreate, PolicyOut, PolicyUpdate, StatusResponse
from naco.db import get_db
from naco.db.models import AdminRole, AdminUser, Policy
from naco.policy import invalidate_policy_cache
from naco.radius.coa_sync import schedule_policy_coa

router = APIRouter(prefix="/api/v1", tags=["Policies"])


@router.get("/policies", response_model=list[PolicyOut])
async def list_policies(
    skip: int = 0, limit: int = Query(50, le=200),
    db: AsyncSession = Depends(get_db),
    _:  AdminUser    = Depends(require_role(AdminRole.VIEWER)),
):
    stmt   = select(Policy).order_by(Policy.priority).offset(skip).limit(limit)
    result = (await db.execute(stmt)).scalars().all()
    return [PolicyOut.model_validate(p) for p in result]


@router.post("/policies", response_model=PolicyOut, status_code=201)
async def create_policy(
    body: PolicyCreate,
    db:   AsyncSession = Depends(get_db),
    admin: AdminUser   = Depends(require_role(AdminRole.OPERATOR)),
):
    pol = Policy(
        name        = body.name,
        description = body.description,
        priority    = body.priority,
        conditions  = body.conditions,
        action      = body.action,
        vlan        = body.vlan,
        reply_attributes = body.reply_attributes,
        group_id    = body.group_id,
        enabled     = body.enabled,
    )
    db.add(pol)
    await audit(db, admin, "CREATE", "policy", "", f"name={body.name}")
    await db.commit()
    await db.refresh(pol)
    invalidate_policy_cache()
    # Sessions the new rule covers were authorised under the old rule set —
    # force them to re-authenticate (config: radius.coa_on_policy_change).
    if pol.enabled:
        schedule_policy_coa(pol.conditions)
    return PolicyOut.model_validate(pol)


@router.put("/policies/{policy_id}", response_model=PolicyOut)
async def update_policy(
    policy_id: int,
    body: PolicyUpdate,
    db:   AsyncSession = Depends(get_db),
    _:    AdminUser    = Depends(require_role(AdminRole.OPERATOR)),
):
    pol = (await db.execute(select(Policy).where(Policy.id == policy_id))).scalar_one_or_none()
    if not pol:
        raise HTTPException(404, "Policy not found")
    old_conditions = pol.conditions  # sessions matched by the OLD rule are affected too
    if body.name        is not None: pol.name        = body.name
    if body.description is not None: pol.description = body.description
    if body.priority    is not None: pol.priority    = body.priority
    if body.conditions  is not None: pol.conditions  = body.conditions
    if body.action      is not None: pol.action      = body.action
    if body.vlan        is not None: pol.vlan        = body.vlan
    if body.reply_attributes is not None: pol.reply_attributes = body.reply_attributes
    if body.group_id    is not None: pol.group_id    = body.group_id
    if body.enabled     is not None: pol.enabled     = body.enabled
    await db.commit()
    await db.refresh(pol)
    invalidate_policy_cache()
    schedule_policy_coa(old_conditions, pol.conditions)
    return PolicyOut.model_validate(pol)


@router.delete("/policies/{policy_id}", response_model=StatusResponse)
async def delete_policy(
    policy_id: int,
    db: AsyncSession = Depends(get_db),
    admin: AdminUser = Depends(require_role(AdminRole.OPERATOR)),
):
    pol = (await db.execute(select(Policy).where(Policy.id == policy_id))).scalar_one_or_none()
    if not pol:
        raise HTTPException(404, "Policy not found")
    await audit(db, admin, "DELETE", "policy", str(policy_id), f"name={pol.name}")
    conditions = pol.conditions
    was_enabled = pol.enabled
    await db.delete(pol)
    await db.commit()
    invalidate_policy_cache()
    # Sessions authorised by the deleted rule must re-authenticate against
    # whatever remains (likely landing on default-deny).
    if was_enabled:
        schedule_policy_coa(conditions)
    return StatusResponse(status="ok", message=f"Policy {policy_id} deleted")
