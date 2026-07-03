"""Group CRUD endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from naco.api.auth import require_role
from naco.api.schemas import GroupCreate, GroupOut, StatusResponse
from naco.db import get_db
from naco.db.models import AdminRole, AdminUser, Group, User

router = APIRouter(prefix="/api/v1", tags=["Groups"])


@router.get("/groups", response_model=list[GroupOut])
async def list_groups(
    skip: int = 0, limit: int = Query(50, le=200),
    db: AsyncSession = Depends(get_db),
    _:  AdminUser    = Depends(require_role(AdminRole.VIEWER)),
):
    result = (await db.execute(select(Group).offset(skip).limit(limit))).scalars().all()
    return [GroupOut.model_validate(g) for g in result]


@router.post("/groups", response_model=GroupOut, status_code=201)
async def create_group(
    body: GroupCreate,
    db:   AsyncSession = Depends(get_db),
    _:    AdminUser    = Depends(require_role(AdminRole.OPERATOR)),
):
    existing = (await db.execute(select(Group).where(Group.name == body.name))).scalar_one_or_none()
    if existing:
        raise HTTPException(409, "Group name already exists")
    grp = Group(name=body.name, description=body.description, command_set_id=body.command_set_id)
    db.add(grp)
    await db.commit()
    await db.refresh(grp)
    return GroupOut.model_validate(grp)


@router.delete("/groups/{group_id}", response_model=StatusResponse)
async def delete_group(
    group_id: int,
    db: AsyncSession = Depends(get_db),
    _:  AdminUser    = Depends(require_role(AdminRole.OPERATOR)),
):
    grp = (await db.execute(select(Group).where(Group.id == group_id))).scalar_one_or_none()
    if not grp:
        raise HTTPException(404, "Group not found")
    user_count = (await db.execute(
        select(func.count()).select_from(User).where(User.group_id == group_id)
    )).scalar() or 0
    if user_count > 0:
        raise HTTPException(409, f"Cannot delete group — {user_count} user(s) still assigned")
    await db.delete(grp)
    await db.commit()
    return StatusResponse(status="ok", message=f"Group {group_id} deleted")


@router.put("/groups/{group_id}", response_model=GroupOut)
async def update_group(
    group_id: int,
    body: GroupCreate,
    db:   AsyncSession = Depends(get_db),
    _:    AdminUser    = Depends(require_role(AdminRole.OPERATOR)),
):
    grp = (await db.execute(select(Group).where(Group.id == group_id))).scalar_one_or_none()
    if not grp:
        raise HTTPException(404, "Group not found")
    if body.name != grp.name:
        existing = (await db.execute(select(Group).where(Group.name == body.name))).scalar_one_or_none()
        if existing:
            raise HTTPException(409, "Group name already exists")
    grp.name = body.name
    grp.description = body.description
    grp.command_set_id = body.command_set_id
    await db.commit()
    await db.refresh(grp)
    return GroupOut.model_validate(grp)
