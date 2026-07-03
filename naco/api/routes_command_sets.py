"""TACACS+ Command Set CRUD endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from naco.api.auth import require_role
from naco.api.schemas import CommandSetCreate, CommandSetOut, CommandSetUpdate, StatusResponse
from naco.db import get_db
from naco.db.models import AdminRole, AdminUser, CommandRule, CommandSet

router = APIRouter(prefix="/api/v1", tags=["Command Sets"])


@router.get("/command-sets", response_model=list[CommandSetOut])
async def list_command_sets(
    db: AsyncSession = Depends(get_db),
    _:  AdminUser    = Depends(require_role(AdminRole.VIEWER)),
):
    stmt = select(CommandSet).options(selectinload(CommandSet.rules)).order_by(CommandSet.name)
    rows = (await db.execute(stmt)).scalars().unique().all()
    return [CommandSetOut.model_validate(r) for r in rows]


@router.post("/command-sets", response_model=CommandSetOut, status_code=201)
async def create_command_set(
    body: CommandSetCreate,
    db:   AsyncSession = Depends(get_db),
    _:    AdminUser    = Depends(require_role(AdminRole.OPERATOR)),
):
    existing = (await db.execute(select(CommandSet).where(CommandSet.name == body.name))).scalar_one_or_none()
    if existing:
        raise HTTPException(409, "Command set name already exists")
    cs = CommandSet(name=body.name, description=body.description)
    for r in body.rules:
        cs.rules.append(CommandRule(
            priority=r.priority, action=r.action,
            command_pattern=r.command_pattern, args_pattern=r.args_pattern,
        ))
    db.add(cs)
    await db.commit()
    await db.refresh(cs, ["rules"])
    return CommandSetOut.model_validate(cs)


@router.get("/command-sets/{cs_id}", response_model=CommandSetOut)
async def get_command_set(
    cs_id: int,
    db: AsyncSession = Depends(get_db),
    _:  AdminUser    = Depends(require_role(AdminRole.VIEWER)),
):
    stmt = select(CommandSet).options(selectinload(CommandSet.rules)).where(CommandSet.id == cs_id)
    cs = (await db.execute(stmt)).scalar_one_or_none()
    if not cs:
        raise HTTPException(404, "Command set not found")
    return CommandSetOut.model_validate(cs)


@router.put("/command-sets/{cs_id}", response_model=CommandSetOut)
async def update_command_set(
    cs_id: int,
    body:  CommandSetUpdate,
    db:    AsyncSession = Depends(get_db),
    _:     AdminUser    = Depends(require_role(AdminRole.OPERATOR)),
):
    stmt = select(CommandSet).options(selectinload(CommandSet.rules)).where(CommandSet.id == cs_id)
    cs = (await db.execute(stmt)).scalar_one_or_none()
    if not cs:
        raise HTTPException(404, "Command set not found")
    if body.name is not None:
        if body.name != cs.name:
            dup = (await db.execute(select(CommandSet).where(CommandSet.name == body.name))).scalar_one_or_none()
            if dup:
                raise HTTPException(409, "Command set name already exists")
        cs.name = body.name
    if body.description is not None:
        cs.description = body.description
    if body.rules is not None:
        # Replace all rules
        cs.rules.clear()
        for r in body.rules:
            cs.rules.append(CommandRule(
                priority=r.priority, action=r.action,
                command_pattern=r.command_pattern, args_pattern=r.args_pattern,
            ))
    await db.commit()
    await db.refresh(cs, ["rules"])
    return CommandSetOut.model_validate(cs)


@router.delete("/command-sets/{cs_id}", response_model=StatusResponse)
async def delete_command_set(
    cs_id: int,
    db: AsyncSession = Depends(get_db),
    _:  AdminUser    = Depends(require_role(AdminRole.OPERATOR)),
):
    cs = (await db.execute(select(CommandSet).where(CommandSet.id == cs_id))).scalar_one_or_none()
    if not cs:
        raise HTTPException(404, "Command set not found")
    await db.delete(cs)
    await db.commit()
    return StatusResponse(status="ok", message=f"Command set {cs_id} deleted")
