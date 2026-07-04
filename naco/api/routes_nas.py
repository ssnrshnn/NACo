"""NAS (RADIUS client) CRUD endpoints.

The RADIUS server hot-reloads these rows every 30 s (background task in
``naco.radius.server``), so changes take effect without a restart. Secrets
are write-only: never returned by the API.
"""
from __future__ import annotations

import ipaddress
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from naco.api._audit import audit
from naco.api.auth import require_role
from naco.api.schemas import StatusResponse
from naco.db import get_db
from naco.db.models import AdminRole, AdminUser, NasClient

router = APIRouter(prefix="/api/v1", tags=["NAS Clients"])


class NasCreate(BaseModel):
    name:        str = Field(..., min_length=1, max_length=64)
    ip_address:  str = Field(..., max_length=45)
    secret:      str = Field(..., min_length=16, max_length=128)
    description: str = Field("", max_length=255)
    enabled:     bool = True

    @field_validator("ip_address")
    @classmethod
    def valid_ip(cls, v):
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"Invalid IP address: {v!r}")
        return v


class NasUpdate(BaseModel):
    name:        str | None = Field(None, min_length=1, max_length=64)
    ip_address:  str | None = Field(None, max_length=45)
    secret:      str | None = Field(None, min_length=16, max_length=128)
    description: str | None = Field(None, max_length=255)
    enabled:     bool | None = None

    @field_validator("ip_address")
    @classmethod
    def valid_ip(cls, v):
        if v is not None:
            return NasCreate.valid_ip(v)
        return v


class NasOut(BaseModel):
    """Secret intentionally omitted — write-only."""
    id:          int
    name:        str
    ip_address:  str
    description: str
    enabled:     bool
    created_at:  datetime

    model_config = {"from_attributes": True}


@router.get("/nas", response_model=list[NasOut])
async def list_nas(
    skip: int = 0, limit: int = Query(100, le=500),
    db: AsyncSession = Depends(get_db),
    _:  AdminUser    = Depends(require_role(AdminRole.VIEWER)),
):
    stmt = select(NasClient).order_by(NasClient.name).offset(skip).limit(limit)
    rows = (await db.execute(stmt)).scalars().all()
    return [NasOut.model_validate(r) for r in rows]


@router.post("/nas", response_model=NasOut, status_code=201)
async def create_nas(
    body: NasCreate,
    db:    AsyncSession = Depends(get_db),
    admin: AdminUser    = Depends(require_role(AdminRole.OPERATOR)),
):
    dup = (await db.execute(
        select(NasClient).where(
            (NasClient.name == body.name) | (NasClient.ip_address == body.ip_address)
        )
    )).scalars().first()
    if dup:
        raise HTTPException(409, "A NAS client with that name or IP already exists")
    nas = NasClient(
        name        = body.name,
        ip_address  = body.ip_address,
        secret      = body.secret,
        description = body.description,
        enabled     = body.enabled,
    )
    db.add(nas)
    await audit(db, admin, "CREATE", "nas_client", "", f"name={body.name} ip={body.ip_address}")
    await db.commit()
    await db.refresh(nas)
    return NasOut.model_validate(nas)


@router.put("/nas/{nas_id}", response_model=NasOut)
async def update_nas(
    nas_id: int,
    body: NasUpdate,
    db:    AsyncSession = Depends(get_db),
    admin: AdminUser    = Depends(require_role(AdminRole.OPERATOR)),
):
    nas = (await db.execute(select(NasClient).where(NasClient.id == nas_id))).scalar_one_or_none()
    if not nas:
        raise HTTPException(404, "NAS client not found")
    if body.name        is not None: nas.name        = body.name
    if body.ip_address  is not None: nas.ip_address  = body.ip_address
    if body.secret      is not None: nas.secret      = body.secret
    if body.description is not None: nas.description = body.description
    if body.enabled     is not None: nas.enabled     = body.enabled
    await audit(db, admin, "UPDATE", "nas_client", str(nas_id),
                f"name={nas.name} secret_changed={body.secret is not None}")
    await db.commit()
    await db.refresh(nas)
    return NasOut.model_validate(nas)


@router.delete("/nas/{nas_id}", response_model=StatusResponse)
async def delete_nas(
    nas_id: int,
    db:    AsyncSession = Depends(get_db),
    admin: AdminUser    = Depends(require_role(AdminRole.OPERATOR)),
):
    nas = (await db.execute(select(NasClient).where(NasClient.id == nas_id))).scalar_one_or_none()
    if not nas:
        raise HTTPException(404, "NAS client not found")
    await audit(db, admin, "DELETE", "nas_client", str(nas_id), f"name={nas.name}")
    await db.delete(nas)
    await db.commit()
    return StatusResponse(status="ok", message=f"NAS client {nas_id} deleted")
