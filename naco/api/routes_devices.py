"""Device CRUD endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from naco.api._audit import audit
from naco.api.auth import require_role
from naco.api.schemas import DeviceCreate, DeviceOut, DeviceUpdate, StatusResponse
from naco.db import get_db
from naco.db.models import AdminRole, AdminUser, Device

router = APIRouter(prefix="/api/v1", tags=["Devices"])


@router.post("/devices", response_model=DeviceOut, status_code=201)
async def create_device(
    body: DeviceCreate,
    db:    AsyncSession = Depends(get_db),
    admin: AdminUser    = Depends(require_role(AdminRole.OPERATOR)),
):
    """Manual device registration — pre-authorize a MAC for MAB without
    waiting for the passive profiler to discover it."""
    existing = (await db.execute(
        select(Device).where(Device.mac_address == body.mac_address)
    )).scalar_one_or_none()
    if existing:
        raise HTTPException(409, f"Device {body.mac_address} already exists")
    dev = Device(
        mac_address = body.mac_address,
        hostname    = body.hostname,
        device_type = body.device_type,
        notes       = body.notes,
        authorized  = body.authorized,
    )
    db.add(dev)
    await audit(db, admin, "CREATE", "device", "", f"mac={body.mac_address} authorized={body.authorized}")
    await db.commit()
    await db.refresh(dev)
    return DeviceOut.model_validate(dev)


@router.get("/devices", response_model=list[DeviceOut])
async def list_devices(
    skip: int = 0, limit: int = Query(100, le=500),
    authorized: bool | None = None,
    db: AsyncSession = Depends(get_db),
    _:  AdminUser    = Depends(require_role(AdminRole.VIEWER)),
):
    stmt = select(Device).offset(skip).limit(limit)
    if authorized is not None:
        stmt = stmt.where(Device.authorized == authorized)
    result = (await db.execute(stmt)).scalars().all()
    return [DeviceOut.model_validate(d) for d in result]


@router.get("/devices/{device_id}", response_model=DeviceOut)
async def get_device(
    device_id: int,
    db: AsyncSession = Depends(get_db),
    _:  AdminUser    = Depends(require_role(AdminRole.VIEWER)),
):
    dev = (await db.execute(select(Device).where(Device.id == device_id))).scalar_one_or_none()
    if not dev:
        raise HTTPException(404, "Device not found")
    return DeviceOut.model_validate(dev)


@router.put("/devices/{device_id}", response_model=DeviceOut)
async def update_device(
    device_id: int,
    body: DeviceUpdate,
    db:   AsyncSession = Depends(get_db),
    _:    AdminUser    = Depends(require_role(AdminRole.OPERATOR)),
):
    dev = (await db.execute(select(Device).where(Device.id == device_id))).scalar_one_or_none()
    if not dev:
        raise HTTPException(404, "Device not found")
    if body.authorized   is not None: dev.authorized   = body.authorized
    if body.notes        is not None: dev.notes        = body.notes
    if body.device_type  is not None: dev.device_type  = body.device_type
    await db.commit()
    await db.refresh(dev)
    return DeviceOut.model_validate(dev)


@router.delete("/devices/{device_id}", response_model=StatusResponse)
async def delete_device(
    device_id: int,
    db: AsyncSession = Depends(get_db),
    _:  AdminUser    = Depends(require_role(AdminRole.OPERATOR)),
):
    dev = (await db.execute(select(Device).where(Device.id == device_id))).scalar_one_or_none()
    if not dev:
        raise HTTPException(404, "Device not found")
    await db.delete(dev)
    await db.commit()
    return StatusResponse(status="ok", message=f"Device {device_id} deleted")
