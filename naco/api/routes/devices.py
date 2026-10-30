"""Device inventory: every MAC seen on the network, and its approval status."""
from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, Query, Response
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from naco.api.audit import AuditTrail, audit_trail, diff
from naco.api.common import Page, Paging, commit_or_conflict, flush_or_conflict, get_or_404, like, snapshot
from naco.api.deps import Principal, operator, viewer
from naco.api.errors import ApiError
from naco.core.netutils import is_randomized_mac, normalize_mac
from naco.core.oui import vendor_for
from naco.db.engine import get_db
from naco.db.models import Device, DeviceStatus
from naco.radius.reevaluate import reevaluator

router = APIRouter(prefix="/devices", tags=["devices"])
FIELDS = ["status", "device_type", "description", "notes"]


class DeviceOut(BaseModel):
    id: int
    mac_address: str
    status: DeviceStatus
    device_type: str
    vendor: str
    randomized: bool
    description: str
    notes: str
    first_seen: datetime
    last_seen: datetime
    last_nas_ip: str
    last_username: str


class DeviceCreate(BaseModel):
    mac_address: str
    status: DeviceStatus = DeviceStatus.APPROVED
    device_type: str = Field("", max_length=64)
    description: str = Field("", max_length=255)
    notes: str = Field("", max_length=4000)

    @field_validator("mac_address")
    @classmethod
    def _mac(cls, v: str) -> str:
        mac = normalize_mac(v)
        if mac is None:
            raise ValueError("not a MAC address")
        return mac


class DeviceUpdate(BaseModel):
    status: DeviceStatus | None = None
    device_type: str | None = Field(None, max_length=64)
    description: str | None = Field(None, max_length=255)
    notes: str | None = Field(None, max_length=4000)


class BulkStatus(BaseModel):
    ids: list[int] = Field(min_length=1, max_length=1000)
    status: DeviceStatus


def out(d: Device) -> DeviceOut:
    return DeviceOut(id=d.id, mac_address=d.mac_address, status=d.status, device_type=d.device_type,
                     vendor=d.vendor, randomized=is_randomized_mac(d.mac_address), description=d.description,
                     notes=d.notes, first_seen=d.first_seen, last_seen=d.last_seen, last_nas_ip=d.last_nas_ip,
                     last_username=d.last_username)


@router.get("", response_model=Page[DeviceOut])
async def list_devices(status: DeviceStatus | None = None, q: str = Query("", max_length=64),
                       paging: Paging = Depends(), _: Principal = Depends(viewer),
                       db: AsyncSession = Depends(get_db)) -> Page[DeviceOut]:
    query = select(Device).order_by(Device.last_seen.desc())
    if status is not None:
        query = query.where(Device.status == status)
    if q:
        mac = normalize_mac(q)
        pattern = like(mac or q.lower())
        query = query.where(or_(Device.mac_address.ilike(pattern, escape="\\"),
                                Device.vendor.ilike(like(q), escape="\\"),
                                Device.description.ilike(like(q), escape="\\"),
                                Device.device_type.ilike(like(q), escape="\\"),
                                Device.last_username.ilike(like(q), escape="\\")))
    rows, total = await paging.fetch(db, query)
    return Page(items=[out(d) for d in rows], total=total, page=paging.page, per_page=paging.per_page)


@router.get("/{device_id}", response_model=DeviceOut)
async def get_device(device_id: int, _: Principal = Depends(viewer), db: AsyncSession = Depends(get_db)) -> DeviceOut:
    return out(await get_or_404(db, Device, device_id, "device"))


@router.post("", response_model=DeviceOut, status_code=201)
async def create_device(body: DeviceCreate, _: Principal = Depends(operator),
                        audit: AuditTrail = Depends(audit_trail)) -> DeviceOut:
    device = Device(mac_address=body.mac_address, status=body.status, device_type=body.device_type,
                    description=body.description, notes=body.notes, vendor=vendor_for(body.mac_address))
    audit.db.add(device)
    await flush_or_conflict(audit.db, f"device {body.mac_address} already exists")
    audit.record("device.create", "device", device.id, device.mac_address, snapshot(device, FIELDS))
    await commit_or_conflict(audit.db, f"device {body.mac_address} already exists")
    reevaluator.schedule(f"device {device.mac_address} added")
    return out(device)


@router.patch("/{device_id}", response_model=DeviceOut)
async def update_device(device_id: int, body: DeviceUpdate, _: Principal = Depends(operator),
                        audit: AuditTrail = Depends(audit_trail)) -> DeviceOut:
    device = await get_or_404(audit.db, Device, device_id, "device")
    before = snapshot(device, FIELDS)
    for key, value in body.model_dump(exclude_unset=True).items():
        if value is not None:
            setattr(device, key, value)
    delta = diff(before, snapshot(device, FIELDS))
    audit.record("device.update", "device", device.id, device.mac_address, delta)
    await audit.db.commit()
    if {"status", "device_type"} & delta.keys():
        reevaluator.schedule(f"device {device.mac_address} changed")
    return out(device)


@router.post("/bulk", response_model=list[DeviceOut])
async def bulk_status(body: BulkStatus, _: Principal = Depends(operator),
                      audit: AuditTrail = Depends(audit_trail)) -> list[DeviceOut]:
    devices = list((await audit.db.execute(select(Device).where(Device.id.in_(body.ids)))).scalars())
    if len(devices) != len(set(body.ids)):
        raise ApiError(404, "some devices do not exist")
    for device in devices:
        if device.status is not body.status:
            audit.record("device.update", "device", device.id, device.mac_address,
                         {"status": [device.status.value, body.status.value]})
            device.status = body.status
    await audit.db.commit()
    reevaluator.schedule(f"{len(devices)} devices set to {body.status.value}")
    return [out(d) for d in devices]


@router.delete("/{device_id}", status_code=204)
async def delete_device(device_id: int, _: Principal = Depends(operator),
                        audit: AuditTrail = Depends(audit_trail)) -> Response:
    device = await get_or_404(audit.db, Device, device_id, "device")
    await audit.db.delete(device)
    audit.record("device.delete", "device", device_id, device.mac_address)
    await audit.db.commit()
    reevaluator.schedule(f"device {device.mac_address} deleted")
    return Response(status_code=204)
