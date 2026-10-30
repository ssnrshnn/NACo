"""CSV export (never secrets) and create-only CSV import.

Exported cells that a spreadsheet would treat as a formula (=, +, -, @, tab,
CR) are prefixed with a quote — device descriptions and usernames can come
from untrusted sources.
"""
from __future__ import annotations

import asyncio
import csv
import io
from collections.abc import Callable
from typing import Any, Literal

from fastapi import APIRouter, Depends, UploadFile
from fastapi.responses import Response
from pydantic import BaseModel, ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from naco.api.audit import AuditTrail, audit_trail
from naco.api.common import commit_or_conflict
from naco.api.deps import Principal, operator, superuser, viewer
from naco.api.errors import ApiError
from naco.api.routes.devices import DeviceCreate
from naco.api.routes.network import NasIn
from naco.api.routes.users import UserCreate
from naco.core.oui import vendor_for
from naco.core.passwords import hash_password, validate_user_password
from naco.core.timeutil import local_now
from naco.db.engine import get_db
from naco.db.models import AdminRole, Device, Group, NasClient, User, UserSource
from naco.radius.reevaluate import reevaluator

router = APIRouter(tags=["import & export"])

MAX_BYTES = 5 * 1024 * 1024
MAX_ERRORS = 100
ROW_LIMITS = {"users": 2000, "devices": 10000, "nas": 1000}
_FORMULA = ("=", "+", "-", "@", "\t", "\r")


def safe_cell(value: Any) -> str:
    text = "" if value is None else str(value.value if hasattr(value, "value") else value)
    return "'" + text if text.startswith(_FORMULA) else text


def _csv(headers: list[str], rows: list[list[Any]], kind: str) -> Response:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(headers)
    writer.writerows([[safe_cell(v) for v in row] for row in rows])
    name = f"naco-{kind}-{local_now():%Y%m%d}.csv"
    return Response(buffer.getvalue(), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})


@router.get("/export/{kind}.csv")
async def export(kind: Literal["users", "devices", "nas"], _: Principal = Depends(viewer),
                 db: AsyncSession = Depends(get_db)) -> Response:
    if kind == "users":
        rows = (await db.execute(select(User, Group).outerjoin(Group, User.group_id == Group.id)
                                 .order_by(User.username))).all()
        return _csv(["username", "source", "email", "full_name", "group", "enabled"],
                    [[u.username, u.source, u.email, u.full_name, g.name if g else "", u.enabled]
                     for u, g in rows], kind)
    if kind == "devices":
        devices = (await db.execute(select(Device).order_by(Device.mac_address))).scalars()
        return _csv(["mac_address", "status", "device_type", "vendor", "description", "notes", "last_seen"],
                    [[d.mac_address, d.status, d.device_type, d.vendor, d.description, d.notes,
                      d.last_seen.isoformat()] for d in devices], kind)
    nas = (await db.execute(select(NasClient).order_by(NasClient.name))).scalars()
    return _csv(["name", "ip_address", "coa_port", "require_message_authenticator", "description", "enabled"],
                [[n.name, n.ip_address, n.coa_port, n.require_message_authenticator, n.description, n.enabled]
                 for n in nas], kind)


class ImportResult(BaseModel):
    created: int
    skipped: int
    errors: list[str]


async def _rows(file: UploadFile, kind: str, required: set[str]) -> list[tuple[int, dict[str, str]]]:
    data = await file.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ApiError(413, "CSV files are limited to 5 MB")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ApiError(422, "the file is not UTF-8 text") from exc
    reader = csv.DictReader(io.StringIO(text))
    headers = {h.strip() for h in reader.fieldnames or []}
    if missing := required - headers:
        raise ApiError(422, f"missing columns: {', '.join(sorted(missing))}")
    rows = [(i + 2, {k.strip(): (v or "").strip() for k, v in row.items() if k}) for i, row in enumerate(reader)]
    if len(rows) > ROW_LIMITS[kind]:
        raise ApiError(413, f"at most {ROW_LIMITS[kind]} rows per {kind} import")
    return rows


def _bool(value: str, default: bool = True) -> bool:
    return default if value == "" else value.lower() in ("1", "true", "yes", "y")


def _error(line: int, exc: Exception) -> str:
    if isinstance(exc, ValidationError):
        first = exc.errors()[0]
        return f"line {line}: {'.'.join(str(p) for p in first['loc'])}: {first['msg']}"
    return f"line {line}: {exc}"


async def _import(rows: list[tuple[int, dict[str, str]]], build: Callable[[dict[str, str]], Any],
                  exists: set[str], key: Callable[[Any], str]) -> tuple[list[Any], int, list[str]]:
    created, skipped, errors = [], 0, []
    for line, row in rows:
        try:
            item = build(row)
        except (ValidationError, ValueError) as exc:
            errors.append(_error(line, exc))
            continue
        if key(item) in exists:
            skipped += 1
            continue
        exists.add(key(item))
        created.append((line, item))
    return created, skipped, errors[:MAX_ERRORS]


@router.post("/import/users", response_model=ImportResult)
async def import_users(file: UploadFile, principal: Principal = Depends(operator),
                       audit: AuditTrail = Depends(audit_trail)) -> ImportResult:
    rows = await _rows(file, "users", {"username", "password"})
    db = audit.db
    groups = {g.name.casefold(): g for g in (await db.execute(select(Group))).scalars()}
    existing = set((await db.execute(select(User.username))).scalars())

    def build(row: dict[str, str]) -> tuple[UserCreate, Group | None]:
        group = groups.get(row.get("group", "").casefold()) if row.get("group") else None
        if row.get("group") and group is None:
            raise ValueError(f"group {row['group']!r} does not exist")
        if group is not None and group.device_admin_privilege is not None and \
                not principal.role.allows(AdminRole.SUPERUSER):
            raise ValueError(f"only a SUPERUSER may add users to device-admin group {group.name}")
        validate_user_password(row.get("password", ""))
        return UserCreate(username=row.get("username", ""), password=row["password"],
                          email=row.get("email", ""), full_name=row.get("full_name", ""),
                          group_id=group.id if group else None, enabled=_bool(row.get("enabled", ""))), group

    created, skipped, errors = await _import(rows, build, existing, lambda item: item[0].username)
    await db.commit()  # don't hold the write lock while hashing passwords
    gate = asyncio.Semaphore(4)  # keep bcrypt from starving RADIUS of worker threads

    async def hashed(body: UserCreate) -> str:
        async with gate:
            return await hash_password(body.password)

    hashes = await asyncio.gather(*(hashed(item[0]) for _, item in created))
    for (_, (body, _group)), digest in zip(created, hashes, strict=True):
        db.add(User(username=body.username, source=UserSource.LOCAL, password_hash=digest, email=body.email,
                    full_name=body.full_name, group_id=body.group_id, enabled=body.enabled))
    audit.record("import.users", "user", "", "", {"created": len(created), "skipped": skipped,
                                                   "errors": len(errors)})
    await commit_or_conflict(db, "users changed while importing — run the import again")
    return ImportResult(created=len(created), skipped=skipped, errors=errors)


@router.post("/import/devices", response_model=ImportResult)
async def import_devices(file: UploadFile, _: Principal = Depends(operator),
                         audit: AuditTrail = Depends(audit_trail)) -> ImportResult:
    rows = await _rows(file, "devices", {"mac_address"})
    db = audit.db
    existing = set((await db.execute(select(Device.mac_address))).scalars())

    def build(row: dict[str, str]) -> DeviceCreate:
        data: dict[str, Any] = {k: row[k] for k in ("mac_address", "device_type", "description", "notes") if row.get(k)}
        if row.get("status"):
            data["status"] = row["status"].upper()
        return DeviceCreate(**data)

    created, skipped, errors = await _import(rows, build, existing, lambda item: item.mac_address)
    for _, body in created:
        db.add(Device(mac_address=body.mac_address, status=body.status, device_type=body.device_type,
                      description=body.description, notes=body.notes, vendor=vendor_for(body.mac_address)))
    audit.record("import.devices", "device", "", "", {"created": len(created), "skipped": skipped,
                                                       "errors": len(errors)})
    await commit_or_conflict(db, "devices changed while importing — run the import again")
    if created:
        reevaluator.schedule("devices imported")
    return ImportResult(created=len(created), skipped=skipped, errors=errors)


@router.post("/import/nas", response_model=ImportResult)
async def import_nas(file: UploadFile, _: Principal = Depends(superuser),
                     audit: AuditTrail = Depends(audit_trail)) -> ImportResult:
    rows = await _rows(file, "nas", {"name", "ip_address", "secret"})
    db = audit.db
    existing_ips = set((await db.execute(select(NasClient.ip_address))).scalars())
    existing_names = set((await db.execute(select(NasClient.name))).scalars())

    def build(row: dict[str, str]) -> NasIn:
        data: dict[str, Any] = {k: row[k] for k in ("name", "ip_address", "secret", "description") if row.get(k)}
        if row.get("coa_port"):
            data["coa_port"] = row["coa_port"]
        for flag in ("require_message_authenticator", "enabled"):
            if row.get(flag):
                data[flag] = _bool(row[flag])
        body = NasIn(**data)
        if body.name in existing_names:
            raise ValueError(f"a NAS named {body.name} already exists")
        return body

    created, skipped, errors = await _import(rows, build, existing_ips, lambda item: item.ip_address)
    for _, body in created:
        db.add(NasClient(**body.model_dump()))
    audit.record("import.nas", "nas", "", "", {"created": len(created), "skipped": skipped, "errors": len(errors)})
    await commit_or_conflict(db, "NAS clients changed while importing — run the import again")
    return ImportResult(created=len(created), skipped=skipped, errors=errors)
