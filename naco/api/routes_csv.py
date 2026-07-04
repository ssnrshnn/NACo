"""CSV import / export for users, devices, and NAS clients.

Day-two bulk operations: migrate from a spreadsheet or another NAC, or
pull an inventory snapshot for auditing.

Design notes:
* Exports never contain credentials (no password hashes, no NAS secrets).
* Imports are **create-only**: rows whose natural key already exists are
  skipped and reported, never overwritten — an import cannot silently
  clobber production objects.
* Every row is validated through the same Pydantic models the JSON API
  uses, so CSV is not a side door around validation.
"""
from __future__ import annotations

import csv
import io

from fastapi import APIRouter, Depends, HTTPException, UploadFile
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from naco.api._audit import audit
from naco.api.auth import hash_password, require_role
from naco.api.routes_nas import NasCreate
from naco.api.schemas import DeviceCreate, UserCreate
from naco.db import get_db
from naco.db.models import AdminRole, AdminUser, Device, Group, NasClient, User

router = APIRouter(prefix="/api/v1", tags=["CSV import/export"])

_MAX_CSV_BYTES = 5 * 1024 * 1024
_MAX_CSV_ROWS = 10_000


class ImportReport(BaseModel):
    created: int
    skipped: int
    errors: list[str]


def _render_csv(header: list[str], rows: list[list]) -> PlainTextResponse:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(header)
    writer.writerows(rows)
    return PlainTextResponse(buf.getvalue(), media_type="text/csv")


async def _read_csv(file: UploadFile) -> list[dict[str, str]]:
    raw = await file.read()
    if len(raw) > _MAX_CSV_BYTES:
        raise HTTPException(413, "CSV larger than 5 MiB")
    try:
        text = raw.decode("utf-8-sig")  # tolerate Excel's BOM
    except UnicodeDecodeError:
        raise HTTPException(422, "CSV must be UTF-8 encoded")
    rows = list(csv.DictReader(io.StringIO(text)))
    if len(rows) > _MAX_CSV_ROWS:
        raise HTTPException(413, f"CSV has more than {_MAX_CSV_ROWS} rows")
    if not rows:
        raise HTTPException(422, "CSV contains no data rows (is the header present?)")
    return rows


def _truthy(value: str | None, default: bool = True) -> bool:
    if value is None or value.strip() == "":
        return default
    return value.strip().lower() in ("1", "true", "yes", "y", "on")


# ── Users ───────────────────────────────────────────────────────────────────

@router.get("/users/export.csv", response_class=PlainTextResponse)
async def export_users(
    db: AsyncSession = Depends(get_db),
    _:  AdminUser    = Depends(require_role(AdminRole.OPERATOR)),
):
    """All network users as CSV (no password hashes)."""
    rows = (await db.execute(
        select(User, Group.name).outerjoin(Group, User.group_id == Group.id)
        .order_by(User.username)
    )).all()
    return _render_csv(
        ["username", "email", "full_name", "group", "enabled"],
        [[u.username, u.email, u.full_name, gname or "", u.enabled] for u, gname in rows],
    )


@router.post("/users/import", response_model=ImportReport)
async def import_users(
    file: UploadFile,
    db: AsyncSession = Depends(get_db),
    admin: AdminUser = Depends(require_role(AdminRole.OPERATOR)),
):
    """Create users from CSV: username,password,email,full_name,group,enabled.

    ``group`` is a group *name* and must already exist. Existing usernames
    are skipped (create-only).
    """
    rows = await _read_csv(file)
    groups = {g.name: g.id for g in (await db.execute(select(Group))).scalars()}
    existing = {u for (u,) in (await db.execute(select(User.username))).all()}

    created, skipped, errors = 0, 0, []
    for lineno, row in enumerate(rows, 2):  # header is line 1
        username = (row.get("username") or "").strip()
        if username in existing:
            skipped += 1
            continue
        group_name = (row.get("group") or "").strip()
        if group_name and group_name not in groups:
            errors.append(f"line {lineno}: group {group_name!r} does not exist")
            continue
        try:
            body = UserCreate(
                username=username,
                password=row.get("password") or "",
                email=(row.get("email") or "").strip(),
                full_name=(row.get("full_name") or "").strip(),
                group_id=groups.get(group_name),
                enabled=_truthy(row.get("enabled")),
            )
        except ValidationError as exc:
            errors.append(f"line {lineno}: {exc.errors()[0]['msg']}")
            continue
        db.add(User(
            username=body.username, password_hash=hash_password(body.password),
            email=body.email, full_name=body.full_name,
            group_id=body.group_id, enabled=body.enabled,
        ))
        existing.add(username)
        created += 1

    await audit(db, admin, "IMPORT", "user", "csv",
                f"created={created} skipped={skipped} errors={len(errors)}")
    await db.commit()
    return ImportReport(created=created, skipped=skipped, errors=errors[:50])


# ── Devices ─────────────────────────────────────────────────────────────────

@router.get("/devices/export.csv", response_class=PlainTextResponse)
async def export_devices(
    db: AsyncSession = Depends(get_db),
    _:  AdminUser    = Depends(require_role(AdminRole.OPERATOR)),
):
    devices = (await db.execute(select(Device).order_by(Device.mac_address))).scalars().all()
    return _render_csv(
        ["mac_address", "ip_address", "hostname", "vendor", "device_type",
         "os_type", "authorized", "notes"],
        [[d.mac_address, d.ip_address or "", d.hostname or "", d.vendor or "",
          d.device_type, d.os_type, d.authorized, d.notes or ""] for d in devices],
    )


@router.post("/devices/import", response_model=ImportReport)
async def import_devices(
    file: UploadFile,
    db: AsyncSession = Depends(get_db),
    admin: AdminUser = Depends(require_role(AdminRole.OPERATOR)),
):
    """Create devices from CSV: mac_address,hostname,device_type,notes,authorized.

    Same semantics as ``POST /api/v1/devices`` (manual MAB pre-authorization).
    Existing MACs are skipped.
    """
    rows = await _read_csv(file)
    existing = {m for (m,) in (await db.execute(select(Device.mac_address))).all()}

    created, skipped, errors = 0, 0, []
    for lineno, row in enumerate(rows, 2):
        try:
            body = DeviceCreate(
                mac_address=(row.get("mac_address") or "").strip(),
                hostname=(row.get("hostname") or "").strip(),
                device_type=(row.get("device_type") or "").strip() or "unknown",
                notes=(row.get("notes") or "").strip(),
                authorized=_truthy(row.get("authorized"), default=False),
            )
        except ValidationError as exc:
            errors.append(f"line {lineno}: {exc.errors()[0]['msg']}")
            continue
        if body.mac_address in existing:
            skipped += 1
            continue
        db.add(Device(
            mac_address=body.mac_address, hostname=body.hostname,
            device_type=body.device_type, notes=body.notes,
            authorized=body.authorized,
        ))
        existing.add(body.mac_address)
        created += 1

    await audit(db, admin, "IMPORT", "device", "csv",
                f"created={created} skipped={skipped} errors={len(errors)}")
    await db.commit()
    return ImportReport(created=created, skipped=skipped, errors=errors[:50])


# ── NAS clients ─────────────────────────────────────────────────────────────

@router.get("/nas/export.csv", response_class=PlainTextResponse)
async def export_nas(
    db: AsyncSession = Depends(get_db),
    _:  AdminUser    = Depends(require_role(AdminRole.OPERATOR)),
):
    """NAS inventory as CSV. Secrets are write-only and never exported."""
    clients = (await db.execute(select(NasClient).order_by(NasClient.name))).scalars().all()
    return _render_csv(
        ["name", "ip_address", "description", "enabled"],
        [[c.name, c.ip_address, c.description or "", c.enabled] for c in clients],
    )


@router.post("/nas/import", response_model=ImportReport)
async def import_nas(
    file: UploadFile,
    db: AsyncSession = Depends(get_db),
    admin: AdminUser = Depends(require_role(AdminRole.OPERATOR)),
):
    """Create NAS clients from CSV: name,ip_address,secret,description,enabled.

    The ``secret`` column is required per row (≥ 16 chars) — exports don't
    include it, so a round-trip needs the column filled in. Existing names
    or IPs are skipped. The RADIUS server hot-reloads within 30 s.
    """
    rows = await _read_csv(file)
    existing_names = {n for (n,) in (await db.execute(select(NasClient.name))).all()}
    existing_ips = {i for (i,) in (await db.execute(select(NasClient.ip_address))).all()}

    created, skipped, errors = 0, 0, []
    for lineno, row in enumerate(rows, 2):
        try:
            body = NasCreate(
                name=(row.get("name") or "").strip(),
                ip_address=(row.get("ip_address") or "").strip(),
                secret=row.get("secret") or "",
                description=(row.get("description") or "").strip(),
                enabled=_truthy(row.get("enabled")),
            )
        except ValidationError as exc:
            errors.append(f"line {lineno}: {exc.errors()[0]['msg']}")
            continue
        if body.name in existing_names or body.ip_address in existing_ips:
            skipped += 1
            continue
        db.add(NasClient(
            name=body.name, ip_address=body.ip_address, secret=body.secret,
            description=body.description, enabled=body.enabled,
        ))
        existing_names.add(body.name)
        existing_ips.add(body.ip_address)
        created += 1

    # Never log secrets — counts only.
    await audit(db, admin, "IMPORT", "nas", "csv",
                f"created={created} skipped={skipped} errors={len(errors)}")
    await db.commit()
    return ImportReport(created=created, skipped=skipped, errors=errors[:50])
