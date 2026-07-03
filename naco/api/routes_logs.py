"""Log query endpoints: auth logs, TACACS+ logs, admin audit logs."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from naco.api.auth import require_role
from naco.api.schemas import AuthLogOut, TacacsLogOut
from naco.db import get_db
from naco.db.models import AdminAuditLog, AdminRole, AdminUser, AuthLog, AuthResult, TacacsLog

router = APIRouter(prefix="/api/v1", tags=["Logs"])


@router.get("/logs/auth", response_model=list[AuthLogOut])
async def auth_logs(
    skip:    int = 0,
    limit:   int = Query(100, le=500),
    result:  str | None = None,
    username: str | None = None,
    db: AsyncSession = Depends(get_db),
    _:  AdminUser    = Depends(require_role(AdminRole.VIEWER)),
):
    stmt = select(AuthLog).order_by(AuthLog.timestamp.desc()).offset(skip).limit(limit)
    if result:
        result_upper = result.upper()
        valid_results = {e.value for e in AuthResult}
        if result_upper not in valid_results:
            raise HTTPException(400, f"Invalid result filter. Must be one of: {', '.join(sorted(valid_results))}")
        stmt = stmt.where(AuthLog.result == result_upper)
    if username:
        stmt = stmt.where(AuthLog.username.ilike(f"%{username}%"))
    rows = (await db.execute(stmt)).scalars().all()
    return [AuthLogOut.model_validate(r) for r in rows]


@router.get("/logs/tacacs", response_model=list[TacacsLogOut])
async def tacacs_logs(
    skip: int = 0, limit: int = Query(100, le=500),
    db: AsyncSession = Depends(get_db),
    _:  AdminUser    = Depends(require_role(AdminRole.VIEWER)),
):
    stmt = select(TacacsLog).order_by(TacacsLog.timestamp.desc()).offset(skip).limit(limit)
    rows = (await db.execute(stmt)).scalars().all()
    return [TacacsLogOut.model_validate(r) for r in rows]


@router.get("/logs/audit")
async def audit_logs(
    skip: int = 0, limit: int = Query(100, le=500),
    admin_username: str | None = None,
    action: str | None = None,
    db: AsyncSession = Depends(get_db),
    _:  AdminUser    = Depends(require_role(AdminRole.OPERATOR)),
):
    stmt = select(AdminAuditLog).order_by(AdminAuditLog.timestamp.desc()).offset(skip).limit(limit)
    if admin_username:
        stmt = stmt.where(AdminAuditLog.admin_username == admin_username)
    if action:
        stmt = stmt.where(AdminAuditLog.action == action.upper())
    rows = (await db.execute(stmt)).scalars().all()
    return [
        {
            "id": r.id,
            "timestamp": r.timestamp.isoformat(),
            "admin_username": r.admin_username,
            "action": r.action,
            "resource_type": r.resource_type,
            "resource_id": r.resource_id,
            "detail": r.detail,
        }
        for r in rows
    ]
