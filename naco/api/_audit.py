"""Shared audit-log helper used by all API sub-routers."""
from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from naco.db.models import AdminAuditLog, AdminUser


async def audit(
    db: AsyncSession,
    admin: AdminUser,
    action: str,
    resource_type: str,
    resource_id: str = "",
    detail: str = "",
) -> None:
    """Record an admin audit log entry (best-effort)."""
    try:
        db.add(AdminAuditLog(
            admin_username=admin.username,
            action=action,
            resource_type=resource_type,
            resource_id=str(resource_id),
            detail=detail[:1024],
        ))
    except Exception:
        pass
