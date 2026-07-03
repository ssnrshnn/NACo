"""Health & metrics endpoints (public, no auth required)."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from naco.db import get_db
from naco.db.models import AdminUser

router = APIRouter(prefix="/api/v1", tags=["Health"])


@router.get("/health")
async def health_check(db: AsyncSession = Depends(get_db)):
    """Liveness/readiness probe — returns 200 if the DB is reachable, 503 otherwise."""
    from naco import __version__
    from naco.config import get_config

    cfg = get_config()

    db_ok = True
    try:
        await db.execute(select(func.count()).select_from(AdminUser))
    except Exception:
        db_ok = False

    services = {
        "radius":   cfg.radius.enabled,
        "tacacs":   cfg.tacacs.enabled,
        "profiler": cfg.profiler.enabled,
        "portal":   cfg.portal.enabled,
    }

    payload = {
        "status":      "ok" if db_ok else "degraded",
        "database":    "connected" if db_ok else "error",
        "services":    services,
        "server_name": cfg.server.name,
        "version":     __version__,
    }
    return JSONResponse(status_code=200 if db_ok else 503, content=payload)


@router.get("/metrics", include_in_schema=False)
async def prometheus_metrics():
    """Prometheus-compatible metrics endpoint (no auth required)."""
    from starlette.responses import Response

    from naco.core.metrics import render_metrics
    return Response(content=render_metrics(), media_type="text/plain; charset=utf-8")
