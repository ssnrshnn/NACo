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
    """Readiness probe (back-compat alias of /health/ready)."""
    return await health_ready(db)


@router.get("/health/live")
async def health_live():
    """Liveness probe — 200 whenever the process serves HTTP.

    Deliberately touches no dependency: an orchestrator restarting the
    container because *Postgres* blipped only makes the outage worse.
    Point restart-triggering probes here; gate traffic on /health/ready.
    """
    from naco import __version__

    return {"status": "alive", "version": __version__}


@router.get("/health/ready")
async def health_ready(db: AsyncSession = Depends(get_db)):
    """Readiness probe — 200 only when the DB (and Redis, if reachable
    state is known) can serve requests; 503 otherwise."""
    from naco import __version__
    from naco.config import get_config

    cfg = get_config()

    db_ok = True
    try:
        await db.execute(select(func.count()).select_from(AdminUser))
    except Exception:
        db_ok = False

    # Redis is reported but does not gate readiness: an outage degrades
    # rate limiting / lockout, but authentication still works (the code
    # falls back to in-process implementations).
    redis_ok = True
    try:
        from naco.core.cache import get_redis
        r = await get_redis()
        redis_ok = bool(await r.ping()) if r is not None else False
    except Exception:
        redis_ok = False

    services = {
        "radius":   cfg.radius.enabled,
        "tacacs":   cfg.tacacs.enabled,
        "profiler": cfg.profiler.enabled,
        "portal":   cfg.portal.enabled,
    }

    payload = {
        "status":      "ok" if db_ok else "degraded",
        "database":    "connected" if db_ok else "error",
        "redis":       "connected" if redis_ok else "degraded",
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
