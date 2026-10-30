"""Public application on port 8080 (only ever reached through Caddy)."""
from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from sqlalchemy import text

from naco.db.engine import session_factory


def create_public_app() -> FastAPI:
    app = FastAPI(title="NACo", docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/api/v1/health/live", include_in_schema=False)
    async def live() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/api/v1/health/ready", include_in_schema=False)
    async def ready() -> JSONResponse:
        try:
            async with session_factory()() as db:
                await db.execute(text("SELECT 1"))
        except Exception:
            return JSONResponse({"status": "unavailable"}, status_code=503)
        return JSONResponse({"status": "ok"})

    return app
