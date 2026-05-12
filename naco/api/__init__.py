"""NACo REST API package.

Exposes a `create_api_app()` factory used by the test suite to spin up a
self-contained API-only FastAPI instance. In production, the REST routes are
mounted into the consolidated `naco.app:app` via `include_router`.
"""
from __future__ import annotations

from fastapi import FastAPI

from naco import __version__
from naco.api.routes import router
from naco.radius.freeradius_routes import router as freeradius_router


def create_api_app() -> FastAPI:
    """Build an API-only FastAPI instance (used by tests)."""
    app = FastAPI(
        title       = "NACo REST API",
        version     = __version__,
        description = "Network Access Control & AAA REST API",
        docs_url    = "/api/v1/docs",
        redoc_url   = "/api/v1/redoc",
        openapi_url = "/api/v1/openapi.json",
    )
    app.include_router(router)
    app.include_router(freeradius_router)
    return app


__all__ = ["create_api_app"]
