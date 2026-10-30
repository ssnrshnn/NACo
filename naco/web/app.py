"""Public application on port 8080 (only ever reached through Caddy)."""
from __future__ import annotations

from fastapi import FastAPI

from naco import __version__
from naco.api import errors
from naco.api.router import build_router
from naco.web.security import SecurityHeaders


def create_public_app() -> FastAPI:
    app = FastAPI(title="NACo", version=__version__, docs_url=None, redoc_url=None, openapi_url=None)
    errors.install(app)
    app.add_middleware(SecurityHeaders)
    app.include_router(build_router())
    return app
