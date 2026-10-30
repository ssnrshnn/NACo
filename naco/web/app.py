"""Public application on port 8080 (only ever reached through Caddy)."""
from __future__ import annotations

from importlib import resources

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from naco import __version__
from naco.api import errors
from naco.api.router import build_router
from naco.portal.app import router as portal_router
from naco.web import pages
from naco.web.security import SecurityHeaders


def create_public_app() -> FastAPI:
    app = FastAPI(title="NACo", version=__version__, docs_url=None, redoc_url=None, openapi_url=None)
    errors.install(app)
    app.add_middleware(SecurityHeaders)
    app.include_router(build_router())
    app.include_router(portal_router)
    app.include_router(pages.router)
    app.mount("/static", StaticFiles(directory=str(resources.files("naco") / "web" / "static")), name="static")
    return app
