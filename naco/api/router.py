"""All /api/v1 routes."""
from __future__ import annotations

from collections.abc import Iterator

from fastapi import APIRouter
from fastapi.routing import APIRoute

from naco.api.routes import (
    admin,
    auth,
    devices,
    health,
    network,
    overview,
    policies,
    sessions,
    transfer,
    users,
)

PREFIX = "/api/v1"
MODULES = (health, auth, users, devices, policies, network, sessions, admin, transfer, overview)

# Routes that are reachable without signing in.
PUBLIC_ROUTES = {("POST", "/api/v1/auth/login"), ("GET", "/api/v1/health/live"),
                 ("GET", "/api/v1/health/ready")}


def build_router() -> APIRouter:
    api = APIRouter(prefix=PREFIX)
    for module in MODULES:
        api.include_router(module.router)
    return api


def iter_api_routes() -> Iterator[tuple[str, str, APIRoute]]:
    """(method, full path, route) for every API endpoint — used by the
    role-matrix and audit-coverage tests."""
    for module in MODULES:
        for route in module.router.routes:
            if isinstance(route, APIRoute):
                for method in sorted((route.methods or set()) - {"HEAD"}):
                    yield method, PREFIX + route.path, route
