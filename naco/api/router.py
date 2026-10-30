"""All /api/v1 routes."""
from __future__ import annotations

from fastapi import APIRouter

from naco.api.routes import auth, health

PUBLIC_ROUTES = {("POST", "/api/v1/auth/login"), ("GET", "/api/v1/health/live"), ("GET", "/api/v1/health/ready")}


def build_router() -> APIRouter:
    api = APIRouter(prefix="/api/v1")
    for module in (health, auth):
        api.include_router(module.router)
    return api
