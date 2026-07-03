"""
NACo REST API — composite router
=================================
Assembles all per-resource sub-routers into a single ``router`` instance that
``naco.api.__init__`` and ``naco.app`` include into the FastAPI application.

Each resource domain lives in its own ``routes_*.py`` module for maintainability:

    routes_health.py       — /health, /metrics (public, no auth)
    routes_auth.py         — /auth/login, /auth/totp/* (login + 2FA)
    routes_users.py        — /users CRUD
    routes_groups.py       — /groups CRUD
    routes_devices.py      — /devices CRUD
    routes_policies.py     — /policies CRUD
    routes_logs.py         — /logs/auth, /logs/tacacs, /logs/audit
    routes_sessions.py     — /sessions (active RADIUS sessions + CoA)
    routes_dashboard.py    — /dashboard stats, /guests
    routes_command_sets.py — /command-sets CRUD (TACACS+)
"""
from __future__ import annotations

from fastapi import APIRouter

from naco.api.routes_auth import router as auth_router
from naco.api.routes_command_sets import router as command_sets_router
from naco.api.routes_dashboard import router as dashboard_router
from naco.api.routes_devices import router as devices_router
from naco.api.routes_groups import router as groups_router
from naco.api.routes_health import router as health_router
from naco.api.routes_logs import router as logs_router
from naco.api.routes_policies import router as policies_router
from naco.api.routes_sessions import router as sessions_router
from naco.api.routes_users import router as users_router

router = APIRouter()

router.include_router(health_router)
router.include_router(auth_router)
router.include_router(users_router)
router.include_router(groups_router)
router.include_router(devices_router)
router.include_router(policies_router)
router.include_router(logs_router)
router.include_router(sessions_router)
router.include_router(dashboard_router)
router.include_router(command_sets_router)
