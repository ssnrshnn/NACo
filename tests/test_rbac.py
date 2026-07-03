"""Phase 1.1 — RBAC enforcement on the REST API.

We use the existing pytest fixtures (in-memory SQLite, ASGI test client)
and seed admins at different role tiers, then verify:

* a VIEWER can GET but cannot mutate;
* an OPERATOR can mutate users/groups/policies but cannot use endpoints
  marked as VIEWER-only-via-OPERATOR-or-higher (audit logs are OPERATOR-
  gated by design);
* a SUPERUSER can do anything an OPERATOR can.

Role enforcement is delegated to :func:`naco.api.auth.require_role`; the
DB-side back-compat (``is_superuser=True`` implies SUPERUSER) is also
exercised here so admins migrated from a pre-Phase-1 row keep working.
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from naco.api.auth import create_access_token, hash_password
from naco.db.models import AdminRole, AdminUser

# ---------------------------------------------------------------------------
# Helpers: seed admins at each role and mint a bearer token for them.
# ---------------------------------------------------------------------------

async def _seed_admin(db: AsyncSession, username: str, role: AdminRole) -> AdminUser:
    u = AdminUser(
        username=username,
        password_hash=hash_password("Passw0rd!"),
        email=f"{username}@test.local",
        role=role,
        is_superuser=(role == AdminRole.SUPERUSER),
        enabled=True,
    )
    db.add(u)
    await db.commit()
    await db.refresh(u)
    return u


@pytest_asyncio.fixture
async def viewer_token(db: AsyncSession) -> str:
    await _seed_admin(db, "viewer1", AdminRole.VIEWER)
    return create_access_token("viewer1")


@pytest_asyncio.fixture
async def operator_token(db: AsyncSession) -> str:
    await _seed_admin(db, "operator1", AdminRole.OPERATOR)
    return create_access_token("operator1")


@pytest_asyncio.fixture
async def superuser_token(db: AsyncSession) -> str:
    await _seed_admin(db, "super1", AdminRole.SUPERUSER)
    return create_access_token("super1")


@pytest_asyncio.fixture
async def legacy_superuser_token(db: AsyncSession) -> str:
    """Admin row from a pre-Phase-1 baseline: ``is_superuser=True`` but
    role left at the default OPERATOR. Must still behave as SUPERUSER."""
    u = AdminUser(
        username="legacy_super",
        password_hash=hash_password("Passw0rd!"),
        role=AdminRole.OPERATOR,    # default for older rows
        is_superuser=True,          # was the *only* signal pre-Phase-1
        enabled=True,
    )
    db.add(u)
    await db.commit()
    return create_access_token("legacy_super")


# ---------------------------------------------------------------------------
# VIEWER can list but cannot mutate.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestViewerRole:
    async def test_viewer_can_list_users(self, client: AsyncClient, viewer_token: str):
        resp = await client.get(
            "/api/v1/users",
            headers={"Authorization": f"Bearer {viewer_token}"},
        )
        assert resp.status_code == 200

    async def test_viewer_can_list_devices(self, client: AsyncClient, viewer_token: str):
        resp = await client.get(
            "/api/v1/devices",
            headers={"Authorization": f"Bearer {viewer_token}"},
        )
        assert resp.status_code == 200

    async def test_viewer_cannot_create_user(self, client: AsyncClient, viewer_token: str):
        resp = await client.post(
            "/api/v1/users",
            headers={"Authorization": f"Bearer {viewer_token}"},
            json={"username": "x", "password": "Passw0rd!", "email": ""},
        )
        assert resp.status_code == 403, resp.text

    async def test_viewer_cannot_delete_user(self, client: AsyncClient, viewer_token: str):
        resp = await client.delete(
            "/api/v1/users/9999",
            headers={"Authorization": f"Bearer {viewer_token}"},
        )
        assert resp.status_code == 403, resp.text

    async def test_viewer_cannot_create_policy(self, client: AsyncClient, viewer_token: str):
        resp = await client.post(
            "/api/v1/policies",
            headers={"Authorization": f"Bearer {viewer_token}"},
            json={"name": "deny-all", "action": "DENY", "priority": 100, "enabled": True},
        )
        assert resp.status_code == 403, resp.text

    async def test_viewer_cannot_read_audit_log(self, client: AsyncClient, viewer_token: str):
        # Audit log is OPERATOR-gated — VIEWER must be refused.
        resp = await client.get(
            "/api/v1/logs/audit",
            headers={"Authorization": f"Bearer {viewer_token}"},
        )
        assert resp.status_code == 403, resp.text


# ---------------------------------------------------------------------------
# OPERATOR can mutate everything an admin needs day-to-day.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestOperatorRole:
    async def test_operator_can_create_user(self, client: AsyncClient, operator_token: str):
        resp = await client.post(
            "/api/v1/users",
            headers={"Authorization": f"Bearer {operator_token}"},
            json={"username": "managed", "password": "Passw0rd!", "email": ""},
        )
        assert resp.status_code == 201

    async def test_operator_can_list_audit_log(self, client: AsyncClient, operator_token: str):
        resp = await client.get(
            "/api/v1/logs/audit",
            headers={"Authorization": f"Bearer {operator_token}"},
        )
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# SUPERUSER is at least as powerful as OPERATOR.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestSuperuserRole:
    async def test_super_can_create_user(self, client: AsyncClient, superuser_token: str):
        resp = await client.post(
            "/api/v1/users",
            headers={"Authorization": f"Bearer {superuser_token}"},
            json={"username": "managed2", "password": "Passw0rd!", "email": ""},
        )
        assert resp.status_code == 201

    async def test_super_can_list_users(self, client: AsyncClient, superuser_token: str):
        resp = await client.get(
            "/api/v1/users",
            headers={"Authorization": f"Bearer {superuser_token}"},
        )
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Back-compat: ``is_superuser=True`` overrides role-rank check.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestLegacySuperuserBackcompat:
    async def test_legacy_super_can_create_user(
        self, client: AsyncClient, legacy_superuser_token: str,
    ):
        resp = await client.post(
            "/api/v1/users",
            headers={"Authorization": f"Bearer {legacy_superuser_token}"},
            json={"username": "legacy_managed", "password": "Passw0rd!", "email": ""},
        )
        assert resp.status_code == 201
