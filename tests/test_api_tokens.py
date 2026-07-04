"""Static API tokens with role scopes (/api/v1/tokens + bearer auth)."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from naco.api.auth import hash_password
from naco.db.models import AdminRole, AdminUser, ApiToken

pytestmark = pytest.mark.asyncio


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


async def _mint(client: AsyncClient, admin_token: str, name: str,
                role: str = "VIEWER", **extra) -> dict:
    r = await client.post(
        "/api/v1/tokens",
        json={"name": name, "role": role, **extra},
        headers=_auth(admin_token),
    )
    assert r.status_code == 201, r.text
    return r.json()


class TestTokenLifecycle:
    async def test_create_returns_raw_once_list_shows_prefix_only(
        self, client: AsyncClient, db: AsyncSession, admin_user: AdminUser, admin_token: str
    ):
        created = await _mint(client, admin_token, "ci-deploy", role="OPERATOR")
        assert created["token"].startswith("naco_")
        assert created["prefix"] == created["token"][:10]

        r = await client.get("/api/v1/tokens", headers=_auth(admin_token))
        rows = r.json()
        assert len(rows) == 1
        assert "token" not in rows[0]
        assert rows[0]["prefix"] == created["prefix"]

        # Raw value must never be persisted
        row = (await db.execute(select(ApiToken))).scalar_one()
        assert created["token"] not in (row.token_hash, row.prefix)

    async def test_duplicate_name_rejected(
        self, client: AsyncClient, admin_user: AdminUser, admin_token: str
    ):
        await _mint(client, admin_token, "dup")
        r = await client.post("/api/v1/tokens", json={"name": "dup"},
                              headers=_auth(admin_token))
        assert r.status_code == 409

    async def test_delete_revokes_immediately(
        self, client: AsyncClient, admin_user: AdminUser, admin_token: str
    ):
        created = await _mint(client, admin_token, "shortlived")
        assert (await client.get("/api/v1/users", headers=_auth(created["token"]))).status_code == 200
        r = await client.delete(f"/api/v1/tokens/{created['id']}", headers=_auth(admin_token))
        assert r.status_code == 200
        assert (await client.get("/api/v1/users", headers=_auth(created["token"]))).status_code == 401


class TestTokenAuth:
    async def test_viewer_token_reads_but_cannot_write(
        self, client: AsyncClient, admin_user: AdminUser, admin_token: str
    ):
        created = await _mint(client, admin_token, "readonly", role="VIEWER")
        tok = created["token"]
        assert (await client.get("/api/v1/users", headers=_auth(tok))).status_code == 200
        r = await client.post(
            "/api/v1/users",
            json={"username": "x1", "password": "Passw0rd!", "email": ""},
            headers=_auth(tok),
        )
        assert r.status_code == 403

    async def test_operator_token_can_write(
        self, client: AsyncClient, admin_user: AdminUser, admin_token: str
    ):
        created = await _mint(client, admin_token, "provisioner", role="OPERATOR")
        r = await client.post(
            "/api/v1/users",
            json={"username": "x2", "password": "Passw0rd!", "email": ""},
            headers=_auth(created["token"]),
        )
        assert r.status_code in (200, 201), r.text

    async def test_expired_token_rejected(
        self, client: AsyncClient, db: AsyncSession, admin_user: AdminUser, admin_token: str
    ):
        created = await _mint(client, admin_token, "expiring", expires_days=1)
        row = (await db.execute(
            select(ApiToken).where(ApiToken.name == "expiring")
        )).scalar_one()
        row.expires_at = datetime.now(UTC) - timedelta(minutes=1)
        await db.commit()
        assert (await client.get("/api/v1/users", headers=_auth(created["token"]))).status_code == 401

    async def test_garbage_token_rejected(self, client: AsyncClient, admin_user: AdminUser):
        assert (await client.get("/api/v1/users",
                                 headers=_auth("naco_not-a-real-token"))).status_code == 401

    async def test_audit_username_is_token_name(
        self, client: AsyncClient, db: AsyncSession, admin_user: AdminUser, admin_token: str
    ):
        created = await _mint(client, admin_token, "auditor", role="OPERATOR")
        await client.post(
            "/api/v1/users",
            json={"username": "x3", "password": "Passw0rd!", "email": ""},
            headers=_auth(created["token"]),
        )
        from naco.db.models import AdminAuditLog
        entries = (await db.execute(
            select(AdminAuditLog).where(AdminAuditLog.admin_username == "token:auditor")
        )).scalars().all()
        assert entries, "user creation via token must be audited under token:<name>"


class TestTokenManagementGuards:
    async def test_token_cannot_manage_tokens(
        self, client: AsyncClient, admin_user: AdminUser, admin_token: str
    ):
        """Even a SUPERUSER-scoped token must not mint or revoke tokens."""
        created = await _mint(client, admin_token, "godmode", role="SUPERUSER")
        tok = created["token"]
        r = await client.post("/api/v1/tokens", json={"name": "sneaky"}, headers=_auth(tok))
        assert r.status_code == 403
        r = await client.delete(f"/api/v1/tokens/{created['id']}", headers=_auth(tok))
        assert r.status_code == 403

    async def test_operator_admin_cannot_manage_tokens(
        self, client: AsyncClient, db: AsyncSession, admin_user: AdminUser, admin_token: str
    ):
        db.add(AdminUser(username="op", password_hash=hash_password("Operator123"),
                         role=AdminRole.OPERATOR, enabled=True))
        await db.commit()
        login = await client.post("/api/v1/auth/login",
                                  json={"username": "op", "password": "Operator123"})
        op_token = login.json()["access_token"]
        assert (await client.get("/api/v1/tokens", headers=_auth(op_token))).status_code == 403
        r = await client.post("/api/v1/tokens", json={"name": "nope"}, headers=_auth(op_token))
        assert r.status_code == 403
