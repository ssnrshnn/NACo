"""Phase 0.3 — TOTP enrollment secret stored server-side; verify uses JSON body only."""
from __future__ import annotations

import pyotp
import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from naco.db.models import AdminUser


@pytest.mark.asyncio
class TestTotpEnrollment:
    async def test_setup_returns_uri_without_top_level_secret_key(
        self, client: AsyncClient, admin_token: str,
    ):
        r = await client.post(
            "/api/v1/auth/totp/setup",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 200
        data = r.json()
        assert "provisioning_uri" in data
        assert "secret" not in data

    async def test_verify_round_trip(self, client: AsyncClient, admin_token: str, db: AsyncSession):
        r = await client.post(
            "/api/v1/auth/totp/setup",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 200

        row = (await db.execute(select(AdminUser).where(AdminUser.username == "testadmin"))).scalar_one()
        assert row.pending_totp_secret
        assert len(row.pending_totp_secret) >= 16

        code = pyotp.TOTP(row.pending_totp_secret).now()
        r2 = await client.post(
            "/api/v1/auth/totp/verify",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={"code": code},
        )
        assert r2.status_code == 200, r2.text
        await db.refresh(row)
        assert row.totp_secret
        assert row.pending_totp_secret is None

    async def test_verify_without_setup_fails(self, client: AsyncClient, admin_token: str, db: AsyncSession):
        u = (await db.execute(select(AdminUser).where(AdminUser.username == "testadmin"))).scalar_one()
        u.pending_totp_secret = None
        u.totp_secret = None
        await db.commit()

        r = await client.post(
            "/api/v1/auth/totp/verify",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={"code": "123456"},
        )
        assert r.status_code == 400
        assert "pending" in r.json()["detail"].lower() or "setup" in r.json()["detail"].lower()
