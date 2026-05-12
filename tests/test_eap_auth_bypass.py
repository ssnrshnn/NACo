"""Phase 0.1 / 0.2 — EAP REST /auth must reject empty passwords and publish Event objects."""
from __future__ import annotations

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
class TestEapAuthBypass:
    async def test_empty_password_rejected(self, client: AsyncClient):
        r = await client.post(
            "/api/v1/eap/auth",
            headers={"Authorization": "Bearer test-eap-bearer-token-not-for-production"},
            json={
                "username": "anyone",
                "password": "",
                "nas_ip": "10.0.0.1",
                "calling_station_id": "aa-bb-cc-dd-ee-ff",
            },
        )
        assert r.status_code == 200
        data = r.json()
        assert data.get("Reply-Message") == "Access denied"
        assert data.get("control:Auth-Type") != "Accept"

    async def test_whitespace_only_password_rejected(self, client: AsyncClient):
        r = await client.post(
            "/api/v1/eap/auth",
            headers={"Authorization": "Bearer test-eap-bearer-token-not-for-production"},
            json={
                "username": "anyone",
                "password": "   \t  ",
                "nas_ip": "10.0.0.1",
                "calling_station_id": "aa-bb-cc-dd-ee-ff",
            },
        )
        assert r.status_code == 200
        assert r.json().get("Reply-Message") == "Access denied"

    async def test_null_password_rejected(self, client: AsyncClient):
        r = await client.post(
            "/api/v1/eap/auth",
            headers={"Authorization": "Bearer test-eap-bearer-token-not-for-production"},
            json={
                "username": "anyone",
                "password": None,
                "nas_ip": "10.0.0.1",
                "calling_station_id": "aa-bb-cc-dd-ee-ff",
            },
        )
        assert r.status_code == 200
        assert r.json().get("Reply-Message") == "Access denied"
