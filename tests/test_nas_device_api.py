"""REST CRUD for NAS clients (/api/v1/nas) and manual device registration
(POST /api/v1/devices) — the two onboarding paths that previously existed
only as web forms (NAS) or not at all (devices)."""
from __future__ import annotations

import pytest
from httpx import AsyncClient

from naco.db.models import AdminUser

pytestmark = pytest.mark.asyncio


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


NAS_BODY = {
    "name": "core-sw01",
    "ip_address": "10.0.0.1",
    "secret": "a-strong-shared-secret",
    "description": "core switch",
}


class TestNasApi:
    async def test_create_and_list(self, client: AsyncClient, admin_user: AdminUser, admin_token: str):
        r = await client.post("/api/v1/nas", json=NAS_BODY, headers=_auth(admin_token))
        assert r.status_code == 201, r.text
        created = r.json()
        assert created["name"] == "core-sw01"
        assert "secret" not in created  # write-only

        r = await client.get("/api/v1/nas", headers=_auth(admin_token))
        assert r.status_code == 200
        rows = r.json()
        assert len(rows) == 1
        assert "secret" not in rows[0]

    async def test_duplicate_rejected(self, client: AsyncClient, admin_user: AdminUser, admin_token: str):
        assert (await client.post("/api/v1/nas", json=NAS_BODY, headers=_auth(admin_token))).status_code == 201
        r = await client.post("/api/v1/nas", json=NAS_BODY, headers=_auth(admin_token))
        assert r.status_code == 409

    async def test_invalid_ip_rejected(self, client: AsyncClient, admin_user: AdminUser, admin_token: str):
        r = await client.post(
            "/api/v1/nas", json={**NAS_BODY, "ip_address": "not-an-ip"}, headers=_auth(admin_token)
        )
        assert r.status_code == 422

    async def test_short_secret_rejected(self, client: AsyncClient, admin_user: AdminUser, admin_token: str):
        r = await client.post(
            "/api/v1/nas", json={**NAS_BODY, "secret": "short"}, headers=_auth(admin_token)
        )
        assert r.status_code == 422

    async def test_update_and_delete(self, client: AsyncClient, admin_user: AdminUser, admin_token: str):
        nas_id = (await client.post("/api/v1/nas", json=NAS_BODY, headers=_auth(admin_token))).json()["id"]
        r = await client.put(
            f"/api/v1/nas/{nas_id}", json={"enabled": False}, headers=_auth(admin_token)
        )
        assert r.status_code == 200 and r.json()["enabled"] is False
        r = await client.delete(f"/api/v1/nas/{nas_id}", headers=_auth(admin_token))
        assert r.status_code == 200
        assert (await client.get("/api/v1/nas", headers=_auth(admin_token))).json() == []

    async def test_requires_auth(self, client: AsyncClient):
        assert (await client.post("/api/v1/nas", json=NAS_BODY)).status_code in (401, 403)


class TestDeviceCreateApi:
    async def test_create_normalises_mac(self, client: AsyncClient, admin_user: AdminUser, admin_token: str):
        r = await client.post(
            "/api/v1/devices",
            json={"mac_address": "AA-BB-CC-DD-EE-FF", "authorized": True, "device_type": "printer"},
            headers=_auth(admin_token),
        )
        assert r.status_code == 201, r.text
        dev = r.json()
        assert dev["mac_address"] == "aa:bb:cc:dd:ee:ff"
        assert dev["authorized"] is True
        assert dev["device_type"] == "printer"

    async def test_duplicate_rejected(self, client: AsyncClient, admin_user: AdminUser, admin_token: str):
        body = {"mac_address": "aa:bb:cc:dd:ee:01"}
        assert (await client.post("/api/v1/devices", json=body, headers=_auth(admin_token))).status_code == 201
        # same MAC in a different notation is still the same device
        r = await client.post(
            "/api/v1/devices", json={"mac_address": "AABB.CCDD.EE01"}, headers=_auth(admin_token)
        )
        assert r.status_code == 409

    async def test_invalid_mac_rejected(self, client: AsyncClient, admin_user: AdminUser, admin_token: str):
        r = await client.post(
            "/api/v1/devices", json={"mac_address": "not-a-mac-addr"}, headers=_auth(admin_token)
        )
        assert r.status_code == 422

    async def test_defaults_to_blocked(self, client: AsyncClient, admin_user: AdminUser, admin_token: str):
        r = await client.post(
            "/api/v1/devices", json={"mac_address": "aa:bb:cc:dd:ee:02"}, headers=_auth(admin_token)
        )
        assert r.status_code == 201
        assert r.json()["authorized"] is False  # default-deny posture preserved
