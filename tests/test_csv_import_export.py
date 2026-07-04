"""CSV import/export endpoints (users, devices, NAS clients).

Key invariants:
* exports never contain credentials (password hashes, NAS secrets)
* imports are create-only — existing rows are skipped, never overwritten
* every row goes through the same Pydantic validation as the JSON API
"""
from __future__ import annotations

import csv
import io

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from naco.api.auth import hash_password
from naco.db.models import AdminUser, Device, Group, NasClient, User

pytestmark = pytest.mark.asyncio


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _upload(content: str) -> dict:
    return {"file": ("import.csv", content.encode(), "text/csv")}


def _parse(body: str) -> list[dict]:
    return list(csv.DictReader(io.StringIO(body)))


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------

class TestUserCsv:
    async def test_export_has_no_password_hash(
        self, client: AsyncClient, db: AsyncSession, admin_user: AdminUser, admin_token: str
    ):
        grp = Group(name="staff")
        db.add(grp)
        await db.flush()
        db.add(User(username="alice", password_hash=hash_password("Passw0rd!"),
                    email="alice@x.io", group_id=grp.id))
        await db.commit()

        r = await client.get("/api/v1/users/export.csv", headers=_auth(admin_token))
        assert r.status_code == 200
        assert "password" not in r.text.lower().splitlines()[0]
        rows = _parse(r.text)
        assert rows[0]["username"] == "alice"
        assert rows[0]["group"] == "staff"

    async def test_import_creates_and_skips(
        self, client: AsyncClient, db: AsyncSession, admin_user: AdminUser, admin_token: str
    ):
        db.add(Group(name="staff"))
        db.add(User(username="existing", password_hash="x"))
        await db.commit()

        csv_body = (
            "username,password,email,full_name,group,enabled\n"
            "alice,Passw0rd!,alice@x.io,Alice,staff,true\n"
            "existing,Passw0rd!,,,,\n"          # already there → skipped
            "bob,short,,,,\n"                    # fails complexity → error
            "carol,Passw0rd!,,,no-such-group,\n"  # unknown group → error
        )
        r = await client.post("/api/v1/users/import",
                              files=_upload(csv_body), headers=_auth(admin_token))
        assert r.status_code == 200, r.text
        report = r.json()
        assert report["created"] == 1
        assert report["skipped"] == 1
        assert len(report["errors"]) == 2
        assert any("line 4" in e for e in report["errors"])
        assert any("no-such-group" in e for e in report["errors"])

        alice = (await db.execute(select(User).where(User.username == "alice"))).scalar_one()
        assert alice.password_hash != "Passw0rd!"  # hashed, not stored raw
        # create-only: the pre-existing row was not touched
        existing = (await db.execute(select(User).where(User.username == "existing"))).scalar_one()
        assert existing.password_hash == "x"

    async def test_import_rejects_empty_csv(
        self, client: AsyncClient, admin_user: AdminUser, admin_token: str
    ):
        r = await client.post("/api/v1/users/import",
                              files=_upload("username,password\n"), headers=_auth(admin_token))
        assert r.status_code == 422

    async def test_import_rejects_non_utf8(
        self, client: AsyncClient, admin_user: AdminUser, admin_token: str
    ):
        files = {"file": ("import.csv", b"\xff\xfe\x00bad", "text/csv")}
        r = await client.post("/api/v1/users/import", files=files, headers=_auth(admin_token))
        assert r.status_code == 422

    async def test_roundtrip(
        self, client: AsyncClient, db: AsyncSession, admin_user: AdminUser, admin_token: str
    ):
        """Export → re-import into empty columns skips everything (create-only)."""
        db.add(User(username="alice", password_hash="x"))
        await db.commit()
        exported = (await client.get("/api/v1/users/export.csv", headers=_auth(admin_token))).text
        r = await client.post("/api/v1/users/import",
                              files=_upload(exported), headers=_auth(admin_token))
        assert r.json()["skipped"] == 1
        assert r.json()["created"] == 0


# ---------------------------------------------------------------------------
# Devices
# ---------------------------------------------------------------------------

class TestDeviceCsv:
    async def test_import_normalises_mac_and_skips_existing(
        self, client: AsyncClient, db: AsyncSession, admin_user: AdminUser, admin_token: str
    ):
        db.add(Device(mac_address="aa:bb:cc:dd:ee:01", device_type="printer"))
        await db.commit()

        csv_body = (
            "mac_address,hostname,device_type,notes,authorized\n"
            "AA-BB-CC-DD-EE-02,printer2,printer,,yes\n"
            "aa:bb:cc:dd:ee:01,dupe,,,\n"
            "zz:zz:zz:zz:zz:zz,bad,,,\n"
        )
        r = await client.post("/api/v1/devices/import",
                              files=_upload(csv_body), headers=_auth(admin_token))
        report = r.json()
        assert report["created"] == 1
        assert report["skipped"] == 1
        assert len(report["errors"]) == 1

        dev = (await db.execute(
            select(Device).where(Device.mac_address == "aa:bb:cc:dd:ee:02")
        )).scalar_one()
        assert dev.authorized is True

    async def test_export_roundtrip(
        self, client: AsyncClient, db: AsyncSession, admin_user: AdminUser, admin_token: str
    ):
        db.add(Device(mac_address="aa:bb:cc:dd:ee:01", device_type="camera", authorized=True))
        await db.commit()
        r = await client.get("/api/v1/devices/export.csv", headers=_auth(admin_token))
        rows = _parse(r.text)
        assert rows[0]["mac_address"] == "aa:bb:cc:dd:ee:01"
        assert rows[0]["device_type"] == "camera"


# ---------------------------------------------------------------------------
# NAS clients
# ---------------------------------------------------------------------------

class TestNasCsv:
    async def test_export_never_contains_secret(
        self, client: AsyncClient, db: AsyncSession, admin_user: AdminUser, admin_token: str
    ):
        db.add(NasClient(name="sw1", ip_address="10.0.0.1",
                         secret="super-secret-shared-key", enabled=True))
        await db.commit()
        r = await client.get("/api/v1/nas/export.csv", headers=_auth(admin_token))
        assert r.status_code == 200
        rows = _parse(r.text)
        assert rows[0]["name"] == "sw1"  # guard against vacuous pass on empty body
        assert "secret" not in r.text.lower()
        assert "super-secret-shared-key" not in r.text

    async def test_import_requires_secret_and_skips_existing(
        self, client: AsyncClient, db: AsyncSession, admin_user: AdminUser, admin_token: str
    ):
        db.add(NasClient(name="sw1", ip_address="10.0.0.1",
                         secret="super-secret-shared-key", enabled=True))
        await db.commit()

        csv_body = (
            "name,ip_address,secret,description,enabled\n"
            "sw2,10.0.0.2,another-strong-secret-123,edge,true\n"
            "sw1,10.0.0.99,another-strong-secret-123,,\n"   # name exists → skipped
            "sw3,10.0.0.1,another-strong-secret-123,,\n"    # ip exists → skipped
            "sw4,10.0.0.4,short,,\n"                        # secret < 16 → error
        )
        r = await client.post("/api/v1/nas/import",
                              files=_upload(csv_body), headers=_auth(admin_token))
        report = r.json()
        assert report["created"] == 1
        assert report["skipped"] == 2
        assert len(report["errors"]) == 1

        sw2 = (await db.execute(select(NasClient).where(NasClient.name == "sw2"))).scalar_one()
        assert sw2.ip_address == "10.0.0.2"

    async def test_viewer_cannot_import(
        self, client: AsyncClient, db: AsyncSession, admin_user: AdminUser, admin_token: str
    ):
        from naco.db.models import AdminRole
        db.add(AdminUser(username="viewer", password_hash=hash_password("Viewer1234"),
                         role=AdminRole.VIEWER, enabled=True))
        await db.commit()
        login = await client.post("/api/v1/auth/login",
                                  json={"username": "viewer", "password": "Viewer1234"})
        token = login.json()["access_token"]
        r = await client.post("/api/v1/nas/import",
                              files=_upload("name,ip_address,secret\n"), headers=_auth(token))
        assert r.status_code == 403
