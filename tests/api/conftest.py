"""API test helpers: an HTTPS test client, admins, sessions and tokens."""
from __future__ import annotations

import hashlib
import secrets

import httpx
import pyotp
import pytest

from naco.api.routes import auth as auth_routes
from naco.core.passwords import hash_password_sync
from naco.db.models import AdminRole, AdminUser, ApiToken
from naco.web.app import create_public_app

BASE = "https://naco.test"
TOTP_SECRET = "JBSWY3DPEHPK3PXP"


@pytest.fixture(autouse=True)
def _reset_login_throttles():
    auth_routes.reset_throttles()


@pytest.fixture
async def api(app_db):
    transport = httpx.ASGITransport(app=create_public_app(), client=("203.0.113.7", 50000))
    async with httpx.AsyncClient(transport=transport, base_url=BASE) as client:
        client.sf = app_db
        yield client


async def make_admin(sf, username="root", role=AdminRole.SUPERUSER, password="correct-horse-battery",
                     *, totp=True, must_change=False, enabled=True) -> AdminUser:
    async with sf() as db:
        admin = AdminUser(username=username, password_hash=hash_password_sync(password), role=role,
                          must_change_password=must_change, enabled=enabled,
                          totp_secret=TOTP_SECRET if totp else None)
        db.add(admin)
        await db.commit()
        return admin


def code(secret: str = TOTP_SECRET, offset: int = 0) -> str:
    import time
    return pyotp.TOTP(secret).at(time.time() + offset * 30)


async def sign_in(client, username="root", password="correct-horse-battery", totp_code=None) -> str:
    r = await client.post("/api/v1/auth/login", json={
        "username": username, "password": password, "totp_code": code() if totp_code is None else totp_code})
    assert r.status_code == 200, r.text
    client.headers["X-CSRF-Token"] = r.json()["csrf_token"]
    return r.json()["csrf_token"]


async def make_token(sf, role: AdminRole, name: str | None = None) -> str:
    raw = "naco_" + secrets.token_urlsafe(32)
    async with sf() as db:
        db.add(ApiToken(name=name or f"t-{role.value}-{secrets.token_hex(3)}",
                        token_hash=hashlib.sha256(raw.encode()).hexdigest(), prefix=raw[:12], role=role))
        await db.commit()
    return raw


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}
