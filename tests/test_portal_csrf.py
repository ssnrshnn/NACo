"""
Cookie-based CSRF protection for the captive portal.

The portal hands out a per-visitor ``naco_portal_csrf`` cookie (HttpOnly,
SameSite=Strict). Every POST must mirror that cookie value in a hidden
``csrf_token`` form field. These tests pin the contract end-to-end via the
real FastAPI app under ``httpx.AsyncClient``.
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from naco.db import get_db
from naco.portal.app import app as portal_app, _CSRF_COOKIE


@pytest_asyncio.fixture
async def portal_client(db: AsyncSession):
    async def _override_get_db():
        yield db

    portal_app.dependency_overrides[get_db] = _override_get_db
    transport = ASGITransport(app=portal_app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    portal_app.dependency_overrides.clear()


@pytest.mark.asyncio
class TestPortalCsrfCookie:
    async def test_landing_sets_cookie(self, portal_client: AsyncClient):
        resp = await portal_client.get("/")
        assert resp.status_code == 200
        cookie = resp.cookies.get(_CSRF_COOKIE)
        assert cookie is not None and len(cookie) >= 32
        # The HTML embeds the same token in the form
        assert cookie in resp.text

    async def test_landing_reuses_existing_cookie(self, portal_client: AsyncClient):
        r1 = await portal_client.get("/")
        c1 = r1.cookies.get(_CSRF_COOKIE)
        assert c1
        r2 = await portal_client.get(
            "/", headers={"cookie": f"{_CSRF_COOKIE}={c1}"},
        )
        assert r2.status_code == 200
        # Token in the form must equal the cookie we presented
        assert c1 in r2.text

    async def test_post_without_cookie_rejected(self, portal_client: AsyncClient):
        # No cookie at all, no matching token → must error
        resp = await portal_client.post(
            "/register",
            data={
                "full_name":  "Alice Example",
                "email":      "alice@example.com",
                "mac":        "aa:bb:cc:dd:ee:01",
                "csrf_token": "anything",
            },
        )
        assert resp.status_code == 200
        assert "Invalid form submission" in resp.text

    async def test_post_with_mismatched_token_rejected(self, portal_client: AsyncClient):
        r1 = await portal_client.get("/")
        cookie = r1.cookies.get(_CSRF_COOKIE)
        resp = await portal_client.post(
            "/register",
            data={
                "full_name":  "Alice",
                "email":      "alice@example.com",
                "mac":        "aa:bb:cc:dd:ee:02",
                "csrf_token": "this-is-not-the-cookie",
            },
            headers={"cookie": f"{_CSRF_COOKIE}={cookie}"},
        )
        assert resp.status_code == 200
        assert "Invalid form submission" in resp.text

    async def test_post_with_matching_token_accepted(
        self, portal_client: AsyncClient, db: AsyncSession,
    ):
        r1 = await portal_client.get("/")
        cookie = r1.cookies.get(_CSRF_COOKIE)
        assert cookie
        resp = await portal_client.post(
            "/register",
            data={
                "full_name":  "Alice Example",
                "email":      "alice@example.com",
                "mac":        "aa:bb:cc:dd:ee:03",
                "csrf_token": cookie,
            },
            headers={"cookie": f"{_CSRF_COOKIE}={cookie}"},
            follow_redirects=False,
        )
        # On success the portal 303s to /portal/success — anything other than
        # the CSRF-rejected 200 page proves the token validated.
        assert resp.status_code in (200, 303)
        if resp.status_code == 200:
            assert "Invalid form submission" not in resp.text
