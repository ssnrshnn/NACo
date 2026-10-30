"""Admin page shells: redirects, roles, safe `next`, and a strict CSP."""
import re

import pytest

from naco.db.models import AdminRole
from naco.web.pages import PAGES
from tests.api.conftest import code, make_admin, sign_in


@pytest.mark.parametrize("path", [p.path for p in PAGES])
async def test_pages_redirect_to_login_when_signed_out(api, path):
    r = await api.get(path)
    assert r.status_code == 303 and r.headers["location"].startswith("/login?next=")


@pytest.mark.parametrize("target,expected", [
    ("/devices", "/devices"), ("/devices?status=PENDING", "/devices?status=PENDING"),
    ("//evil.example", "/"), ("https://evil.example", "/"), ("/\\evil", "/"), ("", "/"),
    ("/\t/evil.example", "/"), ("/\n/evil.example", "/"), ("/\r/evil.example", "/"), ("/ /evil.example", "/"),
])
async def test_login_next_is_never_an_open_redirect(api, target, expected):
    await make_admin(api.sf)
    await sign_in(api)
    r = await api.get("/login", params={"next": target})
    assert r.status_code == 303 and r.headers["location"] == expected


async def test_login_page_carries_only_a_safe_next(api):
    r = await api.get("/login", params={"next": "/\t/evil.example/phish"})
    assert r.status_code == 200 and 'data-next="/"' in r.text


async def test_unfinished_setup_is_forced(api):
    await make_admin(api.sf, totp=False)
    await sign_in(api, totp_code="")
    assert (await api.get("/users")).headers["location"] == "/setup"
    r = await api.get("/setup")
    assert r.status_code == 200 and 'data-step="totp"' in r.text


async def test_role_gated_pages_and_navigation(api):
    await make_admin(api.sf, "viewer", AdminRole.VIEWER)
    await sign_in(api, "viewer")
    assert (await api.get("/admins")).status_code == 403
    page = await api.get("/users")
    assert page.status_code == 200
    assert 'href="/admins"' not in page.text and 'href="/audit"' not in page.text  # hidden from the nav
    assert 'name="naco-role" content="VIEWER"' in page.text


async def test_pages_have_no_inline_script_or_style(api):
    await make_admin(api.sf)
    await sign_in(api, totp_code=code(offset=-1))
    for path in ("/", "/policies", "/login"):
        r = await api.get(path, follow_redirects=True)
        assert not re.search(r"<script(?![^>]*\bsrc=)[^>]*>", r.text), path
        assert ' style="' not in r.text, path
        csp = r.headers["content-security-policy"]
        assert "'unsafe-inline'" not in csp and "script-src 'self'" in csp


async def test_static_assets_are_local(api):
    for asset in ("/static/js/app.js", "/static/css/naco.css", "/static/vendor/bootstrap/bootstrap.min.css",
                  "/static/icons.svg"):
        assert (await api.get(asset)).status_code == 200, asset
    css = (await api.get("/static/vendor/bootstrap/bootstrap.min.css")).text
    assert "sourceMappingURL" not in css
