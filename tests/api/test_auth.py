from datetime import timedelta

import httpx
import pytest
from sqlalchemy import func, select, update

from naco.core.timeutil import utcnow
from naco.db.models import AdminRole, AdminSession, AdminUser, ApiToken, AuditLog
from naco.web.app import create_public_app
from tests.api.conftest import BASE, TOTP_SECRET, bearer, code, make_admin, make_token, sign_in
from tests.conftest import write_config

LOGIN = "/api/v1/auth/login"


async def audit_actions(sf) -> list[str]:
    async with sf() as db:
        return list((await db.execute(select(AuditLog.action).order_by(AuditLog.id))).scalars())


# ── sign in ────────────────────────────────────────────────────────────────

async def test_login_sets_a_hardened_session_cookie(api):
    await make_admin(api.sf)
    r = await api.post(LOGIN, json={"username": "ROOT", "password": "correct-horse-battery", "totp_code": code()})
    assert r.status_code == 200
    body = r.json()
    assert body["username"] == "root" and body["role"] == "SUPERUSER" and body["restricted"] is None
    assert len(body["csrf_token"]) > 30
    cookie = r.headers["set-cookie"].lower()
    assert "naco_session=" in cookie and "httponly" in cookie and "secure" in cookie and "samesite=lax" in cookie
    assert (await api.get("/api/v1/auth/me")).json()["username"] == "root"
    assert await audit_actions(api.sf) == ["auth.login"]


@pytest.mark.parametrize("payload", [
    {"username": "root", "password": "wrong", "totp_code": None},
    {"username": "root", "password": "correct-horse-battery", "totp_code": "000000"},
    {"username": "root", "password": "correct-horse-battery", "totp_code": ""},
    {"username": "nobody", "password": "correct-horse-battery", "totp_code": None},
])
async def test_every_failure_looks_the_same(api, payload):
    await make_admin(api.sf)
    payload = {**payload, "totp_code": code() if payload["totp_code"] is None else payload["totp_code"]}
    r = await api.post(LOGIN, json=payload)
    assert r.status_code == 401
    assert r.json()["error"]["message"] == "invalid username, password or code"
    assert "set-cookie" not in r.headers
    assert await audit_actions(api.sf) == ["auth.login_failed"]


async def test_disabled_admin_cannot_sign_in(api):
    await make_admin(api.sf, enabled=False)
    r = await api.post(LOGIN, json={"username": "root", "password": "correct-horse-battery", "totp_code": code()})
    assert r.status_code == 401


async def test_totp_code_cannot_be_replayed(api):
    await make_admin(api.sf)
    same = code()
    assert (await api.post(LOGIN, json={"username": "root", "password": "correct-horse-battery",
                                        "totp_code": same})).status_code == 200
    r = await api.post(LOGIN, json={"username": "root", "password": "correct-horse-battery", "totp_code": same})
    assert r.status_code == 401


async def test_login_needs_json_and_same_origin(api):
    await make_admin(api.sf)
    form = await api.post(LOGIN, data={"username": "root", "password": "correct-horse-battery"})
    assert form.status_code in (415, 422)
    # A cross-site <form enctype="text/plain"> can smuggle a JSON-looking body.
    import json
    smuggled = await api.post(LOGIN, headers={"Content-Type": "text/plain"}, content=json.dumps(
        {"username": "root", "password": "correct-horse-battery", "totp_code": code()}))
    assert smuggled.status_code in (415, 422)
    cross = await api.post(LOGIN, json={"username": "root", "password": "x"}, headers={"Origin": "https://evil.example"})
    assert cross.status_code == 403


async def test_failed_logins_slow_down_per_user(api):
    await make_admin(api.sf)
    for _ in range(4):
        await api.post(LOGIN, json={"username": "root", "password": "wrong", "totp_code": code()})
    r = await api.post(LOGIN, json={"username": "root", "password": "correct-horse-battery", "totp_code": code()})
    assert r.status_code == 429
    assert int(r.headers["Retry-After"]) >= 1


async def test_login_attempts_are_limited_per_ip(api, tmp_path, monkeypatch):
    write_config(tmp_path, monkeypatch, "security:\n  login_max_attempts: 3\n")
    for i in range(3):
        await api.post(LOGIN, json={"username": f"u{i}", "password": "x"})
    assert (await api.post(LOGIN, json={"username": "u9", "password": "x"})).status_code == 429


# ── sessions and CSRF ──────────────────────────────────────────────────────

async def test_requests_without_a_session_are_rejected(api):
    assert (await api.get("/api/v1/auth/me")).status_code == 401


async def test_state_changes_need_the_csrf_token_and_same_origin(api):
    await make_admin(api.sf)
    csrf = await sign_in(api)
    del api.headers["X-CSRF-Token"]
    assert (await api.post("/api/v1/auth/logout")).status_code == 403
    assert (await api.post("/api/v1/auth/logout", headers={"X-CSRF-Token": "forged"})).status_code == 403
    r = await api.post("/api/v1/auth/logout", headers={"X-CSRF-Token": csrf, "Origin": "https://evil.example"})
    assert r.status_code == 403
    r = await api.post("/api/v1/auth/logout", headers={"X-CSRF-Token": csrf, "Sec-Fetch-Site": "cross-site"})
    assert r.status_code == 403
    r = await api.post("/api/v1/auth/logout", headers={"X-CSRF-Token": csrf, "Origin": BASE})
    assert r.status_code == 204


async def test_logout_ends_the_session_on_the_server(api):
    await make_admin(api.sf)
    await sign_in(api)
    stolen = api.cookies.get("naco_session")
    assert (await api.post("/api/v1/auth/logout")).status_code == 204
    api.cookies.set("naco_session", stolen)
    assert (await api.get("/api/v1/auth/me")).status_code == 401


async def test_idle_session_expires(api):
    await make_admin(api.sf)
    await sign_in(api)
    async with api.sf() as db:
        await db.execute(update(AdminSession).values(last_seen_at=utcnow() - timedelta(minutes=31)))
        await db.commit()
    assert (await api.get("/api/v1/auth/me")).status_code == 401


async def test_disabling_an_admin_kills_their_sessions(api):
    await make_admin(api.sf)
    await sign_in(api)
    async with api.sf() as db:
        await db.execute(update(AdminUser).values(enabled=False))
        await db.commit()
    assert (await api.get("/api/v1/auth/me")).status_code == 401


# ── password ───────────────────────────────────────────────────────────────

async def test_first_login_must_change_password_and_other_sessions_end(api, app_db):
    await make_admin(api.sf, must_change=True)
    csrf_a = await sign_in(api, totp_code=code(offset=-1))
    assert (await api.get("/api/v1/auth/me")).json()["restricted"] == "password"

    other = httpx.AsyncClient(transport=httpx.ASGITransport(app=create_public_app()), base_url=BASE)
    await sign_in(other)

    bad = await api.post("/api/v1/auth/password", json={"current_password": "nope", "new_password": "x" * 12})
    assert bad.status_code == 403
    weak = await api.post("/api/v1/auth/password", json={"current_password": "correct-horse-battery",
                                                         "new_password": "short"})
    assert weak.status_code == 422
    ok = await api.post("/api/v1/auth/password", json={"current_password": "correct-horse-battery",
                                                       "new_password": "a-brand-new-passphrase"})
    assert ok.status_code == 204
    assert (await api.get("/api/v1/auth/me")).json()["restricted"] is None
    assert (await other.get("/api/v1/auth/me")).status_code == 401
    await other.aclose()
    assert csrf_a


# ── TOTP ───────────────────────────────────────────────────────────────────

async def test_totp_enrollment_flow_and_recovery_codes(api):
    await make_admin(api.sf, totp=False)
    await sign_in(api, totp_code="")
    assert (await api.get("/api/v1/auth/me")).json()["restricted"] == "totp"

    assert (await api.post("/api/v1/auth/totp/setup", json={"password": "nope"})).status_code == 403
    setup = (await api.post("/api/v1/auth/totp/setup", json={"password": "correct-horse-battery"})).json()
    assert setup["uri"].startswith("otpauth://totp/NACo:root")
    assert setup["qr_svg"].startswith("<svg")
    assert (await api.post("/api/v1/auth/totp/confirm", json={"code": "123456"})).status_code == 422
    confirm = await api.post("/api/v1/auth/totp/confirm", json={"code": code(setup["secret"])})
    recovery = confirm.json()["recovery_codes"]
    assert len(recovery) == 10 and len(set(recovery)) == 10
    assert (await api.get("/api/v1/auth/me")).json() | {"csrf_token": ""} == {
        "username": "root", "role": "SUPERUSER", "restricted": None, "totp_enabled": True, "csrf_token": ""}

    # A recovery code signs in exactly once.
    fresh = httpx.AsyncClient(transport=httpx.ASGITransport(app=create_public_app()), base_url=BASE)
    body = {"username": "root", "password": "correct-horse-battery", "totp_code": recovery[0]}
    assert (await fresh.post(LOGIN, json=body)).status_code == 200
    assert (await fresh.post(LOGIN, json=body)).status_code == 401
    await fresh.aclose()


async def test_totp_disable_needs_password_and_code(api):
    await make_admin(api.sf)
    await sign_in(api, totp_code=code(offset=-1))
    assert (await api.post("/api/v1/auth/totp/disable", json={"password": "correct-horse-battery",
                                                              "code": "000000"})).status_code == 403
    r = await api.post("/api/v1/auth/totp/disable", json={"password": "correct-horse-battery", "code": code()})
    assert r.status_code == 204
    assert (await api.get("/api/v1/auth/me")).json()["restricted"] == "totp"


# ── my sessions ────────────────────────────────────────────────────────────

async def test_list_and_end_my_sessions(api):
    await make_admin(api.sf)
    await sign_in(api, totp_code=code(offset=-1))
    other = httpx.AsyncClient(transport=httpx.ASGITransport(app=create_public_app()), base_url=BASE)
    await sign_in(other)
    mine = (await api.get("/api/v1/auth/sessions")).json()
    assert len(mine) == 2 and sum(s["current"] for s in mine) == 1
    other_id = next(s["id"] for s in mine if not s["current"])
    assert (await api.delete(f"/api/v1/auth/sessions/{other_id}")).status_code == 204
    assert (await other.get("/api/v1/auth/me")).status_code == 401
    await other.aclose()


# ── API tokens ─────────────────────────────────────────────────────────────

async def test_api_tokens_authenticate_without_csrf_but_cannot_do_account_things(api):
    token = await make_token(api.sf, AdminRole.OPERATOR)
    me = await api.get("/api/v1/auth/me", headers=bearer(token))
    assert me.status_code == 200 and me.json()["role"] == "OPERATOR"
    r = await api.post("/api/v1/auth/password", headers=bearer(token),
                       json={"current_password": "x", "new_password": "y" * 12})
    assert r.status_code == 403


@pytest.mark.parametrize("change", [{"revoked_at": utcnow()}, {"expires_at": utcnow() - timedelta(seconds=1)}])
async def test_revoked_or_expired_tokens_fail(api, change):
    token = await make_token(api.sf, AdminRole.VIEWER)
    async with api.sf() as db:
        await db.execute(update(ApiToken).values(**change))
        await db.commit()
    assert (await api.get("/api/v1/auth/me", headers=bearer(token))).status_code == 401


@pytest.mark.parametrize("header", ["Bearer nonsense", "Bearer naco_unknown", "Bearer " + "naco_" + "x" * 200])
async def test_garbage_tokens(api, header):
    assert (await api.get("/api/v1/auth/me", headers={"Authorization": header})).status_code == 401


async def test_error_shape_and_security_headers(api):
    r = await api.get("/api/v1/auth/me")
    assert r.json() == {"error": {"code": "unauthenticated", "message": "not signed in"}}
    assert r.headers["cache-control"] == "no-store"
    assert r.headers["x-frame-options"] == "DENY"
    assert "max-age" in r.headers["strict-transport-security"]


async def test_health_is_public_and_quiet(api):
    r = await api.get("/api/v1/health/ready")
    assert r.json() == {"status": "ok"}
    async with api.sf() as db:
        assert (await db.execute(select(func.count()).select_from(AuditLog))).scalar_one() == 0
    assert TOTP_SECRET
