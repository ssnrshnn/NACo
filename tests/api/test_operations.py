import asyncio
import io
import socket
from datetime import timedelta

import httpx
import pytest
import uvicorn
from sqlalchemy import select

from naco.core.events import Event, EventType, bus
from naco.core.timeutil import utcnow
from naco.db.models import (
    AdminRole,
    AuthLog,
    AuthResult,
    Device,
    Group,
    NasClient,
    RadiusSession,
    TacacsKind,
    TacacsLog,
    User,
)
from naco.radius import reevaluate
from naco.web.app import create_public_app
from tests.api.conftest import BASE, bearer, make_admin, make_token, sign_in
from tests.fakenas import parse_attrs, start_fake_nas

V1 = "/api/v1"


@pytest.fixture
async def tokens(api):
    return {role: bearer(await make_token(api.sf, role)) for role in AdminRole}


@pytest.fixture
def scheduled(monkeypatch):
    calls = []
    monkeypatch.setattr(reevaluate.reevaluator, "schedule", calls.append)
    return calls


# ── RADIUS sessions ────────────────────────────────────────────────────────

async def test_sessions_list_and_disconnect(api, tokens):
    nas, transport = await start_fake_nas(secret="coa-secret-value")
    try:
        async with api.sf() as db:
            db.add(NasClient(name="sw1", ip_address="127.0.0.1", secret="coa-secret-value", coa_port=nas.port))
            db.add_all([RadiusSession(nas_ip="127.0.0.1", acct_session_id=f"S{i}", username=u, acct_username=u)
                        for i, u in enumerate(["alice", "alice", "bob"])])
            await db.commit()
        page = (await api.get(f"{V1}/sessions?q=ali", headers=tokens[AdminRole.VIEWER])).json()
        assert page["total"] == 2 and page["items"][0]["nas_name"] == "sw1"
        sid = page["items"][0]["id"]
        assert (await api.post(f"{V1}/sessions/{sid}/disconnect", headers=tokens[AdminRole.VIEWER])).status_code == 403
        r = await api.post(f"{V1}/sessions/{sid}/disconnect", headers=tokens[AdminRole.OPERATOR])
        assert r.json() == {"requested": 1, "acked": 1, "failed": 0, "skipped": 0}
        bulk = await api.post(f"{V1}/sessions/disconnect", headers=tokens[AdminRole.OPERATOR],
                              json={"username": "Alice"})
        assert bulk.json()["acked"] == 2
        sent = [parse_attrs(p)[44][0].decode() for p in nas.received]
        assert len(sent) == 3 and set(sent) == {"S0", "S1"}  # bob's session (S2) untouched
        assert (await api.post(f"{V1}/sessions/disconnect", headers=tokens[AdminRole.OPERATOR],
                               json={})).status_code == 422
    finally:
        transport.close()


# ── guests ─────────────────────────────────────────────────────────────────

async def test_guest_registrations(api, tokens, scheduled):
    op = tokens[AdminRole.OPERATOR]
    g = (await api.post(f"{V1}/guests", headers=op, json={"mac_address": "AA-BB-CC-DD-EE-FF", "hours": 2,
                                                           "full_name": "Visitor"})).json()
    assert g["active"] is True and g["created_by"].startswith("token:")
    assert (await api.get(f"{V1}/guests?active=true", headers=op)).json()["total"] == 1
    assert (await api.delete(f"{V1}/guests/{g['id']}", headers=op)).status_code == 204
    assert (await api.get(f"{V1}/guests?active=false", headers=op)).json()["items"][0]["active"] is False
    assert scheduled == ["guest aa:bb:cc:dd:ee:ff registered", "guest aa:bb:cc:dd:ee:ff revoked"]


# ── logs and audit ─────────────────────────────────────────────────────────

async def test_logs_and_audit_visibility(api, tokens):
    async with api.sf() as db:
        db.add_all([AuthLog(username="alice", result=AuthResult.ACCEPT, policy_name="staff"),
                    AuthLog(username="bob", result=AuthResult.REJECT, reason="wrong password"),
                    TacacsLog(kind=TacacsKind.AUTHOR, username="neo", command="show run", result="PASS")])
        await db.commit()
    viewer = tokens[AdminRole.VIEWER]
    rejects = (await api.get(f"{V1}/logs/auth?result=REJECT", headers=viewer)).json()
    assert [r["username"] for r in rejects["items"]] == ["bob"]
    assert (await api.get(f"{V1}/logs/auth?q=staff", headers=viewer)).json()["total"] == 1
    assert (await api.get(f"{V1}/logs/tacacs?q=show", headers=viewer)).json()["items"][0]["kind"] == "AUTHOR"
    assert (await api.get(f"{V1}/audit", headers=viewer)).status_code == 403
    assert (await api.get(f"{V1}/audit", headers=tokens[AdminRole.OPERATOR])).status_code == 200


# ── administrators ─────────────────────────────────────────────────────────

async def test_admin_management(api):
    await make_admin(api.sf)
    await sign_in(api)
    created = (await api.post(f"{V1}/admins", json={"username": "ops", "role": "OPERATOR"})).json()
    temp = created["temporary_password"]
    assert created["admin"]["must_change_password"] is True

    ops = httpx.AsyncClient(transport=httpx.ASGITransport(app=create_public_app()), base_url=BASE)
    r = await ops.post(f"{V1}/auth/login", json={"username": "ops", "password": temp})
    assert r.json()["restricted"] == "password"
    ops.headers["X-CSRF-Token"] = r.json()["csrf_token"]
    assert (await ops.get(f"{V1}/users")).json()["error"]["code"] == "setup_required"

    admin_id = created["admin"]["id"]
    assert (await api.patch(f"{V1}/admins/{admin_id}", json={"role": "VIEWER"})).json()["role"] == "VIEWER"
    assert (await ops.get(f"{V1}/auth/me")).status_code == 401  # role change ended the session
    await ops.aclose()

    reset = (await api.post(f"{V1}/admins/{admin_id}/reset-password")).json()
    assert reset["temporary_password"] != temp
    assert (await api.post(f"{V1}/admins/{admin_id}/reset-totp")).status_code == 200

    me = next(a for a in (await api.get(f"{V1}/admins")).json() if a["username"] == "root")
    assert (await api.patch(f"{V1}/admins/{me['id']}", json={"role": "VIEWER"})).status_code == 409
    assert (await api.delete(f"{V1}/admins/{me['id']}")).status_code == 409
    assert (await api.delete(f"{V1}/admins/{admin_id}")).status_code == 204


async def test_last_superuser_is_protected(api):
    root = await make_admin(api.sf, "root")
    su_token = bearer(await make_token(api.sf, AdminRole.SUPERUSER))
    for attempt in (api.patch(f"{V1}/admins/{root.id}", headers=su_token, json={"role": "OPERATOR"}),
                    api.patch(f"{V1}/admins/{root.id}", headers=su_token, json={"enabled": False}),
                    api.delete(f"{V1}/admins/{root.id}", headers=su_token)):
        r = await attempt
        assert r.status_code == 409 and "last enabled SUPERUSER" in r.text
    await make_admin(api.sf, "second", role=AdminRole.SUPERUSER)
    assert (await api.patch(f"{V1}/admins/{root.id}", headers=su_token,
                            json={"role": "OPERATOR"})).status_code == 200


# ── API tokens ─────────────────────────────────────────────────────────────

async def test_api_token_lifecycle(api):
    await make_admin(api.sf)
    await sign_in(api)
    created = (await api.post(f"{V1}/tokens", json={"name": "ci", "role": "OPERATOR", "expires_days": 30})).json()
    secret = created["secret"]
    assert secret.startswith("naco_") and created["token"]["prefix"] == secret[:12]
    assert "secret" not in (await api.get(f"{V1}/tokens")).json()[0]
    assert (await api.get(f"{V1}/users", headers=bearer(secret))).status_code == 200
    su_token = await make_token(api.sf, AdminRole.SUPERUSER)
    assert (await api.post(f"{V1}/tokens", headers=bearer(su_token), json={"name": "x"})).status_code == 403
    assert (await api.delete(f"{V1}/tokens/{created['token']['id']}")).status_code == 204
    assert (await api.get(f"{V1}/users", headers=bearer(secret))).status_code == 401


# ── CSV ────────────────────────────────────────────────────────────────────

async def test_csv_export_is_formula_safe_and_secret_free(api, tokens):
    async with api.sf() as db:
        db.add(User(username="=cmd|' /c calc'!a0", password_hash="x", full_name="+danger"))
        db.add(Device(mac_address="02:00:00:00:00:01", description="@SUM(1+1)"))
        db.add(NasClient(name="sw1", ip_address="10.0.0.1", secret="super-secret-value"))
        await db.commit()
    viewer = tokens[AdminRole.VIEWER]
    users = (await api.get(f"{V1}/export/users.csv", headers=viewer)).text
    assert "'=cmd" in users and "'+danger" in users
    assert "'@SUM" in (await api.get(f"{V1}/export/devices.csv", headers=viewer)).text
    nas = await api.get(f"{V1}/export/nas.csv", headers=viewer)
    assert "super-secret-value" not in nas.text and "attachment" in nas.headers["content-disposition"]
    assert (await api.get(f"{V1}/export/admins.csv", headers=viewer)).status_code == 422


def upload(text: str) -> dict:
    return {"file": ("import.csv", io.BytesIO(text.encode()), "text/csv")}


async def test_user_import(api, tokens):
    async with api.sf() as db:
        db.add_all([Group(name="staff"), Group(name="netadmins", device_admin_privilege=15),
                    User(username="existing", password_hash="x")])
        await db.commit()
    csv_text = ("username,password,email,group,enabled\n"
                "alice,alice-password,a@x.io,Staff,yes\n"
                "existing,whatever-pw,,,\n"
                "bob,short,,,\n"
                "carol,carol-password,,ghosts,\n"
                "neo,neo-password,,netadmins,\n"
                "alice,dupe-password,,,\n")
    r = (await api.post(f"{V1}/import/users", headers=tokens[AdminRole.OPERATOR], files=upload(csv_text))).json()
    assert r["created"] == 1 and r["skipped"] == 2
    assert [e.split(":")[0] for e in r["errors"]] == ["line 4", "line 5", "line 6"]
    async with api.sf() as db:
        alice = (await db.execute(select(User).where(User.username == "alice"))).scalar_one()
        assert alice.group_id is not None and alice.password_hash.startswith("$2")
    missing = await api.post(f"{V1}/import/users", headers=tokens[AdminRole.OPERATOR], files=upload("user\nx\n"))
    assert missing.status_code == 422


async def test_device_and_nas_import(api, tokens):
    devices = "mac_address,status,description\naa-bb-cc-00-00-01,blocked,lost laptop\nnot-a-mac,,\n"
    r = (await api.post(f"{V1}/import/devices", headers=tokens[AdminRole.OPERATOR], files=upload(devices))).json()
    assert r["created"] == 1 and len(r["errors"]) == 1
    nas = "name,ip_address,secret\nsw9,10.9.9.9,shared-secret-123456\nsw8,10.9.9.8,short\n"
    assert (await api.post(f"{V1}/import/nas", headers=tokens[AdminRole.OPERATOR],
                           files=upload(nas))).status_code == 403
    r = (await api.post(f"{V1}/import/nas", headers=tokens[AdminRole.SUPERUSER], files=upload(nas))).json()
    assert r["created"] == 1 and r["errors"][0].startswith("line 3")
    big = await api.post(f"{V1}/import/devices", headers=tokens[AdminRole.OPERATOR],
                         files=upload("mac_address\n" + "x" * (5 * 1024 * 1024)))
    assert big.status_code == 413


# ── dashboard, system, events ──────────────────────────────────────────────

async def test_dashboard_and_system(api, tokens):
    async with api.sf() as db:
        db.add_all([AuthLog(username="a", result=AuthResult.ACCEPT),
                    AuthLog(username="b", result=AuthResult.REJECT, timestamp=utcnow() - timedelta(hours=3)),
                    AuthLog(username="old", result=AuthResult.ACCEPT, timestamp=utcnow() - timedelta(days=2))])
        await db.commit()
    dash = (await api.get(f"{V1}/dashboard", headers=tokens[AdminRole.VIEWER])).json()
    assert len(dash["last_24h"]) == 24
    assert sum(b["accept"] for b in dash["last_24h"]) == 1 and sum(b["reject"] for b in dash["last_24h"]) == 1
    assert dash["last_24h"][-1]["accept"] == 1
    assert {c["key"]: c["done"] for c in dash["checklist"]} == {
        "nas": False, "policy": False, "radius": True, "totp": True}
    system = (await api.get(f"{V1}/system", headers=tokens[AdminRole.VIEWER])).json()
    assert system["database_bytes"] > 0 and system["settings"]["require_totp"] is True
    assert "secret" not in str(system).lower()


async def test_live_events_stream(app_db):
    token = await make_token(app_db, AdminRole.VIEWER)
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(create_public_app(), log_config=None, lifespan="off"))
    task = asyncio.create_task(server.serve(sockets=[sock]))
    try:
        while not server.started:
            await asyncio.sleep(0.01)
        async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{port}") as client, \
                client.stream("GET", f"{V1}/events", headers=bearer(token)) as response:
            assert response.headers["content-type"].startswith("text/event-stream")
            lines = response.aiter_lines()
            assert await anext(lines) == "retry: 5000"
            await anext(lines)
            bus.publish(Event(EventType.AUTH, {"result": "ACCEPT", "username": "alice"}))
            assert await anext(lines) == "event: auth"
            assert '"username": "alice"' in await anext(lines)
    finally:
        server.should_exit = True
        await task
