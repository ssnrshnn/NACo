from datetime import timedelta

import httpx
import pytest
from sqlalchemy import select

from naco.aaa import service
from naco.aaa.app import create_internal_app
from naco.core.passwords import hash_password_sync
from naco.core.timeutil import utcnow
from naco.db.models import (
    AuthLog,
    AuthResult,
    Device,
    DeviceStatus,
    Group,
    GuestRegistration,
    NasClient,
    Policy,
    PolicyAction,
    RadiusSession,
    User,
)
from tests.conftest import TEST_INTERNAL_TOKEN

NAS_IP = "10.0.0.1"
MAC = "00:1b:63:aa:bb:cc"  # Apple OUI
AUTH = {"Authorization": f"Bearer {TEST_INTERNAL_TOKEN}"}


def rlm(**attrs):
    """Encode like rlm_rest: {"User-Name": {"type": "string", "value": ["x"]}}."""
    return {k.replace("_", "-"): {"type": "string", "value": v if isinstance(v, list) else [v]}
            for k, v in attrs.items()}


@pytest.fixture(autouse=True)
def _reset_throttle():
    service.reset_failure_tracking()


@pytest.fixture
async def world(app_db):
    async with app_db() as db:
        staff = Group(name="staff")
        db.add(staff)
        await db.flush()
        db.add_all([
            NasClient(name="sw1", ip_address=NAS_IP, secret="sw1-secret-%{not-expanded}"),
            NasClient(name="off", ip_address="10.0.0.9", secret="x" * 16, enabled=False),
            NasClient(name="v6", ip_address="2001:db8::1", secret="v6-secret-value!",
                      require_message_authenticator=False),
            User(username="alice", password_hash=hash_password_sync('pa"ss\\wörd'), group_id=staff.id),
            User(username="dave", password_hash=hash_password_sync("dave-pw"), enabled=False),
            Device(mac_address="66:55:44:33:22:11", status=DeviceStatus.BLOCKED),
        ])
        await db.commit()
    return app_db


@pytest.fixture
async def client(world):
    transport = httpx.ASGITransport(app=create_internal_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://naco", headers=AUTH) as c:
        yield c


async def add_policy(sf, name, priority, action, conditions, vlan=None, attrs=None):
    async with sf() as db:
        db.add(Policy(name=name, priority=priority, action=action, conditions=conditions,
                      vlan=vlan, reply_attributes=attrs or {}))
        await db.commit()


async def logs(sf):
    async with sf() as db:
        return (await db.execute(select(AuthLog).order_by(AuthLog.id))).scalars().all()


# ── token and body handling ────────────────────────────────────────────────

@pytest.mark.parametrize("headers", [{}, {"Authorization": "Bearer wrong"}, {"Authorization": "Basic x"},
                                     {"Authorization": "Bearer ünïcode".encode("latin-1")}])
async def test_token_is_required(world, headers):
    transport = httpx.ASGITransport(app=create_internal_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://naco") as c:
        for path in ("/aaa/authorize", "/aaa/authenticate", "/aaa/accounting"):
            assert (await c.post(path, json={}, headers=headers)).status_code == 403
        assert (await c.get(f"/aaa/clients/{NAS_IP}", headers=headers)).status_code == 403


async def test_malformed_body_is_not_an_accept(client):
    r = await client.post("/aaa/authorize", content=b"not json")
    assert r.status_code == 400
    r = await client.post("/aaa/authorize", content=b"x" * (65 * 1024))
    assert r.status_code == 413


# ── dynamic clients ────────────────────────────────────────────────────────

async def test_known_client(client):
    r = await client.get(f"/aaa/clients/{NAS_IP}")
    assert r.status_code == 200
    body = r.json()
    assert body["control:FreeRADIUS-Client-Secret"] == {"value": "sw1-secret-%{not-expanded}", "do_xlat": False}
    assert body["control:FreeRADIUS-Client-IP-Address"]["value"] == NAS_IP
    assert body["control:FreeRADIUS-Client-Shortname"]["value"] == "sw1"
    assert body["control:FreeRADIUS-Client-Require-MA"]["value"] == "yes"


async def test_ipv6_client(client):
    body = (await client.get("/aaa/clients/2001:db8::1")).json()
    assert body["control:FreeRADIUS-Client-IPv6-Address"]["value"] == "2001:db8::1"
    assert body["control:FreeRADIUS-Client-Require-MA"]["value"] == "no"


@pytest.mark.parametrize("ip", ["10.0.0.2", "10.0.0.9", "garbage"])
async def test_unknown_or_disabled_client(client, ip):
    assert (await client.get(f"/aaa/clients/{ip}")).status_code == 404


# ── authenticate ───────────────────────────────────────────────────────────

async def test_authenticate_accepts_valid_password_with_special_characters(client):
    r = await client.post("/aaa/authenticate", json=rlm(
        User_Name="alice", User_Password='pa"ss\\wörd', NACo_NAS_IP=NAS_IP, NACo_Auth_Method="EAP-TTLS"))
    assert r.status_code == 204


async def test_authenticate_rejects_and_logs(client, world):
    r = await client.post("/aaa/authenticate", json=rlm(
        User_Name="alice", User_Password="nope", NACo_NAS_IP=NAS_IP, Calling_Station_Id="00-1B-63-AA-BB-CC",
        NACo_Auth_Method="PAP"))
    assert r.status_code == 401
    (row,) = await logs(world)
    assert row.result is AuthResult.REJECT and row.reason == "wrong password"
    assert row.mac_address == MAC and row.nas_name == "sw1" and row.auth_method == "PAP"


async def test_authenticate_disabled_user(client):
    r = await client.post("/aaa/authenticate", json=rlm(User_Name="dave", User_Password="dave-pw"))
    assert r.status_code == 401


async def test_repeated_failures_are_slowed_down(client, world):
    for _ in range(6):  # five free failures, the sixth starts the delay
        await client.post("/aaa/authenticate", json=rlm(User_Name="alice", User_Password="bad"))
    r = await client.post("/aaa/authenticate", json=rlm(User_Name="alice", User_Password='pa"ss\\wörd'))
    assert r.status_code == 401
    assert (await logs(world))[-1].reason.startswith("too many failed attempts")


# ── authorize ──────────────────────────────────────────────────────────────

STAFF = [{"type": "group", "op": "in", "value": ["staff"]}]


async def test_pap_accept_with_vlan_and_attributes(client, world):
    await add_policy(world, "staff", 10, PolicyAction.PERMIT, STAFF, vlan=10,
                     attrs={"Filter-Id": "staff-acl", "Cisco-AVPair": ["a=1", "b=2"]})
    r = await client.post("/aaa/authorize", json=rlm(
        User_Name="Alice", NACo_Auth_Method="PAP", NACo_NAS_IP=NAS_IP,
        Calling_Station_Id="00-1B-63-AA-BB-CC", Called_Station_Id="AA-BB-CC-00-00-01:Corp"))
    assert r.status_code == 200
    body = r.json()
    assert body["Tunnel-Type"] == {"value": "VLAN", "do_xlat": False}
    assert body["Tunnel-Medium-Type"]["value"] == "IEEE-802"
    assert body["Tunnel-Private-Group-Id"]["value"] == "10"
    assert body["Cisco-AVPair"]["value"] == ["a=1", "b=2"]
    (row,) = await logs(world)
    assert (row.result, row.username, row.policy_name, row.vlan, row.ssid) == (
        AuthResult.ACCEPT, "alice", "staff", 10, "Corp")
    assert len(row.decision_digest) == 64


async def test_accept_without_attributes_is_204(client, world):
    await add_policy(world, "all", 10, PolicyAction.PERMIT, [{"type": "always"}])
    r = await client.post("/aaa/authorize", json=rlm(User_Name="alice", NACo_Auth_Method="PAP",
                                                     NACo_NAS_IP=NAS_IP))
    assert r.status_code == 204


async def test_default_deny(client, world):
    r = await client.post("/aaa/authorize", json=rlm(User_Name="alice", NACo_Auth_Method="PAP",
                                                     NACo_NAS_IP=NAS_IP))
    assert r.status_code == 401
    assert (await logs(world))[0].reason == "no policy matched"


@pytest.mark.parametrize("attrs,reason", [
    ({"User_Name": "alice", "NACo_NAS_IP": NAS_IP}, "unknown authentication method"),
    ({"User_Name": "alice", "NACo_Auth_Method": "CHAP", "NACo_NAS_IP": NAS_IP}, "unknown authentication method"),
    ({"User_Name": "alice", "NACo_Auth_Method": "PAP"}, "unknown or disabled NAS"),
    ({"User_Name": "alice", "NACo_Auth_Method": "PAP", "NAS_IP_Address": NAS_IP}, "unknown or disabled NAS"),
    ({"User_Name": "alice", "NACo_Auth_Method": "PAP", "NACo_NAS_IP": "10.0.0.9"}, "unknown or disabled NAS"),
    ({"User_Name": "dave", "NACo_Auth_Method": "PAP", "NACo_NAS_IP": NAS_IP}, "user disabled"),
    ({"User_Name": "nobody", "NACo_Auth_Method": "PAP", "NACo_NAS_IP": NAS_IP}, "unknown user"),
    ({"User_Name": "anonymous", "NACo_Auth_Method": "EAP-TTLS", "NACo_NAS_IP": NAS_IP},
     "no authenticated identity"),
    ({"User_Name": "alice", "NACo_Auth_Method": "EAP-TLS", "NACo_NAS_IP": NAS_IP}, "no authenticated identity"),
    ({"User_Name": "x", "NACo_Auth_Method": "EAP-TLS", "TLS_Client_Cert_Common_Name": "mallory",
      "NACo_NAS_IP": NAS_IP}, "unknown user"),
])
async def test_authorize_refusals(client, world, attrs, reason):
    await add_policy(world, "all", 10, PolicyAction.PERMIT, [{"type": "always"}], vlan=5)
    r = await client.post("/aaa/authorize", json=rlm(**attrs))
    assert r.status_code == 401
    assert (await logs(world))[-1].reason == reason


async def test_ttls_uses_inner_identity(client, world):
    await add_policy(world, "staff", 10, PolicyAction.PERMIT, STAFF, vlan=10)
    r = await client.post("/aaa/authorize", json=rlm(
        User_Name="anonymous@corp", NACo_Inner_Identity="CORP\\alice", NACo_Auth_Method="EAP-TTLS",
        NACo_NAS_IP=NAS_IP))
    assert r.status_code == 200
    assert (await logs(world))[0].username == "alice"


async def test_eap_tls_uses_certificate_identity(client, world):
    await add_policy(world, "tls-staff", 10, PolicyAction.PERMIT,
                     [*STAFF, {"type": "auth_method", "value": ["EAP-TLS"]}], vlan=20)
    r = await client.post("/aaa/authorize", json=rlm(
        User_Name="bob", TLS_Client_Cert_Common_Name="alice", NACo_Auth_Method="EAP-TLS", NACo_NAS_IP=NAS_IP))
    assert r.status_code == 200
    assert r.json()["Tunnel-Private-Group-Id"]["value"] == "20"


async def test_mab_records_new_device_and_uses_status(client, world):
    await add_policy(world, "pending", 10, PolicyAction.PERMIT,
                     [{"type": "device_status", "value": ["pending"]},
                      {"type": "vendor", "op": "matches", "value": "apple*"}], vlan=30)
    r = await client.post("/aaa/authorize", json=rlm(
        User_Name="001b63aabbcc", User_Password="001b63aabbcc", Calling_Station_Id="00-1B-63-AA-BB-CC",
        NACo_Auth_Method="MAB", NACo_NAS_IP=NAS_IP))
    assert r.status_code == 200
    async with world() as db:
        device = (await db.execute(select(Device).where(Device.mac_address == MAC))).scalar_one()
    assert device.status is DeviceStatus.PENDING
    assert "Apple" in device.vendor
    assert device.last_nas_ip == NAS_IP
    row = (await logs(world))[0]
    assert row.username == "" and row.mac_address == MAC and row.auth_method == "MAB"


async def test_mab_requires_username_to_be_the_station_mac(client, world):
    await add_policy(world, "all", 10, PolicyAction.PERMIT, [{"type": "always"}], vlan=30)
    r = await client.post("/aaa/authorize", json=rlm(
        User_Name="alice", Calling_Station_Id="00-1B-63-AA-BB-CC", NACo_Auth_Method="MAB", NACo_NAS_IP=NAS_IP))
    assert r.status_code == 401
    assert (await logs(world))[0].reason == "not a valid MAB request"


async def test_blocked_device_is_refused_even_with_valid_user(client, world):
    await add_policy(world, "all", 10, PolicyAction.PERMIT, [{"type": "always"}], vlan=30)
    r = await client.post("/aaa/authorize", json=rlm(
        User_Name="alice", Calling_Station_Id="66-55-44-33-22-11", NACo_Auth_Method="PAP", NACo_NAS_IP=NAS_IP))
    assert r.status_code == 401
    assert (await logs(world))[0].reason == "device blocked"


async def test_active_guest_registration_gives_guest_status(client, world):
    async with world() as db:
        db.add(GuestRegistration(mac_address=MAC, expires_at=utcnow() + timedelta(hours=1)))
        db.add(GuestRegistration(mac_address="00:00:00:00:00:02", expires_at=utcnow() - timedelta(hours=1)))
        await db.commit()
    await add_policy(world, "guests", 10, PolicyAction.PERMIT,
                     [{"type": "device_status", "value": ["guest"]}], vlan=40)
    ok = await client.post("/aaa/authorize", json=rlm(
        User_Name=MAC, Calling_Station_Id=MAC, NACo_Auth_Method="MAB", NACo_NAS_IP=NAS_IP))
    assert ok.status_code == 200
    expired = await client.post("/aaa/authorize", json=rlm(
        User_Name="00:00:00:00:00:02", Calling_Station_Id="00:00:00:00:00:02",
        NACo_Auth_Method="MAB", NACo_NAS_IP=NAS_IP))
    assert expired.status_code == 401


async def test_explicit_deny_policy(client, world):
    await add_policy(world, "no-alice", 1, PolicyAction.DENY,
                     [{"type": "username", "op": "equals", "value": "alice"}])
    await add_policy(world, "all", 10, PolicyAction.PERMIT, [{"type": "always"}], vlan=5)
    r = await client.post("/aaa/authorize", json=rlm(User_Name="alice", NACo_Auth_Method="PAP",
                                                     NACo_NAS_IP=NAS_IP))
    assert r.status_code == 401
    assert (await logs(world))[0].policy_name == "no-alice"


# ── accounting ─────────────────────────────────────────────────────────────

async def sessions(sf):
    async with sf() as db:
        return (await db.execute(select(RadiusSession).order_by(RadiusSession.id))).scalars().all()


async def test_accounting_lifecycle_with_context(client, world):
    await add_policy(world, "staff", 10, PolicyAction.PERMIT, STAFF, vlan=10)
    await client.post("/aaa/authorize", json=rlm(
        User_Name="anonymous", NACo_Inner_Identity="alice", NACo_Auth_Method="PEAP", NACo_NAS_IP=NAS_IP,
        Calling_Station_Id="00-1B-63-AA-BB-CC", Called_Station_Id="AA-BB-CC-00-00-01:Corp"))

    start = rlm(Acct_Status_Type="Start", Acct_Session_Id="S1", User_Name="anonymous", NACo_NAS_IP=NAS_IP,
                Calling_Station_Id="00-1B-63-AA-BB-CC")
    assert (await client.post("/aaa/accounting", json=start)).status_code == 204
    (s,) = await sessions(world)
    assert (s.username, s.acct_username, s.calling_station_id) == ("alice", "anonymous", "00-1B-63-AA-BB-CC")
    assert (s.auth_method, s.policy_name, s.vlan, s.ssid) == ("PEAP", "staff", 10, "Corp")
    assert len(s.decision_digest) == 64

    interim = rlm(Acct_Status_Type="Interim-Update", Acct_Session_Id="S1", NACo_NAS_IP=NAS_IP,
                  Framed_IP_Address="192.168.10.5", Acct_Input_Octets="10", Acct_Input_Gigawords="1",
                  Acct_Output_Octets="20", Acct_Session_Time="60")
    await client.post("/aaa/accounting", json=interim)
    (s,) = await sessions(world)
    assert (s.framed_ip, s.input_octets, s.output_octets, s.session_time) == ("192.168.10.5", 2**32 + 10, 20, 60)

    await client.post("/aaa/accounting", json=rlm(Acct_Status_Type="Stop", Acct_Session_Id="S1",
                                                  NACo_NAS_IP=NAS_IP))
    assert await sessions(world) == []


async def test_session_ids_are_per_nas_and_accounting_on_clears_one_nas(client, world):
    for nas in (NAS_IP, "2001:db8::1"):
        await client.post("/aaa/accounting", json=rlm(Acct_Status_Type="Start", Acct_Session_Id="1",
                                                      NACo_NAS_IP=nas))
    assert len(await sessions(world)) == 2
    await client.post("/aaa/accounting", json=rlm(Acct_Status_Type="Accounting-On", NACo_NAS_IP=NAS_IP))
    (s,) = await sessions(world)
    assert s.nas_ip == "2001:db8::1"


async def test_numeric_status_and_duplicate_start_are_idempotent(client, world):
    for _ in range(2):
        r = await client.post("/aaa/accounting", json=rlm(Acct_Status_Type="1", Acct_Session_Id="dup",
                                                          NACo_NAS_IP=NAS_IP))
        assert r.status_code == 204
    assert len(await sessions(world)) == 1


async def test_accounting_without_nas_source_is_ignored(client, world):
    r = await client.post("/aaa/accounting", json=rlm(Acct_Status_Type="Start", Acct_Session_Id="x"))
    assert r.status_code == 204
    assert await sessions(world) == []


async def test_metrics_endpoint_is_open_and_renders(client):
    r = await client.get("/metrics", headers={"Authorization": ""})
    assert r.status_code == 200
    assert "naco_aaa_request_seconds" in r.text
