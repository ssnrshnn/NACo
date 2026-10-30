import pytest
from sqlalchemy import select

from naco.db.models import AdminRole, AuditLog, Device, DeviceStatus, Group, User, UserSource
from naco.radius import reevaluate
from tests.api.conftest import bearer, make_token

V1 = "/api/v1"


@pytest.fixture
async def tokens(api):
    return {role: bearer(await make_token(api.sf, role)) for role in AdminRole}


@pytest.fixture
def scheduled(monkeypatch):
    calls = []
    monkeypatch.setattr(reevaluate.reevaluator, "schedule", calls.append)
    return calls


async def last_audit(sf) -> AuditLog:
    async with sf() as db:
        return (await db.execute(select(AuditLog).order_by(AuditLog.id.desc()).limit(1))).scalar_one()


async def mkgroup(api, su, name="staff", **kw):
    r = await api.post(f"{V1}/groups", headers=su, json={"name": name, **kw})
    assert r.status_code == 201, r.text
    return r.json()


# ── users ──────────────────────────────────────────────────────────────────

async def test_user_lifecycle(api, tokens, scheduled):
    op, su = tokens[AdminRole.OPERATOR], tokens[AdminRole.SUPERUSER]
    staff = await mkgroup(api, su)
    r = await api.post(f"{V1}/users", headers=op, json={
        "username": "CORP\\Alice", "password": "alice-password", "group_id": staff["id"], "email": "a@x.io"})
    assert r.status_code == 201
    user = r.json()
    assert user["username"] == "alice" and user["group_name"] == "staff" and "password" not in user
    audit = await last_audit(api.sf)
    assert (audit.action, audit.actor_type.value, audit.target_name) == ("user.create", "TOKEN", "alice")

    dup = await api.post(f"{V1}/users", headers=op, json={"username": "alice", "password": "x" * 10})
    assert dup.status_code == 409

    r = await api.patch(f"{V1}/users/{user['id']}", headers=op, json={"enabled": False, "password": "new-password"})
    assert r.status_code == 200 and r.json()["enabled"] is False
    changes = (await last_audit(api.sf)).changes
    assert changes == {"enabled": [True, False], "password": ["***", "***"]}
    assert scheduled == ["user alice changed"]

    listing = (await api.get(f"{V1}/users?q=ali&per_page=1", headers=tokens[AdminRole.VIEWER])).json()
    assert listing["total"] == 1 and listing["items"][0]["username"] == "alice"

    assert (await api.delete(f"{V1}/users/{user['id']}", headers=op)).status_code == 204
    assert (await api.get(f"{V1}/users/{user['id']}", headers=op)).status_code == 404


@pytest.mark.parametrize("payload,status", [
    ({"username": "bob", "password": "short"}, 422),
    ({"username": "bob smith", "password": "long-enough"}, 422),
    ({"username": "", "password": "long-enough"}, 422),
    ({"username": "bob", "password": "long-enough", "group_id": 999}, 422),
])
async def test_user_validation(api, tokens, payload, status):
    assert (await api.post(f"{V1}/users", headers=tokens[AdminRole.OPERATOR], json=payload)).status_code == status


async def test_device_admin_users_belong_to_superusers(api, tokens):
    op, su = tokens[AdminRole.OPERATOR], tokens[AdminRole.SUPERUSER]
    netadmins = await mkgroup(api, su, "netadmins", device_admin_privilege=15)
    staff = await mkgroup(api, su, "staff")
    body = {"username": "neo", "password": "neo-password", "group_id": netadmins["id"]}
    assert (await api.post(f"{V1}/users", headers=op, json=body)).status_code == 403
    neo = (await api.post(f"{V1}/users", headers=su, json=body)).json()
    plain = (await api.post(f"{V1}/users", headers=op, json={"username": "pat", "password": "pat-password",
                                                             "group_id": staff["id"]})).json()
    # An operator can neither touch a network admin nor promote someone into that group.
    assert (await api.patch(f"{V1}/users/{neo['id']}", headers=op, json={"password": "pwned-pass"})).status_code == 403
    assert (await api.delete(f"{V1}/users/{neo['id']}", headers=op)).status_code == 403
    assert (await api.patch(f"{V1}/users/{plain['id']}", headers=op,
                            json={"group_id": netadmins["id"]})).status_code == 403
    assert (await api.patch(f"{V1}/users/{plain['id']}", headers=op, json={"group_id": None})).status_code == 200


async def test_ldap_users_have_no_password(api, tokens):
    async with api.sf() as db:
        db.add(User(username="lena", source=UserSource.LDAP, password_hash=None))
        await db.commit()
        uid = (await db.execute(select(User.id))).scalar_one()
    r = await api.patch(f"{V1}/users/{uid}", headers=tokens[AdminRole.OPERATOR], json={"password": "something-long"})
    assert r.status_code == 422


# ── groups ─────────────────────────────────────────────────────────────────

async def test_groups_need_superuser_and_protect_policies(api, tokens, scheduled):
    su = tokens[AdminRole.SUPERUSER]
    assert (await api.post(f"{V1}/groups", headers=tokens[AdminRole.OPERATOR], json={"name": "x"})).status_code == 403
    staff = await mkgroup(api, su)
    assert (await api.post(f"{V1}/groups", headers=su, json={"name": "staff"})).status_code == 409
    assert (await api.post(f"{V1}/groups", headers=su, json={"name": "x", "command_set_id": 42})).status_code == 422
    await api.post(f"{V1}/policies", headers=su, json={
        "name": "staff-ok", "action": "PERMIT", "conditions": [{"type": "group", "op": "in", "value": ["Staff"]}]})
    assert (await api.patch(f"{V1}/groups/{staff['id']}", headers=su, json={"name": "people"})).status_code == 409
    assert (await api.delete(f"{V1}/groups/{staff['id']}", headers=su)).status_code == 409
    assert (await api.patch(f"{V1}/groups/{staff['id']}", headers=su,
                            json={"description": "everyone"})).status_code == 200


async def test_deleting_a_group_frees_its_members(api, tokens, scheduled):
    su = tokens[AdminRole.SUPERUSER]
    temp = await mkgroup(api, su, "temp")
    user = (await api.post(f"{V1}/users", headers=su, json={"username": "t", "password": "t-password",
                                                            "group_id": temp["id"]})).json()
    groups = (await api.get(f"{V1}/groups", headers=su)).json()
    assert groups[0]["members"] == 1
    assert (await api.delete(f"{V1}/groups/{temp['id']}", headers=su)).status_code == 204
    assert (await api.get(f"{V1}/users/{user['id']}", headers=su)).json()["group_id"] is None
    assert "group temp deleted" in scheduled


# ── devices ────────────────────────────────────────────────────────────────

async def test_device_lifecycle(api, tokens, scheduled):
    op = tokens[AdminRole.OPERATOR]
    r = await api.post(f"{V1}/devices", headers=op, json={"mac_address": "00-1B-63-AA-BB-CC", "device_type": "laptop"})
    assert r.status_code == 201
    dev = r.json()
    assert dev["mac_address"] == "00:1b:63:aa:bb:cc" and "Apple" in dev["vendor"] and dev["status"] == "APPROVED"
    assert (await api.post(f"{V1}/devices", headers=op, json={"mac_address": "001b63aabbcc"})).status_code == 409
    assert (await api.post(f"{V1}/devices", headers=op, json={"mac_address": "nope"})).status_code == 422

    r = await api.patch(f"{V1}/devices/{dev['id']}", headers=op, json={"status": "BLOCKED", "notes": "stolen"})
    assert r.json()["status"] == "BLOCKED"
    assert (await last_audit(api.sf)).changes == {"notes": ["", "stolen"], "status": ["APPROVED", "BLOCKED"]}
    assert scheduled[-1] == "device 00:1b:63:aa:bb:cc changed"

    found = (await api.get(f"{V1}/devices?q=AA:BB&status=BLOCKED", headers=tokens[AdminRole.VIEWER])).json()
    assert found["total"] == 1


async def test_bulk_device_status(api, tokens, scheduled):
    async with api.sf() as db:
        db.add_all([Device(mac_address=f"02:00:00:00:00:0{i}") for i in range(3)])
        await db.commit()
        ids = list((await db.execute(select(Device.id))).scalars())
    r = await api.post(f"{V1}/devices/bulk", headers=tokens[AdminRole.OPERATOR], json={"ids": ids, "status": "APPROVED"})
    assert r.status_code == 200 and {d["status"] for d in r.json()} == {"APPROVED"}
    async with api.sf() as db:
        assert set((await db.execute(select(Device.status))).scalars()) == {DeviceStatus.APPROVED}
        assert len((await db.execute(select(AuditLog).where(AuditLog.action == "device.update"))).all()) == 3
    bad = await api.post(f"{V1}/devices/bulk", headers=tokens[AdminRole.OPERATOR], json={"ids": [999], "status": "BLOCKED"})
    assert bad.status_code == 404


# ── policies ───────────────────────────────────────────────────────────────

@pytest.mark.parametrize("payload,fragment", [
    ({"conditions": [{"type": "regex", "value": ".*"}]}, "conditions"),
    ({"conditions": [{"type": "mac", "op": "equals", "value": "zz"}]}, "MAC"),
    ({"action": "DENY", "vlan": 10}, "DENY"),
    ({"reply_attributes": {"control:Auth-Type": "Accept"}}, "attribute"),
    ({"reply_attributes": {"Filter-Id": "%{User-Name}"}}, "expansions"),
    ({"vlan": 4095}, "4094"),
])
async def test_policy_validation(api, tokens, payload, fragment):
    body = {"name": "p", "action": "PERMIT", **payload}
    r = await api.post(f"{V1}/policies", headers=tokens[AdminRole.SUPERUSER], json=body)
    assert r.status_code == 422
    assert fragment.lower() in r.text.lower()


async def test_policy_lifecycle_reorder_and_simulate(api, tokens, scheduled):
    su, viewer = tokens[AdminRole.SUPERUSER], tokens[AdminRole.VIEWER]
    assert (await api.post(f"{V1}/policies", headers=tokens[AdminRole.OPERATOR],
                           json={"name": "x", "action": "PERMIT"})).status_code == 403
    staff = await mkgroup(api, su)
    await api.post(f"{V1}/users", headers=su, json={"username": "alice", "password": "alice-password",
                                                    "group_id": staff["id"]})
    a = (await api.post(f"{V1}/policies", headers=su, json={
        "name": "staff", "action": "PERMIT", "vlan": 10, "priority": 50,
        "conditions": [{"type": "group", "op": "in", "value": ["staff"]},
                       {"type": "mac", "op": "matches", "value": "AA-BB-*"}]})).json()
    assert a["conditions"][1]["value"] == "aa:bb:*"
    b = (await api.post(f"{V1}/policies", headers=su, json={
        "name": "deny-all", "action": "DENY", "priority": 10, "conditions": [{"type": "always"}]})).json()

    sim = (await api.post(f"{V1}/policies/simulate", headers=viewer, json={
        "auth_method": "PEAP", "username": "Alice", "mac": "aa:bb:00:00:00:01"})).json()
    assert sim["accepted"] is False and sim["policy"] == "deny-all"
    assert [t["policy"] for t in sim["trace"]] == ["deny-all", "staff"]
    assert sim["trace"][1]["conditions"] == [{"label": "group in staff", "matched": True},
                                             {"label": "mac matches aa:bb:*", "matched": True}]

    order = (await api.post(f"{V1}/policies/reorder", headers=su, json={"ids": [a["id"], b["id"]]})).json()
    assert [p["priority"] for p in order] == [10, 20]
    assert (await api.post(f"{V1}/policies/reorder", headers=su, json={"ids": [a["id"]]})).status_code == 422
    sim = (await api.post(f"{V1}/policies/simulate", headers=viewer, json={
        "auth_method": "PEAP", "username": "alice", "mac": "aa:bb:00:00:00:01"})).json()
    assert sim["accepted"] is True and sim["vlan"] == 10 and sim["context"]["group"] == "staff"

    unknown = (await api.post(f"{V1}/policies/simulate", headers=viewer, json={
        "auth_method": "PAP", "username": "ghost"})).json()
    assert unknown["accepted"] is False and unknown["reason"] == "unknown user" and unknown["trace"] == []

    r = await api.patch(f"{V1}/policies/{a['id']}", headers=su, json={"vlan": None, "description": "no vlan"})
    assert r.json()["vlan"] is None
    assert (await api.patch(f"{V1}/policies/{b['id']}", headers=su, json={"vlan": 5})).status_code == 422
    assert (await api.delete(f"{V1}/policies/{b['id']}", headers=su)).status_code == 204
    assert scheduled  # every change re-evaluates live sessions


# ── NAS / TACACS+ / command sets ───────────────────────────────────────────

async def test_nas_secret_is_write_only_and_reveal_is_audited(api, tokens):
    su = tokens[AdminRole.SUPERUSER]
    weak = await api.post(f"{V1}/nas", headers=su, json={"name": "sw1", "ip_address": "10.0.0.1", "secret": "short"})
    assert weak.status_code == 422
    assert (await api.post(f"{V1}/nas", headers=su, json={"name": "sw1", "ip_address": "10.0.0.300",
                                                           "secret": "s" * 20})).status_code == 422
    nas = (await api.post(f"{V1}/nas", headers=su, json={"name": "sw1", "ip_address": "10.0.0.1",
                                                          "secret": "s" * 20})).json()
    assert "secret" not in nas and nas["require_message_authenticator"] is True
    assert (await api.post(f"{V1}/nas", headers=su, json={"name": "sw2", "ip_address": "10.0.0.1",
                                                           "secret": "s" * 20})).status_code == 409
    assert (await api.get(f"{V1}/nas/{nas['id']}/secret", headers=tokens[AdminRole.OPERATOR])).status_code == 403
    assert (await api.get(f"{V1}/nas/{nas['id']}/secret", headers=su)).json() == {"secret": "s" * 20}
    assert (await last_audit(api.sf)).action == "nas.secret_viewed"
    await api.patch(f"{V1}/nas/{nas['id']}", headers=su, json={"secret": "t" * 20, "coa_port": 1700})
    assert (await last_audit(api.sf)).changes == {"coa_port": [3799, 1700], "secret": ["***", "***"]}
    assert (await api.post(f"{V1}/nas", headers=tokens[AdminRole.OPERATOR],
                           json={"name": "x", "ip_address": "10.0.0.2", "secret": "s" * 20})).status_code == 403


async def test_tacacs_clients(api, tokens):
    su = tokens[AdminRole.SUPERUSER]
    c = (await api.post(f"{V1}/tacacs-clients", headers=su, json={"name": "core", "ip_address": "2001:db8::5",
                                                                   "key": "k" * 16})).json()
    assert c["ip_address"] == "2001:db8::5" and "key" not in c
    assert (await api.get(f"{V1}/tacacs-clients/{c['id']}/key", headers=su)).json() == {"key": "k" * 16}
    assert (await api.delete(f"{V1}/tacacs-clients/{c['id']}", headers=su)).status_code == 204


async def test_command_sets(api, tokens):
    su = tokens[AdminRole.SUPERUSER]
    cs = (await api.post(f"{V1}/command-sets", headers=su, json={"name": "readonly", "rules": [
        {"action": "PERMIT", "pattern": "show  *"}, {"action": "DENY", "pattern": "configure *"}]})).json()
    assert cs["default_action"] == "DENY"
    assert cs["rules"] == [{"action": "PERMIT", "pattern": "show *"}, {"action": "DENY", "pattern": "configure *"}]
    cs = (await api.patch(f"{V1}/command-sets/{cs['id']}", headers=su,
                          json={"rules": [{"action": "PERMIT", "pattern": "ping *"}]})).json()
    assert [r["pattern"] for r in cs["rules"]] == ["ping *"]
    await mkgroup(api, su, "netops", device_admin_privilege=7, command_set_id=cs["id"])
    assert (await api.get(f"{V1}/command-sets", headers=tokens[AdminRole.VIEWER])).json()[0]["groups"] == 1
    assert (await api.delete(f"{V1}/command-sets/{cs['id']}", headers=su)).status_code == 409
    async with api.sf() as db:
        assert (await db.execute(select(Group.command_set_id))).scalar_one() == cs["id"]
