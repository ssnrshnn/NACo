from datetime import timedelta
from zoneinfo import ZoneInfo

import pytest
from sqlalchemy import select, update

from naco.aaa.subject import subject_context
from naco.auth.identity import lookup_user
from naco.core.timeutil import utcnow
from naco.db.models import (
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
from naco.policy.engine import decide, load_policies
from naco.radius.reevaluate import reevaluate
from tests.conftest import write_config
from tests.fakenas import parse_attrs, start_fake_nas

SECRET = "coa-secret-value"
MAC = "aa:bb:cc:00:00:01"


@pytest.fixture
async def nas():
    proto, transport = await start_fake_nas(secret=SECRET)
    yield proto
    transport.close()


async def current_digest(sf, method, username, mac):
    user = await lookup_user(username) if username else None
    async with sf() as db:
        device = (await db.execute(select(Device).where(Device.mac_address == mac))).scalar_one_or_none()
        policies = await load_policies(db)
    subject = subject_context(method=method, username=username, user=user, mac=mac, device=device,
                              is_guest=False, nas_name="sw1", nas_ip="127.0.0.1", ssid=None, now=utcnow())
    return decide(policies, subject, ZoneInfo("UTC")).digest()


@pytest.fixture
async def world(app_db, nas):
    async with app_db() as db:
        staff = Group(name="staff")
        db.add(staff)
        await db.flush()
        db.add_all([
            NasClient(name="sw1", ip_address="127.0.0.1", secret=SECRET, coa_port=nas.port),
            User(username="alice", password_hash="x", group_id=staff.id),
            Device(mac_address=MAC, status=DeviceStatus.APPROVED),
            Policy(name="staff", priority=10, action=PolicyAction.PERMIT, vlan=10,
                   conditions=[{"type": "group", "op": "in", "value": ["staff"]}]),
            Policy(name="printers", priority=20, action=PolicyAction.PERMIT, vlan=40,
                   conditions=[{"type": "device_status", "value": ["approved"]}]),
        ])
        await db.commit()
    alice_digest = await current_digest(app_db, "PEAP", "alice", None)
    mab_digest = await current_digest(app_db, "MAB", "", MAC)
    async with app_db() as db:
        db.add_all([
            RadiusSession(nas_ip="127.0.0.1", acct_session_id="A1", username="alice", acct_username="anon",
                          auth_method="PEAP", decision_digest=alice_digest),
            RadiusSession(nas_ip="127.0.0.1", acct_session_id="P1", mac_address=MAC, auth_method="MAB",
                          calling_station_id="AA-BB-CC-00-00-01", decision_digest=mab_digest),
            RadiusSession(nas_ip="127.0.0.1", acct_session_id="X", auth_method="PEAP"),  # no context: ignored
        ])
        await db.commit()
    return app_db


def disconnected(nas):
    return sorted(parse_attrs(p)[44][0].decode() for p in nas.received)


async def test_nothing_changes(world, nas):
    s = await reevaluate(["noop"])
    assert (s.checked, s.changed) == (2, 0)
    assert nas.received == []


async def test_cosmetic_policy_edit_disconnects_nobody(world, nas):
    async with world() as db:
        await db.execute(update(Policy).where(Policy.name == "staff").values(
            description="new words", name="staff-renamed"))
        await db.commit()
    assert (await reevaluate()).changed == 0


async def test_vlan_change_disconnects_only_affected_sessions(world, nas):
    async with world() as db:
        await db.execute(update(Policy).where(Policy.name == "staff").values(vlan=11))
        await db.commit()
    s = await reevaluate(["policy edit"])
    assert (s.changed, s.disconnected, s.failed) == (1, 1, 0)
    assert disconnected(nas) == ["A1"]
    assert parse_attrs(nas.received[0])[1] == [b"anon"]  # identifiers as the NAS reported them


async def test_disabling_user_and_blocking_device(world, nas):
    async with world() as db:
        await db.execute(update(User).values(enabled=False))
        await db.execute(update(Device).values(status=DeviceStatus.BLOCKED))
        await db.commit()
    s = await reevaluate()
    assert s.disconnected == 2
    assert disconnected(nas) == ["A1", "P1"]
    assert parse_attrs(next(p for p in nas.received if b"P1" in p))[31] == [b"AA-BB-CC-00-00-01"]


async def test_guest_expiry_and_group_change(world, nas):
    async with world() as db:
        await db.execute(update(User).values(group_id=None))
        db.add(GuestRegistration(mac_address=MAC, expires_at=utcnow() - timedelta(minutes=1)))
        await db.commit()
    s = await reevaluate()
    assert disconnected(nas) == ["A1"]
    assert s.changed == 1


async def test_broken_policy_set_disconnects_nobody(world, nas):
    async with world() as db:
        db.add(Policy(name="broken", priority=1, action=PolicyAction.DENY, conditions=[{"type": "??"}]))
        await db.commit()
    s = await reevaluate()
    assert s.checked == 0
    assert nas.received == []


async def test_unreachable_nas_is_counted_as_failure(world, nas, tmp_path, monkeypatch):
    write_config(tmp_path, monkeypatch, "radius:\n  coa_timeout_seconds: 0.05\n  coa_retries: 1\n")
    nas.silent = True
    async with world() as db:
        await db.execute(update(Policy).where(Policy.name == "staff").values(vlan=12))
        await db.commit()
    s = await reevaluate()
    assert (s.changed, s.failed) == (1, 1)
