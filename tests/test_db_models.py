from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError, StatementError

from naco.db.models import (
    AdminRole,
    AdminSession,
    AdminUser,
    AuthLog,
    AuthResult,
    CommandAction,
    CommandRule,
    CommandSet,
    Device,
    DeviceStatus,
    Group,
    NasClient,
    Policy,
    PolicyAction,
    RadiusSession,
    User,
)


async def test_admin_user_defaults_and_roundtrip(db):
    db.add(AdminUser(username="admin", password_hash="x"))
    await db.commit()
    admin = (await db.execute(select(AdminUser))).scalar_one()
    assert admin.role is AdminRole.VIEWER
    assert admin.must_change_password is True
    assert admin.recovery_codes == []
    assert admin.created_at.tzinfo is not None


def test_role_ordering():
    assert AdminRole.SUPERUSER.allows(AdminRole.OPERATOR)
    assert AdminRole.OPERATOR.allows(AdminRole.OPERATOR)
    assert not AdminRole.VIEWER.allows(AdminRole.OPERATOR)


async def test_datetimes_come_back_aware_utc(db):
    when = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC) + timedelta(hours=3)
    admin = AdminUser(username="a", password_hash="x")
    db.add(admin)
    await db.flush()
    db.add(AdminSession(token_hash="h" * 64, admin_id=admin.id, csrf_token="c", expires_at=when))
    await db.commit()
    db.expire_all()
    s = (await db.execute(select(AdminSession))).scalar_one()
    assert s.expires_at == when
    assert s.expires_at.tzinfo is UTC


async def test_naive_datetime_is_refused(db):
    admin = AdminUser(username="a", password_hash="x")
    db.add(admin)
    await db.flush()
    db.add(AdminSession(token_hash="h" * 64, admin_id=admin.id, csrf_token="c",
                        expires_at=datetime(2026, 1, 1)))
    with pytest.raises(StatementError, match="naive"):
        await db.flush()


async def test_secrets_are_encrypted_at_rest(db):
    db.add(NasClient(name="sw1", ip_address="10.0.0.1", secret="very-secret-value"))
    await db.commit()
    raw = (await db.execute(text("SELECT secret FROM nas_clients"))).scalar_one()
    assert raw.startswith("enc:v2:")
    assert "very-secret-value" not in raw
    db.expire_all()
    nas = (await db.execute(select(NasClient))).scalar_one()
    assert nas.secret == "very-secret-value"
    assert nas.coa_port == 3799
    assert nas.require_message_authenticator is True


async def test_deleting_group_clears_membership(db):
    g = Group(name="staff")
    db.add(g)
    await db.flush()
    db.add(User(username="alice", password_hash="x", group_id=g.id))
    await db.commit()
    await db.execute(text("DELETE FROM groups"))
    await db.commit()
    db.expire_all()
    alice = (await db.execute(select(User))).scalar_one()
    assert alice.group_id is None


async def test_command_rules_cascade_and_order(db):
    cs = CommandSet(name="ro", rules=[
        CommandRule(position=2, action=CommandAction.DENY, pattern="configure *"),
        CommandRule(position=1, action=CommandAction.PERMIT, pattern="show *"),
    ])
    db.add(cs)
    await db.commit()
    db.expire_all()
    cs = (await db.execute(select(CommandSet))).scalar_one()
    await db.refresh(cs, ["rules"])
    assert [r.pattern for r in cs.rules] == ["show *", "configure *"]
    assert cs.default_action is CommandAction.DENY
    await db.delete(cs)
    await db.commit()
    assert (await db.execute(text("SELECT count(*) FROM command_rules"))).scalar_one() == 0


async def test_group_privilege_range_is_enforced(db):
    db.add(Group(name="bad", device_admin_privilege=16))
    with pytest.raises(IntegrityError):
        await db.commit()


async def test_policy_vlan_range_is_enforced(db):
    db.add(Policy(name="p", action=PolicyAction.PERMIT, vlan=5000))
    with pytest.raises(IntegrityError):
        await db.commit()


async def test_enum_check_constraint(db):
    with pytest.raises(IntegrityError):
        await db.execute(text(
            "INSERT INTO devices (mac_address, status, device_type, vendor, description, notes,"
            " first_seen, last_seen, last_nas_ip, last_username)"
            " VALUES ('aa:bb:cc:dd:ee:ff', 'BOGUS', '', '', '', '', '2026-01-01', '2026-01-01', '', '')"
        ))


async def test_device_defaults(db):
    db.add(Device(mac_address="aa:bb:cc:dd:ee:ff"))
    await db.commit()
    d = (await db.execute(select(Device))).scalar_one()
    assert d.status is DeviceStatus.PENDING


async def test_radius_session_unique_per_nas(db):
    db.add(RadiusSession(nas_ip="10.0.0.1", acct_session_id="1"))
    db.add(RadiusSession(nas_ip="10.0.0.2", acct_session_id="1"))
    await db.commit()
    db.add(RadiusSession(nas_ip="10.0.0.1", acct_session_id="1"))
    with pytest.raises(IntegrityError):
        await db.commit()


async def test_auth_log(db):
    db.add(AuthLog(username="alice", result=AuthResult.ACCEPT, vlan=10))
    await db.commit()
    row = (await db.execute(select(AuthLog))).scalar_one()
    assert row.result is AuthResult.ACCEPT
