import pytest
from sqlalchemy import select

from naco.auth import identity
from naco.auth.identity import authenticate_user, canonical_username, lookup_user
from naco.auth.ldap import LdapError, LdapUser
from naco.core.passwords import hash_password_sync
from naco.db.models import Group, User, UserSource
from tests.conftest import write_config

STAFF_DN = "CN=Staff,DC=ex,DC=com"
LDAP_YAML = """
ldap:
  enabled: true
  servers: ['ldaps://dc.ex.com']
  base_dn: dc=ex,dc=com
  group_map:
    - {ldap_group: 'CN=Staff,DC=ex,DC=com', group: staff}
"""


@pytest.fixture
async def seeded(app_db):
    async with app_db() as db:
        staff = Group(name="staff", device_admin_privilege=15)
        db.add(staff)
        await db.flush()
        db.add_all([
            User(username="alice", password_hash=hash_password_sync("alice-pw"), group_id=staff.id),
            User(username="dave", password_hash=hash_password_sync("dave-pw"), enabled=False),
        ])
        await db.commit()
    return app_db


class FakeDirectory:
    def __init__(self, result=None, error=None):
        self.result, self.error, self.calls = result, error, []

    async def __call__(self, username, password):
        self.calls.append(username)
        if self.error:
            raise self.error
        return self.result


@pytest.mark.parametrize("raw,expected", [
    ("Alice", "alice"), ("  CORP\\Alice ", "alice"), ("alice@corp.com", "alice@corp.com"),
    ("", ""), (None, ""), ("x" * 65, ""), ("bad\x00name", ""),
])
def test_canonical_username(raw, expected):
    assert canonical_username(raw) == expected


async def test_local_success_records_login(seeded):
    result = await authenticate_user("CORP\\ALICE", "alice-pw")
    assert result.ok and result.reason == "ok"
    assert result.user.group_name == "staff"
    assert result.user.device_admin_privilege == 15
    async with seeded() as db:
        alice = (await db.execute(select(User).where(User.username == "alice"))).scalar_one()
        assert alice.last_login_at is not None


async def test_local_wrong_password(seeded):
    result = await authenticate_user("alice", "nope")
    assert not result.ok and result.reason == "wrong password"


async def test_disabled_user_is_refused_without_directory(seeded, monkeypatch, tmp_path):
    write_config(tmp_path, monkeypatch, LDAP_YAML)
    fake = FakeDirectory(LdapUser("cn=dave", "", "", ()))
    monkeypatch.setattr(identity, "ldap_authenticate", fake)
    result = await authenticate_user("dave", "dave-pw")
    assert not result.ok and result.reason == "user disabled"
    assert fake.calls == []


async def test_unknown_user_without_ldap(seeded):
    result = await authenticate_user("mallory", "whatever")
    assert not result.ok and result.reason == "unknown user"


@pytest.mark.parametrize("user,pw", [("", "x"), ("alice", ""), (None, None)])
async def test_missing_credentials(seeded, user, pw):
    assert not (await authenticate_user(user, pw)).ok


async def test_local_user_never_goes_to_ldap(seeded, monkeypatch, tmp_path):
    write_config(tmp_path, monkeypatch, LDAP_YAML)
    fake = FakeDirectory(LdapUser("cn=alice", "", "", ()))
    monkeypatch.setattr(identity, "ldap_authenticate", fake)
    assert not (await authenticate_user("alice", "directory-password")).ok
    assert fake.calls == []


async def test_first_ldap_login_provisions_with_mapped_group(seeded, monkeypatch, tmp_path):
    write_config(tmp_path, monkeypatch, LDAP_YAML)
    monkeypatch.setattr(identity, "ldap_authenticate",
                        FakeDirectory(LdapUser("cn=erin", "erin@ex.com", "Erin E", (STAFF_DN.lower(),))))
    result = await authenticate_user("Erin", "pw")
    assert result.ok
    assert result.user.source is UserSource.LDAP
    assert result.user.group_name == "staff"
    async with seeded() as db:
        erin = (await db.execute(select(User).where(User.username == "erin"))).scalar_one()
        assert erin.password_hash is None
        assert erin.email == "erin@ex.com"


async def test_ldap_group_is_refreshed_every_login(seeded, monkeypatch, tmp_path):
    write_config(tmp_path, monkeypatch, LDAP_YAML)
    monkeypatch.setattr(identity, "ldap_authenticate", FakeDirectory(LdapUser("cn=erin", "", "", (STAFF_DN,))))
    assert (await authenticate_user("erin", "pw")).user.group_name == "staff"
    monkeypatch.setattr(identity, "ldap_authenticate", FakeDirectory(LdapUser("cn=erin", "", "", ())))
    result = await authenticate_user("erin", "pw")
    assert result.ok and result.user.group_id is None


async def test_without_group_map_ldap_users_keep_admin_assigned_group(seeded, monkeypatch, tmp_path):
    write_config(tmp_path, monkeypatch, "ldap:\n  enabled: true\n  servers: ['ldaps://dc']\n")
    async with seeded() as db:
        staff = (await db.execute(select(Group))).scalar_one()
        db.add(User(username="fred", source=UserSource.LDAP, password_hash=None, group_id=staff.id))
        await db.commit()
    monkeypatch.setattr(identity, "ldap_authenticate", FakeDirectory(LdapUser("cn=fred", "", "", ())))
    result = await authenticate_user("fred", "pw")
    assert result.ok and result.user.group_name == "staff"


async def test_ldap_rejection(seeded, monkeypatch, tmp_path):
    write_config(tmp_path, monkeypatch, LDAP_YAML)
    monkeypatch.setattr(identity, "ldap_authenticate", FakeDirectory(None))
    result = await authenticate_user("zoe", "pw")
    assert not result.ok and result.reason == "unknown user"


async def test_directory_failure_fails_closed(seeded, monkeypatch, tmp_path):
    write_config(tmp_path, monkeypatch, LDAP_YAML)
    monkeypatch.setattr(identity, "ldap_authenticate", FakeDirectory(error=LdapError("down")))
    result = await authenticate_user("zoe", "pw")
    assert not result.ok and result.reason == "directory unavailable"


async def test_ldap_user_when_ldap_is_switched_off(seeded):
    async with seeded() as db:
        db.add(User(username="gina", source=UserSource.LDAP, password_hash=None))
        await db.commit()
    result = await authenticate_user("gina", "pw")
    assert not result.ok and result.reason == "directory disabled"


async def test_lookup_user(seeded):
    info = await lookup_user("ALICE")
    assert info is not None and info.group_name == "staff" and info.enabled
    assert await lookup_user("nobody") is None
