import pytest
from ldap3 import MOCK_SYNC, Connection, Server
from ldap3.core.exceptions import LDAPSocketOpenError

from naco.auth.ldap import LdapDirectory, LdapError, map_group
from naco.config import ConfigError, LdapConfig, load_config

BASE = "dc=ex,dc=com"
SVC = "cn=svc,dc=ex,dc=com"
ALICE = "cn=Alice,ou=users,dc=ex,dc=com"
STAFF = "CN=Staff,OU=Groups,DC=ex,DC=com"
ADMINS = "CN=Admins,OU=Groups,DC=ex,DC=com"


@pytest.fixture
def server():
    srv = Server("fake")
    seed = Connection(srv, client_strategy=MOCK_SYNC)
    seed.strategy.add_entry(SVC, {"userPassword": "svcpw", "objectClass": "person"})
    seed.strategy.add_entry(ALICE, {
        "userPassword": "alicepw", "sAMAccountName": "alice", "objectClass": "person",
        "memberOf": [STAFF, ADMINS], "mail": "alice@ex.com", "displayName": "Alice Doe",
    })
    seed.strategy.add_entry("cn=Twin1,dc=ex,dc=com", {"userPassword": "x", "sAMAccountName": "twin",
                                                      "objectClass": "person"})
    seed.strategy.add_entry("cn=Twin2,dc=ex,dc=com", {"userPassword": "x", "sAMAccountName": "twin",
                                                      "objectClass": "person"})
    return srv


def cfg(**kw):
    base = {"enabled": True, "servers": ["ldaps://dc.ex.com"], "bind_dn": SVC, "base_dn": BASE}
    base.update(kw)
    return LdapConfig(**base)


def directory(server, bind_password="svcpw", **kw):
    def connect(user, password):
        conn = Connection(server, user=user, password=password, client_strategy=MOCK_SYNC)
        conn.open()
        return conn
    return LdapDirectory(cfg(**kw), bind_password, connect=connect)


def test_valid_credentials(server):
    user = directory(server).authenticate("alice", "alicepw")
    assert user is not None
    assert user.dn == ALICE
    assert user.email == "alice@ex.com"
    assert user.full_name == "Alice Doe"
    assert set(user.group_dns) == {STAFF, ADMINS}


def test_wrong_password(server):
    assert directory(server).authenticate("alice", "nope") is None


def test_empty_password_never_binds(server):
    assert directory(server).authenticate("alice", "") is None


def test_unknown_user(server):
    assert directory(server).authenticate("mallory", "x") is None


def test_ambiguous_match_is_refused(server):
    assert directory(server).authenticate("twin", "x") is None


def test_filter_injection_is_escaped(server):
    assert directory(server).authenticate("*", "alicepw") is None
    assert directory(server).authenticate("alice)(sAMAccountName=*", "alicepw") is None


def test_bad_service_password_is_a_directory_error(server):
    with pytest.raises(LdapError, match="service account"):
        directory(server, bind_password="wrong").authenticate("alice", "alicepw")


def test_unreachable_directory_is_a_directory_error():
    def connect(user, password):
        raise LDAPSocketOpenError("unreachable")
    with pytest.raises(LdapError):
        LdapDirectory(cfg(), "svcpw", connect=connect).authenticate("alice", "alicepw")


def test_map_group_uses_configured_order():
    c = cfg(group_map=[{"ldap_group": ADMINS.lower(), "group": "admins"},
                       {"ldap_group": STAFF, "group": "staff"}])
    assert map_group(c, [STAFF, ADMINS]) == "admins"
    assert map_group(c, [STAFF]) == "staff"
    assert map_group(c, []) is None


@pytest.mark.parametrize("yaml_text,msg", [
    ("ldap:\n  enabled: true\n  servers: ['ldap://dc']\n", "clear text"),
    ("ldap:\n  enabled: true\n  servers: ['dc.example.com']\n", "ldap:// or ldaps://"),
    ("ldap:\n  enabled: true\n  servers: ['ldaps://dc']\n  start_tls: true\n", "start_tls"),
])
def test_insecure_transport_is_refused(tmp_path, yaml_text, msg):
    p = tmp_path / "c.yaml"
    p.write_text(yaml_text)
    with pytest.raises(ConfigError, match=msg):
        load_config(str(p), env={})


@pytest.mark.parametrize("yaml_text", [
    "ldap:\n  enabled: true\n  servers: ['ldap://dc']\n  start_tls: true\n",
    "ldap:\n  enabled: true\n  servers: ['ldap://dc']\n  allow_insecure: true\n",
    "ldap:\n  enabled: true\n  servers: ['ldaps://dc1', 'ldaps://dc2:3269']\n",
])
def test_secure_transport_is_accepted(tmp_path, yaml_text):
    p = tmp_path / "c.yaml"
    p.write_text(yaml_text)
    assert load_config(str(p), env={}).ldap.enabled
