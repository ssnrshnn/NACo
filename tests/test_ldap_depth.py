"""
LDAP/AD depth — failover pools, nested groups, group mapping.

The wire protocol is ldap3's job; these tests pin NACo's logic around it:
which servers make up the failover pool, how the AD nested-group filter is
built, and how directory groups map to NACo groups.
"""
from __future__ import annotations

from naco.auth import ldap as naco_ldap
from naco.config import LdapConfig

# ---------------------------------------------------------------------------
# Server pool (failover)
# ---------------------------------------------------------------------------

def test_server_uris_single_legacy_field():
    cfg = LdapConfig(server="ldap://dc1.example.com")
    assert naco_ldap.server_uris(cfg) == ["ldap://dc1.example.com"]


def test_server_uris_prefers_servers_list():
    cfg = LdapConfig(
        server="ldap://legacy.example.com",
        servers=["ldap://dc1.example.com", "ldap://dc2.example.com"],
    )
    assert naco_ldap.server_uris(cfg) == [
        "ldap://dc1.example.com", "ldap://dc2.example.com",
    ]


def test_server_uris_skips_blanks():
    cfg = LdapConfig(servers=["ldap://dc1.example.com", "", "  "])
    assert naco_ldap.server_uris(cfg) == ["ldap://dc1.example.com"]


# ---------------------------------------------------------------------------
# Nested groups (AD LDAP_MATCHING_RULE_IN_CHAIN)
# ---------------------------------------------------------------------------

def test_nested_group_filter_escapes_dn():
    f = naco_ldap.nested_group_filter("CN=Alice (Admin),DC=example,DC=com")
    assert f.startswith("(member:1.2.840.113556.1.4.1941:=")
    # parentheses in the DN must be escaped, or the filter breaks
    assert "(Admin)" not in f
    assert "\\28Admin\\29" in f


# ---------------------------------------------------------------------------
# Group mapping
# ---------------------------------------------------------------------------

def test_map_groups_matches_dns_case_insensitively():
    cfg = LdapConfig(group_map={
        "CN=NetAdmins,OU=Groups,DC=example,DC=com": "admins",
        "CN=Staff,OU=Groups,DC=example,DC=com": "staff",
    })
    groups = naco_ldap.map_groups(cfg, [
        "cn=netadmins,ou=groups,dc=example,dc=com",
        "CN=Unmapped,OU=Groups,DC=example,DC=com",
    ])
    assert groups == ["admins"]


def test_map_groups_preserves_map_order_for_priority():
    """First entry in group_map wins provisioning priority — the returned
    list is ordered by the map, not by the directory's ordering."""
    cfg = LdapConfig(group_map={
        "CN=A,DC=x": "primary",
        "CN=B,DC=x": "secondary",
    })
    groups = naco_ldap.map_groups(cfg, ["CN=B,DC=x", "CN=A,DC=x"])
    assert groups == ["primary", "secondary"]


def test_map_groups_empty_inputs():
    assert naco_ldap.map_groups(LdapConfig(), []) == []
    assert naco_ldap.map_groups(LdapConfig(group_map={"CN=A": "a"}), []) == []
