"""
Tests for the RADIUS attribute parsers and PAP password helper.

These are pure-function tests — no DB, no socket — so they run on every PR
in <100 ms and exercise the corners of the historical `lstrip("0x")` bug
and the RFC 2865 §5.2 PAP encoding.
"""
from __future__ import annotations

import hashlib

import pytest

from naco.radius.server import (
    _decode_pap_password,
    _is_mac_like,
    parse_vlan_attr,
)

# ---------------------------------------------------------------------------
# parse_vlan_attr
# ---------------------------------------------------------------------------

class TestParseVlanAttr:
    def test_none_returns_none(self):
        assert parse_vlan_attr(None) is None

    def test_empty_returns_none(self):
        assert parse_vlan_attr("") is None
        assert parse_vlan_attr(b"") is None

    @pytest.mark.parametrize("raw,expected", [
        ("42",       42),
        (b"42",      42),
        ("0x2a",     42),
        ("0X2A",     42),
        (b"0x2a",    42),
        ("4094",     4094),
        ("1",        1),
    ])
    def test_valid_values(self, raw, expected):
        assert parse_vlan_attr(raw) == expected

    @pytest.mark.parametrize("raw", [
        "not-a-vlan", "0x", "0xZZ", "abc", "0x12g4",
    ])
    def test_invalid_returns_none(self, raw):
        assert parse_vlan_attr(raw) is None

    def test_int_passthrough(self):
        assert parse_vlan_attr(100) == 100

    def test_int_out_of_range(self):
        assert parse_vlan_attr(0) is None
        assert parse_vlan_attr(4095) is None
        assert parse_vlan_attr(-1) is None

    def test_legacy_lstrip_bug_does_not_regress(self):
        """`str(val).lstrip("0x")` would turn "x10" into "1" — make sure we don't.

        With the old implementation `"x10".lstrip("0x")` → `"1"` because
        `lstrip` removes a *set of characters*, not a prefix. The new parser
        rejects "x10" outright.
        """
        assert parse_vlan_attr("x10") is None
        # And "0x10" must parse as hex 16, not decimal 10.
        assert parse_vlan_attr("0x10") == 16


# ---------------------------------------------------------------------------
# _is_mac_like
# ---------------------------------------------------------------------------

class TestIsMacLike:
    @pytest.mark.parametrize("s", [
        "aabbccddeeff",
        "AA:BB:CC:DD:EE:FF",
        "aa-bb-cc-dd-ee-ff",
        "aabb.ccdd.eeff",
        "AA.BB.CC.DD.EE.FF",
    ])
    def test_valid(self, s):
        assert _is_mac_like(s) is True

    @pytest.mark.parametrize("s", [
        "", "alice", "00:11:22:33", "g0:00:00:00:00:00", "aabbccddee",
    ])
    def test_invalid(self, s):
        assert _is_mac_like(s) is False


# ---------------------------------------------------------------------------
# _decode_pap_password — RFC 2865 §5.2
# ---------------------------------------------------------------------------

def _encode_pap(password: str, secret: bytes, authenticator: bytes) -> bytes:
    """Reference PAP encoder — same algorithm as the decoder, reversed."""
    pw = password.encode().ljust(((len(password) + 15) // 16) * 16 or 16, b"\x00")
    result = bytearray()
    prev = authenticator
    for i in range(0, len(pw), 16):
        block = pw[i:i + 16]
        digest = hashlib.md5(secret + prev).digest()
        cipher = bytes(a ^ b for a, b in zip(digest, block))
        result += cipher
        prev = cipher
    return bytes(result)


class TestPapDecoder:
    def test_roundtrip_short(self):
        secret = b"testing123"
        auth   = bytes(range(16))
        cipher = _encode_pap("hunter2", secret, auth)
        assert _decode_pap_password(cipher, secret, auth) == "hunter2"

    def test_roundtrip_exact_block(self):
        secret = b"sekrit"
        auth   = b"\x01" * 16
        plain  = "X" * 16
        cipher = _encode_pap(plain, secret, auth)
        assert _decode_pap_password(cipher, secret, auth) == plain

    def test_roundtrip_two_blocks(self):
        secret = b"sekrit"
        auth   = b"\x42" * 16
        plain  = "A" * 17
        cipher = _encode_pap(plain, secret, auth)
        assert _decode_pap_password(cipher, secret, auth) == plain

    def test_wrong_secret_yields_garbage(self):
        secret = b"good"
        auth   = b"\x00" * 16
        cipher = _encode_pap("Secret1234", secret, auth)
        decoded = _decode_pap_password(cipher, b"bad-secret", auth)
        assert decoded != "Secret1234"


# ---------------------------------------------------------------------------
# _acct_octets — RFC 2869 Gigawords rollover
# ---------------------------------------------------------------------------

class _FakePkt(dict):
    def get(self, key, default=None):
        return dict.get(self, key, default)


class TestAcctOctets:
    def test_plain_octets(self):
        from naco.radius.server import _acct_octets
        pkt = _FakePkt({"Acct-Input-Octets": [123456]})
        assert _acct_octets(pkt, "Acct-Input-Octets", "Acct-Input-Gigawords") == 123456

    def test_gigawords_rollover(self):
        from naco.radius.server import _acct_octets
        pkt = _FakePkt({"Acct-Input-Octets": [100], "Acct-Input-Gigawords": [2]})
        assert _acct_octets(pkt, "Acct-Input-Octets", "Acct-Input-Gigawords") == (2 << 32) + 100

    def test_missing_attrs_zero(self):
        from naco.radius.server import _acct_octets
        assert _acct_octets(_FakePkt(), "Acct-Input-Octets", "Acct-Input-Gigawords") == 0

    def test_garbage_values_zero(self):
        from naco.radius.server import _acct_octets
        pkt = _FakePkt({"Acct-Input-Octets": ["not-a-number"], "Acct-Input-Gigawords": [None]})
        assert _acct_octets(pkt, "Acct-Input-Octets", "Acct-Input-Gigawords") == 0
