"""
Property-based robustness tests for the protocol parsers.

RADIUS and TACACS+ speak to whatever is on the network — these tests feed
adversarial inputs into every parsing entry point and assert the invariants
that keep the servers alive: *never* raise out of a handler, *never* reply
to undecodable garbage, and pure helpers stay total over their domain.
"""
from __future__ import annotations

import asyncio

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from naco.radius.server import (
    NACoRadiusServer,
    _acct_octets,
    _decode_pap_password,
    _is_mac_like,
    parse_vlan_attr,
)
from naco.tacacs.server import (
    TacacsHeader,
    _crypt,
    _parse_av_pairs,
)

_FUZZ = settings(
    max_examples=80,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)


# ---------------------------------------------------------------------------
# RADIUS — datagram handlers must never raise or answer garbage
# ---------------------------------------------------------------------------

class _RecordingTransport:
    def __init__(self) -> None:
        self.sent: list[tuple[bytes, tuple[str, int]]] = []

    def sendto(self, data: bytes, addr) -> None:
        self.sent.append((data, addr))


@pytest.fixture(scope="module")
def radius_server() -> NACoRadiusServer:
    server = NACoRadiusServer()
    # The rate-limited packet-driven NAS reload would hit the (absent) test
    # DB on the first datagram; pin the clock so it never fires during fuzz.
    server._last_client_reload = float("inf")
    return server


@_FUZZ
@given(data=st.binary(min_size=0, max_size=512))
def test_radius_auth_handler_survives_garbage(radius_server, data):
    """Arbitrary bytes from a *known* NAS: the handler must neither raise
    nor reply (undecodable input gets silence, not a reject)."""
    transport = _RecordingTransport()
    asyncio.run(
        radius_server._handle_auth_datagram(transport, data, ("127.0.0.1", 1645))
    )
    assert transport.sent == []


@_FUZZ
@given(data=st.binary(min_size=0, max_size=512))
def test_radius_acct_handler_survives_garbage(radius_server, data):
    transport = _RecordingTransport()
    asyncio.run(
        radius_server._handle_acct_datagram(transport, data, ("127.0.0.1", 1646))
    )
    assert transport.sent == []


@_FUZZ
@given(
    raw=st.one_of(
        st.none(),
        st.integers(min_value=-2**40, max_value=2**40),
        st.binary(max_size=32),
        st.text(max_size=32),
    )
)
def test_parse_vlan_attr_total_and_in_range(raw):
    """parse_vlan_attr never raises and only ever returns a valid VLAN ID."""
    vlan = parse_vlan_attr(raw)
    assert vlan is None or 1 <= vlan <= 4094


@_FUZZ
@given(
    encrypted=st.binary(max_size=256),
    secret=st.binary(min_size=1, max_size=64),
    authenticator=st.binary(min_size=16, max_size=16),
)
def test_decode_pap_password_never_raises(encrypted, secret, authenticator):
    out = _decode_pap_password(encrypted, secret, authenticator)
    assert isinstance(out, str)


@_FUZZ
@given(s=st.one_of(st.text(max_size=64), st.just("")))
def test_is_mac_like_total(s):
    assert _is_mac_like(s) in (True, False)


@_FUZZ
@given(
    octets=st.one_of(st.none(), st.integers(), st.text(max_size=8), st.binary(max_size=8)),
    giga=st.one_of(st.none(), st.integers(), st.text(max_size=8)),
)
def test_acct_octets_total(octets, giga):
    class _Pkt(dict):
        def get(self, key, default=None):
            return {"Acct-Input-Octets": [octets], "Acct-Input-Gigawords": [giga]}.get(
                key, default
            )

    value = _acct_octets(_Pkt(), "Acct-Input-Octets", "Acct-Input-Gigawords")
    assert isinstance(value, int)
    assert value >= 0 or isinstance(octets, int) or isinstance(giga, int)


# ---------------------------------------------------------------------------
# TACACS+ — header/body parsing helpers stay total
# ---------------------------------------------------------------------------

@_FUZZ
@given(raw=st.binary(min_size=12, max_size=12))
def test_tacacs_header_decode_encode_roundtrip(raw):
    """Any 12 bytes decode into a header whose re-encoding is byte-identical
    (the server reads exactly 12 bytes before calling decode)."""
    hdr = TacacsHeader.decode(raw)
    assert hdr.encode() == raw


@_FUZZ
@given(data=st.binary(max_size=512))
def test_tacacs_av_pairs_never_raise(data):
    pairs = _parse_av_pairs(data)
    assert isinstance(pairs, list)


@_FUZZ
@given(
    body=st.binary(max_size=256),
    key=st.binary(min_size=1, max_size=64),
    session_id=st.integers(min_value=0, max_value=2**32 - 1),
    seq_no=st.integers(min_value=0, max_value=255),
)
def test_tacacs_crypt_is_symmetric(body, key, session_id, seq_no):
    """The RFC 8907 §4.5 body obfuscation is an XOR stream — applying it
    twice must return the original body."""
    version = 0xC0
    once = _crypt(body, key, session_id, version, seq_no)
    twice = _crypt(once, key, session_id, version, seq_no)
    assert twice == body


@pytest.mark.parametrize("raw", ["99999", b"0xffff", "0", "-5", 0, 4095, "4095"])
def test_parse_vlan_attr_rejects_out_of_range(raw):
    """Text and int inputs alike must clamp to the valid VLAN range 1-4094."""
    assert parse_vlan_attr(raw) is None
