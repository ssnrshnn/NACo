import hashlib
import hmac
import socket
import struct

import pytest

from naco.radius.coa import CoaTarget, Outcome, SessionIds, build_disconnect, disconnect, verify_response
from naco.radius.vendors import VENDORS
from tests.fakenas import parse_attrs, start_fake_nas

SECRET = "nas-shared-secret"


def test_packet_authenticators_follow_rfc5176():
    pkt = build_disconnect(SECRET.encode(), 7, SessionIds("S1", "alice", "AA-BB-CC-DD-EE-FF"),
                           event_time=1_700_000_000)
    assert pkt[0] == 40 and pkt[1] == 7
    attrs = parse_attrs(pkt)
    assert attrs[44] == [b"S1"] and attrs[1] == [b"alice"] and attrs[31] == [b"AA-BB-CC-DD-EE-FF"]
    assert struct.unpack("!I", attrs[55][0])[0] == 1_700_000_000
    # Request Authenticator = MD5(packet with zero authenticator + secret)
    zero_auth = pkt[:4] + bytes(16) + pkt[20:]
    assert hashlib.md5(zero_auth + SECRET.encode()).digest() == pkt[4:20]
    # Message-Authenticator = HMAC-MD5 over packet with zero authenticator and zero MA
    ma = attrs[80][0]
    idx = pkt.index(b"\x50\x12") + 2
    zeroed = bytearray(zero_auth)
    zeroed[idx:idx + 16] = bytes(16)
    assert hmac.new(SECRET.encode(), bytes(zeroed), hashlib.md5).digest() == ma


IDS = SessionIds(acct_session_id="S1", user_name="alice", calling_station_id="AA-BB-CC-DD-EE-FF",
                 nas_ip_address="10.0.0.2", nas_identifier="sw2", audit_session_id="0A000002000000F1")
VSA = 26


@pytest.mark.parametrize("vendor,sent", [
    ("standard", {44, 1, 31, 4, 32, 55, 80}),
    ("cisco", {44, 31, VSA, 55, 80}),
    ("meraki", {31, 4, VSA, 80}),
    ("aruba", {44, 1, 31, 4, 32, 80}),
    ("juniper", {44, 1, 31, 4, 80}),
    ("fortinet", {1, 31, 4, 55, 80}),
    ("extreme", {31, 4, 80}),
    ("ruckus-icx", {31, 4}),
])
def test_each_vendor_gets_the_attributes_it_accepts(vendor, sent):
    attrs = parse_attrs(build_disconnect(SECRET.encode(), 1, IDS, VENDORS[vendor]))
    assert set(attrs) == sent
    if 4 in sent:
        assert attrs[4] == [bytes([10, 0, 0, 2])]
    if VSA in sent:  # Cisco-AVPair audit-session-id
        assert attrs[VSA] == [struct.pack("!IBB", 9, 1, 2 + 33) + b"audit-session-id=0A000002000000F1"]


def test_values_the_nas_did_not_report_are_left_out():
    attrs = parse_attrs(build_disconnect(SECRET.encode(), 1, SessionIds(calling_station_id="AA-BB-CC-DD-EE-FF"),
                                         VENDORS["standard"]))
    assert set(attrs) == {31, 55, 80}


def test_without_message_authenticator_the_request_authenticator_still_signs():
    pkt = build_disconnect(SECRET.encode(), 3, IDS, VENDORS["ruckus-icx"])
    zero_auth = pkt[:4] + bytes(16) + pkt[20:]
    assert hashlib.md5(zero_auth + SECRET.encode()).digest() == pkt[4:20]


def test_verify_response_rejects_garbage():
    req = build_disconnect(b"s", 1, SessionIds("x"))
    assert not verify_response(req, b"short", b"s")
    assert not verify_response(req, b"\x29\x02\x00\x14" + bytes(16), b"s")  # wrong id, bad auth


async def target_for(nas):
    return CoaTarget("127.0.0.1", nas.port, SECRET)


async def test_ack():
    nas, transport = await start_fake_nas(secret=SECRET)
    try:
        result = await disconnect(await target_for(nas), SessionIds("S1", "alice"), timeout=1, retries=1)
        assert result.outcome is Outcome.ACK and result.ok
        assert parse_attrs(nas.received[0])[44] == [b"S1"]
    finally:
        transport.close()


async def test_ack_with_message_authenticator():
    nas, transport = await start_fake_nas(secret=SECRET, with_ma=True)
    try:
        assert (await disconnect(await target_for(nas), SessionIds("S1"), timeout=1, retries=1)).ok
    finally:
        transport.close()


async def test_nak():
    nas, transport = await start_fake_nas(secret=SECRET, reply_code=42)
    try:
        assert (await disconnect(await target_for(nas), SessionIds("S1"), timeout=1, retries=1)).outcome is Outcome.NAK
    finally:
        transport.close()


@pytest.mark.parametrize("kw", [{"silent": True}, {"bad_auth": True}, {"wrong_id": True}])
async def test_invalid_or_missing_answers_time_out_after_identical_retransmits(kw):
    nas, transport = await start_fake_nas(secret=SECRET, **kw)
    try:
        result = await disconnect(await target_for(nas), SessionIds("S1"), timeout=0.1, retries=3)
        assert result.outcome is Outcome.TIMEOUT
        assert len(nas.received) == 3
        assert len(set(nas.received)) == 1
    finally:
        transport.close()


async def test_wrong_secret_is_not_accepted():
    nas, transport = await start_fake_nas(secret="other-secret")
    try:
        result = await disconnect(await target_for(nas), SessionIds("S1"), timeout=0.1, retries=1)
        assert result.outcome is Outcome.TIMEOUT
    finally:
        transport.close()


async def test_ipv6():
    try:
        socket.socket(socket.AF_INET6, socket.SOCK_DGRAM).bind(("::1", 0))
    except OSError:
        pytest.skip("no IPv6 loopback")
    nas, transport = await start_fake_nas(host="::1", secret=SECRET)
    try:
        assert (await disconnect(CoaTarget("::1", nas.port, SECRET), SessionIds("S6"), timeout=1, retries=1)).ok
    finally:
        transport.close()


async def test_invalid_address():
    assert (await disconnect(CoaTarget("nope", 3799, SECRET), "S1")).outcome is Outcome.ERROR
