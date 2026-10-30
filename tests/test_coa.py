import hashlib
import hmac
import socket
import struct

import pytest

from naco.radius.coa import CoaTarget, Outcome, build_disconnect, disconnect, verify_response
from tests.fakenas import parse_attrs, start_fake_nas

SECRET = "nas-shared-secret"


def test_packet_authenticators_follow_rfc5176():
    pkt = build_disconnect(SECRET.encode(), 7, acct_session_id="S1", username="alice",
                           calling_station_id="AA-BB-CC-DD-EE-FF", event_time=1_700_000_000)
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


def test_verify_response_rejects_garbage():
    req = build_disconnect(b"s", 1, acct_session_id="x")
    assert not verify_response(req, b"short", b"s")
    assert not verify_response(req, b"\x29\x02\x00\x14" + bytes(16), b"s")  # wrong id, bad auth


async def target_for(nas):
    return CoaTarget("127.0.0.1", nas.port, SECRET)


async def test_ack():
    nas, transport = await start_fake_nas(secret=SECRET)
    try:
        result = await disconnect(await target_for(nas), "S1", username="alice", timeout=1, retries=1)
        assert result.outcome is Outcome.ACK and result.ok
        assert parse_attrs(nas.received[0])[44] == [b"S1"]
    finally:
        transport.close()


async def test_ack_with_message_authenticator():
    nas, transport = await start_fake_nas(secret=SECRET, with_ma=True)
    try:
        assert (await disconnect(await target_for(nas), "S1", timeout=1, retries=1)).ok
    finally:
        transport.close()


async def test_nak():
    nas, transport = await start_fake_nas(secret=SECRET, reply_code=42)
    try:
        assert (await disconnect(await target_for(nas), "S1", timeout=1, retries=1)).outcome is Outcome.NAK
    finally:
        transport.close()


@pytest.mark.parametrize("kw", [{"silent": True}, {"bad_auth": True}, {"wrong_id": True}])
async def test_invalid_or_missing_answers_time_out_after_identical_retransmits(kw):
    nas, transport = await start_fake_nas(secret=SECRET, **kw)
    try:
        result = await disconnect(await target_for(nas), "S1", timeout=0.1, retries=3)
        assert result.outcome is Outcome.TIMEOUT
        assert len(nas.received) == 3
        assert len(set(nas.received)) == 1
    finally:
        transport.close()


async def test_wrong_secret_is_not_accepted():
    nas, transport = await start_fake_nas(secret="other-secret")
    try:
        result = await disconnect(await target_for(nas), "S1", timeout=0.1, retries=1)
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
        assert (await disconnect(CoaTarget("::1", nas.port, SECRET), "S6", timeout=1, retries=1)).ok
    finally:
        transport.close()


async def test_invalid_address():
    assert (await disconnect(CoaTarget("nope", 3799, SECRET), "S1")).outcome is Outcome.ERROR
