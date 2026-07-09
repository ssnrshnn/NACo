"""
Async RADIUS server — event-loop-native UDP transport.

The server must bind via ``asyncio`` datagram endpoints (no blocking pyrad
``Run()`` thread), reply on the wire, process independent requests
concurrently, and drop traffic from unknown NAS clients before decoding.
"""
from __future__ import annotations

import asyncio
import time

import pyrad.packet
import pytest

from naco.db.models import AuthResult
from naco.radius.server import NACoRadiusServer

SECRET = b"testing123"


class _UdpClient(asyncio.DatagramProtocol):
    """Minimal test client capturing every datagram it receives."""

    def __init__(self) -> None:
        self.transport: asyncio.DatagramTransport | None = None
        self.replies: asyncio.Queue[bytes] = asyncio.Queue()

    def connection_made(self, transport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr) -> None:
        self.replies.put_nowait(data)


async def _udp_client(remote: tuple[str, int]) -> _UdpClient:
    loop = asyncio.get_running_loop()
    _transport, proto = await loop.create_datagram_endpoint(
        _UdpClient, remote_addr=remote,
    )
    return proto


def _mab_request(server: NACoRadiusServer, mac: str, pkt_id: int = 7) -> pyrad.packet.AuthPacket:
    """Valid MAB Access-Request: User-Name == User-Password == MAC, with a
    correct Message-Authenticator (the test config requires one)."""
    pkt = pyrad.packet.AuthPacket(secret=SECRET, id=pkt_id, dict=server.dict)
    pkt["User-Name"] = mac
    pkt["User-Password"] = pkt.PwCrypt(mac)
    pkt.add_message_authenticator()
    return pkt


async def _noop_log_auth(*args, **kwargs) -> None:
    return None


def _isolate_db(server: NACoRadiusServer, monkeypatch: pytest.MonkeyPatch) -> None:
    """Cut the server's DB touchpoints so transport tests stay hermetic.

    The module-level engine pools connections across event loops; a pooled
    aiosqlite connection created in one test's loop deadlocks the next
    test's DB call. Transport behaviour is the unit under test here.
    """
    async def _reject(mac: str):
        from naco.db.models import AuthResult
        return AuthResult.FAILURE, "isolated test"

    async def _noop_session(*args, **kwargs) -> None:
        return None

    monkeypatch.setattr(server, "_check_device_authorized", _reject)
    monkeypatch.setattr(server, "_log_auth", _noop_log_auth)
    monkeypatch.setattr(server, "_update_session", _noop_session)
    # Never let the packet-driven NAS reload touch the DB.
    monkeypatch.setattr(server, "_last_client_reload", float("inf"))


@pytest.mark.asyncio
async def test_mab_unknown_device_rejected_over_udp(monkeypatch):
    """End-to-end over loopback UDP: an unknown MAC gets an Access-Reject
    carrying the request's packet id."""
    server = NACoRadiusServer()
    _isolate_db(server, monkeypatch)
    await server.start(host="127.0.0.1", auth_port=0, acct_port=0)
    try:
        client = await _udp_client(server.auth_address)
        req = _mab_request(server, "aabbccddeeff", pkt_id=7)
        client.transport.sendto(req.RequestPacket())

        data = await asyncio.wait_for(client.replies.get(), timeout=5)
        reply = pyrad.packet.Packet(packet=data, secret=SECRET, dict=server.dict)
        assert reply.code == pyrad.packet.AccessReject
        assert reply.id == 7
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_concurrent_requests_processed_in_parallel(monkeypatch):
    """Five requests whose device lookup takes 0.4 s each must complete
    together in well under the 2 s a serialized handler would need."""
    server = NACoRadiusServer()
    _isolate_db(server, monkeypatch)

    async def _slow_check(mac: str) -> tuple[AuthResult, str]:
        await asyncio.sleep(0.4)
        return AuthResult.FAILURE, "slow test check"

    monkeypatch.setattr(server, "_check_device_authorized", _slow_check)
    await server.start(host="127.0.0.1", auth_port=0, acct_port=0)
    try:
        client = await _udp_client(server.auth_address)
        start = time.monotonic()
        for i in range(5):
            req = _mab_request(server, "aabbccddeeff", pkt_id=i + 1)
            client.transport.sendto(req.RequestPacket())

        for _ in range(5):
            await asyncio.wait_for(client.replies.get(), timeout=5)
        elapsed = time.monotonic() - start
        assert elapsed < 1.2, f"handlers appear serialized ({elapsed:.2f}s for 5 requests)"
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_accounting_start_gets_response_over_udp(monkeypatch):
    server = NACoRadiusServer()
    _isolate_db(server, monkeypatch)
    await server.start(host="127.0.0.1", auth_port=0, acct_port=0)
    try:
        client = await _udp_client(server.acct_address)
        pkt = pyrad.packet.AcctPacket(secret=SECRET, id=9, dict=server.dict)
        pkt["User-Name"] = "alice"
        pkt["Acct-Status-Type"] = "Start"
        pkt["Acct-Session-Id"] = "sess-1"
        client.transport.sendto(pkt.RequestPacket())

        data = await asyncio.wait_for(client.replies.get(), timeout=5)
        reply = pyrad.packet.Packet(packet=data, secret=SECRET, dict=server.dict)
        assert reply.code == pyrad.packet.AccountingResponse
        assert reply.id == 9
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_unknown_nas_datagram_dropped(monkeypatch):
    """Datagrams from an address with no configured secret must be dropped
    without any reply (never decoded, never answered)."""
    server = NACoRadiusServer()
    _isolate_db(server, monkeypatch)
    sent: list[tuple[bytes, tuple[str, int]]] = []

    class _Transport:
        def sendto(self, data: bytes, addr) -> None:
            sent.append((data, addr))

    req = _mab_request(server, "aabbccddeeff")
    await server._handle_auth_datagram(
        _Transport(), req.RequestPacket(), ("203.0.113.9", 1645)
    )
    assert sent == []


@pytest.mark.asyncio
async def test_malformed_datagram_dropped(monkeypatch):
    """Garbage bytes from a known NAS must be dropped without a reply and
    without raising."""
    server = NACoRadiusServer()
    _isolate_db(server, monkeypatch)
    sent: list[tuple[bytes, tuple[str, int]]] = []

    class _Transport:
        def sendto(self, data: bytes, addr) -> None:
            sent.append((data, addr))

    await server._handle_auth_datagram(_Transport(), b"\x01\x02trash", ("127.0.0.1", 1645))
    assert sent == []
