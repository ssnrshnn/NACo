"""RFC 5176 Disconnect-Request client.

The session is identified exactly as the NAS reported it in accounting
(Acct-Session-Id, plus User-Name / Calling-Station-Id when known), so the
NAS's own matching rules agree. Requests carry Event-Timestamp and a
Message-Authenticator (RFC 3579 / BlastRADIUS hardening) and are
retransmitted unchanged on timeout. A response is accepted only from the
NAS address, with the request's identifier and a valid Response
Authenticator (and Message-Authenticator, when present).
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import logging
import os
import socket
import struct
import time
from dataclasses import dataclass
from enum import StrEnum

from naco.core.metrics import REGISTRY

log = logging.getLogger(__name__)

DISCONNECT_REQUEST = 40
DISCONNECT_ACK = 41
DISCONNECT_NAK = 42

ATTR_USER_NAME = 1
ATTR_CALLING_STATION_ID = 31
ATTR_ACCT_SESSION_ID = 44
ATTR_EVENT_TIMESTAMP = 55
ATTR_MESSAGE_AUTHENTICATOR = 80

COA_REQUESTS = REGISTRY.counter("naco_coa_requests_total", "Disconnect-Requests sent", ["outcome"])


class Outcome(StrEnum):
    ACK = "ack"
    NAK = "nak"
    TIMEOUT = "timeout"
    ERROR = "error"


@dataclass(frozen=True)
class CoaTarget:
    ip: str
    port: int
    secret: str


@dataclass(frozen=True)
class CoaResult:
    outcome: Outcome
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.outcome is Outcome.ACK


def _attr(kind: int, value: bytes) -> bytes:
    if len(value) > 253:
        value = value[:253]
    return struct.pack("!BB", kind, len(value) + 2) + value


def build_disconnect(secret: bytes, identifier: int, *, acct_session_id: str, username: str = "",
                     calling_station_id: str = "", event_time: int | None = None) -> bytes:
    attrs = _attr(ATTR_ACCT_SESSION_ID, acct_session_id.encode())
    if username:
        attrs += _attr(ATTR_USER_NAME, username.encode())
    if calling_station_id:
        attrs += _attr(ATTR_CALLING_STATION_ID, calling_station_id.encode())
    attrs += _attr(ATTR_EVENT_TIMESTAMP, struct.pack("!I", int(time.time() if event_time is None else event_time)))
    ma_offset = 20 + len(attrs) + 2
    attrs += _attr(ATTR_MESSAGE_AUTHENTICATOR, bytes(16))
    header = struct.pack("!BBH", DISCONNECT_REQUEST, identifier, 20 + len(attrs))

    # RFC 5176 §3.5: Message-Authenticator over the packet with a zero
    # Request Authenticator, then the Request Authenticator over the result.
    zeroed = header + bytes(16) + attrs
    mac = hmac.new(secret, zeroed, hashlib.md5).digest()
    with_ma = bytearray(zeroed)
    with_ma[ma_offset:ma_offset + 16] = mac
    authenticator = hashlib.md5(bytes(with_ma) + secret).digest()
    with_ma[4:20] = authenticator
    return bytes(with_ma)


def _find_attr(packet: bytes, kind: int, length: int) -> int | None:
    """Offset of the first attribute ``kind`` (value start), or None."""
    pos = 20
    while pos + 2 <= length:
        a_type, a_len = packet[pos], packet[pos + 1]
        if a_len < 2 or pos + a_len > length:
            return None
        if a_type == kind:
            return pos + 2
        pos += a_len
    return None


def verify_response(request: bytes, response: bytes, secret: bytes) -> bool:
    if len(response) < 20 or len(request) < 20:
        return False
    length = struct.unpack("!H", response[2:4])[0]
    if length < 20 or length > len(response) or response[1] != request[1]:
        return False
    expected = hashlib.md5(response[:4] + request[4:20] + response[20:length] + secret).digest()
    if not hmac.compare_digest(expected, response[4:20]):
        return False
    ma = _find_attr(response, ATTR_MESSAGE_AUTHENTICATOR, length)
    if ma is not None:
        if response[ma - 1] != 18:
            return False
        check = bytearray(response[:length])
        check[4:20] = request[4:20]
        check[ma:ma + 16] = bytes(16)
        if not hmac.compare_digest(hmac.new(secret, bytes(check), hashlib.md5).digest(), response[ma:ma + 16]):
            return False
    return True


class _Exchange(asyncio.DatagramProtocol):
    def __init__(self, request: bytes, secret: bytes, peer: tuple[str, int]) -> None:
        self.request, self.secret, self.peer = request, secret, peer
        self.answer: asyncio.Future[bytes] = asyncio.get_running_loop().create_future()

    def datagram_received(self, data: bytes, addr: tuple[str | int, ...]) -> None:
        if (str(addr[0]), int(addr[1])) != self.peer or self.answer.done():
            return
        if verify_response(self.request, data, self.secret):
            self.answer.set_result(data)
        else:
            log.warning("CoA: ignoring a response from %s with a bad authenticator", addr[0])

    def error_received(self, exc: Exception) -> None:
        if not self.answer.done():
            self.answer.set_exception(exc)


async def disconnect(target: CoaTarget, acct_session_id: str, *, username: str = "",
                     calling_station_id: str = "", timeout: float = 2.0, retries: int = 3) -> CoaResult:
    try:
        ip = ipaddress.ip_address(target.ip)
    except ValueError:
        return _count(CoaResult(Outcome.ERROR, f"invalid NAS address {target.ip!r}"))
    secret = target.secret.encode()
    packet = build_disconnect(secret, os.urandom(1)[0], acct_session_id=acct_session_id,
                              username=username, calling_station_id=calling_station_id)
    peer = (str(ip), target.port)
    loop = asyncio.get_running_loop()
    family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
    try:
        transport, proto = await loop.create_datagram_endpoint(
            lambda: _Exchange(packet, secret, peer), family=family, remote_addr=peer)
    except OSError as exc:
        return _count(CoaResult(Outcome.ERROR, str(exc)))
    try:
        for _ in range(retries):
            transport.sendto(packet)
            try:
                answer = await asyncio.wait_for(asyncio.shield(proto.answer), timeout)
            except TimeoutError:
                continue
            except OSError as exc:
                return _count(CoaResult(Outcome.ERROR, str(exc)))
            if answer[0] == DISCONNECT_ACK:
                return _count(CoaResult(Outcome.ACK))
            return _count(CoaResult(Outcome.NAK, f"NAS answered code {answer[0]}"))
        return _count(CoaResult(Outcome.TIMEOUT, f"no answer from {target.ip}:{target.port}"))
    finally:
        transport.close()


def _count(result: CoaResult) -> CoaResult:
    COA_REQUESTS.inc(outcome=result.outcome.value)
    return result
