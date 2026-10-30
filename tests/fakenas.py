"""A tiny UDP NAS that answers RFC 5176 Disconnect-Requests (for tests)."""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import struct


def parse_attrs(packet: bytes) -> dict[int, list[bytes]]:
    out: dict[int, list[bytes]] = {}
    pos, length = 20, struct.unpack("!H", packet[2:4])[0]
    while pos < length:
        kind, alen = packet[pos], packet[pos + 1]
        out.setdefault(kind, []).append(packet[pos + 2:pos + alen])
        pos += alen
    return out


class FakeNas(asyncio.DatagramProtocol):
    def __init__(self, secret: str, reply_code: int = 41, *, silent: bool = False,
                 bad_auth: bool = False, wrong_id: bool = False, with_ma: bool = False) -> None:
        self.secret = secret.encode()
        self.reply_code, self.silent, self.bad_auth, self.wrong_id, self.with_ma = (
            reply_code, silent, bad_auth, wrong_id, with_ma)
        self.received: list[bytes] = []
        self.port = 0

    def connection_made(self, transport):
        self.transport = transport
        self.port = transport.get_extra_info("sockname")[1]

    def datagram_received(self, data, addr):
        self.received.append(data)
        if self.silent:
            return
        ident = (data[1] + 1) % 256 if self.wrong_id else data[1]
        attrs = b"\x50\x12" + bytes(16) if self.with_ma else b""
        header = struct.pack("!BBH", self.reply_code, ident, 20 + len(attrs))
        if self.with_ma:
            ma = hmac.new(self.secret, header + data[4:20] + attrs, hashlib.md5).digest()
            attrs = b"\x50\x12" + ma
        auth = hashlib.md5(header + data[4:20] + attrs + self.secret).digest()
        if self.bad_auth:
            auth = bytes(16)
        self.transport.sendto(header + auth + attrs, addr)


async def start_fake_nas(host: str = "127.0.0.1", **kw) -> tuple[FakeNas, asyncio.DatagramTransport]:
    loop = asyncio.get_running_loop()
    transport, proto = await loop.create_datagram_endpoint(lambda: FakeNas(**kw), local_addr=(host, 0))
    return proto, transport
