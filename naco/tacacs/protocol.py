"""TACACS+ wire format (RFC 8907): header, body obfuscation, packet bodies.

Pure functions only — no I/O — so every bound and length check is unit-tested.
Every parser validates declared lengths against the actual body and raises
``ProtocolError`` instead of reading past the end.
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

MAJOR_VERSION = 0xC
MINOR_DEFAULT, MINOR_ONE = 0x0, 0x1
HEADER_LEN = 12
MAX_BODY_LEN = 64 * 1024

AUTHEN, AUTHOR, ACCT = 0x01, 0x02, 0x03
FLAG_UNENCRYPTED, FLAG_SINGLE_CONNECT = 0x01, 0x04

# authentication
ACTION_LOGIN, ACTION_CHPASS, ACTION_SENDAUTH = 0x01, 0x02, 0x04
TYPE_ASCII, TYPE_PAP, TYPE_CHAP, TYPE_MSCHAP, TYPE_MSCHAPV2 = 0x01, 0x02, 0x03, 0x05, 0x06
SERVICE_NONE, SERVICE_LOGIN, SERVICE_ENABLE = 0x00, 0x01, 0x02
STATUS_PASS, STATUS_FAIL, STATUS_GETDATA, STATUS_GETUSER, STATUS_GETPASS = 0x01, 0x02, 0x03, 0x04, 0x05
STATUS_RESTART, STATUS_ERROR = 0x06, 0x07
REPLY_FLAG_NOECHO = 0x01
CONTINUE_FLAG_ABORT = 0x01

# authorization
AUTHOR_PASS_ADD, AUTHOR_PASS_REPL, AUTHOR_FAIL, AUTHOR_ERROR = 0x01, 0x02, 0x10, 0x11

# accounting
ACCT_FLAG_START, ACCT_FLAG_STOP, ACCT_FLAG_WATCHDOG = 0x02, 0x04, 0x08
ACCT_SUCCESS, ACCT_ERROR = 0x01, 0x02


class ProtocolError(ValueError):
    """Malformed or unsupported packet — the connection is closed."""


# ── obfuscation (§4.5) ─────────────────────────────────────────────────────

def _pad(key: bytes, session_id: int, version: int, seq_no: int, length: int) -> bytes:
    # MD5_1 = MD5{session_id, key, version, seq_no}
    # MD5_n = MD5{session_id, key, version, seq_no, MD5_n-1}
    seed = struct.pack("!I", session_id) + key + bytes([version, seq_no])
    blocks, last = [], b""
    for _ in range(-(-length // 16)):
        last = hashlib.md5(seed + last).digest()
        blocks.append(last)
    return b"".join(blocks)[:length]


def crypt(body: bytes, key: bytes, session_id: int, version: int, seq_no: int) -> bytes:
    """XOR with the MD5 pseudo-pad — the same operation obfuscates and restores."""
    if not body:
        return body
    pad = _pad(key, session_id, version, seq_no, len(body))
    return (int.from_bytes(body, "big") ^ int.from_bytes(pad, "big")).to_bytes(len(body), "big")


# ── header ─────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Header:
    version: int
    type: int
    seq_no: int
    flags: int
    session_id: int
    length: int

    @property
    def minor(self) -> int:
        return self.version & 0x0F

    @classmethod
    def decode(cls, raw: bytes) -> Header:
        if len(raw) != HEADER_LEN:
            raise ProtocolError("short header")
        version, kind, seq_no, flags, session_id, length = struct.unpack("!BBBBII", raw)
        if version >> 4 != MAJOR_VERSION or version & 0x0F not in (MINOR_DEFAULT, MINOR_ONE):
            raise ProtocolError(f"unsupported version 0x{version:02x}")
        if kind not in (AUTHEN, AUTHOR, ACCT):
            raise ProtocolError(f"unknown packet type {kind}")
        if length > MAX_BODY_LEN:
            raise ProtocolError(f"body too large ({length} bytes)")
        if seq_no == 0xFF:  # the reply would need 256; RFC 8907 §4.1: sequence numbers never wrap
            raise ProtocolError("sequence number exhausted")
        return cls(version, kind, seq_no, flags, session_id, length)

    def encode(self) -> bytes:
        return struct.pack("!BBBBII", self.version, self.type, self.seq_no, self.flags, self.session_id, self.length)


def packet(request: Header, body: bytes, key: bytes) -> bytes:
    """A reply to ``request``: same session and version, next sequence number."""
    flags = request.flags & FLAG_SINGLE_CONNECT
    header = Header(request.version, request.type, request.seq_no + 1, flags, request.session_id, len(body))
    return header.encode() + crypt(body, key, header.session_id, header.version, header.seq_no)


# ── bodies ─────────────────────────────────────────────────────────────────

class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data, self.pos = data, 0

    def take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise ProtocolError("declared lengths exceed the body")
        chunk = self.data[self.pos:self.pos + n]
        self.pos += n
        return chunk

    def unpack(self, fmt: str) -> tuple[int, ...]:
        return struct.unpack(fmt, self.take(struct.calcsize(fmt)))

    def done(self) -> None:
        if self.pos != len(self.data):
            raise ProtocolError("trailing bytes after the body")


def _text(raw: bytes) -> str:
    return raw.decode("utf-8", errors="replace")


@dataclass(frozen=True)
class AuthenStart:
    action: int
    priv_lvl: int
    authen_type: int
    authen_service: int
    user: str
    port: str
    rem_addr: str
    data: bytes

    @classmethod
    def decode(cls, body: bytes) -> AuthenStart:
        r = _Reader(body)
        action, priv, kind, service, ulen, plen, rlen, dlen = r.unpack("!8B")
        start = cls(action, priv, kind, service, _text(r.take(ulen)), _text(r.take(plen)),
                    _text(r.take(rlen)), r.take(dlen))
        r.done()
        if priv > 15:
            raise ProtocolError("privilege level above 15")
        return start


@dataclass(frozen=True)
class AuthenContinue:
    user_msg: str
    data: bytes
    abort: bool

    @classmethod
    def decode(cls, body: bytes) -> AuthenContinue:
        r = _Reader(body)
        mlen, dlen, flags = r.unpack("!HHB")
        cont = cls(_text(r.take(mlen)), r.take(dlen), bool(flags & CONTINUE_FLAG_ABORT))
        r.done()
        return cont


@dataclass(frozen=True)
class Request:
    """Authorization REQUEST and accounting REQUEST share this layout."""
    flags: int  # accounting only (0 for authorization)
    authen_method: int
    priv_lvl: int
    authen_type: int
    authen_service: int
    user: str
    port: str
    rem_addr: str
    args: list[str]

    @classmethod
    def decode(cls, body: bytes, *, accounting: bool) -> Request:
        r = _Reader(body)
        flags = r.unpack("!B")[0] if accounting else 0
        method, priv, kind, service, ulen, plen, rlen, count = r.unpack("!8B")
        lengths: tuple[int, ...] = r.unpack(f"!{count}B") if count else ()
        user, port, rem = _text(r.take(ulen)), _text(r.take(plen)), _text(r.take(rlen))
        args = [_text(r.take(n)) for n in lengths]
        r.done()
        if priv > 15:
            raise ProtocolError("privilege level above 15")
        return cls(flags, method, priv, kind, service, user, port, rem, args)


def _str(value: str, limit: int) -> bytes:
    return value.encode()[:limit]


def authen_reply(status: int, server_msg: str = "", *, noecho: bool = False, data: bytes = b"") -> bytes:
    msg = _str(server_msg, 0xFFFF)
    return struct.pack("!BBHH", status, REPLY_FLAG_NOECHO if noecho else 0, len(msg), len(data)) + msg + data


def author_reply(status: int, args: list[str] | None = None, server_msg: str = "") -> bytes:
    encoded = [_str(a, 255) for a in args or []]
    msg = _str(server_msg, 0xFFFF)
    head = struct.pack("!BBHH", status, len(encoded), len(msg), 0) + bytes(len(a) for a in encoded)
    return head + msg + b"".join(encoded)


def acct_reply(status: int, server_msg: str = "") -> bytes:
    msg = _str(server_msg, 0xFFFF)
    return struct.pack("!HHB", len(msg), 0, status) + msg


# ── client-side encoders (used by tests and nacoctl probes) ────────────────

def authen_start(action: int, priv_lvl: int, authen_type: int, service: int, user: str,
                 port: str = "", rem_addr: str = "", data: bytes = b"") -> bytes:
    u, p, a = user.encode(), port.encode(), rem_addr.encode()
    return struct.pack("!8B", action, priv_lvl, authen_type, service, len(u), len(p), len(a), len(data)) + u + p + a + data


def authen_continue(data: bytes, user_msg: str = "", abort: bool = False) -> bytes:
    m = user_msg.encode()
    return struct.pack("!HHB", len(m), len(data), CONTINUE_FLAG_ABORT if abort else 0) + m + data


def request(args: list[str], user: str, *, priv_lvl: int = 1, accounting_flags: int | None = None,
            port: str = "tty1", rem_addr: str = "", authen_type: int = TYPE_ASCII,
            service: int = SERVICE_LOGIN, method: int = 0x06) -> bytes:
    u, p, a = user.encode(), port.encode(), rem_addr.encode()
    encoded = [x.encode() for x in args]
    head = b"" if accounting_flags is None else bytes([accounting_flags])
    head += struct.pack("!8B", method, priv_lvl, authen_type, service, len(u), len(p), len(a), len(encoded))
    return head + bytes(len(x) for x in encoded) + u + p + a + b"".join(encoded)
