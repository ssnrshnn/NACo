"""TACACS+: wire format, authorization rules, and a live server checked with
an independent client implementation (``tacacs_plus``)."""
from __future__ import annotations

import asyncio
import hashlib
import struct

import pytest
from sqlalchemy import delete, select
from tacacs_plus.client import TACACSClient
from tacacs_plus.flags import (
    TAC_PLUS_ACCT_FLAG_START,
    TAC_PLUS_AUTHEN_TYPE_ASCII,
    TAC_PLUS_AUTHEN_TYPE_PAP,
)

from naco.config import TacacsConfig
from naco.core.passwords import hash_password_sync
from naco.db.models import (
    CommandAction,
    CommandRule,
    CommandSet,
    Group,
    TacacsClient,
    TacacsKind,
    TacacsLog,
    User,
)
from naco.tacacs import protocol as p
from naco.tacacs.authz import CompiledCommandSet, command_allowed, command_line, parse_args
from naco.tacacs.server import TacacsServer

KEY = "tacacs-shared-key-123"


# ── wire format ────────────────────────────────────────────────────────────

def reference_pad(key: bytes, session_id: int, version: int, seq_no: int, n: int) -> bytes:
    """RFC 8907 §4.5 written out literally."""
    pad, prev = b"", b""
    while len(pad) < n:
        prev = hashlib.md5(struct.pack("!I", session_id) + key + bytes([version, seq_no]) + prev).digest()
        pad += prev
    return pad[:n]


@pytest.mark.parametrize("n", [0, 1, 15, 16, 17, 100])
def test_crypt_matches_the_rfc_and_is_an_involution(n):
    body = bytes(range(n % 256))[:n] if n else b""
    body = (body * 3)[:n]
    out = p.crypt(body, b"k", 0x12345678, 0xC1, 1)
    assert out == bytes(a ^ b for a, b in zip(body, reference_pad(b"k", 0x12345678, 0xC1, 1, n), strict=True))
    assert p.crypt(out, b"k", 0x12345678, 0xC1, 1) == body


@pytest.mark.parametrize("raw,msg", [
    (b"\xc1\x01\x01\x00" + b"\x00" * 8, None),
    (b"\xb1\x01\x01\x00" + b"\x00" * 8, "version"),
    (b"\xc2\x01\x01\x00" + b"\x00" * 8, "version"),
    (b"\xc1\x09\x01\x00" + b"\x00" * 8, "type"),
    (b"\xc1\x01\x01\x00" + b"\x00" * 4 + struct.pack("!I", 70000), "too large"),
    (b"\xc1", "short"),
])
def test_header_validation(raw, msg):
    if msg is None:
        assert p.Header.decode(raw).type == p.AUTHEN
    else:
        with pytest.raises(p.ProtocolError, match=msg):
            p.Header.decode(raw)


def test_body_lengths_are_checked():
    good = p.authen_start(p.ACTION_LOGIN, 1, p.TYPE_PAP, p.SERVICE_LOGIN, "neo", data=b"pw")
    assert p.AuthenStart.decode(good).data == b"pw"
    with pytest.raises(p.ProtocolError, match="exceed"):
        p.AuthenStart.decode(good[:-1])
    with pytest.raises(p.ProtocolError, match="trailing"):
        p.AuthenStart.decode(good + b"x")
    with pytest.raises(p.ProtocolError, match="privilege"):
        p.AuthenStart.decode(p.authen_start(p.ACTION_LOGIN, 16, p.TYPE_PAP, 1, "x"))
    req = p.request(["service=shell", "cmd=show"], "neo")
    assert p.Request.decode(req, accounting=False).args == ["service=shell", "cmd=show"]
    with pytest.raises(p.ProtocolError):
        p.Request.decode(req[:-3], accounting=False)


def test_reply_encodings():
    assert p.authen_reply(p.STATUS_GETPASS, "Password: ", noecho=True) == b"\x05\x01\x00\x0a\x00\x00Password: "
    assert p.author_reply(p.AUTHOR_PASS_ADD, ["priv-lvl=15"]) == b"\x01\x01\x00\x00\x00\x00\x0bpriv-lvl=15"
    assert p.acct_reply(p.ACCT_SUCCESS) == b"\x00\x00\x00\x00\x01"


# ── authorization rules ────────────────────────────────────────────────────

def test_args_and_command_line():
    attrs, cmd_args = parse_args(["service=shell", "cmd=show", "cmd-arg=running-config", "cmd-arg=<cr>",
                                  "optional*1", "junk"])
    assert attrs == {"service": "shell", "cmd": "show", "optional": "1"}
    assert command_line(attrs["cmd"], cmd_args) == "show running-config"


RO = CompiledCommandSet("ro", CommandAction.DENY, (
    (CommandAction.DENY, "show running-config *"),
    (CommandAction.PERMIT, "show *"),
    (CommandAction.PERMIT, "ping *"),
))


@pytest.mark.parametrize("line,allowed", [
    ("show interfaces status", True),
    ("SHOW  version", True),
    ("show running-config all", False),
    ("configure terminal", False),  # no rule → default DENY
    ("ping 10.0.0.1", True),
])
def test_command_rules_see_arguments_and_default_deny(line, allowed):
    assert command_allowed(line, RO).allowed is allowed


def test_no_command_set_means_privilege_governs():
    assert command_allowed("reload", None).allowed


# ── live server ────────────────────────────────────────────────────────────

@pytest.fixture
async def tacacs(app_db):
    async with app_db() as db:
        ro = CommandSet(name="ro", default_action=CommandAction.DENY, rules=[
            CommandRule(position=0, action=CommandAction.PERMIT, pattern="show *")])
        db.add(ro)
        await db.flush()
        net = Group(name="netadmins", device_admin_privilege=15)
        helpdesk = Group(name="helpdesk", device_admin_privilege=7, command_set_id=ro.id)
        staff = Group(name="staff")
        db.add_all([net, helpdesk, staff])
        await db.flush()
        db.add_all([
            TacacsClient(name="core-sw", ip_address="127.0.0.1", key=KEY),
            User(username="neo", password_hash=hash_password_sync("neo-password"), group_id=net.id),
            User(username="hd", password_hash=hash_password_sync("hd-password"), group_id=helpdesk.id),
            User(username="alice", password_hash=hash_password_sync("alice-password"), group_id=staff.id),
            User(username="off", password_hash=hash_password_sync("off-password"), group_id=net.id, enabled=False),
        ])
        await db.commit()
    cfg = TacacsConfig.model_construct(**{**TacacsConfig().model_dump(), "idle_timeout_seconds": 1,
                                          "max_connections_per_client": 3})
    server = TacacsServer(cfg)
    srv = await server.start("127.0.0.1", 0)
    server.port = srv.sockets[0].getsockname()[1]
    server.sf = app_db
    yield server
    await server.stop()


def client(server, key=KEY) -> TACACSClient:
    return TACACSClient("127.0.0.1", server.port, key, timeout=3)


async def logs(server, kind):
    async with server.sf() as db:
        return list((await db.execute(select(TacacsLog).where(TacacsLog.kind == kind).order_by(TacacsLog.id)))
                    .scalars())


@pytest.mark.parametrize("authen_type", [TAC_PLUS_AUTHEN_TYPE_PAP, TAC_PLUS_AUTHEN_TYPE_ASCII])
async def test_login_interop(tacacs, authen_type):
    def run(user, pw):
        return client(tacacs).authenticate(user, pw, authen_type=authen_type).valid
    assert await asyncio.to_thread(run, "neo", "neo-password")
    assert not await asyncio.to_thread(run, "neo", "wrong")
    assert not await asyncio.to_thread(run, "alice", "alice-password")  # network user, not a device admin
    assert not await asyncio.to_thread(run, "off", "off-password")
    reasons = [r.reason for r in await logs(tacacs, TacacsKind.AUTHEN)]
    assert reasons == ["ok", "wrong password", "no device-administration rights", "user disabled"]


async def test_authorization_interop(tacacs):
    def author(user, args):
        reply = client(tacacs).authorize(user, arguments=[a.encode() for a in args])
        return reply.valid, [a.decode() for a in (reply.arguments or [])]

    assert await asyncio.to_thread(author, "neo", ["service=shell", "cmd="]) == (True, ["priv-lvl=15"])
    assert await asyncio.to_thread(author, "hd", ["service=shell", "cmd="]) == (True, ["priv-lvl=7"])
    ok, _ = await asyncio.to_thread(author, "hd", ["service=shell", "cmd=show", "cmd-arg=version", "cmd-arg=<cr>"])
    assert ok
    for args in (["service=shell", "cmd=configure", "cmd-arg=terminal"], ["service=shell", "cmd=reload"]):
        assert not (await asyncio.to_thread(author, "hd", args))[0]
    assert (await asyncio.to_thread(author, "neo", ["service=shell", "cmd=reload"]))[0]  # no command set
    assert not (await asyncio.to_thread(author, "alice", ["service=shell", "cmd="]))[0]
    assert not (await asyncio.to_thread(author, "neo", ["service=ppp", "protocol=ip"]))[0]
    commands = [(r.command, r.result) for r in await logs(tacacs, TacacsKind.AUTHOR)]
    assert ("configure terminal", "FAIL") in commands and ("show version", "PASS") in commands


async def test_accounting_interop(tacacs):
    def account():
        return client(tacacs).account("neo", TAC_PLUS_ACCT_FLAG_START,
                                      arguments=[b"service=shell", b"cmd=show", b"cmd-arg=clock"]).valid
    assert await asyncio.to_thread(account)
    (row,) = await logs(tacacs, TacacsKind.ACCT)
    assert (row.username, row.command, row.result, row.client_ip) == ("neo", "show clock", "START", "127.0.0.1")


async def test_wrong_key_gets_nothing(tacacs):
    def run():
        return client(tacacs, key="not-the-key").authenticate("neo", "neo-password",
                                                              authen_type=TAC_PLUS_AUTHEN_TYPE_PAP).valid
    with pytest.raises(Exception):
        await asyncio.to_thread(run)


# ── hand-built exchanges ───────────────────────────────────────────────────

class Raw:
    def __init__(self, port: int, key: str = KEY, session_id: int = 0x1234) -> None:
        self.port, self.key, self.sid = port, key.encode(), session_id

    async def __aenter__(self):
        self.reader, self.writer = await asyncio.open_connection("127.0.0.1", self.port)
        return self

    async def __aexit__(self, *exc):
        self.writer.close()

    async def send(self, kind: int, seq: int, body: bytes, *, flags: int = 0, version: int = 0xC0,
                   session_id: int | None = None) -> None:
        sid = self.sid if session_id is None else session_id
        header = p.Header(version, kind, seq, flags, sid, len(body))
        payload = body if flags & p.FLAG_UNENCRYPTED else p.crypt(body, self.key, sid, version, seq)
        self.writer.write(header.encode() + payload)
        await self.writer.drain()

    async def recv(self) -> tuple[p.Header, bytes] | None:
        try:
            header = p.Header.decode(await asyncio.wait_for(self.reader.readexactly(12), 3))
        except (asyncio.IncompleteReadError, ConnectionError):
            return None
        body = await self.reader.readexactly(header.length)
        return header, p.crypt(body, self.key, header.session_id, header.version, header.seq_no)


async def enable(port: int, user: str, password: str, level: int = 15) -> int:
    async with Raw(port) as c:
        await c.send(p.AUTHEN, 1, p.authen_start(p.ACTION_LOGIN, level, p.TYPE_ASCII, p.SERVICE_ENABLE, user))
        _, body = await c.recv()
        assert body[0] == p.STATUS_GETPASS and body[1] == p.REPLY_FLAG_NOECHO
        await c.send(p.AUTHEN, 3, p.authen_continue(b"", user_msg=password))
        return (await c.recv())[1][0]


async def test_enable_is_capped_by_the_group_privilege(tacacs):
    assert await enable(tacacs.port, "neo", "neo-password", 15) == p.STATUS_PASS
    assert await enable(tacacs.port, "hd", "hd-password", 15) == p.STATUS_FAIL
    assert await enable(tacacs.port, "hd", "hd-password", 7) == p.STATUS_PASS
    assert (await logs(tacacs, TacacsKind.AUTHEN))[1].reason == "privilege 15 requested, 7 granted"


async def test_ascii_login_asks_for_the_username_and_binds_the_session(tacacs):
    async with Raw(tacacs.port) as c:
        await c.send(p.AUTHEN, 1, p.authen_start(p.ACTION_LOGIN, 1, p.TYPE_ASCII, p.SERVICE_LOGIN, ""))
        assert (await c.recv())[1][0] == p.STATUS_GETUSER
        await c.send(p.AUTHEN, 3, p.authen_continue(b"", user_msg="neo"), session_id=0x9999)
        assert (await c.recv())[1][0] == p.STATUS_ERROR  # another session id cannot hijack the flow
    async with Raw(tacacs.port) as c:
        await c.send(p.AUTHEN, 1, p.authen_start(p.ACTION_LOGIN, 1, p.TYPE_ASCII, p.SERVICE_LOGIN, ""))
        await c.recv()
        await c.send(p.AUTHEN, 3, p.authen_continue(b"", user_msg="neo"))
        assert (await c.recv())[1][0] == p.STATUS_GETPASS
        await c.send(p.AUTHEN, 5, p.authen_continue(b"", user_msg="neo-password"))
        assert (await c.recv())[1][0] == p.STATUS_PASS


@pytest.mark.parametrize("send", [
    {"flags": p.FLAG_UNENCRYPTED},
    {"version": 0xB0},
])
async def test_bad_packets_close_the_connection(tacacs, send):
    async with Raw(tacacs.port) as c:
        await c.send(p.AUTHEN, 1, p.authen_start(p.ACTION_LOGIN, 1, p.TYPE_PAP, 1, "neo", data=b"neo-password"),
                     **send)
        assert await c.recv() is None


async def test_unsupported_methods_fail(tacacs):
    async with Raw(tacacs.port) as c:
        await c.send(p.AUTHEN, 1, p.authen_start(p.ACTION_LOGIN, 1, p.TYPE_CHAP, 1, "neo", data=b"x" * 17))
        assert (await c.recv())[1][0] == p.STATUS_FAIL


async def test_unregistered_or_disabled_clients_are_dropped(tacacs):
    async with tacacs.sf() as db:
        await db.execute(delete(TacacsClient))
        await db.commit()
    async with Raw(tacacs.port) as c:
        await c.send(p.AUTHEN, 1, p.authen_start(p.ACTION_LOGIN, 1, p.TYPE_PAP, 1, "neo", data=b"neo-password"))
        assert await c.recv() is None


async def test_idle_connections_time_out_and_slots_are_limited(tacacs):
    held = [await asyncio.open_connection("127.0.0.1", tacacs.port) for _ in range(3)]
    await asyncio.sleep(0.1)
    reader, writer = await asyncio.open_connection("127.0.0.1", tacacs.port)
    assert await asyncio.wait_for(reader.read(), 2) == b""  # over the per-client cap: closed at once
    writer.close()
    for r, _ in held:
        assert await asyncio.wait_for(r.read(), 3) == b""  # idle timeout (1 s) closes them
    for _, w in held:
        w.close()
