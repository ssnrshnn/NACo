"""TACACS+ server (RFC 8907) for switch and router administration.

* Only registered, enabled clients are served; each has its own key, looked up
  per connection, so adding, disabling or deleting a client applies at once.
* Unencrypted packets, unknown versions, even (server-side) sequence numbers
  and oversized bodies close the connection.
* Idle connections time out; total and per-client connection counts are capped.
* ASCII login state is bound to the TACACS+ session id and its sequence numbers.
* Authentication: PAP and ASCII login (and ``enable``, up to the privilege of the
  user's device-admin group). Authorization: shell start and per-command checks
  against the group's command set. Accounting is logged.
"""
from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import logging
from dataclasses import dataclass, field

from sqlalchemy import select

from naco.auth.identity import authenticate_user, canonical_username, lookup_user
from naco.config import TacacsConfig
from naco.core.events import Event, EventType, bus
from naco.core.metrics import REGISTRY
from naco.core.ratelimit import GuessGuard
from naco.db.engine import session_factory
from naco.db.models import TacacsClient, TacacsKind, TacacsLog
from naco.tacacs import protocol as p
from naco.tacacs.authz import (
    admin_rights,
    command_allowed,
    command_line,
    load_command_set,
    parse_args,
    privilege_allowed,
)

log = logging.getLogger(__name__)
trail = logging.getLogger("naco.trail")

REQUESTS = REGISTRY.counter("naco_tacacs_requests_total", "TACACS+ requests", ["kind", "result"])


def _peer(writer: asyncio.StreamWriter) -> str:
    raw = (writer.get_extra_info("peername") or ("",))[0]
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError:
        return str(raw)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return str(ip.ipv4_mapped)
    return str(ip)


@dataclass
class _Login:
    start: p.AuthenStart
    user: str
    awaiting: str  # "user" or "pass"
    next_seq: int


@dataclass
class _Connection:
    server: TacacsServer
    ip: str
    name: str
    key: bytes
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    logins: dict[int, _Login] = field(default_factory=dict)

    async def run(self) -> None:
        idle = self.server.cfg.idle_timeout_seconds
        while True:
            try:
                header = p.Header.decode(await asyncio.wait_for(self.reader.readexactly(p.HEADER_LEN), idle))
                if header.flags & p.FLAG_UNENCRYPTED:
                    raise p.ProtocolError("unencrypted packets are refused")
                if header.seq_no % 2 == 0:
                    raise p.ProtocolError("clients send odd sequence numbers")
                raw = await asyncio.wait_for(self.reader.readexactly(header.length), idle)
                body = p.crypt(raw, self.key, header.session_id, header.version, header.seq_no)
                reply = await self.dispatch(header, body)
            except (TimeoutError, asyncio.IncompleteReadError, ConnectionError):
                return
            except p.ProtocolError as exc:
                log.warning("TACACS+ %s (%s): %s — closing (wrong key?)", self.name, self.ip, exc)
                return
            if reply is None:
                return
            self.writer.write(p.packet(header, reply, self.key))
            await self.writer.drain()

    async def dispatch(self, header: p.Header, body: bytes) -> bytes | None:
        if header.type == p.AUTHEN:
            if header.seq_no == 1:
                return await self.authen_start(header, p.AuthenStart.decode(body))
            return await self.authen_continue(header, p.AuthenContinue.decode(body))
        if header.seq_no != 1:
            raise p.ProtocolError("authorization and accounting are single-packet sessions")
        if header.type == p.AUTHOR:
            return await self.authorize(p.Request.decode(body, accounting=False))
        return await self.account(p.Request.decode(body, accounting=True))

    # ── authentication ─────────────────────────────────────────────────

    async def authen_start(self, header: p.Header, start: p.AuthenStart) -> bytes:
        self.logins.pop(header.session_id, None)
        if start.action != p.ACTION_LOGIN:
            return await self._authen_fail(start, start.user, "only login is supported")
        if start.authen_type == p.TYPE_PAP:
            return await self.verify(start, start.user, start.data.decode("utf-8", errors="replace"))
        if start.authen_type != p.TYPE_ASCII:
            return await self._authen_fail(start, start.user, "authentication type not supported")
        if start.user:
            self.logins[header.session_id] = _Login(start, start.user, "pass", header.seq_no + 2)
            return p.authen_reply(p.STATUS_GETPASS, "Password: ", noecho=True)
        self.logins[header.session_id] = _Login(start, "", "user", header.seq_no + 2)
        return p.authen_reply(p.STATUS_GETUSER, "Username: ")

    async def authen_continue(self, header: p.Header, cont: p.AuthenContinue) -> bytes:
        login = self.logins.get(header.session_id)
        if login is None or header.seq_no != login.next_seq:
            self.logins.pop(header.session_id, None)
            return p.authen_reply(p.STATUS_ERROR, "unexpected packet")
        answer = cont.user_msg or cont.data.decode("utf-8", errors="replace")
        if cont.abort:
            self.logins.pop(header.session_id, None)
            return p.authen_reply(p.STATUS_FAIL, "aborted")
        if login.awaiting == "user":
            login.user, login.awaiting, login.next_seq = answer, "pass", header.seq_no + 2
            return p.authen_reply(p.STATUS_GETPASS, "Password: ", noecho=True)
        self.logins.pop(header.session_id, None)
        return await self.verify(login.start, login.user, answer)

    async def verify(self, start: p.AuthenStart, username: str, password: str) -> bytes:
        enable = start.authen_service == p.SERVICE_ENABLE
        key = canonical_username(username) or username[:64]
        source = f"{self.ip}|{start.rem_addr}"
        if self.server.failures.delay_for(key, source) > 0:
            return await self._authen_fail(start, username, "too many failed attempts — slowed down")
        result = await authenticate_user(username, password)
        if not result.ok:
            self.server.failures.failure(key, source)
            return await self._authen_fail(start, result.username, result.reason)
        self.server.failures.success(key, source)
        rights = admin_rights(result.user)
        if not rights.allowed:
            return await self._authen_fail(start, result.username, rights.reason)
        assert result.user is not None
        if enable or start.priv_lvl > 1:
            level = privilege_allowed(result.user, start.priv_lvl)
            if not level.allowed:
                return await self._authen_fail(start, result.username, level.reason)
        await self.record(TacacsKind.AUTHEN, result.username, start.rem_addr, start.port, start.priv_lvl,
                          "enable" if enable else "login", "PASS", "ok")
        return p.authen_reply(p.STATUS_PASS)

    async def _authen_fail(self, start: p.AuthenStart, username: str, reason: str) -> bytes:
        what = "enable" if start.authen_service == p.SERVICE_ENABLE else "login"
        await self.record(TacacsKind.AUTHEN, username, start.rem_addr, start.port, start.priv_lvl,
                          what, "FAIL", reason)
        return p.authen_reply(p.STATUS_FAIL)

    # ── authorization ──────────────────────────────────────────────────

    async def authorize(self, req: p.Request) -> bytes:
        user = await lookup_user(req.user)
        attrs, cmd_args = parse_args(req.args)
        cmd = attrs.get("cmd")
        line = command_line(cmd, cmd_args) if cmd else "shell"
        username = user.username if user else (canonical_username(req.user) or req.user[:64])

        async def deny(reason: str) -> bytes:
            await self.record(TacacsKind.AUTHOR, username, req.rem_addr, req.port, req.priv_lvl, line, "FAIL", reason)
            return p.author_reply(p.AUTHOR_FAIL)

        rights = admin_rights(user)
        if not rights.allowed:
            return await deny(rights.reason)
        assert user is not None
        if attrs.get("service", "").lower() != "shell":
            return await deny(f"service {attrs.get('service', '?')} is not offered")
        level = privilege_allowed(user, req.priv_lvl)
        if not level.allowed:
            return await deny(level.reason)
        if not cmd:  # exec/shell start: tell the device the user's level
            await self.record(TacacsKind.AUTHOR, username, req.rem_addr, req.port, req.priv_lvl, line, "PASS",
                              f"priv-lvl {user.device_admin_privilege}")
            return p.author_reply(p.AUTHOR_PASS_ADD, [f"priv-lvl={user.device_admin_privilege}"])
        async with session_factory()() as db:
            command_set = await load_command_set(db, user.command_set_id)
        verdict = command_allowed(line, command_set)
        if not verdict.allowed:
            return await deny(verdict.reason)
        await self.record(TacacsKind.AUTHOR, username, req.rem_addr, req.port, req.priv_lvl, line, "PASS",
                          verdict.reason)
        return p.author_reply(p.AUTHOR_PASS_ADD)

    # ── accounting ─────────────────────────────────────────────────────

    async def account(self, req: p.Request) -> bytes:
        attrs, cmd_args = parse_args(req.args)
        kind = ("start" if req.flags & p.ACCT_FLAG_START else
                "stop" if req.flags & p.ACCT_FLAG_STOP else
                "watchdog" if req.flags & p.ACCT_FLAG_WATCHDOG else "other")
        what = command_line(attrs["cmd"], cmd_args) if attrs.get("cmd") else \
            " ".join(f"{k}={v}" for k, v in sorted(attrs.items()))
        username = canonical_username(req.user) or req.user[:64]
        try:
            await self.record(TacacsKind.ACCT, username, req.rem_addr, req.port, req.priv_lvl, what, kind.upper(), "")
        except Exception:
            log.exception("TACACS+ accounting could not be stored")
            return p.acct_reply(p.ACCT_ERROR)
        return p.acct_reply(p.ACCT_SUCCESS)

    # ── logging ────────────────────────────────────────────────────────

    async def record(self, kind: TacacsKind, username: str, rem_addr: str, port: str, privilege: int,
                     command: str, result: str, reason: str) -> None:
        async with session_factory()() as db:
            db.add(TacacsLog(kind=kind, username=username[:64], client_ip=self.ip, rem_addr=rem_addr[:64],
                             port=port[:64], privilege=privilege, command=command[:4000], result=result[:16],
                             reason=reason[:255]))
            await db.commit()
        REQUESTS.inc(kind=kind.value, result=result)
        bus.publish(Event(EventType.TACACS, {"kind": kind.value, "username": username, "device": self.name,
                                             "command": command, "result": result, "reason": reason}))
        trail.info("tacacs %s %s user=%s device=%s rem=%s priv=%d cmd=%r %s", kind.value, result, username or "-",
                   self.name, rem_addr or "-", privilege, command, reason)


class TacacsServer:
    def __init__(self, cfg: TacacsConfig) -> None:
        self.cfg = cfg
        self.failures = GuessGuard()  # per user and (device, remote address)
        self._total = 0
        self._per_client: dict[str, int] = {}
        self._server: asyncio.Server | None = None

    async def start(self, host: str, port: int) -> asyncio.Server:
        self._server = await asyncio.start_server(self._handle, host, port)
        log.info("TACACS+ listening on %s:%d", host, port)
        return self._server

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()

    async def _client(self, ip: str) -> TacacsClient | None:
        async with session_factory()() as db:
            return (await db.execute(select(TacacsClient).where(
                TacacsClient.ip_address == ip, TacacsClient.enabled.is_(True)))).scalar_one_or_none()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        ip = _peer(writer)
        if self._total >= self.cfg.max_connections or \
                self._per_client.get(ip, 0) >= self.cfg.max_connections_per_client:
            log.warning("TACACS+ connection limit reached — refusing %s", ip)
            writer.close()
            return
        self._total += 1
        self._per_client[ip] = self._per_client.get(ip, 0) + 1
        try:
            client = await self._client(ip)
            if client is None:
                log.info("TACACS+ connection from unregistered address %s refused", ip)
                return
            await _Connection(self, ip, client.name, client.key.encode(), reader, writer).run()
        finally:
            self._total -= 1
            self._per_client[ip] -= 1
            if not self._per_client[ip]:
                del self._per_client[ip]
            writer.close()
            with contextlib.suppress(ConnectionError, OSError):
                await writer.wait_closed()
