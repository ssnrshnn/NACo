"""
NACo RADIUS Server
==================
A focused, pure-Python RADIUS implementation built on `pyrad`. The built-in
server intentionally only speaks the simple, well-understood subset of
RFC 2865/2866/3579/5176 below — anything EAP-flavoured is delegated to the
FreeRADIUS sidecar via `/api/v1/eap/*` REST hooks.

Supported authentication methods
--------------------------------
  • **PAP**  — User-Password attribute (RFC 2865 §5.2).
  • **CHAP** — CHAP-Password + CHAP-Challenge (requires the operator to store
               a reversible secret; bcrypt-only deployments fall through to
               PAP/EAP).
  • **MAB**  — MAC Address Bypass (RFC 3580); the username AND the
               User-Password MUST be the device MAC.

Other features
--------------
  • RFC 2866 accounting Start/Stop/Interim-Update.
  • RFC 3579 Message-Authenticator validation (CVE-2024-3596 mitigation —
    "BlastRADIUS"). Enforcement is per-NAS (defaults to *required*).
  • Hot-reloads NAS clients from the database every 30 s.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
import re
from datetime import UTC
from typing import Any

import pyrad.dictionary
import pyrad.packet
import pyrad.server

from naco.config import get_config
from naco.core.events import Event, EventType, bus
from naco.core.logger import get_logger
from naco.core.utils import chap_verify, normalise_mac
from naco.db.database import AsyncSessionLocal
from naco.db.models import (
    ActiveSession,
    AuthLog,
    AuthMethod,
    AuthResult,
    Device,
    NasClient,
    PolicyAction,
    User,
)
from naco.policy.engine import AuthContext
from naco.policy.engine import engine as policy_engine

log = get_logger(__name__)


_DICT_PATH = os.path.join(os.path.dirname(__file__), "dictionary")
_MESSAGE_AUTHENTICATOR_TYPE = 80  # RFC 3579 §3.2

# Module-level reference for graceful shutdown.
_active_radius_server: NACoRadiusServer | None = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_MAC_RE_HEX  = re.compile(r"^[0-9a-fA-F]{12}$")
_MAC_STRIP   = re.compile(r"[:\-.]")


def _is_mac_like(s: str) -> bool:
    """Return True if *s* looks like a MAC address (12 hex chars after separators)."""
    return bool(_MAC_RE_HEX.fullmatch(_MAC_STRIP.sub("", s or "")))


def _decode_pap_password(encrypted: bytes, secret: bytes | str, authenticator: bytes) -> str:
    """Decrypt PAP User-Password per RFC 2865 §5.2."""
    if isinstance(secret, str):
        secret = secret.encode()
    result = bytearray()
    prev = authenticator
    for i in range(0, len(encrypted), 16):
        block = encrypted[i:i+16]
        digest = hashlib.md5(secret + bytes(prev)).digest()
        chunk  = bytes(a ^ b for a, b in zip(digest, block, strict=False))
        result += chunk
        prev = block
    return result.rstrip(b"\x00").decode("utf-8", errors="replace")


def _acct_octets(pkt, octets_attr: str, gigawords_attr: str) -> int:
    """Combine a 32-bit octet counter with its RFC 2869 Gigawords rollover.

    NASes wrap Acct-*-Octets at 2^32 and count the wraps in the matching
    Gigawords attribute; sessions moving more than 4 GiB are misreported
    without it.
    """
    try:
        octets = int((pkt.get(octets_attr, [0])[0]) or 0)
    except (TypeError, ValueError):
        octets = 0
    try:
        giga = int((pkt.get(gigawords_attr, [0])[0]) or 0)
    except (TypeError, ValueError):
        giga = 0
    return (giga << 32) + octets


def parse_vlan_attr(raw: Any) -> int | None:
    """Parse a Tunnel-Private-Group-Id attribute into an int VLAN ID.

    The attribute may be:
      • ``b"42"`` / ``"42"`` — decimal text.
      • ``b"0x2a"`` / ``"0x2a"`` — hex text (with optional ``0x`` prefix).
      • An ``int`` already parsed by pyrad.

    Returns ``None`` if the value can't be interpreted as a VLAN.

    Replaces the legacy `str(val).lstrip("0x")` bug, which corrupted values
    like ``"x10"`` → ``"1"`` (lstrip strips a *set of characters*, not a prefix).
    """
    if raw is None:
        return None
    if isinstance(raw, int):
        return raw if 1 <= raw <= 4094 else None
    if isinstance(raw, bytes):
        try:
            raw = raw.decode("ascii", errors="replace")
        except Exception:
            return None
    s = str(raw).strip()
    if not s:
        return None
    # RFC 2868: optional tag byte at the start (high bit set when tagged).
    # pyrad usually strips it; defensively drop a leading single byte that
    # isn't a hex digit and isn't '0' (i.e. a tag).
    try:
        if s.lower().startswith("0x"):
            return int(s[2:], 16) if s[2:] else None
        return int(s, 10)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Custom pyrad Server sub-class
# ---------------------------------------------------------------------------

class NACoRadiusServer(pyrad.server.Server):
    """RFC 2865/2866 server with policy engine integration."""

    def __init__(self) -> None:
        cfg = get_config()
        self._cfg = cfg.radius
        self._clients: dict[str, str] = {c.address: c.secret for c in self._cfg.clients}
        self._client_msgauth: dict[str, bool] = {
            c.address: c.require_message_authenticator for c in self._cfg.clients
        }
        self._loop: asyncio.AbstractEventLoop | None = None
        self._last_client_reload: float = 0.0
        self._client_reload_interval: float = 30.0

        dict_path = _DICT_PATH if os.path.isfile(_DICT_PATH) else None
        hosts = {
            c.address: pyrad.server.RemoteHost(c.address, c.secret.encode(), c.name)
            for c in self._cfg.clients
        }

        super().__init__(
            hosts=hosts,
            dict=pyrad.dictionary.Dictionary(dict_path) if dict_path else None,
        )

    # ------------------------------------------------------------------
    # Hot-reload NAS clients from DB
    # ------------------------------------------------------------------

    def _apply_db_clients(self, db_clients: list[tuple[str, str]]) -> None:
        """Diff DB-managed NAS clients into the live host tables."""
        cfg_addrs = {c.address for c in self._cfg.clients}
        db_map = dict(db_clients)

        # Add new / update changed DB-managed clients. Entries from
        # config.yaml always win over a DB row for the same address.
        for ip, secret in db_map.items():
            if ip in cfg_addrs:
                continue
            if self._clients.get(ip) != secret:
                verb = "Updated secret for" if ip in self._clients else "Hot-loaded"
                self._clients[ip] = secret
                self._client_msgauth.setdefault(ip, self._cfg.require_message_authenticator)
                self.hosts[ip] = pyrad.server.RemoteHost(ip, secret.encode(), ip)
                log.info("%s NAS client %s from database", verb, ip)

        # Drop DB-managed clients that were deleted or disabled.
        for ip in list(self._clients):
            if ip not in cfg_addrs and ip not in db_map:
                self._clients.pop(ip, None)
                self._client_msgauth.pop(ip, None)
                self.hosts.pop(ip, None)
                log.info("Removed NAS client %s (deleted or disabled in database)", ip)

    def _maybe_reload_db_clients(self) -> None:
        """Packet-driven refresh (belt) — the background task (braces) in
        ``run_radius_server`` covers the case where no known NAS is talking,
        which is exactly when a *first* NAS gets added via the UI."""
        import time as _time
        now = _time.monotonic()
        if now - self._last_client_reload < self._client_reload_interval:
            return
        self._last_client_reload = now
        if not self._loop:
            return
        try:
            db_clients = asyncio.run_coroutine_threadsafe(
                _load_db_nas_clients(), self._loop,
            ).result(timeout=5)
            self._apply_db_clients(db_clients)
        except Exception as exc:
            log.debug("NAS client reload failed: %s", exc)

    # ------------------------------------------------------------------
    # Authentication handler
    # ------------------------------------------------------------------

    def HandleAuthPacket(self, pkt: pyrad.packet.AuthPacket) -> None:
        nas_ip = pkt.source[0]
        self._maybe_reload_db_clients()

        if nas_ip not in self._clients:
            log.warning("Dropping RADIUS request from unknown NAS %s", nas_ip)
            return

        # ── RFC 3579 / BlastRADIUS (CVE-2024-3596) -----------------------
        if not self._message_authenticator_valid(pkt, nas_ip):
            log.warning("Access-Request from %s missing/invalid Message-Authenticator", nas_ip)
            try:
                reply = self._make_reply(pkt, pyrad.packet.AccessReject)
                self.SendReplyPacket(pkt.fd, reply)
            except Exception:
                pass
            return

        try:
            method, username, result, reason = self._authenticate(pkt)

            policy_vlan: int | None = None
            policy_name: str = ""
            reply_attrs: dict = {}
            if result == AuthResult.SUCCESS:
                policy_vlan, result, reason, policy_name, reply_attrs = self._run_sync(
                    self._apply_policy(username, pkt, method)
                )

            if result == AuthResult.SUCCESS:
                reply = self._make_reply(pkt, pyrad.packet.AccessAccept)
                vlan = policy_vlan if policy_vlan is not None else self._resolve_vlan(username, nas_ip, method, pkt)
                if vlan:
                    # RFC 3580 §3.31 dynamic VLAN assignment. pyrad expects
                    # the RFC 2868 tag in the attribute *key* ("Attr:1"),
                    # and encodes tagged integers as tag + 3-byte value.
                    try:
                        reply["Tunnel-Type:1"]             = 13          # VLAN
                        reply["Tunnel-Medium-Type:1"]      = 6           # IEEE-802
                        reply["Tunnel-Private-Group-Id:1"] = str(vlan)
                    except Exception as exc:
                        log.error(
                            "Failed to attach VLAN %s to Access-Accept for user=%r: %s "
                            "— NAS will fall back to its default VLAN",
                            vlan, username, exc,
                        )
                self._attach_reply_attributes(reply, reply_attrs, username)
                log.info("Access-ACCEPT user=%r nas=%s method=%s", username, nas_ip, method)
            else:
                reply = self._make_reply(pkt, pyrad.packet.AccessReject)
                log.info("Access-REJECT user=%r nas=%s reason=%r", username, nas_ip, reason)

            self.SendReplyPacket(pkt.fd, reply)
            self._log_auth(pkt, username, method, result, reason, policy_name, policy_vlan)
            self._publish(username, pkt, method, result, reason)

        except Exception as exc:
            log.exception("RADIUS auth handler error for NAS %s: %s", nas_ip, exc)
            try:
                self.SendReplyPacket(pkt.fd, self._make_reply(pkt, pyrad.packet.AccessReject))
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Accounting handler
    # ------------------------------------------------------------------

    def HandleAcctPacket(self, pkt: pyrad.packet.AcctPacket) -> None:
        nas_ip   = pkt.source[0]
        status   = pkt.get("Acct-Status-Type", [None])[0]
        session  = pkt.get("Acct-Session-Id",  [""])[0]
        username = pkt.get("User-Name",         [""])[0]
        ip       = pkt.get("Framed-IP-Address", [""])[0]
        nas_port = str(pkt.get("NAS-Port", [""])[0])

        if self._loop:
            asyncio.run_coroutine_threadsafe(
                self._update_session(status, session, username, ip, nas_ip, nas_port, pkt),
                self._loop,
            )

        reply = pkt.CreateReply()
        reply.source = pkt.source
        self.SendReplyPacket(pkt.fd, reply)

    # ------------------------------------------------------------------
    # Message-Authenticator validation (RFC 3579)
    # ------------------------------------------------------------------

    def _message_authenticator_valid(
        self, pkt: pyrad.packet.AuthPacket, nas_ip: str
    ) -> bool:
        """Verify the Message-Authenticator attribute, if required.

        Per RFC 3579 §3.2 / CVE-2024-3596 "BlastRADIUS":
            HMAC-MD5(shared_secret, RADIUS-packet-with-MA-zeroed)
                == value of Message-Authenticator attribute

        When `radius.require_message_authenticator` is true for this NAS, a
        missing attribute is also a hard failure.
        """
        require = self._client_msgauth.get(
            nas_ip, self._cfg.require_message_authenticator
        )
        ma_values = pkt.get(_MESSAGE_AUTHENTICATOR_TYPE, [])
        if not ma_values:
            return not require

        received = ma_values[0]
        if isinstance(received, str):
            received = received.encode("latin-1")
        if len(received) != 16:
            return False

        secret = pkt.secret if isinstance(pkt.secret, bytes) else pkt.secret.encode()

        # The HMAC must be computed over the packet exactly as it appeared on
        # the wire (RFC 3579 §3.2) — re-encoding via ``pkt.RequestPacket()``
        # can reorder/regroup attributes and produce a different byte stream,
        # which made NACo reject *valid* requests from real clients. Prefer
        # the raw datagram pyrad captured at decode time.
        raw = getattr(pkt, "raw_packet", None)
        if raw and len(raw) >= 20:
            attrs = bytearray(raw[20:])
            offset = 0
            while offset + 2 <= len(attrs):
                atype, alen = attrs[offset], attrs[offset + 1]
                if alen < 2 or offset + alen > len(attrs):
                    return False  # malformed TLV stream
                if atype == _MESSAGE_AUTHENTICATOR_TYPE and alen == 18:
                    attrs[offset + 2:offset + 18] = b"\x00" * 16
                offset += alen
            wire = raw[:20] + bytes(attrs)
        else:
            # Fallback (packets built in-process, e.g. unit tests): rebuild
            # the wire image with the MA value zeroed.
            try:
                saved = pkt[_MESSAGE_AUTHENTICATOR_TYPE]
            except KeyError:
                return False
            pkt[_MESSAGE_AUTHENTICATOR_TYPE] = [b"\x00" * 16]
            try:
                wire = pkt.RequestPacket()
            finally:
                pkt[_MESSAGE_AUTHENTICATOR_TYPE] = saved

        expected = hmac.new(secret, wire, hashlib.md5).digest()
        return hmac.compare_digest(expected, received)

    @staticmethod
    def _make_reply(pkt: pyrad.packet.AuthPacket, code: int) -> pyrad.packet.AuthPacket:
        """Build an Access-* reply with a Message-Authenticator.

        Two pyrad-compat details live here so the handlers stay readable:

        * ``AuthPacket.CreateReply(code=…)`` raises ``TypeError`` on pyrad
          2.5 (``code`` collides with a positional arg) — the code must be
          assigned after construction.
        * ``SendReplyPacket`` addresses the datagram to ``reply.source``,
          which ``CreateReply`` does *not* copy from the request — without
          it the send raises ``AttributeError`` and the NAS never hears
          back.
        * Post-BlastRADIUS clients (CVE-2024-3596 hardening) require replies
          to carry a valid MA when the request did — without it they
          silently discard our Accept/Reject and retry until timeout. pyrad
          computes the response HMAC (keyed on the request authenticator)
          at encode time.
        """
        reply = pkt.CreateReply()
        reply.code = code
        reply.source = pkt.source
        try:
            reply.add_message_authenticator()
        except Exception:
            # A reply we cannot stamp is still better than no reply at all
            # (pre-BlastRADIUS clients accept it).
            pass
        return reply

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _authenticate(
        self, pkt: pyrad.packet.AuthPacket
    ) -> tuple[AuthMethod, str, AuthResult, str]:
        username = (pkt.get("User-Name", [""])[0] or "").strip()
        eap_msg  = pkt.get("EAP-Message", [])

        if _is_mac_like(username):
            return self._authenticate_mab(username, pkt)

        if eap_msg:
            # EAP is delegated to FreeRADIUS via `/api/v1/eap/*`; the built-in
            # server should never see an EAP packet directly. Reject loudly so
            # operators notice the misconfiguration.
            return (
                AuthMethod.PEAP, username, AuthResult.FAILURE,
                "EAP not handled by NACo's built-in RADIUS server — route EAP "
                "traffic to the FreeRADIUS sidecar (compose profile `eap`).",
            )

        chap_pw = pkt.get("CHAP-Password", [None])[0]
        if chap_pw:
            return self._authenticate_chap(username, chap_pw, pkt)

        return self._authenticate_pap(username, pkt)

    def _authenticate_pap(
        self, username: str, pkt: pyrad.packet.AuthPacket
    ) -> tuple[AuthMethod, str, AuthResult, str]:
        raw_pw = pkt.get("User-Password", [b""])[0]
        password = _decode_pap_password(raw_pw, pkt.secret, pkt.authenticator)
        result, reason = self._run_sync(self._check_user_password(username, password))
        return AuthMethod.PAP, username, result, reason

    def _authenticate_chap(
        self, username: str, chap_pw: bytes, pkt: pyrad.packet.AuthPacket
    ) -> tuple[AuthMethod, str, AuthResult, str]:
        chap_id   = bytes([chap_pw[0]])
        chap_resp = chap_pw[1:17]
        challenge = pkt.get("CHAP-Challenge", [pkt.authenticator])[0]

        db_password = self._run_sync(self._get_cleartext_password(username))
        if db_password is None:
            return (
                AuthMethod.CHAP, username, AuthResult.FAILURE,
                "CHAP unavailable (cleartext password not stored); use PAP or EAP",
            )

        if chap_verify(chap_id, db_password, chap_resp + challenge):
            return AuthMethod.CHAP, username, AuthResult.SUCCESS, ""
        return AuthMethod.CHAP, username, AuthResult.FAILURE, "CHAP verify failed"

    def _authenticate_mab(
        self, mac_raw: str, pkt: pyrad.packet.AuthPacket
    ) -> tuple[AuthMethod, str, AuthResult, str]:
        """MAC Authentication Bypass — RFC 3580.

        The username **and** the User-Password MUST equal the MAC address; a
        compromised NAS cannot then bypass MAB by sending an arbitrary
        password while claiming a MAC username.
        """
        try:
            mac = normalise_mac(mac_raw)
        except ValueError:
            return AuthMethod.MAB, mac_raw, AuthResult.FAILURE, "Invalid MAC"

        # Verify User-Password (if supplied) matches the username/MAC.
        raw_pw = pkt.get("User-Password", [b""])[0]
        supplied_pw = ""
        if raw_pw:
            supplied_pw = _decode_pap_password(raw_pw, pkt.secret, pkt.authenticator)
            try:
                supplied_mac = normalise_mac(supplied_pw)
            except ValueError:
                supplied_mac = supplied_pw.lower()
            if supplied_mac != mac:
                return (
                    AuthMethod.MAB, mac, AuthResult.FAILURE,
                    "MAB rejected: User-Password does not match MAC (RFC 3580)",
                )

        result, reason = self._run_sync(self._check_device_authorized(mac))
        return AuthMethod.MAB, mac, result, reason

    # ---- DB helpers (run from sync context via _run_sync) ----

    async def _check_user_password(self, username: str, password: str) -> tuple[AuthResult, str]:
        from datetime import datetime

        from naco.api.auth import dummy_verify_async, verify_password_async

        async with AsyncSessionLocal() as db:
            from sqlalchemy import select
            stmt = select(User).where(User.username == username, User.enabled)
            row = (await db.execute(stmt)).scalar_one_or_none()
            if row is not None:
                if await verify_password_async(password, row.password_hash):
                    row.last_login = datetime.now(UTC)
                    await db.commit()
                    return AuthResult.SUCCESS, ""
                return AuthResult.FAILURE, "Wrong password"

            # Constant-time: unknown users cost one bcrypt cycle too.
            await dummy_verify_async(password)

            from naco.auth.ldap import ldap_authenticate, ldap_auto_provision
            ldap_result = await ldap_authenticate(username, password)
            if ldap_result is not None:
                await ldap_auto_provision(username, ldap_result, db)
                return AuthResult.SUCCESS, ""
            return AuthResult.FAILURE, "Unknown user"

    async def _get_cleartext_password(self, _username: str) -> str | None:
        """CHAP requires a reversible secret. Bcrypt-only deployments can't
        provide one; extend this hook to read from a secrets vault or NTLM
        hash table if CHAP support is required."""
        return None

    async def _check_device_authorized(self, mac: str) -> tuple[AuthResult, str]:
        async with AsyncSessionLocal() as db:
            from sqlalchemy import select
            stmt = select(Device).where(Device.mac_address == mac)
            dev = (await db.execute(stmt)).scalar_one_or_none()
            if dev is not None and dev.authorized:
                return AuthResult.SUCCESS, ""
            # Not (or not yet) authorised in the inventory — a live captive-
            # portal registration also authorises the MAC for its lifetime.
            if await _has_active_guest_session(db, mac):
                return AuthResult.SUCCESS, "Guest session"
            if dev is None:
                return AuthResult.FAILURE, "Unknown MAC"
            return AuthResult.FAILURE, "MAC not authorised"

    # ---- Session accounting ----

    async def _update_session(
        self, status, session_id, username, ip, nas_ip, nas_port, pkt,
    ) -> None:
        from sqlalchemy import select
        from sqlalchemy.exc import IntegrityError

        async with AsyncSessionLocal() as db:
            if status in (1, "Start"):
                mac_raw = pkt.get("Calling-Station-Id", [""])[0]
                try:
                    mac = normalise_mac(mac_raw)
                except ValueError:
                    mac = mac_raw

                vlan_raw_list = pkt.get("Tunnel-Private-Group-Id", [None])
                vlan = parse_vlan_attr(vlan_raw_list[0] if vlan_raw_list else None)

                db.add(ActiveSession(
                    session_id=session_id, username=username,
                    mac_address=mac, ip_address=ip,
                    nas_ip=nas_ip, nas_port=nas_port,
                    vlan=vlan,
                ))
            elif status in (2, "Stop"):
                stmt = select(ActiveSession).where(ActiveSession.session_id == session_id)
                sess = (await db.execute(stmt)).scalar_one_or_none()
                if sess:
                    await db.delete(sess)
            elif status in (3, "Interim-Update"):
                stmt = select(ActiveSession).where(ActiveSession.session_id == session_id)
                sess = (await db.execute(stmt)).scalar_one_or_none()
                if sess is None:
                    # Session started before a NACo restart (or the Start was
                    # lost). Recover it from the Interim-Update so the active-
                    # sessions view converges instead of staying blind.
                    mac_raw = pkt.get("Calling-Station-Id", [""])[0]
                    try:
                        mac = normalise_mac(mac_raw)
                    except ValueError:
                        mac = mac_raw
                    sess = ActiveSession(
                        session_id=session_id, username=username,
                        mac_address=mac, ip_address=ip,
                        nas_ip=nas_ip, nas_port=nas_port,
                    )
                    db.add(sess)
                sess.bytes_in  = _acct_octets(pkt, "Acct-Input-Octets",  "Acct-Input-Gigawords")
                sess.bytes_out = _acct_octets(pkt, "Acct-Output-Octets", "Acct-Output-Gigawords")
            try:
                await db.commit()
            except IntegrityError:
                await db.rollback()
                log.debug("Duplicate Accounting-Start for session %s — ignored", session_id)

    # ---- VLAN resolution ----

    def _resolve_vlan(self, _username, _nas_ip, method, _pkt) -> int | None:
        cfg = self._cfg
        return cfg.guest_vlan if method == AuthMethod.MAB else cfg.default_vlan

    # ---- Policy evaluation ----

    async def _apply_policy(
        self, username: str, pkt, method: AuthMethod,
    ) -> tuple[int | None, AuthResult, str, str, dict]:
        from sqlalchemy import select
        from sqlalchemy.orm import selectinload

        nas_ip  = pkt.source[0]
        mac_raw = pkt.get("Calling-Station-Id", [""])[0]
        try:
            mac = normalise_mac(mac_raw)
        except ValueError:
            mac = mac_raw

        group_name  = ""
        device_type = "unknown"
        has_guest_session = False

        async with AsyncSessionLocal() as db:
            if method == AuthMethod.MAB:
                dev_stmt = select(Device).where(Device.mac_address == (mac or username))
                dev = (await db.execute(dev_stmt)).scalar_one_or_none()
                if dev:
                    device_type = dev.device_type or "unknown"
                has_guest_session = await _has_active_guest_session(db, mac or username)
            else:
                user_stmt = (
                    select(User)
                    .options(selectinload(User.group))
                    .where(User.username == username, User.enabled)
                )
                user = (await db.execute(user_stmt)).scalar_one_or_none()
                if user and user.group:
                    group_name = user.group.name

            ctx = AuthContext(
                username=username, mac_address=mac, nas_ip=nas_ip,
                auth_method=str(method.value),
                group_name=group_name, device_type=device_type,
            )
            decision = await policy_engine.evaluate(ctx, db)

        if decision.action == PolicyAction.PERMIT:
            return decision.vlan, AuthResult.SUCCESS, "", decision.policy_name, decision.reply_attributes
        if decision.action == PolicyAction.GUEST:
            return self._cfg.guest_vlan, AuthResult.SUCCESS, "GUEST access", decision.policy_name, decision.reply_attributes
        # A MAB request backed by a live captive-portal registration gets the
        # guest VLAN when no explicit policy matched. An explicit DENY policy
        # matching above still wins — only the default-deny fallthrough is
        # softened for registered guests.
        if (
            method == AuthMethod.MAB
            and has_guest_session
            and decision.policy_name == "DEFAULT_DENY"
        ):
            return self._cfg.guest_vlan, AuthResult.SUCCESS, "Captive-portal guest session", "GUEST_SESSION", {}
        return None, AuthResult.FAILURE, f"Policy denied: {decision.reason}", decision.policy_name, {}

    # ---- Vendor / custom reply attributes ----

    def _attach_reply_attributes(self, reply, attrs: dict, username: str) -> None:
        """Attach per-policy reply attributes (standard or VSA) to an
        Access-Accept. Unknown attribute names or bad values are logged and
        skipped — one bad attribute must not turn an Accept into silence."""
        for name, raw in (attrs or {}).items():
            values = raw if isinstance(raw, list) else [raw]
            for value in values:
                # JSON can't distinguish "10" from 10 — try the raw value,
                # then the opposite coercion, before giving up.
                candidates: list = [value]
                if isinstance(value, str) and value.lstrip("-").isdigit():
                    candidates.append(int(value))
                elif isinstance(value, int):
                    candidates.append(str(value))
                last_exc: Exception | None = None
                for candidate in candidates:
                    try:
                        reply.AddAttribute(str(name), candidate)
                        break
                    except Exception as exc:
                        last_exc = exc
                else:
                    log.error(
                        "Failed to attach reply attribute %s=%r for user=%r: %s "
                        "— check the name exists in naco/radius/dictionary",
                        name, value, username, last_exc,
                    )

    # ---- Sync bridge ----

    def _run_sync(self, coro) -> Any:
        if self._loop is None:
            raise RuntimeError("RADIUS server event loop not initialised")
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        return future.result(timeout=10)

    # ---- Auth logging ----

    def _log_auth(
        self, pkt, username, method, result, reason,
        policy_name: str = "", vlan: int | None = None,
    ) -> None:
        nas_ip  = pkt.source[0]
        mac_raw = pkt.get("Calling-Station-Id", [""])[0]
        try:
            mac = normalise_mac(mac_raw)
        except ValueError:
            mac = mac_raw

        if self._loop:
            asyncio.run_coroutine_threadsafe(
                self._write_auth_log(username, mac, nas_ip, method, result, reason, policy_name, vlan),
                self._loop,
            )

    async def _write_auth_log(
        self, username, mac, nas_ip, method, result, reason,
        policy_name: str = "", vlan: int | None = None,
    ) -> None:
        async with AsyncSessionLocal() as db:
            db.add(AuthLog(
                username=username, mac_address=mac, nas_ip=nas_ip,
                auth_method=method, result=result, reason=reason,
                policy_name=policy_name, vlan=vlan,
            ))
            await db.commit()

    # ---- Event publishing ----

    def _publish(self, username, pkt, method, result, reason) -> None:
        nas_ip  = pkt.source[0]
        mac_raw = pkt.get("Calling-Station-Id", [""])[0]
        etype   = EventType.AUTH_SUCCESS if result == AuthResult.SUCCESS else EventType.AUTH_FAILURE
        bus.publish_sync(Event(etype, data={
            "username": username, "mac": mac_raw,
            "nas_ip": nas_ip, "method": str(method),
            "reason": reason,
        }))


# ---------------------------------------------------------------------------
# DB helper for NAS client loading
# ---------------------------------------------------------------------------

async def _has_active_guest_session(db, mac: str) -> bool:
    """True if *mac* holds an unexpired, active captive-portal guest session."""
    from sqlalchemy import select

    from naco.core.utils import utcnow
    from naco.db.models import GuestSession

    if not mac:
        return False
    stmt = (
        select(GuestSession.id)
        .where(
            GuestSession.mac_address == mac,
            GuestSession.active,
            GuestSession.expires_at > utcnow(),
        )
        .limit(1)
    )
    return (await db.execute(stmt)).scalar_one_or_none() is not None


async def _load_db_nas_clients() -> list[tuple[str, str]]:
    from sqlalchemy import select
    async with AsyncSessionLocal() as db:
        stmt = select(NasClient).where(NasClient.enabled)
        clients = (await db.execute(stmt)).scalars().all()
        return [(c.ip_address, c.secret) for c in clients]


async def _client_refresh_loop(server: NACoRadiusServer) -> None:
    """Periodic NAS reload. Without this, a freshly-added first NAS is never
    picked up: pyrad drops packets from unknown hosts *before*
    ``HandleAuthPacket`` runs, so the packet-driven reload can't fire."""
    while True:
        await asyncio.sleep(server._client_reload_interval)
        try:
            server._apply_db_clients(await _load_db_nas_clients())
        except Exception as exc:
            log.warning("Background NAS client refresh failed: %s", exc)


# ---------------------------------------------------------------------------
# Public launchers
# ---------------------------------------------------------------------------

def run_radius_server(loop: asyncio.AbstractEventLoop) -> None:
    """Start the (blocking) RADIUS server in the calling thread."""
    global _active_radius_server
    cfg = get_config().radius
    server = NACoRadiusServer()
    server._loop = loop
    _active_radius_server = server

    try:
        db_clients = asyncio.run_coroutine_threadsafe(
            _load_db_nas_clients(), loop,
        ).result(timeout=10)
        for ip, secret in db_clients:
            if ip not in server._clients:
                server._clients[ip] = secret
                server._client_msgauth.setdefault(ip, cfg.require_message_authenticator)
                server.hosts[ip] = pyrad.server.RemoteHost(ip, secret.encode(), ip)
        if db_clients:
            log.info("Loaded %d NAS client(s) from database", len(db_clients))
    except Exception as exc:
        log.warning("Could not load NAS clients from DB: %s", exc)

    refresh_future = asyncio.run_coroutine_threadsafe(
        _client_refresh_loop(server), loop,
    )

    server.BindToAddress(cfg.host)
    log.info(
        "RADIUS server listening on %s:%d (auth) %s:%d (acct)",
        cfg.host, cfg.auth_port, cfg.host, cfg.acct_port,
    )
    try:
        server.Run()
    finally:
        refresh_future.cancel()


async def run_radius_server_async() -> None:
    """Async-friendly launcher.

    pyrad's ``server.Server.Run()`` is a blocking ``select`` loop, so we run
    it in an executor thread. The whole sub-tree (DB, policy engine) remains
    async — the RADIUS thread bridges into the main event loop via
    ``asyncio.run_coroutine_threadsafe``.

    A future refactor can move to ``pyrad.server_async`` to drop the thread.
    """
    global _active_radius_server
    loop = asyncio.get_running_loop()

    def _runner() -> None:
        run_radius_server(loop)

    thread_task = loop.run_in_executor(None, _runner)
    try:
        await thread_task
    except asyncio.CancelledError:
        srv = _active_radius_server
        if srv is not None:
            try:
                srv._running = False
            except Exception:
                pass
        raise
