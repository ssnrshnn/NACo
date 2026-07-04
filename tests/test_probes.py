"""Synthetic AAA probes (naco.probe) — packet building, parsing, and
round-trips against in-process fake servers."""
from __future__ import annotations

import socket
import struct
import threading

import pytest

from naco.probe import _build_pap_start, _parse_authen_reply, probe_radius, probe_tacacs
from naco.tacacs.server import (
    TAC_PLUS_AUTHEN,
    TAC_PLUS_AUTHEN_STATUS_FAIL,
    TAC_PLUS_AUTHEN_STATUS_PASS,
    TAC_PLUS_AUTHEN_TYPE_PAP,
    TacacsHeader,
    _crypt,
)

# ---------------------------------------------------------------------------
# Packet helpers
# ---------------------------------------------------------------------------

class TestPacketHelpers:
    def test_pap_start_layout_matches_server_parser(self):
        """Parse the body exactly the way TacacsSession._handle_authen_start does."""
        body = _build_pap_start("alice", "s3cret", rem_addr="10.1.2.3")
        _action, _priv, authen_type, _svc = struct.unpack("!BBBB", body[0:4])
        user_len, port_len, rem_len, data_len = struct.unpack("!BBBB", body[4:8])
        assert authen_type == TAC_PLUS_AUTHEN_TYPE_PAP
        assert 8 + user_len + port_len + rem_len + data_len == len(body)
        off = 8
        assert body[off:off + user_len] == b"alice"; off += user_len
        off += port_len
        assert body[off:off + rem_len] == b"10.1.2.3"; off += rem_len
        assert body[off:off + data_len] == b"s3cret"

    def test_parse_authen_reply(self):
        # Same shape TacacsSession._send_authen_reply produces
        msg = b"Authentication failed"
        body = struct.pack("!BBHH", TAC_PLUS_AUTHEN_STATUS_FAIL, 0, len(msg), 0) + msg
        status, text = _parse_authen_reply(body)
        assert status == TAC_PLUS_AUTHEN_STATUS_FAIL
        assert text == "Authentication failed"

    def test_parse_authen_reply_too_short(self):
        with pytest.raises(ValueError):
            _parse_authen_reply(b"\x01")


# ---------------------------------------------------------------------------
# TACACS+ probe against a fake TCP server (uses the real crypt helpers)
# ---------------------------------------------------------------------------

def _fake_tacacs_server(key: str, status: int, msg: str) -> tuple[str, int, threading.Thread, dict]:
    """One-shot TCP server that decrypts the START and replies with status."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    host, port = srv.getsockname()
    seen: dict = {}

    def _serve():
        conn, _ = srv.accept()
        with conn:
            raw = conn.recv(4096)
            hdr = TacacsHeader.decode(raw[:12])
            body = _crypt(raw[12:12 + hdr.length], key.encode(),
                          hdr.session_id, hdr.version, hdr.seq_no)
            # Record what we saw — asserting in a thread only warns. The
            # wrong-key test decrypts to garbage on purpose, so no asserts.
            seen["decrypted"] = body

            msg_b = msg.encode()
            reply_body = struct.pack("!BBHH", status, 0, len(msg_b), 0) + msg_b
            reply_hdr = TacacsHeader(
                version=hdr.version, pkt_type=TAC_PLUS_AUTHEN, seq_no=hdr.seq_no + 1,
                flags=0, session_id=hdr.session_id, length=len(reply_body),
            )
            conn.sendall(reply_hdr.encode() + _crypt(
                reply_body, key.encode(), hdr.session_id, hdr.version, hdr.seq_no + 1))
        srv.close()

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    return host, port, t, seen


class TestTacacsProbe:
    def test_pass_reported_as_accept(self):
        host, port, t, seen = _fake_tacacs_server("k3y", TAC_PLUS_AUTHEN_STATUS_PASS, "welcome")
        out = probe_tacacs(host, port, "k3y", timeout=3.0)
        t.join(timeout=5)
        assert out["result"] == "accept"
        assert out["latency_ms"] is not None
        # The server-side decrypt saw a PAP START for the probe user.
        assert seen["decrypted"][2] == TAC_PLUS_AUTHEN_TYPE_PAP
        assert b"naco-probe" in seen["decrypted"]

    def test_fail_reported_as_reject(self):
        host, port, t, _ = _fake_tacacs_server("k3y", TAC_PLUS_AUTHEN_STATUS_FAIL, "nope")
        out = probe_tacacs(host, port, "k3y", timeout=3.0)
        t.join(timeout=5)
        assert out["result"] == "reject"
        assert out["message"] == "nope"

    def test_wrong_key_reported_as_error(self):
        """Wrong key garbles the reply body — must not crash, must not PASS."""
        host, port, t, _ = _fake_tacacs_server("right-key", TAC_PLUS_AUTHEN_STATUS_PASS, "x")
        out = probe_tacacs(host, port, "wrong-key", timeout=3.0)
        t.join(timeout=5)
        assert out["result"] in ("error", "reject")
        assert out["result"] != "accept" or out["message"] == "x"

    def test_connection_refused_is_error(self):
        # Grab a port and close it so nothing listens there.
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        out = probe_tacacs("127.0.0.1", port, "k", timeout=0.5)
        assert out["result"] in ("error", "timeout")


# ---------------------------------------------------------------------------
# RADIUS probe against a fake UDP server (pyrad on both ends)
# ---------------------------------------------------------------------------

def _fake_radius_server(secret: bytes, accept: bool) -> tuple[str, int, threading.Thread, dict]:
    import pyrad.dictionary
    import pyrad.packet

    from naco.radius.server import _DICT_PATH

    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    host, port = srv.getsockname()
    seen: dict = {}

    def _serve():
        data, addr = srv.recvfrom(4096)
        req = pyrad.packet.AuthPacket(
            packet=data, secret=secret,
            dict=pyrad.dictionary.Dictionary(_DICT_PATH),
        )
        seen["username"] = req["User-Name"][0]
        seen["password"] = req.PwDecrypt(req["User-Password"][0])
        seen["has_ma"] = "Message-Authenticator" in req
        reply = req.CreateReply()
        reply.code = pyrad.packet.AccessAccept if accept else pyrad.packet.AccessReject
        srv.sendto(reply.ReplyPacket(), addr)
        srv.close()

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    return host, port, t, seen


class TestRadiusProbe:
    def test_reject_roundtrip_and_request_shape(self):
        host, port, t, seen = _fake_radius_server(b"testing123", accept=False)
        out = probe_radius(host, port, "testing123",
                           username="alice", password="pw", timeout=3.0)
        t.join(timeout=5)
        assert out["result"] == "reject"
        assert out["latency_ms"] is not None
        assert seen["username"] == "alice"
        assert seen["password"] == "pw"        # PAP crypt round-trips
        assert seen["has_ma"] is True          # BlastRADIUS mitigation honoured

    def test_accept_roundtrip(self):
        host, port, t, _ = _fake_radius_server(b"testing123", accept=True)
        out = probe_radius(host, port, "testing123", timeout=3.0)
        t.join(timeout=5)
        assert out["result"] == "accept"

    def test_timeout_when_nobody_listens(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        out = probe_radius("127.0.0.1", port, "x", timeout=0.3, retries=0)
        assert out["result"] == "timeout"
