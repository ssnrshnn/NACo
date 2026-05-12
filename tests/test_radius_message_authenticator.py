"""
RFC 3579 §3.2 / BlastRADIUS (CVE-2024-3596) — Message-Authenticator validation.

These tests exercise :pyfunc:`naco.radius.server.NACoRadiusServer._message_authenticator_valid`
directly by constructing real pyrad ``AuthPacket`` instances and feeding them
through the validator with known-good, tampered, and absent HMACs.
"""
from __future__ import annotations

import hashlib
import hmac as _hmac

import pyrad.packet
import pytest

from naco.radius.server import NACoRadiusServer

NAS_IP = "127.0.0.1"
SECRET = b"testing123"
_MA = 80


def _compute_ma(secret: bytes, packet: pyrad.packet.AuthPacket) -> bytes:
    """Compute the canonical RFC 3579 Message-Authenticator for *packet*."""
    saved = packet[_MA]
    packet[_MA] = [b"\x00" * 16]
    try:
        raw = packet.RequestPacket()
    finally:
        packet[_MA] = saved
    return _hmac.new(secret, raw, hashlib.md5).digest()


@pytest.fixture(scope="module")
def server() -> NACoRadiusServer:
    """A real ``NACoRadiusServer`` configured from ``tests/test_config.yaml``.

    The constructor does not bind any sockets when ``addresses=[]`` so the
    instance is safe to use inside the test sandbox.
    """
    return NACoRadiusServer()


def _build_pkt(server: NACoRadiusServer, with_ma: bytes | None = b"valid"
              ) -> pyrad.packet.AuthPacket:
    """Build an Access-Request from NAS_IP with optional Message-Authenticator.

    * ``with_ma == b"valid"`` — attach the correct MA (default).
    * ``with_ma is None``     — no Message-Authenticator attribute at all.
    * ``with_ma == b"<16b>"`` — attach the literal bytes instead.
    """
    pkt = pyrad.packet.AuthPacket(secret=SECRET, id=42, dict=server.dict)
    pkt.authenticator = bytes(range(16))
    pkt.source = (NAS_IP, 12345)
    pkt["User-Name"] = "alice"

    if with_ma is None:
        return pkt

    pkt[_MA] = [b"\x00" * 16]
    if with_ma == b"valid":
        pkt[_MA] = [_compute_ma(SECRET, pkt)]
    else:
        pkt[_MA] = [with_ma]
    return pkt


class TestMessageAuthenticator:
    def test_valid_ma_passes(self, server: NACoRadiusServer):
        pkt = _build_pkt(server, b"valid")
        assert server._message_authenticator_valid(pkt, NAS_IP) is True

    def test_tampered_ma_fails(self, server: NACoRadiusServer):
        pkt = _build_pkt(server, b"\xff" * 16)
        assert server._message_authenticator_valid(pkt, NAS_IP) is False

    def test_wrong_length_ma_fails(self, server: NACoRadiusServer):
        pkt = _build_pkt(server, b"\x00" * 8)
        assert server._message_authenticator_valid(pkt, NAS_IP) is False

    def test_missing_ma_with_enforcement_fails(self, server: NACoRadiusServer):
        """No MA attribute + require_message_authenticator=True ⇒ reject.

        This is the core BlastRADIUS mitigation: silently accepting requests
        without an MA would allow a man-in-the-middle to craft a valid
        Access-Accept once it sees the response Authenticator.
        """
        pkt = _build_pkt(server, None)
        server._client_msgauth[NAS_IP] = True
        assert server._message_authenticator_valid(pkt, NAS_IP) is False

    def test_missing_ma_without_enforcement_passes(self, server: NACoRadiusServer):
        """When the operator opts the NAS out of enforcement, missing MA = pass."""
        pkt = _build_pkt(server, None)
        server._client_msgauth[NAS_IP] = False
        try:
            assert server._message_authenticator_valid(pkt, NAS_IP) is True
        finally:
            server._client_msgauth[NAS_IP] = True
