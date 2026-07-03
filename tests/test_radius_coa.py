"""
RFC 5176 CoA — Response Authenticator forgery resistance.

The ``Disconnect-Request`` we send carries a freshly-computed request
authenticator. A genuine response must echo back
``MD5(Code + ID + Length + RequestAuth + Attributes + Secret)``.

An attacker without the shared secret cannot forge such a response, so any
inbound packet whose authenticator does not match must be treated as
hostile and discarded.
"""
from __future__ import annotations

import hashlib
import struct

from naco.radius.coa import (
    DISCONNECT_ACK,
    _build_disconnect_request,
    verify_response_authenticator,
)

SECRET = "testing123"
NAS_IP = "10.0.0.1"


def _forge_response(
    request_pkt: bytes,
    *,
    code: int = DISCONNECT_ACK,
    secret: str = SECRET,
    tamper_auth: bool = False,
    tamper_attrs: bool = False,
) -> bytes:
    """Build a syntactically valid response.

    *tamper_auth*  → overwrite the (otherwise correct) authenticator with
                     ``\\xff * 16``.
    *tamper_attrs* → leave the authenticator alone but flip a byte in the
                     attributes (which should invalidate the MD5).
    """
    ident = request_pkt[1]
    attrs = b""
    length = 20 + len(attrs)
    header = struct.pack("!BBH", code, ident, length)
    req_auth = request_pkt[4:20]

    if tamper_auth:
        return header + (b"\xff" * 16) + attrs

    # Honest authenticator
    payload = header + req_auth + attrs + secret.encode()
    auth = hashlib.md5(payload).digest()

    if tamper_attrs:
        attrs = b"\x00\x02"          # one bogus attribute byte
        length = 20 + len(attrs)
        header = struct.pack("!BBH", code, ident, length)
        # auth still computed from original (empty-attrs) payload

    return header + auth + attrs


class TestVerifyResponseAuthenticator:
    def test_honest_response_passes(self):
        req = _build_disconnect_request("sess-1", NAS_IP, "alice", SECRET)
        resp = _forge_response(req)
        assert verify_response_authenticator(req, resp, SECRET) is True

    def test_forged_authenticator_rejected(self):
        req = _build_disconnect_request("sess-1", NAS_IP, "alice", SECRET)
        resp = _forge_response(req, tamper_auth=True)
        assert verify_response_authenticator(req, resp, SECRET) is False

    def test_tampered_attributes_rejected(self):
        req = _build_disconnect_request("sess-1", NAS_IP, "alice", SECRET)
        resp = _forge_response(req, tamper_attrs=True)
        assert verify_response_authenticator(req, resp, SECRET) is False

    def test_wrong_secret_rejected(self):
        req = _build_disconnect_request("sess-1", NAS_IP, "alice", SECRET)
        resp = _forge_response(req)
        assert verify_response_authenticator(req, resp, "wrong-secret") is False

    def test_short_response_rejected(self):
        req = _build_disconnect_request("sess-1", NAS_IP, "alice", SECRET)
        assert verify_response_authenticator(req, b"\x29\x01\x00\x14", SECRET) is False

    def test_short_request_rejected(self):
        resp = b"\x29\x01\x00\x14" + (b"\x00" * 16)
        assert verify_response_authenticator(b"", resp, SECRET) is False

    def test_length_field_beyond_buffer_rejected(self):
        """A response whose declared length exceeds the buffer must not crash."""
        req = _build_disconnect_request("sess-1", NAS_IP, "alice", SECRET)
        bogus = struct.pack("!BBH", 41, req[1], 9999) + (b"\x00" * 16)
        assert verify_response_authenticator(req, bogus, SECRET) is False
