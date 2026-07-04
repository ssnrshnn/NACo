"""Synthetic AAA probes — back `nacoctl test-radius` / `test-tacacs`.

Monitoring needs an end-to-end signal that the *protocol* path works, not
just that the process is alive (/health/live) or that the DB answers
(/health/ready): a probe here exercises socket → packet parsing → policy
engine → response, exactly what a NAS experiences.

Both probes return a dict::

    {"result": "accept" | "reject" | "timeout" | "error",
     "latency_ms": float | None,
     "message": str}

A *reject* is a healthy outcome for monitoring purposes — it proves the
server parsed the request and evaluated policy. Callers decide what to
alert on (see the ``--expect`` CLI flag).

Note: the RADIUS server only answers clients it knows, so the probe's
source IP must be a registered NAS (quickstart registers ``127.0.0.1``
for exactly this).
"""
from __future__ import annotations

import secrets
import socket
import struct
import time
from typing import Any

# ---------------------------------------------------------------------------
# RADIUS (PAP Access-Request via pyrad, Message-Authenticator included)
# ---------------------------------------------------------------------------

def probe_radius(
    host: str,
    port: int,
    secret: str,
    username: str = "naco-probe",
    password: str = "naco-probe",  # noqa: S107 — synthetic probe credential, not a secret
    timeout: float = 3.0,
    retries: int = 1,
) -> dict[str, Any]:
    """Send one PAP Access-Request and classify the reply."""
    import pyrad.dictionary
    import pyrad.packet
    from pyrad.client import Client, Timeout

    from naco.radius.server import _DICT_PATH

    client = Client(
        server=host, authport=port, secret=secret.encode(),
        dict=pyrad.dictionary.Dictionary(_DICT_PATH),
    )
    client.timeout = timeout
    client.retries = retries

    req = client.CreateAuthPacket(code=pyrad.packet.AccessRequest)
    req["User-Name"] = username
    req["User-Password"] = req.PwCrypt(password)
    req["NAS-Identifier"] = "naco-probe"
    # The server drops Access-Requests without a Message-Authenticator by
    # default (BlastRADIUS mitigation) — always send one.
    req.add_message_authenticator()

    t0 = time.perf_counter()
    try:
        reply = client.SendPacket(req)
    except Timeout:
        return {"result": "timeout", "latency_ms": None,
                "message": f"no reply from {host}:{port} after {retries + 1} tries "
                           "(wrong secret, or source IP not a registered NAS? "
                           "the server drops both silently)"}
    except OSError as exc:
        return {"result": "error", "latency_ms": None, "message": str(exc)}
    ms = (time.perf_counter() - t0) * 1000

    if reply.code == pyrad.packet.AccessAccept:
        return {"result": "accept", "latency_ms": ms, "message": "Access-Accept"}
    if reply.code == pyrad.packet.AccessReject:
        return {"result": "reject", "latency_ms": ms, "message": "Access-Reject"}
    return {"result": "error", "latency_ms": ms,
            "message": f"unexpected reply code {reply.code}"}


# ---------------------------------------------------------------------------
# TACACS+ (PAP AUTHEN START, RFC 8907) — reuses the server's own
# header/obfuscation helpers so client and server can't drift apart.
# ---------------------------------------------------------------------------

def _build_pap_start(username: str, password: str, rem_addr: str = "naco-probe") -> bytes:
    """AUTHEN START body: PAP login at priv level 1 (RFC 8907 §5.1)."""
    from naco.tacacs.server import TAC_PLUS_AUTHEN_LOGIN, TAC_PLUS_AUTHEN_TYPE_PAP

    user_b, port_b, rem_b, data_b = (
        username.encode(), b"probe", rem_addr.encode(), password.encode()
    )
    return (
        struct.pack(
            "!BBBBBBBB",
            TAC_PLUS_AUTHEN_LOGIN, 1, TAC_PLUS_AUTHEN_TYPE_PAP, 1,
            len(user_b), len(port_b), len(rem_b), len(data_b),
        )
        + user_b + port_b + rem_b + data_b
    )


def _parse_authen_reply(body: bytes) -> tuple[int, str]:
    """AUTHEN REPLY body → (status, server_msg)."""
    if len(body) < 6:
        raise ValueError("authen reply body too short")
    status, _flags, msg_len, _data_len = struct.unpack("!BBHH", body[0:6])
    return status, body[6:6 + msg_len].decode("utf-8", errors="replace")


def probe_tacacs(
    host: str,
    port: int,
    key: str,
    username: str = "naco-probe",
    password: str = "naco-probe",  # noqa: S107 — synthetic probe credential, not a secret
    timeout: float = 3.0,
) -> dict[str, Any]:
    """One PAP authentication round-trip against a TACACS+ server."""
    from naco.tacacs.server import (
        TAC_PLUS_AUTHEN,
        TAC_PLUS_AUTHEN_STATUS_FAIL,
        TAC_PLUS_AUTHEN_STATUS_PASS,
        TAC_PLUS_VER,
        TacacsHeader,
        _crypt,
    )

    body = _build_pap_start(username, password)
    session_id = secrets.randbits(32)
    hdr = TacacsHeader(
        version=TAC_PLUS_VER, pkt_type=TAC_PLUS_AUTHEN, seq_no=1,
        flags=0, session_id=session_id, length=len(body),
    )
    payload = hdr.encode() + _crypt(body, key.encode(), session_id, TAC_PLUS_VER, 1)

    t0 = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(payload)
            raw_hdr = _recv_exact(sock, 12)
            reply_hdr = TacacsHeader.decode(raw_hdr)
            raw_body = _recv_exact(sock, reply_hdr.length)
    except TimeoutError:
        return {"result": "timeout", "latency_ms": None,
                "message": f"no reply from {host}:{port}"}
    except OSError as exc:
        return {"result": "error", "latency_ms": None, "message": str(exc)}
    ms = (time.perf_counter() - t0) * 1000

    reply_body = _crypt(raw_body, key.encode(), reply_hdr.session_id,
                        reply_hdr.version, reply_hdr.seq_no)
    try:
        status, msg = _parse_authen_reply(reply_body)
    except ValueError as exc:
        return {"result": "error", "latency_ms": ms,
                "message": f"{exc} (wrong shared key?)"}

    if status == TAC_PLUS_AUTHEN_STATUS_PASS:
        return {"result": "accept", "latency_ms": ms, "message": msg or "PASS"}
    if status == TAC_PLUS_AUTHEN_STATUS_FAIL:
        return {"result": "reject", "latency_ms": ms, "message": msg or "FAIL"}
    return {"result": "error", "latency_ms": ms,
            "message": f"status 0x{status:02x}: {msg} (wrong shared key?)"}


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise OSError("connection closed by server")
        buf += chunk
    return buf
