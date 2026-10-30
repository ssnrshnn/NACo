"""TOTP (RFC 6238) with replay protection and one-time recovery codes."""
from __future__ import annotations

import hmac
import secrets
import time

import pyotp
import qrcode
import qrcode.image.svg

STEP = 30
RECOVERY_CODES = 10


def new_secret() -> str:
    return pyotp.random_base32()


def provisioning(secret: str, username: str, issuer: str = "NACo") -> tuple[str, str]:
    """(otpauth:// URI, inline SVG QR code)."""
    uri = pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)
    svg = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage, box_size=8, border=2)
    return uri, svg.to_string(encoding="unicode")


def current_step(now: float | None = None) -> int:
    return int((time.time() if now is None else now) // STEP)


def match(secret: str, code: str, last_step: int | None, now: float | None = None) -> int | None:
    """Matching time step (±1 for clock drift) newer than ``last_step``, else None."""
    code = code.strip().replace(" ", "")
    if len(code) != 6 or not code.isdigit():
        return None
    totp = pyotp.TOTP(secret)
    step = current_step(now)
    for candidate in (step - 1, step, step + 1):
        if last_step is not None and candidate <= last_step:
            continue
        if hmac.compare_digest(totp.generate_otp(candidate), code):
            return candidate
    return None


def new_recovery_codes() -> list[str]:
    alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
    return ["".join(secrets.choice(alphabet) for _ in range(4)) + "-" +
            "".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(RECOVERY_CODES)]


def looks_like_recovery_code(code: str) -> bool:
    code = code.strip().lower()
    return len(code) == 9 and code[4] == "-"
