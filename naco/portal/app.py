"""
NACo Captive / Guest Portal
===========================
Mounted under ``/portal`` on the consolidated NACo app.

Guest flow
----------
  1. Guest device connects to the guest SSID / VLAN.
  2. Captive-portal redirect routes the browser to ``/portal``.
  3. Guest fills in the registration form (name + email).
  4. A timed ``GuestSession`` is persisted.
  5. The device MAC is authorised for the configured session duration.
  6. Guest is shown a success page with the Wi-Fi QR code.

CSRF model
----------
Each visitor gets an ``HttpOnly``, ``Secure``, ``SameSite=Strict`` cookie
named ``naco_portal_csrf`` containing a random 32-byte token. Every POST
form includes a hidden ``csrf_token`` whose value must equal the cookie
value byte-for-byte. The token is stable across the visitor's session,
survives server restarts (it lives in the cookie, not in process memory),
and is unaffected by NAT or shared IPs.
"""
from __future__ import annotations

import asyncio
import hmac
import os
import re
import secrets
from datetime import timedelta
from typing import Annotated

from fastapi import Depends, FastAPI, Form, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession

from naco.config import get_config
from naco.core.logger import get_logger
from naco.core.ratelimit import check_rate_limit
from naco.core.utils import client_ip, generate_token, normalise_mac, utcnow
from naco.db import get_db
from naco.db.models import GuestSession

log = get_logger(__name__)

app = FastAPI(title="NACo Guest Portal", docs_url=None, redoc_url=None)

_TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")
templates = Jinja2Templates(directory=_TEMPLATE_DIR)


# ---------------------------------------------------------------------------
# Cookie-based CSRF (no IP-derived tokens — works through NAT, shared Wi-Fi)
# ---------------------------------------------------------------------------

_CSRF_COOKIE = "naco_portal_csrf"
_CSRF_LIFETIME_SECONDS = 8 * 3600
_CSRF_TOKEN_BYTES = 32


def _csrf_token_for(request: Request) -> tuple[str, bool]:
    """Return ``(token, is_new)`` for *request*.

    If the visitor already carries a valid ``naco_portal_csrf`` cookie, the
    same value is reused so re-renders of the registration page do not
    invalidate the in-flight form. Otherwise a fresh 32-byte URL-safe token
    is minted; callers are expected to attach it via :func:`_set_csrf_cookie`.
    """
    existing = request.cookies.get(_CSRF_COOKIE, "")
    if existing and len(existing) >= 32:
        return existing, False
    return secrets.token_urlsafe(_CSRF_TOKEN_BYTES), True


def _set_csrf_cookie(request: Request, response: Response, token: str) -> None:
    is_https = (
        request.url.scheme == "https"
        or request.headers.get("x-forwarded-proto") == "https"
    )
    response.set_cookie(
        _CSRF_COOKIE, token,
        httponly=True, secure=is_https, samesite="strict",
        max_age=_CSRF_LIFETIME_SECONDS, path="/portal",
    )


def _csrf_validate(presented: str, cookie_value: str) -> bool:
    if not presented or not cookie_value:
        return False
    return hmac.compare_digest(presented.encode(), cookie_value.encode())


# ---------------------------------------------------------------------------
# Periodic cleanup: expire guest sessions whose expires_at has passed.
# Called from main.py _lifespan so it shares the application event loop.
# ---------------------------------------------------------------------------

async def expire_overdue_guest_sessions(db: AsyncSession) -> int:
    """Mark overdue guest sessions inactive; return how many were expired."""
    from sqlalchemy import update

    result = await db.execute(
        update(GuestSession)
        .where(GuestSession.active, GuestSession.expires_at <= utcnow())
        .values(active=False)
    )
    await db.commit()
    return result.rowcount or 0


async def expire_guest_sessions_loop() -> None:
    """Background task: mark overdue guest sessions inactive every 60 s."""
    from naco.db.database import AsyncSessionLocal
    while True:
        try:
            async with AsyncSessionLocal() as db:
                expired = await expire_overdue_guest_sessions(db)
                if expired:
                    log.info("Guest-session expiry: deactivated %d session(s)", expired)
        except Exception as exc:
            log.warning("Guest-session expiry cleanup failed: %s", exc)
        await asyncio.sleep(60)


# ---------------------------------------------------------------------------
# Helper: extract client MAC from request
# ---------------------------------------------------------------------------

def _get_client_mac(request: Request) -> str:
    """
    In a real deployment, the NAS/AP inserts the MAC into a custom header
    (e.g. X-Client-MAC) or uses the redirect URL as query param.
    We also support ?mac= from the iptables redirect rule.
    """
    mac_raw = (
        request.query_params.get("mac")
        or request.headers.get("X-Client-MAC", "")
    )
    try:
        return normalise_mac(mac_raw) if mac_raw else ""
    except ValueError:
        return ""


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

def _portal_error(request: Request, *, mac: str, message: str) -> HTMLResponse:
    cfg = get_config().portal
    token, is_new = _csrf_token_for(request)
    resp = templates.TemplateResponse(request, "portal.html", {
        "request": request, "mac": mac, "ssid": cfg.guest_ssid,
        "error": message, "redirect": "", "csrf_token": token,
    })
    if is_new:
        _set_csrf_cookie(request, resp, token)
    return resp


@app.get("/", response_class=HTMLResponse)
async def landing(request: Request):
    cfg = get_config().portal
    mac = _get_client_mac(request)
    token, is_new = _csrf_token_for(request)
    resp = templates.TemplateResponse(request, "portal.html", {
        "request":    request,
        "mac":        mac,
        "ssid":       cfg.guest_ssid,
        "redirect":   request.query_params.get("redirect", "http://example.com"),
        "csrf_token": token,
    })
    if is_new:
        _set_csrf_cookie(request, resp, token)
    return resp


@app.post("/register", response_class=HTMLResponse)
async def register(
    request:      Request,
    full_name:    Annotated[str, Form()],
    email:        Annotated[str, Form()],
    mac:          Annotated[str, Form()] = "",
    csrf_token:   Annotated[str, Form()] = "",
    db:           AsyncSession = Depends(get_db),
):
    cfg = get_config().portal
    ip  = client_ip(request)

    cookie_token = request.cookies.get(_CSRF_COOKIE, "")
    if not _csrf_validate(csrf_token, cookie_token):
        return _portal_error(request, mac=mac,
            message="Invalid form submission. Please reload and try again.")

    if not check_rate_limit(f"portal:{ip}"):
        return _portal_error(request, mac=mac,
            message="Too many registration attempts. Please try again later.")

    if not full_name.strip() or len(full_name) > 128:
        return _portal_error(request, mac=mac, message="Please enter your full name.")
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        return _portal_error(request, mac=mac, message="Please enter a valid email address.")

    try:
        norm_mac = normalise_mac(mac) if mac else _get_client_mac(request)
    except ValueError:
        norm_mac = ""

    if not norm_mac:
        return _portal_error(request, mac=mac,
            message="Could not determine your device MAC address.")

    # Expire any existing active sessions for this MAC atomically
    if norm_mac:
        from sqlalchemy import update
        await db.execute(
            update(GuestSession)
            .where(GuestSession.mac_address == norm_mac, GuestSession.active)
            .values(active=False)
        )
        await db.flush()

    expires_at = utcnow() + timedelta(hours=cfg.session_hours)
    session = GuestSession(
        token       = generate_token(32),
        email       = email.strip().lower()[:128],
        full_name   = full_name.strip()[:128],
        mac_address = norm_mac,
        ip_address  = ip,
        expires_at  = expires_at,
    )
    db.add(session)
    await db.commit()

    log.info("Guest registered: name=%r email=%r mac=%s expires=%s",
             full_name, email, norm_mac, expires_at.isoformat())

    return RedirectResponse(
        url=f"/portal/success?token={session.token}",
        status_code=303,
    )


@app.get("/success", response_class=HTMLResponse)
async def success(request: Request, token: str = "", db: AsyncSession = Depends(get_db)):
    from sqlalchemy import select
    cfg = get_config().portal

    # Verify the token maps to a real, active session
    sess = None
    if token:
        stmt = select(GuestSession).where(GuestSession.token == token)
        sess = (await db.execute(stmt)).scalar_one_or_none()

    if not sess:
        return RedirectResponse(url="/portal/", status_code=302)

    # Generate QR code image from server-side config — PSK never leaves the server
    qr_base64 = ""
    import base64
    import io

    import qrcode
    qr_payload = f"WIFI:T:WPA;S:{cfg.guest_ssid};P:{cfg.guest_psk};;"
    img = qrcode.make(qr_payload)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_base64 = base64.b64encode(buf.getvalue()).decode()

    return templates.TemplateResponse(request, "success.html", {
        "request":   request,
        "ssid":      cfg.guest_ssid,
        "qr_base64": qr_base64,
    })


@app.get("/status")
async def session_status(mac: str, db: AsyncSession = Depends(get_db)):
    from sqlalchemy import select
    try:
        norm_mac = normalise_mac(mac)
    except ValueError:
        return {"active": False, "error": "invalid MAC"}

    stmt = (
        select(GuestSession)
        .where(
            GuestSession.mac_address == norm_mac,
            GuestSession.active,
            GuestSession.expires_at > utcnow(),
        )
        .order_by(GuestSession.created_at.desc())
    )
    sess = (await db.execute(stmt)).scalar_one_or_none()
    if sess:
        return {"active": True, "expires_at": sess.expires_at.isoformat()}
    return {"active": False}
