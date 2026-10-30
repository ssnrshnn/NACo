"""Guest portal — central web authentication (CWA).

A guest on the portal VLAN opens /portal. The device is identified from the
browser's IP address through the RADIUS session NACo saw for it (Framed-IP
from accounting) — never from anything the browser sends. Accepting the
terms registers that MAC as a guest for ``portal.session_hours`` and CoA
re-evaluation moves the device to whatever the "guest" policy grants.

Served over plain HTTP too (captive-portal detection does not follow
HTTPS), so the form is protected by a double-submit cookie plus an Origin
check rather than an admin session.
"""
from __future__ import annotations

import hmac
import secrets
from dataclasses import dataclass
from datetime import timedelta
from importlib import resources
from typing import Any

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from naco.config import PortalConfig, get_config
from naco.core.ratelimit import SlidingWindow
from naco.core.timeutil import to_local, utcnow
from naco.db.engine import get_db
from naco.db.models import Device, DeviceStatus, GuestRegistration, RadiusSession
from naco.radius.reevaluate import reevaluator

router = APIRouter(prefix="/portal", include_in_schema=False)
templates = Jinja2Templates(directory=str(resources.files("naco") / "portal" / "templates"))

CSRF_COOKIE = "naco_portal"
_attempts = SlidingWindow(limit=10, window_seconds=600)


def reset_rate_limit() -> None:
    _attempts._hits.clear()


@dataclass(frozen=True)
class Guest:
    mac: str
    nas_ip: str
    blocked: bool


async def identify(db: AsyncSession, client_ip: str, cfg: PortalConfig) -> Guest | None:
    """The device behind this IP, from its live RADIUS session."""
    if not client_ip:
        return None
    since = utcnow() - timedelta(minutes=cfg.match_window_minutes)
    session = (await db.execute(
        select(RadiusSession).where(RadiusSession.framed_ip == client_ip, RadiusSession.mac_address != "",
                                    RadiusSession.updated_at >= since)
        .order_by(RadiusSession.updated_at.desc()).limit(1)
    )).scalar_one_or_none()
    if session is None:
        return None
    device = (await db.execute(select(Device).where(Device.mac_address == session.mac_address))).scalar_one_or_none()
    return Guest(session.mac_address, session.nas_ip, device is not None and device.status is DeviceStatus.BLOCKED)


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else ""


def _render(request: Request, name: str, status: int = 200, **context: Any) -> HTMLResponse:
    cfg = get_config().portal
    return templates.TemplateResponse(request, name, {"org": cfg.organization, **context}, status_code=status)


def _enabled() -> PortalConfig:
    cfg = get_config().portal
    if not cfg.enabled:
        from naco.api.errors import ApiError
        raise ApiError(404, "not found")
    return cfg


@router.get("", response_class=HTMLResponse)
@router.get("/", response_class=HTMLResponse)
async def page(request: Request, cfg: PortalConfig = Depends(_enabled),
               db: AsyncSession = Depends(get_db)) -> Response:
    guest = await identify(db, _client_ip(request), cfg)
    if guest is None:
        return _render(request, "waiting.html")
    if guest.blocked:
        return _render(request, "refused.html", 403)
    token = secrets.token_urlsafe(24)
    response = _render(request, "register.html", terms=cfg.terms, needs_code=bool(cfg.access_code),
                       hours=cfg.session_hours, csrf=token)
    response.set_cookie(CSRF_COOKIE, token, httponly=True, samesite="strict", path="/portal",
                        secure=request.url.scheme == "https", max_age=1800)
    return response


@router.post("/register", response_class=HTMLResponse)
async def register(request: Request, csrf: str = Form(""), accept: str = Form(""), code: str = Form(""),
                   full_name: str = Form("", max_length=128), email: str = Form("", max_length=128),
                   cfg: PortalConfig = Depends(_enabled), db: AsyncSession = Depends(get_db)) -> Response:
    ip = _client_ip(request)
    cookie = request.cookies.get(CSRF_COOKIE, "")
    origin = request.headers.get("origin")
    if not cookie or not hmac.compare_digest(cookie.encode(), csrf.encode()) or \
            (origin is not None and origin != f"{request.url.scheme}://{request.headers.get('host', '')}"):
        return _render(request, "message.html", 403, title="Please try again",
                       text="Your session expired. Reload the page and accept the terms again.")
    if not _attempts.hit(ip):
        return _render(request, "message.html", 429, title="Too many attempts",
                       text="Please wait a few minutes and try again.")
    guest = await identify(db, ip, cfg)
    if guest is None:
        return _render(request, "waiting.html")
    if guest.blocked:
        return _render(request, "refused.html", 403)
    if accept != "yes":
        return _render(request, "register.html", 422, terms=cfg.terms, needs_code=bool(cfg.access_code),
                       hours=cfg.session_hours, csrf=csrf, error="Please accept the terms to continue.")
    if cfg.access_code and not hmac.compare_digest(code.strip().encode(), cfg.access_code.encode()):
        return _render(request, "register.html", 422, terms=cfg.terms, needs_code=True, hours=cfg.session_hours,
                       csrf=csrf, error="That access code is not right.")

    now = utcnow()
    expires = now + timedelta(hours=cfg.session_hours)
    if (await db.execute(select(Device).where(Device.mac_address == guest.mac))).scalar_one_or_none() is None:
        from naco.core.oui import vendor_for
        db.add(Device(mac_address=guest.mac, vendor=vendor_for(guest.mac), last_nas_ip=guest.nas_ip))
    db.add(GuestRegistration(mac_address=guest.mac, full_name=full_name.strip(), email=email.strip(),
                             nas_ip=guest.nas_ip, client_ip=ip, created_by="portal", created_at=now,
                             expires_at=expires))
    await db.commit()
    reevaluator.schedule(f"portal registration {guest.mac}")
    response = _render(request, "done.html", until=to_local(expires).strftime("%H:%M"))
    response.delete_cookie(CSRF_COOKIE, path="/portal")
    return response
