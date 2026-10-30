"""Admin pages: server-rendered shells; data and every change go through /api/v1."""
from __future__ import annotations

import re
from dataclasses import dataclass
from importlib import resources
from typing import Any
from urllib.parse import quote

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession

from naco import __version__
from naco.api import sessions
from naco.api.deps import Principal, client_ip, restriction
from naco.config import get_config
from naco.db.engine import get_db
from naco.db.models import AdminRole

router = APIRouter(include_in_schema=False)
templates = Jinja2Templates(directory=str(resources.files("naco") / "web" / "templates"))

V, O, S = AdminRole.VIEWER, AdminRole.OPERATOR, AdminRole.SUPERUSER  # noqa: E741


@dataclass(frozen=True)
class Page:
    path: str
    title: str
    icon: str
    key: str
    role: AdminRole
    intro: str = ""


NAV: list[tuple[str, list[Page]]] = [
    ("Overview", [
        Page("/", "Overview", "speedometer2", "dashboard", V),
    ]),
    ("Identity", [
        Page("/users", "Users", "people", "users", V, "People who sign in to the network (802.1X, VPN, switch logins)."),
        Page("/groups", "Groups", "people-fill", "groups", V,
             "Groups drive policy decisions; a device-admin profile lets members manage switches over TACACS+."),
        Page("/devices", "Devices", "pc-display", "devices", V,
             "Every MAC address NACo has seen. Approve devices for MAB, block anything that should never connect."),
    ]),
    ("Access", [
        Page("/policies", "Policies", "shield-check", "policies", V,
             "Evaluated top to bottom; the first policy whose conditions all match decides. Nothing matched → denied."),
        Page("/simulator", "Simulator", "signpost-split", "simulator", V,
             "See exactly which policy would decide a request — and why — without touching the network."),
    ]),
    ("Network", [
        Page("/nas", "RADIUS clients", "router", "nas", V,
             "Switches, access points and controllers allowed to send RADIUS to NACo."),
        Page("/tacacs-clients", "TACACS+ clients", "terminal", "tacacs", V,
             "Network devices that authenticate administrators against NACo over TACACS+."),
        Page("/command-sets", "Command sets", "list-check", "command_sets", V,
             "Which CLI commands device administrators may run. Rules match the full command line, top to bottom."),
    ]),
    ("Monitoring", [
        Page("/sessions", "Sessions", "activity", "sessions", V, "Who is connected right now, live from accounting."),
        Page("/guests", "Guests", "person-badge", "guests", V, "Time-limited guest registrations from the portal or the help desk."),
        Page("/logs", "Logs", "journal-text", "logs", V, "Every RADIUS decision and TACACS+ request, with the reason."),
    ]),
    ("Administration", [
        Page("/admins", "Administrators", "person-gear", "admins", S, "Accounts that can sign in to this panel."),
        Page("/tokens", "API tokens", "key", "tokens", S, "Long-lived credentials for automation, each limited to a role."),
        Page("/audit", "Audit log", "clock-history", "audit", O, "Every change, by whom, from where."),
        Page("/system", "System", "info-circle", "system", V),
    ]),
]
ACCOUNT = Page("/account", "My account", "person-circle", "account", V, "Your password, two-factor authentication and sessions.")
PAGES = [p for _, items in NAV for p in items] + [ACCOUNT]


async def _principal(request: Request, db: AsyncSession) -> Principal | None:
    found = await sessions.resolve(db, request.cookies.get(sessions.COOKIE))
    if found is None:
        return None
    session, admin = found
    principal = Principal(kind="session", username=admin.username, role=admin.role, admin_id=admin.id,
                          session_id=session.id, csrf_token=session.csrf_token, restricted=restriction(admin),
                          ip=client_ip(request))
    await db.commit()
    return principal


_SAFE_PATH = re.compile(r"/(?![/\\])[\x21-\x7e]*")


def _safe_next(target: str | None) -> str:
    """Only same-site paths — never //host or scheme://. Browsers drop tabs and
    line breaks from URLs (slash, tab, slash becomes "//"), so only printable
    ASCII without spaces or backslashes is accepted."""
    if not target or not _SAFE_PATH.fullmatch(target) or "\\" in target:
        return "/"
    return target


def _base(request: Request, principal: Principal | None, **extra: Any) -> dict[str, Any]:
    cfg = get_config()
    nav = []
    if principal is not None:
        nav = [(section, [p for p in items if principal.role.allows(p.role)]) for section, items in NAV]
        nav = [(section, items) for section, items in nav if items]
    return {"user": principal, "nav": nav, "path": request.url.path, "tz": cfg.server.timezone,
            "server_name": cfg.server.name, "version": __version__, **extra}


def render(request: Request, name: str, status: int = 200, **context: Any) -> HTMLResponse:
    return templates.TemplateResponse(request, name, context, status_code=status)


def _make(page: Page) -> Any:
    async def view(request: Request, db: AsyncSession = Depends(get_db)) -> Response:
        principal = await _principal(request, db)
        if principal is None:
            return RedirectResponse(f"/login?next={quote(request.url.path)}", status_code=303)
        if principal.restricted:
            return RedirectResponse("/setup", status_code=303)
        if not principal.role.allows(page.role):
            return render(request, "error.html", 403, **_base(request, principal, code=403, title="Not allowed",
                          message=f"This page needs the {page.role.value.lower()} role."))
        return render(request, "page.html", **_base(request, principal, page=page))
    view.__name__ = f"page_{page.key}"
    return view


for _page in PAGES:
    router.add_api_route(_page.path, _make(_page), methods=["GET"], response_class=HTMLResponse)


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, next: str | None = None, db: AsyncSession = Depends(get_db)) -> Response:
    principal = await _principal(request, db)
    target = _safe_next(next)
    if principal is not None:
        return RedirectResponse("/setup" if principal.restricted else target, status_code=303)
    return render(request, "login.html", **_base(request, None, next=target))


@router.get("/setup", response_class=HTMLResponse)
async def setup_page(request: Request, db: AsyncSession = Depends(get_db)) -> Response:
    principal = await _principal(request, db)
    if principal is None:
        return RedirectResponse("/login", status_code=303)
    if not principal.restricted:
        return RedirectResponse("/", status_code=303)
    return render(request, "setup.html", **_base(request, principal, step=principal.restricted))
