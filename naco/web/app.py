"""
NACo Web Admin UI
====================
Server-side rendered FastAPI app with Jinja2 + Bootstrap 5 dark theme.
Runs on port 8080 (configurable).

Routes
------
  GET  /login                  – Login page
  POST /login                  – Submit login
  GET  /logout                 – Clear session
  GET  /                       – Dashboard
  GET  /users                  – User management
  GET  /groups                 – Group management
  POST /groups                 – Create group
  POST /groups/{id}/delete     – Delete group
  GET  /devices                – Device inventory
  GET  /policies               – Policy management
  GET  /logs                   – Auth log viewer
  GET  /logs/tacacs            – TACACS+ log viewer
  GET  /sessions               – Active RADIUS sessions
  DELETE /sessions/{id}        – Force-terminate session
  GET  /guests                 – Guest sessions
  GET  /radius-clients         – RADIUS NAS client management
  POST /radius-clients         – Add NAS client
  POST /radius-clients/{id}/delete – Remove NAS client
  GET  /tacacs-clients         – TACACS+ client management
  POST /tacacs-clients         – Add TACACS+ client
  POST /tacacs-clients/{id}/delete – Remove TACACS+ client
  GET  /vlans                  – VLAN mapping management
  POST /vlans                  – Add VLAN mapping
  POST /vlans/{id}/delete      – Remove VLAN mapping
  GET  /admin-users            – Admin account management
  POST /admin-users            – Create admin account
  POST /admin-users/{id}/delete – Delete admin account
  POST /admin-users/{id}/password – Change admin password
  GET  /settings               – Editable system settings
  POST /settings/save          – Save config section
  GET  /system                 – System status (services, logs)
"""
from __future__ import annotations

import asyncio
import functools
import os
import subprocess
from datetime import UTC, datetime

import jwt
from fastapi import Depends, FastAPI, Form, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from naco.api.auth import (
    has_role,
    hash_password,
    needs_rehash,
    verify_password_async,
)
from naco.config import get_config
from naco.db import get_db
from naco.db.models import (
    ActiveSession,
    AdminRole,
    AdminUser,
    AuthLog,
    AuthResult,
    CommandSet,
    Device,
    Group,
    GuestSession,
    NasClient,
    Policy,
    TacacsClient,
    TacacsLog,
    User,
    VlanMapping,
)

app = FastAPI(title="NACo Admin", docs_url=None, redoc_url=None)

_BASE = os.path.dirname(__file__)
templates = Jinja2Templates(directory=os.path.join(_BASE, "templates"))
app.mount("/static", StaticFiles(directory=os.path.join(_BASE, "static")), name="static")

import json as _json


def _from_json(value):
    """Tolerant JSON filter — the JSON column type already returns parsed
    lists/dicts on Postgres, but SQLite (and old rows) may hand back text."""
    if isinstance(value, (list, dict)) or value is None:
        return value if value is not None else []
    try:
        return _json.loads(value)
    except (ValueError, TypeError):
        return []


templates.env.filters["from_json"] = _from_json


# Make the per-request CSP nonce available to templates. Usage in Jinja:
#
#     <script nonce="{{ csp_nonce() }}">…</script>
#
# Implemented via ``pass_context`` so we can pull the request from the
# template context (Jinja can't see ``request.state`` directly).
from jinja2 import pass_context as _pass_context


@_pass_context
def _csp_nonce(context):
    req = context.get("request")
    return getattr(req.state, "csp_nonce", "") if req is not None else ""


templates.env.globals["csp_nonce"] = _csp_nonce


# ---------------------------------------------------------------------------
# Session cookie helpers — signed JWT stored as an HttpOnly cookie
# ---------------------------------------------------------------------------

_SESSION_COOKIE   = "naco_session"
_SESSION_ALGORITHM = "HS256"
_SESSION_MAX_AGE   = 3600 * 8   # 8 hours

# ---------------------------------------------------------------------------
# CSRF protection — signed token per session, validated on every state-changing POST
# ---------------------------------------------------------------------------
import hashlib as _hashlib
import hmac as _hmac
import secrets as _secrets

_CSRF_COOKIE = "naco_csrf"


def _generate_csrf_token(session_token: str) -> str:
    """Generate a CSRF token bound to the user's session.

    Uses `server.csrf_secret` (separate from the session/API secrets) so a
    leak of either of the JWT signing keys does not reveal valid CSRF tokens
    for active sessions, and vice-versa.
    """
    secret = get_config().server.csrf_secret
    nonce = _secrets.token_hex(16)
    sig = _hmac.new(
        secret.encode(), (nonce + session_token).encode(), _hashlib.sha256
    ).hexdigest()[:32]
    return f"{nonce}:{sig}"


def _validate_csrf_token(token: str, session_token: str) -> bool:
    """Verify the CSRF token matches the session."""
    if not token or ":" not in token:
        return False
    nonce, sig = token.split(":", 1)
    secret = get_config().server.csrf_secret
    expected = _hmac.new(
        secret.encode(), (nonce + session_token).encode(), _hashlib.sha256
    ).hexdigest()[:32]
    return _hmac.compare_digest(sig, expected)


def _get_csrf_token(request: Request) -> str:
    """Get or create a CSRF token for the current session."""
    session_raw = request.cookies.get(_SESSION_COOKIE, "")
    return _generate_csrf_token(session_raw)


# Inject csrf_token into all template contexts
_orig_template_response = templates.TemplateResponse


def _csrf_template_response(request_or_name, *args, **kwargs):
    """Wrapper that injects csrf_token into every template context."""
    # Handle both old-style (name, context) and new-style (request, name, context)
    ctx = kwargs.get("context")
    if ctx is None and args:
        # Positional: TemplateResponse(request, name, context) or (name, context)
        if len(args) >= 2 and isinstance(args[1], dict):
            ctx = args[1]
        elif len(args) >= 1 and isinstance(args[0], str) and len(args) >= 2:
            ctx = args[1] if isinstance(args[1], dict) else {}
    if ctx is None:
        # Try to find request in args/kwargs to generate token
        ctx = {}
    # Find request object to generate token
    req = None
    if isinstance(request_or_name, Request):
        req = request_or_name
    elif ctx and "request" in ctx:
        req = ctx["request"]
    if req and "csrf_token" not in ctx:
        ctx["csrf_token"] = _get_csrf_token(req)
    return _orig_template_response(request_or_name, *args, **kwargs)


templates.TemplateResponse = _csrf_template_response  # type: ignore[assignment,method-assign]


# ---------------------------------------------------------------------------
# CSRF validation middleware for all POST/PUT/DELETE requests (except API proxy)
# ---------------------------------------------------------------------------

from starlette.middleware.base import BaseHTTPMiddleware

# Paths that legitimately accept POSTs without a CSRF token, either because
# they pre-date the session cookie (the login form) or because they're API
# endpoints authenticated by a bearer token (a stolen session cookie can't
# be used to issue API requests because requests carrying a `Authorization:
# Bearer` header are *also* outside the cookie-trust boundary).
_CSRF_EXEMPT_PATHS: tuple[str, ...] = (
    "/login",
    "/api/v1/auth/login",
    "/api/v1/auth/totp/verify",  # bearer-auth + body-bound code
    "/api/v1/eap/",              # FreeRADIUS REST hooks — bearer-auth
    "/portal",                   # captive portal has its own cookie-based CSRF;
                                 # guests never hold an admin session cookie, and
                                 # an admin browsing the portal must not have the
                                 # admin CSRF scheme enforced on the guest form.
)


class CSRFMiddleware(BaseHTTPMiddleware):
    """Double-submit CSRF guard for session-cookie-authenticated POSTs.

    Cookie-bearing browser requests must include the CSRF token either in
    the ``X-CSRF-Token`` header (for XHR / fetch) or in a body field named
    ``csrf_token`` (for ``<form>`` POSTs).

    How body parsing works
    ----------------------
    The naïve "read the body, parse the token, hand back the parsed
    request to FastAPI" approach used to fail in two ways:

    1. ``await request.body()`` consumes the ASGI receive channel; the
       downstream ``Form(...)`` handler would then see an empty body and
       return 422.
    2. The pre-Phase-1 workaround used a regex on the raw multipart bytes
       to find the token. The regex (``[^\\r\\n-]+``) excluded ``-`` —
       which is a perfectly valid character in URL-safe base64 — so any
       token containing one was truncated and incorrectly rejected.

    The new approach buffers the body once, parses it with
    ``python-multipart`` (the same library FastAPI uses internally), and
    then **replays the buffered bytes** on a synthetic ``receive`` callable
    so the downstream handler reads them exactly as if they'd come fresh
    off the wire. Memory cost: one full body per state-changing request,
    capped by Caddy's upstream body-size limit.
    """

    async def dispatch(self, request: Request, call_next):
        if request.method not in ("POST", "PUT", "DELETE", "PATCH"):
            return await call_next(request)

        # Bearer-auth and API endpoints are exempt: a CSRF attack relies on
        # the browser silently attaching a cookie, but `Authorization:
        # Bearer ...` is never set automatically by the browser.
        path = request.url.path
        if any(path == p or path.startswith(p) for p in _CSRF_EXEMPT_PATHS):
            return await call_next(request)
        if request.headers.get("authorization", "").lower().startswith("bearer "):
            return await call_next(request)

        session_raw = request.cookies.get(_SESSION_COOKIE, "")
        if not session_raw:
            # No session cookie → not a cookie-authenticated request → no CSRF risk.
            return await call_next(request)

        csrf_token = request.headers.get("X-CSRF-Token", "")
        content_type = request.headers.get("content-type", "")

        # For form / multipart POSTs we read the body once, parse out the
        # csrf_token field, then rebuild the ASGI receive channel so the
        # body bytes are still delivered to the route handler intact.
        body_bytes: bytes | None = None
        if not csrf_token and (
            "application/x-www-form-urlencoded" in content_type
            or "multipart/form-data" in content_type
        ):
            body_bytes = await request.body()
            csrf_token = _extract_csrf_from_body(body_bytes, content_type)

        if not _validate_csrf_token(csrf_token, session_raw):
            return Response(
                content="CSRF token missing or invalid. Please reload the page and try again.",
                status_code=403,
                media_type="text/plain",
            )

        # If we already drained the body, hand it back to the route via a
        # one-shot receive callable. Starlette caches `await request.body()`
        # internally, so once we've called it the next downstream
        # ``await request.body()`` returns the cached bytes — but
        # ``await request.form()`` re-creates the parser, which in turn
        # calls ``receive()``. We give it the buffered bytes here.
        if body_bytes is not None:
            replayed = False

            async def _receive():
                nonlocal replayed
                if not replayed:
                    replayed = True
                    return {"type": "http.request", "body": body_bytes, "more_body": False}
                return {"type": "http.disconnect"}

            request._receive = _receive

        return await call_next(request)


def _extract_csrf_from_body(body: bytes, content_type: str) -> str:
    """Find the ``csrf_token`` field in a request body.

    Supports both ``application/x-www-form-urlencoded`` and
    ``multipart/form-data`` encodings. Returns an empty string if the
    body is malformed or the field isn't present.
    """
    if "application/x-www-form-urlencoded" in content_type:
        from urllib.parse import parse_qs
        try:
            params = parse_qs(body.decode("utf-8", errors="replace"), keep_blank_values=True)
        except Exception:
            return ""
        return params.get("csrf_token", [""])[0]

    if "multipart/form-data" in content_type:
        # Pull the boundary off the Content-Type header and let the stdlib
        # `email.parser` machinery parse the body. ``python-multipart`` is
        # an option but importing it for this single use-case adds startup
        # cost we don't need.
        import re
        m = re.search(r"boundary=([^;]+)", content_type)
        if not m:
            return ""
        boundary = m.group(1).strip().strip('"').encode()
        # Multipart bodies are separated by ``--<boundary>\r\n``.
        sep = b"--" + boundary
        for part in body.split(sep):
            if b'name="csrf_token"' not in part:
                continue
            # Split off the headers / body separator (CRLF CRLF).
            _head, _, value = part.partition(b"\r\n\r\n")
            if not value:
                continue
            # Strip *only* the trailing CRLF that precedes the next boundary
            # marker — never trailing dashes, because URL-safe base64
            # (used for the token format) emits them legitimately.
            value = value.rstrip(b"\r\n")
            try:
                return value.decode("utf-8", errors="replace").strip()
            except Exception:
                return ""

    return ""


app.add_middleware(CSRFMiddleware)


# ---------------------------------------------------------------------------
# Security response headers — prevent clickjacking, MIME-sniffing, etc.
# ---------------------------------------------------------------------------
#
# CSP nonce strategy
# ------------------
# The previous CSP used ``'unsafe-inline'`` for ``script-src`` and
# ``style-src``, which defeats one of the main reasons to have a CSP at all
# (it permits any injected ``<script>...</script>`` to execute). We replace
# it with a per-request nonce:
#
#   1. This middleware generates a fresh nonce on every request and stores
#      it on ``request.state.csp_nonce``.
#   2. Jinja templates expose the nonce as ``{{ csp_nonce }}`` via the
#      ``_inject_template_globals`` middleware below.
#   3. Inline ``<script nonce="{{ csp_nonce }}">`` and
#      ``<style nonce="{{ csp_nonce }}">`` tags are accepted by the browser.
#   4. The CSP header carries ``script-src 'self' 'nonce-...' https://cdn.jsdelivr.net``
#      so the CDN-hosted Bootstrap bundle still loads.
#
# We keep ``'unsafe-inline'`` for ``style-src`` for now because numerous
# Bootstrap utilities emit inline ``style="..."`` attributes (CSS attribute
# styles aren't covered by nonces — they need ``'unsafe-inline'`` regardless
# unless we move every utility class into a CSS file). Phase 4 may revisit
# this; the impact is low because reflected-XSS via attribute style is
# limited to UI defacement.



class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Generate a per-request CSP nonce *before* the route handler runs
        # so templates can pick it up via request.state.
        nonce = _secrets.token_urlsafe(16)
        request.state.csp_nonce = nonce

        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"

        # HSTS — only meaningful over HTTPS. Setting it on plain HTTP would
        # be ignored by browsers but could cause confusion in mixed dev
        # setups, so we gate on the scheme (after honouring
        # X-Forwarded-Proto from trusted proxies).
        scheme = request.url.scheme
        fwd = request.headers.get("x-forwarded-proto", "").lower()
        if scheme == "https" or fwd == "https":
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )

        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            f"script-src 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "font-src 'self' https://cdn.jsdelivr.net; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'"
        )
        return response


app.add_middleware(SecurityHeadersMiddleware)


# ---------------------------------------------------------------------------
# Request-ID middleware — added LAST so it wraps every other middleware,
# meaning the contextvar is set before anything else runs and logs from
# CSRF / security-headers code all carry the correlation ID.
# ---------------------------------------------------------------------------
from naco.core.request_id import RequestIDMiddleware

app.add_middleware(RequestIDMiddleware)


# ---------------------------------------------------------------------------
# Login rate limiter — shared with the REST API via core.ratelimit
# ---------------------------------------------------------------------------
from naco.core.ratelimit import (
    check_account_lock,
    check_rate_limit,
    clear_account_failures,
    clear_failures,
    record_account_failure,
    record_failure,
)


def _sign_session(username: str) -> str:
    """Encode a signed, time-limited session token for *username*.

    Uses `server.session_secret` — kept independent from the API JWT secret
    so that a leak of one does not compromise the other.
    """
    import time
    secret = get_config().server.session_secret
    payload = {
        "sub": username,
        "iat": int(time.time()),
        "exp": int(time.time()) + _SESSION_MAX_AGE,
        "kind": "session",
    }
    return jwt.encode(payload, secret, algorithm=_SESSION_ALGORITHM)


def _verify_session(value: str) -> str | None:
    """Decode and verify a session token; return the username or None."""
    try:
        secret = get_config().server.session_secret
        payload = jwt.decode(value, secret, algorithms=[_SESSION_ALGORITHM])
        return payload.get("sub")
    except jwt.PyJWTError:
        return None


def _get_session_user(request: Request) -> str | None:
    """Return username from signed session cookie, or None."""
    raw = request.cookies.get(_SESSION_COOKIE)
    if not raw:
        return None
    return _verify_session(raw)


def _require_auth(request: Request):
    user = _get_session_user(request)
    if not user:
        raise RedirectToLogin()
    return user


class RedirectToLogin(Exception):
    pass


class Forbidden(Exception):
    """Raised when the session user lacks the role required by a route.

    Rendered as a 403 HTML page via :func:`_render_forbidden` rather than the
    default FastAPI JSON 403 — the admin UI is a browser experience.
    """

    def __init__(self, message: str = "You do not have permission to do that."):
        super().__init__(message)
        self.message = message


async def _resolve_admin(request: Request, db: AsyncSession) -> AdminUser | None:
    """Return the :class:`AdminUser` row for the current session, or ``None``.

    This is the web-side counterpart to :func:`naco.api.auth.get_current_admin`
    — it walks the signed cookie back to a DB row so we can check the role.
    Looked up on every request that calls :func:`_require_role`; callers that
    don't need the role check should use :func:`_require_auth` for speed.
    """
    username = _get_session_user(request)
    if not username:
        return None
    stmt = select(AdminUser).where(AdminUser.username == username, AdminUser.enabled)
    return (await db.execute(stmt)).scalar_one_or_none()


async def _require_role(request: Request, db: AsyncSession, minimum: AdminRole) -> AdminUser:
    """Authenticate AND authorise the current session.

    * Missing/invalid cookie → :class:`RedirectToLogin` (302 to /login)
    * Authenticated but role too low → :class:`Forbidden` (403 HTML page)
    """
    admin = await _resolve_admin(request, db)
    if admin is None:
        raise RedirectToLogin()
    if not has_role(admin, minimum):
        raise Forbidden(
            f"This action requires the {minimum.value} role or higher. "
            f"You are signed in as {admin.username} ({getattr(admin, 'role', '?')})."
        )
    return admin


# ---------------------------------------------------------------------------
# Exception handler — redirect to login on unauthenticated access
# ---------------------------------------------------------------------------

@app.exception_handler(RedirectToLogin)
async def _redirect_to_login(request: Request, exc: RedirectToLogin):
    return RedirectResponse(url="/login", status_code=302)


@app.exception_handler(Forbidden)
async def _forbidden_handler(request: Request, exc: Forbidden):
    """Render a 403 page (HTML for browsers, JSON for XHR/API callers)."""
    accept = request.headers.get("accept", "")
    if "application/json" in accept or request.url.path.startswith("/api/"):
        from fastapi.responses import JSONResponse
        return JSONResponse({"detail": exc.message}, status_code=403)
    try:
        return templates.TemplateResponse(
            request, "403.html",
            {"request": request, "message": exc.message},
            status_code=403,
        )
    except Exception:
        # Fallback when the template is missing — never let the 403 itself 500.
        return HTMLResponse(
            f"<h1>403 — Forbidden</h1><p>{exc.message}</p>"
            f"<p><a href=\"/\">Back to dashboard</a></p>",
            status_code=403,
        )


# ---------------------------------------------------------------------------
# Login / Logout
# ---------------------------------------------------------------------------

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: str = ""):
    return templates.TemplateResponse(request, "login.html", {"request": request, "error": error})


@app.post("/login")
async def do_login(
    request:  Request,
    username: str = Form(...),
    password: str = Form(...),
    totp_code: str = Form(""),
    db: AsyncSession = Depends(get_db),
):
    from naco.core.utils import client_ip
    ip = client_ip(request)

    if not check_rate_limit(ip):
        return templates.TemplateResponse(
            request,
            "login.html",
            {"request": request, "error": "Too many failed attempts. Try again in 5 minutes."},
            status_code=429,
        )
    if not check_account_lock(username):
        return templates.TemplateResponse(
            request,
            "login.html",
            {"request": request, "error": "Account temporarily locked due to repeated failed logins."},
            status_code=429,
        )

    stmt = select(AdminUser).where(AdminUser.username == username, AdminUser.enabled)
    user = (await db.execute(stmt)).scalar_one_or_none()

    # Constant-time bcrypt on the missing-user branch — see comment in
    # ``naco.api.auth.dummy_verify`` for why.
    if user is None:
        from naco.api.auth import dummy_verify_async
        await dummy_verify_async(password)

    if user and await verify_password_async(password, user.password_hash):
        # TOTP verification (if enabled for this user)
        if user.totp_secret:
            import pyotp
            if not totp_code or not pyotp.TOTP(user.totp_secret).verify(totp_code, valid_window=1):
                record_failure(ip)
                record_account_failure(username)
                return templates.TemplateResponse(
                    request,
                    "login.html",
                    {"request": request, "error": "Invalid or missing TOTP code.", "totp_required": True},
                    status_code=401,
                )

        clear_failures(ip)
        clear_account_failures(username)
        user.last_login = datetime.now(UTC)

        # Opportunistic bcrypt cost upgrade — see comment in
        # ``naco.api.routes.login`` for rationale.
        if needs_rehash(user.password_hash):
            user.password_hash = hash_password(password)

        await db.commit()
        resp = RedirectResponse(url="/", status_code=303)
        is_https = request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"
        resp.set_cookie(
            _SESSION_COOKIE, _sign_session(username),
            httponly=True, samesite="lax",
            secure=is_https,
            max_age=_SESSION_MAX_AGE,
        )
        return resp

    record_failure(ip)
    record_account_failure(username)
    return templates.TemplateResponse(
        request,
        "login.html",
        {"request": request, "error": "Invalid username or password."},
        status_code=401,
    )


@app.post("/logout")
async def logout(request: Request):
    resp = RedirectResponse(url="/login", status_code=302)
    resp.delete_cookie(_SESSION_COOKIE)
    return resp


# Also accept GET for backwards compatibility but redirect through POST
@app.get("/logout")
async def logout_get(request: Request):
    resp = RedirectResponse(url="/login", status_code=302)
    resp.delete_cookie(_SESSION_COOKIE)
    return resp


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, db: AsyncSession = Depends(get_db)):
    user = _require_auth(request)
    today = datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)

    stats = {
        "total_users":    (await db.execute(select(func.count()).select_from(User))).scalar_one(),
        "total_devices":  (await db.execute(select(func.count()).select_from(Device))).scalar_one(),
        "active_sessions":(await db.execute(select(func.count()).select_from(ActiveSession))).scalar_one(),
        "auth_today":     (await db.execute(
            select(func.count()).select_from(AuthLog).where(AuthLog.timestamp >= today)
        )).scalar_one(),
        "auth_success":   (await db.execute(
            select(func.count()).select_from(AuthLog).where(
                AuthLog.timestamp >= today, AuthLog.result == AuthResult.SUCCESS
            )
        )).scalar_one(),
        "auth_failure":   (await db.execute(
            select(func.count()).select_from(AuthLog).where(
                AuthLog.timestamp >= today, AuthLog.result == AuthResult.FAILURE
            )
        )).scalar_one(),
        "guest_active":   (await db.execute(
            select(func.count()).select_from(GuestSession).where(
                GuestSession.active,
                GuestSession.expires_at > datetime.now(UTC),
            )
        )).scalar_one(),
    }

    recent_logs = (await db.execute(
        select(AuthLog).order_by(AuthLog.timestamp.desc()).limit(10)
    )).scalars().all()

    cfg = get_config()

    # First-boot setup checklist — shown until the three core steps
    # (NAS, policy, users) are done; the optional rows are informational.
    nas_count = (await db.execute(select(func.count()).select_from(NasClient))).scalar_one()
    policy_count = (await db.execute(select(func.count()).select_from(Policy))).scalar_one()
    from naco.core.secrets import get_master_key
    setup = {
        "nas":        nas_count > 0,
        "policy":     policy_count > 0,
        "users":      stats["total_users"] > 0 or cfg.ldap.enabled,
        "eap":        cfg.eap.enabled,
        "master_key": get_master_key() is not None,
    }
    setup_done = setup["nas"] and setup["policy"] and setup["users"]

    return templates.TemplateResponse(request, "dashboard.html", {
        "request":     request,
        "user":        user,
        "stats":       stats,
        "recent_logs": recent_logs,
        "server_name": cfg.server.name,
        "setup":       setup,
        "setup_done":  setup_done,
    })


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------

@app.get("/users", response_class=HTMLResponse)
async def users_page(request: Request, db: AsyncSession = Depends(get_db)):
    user = _require_auth(request)
    from sqlalchemy.orm import selectinload
    rows = (await db.execute(
        select(User).options(selectinload(User.group)).order_by(User.username)
    )).scalars().all()
    groups = (await db.execute(select(Group).order_by(Group.name))).scalars().all()
    return templates.TemplateResponse(request, "users.html", {
        "request": request, "user": user,
        "users": rows, "groups": groups,
    })


# ---------------------------------------------------------------------------
# Devices
# ---------------------------------------------------------------------------

@app.get("/devices", response_class=HTMLResponse)
async def devices_page(request: Request, db: AsyncSession = Depends(get_db)):
    user = _require_auth(request)
    rows = (await db.execute(
        select(Device).order_by(Device.last_seen.desc()).limit(200)
    )).scalars().all()
    return templates.TemplateResponse(request, "devices.html", {
        "request": request, "user": user, "devices": rows,
    })


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------

@app.get("/policies", response_class=HTMLResponse)
async def policies_page(request: Request, db: AsyncSession = Depends(get_db)):
    user = _require_auth(request)
    rows = (await db.execute(
        select(Policy).order_by(Policy.priority)
    )).scalars().all()
    groups = (await db.execute(select(Group))).scalars().all()
    return templates.TemplateResponse(request, "policies.html", {
        "request": request, "user": user, "policies": rows, "groups": groups,
    })


# ---------------------------------------------------------------------------
# Centralized Logs (Auth + TACACS+ unified view)
# ---------------------------------------------------------------------------

@app.get("/logs", response_class=HTMLResponse)
async def logs_page(
    request:  Request,
    tab:      str = "all",
    page:     int = 1,
    result:   str = "",
    db: AsyncSession = Depends(get_db),
):
    user = _require_auth(request)
    per_page = 50
    if tab not in ("all", "auth", "tacacs"):
        tab = "all"

    # Totals for the tab badges
    total_auth = (await db.execute(
        select(func.count()).select_from(AuthLog)
    )).scalar_one()
    total_tacacs = (await db.execute(
        select(func.count()).select_from(TacacsLog)
    )).scalar_one()
    total_all = total_auth + total_tacacs

    # Sanitise result filter
    filter_result = ""
    if result:
        valid_results = {e.value for e in AuthResult}
        if result.upper() in valid_results:
            filter_result = result.upper()

    merged: list = []

    if tab in ("all", "auth"):
        auth_stmt = select(AuthLog).order_by(AuthLog.timestamp.desc())
        if filter_result:
            auth_stmt = auth_stmt.where(AuthLog.result == filter_result)
        if tab == "auth":
            auth_stmt = auth_stmt.offset((page - 1) * per_page).limit(per_page)
        else:
            auth_stmt = auth_stmt.limit(per_page * 2)
        auth_rows = (await db.execute(auth_stmt)).scalars().all()
        for auth_row in auth_rows:
            auth_row._source = "auth"
        merged.extend(auth_rows)

    if tab in ("all", "tacacs"):
        tac_stmt = select(TacacsLog).order_by(TacacsLog.timestamp.desc())
        if filter_result:
            if filter_result == "SUCCESS":
                tac_stmt = tac_stmt.where(TacacsLog.result.in_(["PASS", "SUCCESS", "LOGGED"]))
            elif filter_result == "FAILURE":
                tac_stmt = tac_stmt.where(TacacsLog.result.in_(["FAIL", "FAILURE"]))
        if tab == "tacacs":
            tac_stmt = tac_stmt.offset((page - 1) * per_page).limit(per_page)
        else:
            tac_stmt = tac_stmt.limit(per_page * 2)
        tac_rows = (await db.execute(tac_stmt)).scalars().all()
        for tac_row in tac_rows:
            tac_row._source = "tacacs"
        merged.extend(tac_rows)

    # For the "all" tab, merge-sort by timestamp descending and paginate
    if tab == "all":
        merged.sort(key=lambda e: e.timestamp, reverse=True)
        start = (page - 1) * per_page
        merged = merged[start:start + per_page]

    # Compute total for the active tab (with filters)
    if tab == "auth":
        if filter_result:
            total = (await db.execute(
                select(func.count()).select_from(AuthLog).where(AuthLog.result == filter_result)
            )).scalar_one()
        else:
            total = total_auth
    elif tab == "tacacs":
        total = total_tacacs
    else:
        total = total_all

    total_pages = max(1, (total + per_page - 1) // per_page)

    return templates.TemplateResponse(request, "logs.html", {
        "request": request, "user": user, "logs": merged,
        "tab": tab, "page": page, "per_page": per_page,
        "total": total, "total_pages": total_pages,
        "total_all": total_all, "total_auth": total_auth,
        "total_tacacs": total_tacacs, "filter_result": filter_result,
    })


# ---------------------------------------------------------------------------
# Active Sessions
# ---------------------------------------------------------------------------

@app.get("/sessions", response_class=HTMLResponse)
async def sessions_page(request: Request, db: AsyncSession = Depends(get_db)):
    user = _require_auth(request)
    rows = (await db.execute(
        select(ActiveSession).order_by(ActiveSession.started_at.desc())
    )).scalars().all()
    return templates.TemplateResponse(request, "sessions.html", {
        "request": request, "user": user, "sessions": rows,
    })


# ---------------------------------------------------------------------------
# Guest Sessions
# ---------------------------------------------------------------------------

@app.get("/guests", response_class=HTMLResponse)
async def guests_page(request: Request, db: AsyncSession = Depends(get_db)):
    user = _require_auth(request)
    cfg  = get_config()
    rows = (await db.execute(
        select(GuestSession).order_by(GuestSession.created_at.desc()).limit(100)
    )).scalars().all()
    now = datetime.now(UTC)
    # Build portal URL from config — never trust the Host header for URL construction
    cfg_host = request.headers.get("host", "").split(":")[0] or "localhost"
    # Validate host: only allow alphanumeric, dots, hyphens (valid hostname chars)
    import re as _re
    if not _re.match(r"^[a-zA-Z0-9._-]+$", cfg_host):
        cfg_host = "localhost"
    portal_url  = f"http://{cfg_host}:{cfg.server.port}/portal"
    return templates.TemplateResponse(request, "guests.html", {
        "request": request, "user": user, "sessions": rows, "now": now,
        "portal_url": portal_url,
    })


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    user = _require_auth(request)
    cfg  = get_config()
    return templates.TemplateResponse(request, "settings.html", {
        "request": request, "user": user, "cfg": cfg,
    })


def _form_int(form, key: str, default: int) -> int:
    """Parse an integer form field, returning *default* on any invalid input."""
    try:
        return int(form.get(key, default))
    except (ValueError, TypeError):
        return default


def _form_float(form, key: str, default: float) -> float:
    try:
        return float(form.get(key, default))
    except (ValueError, TypeError):
        return default


def _form_str(form, key: str, default: str = "") -> str:
    """Return a form field as a plain string.

    Starlette's ``FormData.get`` is typed ``str | UploadFile``. A text field
    that unexpectedly arrives as a file part (or is absent) collapses to
    *default* instead of raising when treated as text downstream.
    """
    val = form.get(key, default)
    return val if isinstance(val, str) else default


@app.post("/settings/save")
async def settings_save(request: Request, db: AsyncSession = Depends(get_db)):
    """Save a config section from a form POST and reload the in-memory config.

    SUPERUSER only — these fields control protocol-level credentials
    (LDAP bind password, RADIUS/TACACS secrets, log-forwarding webhook
    URLs that act as data egress channels).
    """
    await _require_role(request, db, AdminRole.SUPERUSER)
    import os
    import re as _re_settings

    import yaml

    form = await request.form()
    section = form.get("section", "")

    # Whitelist allowed section names to prevent injection
    _ALLOWED_SECTIONS = {
        "server", "radius", "tacacs", "portal",
        "log_forwarding_syslog", "log_forwarding_graylog",
        "log_forwarding_webhook", "ldap",
    }
    if section not in _ALLOWED_SECTIONS:
        return RedirectResponse(url="/settings?error=Invalid+section", status_code=303)

    def _sanitize_str(val: object, max_len: int = 256) -> str:
        """Strip control characters and enforce max length.

        Non-string form values (e.g. an unexpected file part, or a missing
        field) collapse to an empty string rather than raising.
        """
        if not isinstance(val, str):
            return ""
        return _re_settings.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', val)[:max_len]

    cfg_path = os.environ.get("NACO_CONFIG", "/etc/naco/config.yaml")
    if not os.path.exists(cfg_path):
        cfg_path = os.path.join(
            os.path.dirname(__file__), "..", "config", "config.yaml"
        )

    # Validate the resolved path is within an allowed directory (prevent path traversal)
    _ALLOWED_CONFIG_DIRS = (
        os.path.realpath("/etc/naco"),
        os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "config")),
    )
    real_cfg_path = os.path.realpath(cfg_path)
    if not any(real_cfg_path.startswith(d + os.sep) or real_cfg_path == os.path.join(d, "config.yaml")
               for d in _ALLOWED_CONFIG_DIRS):
        return RedirectResponse(url="/settings?error=Invalid+config+path", status_code=303)

    with open(cfg_path) as f:
        data = yaml.safe_load(f) or {}

    # Map form fields into config dict based on section
    if section == "server":
        data.setdefault("server", {})
        data["server"]["name"]      = _sanitize_str(form.get("name", data["server"].get("name", "NACo")), 64)
        data["server"]["log_level"] = form.get("log_level", "INFO") if form.get("log_level") in ("DEBUG","INFO","WARNING","ERROR","CRITICAL") else "INFO"
        data["server"]["debug"]     = form.get("debug") == "on"

    elif section == "radius":
        data.setdefault("radius", {})
        data["radius"]["enabled"]      = form.get("enabled") == "on"
        data["radius"]["auth_port"]    = _form_int(form, "auth_port", 1812)
        data["radius"]["acct_port"]    = _form_int(form, "acct_port", 1813)
        data["radius"]["default_vlan"] = _form_int(form, "default_vlan", 1)
        data["radius"]["guest_vlan"]   = _form_int(form, "guest_vlan", 99)

    elif section == "tacacs":
        data.setdefault("tacacs", {})
        data["tacacs"]["enabled"] = form.get("enabled") == "on"
        data["tacacs"]["port"]    = _form_int(form, "port", 49)

    elif section == "portal":
        data.setdefault("portal", {})
        data["portal"]["session_hours"] = _form_int(form, "session_hours", 8)
        data["portal"]["guest_ssid"]    = _sanitize_str(form.get("guest_ssid", ""), 32)
        data["portal"]["guest_psk"]     = _sanitize_str(form.get("guest_psk", ""), 63)

    elif section == "log_forwarding_syslog":
        data.setdefault("log_forwarding", {}).setdefault("syslog", {})
        sl = data["log_forwarding"]["syslog"]
        sl["enabled"]  = form.get("enabled") == "on"
        sl["address"]  = _sanitize_str(form.get("address", "/dev/log"), 128)
        sl["facility"] = form.get("facility", "local0") if form.get("facility") in ("local0","local1","local2","local3","local4","local5","local6","local7","daemon","auth","syslog") else "local0"
        sl["protocol"] = form.get("protocol", "udp") if form.get("protocol") in ("udp", "tcp") else "udp"
        sl["port"]     = _form_int(form, "port", 514)

    elif section == "log_forwarding_graylog":
        data.setdefault("log_forwarding", {}).setdefault("graylog", {})
        gl = data["log_forwarding"]["graylog"]
        gl["enabled"]  = form.get("enabled") == "on"
        gl["host"]     = _sanitize_str(form.get("host", "127.0.0.1"), 128)
        gl["port"]     = _form_int(form, "port", 12201)
        gl["protocol"] = form.get("protocol", "udp") if form.get("protocol") in ("udp", "tcp") else "udp"

    elif section == "log_forwarding_webhook":
        data.setdefault("log_forwarding", {}).setdefault("webhook", {})
        wh = data["log_forwarding"]["webhook"]
        wh["enabled"]                 = form.get("enabled") == "on"
        wh["url"]                     = _sanitize_str(form.get("url", ""), 512)
        wh["level"]                   = form.get("level", "WARNING") if form.get("level") in ("DEBUG","INFO","WARNING","ERROR","CRITICAL") else "WARNING"
        wh["timeout_seconds"]         = _form_float(form, "timeout_seconds", 3.0)
        wh["batch_size"]              = _form_int(form, "batch_size", 10)
        wh["batch_interval_seconds"]  = _form_float(form, "batch_interval_seconds", 5.0)
        # Parse raw headers textarea ("Key: Value" per line)
        headers: dict[str, str] = {}
        for line in _form_str(form, "headers_raw").splitlines():
            line = line.strip()
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip()] = v.strip()
        wh["headers"] = headers

    elif section == "ldap":
        data.setdefault("ldap", {})
        ld = data["ldap"]
        ld["enabled"]         = form.get("enabled") == "on"
        ld["server"]          = _sanitize_str(form.get("server", "ldap://dc.example.com"), 256)
        ld["port"]            = _form_int(form, "port", 389)
        ld["use_ssl"]         = form.get("use_ssl") == "on"
        ld["bind_dn"]         = _sanitize_str(form.get("bind_dn", ""), 512)
        ld["bind_password"]   = _sanitize_str(form.get("bind_password", ""), 256)
        ld["base_dn"]         = _sanitize_str(form.get("base_dn", ""), 512)
        ld["user_filter"]     = _sanitize_str(form.get("user_filter", "(sAMAccountName={username})"), 256)
        ld["group_attribute"] = _sanitize_str(form.get("group_attribute", "memberOf"), 64)
        # Parse group_map_raw textarea ("LDAP DN = NACo group" per line)
        group_map: dict[str, str] = {}
        for line in _form_str(form, "group_map_raw").splitlines():
            line = line.strip()
            if "=" in line:
                k, _, v = line.partition("=")
                k, v = k.strip(), v.strip()
                if k and v:
                    group_map[k] = v
        ld["group_map"] = group_map

    try:
        with open(cfg_path, "w") as f:
            yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)
    except OSError as _exc:
        return RedirectResponse(
            url="/settings?error=Cannot+write+config+(read-only+filesystem)",
            status_code=303,
        )

    # Invalidate cached config so next request re-reads it
    from naco.config import get_config as _gc
    _gc.cache_clear()

    # Re-apply log handlers so forwarding changes take effect immediately
    from naco.core.logger import setup_logging as _setup_logging
    _setup_logging()

    return RedirectResponse(url="/settings?saved=1", status_code=303)


# ---------------------------------------------------------------------------
# Log forwarding — test endpoint  (called via JS fetch on the Settings page)
# ---------------------------------------------------------------------------

from fastapi.responses import JSONResponse


@app.post("/settings/test-log/{target}")
async def test_log_forwarding(target: str, request: Request, db: AsyncSession = Depends(get_db)):
    await _require_role(request, db, AdminRole.SUPERUSER)
    allowed = {"syslog", "graylog", "webhook"}
    if target not in allowed:
        return JSONResponse({"ok": False, "message": "Unknown target."})
    from naco.core.logger import send_test_log
    ok, msg = send_test_log(target)
    return JSONResponse({"ok": ok, "message": msg})


@app.post("/settings/test-ldap")
async def test_ldap_connection(request: Request, db: AsyncSession = Depends(get_db)):
    await _require_role(request, db, AdminRole.SUPERUSER)
    cfg = get_config().ldap
    if not cfg.enabled:
        return JSONResponse({"ok": False, "message": "LDAP is not enabled."})
    try:
        import ldap3
        server = ldap3.Server(cfg.server, port=cfg.port, use_ssl=cfg.use_ssl, get_info=ldap3.NONE)
        conn = ldap3.Connection(server, user=cfg.bind_dn, password=cfg.bind_password, auto_bind=True)
        conn.unbind()
        return JSONResponse({"ok": True, "message": "LDAP bind successful."})
    except ImportError:
        return JSONResponse({"ok": False, "message": "ldap3 not installed (pip install ldap3)."})
    except Exception as exc:
        return JSONResponse({"ok": False, "message": str(exc)[:200]})


# ---------------------------------------------------------------------------
# Groups
# ---------------------------------------------------------------------------

@app.get("/groups", response_class=HTMLResponse)
async def groups_page(request: Request, db: AsyncSession = Depends(get_db)):
    user = _require_auth(request)
    from sqlalchemy.orm import selectinload
    rows = (await db.execute(
        select(Group).options(selectinload(Group.command_set)).order_by(Group.name)
    )).scalars().all()
    # count users per group
    counts: dict[int, int] = {}
    for g in rows:
        c = (await db.execute(
            select(func.count()).select_from(User).where(User.group_id == g.id)
        )).scalar_one()
        counts[g.id] = c
    # command sets for dropdown
    cs_list = (await db.execute(select(CommandSet).order_by(CommandSet.name))).scalars().all()
    return templates.TemplateResponse(request, "groups.html", {
        "request": request, "user": user, "groups": rows, "counts": counts,
        "command_sets": cs_list,
        "saved": request.query_params.get("saved"),
        "error": request.query_params.get("error"),
    })


@app.post("/groups")
async def create_group(
    request: Request,
    name: str = Form(...),
    description: str = Form(""),
    command_set_id: str = Form(""),
    db: AsyncSession = Depends(get_db),
):
    _require_auth(request)
    existing = (await db.execute(select(Group).where(Group.name == name))).scalar_one_or_none()
    if existing:
        return RedirectResponse(url="/groups?error=Group+name+already+exists", status_code=303)
    cs_id = int(command_set_id) if command_set_id else None
    db.add(Group(name=name, description=description, command_set_id=cs_id))
    await db.commit()
    return RedirectResponse(url="/groups?saved=1", status_code=303)


@app.post("/groups/{group_id}/delete")
async def delete_group(group_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    _require_auth(request)
    g = (await db.execute(select(Group).where(Group.id == group_id))).scalar_one_or_none()
    if g:
        await db.delete(g)
        await db.commit()
    return RedirectResponse(url="/groups", status_code=303)


# ---------------------------------------------------------------------------
# TACACS+ Logs (redirect to unified /logs?tab=tacacs)
# ---------------------------------------------------------------------------

@app.get("/logs/tacacs")
async def tacacs_logs_page(request: Request, page: int = 1):
    return RedirectResponse(url=f"/logs?tab=tacacs&page={page}", status_code=302)


# ---------------------------------------------------------------------------
# Force-terminate session
# ---------------------------------------------------------------------------

@app.post("/sessions/{session_id}/delete")
async def delete_session(session_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    _require_auth(request)
    s = (await db.execute(
        select(ActiveSession).where(ActiveSession.id == session_id)
    )).scalar_one_or_none()
    if s:
        # Send RADIUS Disconnect-Request to the NAS before removing from DB
        if s.nas_ip and s.session_id:
            try:
                nas_secret = await _get_web_nas_secret(s.nas_ip, db)
                if nas_secret:
                    from naco.radius.coa import disconnect_session
                    await disconnect_session(
                        session_id=str(s.id),
                        nas_ip=s.nas_ip,
                        acct_session_id=s.session_id,
                        username=s.username,
                        nas_secret=nas_secret,
                    )
            except Exception:
                pass  # best-effort — still remove from DB
        await db.delete(s)
        await db.commit()
    return RedirectResponse(url="/sessions", status_code=303)


async def _get_web_nas_secret(nas_ip: str, db: AsyncSession) -> str:
    """Look up NAS shared secret from DB then config for CoA."""
    c = (await db.execute(
        select(NasClient).where(NasClient.ip_address == nas_ip, NasClient.enabled)
    )).scalar_one_or_none()
    if c:
        return c.secret
    cfg = get_config()
    for client in cfg.radius.clients:
        if client.address == nas_ip:
            return client.secret
    return ""


# ---------------------------------------------------------------------------
# RADIUS NAS Clients
# ---------------------------------------------------------------------------

@app.get("/radius-clients", response_class=HTMLResponse)
async def radius_clients_page(request: Request, db: AsyncSession = Depends(get_db)):
    user = _require_auth(request)
    rows = (await db.execute(select(NasClient).order_by(NasClient.name))).scalars().all()
    return templates.TemplateResponse(request, "radius_clients.html", {
        "request": request, "user": user, "clients": rows,
        "saved": request.query_params.get("saved"),
        "error": request.query_params.get("error"),
    })


@app.post("/radius-clients")
async def create_radius_client(
    request: Request,
    name: str = Form(...),
    ip_address: str = Form(...),
    secret: str = Form(...),
    description: str = Form(""),
    db: AsyncSession = Depends(get_db),
):
    await _require_role(request, db, AdminRole.SUPERUSER)
    existing = (await db.execute(
        select(NasClient).where(NasClient.name == name)
    )).scalar_one_or_none()
    if existing:
        return RedirectResponse(url="/radius-clients?error=Name+already+exists", status_code=303)
    db.add(NasClient(name=name, ip_address=ip_address, secret=secret, description=description))
    await db.commit()
    return RedirectResponse(url="/radius-clients?saved=1", status_code=303)


@app.post("/radius-clients/{client_id}/delete")
async def delete_radius_client(
    client_id: int, request: Request, db: AsyncSession = Depends(get_db)
):
    await _require_role(request, db, AdminRole.SUPERUSER)
    c = (await db.execute(select(NasClient).where(NasClient.id == client_id))).scalar_one_or_none()
    if c:
        await db.delete(c)
        await db.commit()
    return RedirectResponse(url="/radius-clients", status_code=303)


@app.post("/radius-clients/{client_id}/toggle")
async def toggle_radius_client(
    client_id: int, request: Request, db: AsyncSession = Depends(get_db)
):
    await _require_role(request, db, AdminRole.SUPERUSER)
    c = (await db.execute(select(NasClient).where(NasClient.id == client_id))).scalar_one_or_none()
    if c:
        c.enabled = not c.enabled
        await db.commit()
    return RedirectResponse(url="/radius-clients", status_code=303)


@app.get("/radius-clients/{client_id}/secret")
async def reveal_radius_secret(
    client_id: int, request: Request, db: AsyncSession = Depends(get_db)
):
    # Plaintext RADIUS secret reveal is SUPERUSER-only — Phase 2 will move
    # this column into ``EncryptedString`` storage and the endpoint will
    # decrypt on demand, but the role gate stays.
    await _require_role(request, db, AdminRole.SUPERUSER)
    c = (await db.execute(select(NasClient).where(NasClient.id == client_id))).scalar_one_or_none()
    if not c:
        return Response(content='{"detail":"Not found"}', status_code=404, media_type="application/json")
    return Response(content=_json.dumps({"secret": c.secret}), media_type="application/json")


# ---------------------------------------------------------------------------
# TACACS+ Clients
# ---------------------------------------------------------------------------

@app.get("/tacacs-clients", response_class=HTMLResponse)
async def tacacs_clients_page(request: Request, db: AsyncSession = Depends(get_db)):
    user = _require_auth(request)
    rows = (await db.execute(select(TacacsClient).order_by(TacacsClient.name))).scalars().all()
    return templates.TemplateResponse(request, "tacacs_clients.html", {
        "request": request, "user": user, "clients": rows,
        "saved": request.query_params.get("saved"),
        "error": request.query_params.get("error"),
    })


@app.post("/tacacs-clients")
async def create_tacacs_client(
    request: Request,
    name: str = Form(...),
    ip_address: str = Form(...),
    key: str = Form(...),
    description: str = Form(""),
    db: AsyncSession = Depends(get_db),
):
    await _require_role(request, db, AdminRole.SUPERUSER)
    existing = (await db.execute(
        select(TacacsClient).where(TacacsClient.name == name)
    )).scalar_one_or_none()
    if existing:
        return RedirectResponse(url="/tacacs-clients?error=Name+already+exists", status_code=303)
    db.add(TacacsClient(name=name, ip_address=ip_address, key=key, description=description))
    await db.commit()
    return RedirectResponse(url="/tacacs-clients?saved=1", status_code=303)


@app.post("/tacacs-clients/{client_id}/delete")
async def delete_tacacs_client(
    client_id: int, request: Request, db: AsyncSession = Depends(get_db)
):
    await _require_role(request, db, AdminRole.SUPERUSER)
    c = (await db.execute(select(TacacsClient).where(TacacsClient.id == client_id))).scalar_one_or_none()
    if c:
        await db.delete(c)
        await db.commit()
    return RedirectResponse(url="/tacacs-clients", status_code=303)


@app.post("/tacacs-clients/{client_id}/toggle")
async def toggle_tacacs_client(
    client_id: int, request: Request, db: AsyncSession = Depends(get_db)
):
    await _require_role(request, db, AdminRole.SUPERUSER)
    c = (await db.execute(select(TacacsClient).where(TacacsClient.id == client_id))).scalar_one_or_none()
    if c:
        c.enabled = not c.enabled
        await db.commit()
    return RedirectResponse(url="/tacacs-clients", status_code=303)


@app.get("/tacacs-clients/{client_id}/key")
async def reveal_tacacs_key(
    client_id: int, request: Request, db: AsyncSession = Depends(get_db)
):
    await _require_role(request, db, AdminRole.SUPERUSER)
    c = (await db.execute(select(TacacsClient).where(TacacsClient.id == client_id))).scalar_one_or_none()
    if not c:
        return Response(content='{"detail":"Not found"}', status_code=404, media_type="application/json")
    return Response(content=_json.dumps({"key": c.key}), media_type="application/json")


# ---------------------------------------------------------------------------
# Command Sets
# ---------------------------------------------------------------------------

@app.get("/command-sets", response_class=HTMLResponse)
async def command_sets_page(request: Request, db: AsyncSession = Depends(get_db)):
    user = _require_auth(request)
    from sqlalchemy.orm import selectinload
    rows = (await db.execute(
        select(CommandSet)
        .options(selectinload(CommandSet.rules), selectinload(CommandSet.groups))
        .order_by(CommandSet.name)
    )).scalars().unique().all()
    return templates.TemplateResponse(request, "command_sets.html", {
        "request": request, "user": user, "command_sets": rows,
    })


# ---------------------------------------------------------------------------
# VLAN Mappings
# ---------------------------------------------------------------------------

@app.get("/vlans", response_class=HTMLResponse)
async def vlans_page(request: Request, db: AsyncSession = Depends(get_db)):
    user = _require_auth(request)
    rows = (await db.execute(select(VlanMapping).order_by(VlanMapping.vlan_id))).scalars().all()
    return templates.TemplateResponse(request, "vlans.html", {
        "request": request, "user": user, "vlans": rows,
        "saved": request.query_params.get("saved"),
        "error": request.query_params.get("error"),
    })


@app.post("/vlans")
async def create_vlan(
    request: Request,
    name: str = Form(...),
    vlan_id: int = Form(...),
    description: str = Form(""),
    db: AsyncSession = Depends(get_db),
):
    _require_auth(request)
    existing = (await db.execute(select(VlanMapping).where(VlanMapping.name == name))).scalar_one_or_none()
    if existing:
        return RedirectResponse(url="/vlans?error=Name+already+exists", status_code=303)
    db.add(VlanMapping(name=name, vlan_id=vlan_id, description=description))
    await db.commit()
    return RedirectResponse(url="/vlans?saved=1", status_code=303)


@app.post("/vlans/{vlan_id}/delete")
async def delete_vlan(vlan_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    _require_auth(request)
    v = (await db.execute(select(VlanMapping).where(VlanMapping.id == vlan_id))).scalar_one_or_none()
    if v:
        await db.delete(v)
        await db.commit()
    return RedirectResponse(url="/vlans", status_code=303)


# ---------------------------------------------------------------------------
# Admin Users
# ---------------------------------------------------------------------------

@app.get("/admin-users", response_class=HTMLResponse)
async def admin_users_page(request: Request, db: AsyncSession = Depends(get_db)):
    # Admin-user management is restricted to SUPERUSER.
    actor = await _require_role(request, db, AdminRole.SUPERUSER)
    rows = (await db.execute(select(AdminUser).order_by(AdminUser.username))).scalars().all()
    return templates.TemplateResponse(request, "admin_users.html", {
        "request": request, "user": actor.username, "actor_role": actor.role,
        "admins": rows,
        "roles": [r.value for r in AdminRole],
        "saved": request.query_params.get("saved"),
        "error": request.query_params.get("error"),
    })


@app.post("/admin-users")
async def create_admin_user(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    email: str = Form(""),
    role: str = Form(AdminRole.OPERATOR.value),
    is_superuser: str = Form(""),
    db: AsyncSession = Depends(get_db),
):
    await _require_role(request, db, AdminRole.SUPERUSER)
    from naco.core.utils import client_ip
    ip = client_ip(request)
    if not check_rate_limit(f"admin-create:{ip}"):
        return RedirectResponse(url="/admin-users?error=Too+many+requests.+Try+again+later.", status_code=303)
    if len(password) < 8:
        return RedirectResponse(url="/admin-users?error=Password+must+be+at+least+8+characters", status_code=303)
    if len(username) < 2 or len(username) > 64:
        return RedirectResponse(url="/admin-users?error=Username+must+be+2-64+characters", status_code=303)
    existing = (await db.execute(
        select(AdminUser).where(AdminUser.username == username)
    )).scalar_one_or_none()
    if existing:
        return RedirectResponse(url="/admin-users?error=Username+already+exists", status_code=303)

    # Resolve role from form. Honour the legacy ``is_superuser`` checkbox so an
    # operator using the old form template still ends up with a SUPERUSER row;
    # otherwise pick from the dropdown, defaulting to OPERATOR if it's invalid.
    try:
        chosen_role = AdminRole(role)
    except ValueError:
        chosen_role = AdminRole.OPERATOR
    if is_superuser == "on":
        chosen_role = AdminRole.SUPERUSER

    db.add(AdminUser(
        username=username,
        password_hash=hash_password(password),
        email=email,
        role=chosen_role,
        is_superuser=(chosen_role == AdminRole.SUPERUSER),
    ))
    await db.commit()
    return RedirectResponse(url="/admin-users?saved=1", status_code=303)


@app.post("/admin-users/{admin_id}/delete")
async def delete_admin_user(
    admin_id: int, request: Request, db: AsyncSession = Depends(get_db)
):
    actor = await _require_role(request, db, AdminRole.SUPERUSER)
    a = (await db.execute(select(AdminUser).where(AdminUser.id == admin_id))).scalar_one_or_none()
    if not a or a.username == actor.username:  # prevent self-deletion
        return RedirectResponse(url="/admin-users", status_code=303)

    # Don't allow deleting the last enabled SUPERUSER — that would lock the
    # entire admin-user / settings management surface.
    if a.role == AdminRole.SUPERUSER.value or a.is_superuser:
        remaining = (await db.execute(
            select(func.count()).select_from(AdminUser).where(
                AdminUser.role == AdminRole.SUPERUSER,
                AdminUser.enabled,
                AdminUser.id != a.id,
            )
        )).scalar_one()
        if remaining < 1:
            return RedirectResponse(
                url="/admin-users?error=Cannot+delete+the+last+SUPERUSER",
                status_code=303,
            )

    await db.delete(a)
    await db.commit()
    return RedirectResponse(url="/admin-users", status_code=303)


@app.post("/admin-users/{admin_id}/role")
async def change_admin_role(
    admin_id: int,
    request: Request,
    role: str = Form(...),
    db: AsyncSession = Depends(get_db),
):
    """SUPERUSER-only: change another admin's role."""
    actor = await _require_role(request, db, AdminRole.SUPERUSER)

    try:
        new_role = AdminRole(role)
    except ValueError:
        return RedirectResponse(url="/admin-users?error=Invalid+role", status_code=303)

    a = (await db.execute(select(AdminUser).where(AdminUser.id == admin_id))).scalar_one_or_none()
    if not a:
        return RedirectResponse(url="/admin-users", status_code=303)

    # Block self-demotion if it would leave zero SUPERUSERs.
    if a.username == actor.username and new_role != AdminRole.SUPERUSER:
        remaining = (await db.execute(
            select(func.count()).select_from(AdminUser).where(
                AdminUser.role == AdminRole.SUPERUSER,
                AdminUser.enabled,
                AdminUser.id != a.id,
            )
        )).scalar_one()
        if remaining < 1:
            return RedirectResponse(
                url="/admin-users?error=Cannot+demote+the+last+SUPERUSER",
                status_code=303,
            )

    a.role = new_role
    a.is_superuser = (new_role == AdminRole.SUPERUSER)
    await db.commit()
    return RedirectResponse(url="/admin-users?saved=1", status_code=303)


@app.post("/admin-users/{admin_id}/password")
async def change_admin_password(
    admin_id: int,
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    db: AsyncSession = Depends(get_db),
):
    """
    Two policies depending on target:

    * Changing **your own** password: only requires being logged in. The
      ``current_password`` field has to match your own stored hash.
    * Changing **someone else's** password: SUPERUSER only. The
      ``current_password`` is *still* the acting user's own — never the
      target's — so a compromised session can't pivot without the original
      password.
    """
    actor = await _resolve_admin(request, db)
    if actor is None:
        raise RedirectToLogin()

    target = (await db.execute(
        select(AdminUser).where(AdminUser.id == admin_id)
    )).scalar_one_or_none()
    if target is None:
        return RedirectResponse(url="/admin-users?error=User+not+found", status_code=303)

    # Cross-account password changes require SUPERUSER.
    if target.id != actor.id and not has_role(actor, AdminRole.SUPERUSER):
        raise Forbidden("Only SUPERUSER admins can change another admin's password.")

    # Always re-verify the acting user's own password.
    if not await verify_password_async(current_password, actor.password_hash):
        return RedirectResponse(url="/admin-users?error=Current+password+incorrect", status_code=303)

    if len(new_password) < 8:
        return RedirectResponse(url="/admin-users?error=Password+must+be+at+least+8+characters", status_code=303)

    target.password_hash = hash_password(new_password)
    await db.commit()
    return RedirectResponse(url="/admin-users?saved=1", status_code=303)


# ---------------------------------------------------------------------------
# System Status
# ---------------------------------------------------------------------------

@app.get("/system", response_class=HTMLResponse)
async def system_page(request: Request, db: AsyncSession = Depends(get_db)):
    user = _require_auth(request)
    import platform

    import psutil

    services = []
    for svc in ("naco", "freeradius"):
        try:
            result = subprocess.run(
                ["systemctl", "show", "--property=LoadState,ActiveState", svc],
                capture_output=True, text=True, timeout=2
            )
            props: dict[str, str] = {}
            for line in result.stdout.strip().splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    props[k] = v
            if props.get("LoadState") == "not-found":
                continue  # Service not installed on this system
            status = props.get("ActiveState", "unknown")
        except Exception:
            status = "unknown"
        services.append({"name": svc, "status": status})

    # Recent journal entries for naco service
    log_lines: list[str] = []
    try:
        result = subprocess.run(
            ["journalctl", "-u", "naco", "-n", "40", "--no-pager", "--output=short"],
            capture_output=True, text=True, timeout=5
        )
        log_lines = result.stdout.strip().splitlines()
    except Exception:
        log_lines = ["(journalctl unavailable — running outside systemd?)"]

    cpu_percent  = await asyncio.get_running_loop().run_in_executor(
        None, functools.partial(psutil.cpu_percent, interval=1)
    )
    mem          = psutil.virtual_memory()
    disk         = psutil.disk_usage("/")
    temperature  = None
    try:
        temps = psutil.sensors_temperatures()
        if "cpu_thermal" in temps:
            temperature = round(temps["cpu_thermal"][0].current, 1)
        elif "coretemp" in temps:
            temperature = round(temps["coretemp"][0].current, 1)
    except Exception:
        pass

    db_size = 0
    try:
        import os as _os
        cfg = get_config()
        # cfg.database.url is like "sqlite+aiosqlite:////var/lib/naco/naco.db"
        db_path = cfg.database.url.split("sqlite+aiosqlite:///")[-1]
        if _os.path.exists(db_path):
            db_size = _os.path.getsize(db_path)
    except Exception:
        pass

    total_logs = (await db.execute(select(func.count()).select_from(AuthLog))).scalar_one()

    return templates.TemplateResponse(request, "system.html", {
        "request":      request,
        "user":         user,
        "services":     services,
        "log_lines":    log_lines,
        "cpu_percent":  cpu_percent,
        "mem":          mem,
        "disk":         disk,
        "temperature":  temperature,
        "db_size":      db_size,
        "total_logs":   total_logs,
        "platform":     platform.platform(),
        "python_ver":   platform.python_version(),
    })


@app.post("/system/service/{service_name}/restart")
async def restart_service(service_name: str, request: Request):
    _require_auth(request)
    # Only allow known service names to prevent command injection
    allowed = {"naco"}
    if service_name not in allowed:
        return RedirectResponse(url="/system", status_code=303)
    try:
        # No sudo — polkit rule in /etc/polkit-1/rules.d/10-naco.rules grants
        # the naco user permission to restart these services via DBus.
        subprocess.run(["systemctl", "restart", service_name], timeout=10, check=False)
    except Exception:
        pass
    return RedirectResponse(url="/system", status_code=303)


