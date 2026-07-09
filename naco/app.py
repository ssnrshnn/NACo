"""
NACo — single FastAPI application
=================================
Collapses the three legacy uvicorn apps (Admin UI, REST API, Guest Portal)
into a single ASGI app exposed at the address configured by `server.host` /
`server.port`. Routes are partitioned as follows:

    /                 → Admin UI (Jinja2 templates, session-cookie auth)
    /static/*         → Admin UI static assets
    /api/v1/*         → REST API + FreeRADIUS hooks
    /api/v1/docs      → Swagger UI
    /api/v1/redoc     → ReDoc
    /api/v1/openapi.json
    /portal/*         → Captive guest portal

The lifespan starts background services exactly once: TACACS+, RADIUS,
device profiler, log retention, webhook dispatcher, metrics collector, and
guest-session expiry. No race-guard flags, no shared lifespan across apps.
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta

from fastapi import FastAPI

from naco import __version__
from naco.config import get_config
from naco.core import Event, EventType, bus, get_logger, setup_logging
from naco.db import AsyncSessionLocal, init_db

log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Background-task helpers
# ---------------------------------------------------------------------------

def _task_done_callback(task: asyncio.Task) -> None:
    if task.cancelled():
        return
    exc = task.exception()
    if exc is not None:
        log.error("Background task %r crashed: %s", task.get_name(), exc, exc_info=exc)


def _create_monitored_task(coro, *, name: str | None = None) -> asyncio.Task:
    task = asyncio.create_task(coro, name=name)
    task.add_done_callback(_task_done_callback)
    return task


# ---------------------------------------------------------------------------
# Database bootstrap
# ---------------------------------------------------------------------------

async def _seed_database() -> None:
    from sqlalchemy import select
    from sqlalchemy.exc import IntegrityError

    from naco.api.auth import hash_password
    from naco.db.models import AdminRole, AdminUser

    cfg = get_config()

    async with AsyncSessionLocal() as db:
        existing = (await db.execute(
            select(AdminUser).where(AdminUser.username == cfg.server.admin_username)
        )).scalar_one_or_none()
        if not existing:
            db.add(AdminUser(
                username      = cfg.server.admin_username,
                password_hash = hash_password(cfg.server.admin_password),
                is_superuser  = True,
                role          = AdminRole.SUPERUSER,
                enabled       = True,
            ))
            log.info("Created default admin user: %s (role=SUPERUSER)", cfg.server.admin_username)

        # Production safety net: if every admin somehow ended up as VIEWER,
        # log a loud warning. Without at least one SUPERUSER the system is
        # effectively locked — operators can recover via ``nacoctl
        # reset-password`` and the manual SQL we document in SECURITY.md.
        else:
            sup_count = (await db.execute(
                select(AdminUser).where(AdminUser.role == AdminRole.SUPERUSER, AdminUser.enabled)
            )).scalars().first()
            if sup_count is None:
                log.warning(
                    "No enabled SUPERUSER admin exists — admin management, "
                    "secret rotation, and YAML settings will be inaccessible. "
                    "Promote one with: UPDATE admin_users SET role='SUPERUSER' WHERE username='...';"
                )

        # NOTE: We intentionally do NOT seed a Default-Permit-All policy here.
        # The policy engine is default-deny when no policy matches — operators
        # must explicitly create permit policies. See SECURITY.md.

        try:
            await db.commit()
        except IntegrityError:
            await db.rollback()


# ---------------------------------------------------------------------------
# Background loops
# ---------------------------------------------------------------------------

_LOG_RETENTION_DAYS = 90
_LOG_CLEANUP_INTERVAL = 3600
_ADMIN_AUDIT_RETENTION_DAYS = 365
_STALE_SESSION_HOURS = 24
_STALE_SESSION_INTERVAL = 1800


async def _log_retention_loop() -> None:
    from sqlalchemy import delete as sa_delete

    from naco.db.models import AdminAuditLog, AuthLog, TacacsLog
    from naco.db.partitions import (
        drop_expired_partitions,
        ensure_month_partitions,
    )

    while True:
        try:
            now = datetime.now(UTC)
            auth_cutoff  = now - timedelta(days=_LOG_RETENTION_DAYS)
            admin_cutoff = now - timedelta(days=_ADMIN_AUDIT_RETENTION_DAYS)
            async with AsyncSessionLocal() as db:
                # Postgres: keep next month's partitions provisioned and drop
                # whole expired months (instant, no dead tuples). Row deletes
                # below then only handle the partially-expired boundary month
                # and non-partitioned deployments. No-ops on SQLite.
                await ensure_month_partitions(db, months_ahead=1, now=now)
                await drop_expired_partitions(db, cutoff=auth_cutoff)

                r1 = await db.execute(sa_delete(AuthLog).where(AuthLog.timestamp < auth_cutoff))
                r2 = await db.execute(sa_delete(TacacsLog).where(TacacsLog.timestamp < auth_cutoff))
                r3 = await db.execute(
                    sa_delete(AdminAuditLog).where(AdminAuditLog.timestamp < admin_cutoff)
                )
                await db.commit()
                total = r1.rowcount + r2.rowcount + r3.rowcount
                if total:
                    log.info("Log retention: pruned %d log entries", total)
        except Exception as exc:
            log.warning("Log retention cleanup failed: %s", exc)
        await asyncio.sleep(_LOG_CLEANUP_INTERVAL)


async def _stale_session_cleanup_loop() -> None:
    from sqlalchemy import delete as sa_delete

    from naco.db.models import ActiveSession

    while True:
        try:
            cutoff = datetime.now(UTC) - timedelta(hours=_STALE_SESSION_HOURS)
            async with AsyncSessionLocal() as db:
                result = await db.execute(
                    sa_delete(ActiveSession).where(ActiveSession.updated_at < cutoff)
                )
                await db.commit()
                if result.rowcount:
                    log.info(
                        "Stale session cleanup: removed %d sessions (>%dh inactive)",
                        result.rowcount, _STALE_SESSION_HOURS,
                    )
        except Exception as exc:
            log.warning("Stale session cleanup failed: %s", exc)
        await asyncio.sleep(_STALE_SESSION_INTERVAL)


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

_radius_runner: asyncio.Task | None = None


@asynccontextmanager
async def lifespan(_app: FastAPI):
    setup_logging()
    cfg  = get_config()
    loop = asyncio.get_running_loop()
    bus.set_loop(loop)

    log.info("═══════════════════════════════════════")
    log.info("  NACo v%s  —  %s", __version__, cfg.server.name)
    log.info("═══════════════════════════════════════")

    _INSECURE_KEYS = {
        "change_me", "CHANGE_ME_USE_A_STRONG_RANDOM_STRING", "",
        "CHANGE_ME_session_secret_32_bytes_hex",
        "CHANGE_ME_api_secret_32_bytes_hex",
        "CHANGE_ME_csrf_secret_32_bytes_hex",
        "change_me_session_secret", "change_me_api_secret", "change_me_csrf_secret",
    }
    _insecure_secrets: list[str] = []
    if cfg.server.session_secret in _INSECURE_KEYS:
        _insecure_secrets.append("server.session_secret")
        log.warning("server.session_secret is set to a placeholder — please change it.")
    if cfg.server.api_secret in _INSECURE_KEYS:
        _insecure_secrets.append("server.api_secret")
        log.warning("server.api_secret is set to a placeholder — please change it.")
    if cfg.server.csrf_secret in _INSECURE_KEYS:
        _insecure_secrets.append("server.csrf_secret")
        log.warning("server.csrf_secret is set to a placeholder — please change it.")

    _DEFAULT_PASSWORDS = {"NACo@admin1", "admin", "password", "", "CHANGE_ME_initial_admin_password"}
    if cfg.server.admin_password in _DEFAULT_PASSWORDS:
        log.warning("Admin password is a placeholder — please change it after first login.")

    if cfg.tacacs.enabled and cfg.tacacs.key in (
        "tacacs_secret", "testing123", "", "CHANGE_ME_tacacs_default_key"
    ):
        log.warning("TACACS+ key is set to a placeholder — please change it.")

    # Phase 2.4: refuse to start with placeholder secrets in production.
    if _insecure_secrets and not cfg.server.debug:
        raise SystemExit(
            f"FATAL: refusing to start with placeholder secrets in production mode "
            f"(debug=False). The following secrets must be changed: "
            f"{', '.join(_insecure_secrets)}. "
            f"Set server.debug=true to override (development only)."
        )

    await init_db()
    await _seed_database()

    # OpenTelemetry (optional): HTTP + SQL + auth-plane spans. No-op unless
    # otel.enabled and the `naco[otel]` extra is installed.
    from naco.core.tracing import setup_tracing
    from naco.db.database import engine as db_engine
    setup_tracing(cfg, app=app, engine=db_engine)

    # ── Role-gated subsystems ────────────────────────────────────────────
    # "all" (default) runs everything → identical to the classic single-node
    # deployment. Splitting roles lets the stateless API scale independently
    # of the host-networked RADIUS/TACACS auth planes.
    roles = [r for r in ("api", "radius", "tacacs", "profiler", "workers")
             if cfg.server.has_role(r)]
    log.info("Active roles: %s", ", ".join(roles) or "(none)")

    if cfg.tacacs.enabled and cfg.server.has_role("tacacs"):
        from naco.tacacs import run_tacacs_server
        _create_monitored_task(run_tacacs_server(), name="tacacs-server")

    global _radius_runner
    if cfg.radius.enabled and cfg.server.has_role("radius"):
        from naco.radius import run_radius_server_async
        _radius_runner = _create_monitored_task(run_radius_server_async(), name="radius-server")

    if cfg.profiler.enabled and cfg.server.has_role("profiler"):
        from naco.profiler import profiler
        profiler.start(loop)

    # Singleton maintenance loops — must run on exactly one replica set to
    # avoid N× duplicate work, so they are gated behind the "workers" role.
    if cfg.server.has_role("workers"):
        from naco.portal.app import expire_guest_sessions_loop
        _create_monitored_task(expire_guest_sessions_loop(), name="guest-session-expiry")
        _create_monitored_task(_log_retention_loop(),       name="log-retention")
        _create_monitored_task(_stale_session_cleanup_loop(), name="stale-session-cleanup")

        from naco.core.webhooks import run_webhook_dispatcher
        _create_monitored_task(run_webhook_dispatcher(), name="webhook-dispatcher")

    # Per-process tasks — every replica needs its own metrics collector (counts
    # events on its own bus) and policy-cache invalidation subscriber.
    from naco.core.metrics import run_metrics_collector
    _create_monitored_task(run_metrics_collector(bus), name="metrics-collector")

    from naco.policy import run_policy_invalidation_subscriber
    _create_monitored_task(
        run_policy_invalidation_subscriber(), name="policy-invalidation-subscriber"
    )

    await bus.publish(Event(EventType.SYSTEM_START, data={"node": cfg.server.name}))

    log.info("HTTP listener → http://%s:%d", cfg.server.host, cfg.server.port)
    log.info("Admin UI       → /")
    log.info("REST API       → /api/v1/  (Swagger at /api/v1/docs)")
    log.info("Guest portal   → /portal/")

    try:
        yield
    finally:
        if cfg.profiler.enabled:
            from naco.profiler import profiler
            profiler.stop()

        if _radius_runner is not None and not _radius_runner.done():
            _radius_runner.cancel()
            try:
                await _radius_runner
            except (asyncio.CancelledError, Exception):
                pass

        await bus.publish(Event(EventType.SYSTEM_STOP))
        log.info("NACo shutting down.")


# ---------------------------------------------------------------------------
# Build the single FastAPI instance
# ---------------------------------------------------------------------------

def create_app() -> FastAPI:
    """Return the consolidated NACo FastAPI app.

    The admin UI (`naco.web.app`) is used as the root application because its
    CSRF and security-header middleware must run for every browser request —
    including the AJAX calls the UI makes to `/api/v1/*`. The REST API,
    FreeRADIUS REST hooks, and captive portal are layered on top.
    """
    from naco.api.routes import router as api_router
    from naco.portal.app import app as portal_app
    from naco.radius.freeradius_routes import router as freeradius_router
    from naco.web.app import app as web_app

    web_app.title       = "NACo"
    web_app.version     = __version__
    web_app.openapi_url = "/api/v1/openapi.json"
    web_app.docs_url    = "/api/v1/docs"
    web_app.redoc_url   = "/api/v1/redoc"
    web_app.router.lifespan_context = lifespan

    web_app.include_router(api_router)
    web_app.include_router(freeradius_router)
    web_app.mount("/portal", portal_app)

    return web_app


app = create_app()

__all__ = ["app", "create_app", "lifespan"]
