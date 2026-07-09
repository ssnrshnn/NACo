"""NACo — main entry point.

Boots a single uvicorn server hosting `naco.app:app`. All background services
(RADIUS, TACACS+, profiler, log retention, webhook dispatcher, metrics
collector, guest-session expiry) are started by the FastAPI lifespan.
"""
from __future__ import annotations

import asyncio

import uvicorn

from naco.config import check_production_secrets, check_weak_secrets, get_config
from naco.core import get_logger, setup_logging

log = get_logger(__name__)


def _enforce_production_secrets() -> None:
    """Refuse to boot with placeholder secrets unless ``server.debug`` is on.

    Placeholder session/API/CSRF secrets make every cookie and JWT forgeable;
    the default admin password is public knowledge. quickstart.sh generates
    real values — a placeholder in production means setup was skipped.
    """
    cfg = get_config()
    for warning in check_weak_secrets(cfg):
        log.warning("weak configuration: %s (change it, but not blocking startup)", warning)
    problems = check_production_secrets(cfg)
    if not problems:
        return
    if cfg.server.debug:
        for p in problems:
            log.warning("placeholder secret (allowed in debug mode): %s", p)
        return
    for p in problems:
        log.critical("placeholder secret: %s", p)
    log.critical(
        "Refusing to start with placeholder secrets while server.debug is "
        "false. Run ./quickstart.sh to generate a proper .env, or set real "
        "values via NACO_SESSION_SECRET / NACO_API_SECRET / NACO_CSRF_SECRET "
        "/ NACO_ADMIN_PASSWORD and config.yaml."
    )
    raise SystemExit(1)


async def _serve() -> None:
    cfg = get_config()

    # `proxy_headers=True` makes uvicorn rewrite `request.client.host` /
    # `request.url.scheme` from `X-Forwarded-For` / `X-Forwarded-Proto` —
    # but only for hops listed in `forwarded_allow_ips`. We feed it
    # `server.trusted_proxies` directly so an attacker who can speak to
    # the app port directly cannot spoof the source IP. Application code
    # additionally consults `naco.core.utils.client_ip()` which respects
    # the same allow-list when reading the raw header.
    trusted = cfg.server.trusted_proxies or []
    allow   = ",".join(trusted) if trusted else "127.0.0.1"

    config = uvicorn.Config(
        "naco.app:app",
        host                  = cfg.server.host,
        port                  = cfg.server.port,
        log_level             = cfg.server.log_level.lower(),
        proxy_headers         = True,
        forwarded_allow_ips   = allow,
        access_log            = False,
        timeout_graceful_shutdown = 10,
    )
    server = uvicorn.Server(config)
    await server.serve()


def main() -> None:
    setup_logging()
    _enforce_production_secrets()
    try:
        asyncio.run(_serve())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
