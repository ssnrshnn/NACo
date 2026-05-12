"""NACo — main entry point.

Boots a single uvicorn server hosting `naco.app:app`. All background services
(RADIUS, TACACS+, profiler, log retention, webhook dispatcher, metrics
collector, guest-session expiry) are started by the FastAPI lifespan.
"""
from __future__ import annotations

import asyncio

import uvicorn

from naco.config import get_config
from naco.core import get_logger, setup_logging

log = get_logger(__name__)


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
    try:
        asyncio.run(_serve())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
