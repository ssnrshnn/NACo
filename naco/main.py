"""NACo entry point: one process, one event loop.

* port ``http_port`` (8080) — admin UI, REST API, guest portal (behind Caddy)
* port ``internal_port`` (8081) — the AAA API FreeRADIUS calls, and /metrics
* port ``tacacs.port`` (4949) — TACACS+, when enabled
* background: maintenance, CoA re-evaluation

Startup refuses invalid configuration or secrets before touching anything.
"""
from __future__ import annotations

import asyncio
import contextlib
import logging
import signal
import sys
from collections.abc import Iterator

import uvicorn

from naco import __version__
from naco.aaa.app import create_internal_app
from naco.bootstrap import ensure_admin
from naco.config import AppConfig, ConfigError, get_config, get_secrets
from naco.core.logging import setup_logging
from naco.db.engine import dispose_engine, init_engine
from naco.db.migrate import upgrade_head
from naco.maintenance import run_maintenance
from naco.radius.reevaluate import reevaluator
from naco.tacacs.server import TacacsServer
from naco.web.app import create_public_app

log = logging.getLogger("naco")


class _Server(uvicorn.Server):
    """uvicorn server whose signals are handled by ``serve`` for both listeners."""

    @contextlib.contextmanager
    def capture_signals(self) -> Iterator[None]:
        yield


def _servers(cfg: AppConfig) -> list[_Server]:
    common = {"host": cfg.server.host, "access_log": False, "log_config": None,
              "server_header": False, "date_header": False, "lifespan": "off"}
    public = uvicorn.Config(
        create_public_app(), port=cfg.server.http_port, proxy_headers=True,
        forwarded_allow_ips=list(cfg.server.trusted_proxies), **common,  # type: ignore[arg-type]
    )
    internal = uvicorn.Config(
        create_internal_app(), port=cfg.server.internal_port, proxy_headers=False, **common,  # type: ignore[arg-type]
    )
    return [_Server(public), _Server(internal)]


async def serve(cfg: AppConfig) -> None:
    init_engine(cfg.database.path)
    await ensure_admin()
    servers = _servers(cfg)
    background = [
        asyncio.create_task(run_maintenance(), name="maintenance"),
        asyncio.create_task(reevaluator.run_forever(), name="coa-reevaluation"),
    ]
    tacacs = TacacsServer(cfg.tacacs) if cfg.tacacs.enabled else None
    if tacacs is not None:
        await tacacs.start(cfg.server.host, cfg.tacacs.port)

    loop = asyncio.get_running_loop()

    def stop() -> None:
        log.info("shutting down")
        for server in servers:
            server.should_exit = True

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop)

    log.info("NACo %s — UI/API on :%d, AAA on :%d%s", __version__, cfg.server.http_port, cfg.server.internal_port,
             f", TACACS+ on :{cfg.tacacs.port}" if tacacs else "")
    try:
        await asyncio.gather(*(s.serve() for s in servers))
    finally:
        if tacacs is not None:
            await tacacs.stop()
        for task in background:
            task.cancel()
        await asyncio.gather(*background, return_exceptions=True)
        await dispose_engine()


def main() -> None:
    try:
        cfg = get_config()
        get_secrets()
    except ConfigError as exc:
        sys.stderr.write(f"naco: {exc}\n")
        raise SystemExit(2) from None
    setup_logging(cfg.server.log_level, cfg.server.log_format, cfg.syslog)
    upgrade_head(cfg.database.path)
    try:
        asyncio.run(serve(cfg))
    except ConfigError as exc:
        log.critical("%s", exc)
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
