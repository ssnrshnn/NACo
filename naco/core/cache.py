"""Redis client factories — both async and sync flavours.

Why two clients?
    The web request path is async; the RADIUS/TACACS+ servers run in worker
    threads. Rather than ferry one across event loops, each side gets its own
    connection pool. Both honour the same ``cache.url`` config and gracefully
    degrade to ``None`` (callers should handle that) when Redis is unreachable.
"""
from __future__ import annotations

import asyncio
import threading
from typing import Any

from naco.config import get_config
from naco.core.logger import get_logger

log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Lazy singletons
# ---------------------------------------------------------------------------

_async_client = None
_async_client_lock = asyncio.Lock()

_sync_client = None
_sync_client_lock = threading.Lock()

_warned_unreachable: dict[str, bool] = {"async": False, "sync": False}


def _warn_once(flavour: str, url: str, exc: Exception) -> None:
    if _warned_unreachable[flavour]:
        return
    _warned_unreachable[flavour] = True
    log.warning("Redis (%s) at %s unreachable: %s — using in-memory fallback", flavour, url, exc)


async def get_redis() -> Any | None:
    """Return an `redis.asyncio.Redis` client, or `None` if unreachable."""
    global _async_client
    cfg_url = get_config().cache.url
    if not cfg_url:
        return None

    if _async_client is not None:
        return _async_client

    async with _async_client_lock:
        if _async_client is not None:
            return _async_client
        try:
            from redis.asyncio import from_url as _from_url
            client = _from_url(cfg_url, decode_responses=True)
            await client.ping()
            _async_client = client
            log.info("Connected to Redis at %s (async)", cfg_url)
            return _async_client
        except Exception as exc:
            _warn_once("async", cfg_url, exc)
            return None


def get_sync_redis() -> Any | None:
    """Return a synchronous `redis.Redis` client, or `None` if unreachable."""
    global _sync_client
    cfg_url = get_config().cache.url
    if not cfg_url:
        return None

    if _sync_client is not None:
        return _sync_client

    with _sync_client_lock:
        if _sync_client is not None:
            return _sync_client
        try:
            import redis
            client = redis.Redis.from_url(cfg_url, decode_responses=True, socket_timeout=2.0)
            client.ping()
            _sync_client = client
            log.info("Connected to Redis at %s (sync)", cfg_url)
            return _sync_client
        except Exception as exc:
            _warn_once("sync", cfg_url, exc)
            return None


async def close_clients() -> None:
    """Close both clients (used by tests and graceful shutdown)."""
    global _async_client, _sync_client
    if _async_client is not None:
        try:
            await _async_client.aclose()
        except Exception:
            pass
        _async_client = None
    if _sync_client is not None:
        try:
            _sync_client.close()
        except Exception:
            pass
        _sync_client = None


__all__ = ["close_clients", "get_redis", "get_sync_redis"]
