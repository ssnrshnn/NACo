"""Per-request correlation IDs.

A single browser click can fan out into a Web UI handler, a database write,
a webhook dispatch, and a RADIUS log emit — each running on different
coroutines and threads. Without a correlation ID, stitching those log lines
back together during an incident is guesswork.

What this module does
---------------------
* Generates a UUID4 (or honours an upstream ``X-Request-ID`` if a trusted
  proxy provided one — Caddy / Nginx commonly do this).
* Stashes it in a :class:`contextvars.ContextVar` so it survives ``await``
  boundaries and ``asyncio.create_task``-spawned children.
* Exposes a :class:`RequestIDFilter` that splices the ID onto every
  :class:`logging.LogRecord` as ``record.request_id`` so it can be
  referenced from log formatters with ``%(request_id)s``.
* Echoes the ID back on the response as ``X-Request-ID`` so clients can
  cite it in support requests.

Use from non-HTTP code
----------------------
RADIUS / TACACS+ packet handlers don't have a Request object, but they
can still benefit from correlation when, e.g., a RADIUS accounting packet
triggers an event handled by an HTTP webhook. Helpers:

    set_request_id("radius-" + secrets.token_hex(8))
    log.info("processing packet")  # log records carry request_id="radius-..."
"""
from __future__ import annotations

import logging
import uuid
from contextvars import ContextVar

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request


# Default value is an empty string so format strings like
# ``%(request_id)s`` don't blow up when the filter hasn't run yet (e.g.
# logs emitted during application start-up).
_request_id_var: ContextVar[str] = ContextVar("naco_request_id", default="")

# Header used both for inbound (trusted-proxy) and outbound propagation.
HEADER_NAME = "X-Request-ID"

# Cap inbound IDs at this length to bound log line growth — pathological
# proxies can otherwise send multi-KB values. UUIDv4 is 36 chars; we allow
# enough headroom for Cloudflare's ray IDs (16 chars) and the K8s
# ``istio-request-id`` (UUID + suffix).
_MAX_INBOUND_LEN = 128


def get_request_id() -> str:
    """Return the current request ID, or ``""`` if none is set."""
    return _request_id_var.get()


def set_request_id(value: str) -> None:
    """Set the request ID for the current asyncio context.

    Useful from background-task code (RADIUS / TACACS+ packet handlers,
    profiler) so log lines emitted under that ID carry it through.
    """
    _request_id_var.set(value)


def new_request_id() -> str:
    """Mint a fresh UUID4 hex (no dashes — shorter, still unique)."""
    return uuid.uuid4().hex


class RequestIDFilter(logging.Filter):
    """Logging filter that splices the current request ID onto every record.

    Applied at the root logger by :func:`naco.core.logger.setup_logging`.
    Format strings can then reference ``%(request_id)s``.
    """

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003 — stdlib API
        record.request_id = get_request_id() or "-"
        return True


class RequestIDMiddleware(BaseHTTPMiddleware):
    """ASGI middleware that assigns / propagates ``X-Request-ID``.

    Behaviour:

    1. If the request carries ``X-Request-ID`` *and* the immediate client
       is in ``server.trusted_proxies``, the inbound value is honoured
       (after length-capping). This lets the operator's load-balancer set
       the ID so trace IDs line up across services.
    2. Otherwise a fresh UUID4 hex is generated.
    3. The ID is stored on ``request.state.request_id`` (cheap accessor
       for route code) and in the contextvar (for log lines emitted from
       deep call stacks).
    4. The response ``X-Request-ID`` header echoes the ID so clients can
       cite it.
    """

    async def dispatch(self, request: Request, call_next):
        # Honour an upstream-set ID only when the immediate peer is trusted.
        inbound = request.headers.get(HEADER_NAME, "").strip()
        request_id = ""
        if inbound:
            # Defer the trusted-proxy lookup to the same helper used elsewhere
            # so the policy is unified.
            from naco.core.utils import _peer_ip_is_trusted  # type: ignore[attr-defined]
            try:
                trusted = _peer_ip_is_trusted(request)
            except Exception:
                trusted = False
            if trusted:
                request_id = inbound[:_MAX_INBOUND_LEN]

        if not request_id:
            request_id = new_request_id()

        token = _request_id_var.set(request_id)
        request.state.request_id = request_id
        try:
            response = await call_next(request)
        finally:
            _request_id_var.reset(token)

        response.headers[HEADER_NAME] = request_id
        return response
