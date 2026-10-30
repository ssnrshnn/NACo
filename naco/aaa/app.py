"""Internal HTTP API for FreeRADIUS (port 8081 — never published, never proxied).

Status codes are chosen for rlm_rest:

* authenticate: 204 → ``ok``, 401 → ``reject``
* authorize: 200 with ``control:NACo-Decision`` = ``accept`` (plus VLAN and
  attributes) or ``reject``; our FreeRADIUS config accepts only on an
  explicit ``accept``
* accounting: 204 once the database write succeeded
* anything else (bad token, malformed body, crash, timeout) → ``fail`` /
  ``invalid``, which rejects — and for accounting sends *no*
  Accounting-Response, so the NAS retransmits.
"""
from __future__ import annotations

import hmac
import logging
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse

from naco.aaa import service
from naco.aaa.rlm import Attrs, loads, reply, vlan_attributes
from naco.config import get_secrets
from naco.core import runtime
from naco.core.metrics import REGISTRY
from naco.core.netutils import parse_ip

log = logging.getLogger(__name__)

MAX_BODY = 64 * 1024
LATENCY = REGISTRY.histogram("naco_aaa_request_seconds", "Internal AAA API latency", ["endpoint"])


def _require_token(request: Request) -> None:
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    expected = get_secrets().internal_token.encode()
    if scheme.lower() != "bearer" or not hmac.compare_digest(token.strip().encode(), expected):
        raise HTTPException(status_code=403, detail="forbidden")
    runtime.mark_aaa_request()


async def _attrs(request: Request) -> Attrs:
    body = await request.body()
    if len(body) > MAX_BODY:
        raise HTTPException(status_code=413, detail="request too large")
    try:
        return Attrs.parse(loads(body))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="malformed rlm_rest body") from exc


@contextmanager
def _timer(endpoint: str) -> Iterator[None]:
    start = time.perf_counter()
    try:
        yield
    finally:
        LATENCY.observe(time.perf_counter() - start, endpoint=endpoint)


def create_internal_app() -> FastAPI:
    app = FastAPI(title="NACo internal AAA API", docs_url=None, redoc_url=None, openapi_url=None)
    guarded = [Depends(_require_token)]

    @app.get("/aaa/clients/{ip}", dependencies=guarded)
    async def client(ip: str) -> Response:
        if parse_ip(ip) is None:
            return Response(status_code=404)
        with _timer("clients"):
            found = await service.lookup_client(ip)
        if found is None:
            return Response(status_code=404)
        addr_attr = "FreeRADIUS-Client-IPv6-Address" if ":" in found.ip else "FreeRADIUS-Client-IP-Address"
        return JSONResponse(reply({
            f"control:{addr_attr}": found.ip,
            "control:FreeRADIUS-Client-Secret": found.secret,
            "control:FreeRADIUS-Client-Shortname": found.name,
            "control:FreeRADIUS-Client-NAS-Type": "other",
            "control:FreeRADIUS-Client-Require-MA": "yes" if found.require_message_authenticator else "no",
        }))

    @app.get("/aaa/status", dependencies=guarded)
    async def status() -> Response:
        """FreeRADIUS answers a NAS's Status-Server probe only when this answers."""
        return Response(status_code=204)

    @app.post("/aaa/authenticate", dependencies=guarded)
    async def authenticate(request: Request) -> Response:
        attrs = await _attrs(request)
        with _timer("authenticate"):
            ok = await service.authenticate(attrs)
        return Response(status_code=204 if ok else 401)

    @app.post("/aaa/authorize", dependencies=guarded)
    async def authorize(request: Request) -> Response:
        # The decision travels as control:NACo-Decision; FreeRADIUS accepts
        # only on an explicit "accept" (errors and anything else reject).
        attrs = await _attrs(request)
        with _timer("authorize"):
            decision = await service.authorize(attrs)
        if not decision.accepted:
            return JSONResponse(reply({"control:NACo-Decision": "reject"}))
        out: dict[str, Any] = {"control:NACo-Decision": "accept"}
        if decision.vlan:
            out.update(vlan_attributes(decision.vlan))
        out.update(decision.reply_attributes)
        return JSONResponse(reply(out))

    @app.post("/aaa/accounting", dependencies=guarded)
    async def accounting(request: Request) -> Response:
        attrs = await _attrs(request)
        with _timer("accounting"):
            await service.accounting(attrs)  # an exception → 500 → no Accounting-Response
        return Response(status_code=204)

    @app.get("/metrics")
    async def metrics() -> PlainTextResponse:
        return PlainTextResponse(REGISTRY.render(), media_type="text/plain; version=0.0.4")

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    return app
