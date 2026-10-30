"""Internal HTTP API for FreeRADIUS (port 8081 — never published, never proxied).

Status codes are chosen for rlm_rest:

* 200 + attributes → ``updated``, 204 → ``ok``  (accept / done)
* 401 → ``reject``
* anything else (bad token, malformed body, crash, timeout) → ``fail`` /
  ``invalid``, which our FreeRADIUS config turns into a reject — and for
  accounting into *no* Accounting-Response, so the NAS retransmits.
"""
from __future__ import annotations

import hmac
import json
import logging
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse

from naco.aaa import service
from naco.aaa.rlm import Attrs, reply, vlan_attributes
from naco.config import get_secrets
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


async def _attrs(request: Request) -> Attrs:
    body = await request.body()
    if len(body) > MAX_BODY:
        raise HTTPException(status_code=413, detail="request too large")
    try:
        return Attrs.parse(json.loads(body or b"{}"))
    except (ValueError, UnicodeDecodeError) as exc:
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

    @app.post("/aaa/authenticate", dependencies=guarded)
    async def authenticate(request: Request) -> Response:
        attrs = await _attrs(request)
        with _timer("authenticate"):
            ok = await service.authenticate(attrs)
        return Response(status_code=204 if ok else 401)

    @app.post("/aaa/authorize", dependencies=guarded)
    async def authorize(request: Request) -> Response:
        attrs = await _attrs(request)
        with _timer("authorize"):
            decision = await service.authorize(attrs)
        if not decision.accepted:
            return Response(status_code=401)
        out: dict[str, Any] = {}
        if decision.vlan:
            out.update(vlan_attributes(decision.vlan))
        out.update(decision.reply_attributes)
        return JSONResponse(reply(out)) if out else Response(status_code=204)

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
