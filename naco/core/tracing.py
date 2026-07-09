"""
OpenTelemetry tracing — optional and zero-cost when disabled.

Design constraints:

* The OTel libraries are an optional extra (``pip install naco[otel]``);
  every import here is deferred and failure-tolerant.
* ``span()`` must be safe to call unconditionally from hot paths (RADIUS
  and TACACS+ handlers): with tracing off it is a no-op context manager
  with no allocations beyond the generator frame.
* Setup never raises — a broken collector configuration must not take
  down the AAA plane.
"""
from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from naco.core.logger import get_logger

log = get_logger(__name__)

_tracer: Any = None  # opentelemetry.trace.Tracer once setup succeeds


@contextmanager
def span(name: str, **attributes: Any) -> Iterator[Any]:
    """Open a tracing span, or do nothing when tracing is not configured.

    Yields the live span object (or ``None`` when disabled) so callers can
    attach late attributes. Exceptions always propagate; with tracing on
    they are recorded on the span first.
    """
    if _tracer is None:
        yield None
        return
    with _tracer.start_as_current_span(name) as current:
        for key, value in attributes.items():
            current.set_attribute(key, value)
        yield current


def setup_tracing(cfg: Any, app: Any = None, engine: Any = None) -> bool:
    """Initialise the OTLP exporter and instrumentations.

    Returns True when tracing is live. Missing libraries, disabled config
    or exporter errors all log and return False.
    """
    global _tracer
    otel = getattr(cfg, "otel", None)
    if otel is None or not otel.enabled:
        return False

    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
            OTLPSpanExporter,
        )
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.sdk.trace.sampling import TraceIdRatioBased
    except ImportError as exc:
        log.warning(
            "otel.enabled is true but the OpenTelemetry libraries are not "
            "installed (pip install 'naco[otel]') — tracing disabled: %s", exc,
        )
        return False

    try:
        resource = Resource.create({
            "service.name": "naco",
            "service.instance.id": cfg.server.name,
            "service.version": __import__("naco").__version__,
        })
        provider = TracerProvider(
            resource=resource,
            sampler=TraceIdRatioBased(max(0.0, min(1.0, otel.sample_ratio))),
        )
        exporter_kwargs = {}
        if otel.endpoint:
            exporter_kwargs["endpoint"] = otel.endpoint.rstrip("/") + "/v1/traces"
        provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(**exporter_kwargs)))
        trace.set_tracer_provider(provider)
        _tracer = trace.get_tracer("naco")
    except Exception as exc:
        log.warning("OpenTelemetry setup failed — tracing disabled: %s", exc)
        return False

    if app is not None:
        try:
            from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
            FastAPIInstrumentor.instrument_app(app)
        except Exception as exc:
            log.debug("FastAPI instrumentation unavailable: %s", exc)
    if engine is not None:
        try:
            from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
            SQLAlchemyInstrumentor().instrument(engine=engine.sync_engine)
        except Exception as exc:
            log.debug("SQLAlchemy instrumentation unavailable: %s", exc)

    log.info("OpenTelemetry tracing enabled (endpoint=%s, sample_ratio=%s)",
             otel.endpoint or "default", otel.sample_ratio)
    return True
