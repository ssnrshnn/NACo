"""
OpenTelemetry integration — optional, graceful, zero-cost when disabled.

The tracing layer must be safe to call unconditionally from hot paths:
with tracing disabled (or the OTel libraries absent) `span()` has to be a
working no-op context manager, and setup must never raise.
"""
from __future__ import annotations

import pytest

from naco.core import tracing


def test_span_is_noop_when_disabled():
    with tracing.span("radius.auth", nas_ip="10.0.0.1") as current:
        assert current is None  # no active tracer → no span object


def test_span_swallows_nothing(recwarn):
    """Exceptions inside a span must propagate — tracing is observability,
    not error handling."""
    with pytest.raises(ValueError):
        with tracing.span("radius.auth"):
            raise ValueError("boom")


def test_setup_disabled_returns_false():
    from naco.config import get_config
    cfg = get_config()
    assert cfg.otel.enabled is False
    assert tracing.setup_tracing(cfg) is False


def test_setup_enabled_without_libs_is_graceful(monkeypatch):
    """With otel.enabled=true but the SDK not importable, setup logs and
    returns False instead of crashing the process."""
    import builtins

    from naco.config import get_config

    real_import = builtins.__import__

    def _no_otel(name, *args, **kwargs):
        if name.startswith("opentelemetry"):
            raise ImportError(f"blocked for test: {name}")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _no_otel)
    cfg = get_config().model_copy(deep=True)
    cfg.otel.enabled = True
    cfg.otel.endpoint = "http://localhost:4318"
    assert tracing.setup_tracing(cfg) is False


def test_otel_env_override(monkeypatch, tmp_path):
    """NACO_OTEL_ENDPOINT enables tracing unless YAML explicitly disables."""
    import naco.config as config_mod

    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text("server:\n  name: t\n")
    monkeypatch.setenv("NACO_CONFIG", str(cfg_file))
    monkeypatch.setenv("NACO_OTEL_ENDPOINT", "http://collector:4318")
    config_mod.get_config.cache_clear()
    try:
        cfg = config_mod.get_config()
        assert cfg.otel.enabled is True
        assert cfg.otel.endpoint == "http://collector:4318"
    finally:
        config_mod.get_config.cache_clear()
