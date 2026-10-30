from datetime import UTC, datetime

from naco import config
from naco.core.oui import vendor_for
from naco.core.timeutil import to_local, utcnow


def test_oui_lookup():
    assert "Apple" in vendor_for("00:1B:63:00:00:01")
    assert vendor_for("da:a1:19:00:00:01") == ""  # randomised
    assert vendor_for("not-a-mac") == ""


def test_time_helpers(monkeypatch, tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text("server:\n  timezone: Europe/Istanbul\n")
    monkeypatch.setenv("NACO_CONFIG", str(p))
    config.reset_caches()
    assert utcnow().tzinfo is UTC
    local = to_local(datetime(2026, 1, 1, 12, 0, tzinfo=UTC))
    assert local.hour == 15
