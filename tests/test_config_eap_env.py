"""NACO_EAP_BEARER_TOKEN env handling — the FreeRADIUS sidecar contract.

Compose passes the token to both containers; on the NACo side its presence
must populate ``eap.bearer_token`` and auto-enable the EAP endpoints, while
an explicit ``eap.enabled: false`` in YAML must still win.
"""
from __future__ import annotations

import naco.config as config_mod
from naco.config import get_config


def _fresh_config(monkeypatch, tmp_path, yaml_text: str, token: str | None):
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(yaml_text)
    monkeypatch.setenv("NACO_CONFIG", str(cfg_file))
    if token is None:
        monkeypatch.delenv("NACO_EAP_BEARER_TOKEN", raising=False)
    else:
        monkeypatch.setenv("NACO_EAP_BEARER_TOKEN", token)
    config_mod.get_config.cache_clear()
    try:
        return get_config()
    finally:
        config_mod.get_config.cache_clear()


def test_token_env_auto_enables_eap(monkeypatch, tmp_path):
    cfg = _fresh_config(monkeypatch, tmp_path, "server: {}\n", token="tok123")
    assert cfg.eap.enabled is True
    assert cfg.eap.bearer_token == "tok123"


def test_no_token_leaves_eap_disabled(monkeypatch, tmp_path):
    cfg = _fresh_config(monkeypatch, tmp_path, "server: {}\n", token=None)
    assert cfg.eap.enabled is False
    assert cfg.eap.bearer_token == ""


def test_yaml_explicit_disable_wins_over_token(monkeypatch, tmp_path):
    cfg = _fresh_config(
        monkeypatch, tmp_path, "eap:\n  enabled: false\n", token="tok123"
    )
    assert cfg.eap.enabled is False
    assert cfg.eap.bearer_token == "tok123"
