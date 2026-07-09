"""Role selection — the horizontal-scale split contract.

``server.roles`` controls which subsystems a process runs. The default
(``["all"]``) must behave exactly like the classic all-in-one deployment so
existing single-node installs never change. ``NACO_ROLES`` overrides YAML.
"""
from __future__ import annotations

import naco.config as config_mod
from naco.config import ServerConfig, get_config


def _fresh_config(monkeypatch, tmp_path, yaml_text: str, roles_env: str | None):
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(yaml_text)
    monkeypatch.setenv("NACO_CONFIG", str(cfg_file))
    if roles_env is None:
        monkeypatch.delenv("NACO_ROLES", raising=False)
    else:
        monkeypatch.setenv("NACO_ROLES", roles_env)
    config_mod.get_config.cache_clear()
    try:
        return get_config()
    finally:
        config_mod.get_config.cache_clear()


def test_default_is_all_in_one():
    srv = ServerConfig()
    assert srv.roles == ["all"]
    for role in ("api", "radius", "tacacs", "profiler", "workers"):
        assert srv.has_role(role) is True


def test_all_keyword_implies_every_role():
    srv = ServerConfig(roles=["all"])
    assert srv.has_role("radius") is True
    assert srv.has_role("workers") is True


def test_explicit_subset_excludes_others():
    srv = ServerConfig(roles=["api", "workers"])
    assert srv.has_role("api") is True
    assert srv.has_role("workers") is True
    assert srv.has_role("radius") is False
    assert srv.has_role("tacacs") is False
    assert srv.has_role("profiler") is False


def test_role_matching_is_case_and_space_insensitive():
    srv = ServerConfig(roles=[" Radius ", "TACACS"])
    assert srv.has_role("radius") is True
    assert srv.has_role("tacacs") is True
    assert srv.has_role("api") is False


def test_empty_roles_falls_back_to_all():
    srv = ServerConfig(roles=[])
    assert srv.has_role("radius") is True


def test_env_overrides_yaml_roles(monkeypatch, tmp_path):
    cfg = _fresh_config(
        monkeypatch, tmp_path, "server:\n  roles: [all]\n", roles_env="api,workers"
    )
    assert cfg.server.roles == ["api", "workers"]
    assert cfg.server.has_role("api") is True
    assert cfg.server.has_role("radius") is False


def test_blank_env_keeps_yaml_roles(monkeypatch, tmp_path):
    cfg = _fresh_config(
        monkeypatch, tmp_path, "server:\n  roles: [radius]\n", roles_env=" , "
    )
    assert cfg.server.roles == ["radius"]
    assert cfg.server.has_role("radius") is True
    assert cfg.server.has_role("api") is False


def test_unset_env_uses_yaml_default(monkeypatch, tmp_path):
    cfg = _fresh_config(monkeypatch, tmp_path, "server: {}\n", roles_env=None)
    assert cfg.server.roles == ["all"]
    assert cfg.server.has_role("radius") is True
