"""Placeholder-secret startup guard + age-encrypted backups."""
from __future__ import annotations

import shutil
import subprocess

import pytest

from naco.config import (
    AppConfig,
    RadiusClientConfig,
    ServerConfig,
    TacacsConfig,
    check_production_secrets,
)

REAL = {
    "session_secret": "a" * 32, "api_secret": "b" * 32, "csrf_secret": "c" * 32,
    "admin_password": "Str0ng-adm1n-pass",
}


def test_default_config_flags_all_placeholders():
    problems = check_production_secrets(AppConfig())
    joined = " ".join(problems)
    assert "server.session_secret" in joined
    assert "server.api_secret" in joined
    assert "server.csrf_secret" in joined
    assert "server.admin_password" in joined
    assert "tacacs.key" in joined  # tacacs enabled by default with placeholder key


def test_real_secrets_pass():
    cfg = AppConfig(
        server=ServerConfig(**REAL),
        tacacs=TacacsConfig(key="x" * 32),
    )
    assert check_production_secrets(cfg) == []


def test_replace_me_prefix_is_placeholder():
    cfg = AppConfig(server=ServerConfig(**{**REAL, "api_secret": "REPLACE_ME_with_32_random_bytes_hex"}))
    assert any("api_secret" in p for p in check_production_secrets(cfg))


def test_disabled_tacacs_key_not_flagged():
    cfg = AppConfig(server=ServerConfig(**REAL), tacacs=TacacsConfig(enabled=False))
    assert check_production_secrets(cfg) == []


def test_radius_client_placeholder_flagged():
    cfg = AppConfig(server=ServerConfig(**REAL), tacacs=TacacsConfig(key="x" * 32))
    cfg.radius.clients = [RadiusClientConfig(name="sw1", address="10.0.0.1", secret="REPLACE_ME_now")]
    assert any("radius.clients[sw1]" in p for p in check_production_secrets(cfg))


def test_main_refuses_placeholder_secrets_when_not_debug(monkeypatch):
    import naco.main as main_mod

    cfg = AppConfig()  # all placeholders, debug=False
    monkeypatch.setattr(main_mod, "get_config", lambda: cfg)
    with pytest.raises(SystemExit):
        main_mod._enforce_production_secrets()


def test_main_allows_placeholders_in_debug(monkeypatch):
    import naco.main as main_mod

    cfg = AppConfig()
    cfg.server.debug = True
    monkeypatch.setattr(main_mod, "get_config", lambda: cfg)
    main_mod._enforce_production_secrets()  # no raise


def test_main_allows_real_secrets(monkeypatch):
    import naco.main as main_mod

    cfg = AppConfig(server=ServerConfig(**REAL), tacacs=TacacsConfig(key="x" * 32))
    monkeypatch.setattr(main_mod, "get_config", lambda: cfg)
    main_mod._enforce_production_secrets()  # no raise


# ── age encryption helpers ──────────────────────────────────────────────────

age_available = shutil.which("age") and shutil.which("age-keygen")


@pytest.mark.skipif(not age_available, reason="age / age-keygen not installed")
def test_age_roundtrip(tmp_path):
    from naco.cli import _age_decrypt, _age_encrypt

    keyfile = tmp_path / "key.txt"
    out = subprocess.run(["age-keygen", "-o", str(keyfile)], capture_output=True, text=True)
    recipient = out.stderr.strip().split()[-1]  # "Public key: age1…"
    assert recipient.startswith("age1")

    blob = _age_encrypt(b"pg_dump payload with secrets", (recipient,))
    assert b"pg_dump payload" not in blob  # actually encrypted
    assert blob.startswith(b"age-encryption.org/")
    assert _age_decrypt(blob, str(keyfile)) == b"pg_dump payload with secrets"
