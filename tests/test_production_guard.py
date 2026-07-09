"""Placeholder-secret startup guard + age-encrypted backups."""
from __future__ import annotations

import shutil
import subprocess

import pytest

from naco.config import (
    AppConfig,
    PortalConfig,
    RadiusClientConfig,
    ServerConfig,
    TacacsConfig,
    check_production_secrets,
    check_weak_secrets,
)

REAL = {
    "session_secret": "a" * 32, "api_secret": "b" * 32, "csrf_secret": "c" * 32,
    "admin_password": "Str0ng-adm1n-pass",
}

# Portal is enabled by default with a placeholder PSK; a fully-clean config
# must also supply a real one.
REAL_PORTAL = PortalConfig(guest_psk="Str0ng-Gu3st-PSK")


def _clean_config() -> AppConfig:
    return AppConfig(
        server=ServerConfig(**REAL),
        tacacs=TacacsConfig(key="x" * 32),
        portal=REAL_PORTAL,
    )


def test_default_config_flags_all_placeholders():
    problems = check_production_secrets(AppConfig())
    joined = " ".join(problems)
    assert "server.session_secret" in joined
    assert "server.api_secret" in joined
    assert "server.csrf_secret" in joined
    assert "server.admin_password" in joined
    assert "tacacs.key" in joined  # tacacs enabled by default with placeholder key


def test_real_secrets_pass():
    assert check_production_secrets(_clean_config()) == []


def test_change_me_prefix_is_placeholder():
    # config.yaml ships "CHANGE_ME_…" placeholders — these must be caught too.
    cfg = AppConfig(server=ServerConfig(**{**REAL, "csrf_secret": "CHANGE_ME_csrf_secret_now"}))
    assert any("csrf_secret" in p for p in check_production_secrets(cfg))


def test_guest_psk_placeholder_is_warning_not_blocker():
    # A placeholder guest Wi-Fi PSK is a non-fatal warning: it must NOT appear
    # in the boot-blocking check, but SHOULD appear in the weak-secret warnings.
    cfg = AppConfig(
        server=ServerConfig(**REAL),
        tacacs=TacacsConfig(key="x" * 32),
        portal=PortalConfig(guest_psk="CHANGE_ME_guest_wifi_password"),
    )
    assert check_production_secrets(cfg) == []
    assert any("portal.guest_psk" in w for w in check_weak_secrets(cfg))


def test_guest_psk_not_warned_when_portal_disabled():
    cfg = AppConfig(
        server=ServerConfig(**REAL),
        tacacs=TacacsConfig(key="x" * 32),
        portal=PortalConfig(enabled=False, guest_psk="guest_password"),
    )
    assert check_weak_secrets(cfg) == []


def test_replace_me_prefix_is_placeholder():
    cfg = AppConfig(server=ServerConfig(**{**REAL, "api_secret": "REPLACE_ME_with_32_random_bytes_hex"}))
    assert any("api_secret" in p for p in check_production_secrets(cfg))


def test_disabled_tacacs_key_not_flagged():
    cfg = AppConfig(
        server=ServerConfig(**REAL),
        tacacs=TacacsConfig(enabled=False),
        portal=REAL_PORTAL,
    )
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

    cfg = _clean_config()
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
