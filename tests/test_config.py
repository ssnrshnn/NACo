import base64

import pytest

from naco.config import ConfigError, load_config, load_secrets

GOOD_KEY = base64.b64encode(bytes(range(32))).decode()
GOOD_TOKEN = "t" * 40


def write(tmp_path, text):
    p = tmp_path / "config.yaml"
    p.write_text(text)
    return str(p)


# ── load_config ─────────────────────────────────────────────────────────────

def test_defaults_without_file():
    cfg = load_config(env={})
    assert cfg.server.http_port == 8080
    assert cfg.server.internal_port == 8081
    assert cfg.database.path == "/var/lib/naco/naco.db"
    assert cfg.security.require_totp is True
    assert cfg.tacacs.port == 4949
    assert cfg.ldap.enabled is False


def test_empty_file_gives_defaults(tmp_path):
    cfg = load_config(write(tmp_path, ""), env={})
    assert cfg.server.name == "NACo"


def test_values_are_read(tmp_path):
    cfg = load_config(write(tmp_path, "server:\n  name: core-nac\n  timezone: Europe/Istanbul\n"), env={})
    assert cfg.server.name == "core-nac"
    assert cfg.server.timezone == "Europe/Istanbul"


def test_unknown_key_is_rejected(tmp_path):
    with pytest.raises(ConfigError, match="bogus"):
        load_config(write(tmp_path, "server:\n  bogus: 1\n"), env={})


def test_unknown_section_is_rejected(tmp_path):
    with pytest.raises(ConfigError, match="redis"):
        load_config(write(tmp_path, "redis:\n  url: x\n"), env={})


def test_invalid_timezone_is_rejected(tmp_path):
    with pytest.raises(ConfigError, match="timezone"):
        load_config(write(tmp_path, "server:\n  timezone: Mars/Olympus\n"), env={})


def test_missing_explicit_file_is_an_error(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        load_config(str(tmp_path / "nope.yaml"), env={})


def test_config_path_from_env(tmp_path):
    path = write(tmp_path, "server:\n  name: from-env\n")
    assert load_config(env={"NACO_CONFIG": path}).server.name == "from-env"


def test_env_overrides(tmp_path):
    cfg = load_config(env={
        "NACO_DATABASE_PATH": str(tmp_path / "x.db"),
        "NACO_TRUSTED_PROXIES": "172.30.0.10, 10.0.0.0/8",
    })
    assert cfg.database.path == str(tmp_path / "x.db")
    assert cfg.server.trusted_proxies == ["172.30.0.10/32", "10.0.0.0/8"]


def test_invalid_trusted_proxy_is_rejected():
    with pytest.raises(ConfigError, match="trusted_proxies"):
        load_config(env={"NACO_TRUSTED_PROXIES": "not-an-ip"})


def test_ldap_user_filter_needs_placeholder(tmp_path):
    with pytest.raises(ConfigError, match="username"):
        load_config(write(tmp_path, "ldap:\n  user_filter: '(uid=alice)'\n"), env={})


def test_ldap_enabled_needs_servers(tmp_path):
    with pytest.raises(ConfigError, match="servers"):
        load_config(write(tmp_path, "ldap:\n  enabled: true\n"), env={})


def test_ldap_group_map_keeps_order(tmp_path):
    cfg = load_config(write(tmp_path, (
        "ldap:\n  group_map:\n"
        "    - {ldap_group: 'CN=Admins,DC=x', group: admins}\n"
        "    - {ldap_group: 'CN=Staff,DC=x', group: staff}\n"
    )), env={})
    assert [m.group for m in cfg.ldap.group_map] == ["admins", "staff"]


def test_syslog_enabled_needs_host(tmp_path):
    with pytest.raises(ConfigError, match="host"):
        load_config(write(tmp_path, "syslog:\n  enabled: true\n"), env={})


# ── load_secrets ────────────────────────────────────────────────────────────

def test_secrets_ok():
    s = load_secrets({"NACO_MASTER_KEY": GOOD_KEY, "NACO_INTERNAL_TOKEN": GOOD_TOKEN})
    assert s.master_key == bytes(range(32))
    assert s.internal_token == GOOD_TOKEN
    assert s.ldap_bind_password == ""
    assert s.admin_password is None


def test_hex_master_key_accepted():
    s = load_secrets({"NACO_MASTER_KEY": bytes(range(32)).hex(), "NACO_INTERNAL_TOKEN": GOOD_TOKEN})
    assert s.master_key == bytes(range(32))


def test_missing_master_key_is_an_error():
    with pytest.raises(ConfigError, match="NACO_MASTER_KEY"):
        load_secrets({"NACO_INTERNAL_TOKEN": GOOD_TOKEN})


def test_short_master_key_is_an_error():
    with pytest.raises(ConfigError, match="32 bytes"):
        load_secrets({"NACO_MASTER_KEY": base64.b64encode(b"short").decode(),
                      "NACO_INTERNAL_TOKEN": GOOD_TOKEN})


def test_short_internal_token_is_an_error():
    with pytest.raises(ConfigError, match="NACO_INTERNAL_TOKEN"):
        load_secrets({"NACO_MASTER_KEY": GOOD_KEY, "NACO_INTERNAL_TOKEN": "short"})


@pytest.mark.parametrize("value", ["REPLACE_ME_with_something_long_enough_123", "change_me_" + "x" * 40])
def test_placeholder_is_an_error(value):
    with pytest.raises(ConfigError, match="placeholder"):
        load_secrets({"NACO_MASTER_KEY": GOOD_KEY, "NACO_INTERNAL_TOKEN": value})


def test_file_variant_takes_precedence(tmp_path):
    f = tmp_path / "token"
    f.write_text("f" * 40 + "\n")
    s = load_secrets({
        "NACO_MASTER_KEY": GOOD_KEY,
        "NACO_INTERNAL_TOKEN": "e" * 40,
        "NACO_INTERNAL_TOKEN_FILE": str(f),
    })
    assert s.internal_token == "f" * 40


def test_unreadable_secret_file_is_an_error(tmp_path):
    with pytest.raises(ConfigError, match="NACO_INTERNAL_TOKEN_FILE"):
        load_secrets({"NACO_MASTER_KEY": GOOD_KEY, "NACO_INTERNAL_TOKEN_FILE": str(tmp_path / "missing")})


def test_optional_secrets_are_read():
    s = load_secrets({
        "NACO_MASTER_KEY": GOOD_KEY, "NACO_INTERNAL_TOKEN": GOOD_TOKEN,
        "NACO_LDAP_BIND_PASSWORD": "bindpw", "NACO_ADMIN_PASSWORD": "initial-admin-pw",
    })
    assert s.ldap_bind_password == "bindpw"
    assert s.admin_password == "initial-admin-pw"


def test_dev_mode_fills_missing_secrets():
    s = load_secrets({"NACO_DEV": "1"})
    assert len(s.master_key) == 32
    assert len(s.internal_token) >= 32


def test_dev_mode_still_rejects_bad_values():
    with pytest.raises(ConfigError):
        load_secrets({"NACO_DEV": "1", "NACO_INTERNAL_TOKEN": "short"})


def test_portal_access_code_must_not_be_guessable(tmp_path):
    with pytest.raises(ConfigError, match="access_code"):
        load_config(write(tmp_path, "portal:\n  access_code: '1234'\n"), env={})
    assert load_config(write(tmp_path, "portal:\n  access_code: ' Sesame-42 '\n"), env={}).portal.access_code == "Sesame-42"


# ── shipped files ───────────────────────────────────────────────────────────

def test_shipped_config_is_valid_and_matches_defaults():
    """config/config.yaml documents the defaults; it must load and agree with them."""
    from pathlib import Path
    shipped = load_config(str(Path(__file__).parent.parent / "config" / "config.yaml"), env={})
    assert shipped == load_config(env={})


def test_env_example_holds_only_placeholders():
    from pathlib import Path
    text = (Path(__file__).parent.parent / ".env.example").read_text()
    values = dict(line.split("=", 1) for line in text.splitlines() if line and not line.startswith("#"))
    for name in ("NACO_MASTER_KEY", "NACO_INTERNAL_TOKEN", "NACO_ADMIN_PASSWORD"):
        assert values[name] == "REPLACE_ME"
