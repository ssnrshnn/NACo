"""Phase 0.4 — PostgreSQL CLI must not put the DB password on the command line."""
from __future__ import annotations

from urllib.parse import quote

from naco.cli import postgresql_cli_env_and_argv


def test_password_only_in_pgpassword_env():
    # Password contains reserved URL characters — they must be percent-encoded
    # in the DSN or the first ``@`` is treated as end of ``user:password``.
    secret = "hunter2!@#"
    enc = quote(secret, safe="")
    url = f"postgresql+asyncpg://nacouser:{enc}@db.example.com:5433/mydb"
    env, argv = postgresql_cli_env_and_argv(url)

    assert env.get("PGPASSWORD") == secret

    cmdline = " ".join(["pg_dump", "--format=plain", *argv])
    assert secret not in cmdline
    assert "hunter2" not in cmdline

    assert "-h" in argv and "db.example.com" in argv
    assert "-p" in argv and "5433" in argv
    assert "-U" in argv and "nacouser" in argv
    assert "-d" in argv and "mydb" in argv


def test_no_password_clears_stale_pgpassword(monkeypatch):
    monkeypatch.setenv("PGPASSWORD", "stale-from-shell")
    env, _argv = postgresql_cli_env_and_argv(
        "postgresql://nacouser@localhost:5432/mydb",
    )
    assert env.get("PGPASSWORD") is None
