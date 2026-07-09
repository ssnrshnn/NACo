"""Connection-pool tuning + PgBouncer mode — the DB-tier scaling contract.

Running N stateless API replicas can exhaust Postgres `max_connections`, so the
pool must be tunable and NACo must support fronting Postgres with PgBouncer
(NullPool + no asyncpg prepared-statement cache). We assert on the engine kwargs
directly so the test needs no live DB driver.
"""
from __future__ import annotations

from sqlalchemy.pool import NullPool

import naco.config as config_mod
from naco.config import AppConfig
from naco.db.database import _engine_kwargs


def _kwargs_for(database: dict) -> dict:
    cfg = AppConfig.model_validate({"database": database, "server": {"debug": False}})
    return _engine_kwargs(cfg)


def test_defaults_use_configured_pool_size():
    kw = _kwargs_for({"url": "postgresql+asyncpg://naco:naco@db:5432/naco"})
    assert kw["pool_size"] == 10
    assert kw["max_overflow"] == 20
    assert kw["pool_timeout"] == 30
    assert kw["pool_recycle"] == 1800
    assert "poolclass" not in kw


def test_custom_pool_size_is_honoured():
    kw = _kwargs_for({
        "url": "postgresql+asyncpg://naco:naco@db:5432/naco",
        "pool_size": 3,
        "max_overflow": 7,
    })
    assert kw["pool_size"] == 3
    assert kw["max_overflow"] == 7


def test_pgbouncer_switches_to_nullpool_and_disables_stmt_cache():
    kw = _kwargs_for({
        "url": "postgresql+asyncpg://naco:naco@pgbouncer:6432/naco",
        "pgbouncer": True,
    })
    assert kw["poolclass"] is NullPool
    # No client-side pool sizing when PgBouncer owns the pool.
    assert "pool_size" not in kw
    assert kw["connect_args"]["prepared_statement_cache_size"] == 0
    assert callable(kw["connect_args"]["prepared_statement_name_func"])
    # Unique statement names each call (transaction-pooling safe).
    f = kw["connect_args"]["prepared_statement_name_func"]
    assert f() != f()


def test_pgbouncer_non_asyncpg_driver_skips_asyncpg_args():
    kw = _kwargs_for({
        "url": "postgresql+psycopg://naco:naco@pgbouncer:6432/naco",
        "pgbouncer": True,
    })
    assert kw["poolclass"] is NullPool
    assert kw["connect_args"] == {}


def test_sqlite_uses_no_pg_pool_settings():
    kw = _kwargs_for({"url": "sqlite+aiosqlite://", "pool_size": 99, "pgbouncer": True})
    assert "pool_size" not in kw
    assert "poolclass" not in kw
    assert kw["connect_args"] == {"check_same_thread": False}


def test_env_overrides_pool_size(monkeypatch, tmp_path):
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(
        "database:\n  url: postgresql+asyncpg://naco:naco@db:5432/naco\n"
    )
    monkeypatch.setenv("NACO_CONFIG", str(cfg_file))
    monkeypatch.setenv("NACO_DB_POOL_SIZE", "5")
    monkeypatch.setenv("NACO_DB_PGBOUNCER", "false")
    config_mod.get_config.cache_clear()
    try:
        cfg = config_mod.get_config()
    finally:
        config_mod.get_config.cache_clear()
    assert cfg.database.pool_size == 5
    assert cfg.database.pgbouncer is False


def test_env_enables_pgbouncer(monkeypatch, tmp_path):
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(
        "database:\n  url: postgresql+asyncpg://naco:naco@pgb:6432/naco\n"
    )
    monkeypatch.setenv("NACO_CONFIG", str(cfg_file))
    monkeypatch.setenv("NACO_DB_PGBOUNCER", "yes")
    config_mod.get_config.cache_clear()
    try:
        cfg = config_mod.get_config()
    finally:
        config_mod.get_config.cache_clear()
    assert cfg.database.pgbouncer is True
