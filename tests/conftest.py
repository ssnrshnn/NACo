"""Shared pytest fixtures.

Every test runs with valid secrets in the environment and its own SQLite file,
so nothing leaks between tests or depends on the developer's machine.
"""
from __future__ import annotations

import base64

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker

from naco import config

TEST_MASTER_KEY = bytes(range(32))
TEST_INTERNAL_TOKEN = "test-internal-token-0123456789abcdef"


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch, tmp_path):
    monkeypatch.setenv("NACO_MASTER_KEY", base64.b64encode(TEST_MASTER_KEY).decode())
    monkeypatch.setenv("NACO_INTERNAL_TOKEN", TEST_INTERNAL_TOKEN)
    monkeypatch.setenv("NACO_DATABASE_PATH", str(tmp_path / "naco.db"))
    for var in ("NACO_CONFIG", "NACO_DEV", "NACO_TRUSTED_PROXIES", "NACO_ADMIN_PASSWORD",
                "NACO_LDAP_BIND_PASSWORD"):
        monkeypatch.delenv(var, raising=False)
    config.reset_caches()
    yield
    config.reset_caches()


@pytest.fixture(autouse=True)
def _fast_bcrypt(monkeypatch):
    from naco.core import passwords
    monkeypatch.setattr(passwords, "BCRYPT_ROUNDS", 4)
    passwords._dummy_hash.cache_clear()
    yield
    passwords._dummy_hash.cache_clear()


@pytest.fixture
async def app_db(tmp_path):
    """The process-wide engine on a freshly migrated database."""
    from naco.db import engine as eng
    from naco.db.migrate import upgrade_head

    path = str(tmp_path / "naco.db")
    upgrade_head(path)
    eng.init_engine(path)
    yield eng.session_factory()
    await eng.dispose_engine()


def write_config(tmp_path, monkeypatch, text: str) -> None:
    p = tmp_path / "config.yaml"
    p.write_text(text)
    monkeypatch.setenv("NACO_CONFIG", str(p))
    config.reset_caches()


@pytest.fixture
async def db_engine(tmp_path):
    import naco.db.models  # noqa: F401 — register tables
    from naco.db.engine import Base, create_engine_for

    engine = create_engine_for(str(tmp_path / "models.db"))
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest.fixture
async def db(db_engine):
    async with async_sessionmaker(db_engine, expire_on_commit=False)() as session:
        yield session
