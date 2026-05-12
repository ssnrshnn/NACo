"""SQLAlchemy async database engine and session factory.

Defaults target PostgreSQL via `asyncpg`. SQLite (via `aiosqlite`) is supported
for local development and the test suite — when the database URL starts with
``sqlite``, SQLite-only connect args and PRAGMAs are applied; otherwise we
configure a Postgres-friendly engine with a real connection pool.
"""
from __future__ import annotations

import threading

from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from naco.config import get_config


class Base(DeclarativeBase):
    pass


_engine = None
_session_factory = None
_init_lock = threading.Lock()


def _is_sqlite(url: str) -> bool:
    return url.startswith("sqlite")


def _build_engine():
    cfg = get_config()
    url = cfg.database.url

    if _is_sqlite(url):
        engine = create_async_engine(
            url,
            echo=cfg.server.debug,
            pool_pre_ping=True,
            connect_args={"check_same_thread": False},
        )

        @event.listens_for(engine.sync_engine, "connect")
        def _set_sqlite_pragmas(dbapi_conn, _connection_record):
            cursor = dbapi_conn.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA busy_timeout=5000")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

        return engine

    # PostgreSQL (or any non-SQLite backend): real pool, no SQLite-only kwargs.
    return create_async_engine(
        url,
        echo=cfg.server.debug,
        pool_pre_ping=True,
        pool_size=10,
        max_overflow=20,
        pool_recycle=1800,
    )


def _get_engine():
    global _engine
    if _engine is None:
        with _init_lock:
            if _engine is None:
                _engine = _build_engine()
    return _engine


def _get_session_factory():
    global _session_factory
    if _session_factory is None:
        with _init_lock:
            if _session_factory is None:
                _session_factory = async_sessionmaker(
                    bind=_get_engine(),
                    class_=AsyncSession,
                    expire_on_commit=False,
                )
    return _session_factory


class _EngineProxy:
    """Proxy that lazily creates the engine on first attribute access."""

    def __getattr__(self, name):
        return getattr(_get_engine(), name)

    def __call__(self, *args, **kwargs):
        return _get_engine()(*args, **kwargs)


class _SessionProxy:
    """Proxy that lazily creates the session factory on first call."""

    def __call__(self, *args, **kwargs):
        return _get_session_factory()(*args, **kwargs)

    def __getattr__(self, name):
        return getattr(_get_session_factory(), name)


engine = _EngineProxy()
AsyncSessionLocal = _SessionProxy()


async def get_db() -> AsyncSession:
    """FastAPI dependency — yields an async session."""
    async with _get_session_factory()() as session:
        yield session


async def init_db() -> None:
    """Create all tables (used by tests and the first-run bootstrap).

    In production the schema is managed by Alembic migrations; this function
    is idempotent and only creates missing tables, so it's safe to call.
    """
    from naco.db import models  # noqa: F401 — populate Base.metadata
    async with _get_engine().begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
