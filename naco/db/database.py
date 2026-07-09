"""SQLAlchemy async database engine and session factory.

Defaults target PostgreSQL via `asyncpg`. SQLite (via `aiosqlite`) is supported
for local development and the test suite — when the database URL starts with
``sqlite``, SQLite-only connect args and PRAGMAs are applied; otherwise we
configure a Postgres-friendly engine with a real connection pool.
"""
from __future__ import annotations

import threading
import uuid
from collections.abc import AsyncGenerator

from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.pool import NullPool

from naco.config import get_config


class Base(DeclarativeBase):
    pass


_engine = None
_session_factory = None
_init_lock = threading.Lock()


def _is_sqlite(url: str) -> bool:
    return url.startswith("sqlite")


def _engine_kwargs(cfg) -> dict:
    """Compute create_async_engine kwargs for *cfg* (no driver import needed).

    Split out from :func:`_build_engine` so the pool-selection logic can be
    unit-tested without a live database driver installed.
    """
    url = cfg.database.url
    db = cfg.database

    if _is_sqlite(url):
        return {
            "echo": cfg.server.debug,
            "pool_pre_ping": True,
            "connect_args": {"check_same_thread": False},
        }

    # PgBouncer (or any transaction-level pooler) in front of Postgres: let the
    # proxy own the pool (NullPool) and disable asyncpg's prepared-statement
    # cache with unique statement names — required for transaction pooling,
    # where a client connection is not pinned to one backend.
    if db.pgbouncer:
        # asyncpg-specific knobs; harmless to omit for other drivers.
        connect_args: dict = {}
        if "asyncpg" in url:
            connect_args = {
                "prepared_statement_cache_size": 0,
                "prepared_statement_name_func": lambda: f"__asyncpg_{uuid.uuid4()}__",
            }
        return {
            "echo": cfg.server.debug,
            "poolclass": NullPool,
            "pool_pre_ping": db.pool_pre_ping,
            "connect_args": connect_args,
        }

    # Direct-to-Postgres: a real client-side connection pool. Size it so that
    # (replicas × (pool_size + max_overflow)) stays under `max_connections`.
    return {
        "echo": cfg.server.debug,
        "pool_pre_ping": db.pool_pre_ping,
        "pool_size": db.pool_size,
        "max_overflow": db.max_overflow,
        "pool_timeout": db.pool_timeout,
        "pool_recycle": db.pool_recycle,
    }


def _build_engine():
    cfg = get_config()
    url = cfg.database.url
    engine = create_async_engine(url, **_engine_kwargs(cfg))

    if _is_sqlite(url):
        @event.listens_for(engine.sync_engine, "connect")
        def _set_sqlite_pragmas(dbapi_conn, _connection_record):
            cursor = dbapi_conn.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA busy_timeout=5000")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    return engine


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


async def get_db() -> AsyncGenerator[AsyncSession, None]:
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
