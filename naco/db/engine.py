"""SQLite engine and session factory.

Every transaction starts with ``BEGIN IMMEDIATE``: it takes the write lock up
front, so concurrent writers queue on ``busy_timeout`` instead of failing with
``SQLITE_BUSY`` when a read transaction later tries to write. The price is that
transactions are serialised — keep them short and never hold one open across
slow work (bcrypt, LDAP, network I/O): commit or roll back first.
"""
from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

from sqlalchemy import MetaData, event
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.pool import StaticPool

# Deterministic constraint names — SQLite batch migrations need them.
NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


_engine: AsyncEngine | None = None
_factory: async_sessionmaker[AsyncSession] | None = None


def create_engine_for(path: str) -> AsyncEngine:
    memory = path == ":memory:"
    if memory:
        engine = create_async_engine(
            "sqlite+aiosqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False}
        )
    else:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        engine = create_async_engine(f"sqlite+aiosqlite:///{path}")

    @event.listens_for(engine.sync_engine, "connect")
    def _on_connect(dbapi_conn: Any, _record: Any) -> None:
        # Let SQLAlchemy's "begin" hook below own transaction control.
        dbapi_conn.isolation_level = None
        cur = dbapi_conn.cursor()
        if not memory:
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA synchronous=NORMAL")
        cur.execute("PRAGMA foreign_keys=ON")
        cur.execute("PRAGMA busy_timeout=5000")
        cur.close()

    @event.listens_for(engine.sync_engine, "begin")
    def _on_begin(conn: Any) -> None:
        conn.exec_driver_sql("BEGIN IMMEDIATE")

    return engine


def init_engine(path: str | None = None) -> AsyncEngine:
    """Create the process-wide engine (idempotent for the same process)."""
    global _engine, _factory
    if _engine is None:
        if path is None:
            from naco.config import get_config
            path = get_config().database.path
        _engine = create_engine_for(path)
        _factory = async_sessionmaker(_engine, expire_on_commit=False)
    return _engine


def get_engine() -> AsyncEngine:
    return init_engine()


def session_factory() -> async_sessionmaker[AsyncSession]:
    init_engine()
    assert _factory is not None
    return _factory


async def release(db: AsyncSession) -> None:
    """End the open transaction before slow work — bcrypt, LDAP, the network.

    Every transaction holds SQLite's write lock (BEGIN IMMEDIATE), and RADIUS
    decisions wait behind it. Loaded objects stay usable (expire_on_commit is
    off); call this only when nothing is pending, or pending work is complete.
    """
    if db.in_transaction():
        await db.commit()


async def get_db() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency."""
    async with session_factory()() as session:
        yield session


async def dispose_engine() -> None:
    global _engine, _factory
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _factory = None
