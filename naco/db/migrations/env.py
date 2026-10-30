"""Alembic environment — runs inside the package, configured by naco.db.migrate."""
from __future__ import annotations

from typing import Any

import sqlalchemy as sa
from alembic import context

import naco.db.models  # noqa: F401 — register tables
from naco.db.engine import Base
from naco.db.types import EncryptedString, UTCDateTime

config = context.config
target_metadata = Base.metadata


def render_item(type_: str, obj: Any, autogen_context: Any) -> str | bool:
    """Render NACo's TypeDecorators as their storage types.

    Migrations describe the on-disk schema; encryption and timezone handling
    live in the models, so migration files never import naco.db.types.
    """
    if type_ == "type" and isinstance(obj, UTCDateTime):
        return "sa.DateTime()"
    if type_ == "type" and isinstance(obj, EncryptedString):
        return f"sa.String(length={obj.impl.length})"
    return False


def _configure(**kwargs: Any) -> None:
    context.configure(
        target_metadata=target_metadata,
        render_as_batch=True,
        render_item=render_item,
        compare_type=True,
        **kwargs,
    )


def run_migrations_offline() -> None:
    _configure(url=config.get_main_option("sqlalchemy.url"), literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    engine = sa.create_engine(config.get_main_option("sqlalchemy.url"), poolclass=sa.pool.NullPool)
    with engine.connect() as connection:
        _configure(connection=connection)
        with context.begin_transaction():
            context.run_migrations()
    engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
