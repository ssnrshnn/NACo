"""add admin_users.role for RBAC (Phase 1.1)

Adds a three-valued ``role`` column to ``admin_users``:

* ``SUPERUSER`` – full access (rotate secrets, edit YAML, manage admins).
* ``OPERATOR``  – day-to-day CRUD (default for any existing non-superuser).
* ``VIEWER``    – read-only.

Existing rows are upgraded as follows:
  * ``is_superuser=True`` → ``SUPERUSER``
  * everyone else          → ``OPERATOR``

We deliberately don't grant ``OPERATOR`` to the bootstrap admin — the seeder
in ``naco.app._seed_database`` keeps creating the first user as
``SUPERUSER``.

Revision ID: 0002_admin_role
Revises:    0001_initial
Create Date: 2026-05-12 12:00:00.000000
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0002_admin_role"
down_revision: Union[str, None] = "0001_initial"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_ROLE_ENUM = sa.Enum("SUPERUSER", "OPERATOR", "VIEWER", name="adminrole")


def upgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name

    # Postgres needs the type created before referencing it in a column;
    # SQLite ignores enums entirely (renders as VARCHAR + CHECK).
    if dialect == "postgresql":
        _ROLE_ENUM.create(bind, checkfirst=True)

    # Adding a NOT NULL column to a populated table requires a default.
    with op.batch_alter_table("admin_users") as batch:
        batch.add_column(
            sa.Column(
                "role",
                _ROLE_ENUM,
                nullable=False,
                server_default="OPERATOR",
            )
        )

    # Promote existing superusers; everyone else stays OPERATOR (the default).
    op.execute(
        "UPDATE admin_users SET role = 'SUPERUSER' WHERE is_superuser = TRUE"
        if dialect == "postgresql"
        else "UPDATE admin_users SET role = 'SUPERUSER' WHERE is_superuser = 1"
    )


def downgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name

    with op.batch_alter_table("admin_users") as batch:
        batch.drop_column("role")

    if dialect == "postgresql":
        _ROLE_ENUM.drop(bind, checkfirst=True)
