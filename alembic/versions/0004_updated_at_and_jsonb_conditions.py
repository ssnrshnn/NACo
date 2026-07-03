"""Add updated_at to key models + switch policies.conditions to JSON type

Adds ``updated_at`` (nullable, server_default=now()) to:
  * users
  * policies
  * nas_clients
  * tacacs_clients
  * admin_users

Switches ``policies.conditions`` from Text to JSON (JSONB on Postgres,
JSON-as-text on SQLite) so the DB can index and query conditions natively.

Revision ID: 0004_updated_at_jsonb
Revises:    0003_phase0
Create Date: 2026-05-17 12:00:00.000000
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0004_updated_at_jsonb"
down_revision: Union[str, None] = "0003_phase0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_TABLES_NEEDING_UPDATED_AT = [
    "users",
    "policies",
    "nas_clients",
    "tacacs_clients",
    "admin_users",
]


def upgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name

    # ── Add updated_at columns ────────────────────────────────────────
    for table in _TABLES_NEEDING_UPDATED_AT:
        with op.batch_alter_table(table) as batch:
            batch.add_column(
                sa.Column(
                    "updated_at",
                    sa.DateTime(timezone=True),
                    nullable=True,
                    server_default=sa.func.now(),
                ),
            )

    # Backfill updated_at = created_at for existing rows
    for table in _TABLES_NEEDING_UPDATED_AT:
        op.execute(f"UPDATE {table} SET updated_at = created_at WHERE updated_at IS NULL")

    # ── Switch policies.conditions from Text to JSON ──────────────────
    if dialect == "postgresql":
        # Postgres: cast the existing text to jsonb in-place
        op.execute(
            "ALTER TABLE policies "
            "ALTER COLUMN conditions TYPE JSONB USING conditions::jsonb"
        )
        op.execute(
            "ALTER TABLE policies "
            "ALTER COLUMN conditions SET DEFAULT '[]'::jsonb"
        )
    # SQLite: JSON is stored as text anyway — no schema change needed.
    # The SQLAlchemy model change (Text → JSON) is sufficient.


def downgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name

    # ── Revert policies.conditions back to Text ───────────────────────
    if dialect == "postgresql":
        op.execute(
            "ALTER TABLE policies "
            "ALTER COLUMN conditions TYPE TEXT USING conditions::text"
        )
        op.execute(
            "ALTER TABLE policies "
            "ALTER COLUMN conditions SET DEFAULT '[]'"
        )

    # ── Drop updated_at columns ───────────────────────────────────────
    for table in reversed(_TABLES_NEEDING_UPDATED_AT):
        with op.batch_alter_table(table) as batch:
            batch.drop_column("updated_at")
