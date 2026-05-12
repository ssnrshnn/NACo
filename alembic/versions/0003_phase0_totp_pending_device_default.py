"""Phase 0 — TOTP pending secret column + device default-deny

* Adds ``admin_users.pending_totp_secret`` so TOTP provisioning never relies
  on a ``secret=`` query parameter (server logs, Referer leakage).
* Sets ``devices.authorized`` database default to false so profiler-created
  rows and raw SQL inserts default to blocked until an operator approves.

Revision ID: 0003_phase0
Revises:    0002_admin_role
Create Date: 2026-05-12 18:00:00.000000
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0003_phase0"
down_revision: Union[str, None] = "0002_admin_role"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name

    with op.batch_alter_table("admin_users") as batch:
        batch.add_column(
            sa.Column("pending_totp_secret", sa.String(64), nullable=True),
        )

    with op.batch_alter_table("devices") as batch:
        if dialect == "postgresql":
            batch.alter_column(
                "authorized",
                existing_type=sa.Boolean(),
                server_default=sa.text("false"),
                existing_nullable=False,
            )
        else:
            batch.alter_column(
                "authorized",
                existing_type=sa.Boolean(),
                server_default=sa.text("0"),
                existing_nullable=False,
            )


def downgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name

    with op.batch_alter_table("devices") as batch:
        if dialect == "postgresql":
            batch.alter_column(
                "authorized",
                existing_type=sa.Boolean(),
                server_default=sa.text("true"),
                existing_nullable=False,
            )
        else:
            batch.alter_column(
                "authorized",
                existing_type=sa.Boolean(),
                server_default=sa.text("1"),
                existing_nullable=False,
            )

    with op.batch_alter_table("admin_users") as batch:
        batch.drop_column("pending_totp_secret")
