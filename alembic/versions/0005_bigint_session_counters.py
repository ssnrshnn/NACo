"""Widen active_sessions byte counters to BigInteger

RADIUS Acct-Input/Output-Octets are 32-bit on the wire; NASes report
rollovers via the RFC 2869 Gigawords attributes. NACo now combines the two
(``naco.radius.server._acct_octets``), so sessions can legitimately report
totals far beyond 2^31 — the previous ``Integer`` columns would overflow on
PostgreSQL for any session moving more than ~2 GiB.

Revision ID: 0005_bigint_counters
Revises:    0004_updated_at_jsonb
Create Date: 2026-07-03 12:00:00.000000
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0005_bigint_counters"
down_revision: Union[str, None] = "0004_updated_at_jsonb"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # SQLite stores all integers as variable-width — only Postgres needs the
    # column type widened, but batch_alter_table keeps this portable.
    with op.batch_alter_table("active_sessions") as batch:
        batch.alter_column(
            "bytes_in", existing_type=sa.Integer(), type_=sa.BigInteger(),
            existing_nullable=False,
        )
        batch.alter_column(
            "bytes_out", existing_type=sa.Integer(), type_=sa.BigInteger(),
            existing_nullable=False,
        )


def downgrade() -> None:
    with op.batch_alter_table("active_sessions") as batch:
        batch.alter_column(
            "bytes_in", existing_type=sa.BigInteger(), type_=sa.Integer(),
            existing_nullable=False,
        )
        batch.alter_column(
            "bytes_out", existing_type=sa.BigInteger(), type_=sa.Integer(),
            existing_nullable=False,
        )
