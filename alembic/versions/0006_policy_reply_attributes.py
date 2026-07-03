"""Add policies.reply_attributes for vendor-specific RADIUS reply attributes

Policies can now attach arbitrary RADIUS attributes (standard or VSA) to the
Access-Accept — e.g. ``Aruba-User-Role``, ``Cisco-AVPair``,
``Mikrotik-Rate-Limit`` — enabling role/bandwidth assignment on gear from any
vendor defined in ``naco/radius/dictionary``.

Revision ID: 0006_policy_reply_attrs
Revises:    0005_bigint_counters
Create Date: 2026-07-03 12:00:00.000000
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0006_policy_reply_attrs"
down_revision: Union[str, None] = "0005_bigint_counters"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        col_type = sa.dialects.postgresql.JSONB()
    else:
        col_type = sa.JSON()
    op.add_column(
        "policies",
        sa.Column("reply_attributes", col_type, nullable=True),
    )


def downgrade() -> None:
    op.drop_column("policies", "reply_attributes")
