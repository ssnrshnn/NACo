"""groups: TACACS+ attributes for services other than shell

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-30 19:30:00
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("groups") as batch:
        batch.add_column(sa.Column("device_admin_attributes", sa.JSON(), nullable=False, server_default="[]"))


def downgrade() -> None:
    with op.batch_alter_table("groups") as batch:
        batch.drop_column("device_admin_attributes")
