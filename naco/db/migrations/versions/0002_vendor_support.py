"""vendor support: TACACS+ attributes per service, NAS vendor, session ids

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
    with op.batch_alter_table("nas_clients") as batch:
        batch.add_column(sa.Column("vendor", sa.String(length=32), nullable=False, server_default="standard"))
    with op.batch_alter_table("radius_sessions") as batch:
        batch.add_column(sa.Column("nas_ip_address", sa.String(length=45), nullable=False, server_default=""))
        batch.add_column(sa.Column("nas_identifier", sa.String(length=64), nullable=False, server_default=""))
        batch.add_column(sa.Column("audit_session_id", sa.String(length=64), nullable=False, server_default=""))


def downgrade() -> None:
    with op.batch_alter_table("radius_sessions") as batch:
        batch.drop_column("audit_session_id")
        batch.drop_column("nas_identifier")
        batch.drop_column("nas_ip_address")
    with op.batch_alter_table("nas_clients") as batch:
        batch.drop_column("vendor")
    with op.batch_alter_table("groups") as batch:
        batch.drop_column("device_admin_attributes")
