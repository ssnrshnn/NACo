"""API tokens with role scopes

New ``api_tokens`` table: long-lived bearer credentials for automation.
Only the SHA-256 digest of the token is stored; ``role`` is the token's
permission ceiling (same RBAC ranks as admin users).

Revision ID: 0008_api_tokens
Revises:    0007_encrypted_secrets
Create Date: 2026-07-04 21:00:00.000000
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0008_api_tokens"
down_revision: Union[str, None] = "0007_encrypted_secrets"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _role_type():
    """Reuse the existing ``adminrole`` enum on Postgres (0002 created it);
    plain Enum elsewhere (SQLite renders VARCHAR + CHECK)."""
    values = ("SUPERUSER", "OPERATOR", "VIEWER")
    if op.get_bind().dialect.name == "postgresql":
        from sqlalchemy.dialects import postgresql
        return postgresql.ENUM(*values, name="adminrole", create_type=False)
    return sa.Enum(*values, name="adminrole")


def upgrade() -> None:
    # The app's startup create_all() may have already created the table
    # (fresh installs, or an image upgraded before db-upgrade ran) — this
    # migration then only needs to record the revision.
    if sa.inspect(op.get_bind()).has_table("api_tokens"):
        return
    op.create_table(
        "api_tokens",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(64), nullable=False, unique=True),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("prefix", sa.String(16), nullable=False, server_default=""),
        sa.Column("role", _role_type(), nullable=False, server_default="VIEWER"),
        sa.Column("created_by", sa.String(64), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
    )
    op.create_index("ix_api_tokens_token_hash", "api_tokens", ["token_hash"])


def downgrade() -> None:
    op.drop_index("ix_api_tokens_token_hash", table_name="api_tokens")
    op.drop_table("api_tokens")
