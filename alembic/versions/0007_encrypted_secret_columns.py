"""Widen secret columns for the AES-GCM encryption envelope

``nas_clients.secret``, ``tacacs_clients.key`` and the admin TOTP columns
are now stored via the ``EncryptedString`` type. Encrypted values carry an
``enc:v1:<base64(nonce||ct||tag)>`` envelope (~1.4× plaintext + 50 chars),
so the columns grow to 512. Data is NOT rewritten here — reads accept both
plaintext and encrypted forms; rows encrypt on next write or in bulk via
``nacoctl encrypt-secrets``.

Revision ID: 0007_encrypted_secrets
Revises:    0006_policy_reply_attrs
Create Date: 2026-07-04 12:00:00.000000
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0007_encrypted_secrets"
down_revision: Union[str, None] = "0006_policy_reply_attrs"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_COLUMNS = [
    ("nas_clients", "secret", sa.String(128), False),
    ("tacacs_clients", "key", sa.String(128), False),
    ("admin_users", "totp_secret", sa.String(64), True),
    ("admin_users", "pending_totp_secret", sa.String(64), True),
]


def upgrade() -> None:
    for table, column, old_type, nullable in _COLUMNS:
        op.alter_column(
            table, column,
            existing_type=old_type, type_=sa.String(512),
            existing_nullable=nullable,
        )


def downgrade() -> None:
    # Only safe while values are still plaintext (≤ old length). Encrypted
    # values would be truncated — decrypt first (unset NACO_MASTER_KEY is
    # not enough; there is deliberately no bulk-decrypt command).
    for table, column, old_type, nullable in _COLUMNS:
        op.alter_column(
            table, column,
            existing_type=sa.String(512), type_=old_type,
            existing_nullable=nullable,
        )
