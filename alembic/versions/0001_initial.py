"""initial baseline schema (NACo v2.0.0)

Revision ID: 0001_initial
Revises:
Create Date: 2026-05-12 00:00:00.000000

Creates every table described by `naco.db.models`. Compatible with PostgreSQL
(production) and SQLite (development / tests). For SQLite, ``render_as_batch``
in `alembic/env.py` rewrites ALTERs into batch operations.
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── Enums ─────────────────────────────────────────────────────────────
    auth_result   = sa.Enum("SUCCESS", "FAILURE", "CHALLENGE", name="authresult")
    auth_method   = sa.Enum("PAP", "CHAP", "PEAP", "EAP_TLS", "MAB", "WEB_AUTH", "PAP/CHAP",
                            name="authmethod")
    policy_action = sa.Enum("PERMIT", "DENY", "GUEST", name="policyaction")
    tacacs_type   = sa.Enum("AUTHEN", "AUTHOR", "ACCTING", name="tacacspackettype")
    cmd_action    = sa.Enum("PERMIT", "DENY", name="commandruleaction")

    # ── command_sets ──────────────────────────────────────────────────────
    op.create_table(
        "command_sets",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("name", sa.String(64), nullable=False, unique=True),
        sa.Column("description", sa.String(255), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
    )

    # ── groups ────────────────────────────────────────────────────────────
    op.create_table(
        "groups",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("name", sa.String(64), nullable=False, unique=True),
        sa.Column("description", sa.String(255), nullable=False, server_default=""),
        sa.Column("command_set_id", sa.Integer,
                  sa.ForeignKey("command_sets.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
    )

    # ── users ─────────────────────────────────────────────────────────────
    op.create_table(
        "users",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("username", sa.String(64), nullable=False, unique=True, index=True),
        sa.Column("password_hash", sa.String(128), nullable=False),
        sa.Column("email", sa.String(128), nullable=False, server_default=""),
        sa.Column("full_name", sa.String(128), nullable=False, server_default=""),
        sa.Column("group_id", sa.Integer,
                  sa.ForeignKey("groups.id", ondelete="SET NULL"), nullable=True),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("must_change_password", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("last_login", sa.DateTime(timezone=True), nullable=True),
    )

    # ── devices ───────────────────────────────────────────────────────────
    op.create_table(
        "devices",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("mac_address", sa.String(17), nullable=False, unique=True, index=True),
        sa.Column("ip_address", sa.String(45), nullable=False, server_default=""),
        sa.Column("hostname", sa.String(128), nullable=False, server_default=""),
        sa.Column("vendor", sa.String(128), nullable=False, server_default=""),
        sa.Column("device_type", sa.String(64), nullable=False, server_default="unknown"),
        sa.Column("os_type", sa.String(64), nullable=False, server_default="unknown"),
        sa.Column("user_agent", sa.String(512), nullable=False, server_default=""),
        sa.Column("dhcp_fingerprint", sa.String(256), nullable=False, server_default=""),
        sa.Column("authorized", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("notes", sa.Text, nullable=False, server_default=""),
    )

    # ── policies ──────────────────────────────────────────────────────────
    op.create_table(
        "policies",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("name", sa.String(128), nullable=False, unique=True),
        sa.Column("description", sa.String(512), nullable=False, server_default=""),
        sa.Column("priority", sa.Integer, nullable=False, server_default="100"),
        sa.Column("conditions", sa.Text, nullable=False, server_default="[]"),
        sa.Column("action", policy_action, nullable=False, server_default="PERMIT"),
        sa.Column("vlan", sa.Integer, nullable=True),
        sa.Column("group_id", sa.Integer,
                  sa.ForeignKey("groups.id", ondelete="SET NULL"), nullable=True),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.CheckConstraint(
            "vlan IS NULL OR (vlan >= 1 AND vlan <= 4094)",
            name="ck_policy_vlan_range",
        ),
    )

    # ── auth_logs ─────────────────────────────────────────────────────────
    op.create_table(
        "auth_logs",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now(), index=True),
        sa.Column("username", sa.String(64), nullable=False, server_default="", index=True),
        sa.Column("mac_address", sa.String(17), nullable=False, server_default="", index=True),
        sa.Column("ip_address", sa.String(45), nullable=False, server_default=""),
        sa.Column("nas_ip", sa.String(45), nullable=False, server_default=""),
        sa.Column("nas_port", sa.String(64), nullable=False, server_default=""),
        sa.Column("auth_method", auth_method, nullable=False, server_default="PAP"),
        sa.Column("result", auth_result, nullable=False),
        sa.Column("reason", sa.String(255), nullable=False, server_default=""),
        sa.Column("policy_name", sa.String(128), nullable=False, server_default=""),
        sa.Column("vlan", sa.Integer, nullable=True),
        sa.Column("session_id", sa.String(64), nullable=False, server_default=""),
        sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id"), nullable=True),
        sa.Column("device_id", sa.Integer, sa.ForeignKey("devices.id"), nullable=True),
    )

    # ── active_sessions ──────────────────────────────────────────────────
    op.create_table(
        "active_sessions",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("session_id", sa.String(64), nullable=False, unique=True, index=True),
        sa.Column("username", sa.String(64), nullable=False),
        sa.Column("mac_address", sa.String(17), nullable=False, server_default=""),
        sa.Column("ip_address", sa.String(45), nullable=False, server_default=""),
        sa.Column("nas_ip", sa.String(45), nullable=False, server_default=""),
        sa.Column("nas_port", sa.String(64), nullable=False, server_default=""),
        sa.Column("vlan", sa.Integer, nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("bytes_in", sa.Integer, nullable=False, server_default="0"),
        sa.Column("bytes_out", sa.Integer, nullable=False, server_default="0"),
    )

    # ── guest_sessions ───────────────────────────────────────────────────
    op.create_table(
        "guest_sessions",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("token", sa.String(64), nullable=False, unique=True, index=True),
        sa.Column("email", sa.String(128), nullable=False, server_default=""),
        sa.Column("full_name", sa.String(128), nullable=False, server_default=""),
        sa.Column("mac_address", sa.String(17), nullable=False, server_default="", index=True),
        sa.Column("ip_address", sa.String(45), nullable=False, server_default=""),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("active", sa.Boolean, nullable=False, server_default=sa.true()),
    )

    # ── tacacs_logs ──────────────────────────────────────────────────────
    op.create_table(
        "tacacs_logs",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now(), index=True),
        sa.Column("packet_type", tacacs_type, nullable=False),
        sa.Column("username", sa.String(64), nullable=False, server_default="", index=True),
        sa.Column("remote_ip", sa.String(45), nullable=False, server_default=""),
        sa.Column("nas_port", sa.String(64), nullable=False, server_default=""),
        sa.Column("privilege_level", sa.Integer, nullable=False, server_default="1"),
        sa.Column("command", sa.Text, nullable=False, server_default=""),
        sa.Column("result", sa.String(16), nullable=False, server_default="PASS"),
        sa.Column("reason", sa.String(255), nullable=False, server_default=""),
    )

    # ── admin_users ──────────────────────────────────────────────────────
    op.create_table(
        "admin_users",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("username", sa.String(64), nullable=False, unique=True),
        sa.Column("password_hash", sa.String(128), nullable=False),
        sa.Column("email", sa.String(128), nullable=False, server_default=""),
        sa.Column("is_superuser", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("totp_secret", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("last_login", sa.DateTime(timezone=True), nullable=True),
    )

    # ── nas_clients ──────────────────────────────────────────────────────
    op.create_table(
        "nas_clients",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("name", sa.String(64), nullable=False, unique=True),
        sa.Column("ip_address", sa.String(45), nullable=False, index=True),
        sa.Column("secret", sa.String(128), nullable=False),
        sa.Column("description", sa.String(255), nullable=False, server_default=""),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
    )

    # ── tacacs_clients ───────────────────────────────────────────────────
    op.create_table(
        "tacacs_clients",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("name", sa.String(64), nullable=False, unique=True),
        sa.Column("ip_address", sa.String(45), nullable=False, index=True),
        sa.Column("key", sa.String(128), nullable=False),
        sa.Column("description", sa.String(255), nullable=False, server_default=""),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
    )

    # ── vlan_mappings ────────────────────────────────────────────────────
    op.create_table(
        "vlan_mappings",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("name", sa.String(64), nullable=False, unique=True),
        sa.Column("vlan_id", sa.Integer, nullable=False),
        sa.Column("description", sa.String(255), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.CheckConstraint("vlan_id >= 1 AND vlan_id <= 4094", name="ck_vlan_mapping_range"),
    )

    # ── command_rules ────────────────────────────────────────────────────
    op.create_table(
        "command_rules",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("command_set_id", sa.Integer,
                  sa.ForeignKey("command_sets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("priority", sa.Integer, nullable=False, server_default="100"),
        sa.Column("action", cmd_action, nullable=False, server_default="PERMIT"),
        sa.Column("command_pattern", sa.String(256), nullable=False),
        sa.Column("args_pattern", sa.String(256), nullable=False, server_default=""),
    )

    # ── admin_audit_logs ─────────────────────────────────────────────────
    op.create_table(
        "admin_audit_logs",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now(), index=True),
        sa.Column("admin_username", sa.String(64), nullable=False, index=True),
        sa.Column("action", sa.String(32), nullable=False),
        sa.Column("resource_type", sa.String(64), nullable=False),
        sa.Column("resource_id", sa.String(64), nullable=False, server_default=""),
        sa.Column("detail", sa.Text, nullable=False, server_default=""),
    )


def downgrade() -> None:
    for table in (
        "admin_audit_logs", "command_rules", "vlan_mappings", "tacacs_clients",
        "nas_clients", "admin_users", "tacacs_logs", "guest_sessions",
        "active_sessions", "auth_logs", "policies", "devices", "users",
        "groups", "command_sets",
    ):
        op.drop_table(table)

    bind = op.get_bind()
    for enum_name in ("authresult", "authmethod", "policyaction",
                      "tacacspackettype", "commandruleaction"):
        sa.Enum(name=enum_name).drop(bind, checkfirst=True)
