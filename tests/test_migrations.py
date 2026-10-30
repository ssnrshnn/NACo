import re

import sqlalchemy as sa
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext

import naco.db.models  # noqa: F401
from naco.db.engine import Base
from naco.db.migrate import upgrade_head


def _engine(path):
    return sa.create_engine(f"sqlite:///{path}")


def test_upgrade_creates_every_table(tmp_path):
    path = tmp_path / "m.db"
    upgrade_head(str(path))
    tables = set(sa.inspect(_engine(path)).get_table_names())
    assert set(Base.metadata.tables) <= tables
    assert "alembic_version" in tables


def test_upgrade_is_idempotent(tmp_path):
    path = str(tmp_path / "m.db")
    upgrade_head(path)
    upgrade_head(path)


def test_upgrade_creates_parent_directory(tmp_path):
    path = tmp_path / "nested" / "dir" / "m.db"
    upgrade_head(str(path))
    assert path.exists()


def test_migrations_match_models(tmp_path):
    """Guard against drift: the migrated schema must equal the ORM metadata."""
    path = tmp_path / "m.db"
    upgrade_head(str(path))
    with _engine(path).connect() as conn:
        ctx = MigrationContext.configure(conn, opts={"compare_type": True, "render_as_batch": True})
        diff = compare_metadata(ctx, Base.metadata)
    assert diff == []


def test_no_stray_revision_files():
    """Alembic loads every .py in versions/ — a copy (e.g. an iCloud "x 2.py") adds a second head."""
    from naco.db.migrate import MIGRATIONS_DIR
    names = sorted(p.name for p in (MIGRATIONS_DIR / "versions").glob("*.py"))
    assert all(re.fullmatch(r"\d{4}_[a-z0-9_]+\.py", n) for n in names), names
    assert [int(n[:4]) for n in names] == list(range(1, len(names) + 1)), names


def test_upgrading_a_3_0_database_keeps_its_rows(tmp_path):
    from alembic import command

    from naco.db.migrate import alembic_config

    path = str(tmp_path / "m.db")
    command.upgrade(alembic_config(path), "0001")
    with _engine(path).begin() as conn:
        conn.execute(sa.text("INSERT INTO groups (name, description, created_at, updated_at) "
                             "VALUES ('staff', '', '2026-10-30', '2026-10-30')"))
        conn.execute(sa.text("INSERT INTO nas_clients (name, ip_address, secret, coa_port, "
                             "require_message_authenticator, description, enabled, created_at, updated_at) "
                             "VALUES ('sw1', '10.0.0.1', 'x', 3799, 1, '', 1, '2026-10-30', '2026-10-30')"))
    upgrade_head(path)
    with _engine(path).connect() as conn:
        assert conn.execute(sa.text("SELECT device_admin_attributes FROM groups")).scalar_one() == "[]"
        assert conn.execute(sa.text("SELECT vendor FROM nas_clients")).scalar_one() == "standard"
