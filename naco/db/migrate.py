"""Apply schema migrations. NACo runs ``upgrade_head`` on every start."""
from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config

MIGRATIONS_DIR = Path(__file__).parent / "migrations"


def alembic_config(db_path: str) -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS_DIR))
    # configparser interpolation: a literal % in a path must be doubled.
    cfg.set_main_option("sqlalchemy.url", f"sqlite:///{db_path}".replace("%", "%%"))
    return cfg


def upgrade_head(db_path: str) -> None:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    command.upgrade(alembic_config(db_path), "head")
