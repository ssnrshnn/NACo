"""
Monthly range partitions for the high-volume log tables (PostgreSQL).

``auth_logs`` and ``tacacs_logs`` grow by one row per authentication —
at enterprise volume that is millions of rows a month. Migration
``0009_partition_logs`` converts them to declaratively partitioned tables
on PostgreSQL; the helpers here keep future partitions provisioned and
let retention drop whole months (an instant ``DROP TABLE``) instead of
deleting millions of rows.

Everything degrades to a no-op on SQLite (dev/test) and on databases
whose tables were never converted (e.g. a quickstart install that has
not run ``nacoctl db-upgrade``).
"""
from __future__ import annotations

import re
from datetime import UTC, datetime

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from naco.core.logger import get_logger

log = get_logger(__name__)

#: Tables managed by the monthly partition scheme.
PARTITIONED_TABLES = ("auth_logs", "tacacs_logs")

_NAME_RE = re.compile(r"^(?P<table>[a-z_]+)_y(?P<year>\d{4})m(?P<month>\d{2})$")


def partition_name(table: str, moment: datetime) -> str:
    """``auth_logs`` + 2026-07 → ``auth_logs_y2026m07``."""
    return f"{table}_y{moment.year:04d}m{moment.month:02d}"


def month_bounds(moment: datetime) -> tuple[datetime, datetime]:
    """Return (first day of month, first day of next month) in UTC."""
    start = datetime(moment.year, moment.month, 1, tzinfo=UTC)
    if moment.month == 12:
        end = datetime(moment.year + 1, 1, 1, tzinfo=UTC)
    else:
        end = datetime(moment.year, moment.month + 1, 1, tzinfo=UTC)
    return start, end


def partition_month(name: str) -> datetime | None:
    """Parse a partition name back into the first day of its month.

    Returns ``None`` for anything that is not one of our monthly
    partitions (including the parent table and a default partition).
    """
    match = _NAME_RE.match(name)
    if not match:
        return None
    year, month = int(match.group("year")), int(match.group("month"))
    if not 1 <= month <= 12:
        return None
    return datetime(year, month, 1, tzinfo=UTC)


def _add_months(moment: datetime, months: int) -> datetime:
    month_index = (moment.year * 12 + (moment.month - 1)) + months
    return datetime(month_index // 12, month_index % 12 + 1, 1, tzinfo=UTC)


async def _is_partitioned_parent(db: AsyncSession, table: str) -> bool:
    if db.bind is None or db.bind.dialect.name != "postgresql":
        return False
    result = await db.execute(
        text(
            "SELECT 1 FROM pg_partitioned_table pt"
            " JOIN pg_class c ON c.oid = pt.partrelid"
            " WHERE c.relname = :table"
        ),
        {"table": table},
    )
    return result.scalar_one_or_none() is not None


async def _existing_partitions(db: AsyncSession, table: str) -> list[str]:
    result = await db.execute(
        text(
            "SELECT child.relname FROM pg_inherits"
            " JOIN pg_class parent ON parent.oid = pg_inherits.inhparent"
            " JOIN pg_class child ON child.oid = pg_inherits.inhrelid"
            " WHERE parent.relname = :table"
        ),
        {"table": table},
    )
    return [row[0] for row in result]


async def ensure_month_partitions(
    db: AsyncSession,
    tables: list[str] | tuple[str, ...] = PARTITIONED_TABLES,
    *,
    months_ahead: int = 1,
    now: datetime | None = None,
) -> list[str]:
    """Create partitions for the current month through *months_ahead*.

    Returns the names of partitions actually created. No-op on SQLite and
    on unconverted (non-partitioned) tables.
    """
    now = now or datetime.now(UTC)
    created: list[str] = []
    for table in tables:
        if not await _is_partitioned_parent(db, table):
            continue
        existing = set(await _existing_partitions(db, table))
        for offset in range(months_ahead + 1):
            month = _add_months(now, offset)
            name = partition_name(table, month)
            if name in existing:
                continue
            start, end = month_bounds(month)
            # DDL cannot take bind parameters; the bounds are datetimes we
            # computed above, rendered as ISO literals.
            await db.execute(
                text(
                    f'CREATE TABLE IF NOT EXISTS "{name}" PARTITION OF "{table}"'
                    f" FOR VALUES FROM ('{start.isoformat()}') TO ('{end.isoformat()}')"
                )
            )
            created.append(name)
            log.info("Created log partition %s", name)
    if created:
        await db.commit()
    return created


async def drop_expired_partitions(
    db: AsyncSession,
    tables: list[str] | tuple[str, ...] = PARTITIONED_TABLES,
    *,
    cutoff: datetime,
) -> list[str]:
    """Drop partitions whose whole month lies before *cutoff*.

    A partition for July may only be dropped when ``Aug 1 <= cutoff`` —
    rows younger than the cutoff inside a partially-expired month are left
    to the row-level retention delete.
    """
    dropped: list[str] = []
    for table in tables:
        if not await _is_partitioned_parent(db, table):
            continue
        for name in await _existing_partitions(db, table):
            month = partition_month(name)
            if month is None:
                continue
            _, month_end = month_bounds(month)
            if month_end <= cutoff:
                await db.execute(text(f'DROP TABLE IF EXISTS "{name}"'))
                dropped.append(name)
                log.info("Dropped expired log partition %s", name)
    if dropped:
        await db.commit()
    return dropped
