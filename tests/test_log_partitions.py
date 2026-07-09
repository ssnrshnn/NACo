"""
Monthly log-partition helpers.

The DDL side (attach/drop) only runs on PostgreSQL; these tests pin the
pure logic — partition naming, month boundaries, and which partitions the
retention pass may drop — plus the graceful no-op on non-Postgres engines.
"""
from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from naco.db.partitions import (
    drop_expired_partitions,
    ensure_month_partitions,
    month_bounds,
    partition_month,
    partition_name,
)


def test_partition_name_is_stable():
    assert partition_name("auth_logs", datetime(2026, 7, 9, tzinfo=UTC)) == "auth_logs_y2026m07"
    assert partition_name("tacacs_logs", datetime(2026, 12, 1, tzinfo=UTC)) == "tacacs_logs_y2026m12"


def test_month_bounds_cover_the_month():
    start, end = month_bounds(datetime(2026, 7, 9, 15, 30, tzinfo=UTC))
    assert start == datetime(2026, 7, 1, tzinfo=UTC)
    assert end == datetime(2026, 8, 1, tzinfo=UTC)


def test_month_bounds_year_rollover():
    start, end = month_bounds(datetime(2026, 12, 31, tzinfo=UTC))
    assert start == datetime(2026, 12, 1, tzinfo=UTC)
    assert end == datetime(2027, 1, 1, tzinfo=UTC)


def test_partition_month_parses_names():
    assert partition_month("auth_logs_y2026m07") == datetime(2026, 7, 1, tzinfo=UTC)
    assert partition_month("tacacs_logs_y2027m01") == datetime(2027, 1, 1, tzinfo=UTC)


def test_partition_month_rejects_foreign_names():
    assert partition_month("auth_logs") is None
    assert partition_month("auth_logs_default") is None
    assert partition_month("auth_logs_y20xxm07") is None


@pytest.mark.asyncio
async def test_ensure_partitions_noop_on_sqlite(db: AsyncSession):
    """On non-Postgres engines the helpers must return without touching
    the database (SQLite has no declarative partitioning)."""
    created = await ensure_month_partitions(db, ["auth_logs"], months_ahead=1)
    assert created == []


@pytest.mark.asyncio
async def test_drop_expired_noop_on_sqlite(db: AsyncSession):
    dropped = await drop_expired_partitions(
        db, ["auth_logs"], cutoff=datetime(2020, 1, 1, tzinfo=UTC)
    )
    assert dropped == []
