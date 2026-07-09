"""
Profiler write coalescing.

A busy LAN produces hundreds of DHCP/ARP packets per second and the old
profiler issued one SELECT + UPSERT transaction per packet. Observations
are now merged into an in-memory buffer keyed by MAC and flushed as a
single transaction on an interval.
"""
from __future__ import annotations

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from naco.core.events import EventType, bus
from naco.db.models import Device


@pytest.fixture
def profiler(monkeypatch: pytest.MonkeyPatch):
    import sys

    import naco.profiler.profiler  # noqa: F401 — ensure the submodule is loaded
    from tests.conftest import _TestSession

    # The package exports a singleton named `profiler`, which shadows the
    # submodule as an attribute — resolve the real module via sys.modules.
    profiler_mod = sys.modules["naco.profiler.profiler"]
    monkeypatch.setattr(profiler_mod, "AsyncSessionLocal", _TestSession)
    return profiler_mod.DeviceProfiler()


@pytest.fixture
def events(monkeypatch: pytest.MonkeyPatch) -> list:
    captured: list = []
    monkeypatch.setattr(bus, "publish_sync", captured.append)
    return captured


@pytest.mark.asyncio
async def test_observations_coalesce_into_single_row(db: AsyncSession, profiler, events):
    """Three packets for one MAC produce one merged device row and one
    NEW_DEVICE event."""
    profiler._queue_observation("AA:BB:CC:DD:EE:01", hostname="printer-1",
                                ip="", vendor_cls="", dhcp_fp="")
    profiler._queue_observation("aa:bb:cc:dd:ee:01", hostname="",
                                ip="10.0.0.9", vendor_cls="", dhcp_fp="")
    profiler._queue_observation("aa-bb-cc-dd-ee-01", hostname="",
                                ip="", vendor_cls="", dhcp_fp="1,3,28,6")
    await profiler._flush_once()

    rows = (await db.execute(select(Device))).scalars().all()
    assert len(rows) == 1
    dev = rows[0]
    assert dev.hostname == "printer-1"
    assert dev.ip_address == "10.0.0.9"
    assert dev.dhcp_fingerprint == "1,3,28,6"

    new_events = [e for e in events if e.type == EventType.NEW_DEVICE]
    assert len(new_events) == 1


@pytest.mark.asyncio
async def test_flush_handles_multiple_macs(db: AsyncSession, profiler, events):
    profiler._queue_observation("aa:bb:cc:dd:ee:02", hostname="a", ip="", vendor_cls="", dhcp_fp="")
    profiler._queue_observation("aa:bb:cc:dd:ee:03", hostname="b", ip="", vendor_cls="", dhcp_fp="")
    await profiler._flush_once()

    rows = (await db.execute(select(Device))).scalars().all()
    assert {r.mac_address for r in rows} == {"aa:bb:cc:dd:ee:02", "aa:bb:cc:dd:ee:03"}


@pytest.mark.asyncio
async def test_second_flush_updates_not_duplicates(db: AsyncSession, profiler, events):
    profiler._queue_observation("aa:bb:cc:dd:ee:04", hostname="first", ip="", vendor_cls="", dhcp_fp="")
    await profiler._flush_once()
    profiler._queue_observation("aa:bb:cc:dd:ee:04", hostname="second", ip="", vendor_cls="", dhcp_fp="")
    await profiler._flush_once()

    rows = (await db.execute(select(Device))).scalars().all()
    assert len(rows) == 1
    assert rows[0].hostname == "second"

    kinds = [e.type for e in events]
    assert kinds.count(EventType.NEW_DEVICE) == 1
    assert kinds.count(EventType.DEVICE_UPDATED) == 1


@pytest.mark.asyncio
async def test_invalid_mac_ignored(db: AsyncSession, profiler, events):
    profiler._queue_observation("not-a-mac", hostname="x", ip="", vendor_cls="", dhcp_fp="")
    await profiler._flush_once()
    rows = (await db.execute(select(Device))).scalars().all()
    assert rows == []
    assert events == []


@pytest.mark.asyncio
async def test_empty_flush_is_noop(profiler, events):
    await profiler._flush_once()
    assert events == []
