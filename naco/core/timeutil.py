"""Time helpers: storage is UTC, display is ``server.timezone``."""
from __future__ import annotations

from datetime import UTC, datetime
from zoneinfo import ZoneInfo


def utcnow() -> datetime:
    return datetime.now(UTC)


def local_zone() -> ZoneInfo:
    from naco.config import get_config
    return ZoneInfo(get_config().server.timezone)


def to_local(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(local_zone())


def local_now() -> datetime:
    return datetime.now(local_zone())
