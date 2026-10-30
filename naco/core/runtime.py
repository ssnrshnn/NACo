"""Process facts the status pages show: start time and FreeRADIUS activity."""
from __future__ import annotations

from datetime import datetime

from naco.core.timeutil import utcnow

STARTED_AT: datetime = utcnow()
_aaa_last_request: datetime | None = None


def mark_aaa_request() -> None:
    global _aaa_last_request
    _aaa_last_request = utcnow()


def aaa_last_request() -> datetime | None:
    return _aaa_last_request
