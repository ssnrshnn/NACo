"""In-process event bus feeding the live dashboard (SSE), metrics and syslog.

Publishing never blocks: a subscriber that falls behind loses its oldest
events rather than slowing down authentication.
"""
from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

from naco.core.timeutil import utcnow


class EventType(StrEnum):
    AUTH = "auth"
    ACCOUNTING = "accounting"
    TACACS = "tacacs"
    DEVICE = "device"
    AUDIT = "audit"


@dataclass(frozen=True)
class Event:
    type: EventType
    data: dict[str, Any]
    ts: datetime = field(default_factory=utcnow)


class EventBus:
    def __init__(self, queue_size: int = 256) -> None:
        self._queue_size = queue_size
        self._subscribers: set[asyncio.Queue[Event]] = set()

    def publish(self, event: Event) -> None:
        for q in self._subscribers:
            if q.full():
                q.get_nowait()
            q.put_nowait(event)

    @asynccontextmanager
    async def subscribe(self) -> AsyncIterator[asyncio.Queue[Event]]:
        q: asyncio.Queue[Event] = asyncio.Queue(maxsize=self._queue_size)
        self._subscribers.add(q)
        try:
            yield q
        finally:
            self._subscribers.discard(q)

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)


bus = EventBus()
