"""Column types that keep the rest of the code honest."""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import DateTime, String
from sqlalchemy.types import TypeDecorator

from naco.core import secrets


class UTCDateTime(TypeDecorator[datetime]):
    """Timezone-aware UTC datetimes on SQLite.

    SQLite has no timezone type, so values are stored as naive UTC and come
    back aware. Binding a naive datetime is a bug and raises immediately.
    """

    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Any) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("naive datetime bound to a UTCDateTime column")
        return value.astimezone(UTC).replace(tzinfo=None)

    def process_result_value(self, value: datetime | None, dialect: Any) -> datetime | None:
        if value is None:
            return None
        return value.replace(tzinfo=UTC)


class EncryptedString(TypeDecorator[str]):
    """String encrypted at rest with AES-256-GCM, bound to its column via AAD."""

    impl = String
    cache_ok = True

    def __init__(self, length: int = 512, *, aad: str) -> None:
        super().__init__(length)
        self.aad = aad

    def process_bind_param(self, value: str | None, dialect: Any) -> str | None:
        if value is None:
            return None
        return secrets.encrypt(value, aad=self.aad)

    def process_result_value(self, value: str | None, dialect: Any) -> str | None:
        if value is None:
            return None
        return secrets.decrypt(value, aad=self.aad)
