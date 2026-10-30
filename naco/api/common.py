"""Small helpers shared by the resource routes."""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from fastapi import Query
from pydantic import BaseModel
from sqlalchemy import Select, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from naco.api.errors import ApiError


class Page[T](BaseModel):
    items: list[T]
    total: int
    page: int
    per_page: int


class Paging:
    def __init__(self, page: int = Query(1, ge=1, le=100_000),
                 per_page: int = Query(50, ge=1, le=500)) -> None:
        self.page, self.per_page = page, per_page

    async def fetch(self, db: AsyncSession, query: Select[Any] | Any) -> tuple[list[Any], int]:
        total = (await db.execute(select(func.count()).select_from(query.order_by(None).subquery()))).scalar_one()
        rows = (await db.execute(query.limit(self.per_page).offset((self.page - 1) * self.per_page))).all()
        return [r[0] if len(r) == 1 else r for r in rows], total


async def get_or_404[M](db: AsyncSession, model: type[M], ident: int, what: str) -> M:
    obj = await db.get(model, ident)
    if obj is None:
        raise ApiError(404, f"{what} not found")
    return obj


def snapshot(obj: Any, fields: list[str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for name in fields:
        value = getattr(obj, name)
        if isinstance(value, Enum):
            value = value.value
        elif isinstance(value, datetime):
            value = value.isoformat()
        out[name] = value
    return out


async def commit_or_conflict(db: AsyncSession, message: str) -> None:
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise ApiError(409, message) from exc


async def flush_or_conflict(db: AsyncSession, message: str) -> None:
    try:
        await db.flush()
    except IntegrityError as exc:
        await db.rollback()
        raise ApiError(409, message) from exc


def like(term: str) -> str:
    escaped = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"
