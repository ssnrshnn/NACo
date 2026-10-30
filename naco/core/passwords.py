"""bcrypt password hashing, always off the event loop.

bcrypt only looks at the first 72 bytes and bcrypt>=5 refuses longer input,
so longer passwords are rejected when set and simply never match on verify.
"""
from __future__ import annotations

import asyncio
from functools import lru_cache

import bcrypt

BCRYPT_ROUNDS = 12
_MAX_BYTES = 72


@lru_cache(maxsize=1)
def _dummy_hash() -> bytes:
    return bcrypt.hashpw(b"naco-timing-equaliser", bcrypt.gensalt(BCRYPT_ROUNDS))


def hash_password_sync(password: str) -> str:
    raw = password.encode()
    if len(raw) > _MAX_BYTES:
        raise ValueError("password is longer than 72 bytes")
    return bcrypt.hashpw(raw, bcrypt.gensalt(BCRYPT_ROUNDS)).decode()


def verify_password_sync(password: str, hashed: str | None) -> bool:
    """Constant-cost check: unknown users and over-long input still pay one bcrypt."""
    raw = password.encode()
    usable = hashed is not None and len(raw) <= _MAX_BYTES
    target = hashed.encode() if usable and hashed else _dummy_hash()
    try:
        ok = bcrypt.checkpw(raw[:_MAX_BYTES], target)
    except ValueError:  # malformed stored hash
        ok = False
    return ok and usable


async def hash_password(password: str) -> str:
    return await asyncio.to_thread(hash_password_sync, password)


async def verify_password(password: str, hashed: str | None) -> bool:
    return await asyncio.to_thread(verify_password_sync, password, hashed)


def _validate(password: str, minimum: int) -> None:
    if len(password) < minimum:
        raise ValueError(f"password must be at least {minimum} characters")
    if len(password.encode()) > _MAX_BYTES:
        raise ValueError("password must be at most 72 bytes")


def validate_admin_password(password: str) -> None:
    _validate(password, 12)


def validate_user_password(password: str) -> None:
    _validate(password, 8)
