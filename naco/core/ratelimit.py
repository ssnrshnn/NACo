"""Rate limiter + per-account lockout used by the web UI and REST API.

Two abuse-resistance primitives live here:

1. **IP rate limit** — sliding-window counter keyed on the client IP.
   Default: 5 failures per 5 minutes per IP.
2. **Account lockout** — per-username counter that *locks* a user for a
   cool-down period after a small number of consecutive failures.
   Default: 10 failures → 15-minute lock. Cleared on a successful login.

Both primitives are backed by Redis when ``cache.url`` is reachable, with an
in-process fallback so unit tests and quick local-dev experiments stay
zero-config. The Redis path uses an atomic Lua script so the check+incr is
race-free; the in-process path uses a process-global lock and is consistent
within a single replica only.

Public API
----------
``check_rate_limit(key)``      → ``True`` while the IP is still under the limit.
``record_failure(key)``        → atomically increment and apply the cap.
``clear_failures(key)``        → reset the IP counter after a success.

``check_account_lock(user)``   → ``True`` if the account is *not* locked.
``record_account_failure(u)``  → increment the per-user counter and lock if needed.
``clear_account_failures(u)``  → wipe the per-user counter (post-login).

Keys are usually IPs / usernames but anything stringy works.
"""
from __future__ import annotations

import asyncio
import time as _time
from collections import defaultdict
from threading import Lock as _Lock

from naco.core.cache import get_sync_redis


# ──────────────────────────────────────────────────────────────────────────
# Tunables
# ──────────────────────────────────────────────────────────────────────────

# Per-IP sliding window.
_RATE_MAX_HITS: int = 5
_RATE_WINDOW:   int = 300  # seconds (5 minutes)
_KEY_PREFIX = "naco:ratelimit:login:"

# Per-account lockout. Higher threshold than the IP limit because a single
# user typing their password wrong six times in a row is plausible — we
# want to catch credential-stuffing botnets spread across many IPs, not
# punish a forgetful admin. Cleared on successful login.
_LOCKOUT_THRESHOLD: int = 10
_LOCKOUT_SECONDS:   int = 900  # 15 minutes
_LOCK_KEY_PREFIX = "naco:lockout:login:"


# ──────────────────────────────────────────────────────────────────────────
# In-process fallback (used when Redis is unreachable)
# ──────────────────────────────────────────────────────────────────────────

_login_failures: dict[str, list[float]] = defaultdict(list)
_account_failures: dict[str, int] = defaultdict(int)
_account_lock_until: dict[str, float] = {}
_lock = _Lock()
_last_cleanup: float = 0.0
_CLEANUP_INTERVAL: float = 60.0


def _maybe_cleanup() -> None:
    """Garbage-collect stale entries from the in-process maps."""
    global _last_cleanup
    now = _time.monotonic()
    if now - _last_cleanup < _CLEANUP_INTERVAL:
        return
    _last_cleanup = now
    stale_ips = [
        ip for ip, hits in _login_failures.items()
        if not hits or (now - max(hits)) >= _RATE_WINDOW
    ]
    for ip in stale_ips:
        _login_failures.pop(ip, None)
    expired_locks = [u for u, until in _account_lock_until.items() if until <= now]
    for u in expired_locks:
        _account_lock_until.pop(u, None)
        _account_failures.pop(u, None)


def _local_check_ip(key: str) -> bool:
    with _lock:
        now  = _time.monotonic()
        hits = _login_failures[key]
        hits[:] = [t for t in hits if now - t < _RATE_WINDOW]
        if not hits:
            _login_failures.pop(key, None)
        _maybe_cleanup()
        return len(hits) < _RATE_MAX_HITS


def _local_record_ip(key: str) -> None:
    with _lock:
        _login_failures[key].append(_time.monotonic())


def _local_clear_ip(key: str) -> None:
    with _lock:
        _login_failures.pop(key, None)


def _local_check_account(user: str) -> bool:
    """Return True if user is *not* locked."""
    with _lock:
        until = _account_lock_until.get(user)
        if until is None:
            return True
        if until <= _time.monotonic():
            _account_lock_until.pop(user, None)
            _account_failures.pop(user, None)
            return True
        return False


def _local_record_account(user: str) -> bool:
    """Return True if this call pushed the user into a lockout."""
    with _lock:
        _account_failures[user] += 1
        if _account_failures[user] >= _LOCKOUT_THRESHOLD:
            _account_lock_until[user] = _time.monotonic() + _LOCKOUT_SECONDS
            return True
        return False


def _local_clear_account(user: str) -> None:
    with _lock:
        _account_failures.pop(user, None)
        _account_lock_until.pop(user, None)


# ──────────────────────────────────────────────────────────────────────────
# Redis-backed atomic primitives
# ──────────────────────────────────────────────────────────────────────────

# Atomically: INCR key by 1, set TTL only if previously absent, return new value.
# Avoids the historical check+incr TOCTOU where two concurrent callers could
# both pass ``check_rate_limit`` before either had called ``record_failure``.
_REDIS_INCR_SCRIPT = """
local v = redis.call('INCR', KEYS[1])
if v == 1 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return v
"""

# Atomically: INCR per-user counter; if it reached the threshold, also
# SET the lock key with its own TTL. Returns the new counter value AND
# whether the lock was just placed (1) or already present (0).
_REDIS_LOCK_SCRIPT = """
local count = redis.call('INCR', KEYS[1])
if count == 1 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
local locked = 0
if count >= tonumber(ARGV[2]) then
  if redis.call('EXISTS', KEYS[2]) == 0 then
    redis.call('SET', KEYS[2], '1', 'EX', ARGV[3])
    locked = 1
  end
end
return {count, locked}
"""


def _redis_count(key: str) -> int | None:
    """Return current failure count for *key*, or ``None`` if Redis is down."""
    r = get_sync_redis()
    if r is None:
        return None
    try:
        val = r.get(_KEY_PREFIX + key)
        return int(val) if val else 0
    except Exception:
        return None


def _redis_incr(key: str) -> int | None:
    """Atomic INCR+EXPIRE. Returns the new counter, or ``None`` if Redis is down."""
    r = get_sync_redis()
    if r is None:
        return None
    try:
        full = _KEY_PREFIX + key
        return int(r.eval(_REDIS_INCR_SCRIPT, 1, full, _RATE_WINDOW))
    except Exception:
        return None


def _redis_clear(key: str) -> bool:
    r = get_sync_redis()
    if r is None:
        return False
    try:
        r.delete(_KEY_PREFIX + key)
        return True
    except Exception:
        return False


def _redis_check_lock(user: str) -> bool | None:
    """``True`` if account is unlocked, ``False`` if locked, ``None`` if Redis down."""
    r = get_sync_redis()
    if r is None:
        return None
    try:
        return r.get(_LOCK_KEY_PREFIX + user) is None
    except Exception:
        return None


def _redis_record_account(user: str) -> tuple[int, bool] | None:
    """Atomic increment + maybe-lock. Returns (count, just_locked) or None."""
    r = get_sync_redis()
    if r is None:
        return None
    try:
        count_key = _KEY_PREFIX + "account:" + user
        lock_key  = _LOCK_KEY_PREFIX + user
        res = r.eval(
            _REDIS_LOCK_SCRIPT, 2, count_key, lock_key,
            _RATE_WINDOW, _LOCKOUT_THRESHOLD, _LOCKOUT_SECONDS,
        )
        return int(res[0]), bool(res[1])
    except Exception:
        return None


def _redis_clear_account(user: str) -> bool:
    r = get_sync_redis()
    if r is None:
        return False
    try:
        r.delete(_KEY_PREFIX + "account:" + user, _LOCK_KEY_PREFIX + user)
        return True
    except Exception:
        return False


# ──────────────────────────────────────────────────────────────────────────
# Public API — IP rate limit
# ──────────────────────────────────────────────────────────────────────────

def check_rate_limit(key: str) -> bool:
    """Return ``True`` if *key* is still under the per-window threshold."""
    count = _redis_count(key)
    if count is not None:
        return count < _RATE_MAX_HITS
    return _local_check_ip(key)


def record_failure(key: str) -> None:
    """Atomically increment the counter for *key* and apply the TTL."""
    if _redis_incr(key) is None:
        _local_record_ip(key)


def clear_failures(key: str) -> None:
    if not _redis_clear(key):
        _local_clear_ip(key)


# ──────────────────────────────────────────────────────────────────────────
# Public API — per-account lockout
# ──────────────────────────────────────────────────────────────────────────

def check_account_lock(user: str) -> bool:
    """Return ``True`` if the account is *not* locked (i.e. login is allowed)."""
    if not user:
        return True
    ok = _redis_check_lock(user)
    if ok is not None:
        return ok
    return _local_check_account(user)


def record_account_failure(user: str) -> bool:
    """Record one failure for *user*. Returns ``True`` if this call just placed a lock."""
    if not user:
        return False
    res = _redis_record_account(user)
    if res is not None:
        _count, just_locked = res
        return just_locked
    return _local_record_account(user)


def clear_account_failures(user: str) -> None:
    if not user:
        return
    if not _redis_clear_account(user):
        _local_clear_account(user)


# ──────────────────────────────────────────────────────────────────────────
# Test / admin helpers
# ──────────────────────────────────────────────────────────────────────────

def _reset_all_local() -> None:
    """Used by unit tests to wipe the in-process state."""
    with _lock:
        _login_failures.clear()
        _account_failures.clear()
        _account_lock_until.clear()


async def _reset_all_redis() -> None:
    """Used by integration tests to wipe Redis state for both prefixes."""
    from naco.core.cache import get_redis
    r = await get_redis()
    if r is None:
        return
    pipe = r.pipeline()
    for prefix in (_KEY_PREFIX, _LOCK_KEY_PREFIX):
        cursor = 0
        while True:
            cursor, batch = await r.scan(cursor=cursor, match=prefix + "*", count=200)
            if batch:
                pipe.delete(*batch)
            if cursor == 0:
                break
    await pipe.execute()


def reset_all() -> None:
    """Best-effort reset used in tests."""
    _reset_all_local()
    try:
        asyncio.get_event_loop().run_until_complete(_reset_all_redis())
    except Exception:
        pass
