"""In-memory throttling — NACo is a single process, so no shared store is needed."""
from __future__ import annotations

import time
from collections import OrderedDict, deque


class SlidingWindow:
    """At most ``limit`` hits per ``window_seconds`` per key."""

    def __init__(self, limit: int, window_seconds: float, max_keys: int = 50_000) -> None:
        self.limit = limit
        self.window = window_seconds
        self.max_keys = max_keys
        self._hits: OrderedDict[str, deque[float]] = OrderedDict()

    def hit(self, key: str, now: float | None = None) -> bool:
        """Record a hit; return False (and record nothing) when over the limit."""
        now = time.monotonic() if now is None else now
        q = self._hits.get(key)
        if q is None:
            if len(self._hits) >= self.max_keys:
                self._hits.popitem(last=False)
            q = self._hits[key] = deque()
        else:
            self._hits.move_to_end(key)
        while q and q[0] <= now - self.window:
            q.popleft()
        if len(q) >= self.limit:
            return False
        q.append(now)
        return True

    def reset(self, key: str) -> None:
        self._hits.pop(key, None)


class ProgressiveDelay:
    """Growing wait after repeated failures — slows guessing without a lockout.

    The first ``free_attempts`` failures cost nothing; after that the wait
    doubles from ``base`` up to ``cap`` seconds. A success, or ``forget_after``
    seconds without failures, clears the key.
    """

    def __init__(self, base: float = 1.0, cap: float = 30.0, free_attempts: int = 3,
                 forget_after: float = 900.0, max_keys: int = 50_000) -> None:
        self.base, self.cap, self.free, self.forget = base, cap, free_attempts, forget_after
        self.max_keys = max_keys
        self._state: OrderedDict[str, tuple[int, float, float]] = OrderedDict()  # failures, next_allowed, last

    def _get(self, key: str, now: float) -> tuple[int, float, float]:
        state = self._state.get(key)
        if state and now - state[2] > self.forget:
            del self._state[key]
            state = None
        return state or (0, 0.0, now)

    def delay_for(self, key: str, now: float | None = None) -> float:
        now = time.monotonic() if now is None else now
        _, next_allowed, _ = self._get(key, now)
        return max(0.0, next_allowed - now)

    def failure(self, key: str, now: float | None = None) -> None:
        now = time.monotonic() if now is None else now
        failures, _, _ = self._get(key, now)
        failures += 1
        wait = 0.0 if failures <= self.free else min(self.cap, self.base * 2 ** (failures - self.free - 1))
        if key not in self._state and len(self._state) >= self.max_keys:
            self._state.popitem(last=False)
        self._state[key] = (failures, now + wait, now)
        self._state.move_to_end(key)

    def success(self, key: str) -> None:
        self._state.pop(key, None)


class GuessGuard:
    """Slows password guessing per identity *and source*.

    One source — an attacker, or the user's own phone still trying an old
    password — only slows itself down, so it cannot lock the owner out from
    their other devices. Failures from ``spread`` different sources within
    ``window`` seconds look like a distributed guess: then the identity is
    slowed down everywhere.
    """

    def __init__(self, *, free_attempts: int = 5, cap: float = 30.0, spread: int = 10,
                 window: float = 900.0, max_keys: int = 50_000) -> None:
        self._pair = ProgressiveDelay(base=1.0, cap=cap, free_attempts=free_attempts,
                                      forget_after=window, max_keys=max_keys)
        self._identity = ProgressiveDelay(base=1.0, cap=cap, free_attempts=0,
                                          forget_after=window, max_keys=max_keys)
        self._sources: OrderedDict[str, dict[str, float]] = OrderedDict()
        self.spread, self.window, self.max_keys = spread, window, max_keys

    def clear(self) -> None:
        self._pair._state.clear()
        self._identity._state.clear()
        self._sources.clear()

    def _failing_sources(self, identity: str, now: float) -> dict[str, float]:
        sources = self._sources.get(identity, {})
        for source in [s for s, at in sources.items() if now - at > self.window]:
            del sources[source]
        return sources

    def delay_for(self, identity: str, source: str, now: float | None = None) -> float:
        now = time.monotonic() if now is None else now
        wait = self._pair.delay_for(f"{identity}\x00{source}", now)
        if len(self._failing_sources(identity, now)) >= self.spread:
            wait = max(wait, self._identity.delay_for(identity, now))
        return wait

    def failure(self, identity: str, source: str, now: float | None = None) -> None:
        now = time.monotonic() if now is None else now
        self._pair.failure(f"{identity}\x00{source}", now)
        sources = self._failing_sources(identity, now)
        if identity not in self._sources and len(self._sources) >= self.max_keys:
            self._sources.popitem(last=False)
        sources[source] = now
        if len(sources) > self.spread * 4:  # bounded: only "many" matters
            del sources[min(sources, key=sources.__getitem__)]
        self._sources[identity] = sources
        self._sources.move_to_end(identity)
        if len(sources) >= self.spread:
            self._identity.failure(identity, now)

    def success(self, identity: str, source: str) -> None:
        self._pair.success(f"{identity}\x00{source}")
