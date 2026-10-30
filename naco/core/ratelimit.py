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
