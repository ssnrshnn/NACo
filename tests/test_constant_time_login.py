"""Phase 1.2 — Constant-time login.

We don't try to assert exact wall-clock parity (CI is too noisy for that),
just that:

1. The login endpoint takes a measurable bcrypt-shaped amount of time
   when the user **doesn't exist** (i.e. ``dummy_verify`` was invoked),
   so the username-enumeration oracle is closed.
2. Public API: :func:`naco.api.auth.dummy_verify` always returns ``False``
   and exhibits no observable side effects across calls.

To keep the suite fast we'd normally lower the bcrypt cost during tests,
but here the *point* of the test is that the dummy path *does* spend the
bcrypt cost. We compare it against a known real-bcrypt baseline measured
in the same process so noise cancels.
"""
from __future__ import annotations

import time
import pytest
from httpx import AsyncClient

from naco.api.auth import dummy_verify, hash_password, verify_password


# ---------------------------------------------------------------------------
# Direct unit test: dummy_verify exists, returns False, and is non-trivial.
# ---------------------------------------------------------------------------

class TestDummyVerify:
    def test_returns_false(self):
        assert dummy_verify("anything") is False
        assert dummy_verify("") is False

    def test_is_not_a_noop(self):
        """Calling dummy_verify must spend measurable CPU — otherwise the
        "user not found" branch would be a timing oracle. We tolerate a
        generous lower bound (10 ms) to avoid flaky CI on burst-credited VMs.
        """
        t0 = time.perf_counter()
        for _ in range(3):
            dummy_verify("password")
        elapsed = (time.perf_counter() - t0) / 3
        assert elapsed > 0.010, (
            f"dummy_verify too fast ({elapsed*1000:.1f}ms) — it should spend "
            "a full bcrypt comparison, otherwise it leaks the unknown-user "
            "branch via timing."
        )

    def test_timing_parity_with_real_verify(self):
        """Real and dummy bcrypt should be within an order of magnitude.

        ``verify_password(wrong, hash)`` and ``dummy_verify(...)`` both run
        a bcrypt comparison at the same cost factor, so they should take
        roughly equal wall-clock time. We accept up to a 5x ratio either
        way to cover JIT warm-up, scheduler jitter, and CI noise.
        """
        real_hash = hash_password("Realone1")

        # Warm up — first bcrypt call after import is dominated by salt init.
        verify_password("wrong", real_hash)
        dummy_verify("wrong")

        t0 = time.perf_counter()
        verify_password("wrong", real_hash)
        real_dt = time.perf_counter() - t0

        t0 = time.perf_counter()
        dummy_verify("wrong")
        dummy_dt = time.perf_counter() - t0

        ratio = max(real_dt, dummy_dt) / min(real_dt, dummy_dt)
        assert ratio < 5.0, (
            f"verify_password={real_dt*1000:.1f}ms vs "
            f"dummy_verify={dummy_dt*1000:.1f}ms (ratio {ratio:.1f}) — "
            "should be within an order of magnitude."
        )


# ---------------------------------------------------------------------------
# Integration: hitting the API with a non-existent user must NOT be faster
# than hitting it with an existing user + wrong password.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestApiLoginTiming:
    async def test_unknown_user_not_faster_than_wrong_password(
        self, client: AsyncClient, admin_user,
    ):
        # Warm-up call — the first bcrypt comparison after process start is
        # always slower due to salt machinery.
        await client.post(
            "/api/v1/auth/login",
            json={"username": "warmup", "password": "Wrong1234"},
        )

        # Wrong password against an existing user — real bcrypt path.
        t0 = time.perf_counter()
        resp = await client.post(
            "/api/v1/auth/login",
            json={"username": "testadmin", "password": "Wrong1234"},
        )
        wrong_pw_dt = time.perf_counter() - t0
        assert resp.status_code == 401

        # Unknown user — should now also spend bcrypt time (Phase 1.2).
        t0 = time.perf_counter()
        resp = await client.post(
            "/api/v1/auth/login",
            json={"username": "nonexistent-user-xyzzy", "password": "Wrong1234"},
        )
        unknown_user_dt = time.perf_counter() - t0
        assert resp.status_code == 401

        # The unknown-user path must spend at least 25% of the wrong-pw cost
        # to count as "not a timing oracle". In a perfect world they're
        # equal; we leave headroom because rate-limit / DB-lookup noise
        # tilts the ratio slightly.
        assert unknown_user_dt > wrong_pw_dt * 0.25, (
            f"Unknown-user response was {unknown_user_dt*1000:.1f}ms, "
            f"wrong-password was {wrong_pw_dt*1000:.1f}ms — too fast, "
            "indicates the dummy_verify call was skipped."
        )
