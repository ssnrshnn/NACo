"""Phase 1.3/1.4 — Account lockout and atomic rate limiter.

These exercise the in-process fallback path (Redis is not started in CI
unit jobs). The Lua-script branch is covered by the integration suite.
"""
from __future__ import annotations

import pytest

from naco.core.ratelimit import (
    _LOCKOUT_THRESHOLD,
    _RATE_MAX_HITS,
    check_account_lock,
    check_rate_limit,
    clear_account_failures,
    clear_failures,
    record_account_failure,
    record_failure,
    reset_all,
)


# ---------------------------------------------------------------------------
# IP rate limit — sliding-window counter.
# ---------------------------------------------------------------------------

class TestIpRateLimit:
    def setup_method(self):
        reset_all()

    def test_allows_up_to_max_hits(self):
        """First N failures must be allowed; only the (N+1)-th rejects."""
        for _ in range(_RATE_MAX_HITS):
            assert check_rate_limit("1.2.3.4") is True
            record_failure("1.2.3.4")
        # The (N+1)-th check should be False — counter has hit the cap.
        assert check_rate_limit("1.2.3.4") is False

    def test_isolated_per_ip(self):
        for _ in range(_RATE_MAX_HITS):
            record_failure("1.2.3.4")
        assert check_rate_limit("1.2.3.4") is False
        # A different IP should still be allowed.
        assert check_rate_limit("5.6.7.8") is True

    def test_clear_resets(self):
        for _ in range(_RATE_MAX_HITS):
            record_failure("9.9.9.9")
        assert check_rate_limit("9.9.9.9") is False
        clear_failures("9.9.9.9")
        assert check_rate_limit("9.9.9.9") is True


# ---------------------------------------------------------------------------
# Per-account lockout.
# ---------------------------------------------------------------------------

class TestAccountLockout:
    def setup_method(self):
        reset_all()

    def test_unlocked_by_default(self):
        assert check_account_lock("alice") is True

    def test_unlocked_below_threshold(self):
        # threshold - 1 failures must not trigger the lock yet.
        for _ in range(_LOCKOUT_THRESHOLD - 1):
            record_account_failure("alice")
        assert check_account_lock("alice") is True

    def test_locks_at_threshold(self):
        triggers = []
        for i in range(_LOCKOUT_THRESHOLD):
            triggers.append(record_account_failure("bob"))
        # The Nth failure must have flipped the just_locked flag (or rather,
        # the helper returned True on the call that placed the lock).
        assert any(triggers), "no failure call reported placing a lock"
        # Subsequent check must now refuse the login.
        assert check_account_lock("bob") is False

    def test_clear_unlocks(self):
        for _ in range(_LOCKOUT_THRESHOLD):
            record_account_failure("carol")
        assert check_account_lock("carol") is False
        clear_account_failures("carol")
        assert check_account_lock("carol") is True

    def test_separate_users_independent(self):
        for _ in range(_LOCKOUT_THRESHOLD):
            record_account_failure("dan")
        assert check_account_lock("dan") is False
        assert check_account_lock("erin") is True

    def test_empty_username_is_noop(self):
        # Empty / None usernames must not be tracked — otherwise an
        # attacker could DoS legitimate logins by spamming the empty
        # username and "filling up" the global slot.
        for _ in range(_LOCKOUT_THRESHOLD + 5):
            record_account_failure("")
        assert check_account_lock("") is True


# ---------------------------------------------------------------------------
# Integration with API login — successful login must reset both counters.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestApiLoginClearsCounters:
    async def test_successful_login_clears_account_counter(
        self, client, admin_user,
    ):
        from naco.core import ratelimit as rl
        rl.reset_all()

        # Burn a couple of failures.
        for _ in range(3):
            r = await client.post(
                "/api/v1/auth/login",
                json={"username": "testadmin", "password": "Wrong1"},
            )
            assert r.status_code == 401

        # Now succeed — that should wipe the per-account counter.
        r = await client.post(
            "/api/v1/auth/login",
            json={"username": "testadmin", "password": "Admin1234"},
        )
        assert r.status_code == 200

        # Drive the counter close to the threshold from scratch — if the
        # previous failures hadn't been cleared, we'd trip the lock early.
        for _ in range(_LOCKOUT_THRESHOLD - 1):
            record_account_failure("testadmin")
        assert check_account_lock("testadmin") is True
