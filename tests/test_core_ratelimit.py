from naco.core.ratelimit import ProgressiveDelay, SlidingWindow


def test_sliding_window_limits_and_recovers():
    w = SlidingWindow(limit=3, window_seconds=10)
    assert all(w.hit("ip", now=t) for t in (0, 1, 2))
    assert not w.hit("ip", now=3)
    assert w.hit("other", now=3)
    assert w.hit("ip", now=10.5)  # the hit at t=0 left the window


def test_sliding_window_rejected_hits_are_not_counted():
    w = SlidingWindow(limit=1, window_seconds=10)
    assert w.hit("k", now=0)
    for t in range(1, 9):
        assert not w.hit("k", now=t)
    assert w.hit("k", now=10.1)


def test_sliding_window_bounds_memory():
    w = SlidingWindow(limit=1, window_seconds=60, max_keys=2)
    w.hit("a", now=0)
    w.hit("b", now=0)
    w.hit("c", now=0)
    assert w.hit("a", now=1)  # "a" was evicted


def test_progressive_delay_grows_then_caps():
    d = ProgressiveDelay(base=1, cap=8, free_attempts=2)
    waits = []
    now = 0.0
    for _ in range(7):
        d.failure("u", now=now)
        waits.append(d.delay_for("u", now=now))
    assert waits == [0, 0, 1, 2, 4, 8, 8]


def test_progressive_delay_expires_and_resets():
    d = ProgressiveDelay(base=1, cap=30, free_attempts=0, forget_after=100)
    d.failure("u", now=0)
    assert d.delay_for("u", now=0.5) == 0.5
    assert d.delay_for("u", now=2) == 0
    d.failure("u", now=2)
    d.success("u")
    assert d.delay_for("u", now=2) == 0
    d.failure("u", now=3)
    assert d.delay_for("u", now=200) == 0  # forgotten
