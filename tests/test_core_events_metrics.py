import pytest

from naco.core.events import Event, EventBus, EventType
from naco.core.metrics import Registry


async def test_bus_delivers_and_drops_oldest_when_full():
    bus = EventBus(queue_size=2)
    async with bus.subscribe() as q:
        assert bus.subscriber_count == 1
        for i in range(3):
            bus.publish(Event(EventType.AUTH, {"i": i}))
        assert [q.get_nowait().data["i"] for _ in range(2)] == [1, 2]
    assert bus.subscriber_count == 0


def test_publish_without_subscribers_is_a_noop():
    EventBus().publish(Event(EventType.AUDIT, {}))


def test_registry_renders_prometheus_text():
    r = Registry()
    c = r.counter("naco_auth_total", "Decisions", ["result"])
    g = r.gauge("naco_sessions", "Active sessions")
    h = r.histogram("naco_aaa_seconds", "Latency", buckets=[0.1, 1])
    c.inc(result="ACCEPT")
    c.inc(2, result="REJECT")
    g.set(5)
    h.observe(0.05)
    h.observe(0.5)
    text = r.render()
    assert '# TYPE naco_auth_total counter' in text
    assert 'naco_auth_total{result="ACCEPT"} 1' in text
    assert 'naco_auth_total{result="REJECT"} 2' in text
    assert "naco_sessions 5" in text
    assert 'naco_aaa_seconds_bucket{le="0.1"} 1' in text
    assert 'naco_aaa_seconds_bucket{le="+Inf"} 2' in text
    assert "naco_aaa_seconds_count 2" in text


def test_label_values_are_escaped_and_checked():
    r = Registry()
    c = r.counter("x_total", "x", ["v"])
    c.inc(v='a"b\\c\n')
    assert 'x_total{v="a\\"b\\\\c\\n"} 1' in r.render()
    with pytest.raises(ValueError):
        c.inc(wrong="1")
    with pytest.raises(ValueError):
        r.counter("x_total", "dup")
