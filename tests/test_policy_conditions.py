from datetime import UTC, datetime
from zoneinfo import ZoneInfo

import pytest

from naco.db.models import PolicyAction
from naco.policy.attributes import validate_reply_attributes
from naco.policy.conditions import condition_matches, dump_conditions, parse_conditions
from naco.policy.context import AuthContext, Decision

UTC_TZ = ZoneInfo("UTC")


def ctx(**kw):
    base = {"auth_method": "PEAP", "username": "alice", "group": "staff", "mac": "aa:bb:cc:dd:ee:ff",
            "device_status": "approved", "device_type": "laptop", "vendor": "Apple, Inc.",
            "nas_name": "core-sw1", "nas_ip": "10.0.0.1", "ssid": "Corp",
            "now": datetime(2026, 10, 28, 10, 30, tzinfo=UTC)}  # a Wednesday
    base.update(kw)
    return AuthContext(**base)


def match(cond: dict, **kw) -> bool:
    (parsed,) = parse_conditions([cond])
    return condition_matches(parsed, ctx(**kw), UTC_TZ)


# ── parsing ────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("raw,msg", [
    ({"type": "bogus"}, "type"),
    ({"type": "username", "op": "regex", "value": ".*"}, "op"),
    ({"type": "username", "op": "in", "value": "alice"}, "list"),
    ({"type": "username", "op": "equals", "value": ["alice"]}, "string"),
    ({"type": "username", "op": "equals", "value": "  "}, "non-empty"),
    ({"type": "username", "op": "matches", "value": "x" * 129}, "128"),
    ({"type": "group", "op": "in", "value": []}, "non-empty"),
    ({"type": "auth_method", "value": ["CHAP"]}, "auth_method"),
    ({"type": "device_status", "value": ["blocked"]}, "device_status"),
    ({"type": "mac", "op": "equals", "value": "not-a-mac"}, "MAC"),
    ({"type": "mac", "op": "matches", "value": "zz:*"}, "hex"),
    ({"type": "time", "start": "25:00", "end": "10:00"}, "HH:MM"),
    ({"type": "time", "start": "9:00", "end": "10:00"}, "HH:MM"),
    ({"type": "time", "start": "09:00", "end": "10:00", "days": ["funday"]}, "days"),
    ({"type": "always", "extra": 1}, "extra"),
])
def test_invalid_conditions_are_rejected(raw, msg):
    with pytest.raises(ValueError, match=msg):
        parse_conditions([raw])


def test_condition_count_is_limited():
    with pytest.raises(ValueError, match="at most"):
        parse_conditions([{"type": "always"}] * 21)


def test_conditions_must_be_a_list():
    with pytest.raises(ValueError):
        parse_conditions({"type": "always"})


def test_values_are_normalised_and_dump_roundtrips():
    parsed = parse_conditions([
        {"type": "mac", "op": "in", "value": ["AA-BB-CC-DD-EE-FF", "aabb.ccdd.ee00"]},
        {"type": "mac", "op": "matches", "value": "AA-BB-CC-*"},
        {"type": "username", "op": "equals", "value": "  bob "},
    ])
    dumped = dump_conditions(parsed)
    assert dumped[0]["value"] == ["aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:00"]
    assert dumped[1]["value"] == "aa:bb:cc:*"
    assert dumped[2]["value"] == "bob"
    assert dump_conditions(parse_conditions(dumped)) == dumped


# ── evaluation ─────────────────────────────────────────────────────────────

def test_always():
    assert match({"type": "always"})


@pytest.mark.parametrize("cond,expected", [
    ({"op": "equals", "value": "ALICE"}, True),
    ({"op": "equals", "value": "bob"}, False),
    ({"op": "not_equals", "value": "bob"}, True),
    ({"op": "in", "value": ["bob", "Alice"]}, True),
    ({"op": "matches", "value": "al*"}, True),
    ({"op": "matches", "value": "b?b"}, False),
])
def test_username(cond, expected):
    assert match({"type": "username", **cond}) is expected


def test_username_conditions_never_match_missing_identity():
    assert not match({"type": "username", "op": "equals", "value": "alice"}, username="")
    assert not match({"type": "username", "op": "matches", "value": "*"}, username="")


def test_group():
    assert match({"type": "group", "op": "in", "value": ["Staff"]})
    assert not match({"type": "group", "op": "in", "value": ["staff"]}, group=None)
    assert match({"type": "group", "op": "not_in", "value": ["admins"]})
    assert match({"type": "group", "op": "not_in", "value": ["staff"]}, group=None)


def test_auth_method_and_device_status():
    assert match({"type": "auth_method", "value": ["PEAP", "EAP-TLS"]})
    assert not match({"type": "auth_method", "value": ["MAB"]})
    assert match({"type": "device_status", "value": ["approved"]})
    assert not match({"type": "device_status", "value": ["guest"]}, device_status=None)


def test_mac():
    assert match({"type": "mac", "op": "equals", "value": "AA:BB:CC:DD:EE:FF"})
    assert match({"type": "mac", "op": "matches", "value": "aa:bb:cc:*"})
    assert not match({"type": "mac", "op": "matches", "value": "aa:bb:cc:*"}, mac=None)
    assert not match({"type": "mac", "op": "in", "value": ["00:00:00:00:00:01"]})


def test_text_fields():
    assert match({"type": "device_type", "op": "in", "value": ["Laptop"]})
    assert match({"type": "vendor", "op": "matches", "value": "apple*"})
    assert match({"type": "nas", "op": "in", "value": ["core-sw1"]})
    assert match({"type": "ssid", "op": "in", "value": ["corp"]})
    assert not match({"type": "ssid", "op": "in", "value": ["corp"]}, ssid=None)
    assert match({"type": "ssid", "op": "not_in", "value": ["guest"]}, ssid=None)


@pytest.mark.parametrize("cond,now,expected", [
    ({"start": "09:00", "end": "17:00"}, datetime(2026, 10, 28, 10, 30, tzinfo=UTC), True),
    ({"start": "09:00", "end": "17:00"}, datetime(2026, 10, 28, 17, 0, 59, tzinfo=UTC), True),
    ({"start": "09:00", "end": "17:00"}, datetime(2026, 10, 28, 17, 1, tzinfo=UTC), False),
    ({"start": "22:00", "end": "06:00"}, datetime(2026, 10, 28, 23, 0, tzinfo=UTC), True),
    ({"start": "22:00", "end": "06:00"}, datetime(2026, 10, 28, 5, 0, tzinfo=UTC), True),
    ({"start": "22:00", "end": "06:00"}, datetime(2026, 10, 28, 12, 0, tzinfo=UTC), False),
    ({"start": "00:00", "end": "23:59", "days": ["sat", "sun"]}, datetime(2026, 10, 28, 12, tzinfo=UTC), False),
    ({"start": "00:00", "end": "23:59", "days": ["wed"]}, datetime(2026, 10, 28, 12, tzinfo=UTC), True),
])
def test_time(cond, now, expected):
    assert match({"type": "time", **cond}, now=now) is expected


def test_time_uses_configured_zone():
    (cond,) = parse_conditions([{"type": "time", "start": "09:00", "end": "17:00"}])
    late_utc = ctx(now=datetime(2026, 10, 28, 18, 0, tzinfo=UTC))  # 21:00 in Istanbul
    early_utc = ctx(now=datetime(2026, 10, 28, 7, 0, tzinfo=UTC))  # 10:00 in Istanbul
    assert not condition_matches(cond, late_utc, ZoneInfo("Europe/Istanbul"))
    assert condition_matches(cond, early_utc, ZoneInfo("Europe/Istanbul"))


def test_labels_are_readable():
    parsed = parse_conditions([
        {"type": "group", "op": "in", "value": ["a", "b"]},
        {"type": "time", "start": "09:00", "end": "17:00", "days": ["mon"]},
    ])
    assert parsed[0].label() == "group in a, b"
    assert parsed[1].label() == "time 09:00-17:00 on mon"


# ── reply attributes ───────────────────────────────────────────────────────

def test_reply_attributes_accepted():
    attrs = validate_reply_attributes({
        "Aruba-User-Role": "employee", "Session-Timeout": 3600, "Cisco-AVPair": ["a=b", "c=d"],
    })
    assert attrs["Session-Timeout"] == 3600


@pytest.mark.parametrize("raw", [
    {"control:Auth-Type": "Accept"},
    {"outer.reply:Foo": "x"},
    {"Tunnel-Private-Group-Id": "10"},
    {"Message-Authenticator": "x"},
    {"MS-MPPE-Send-Key": "x"},
    {"Filter-Id": "%{User-Name}"},
    {"Filter-Id": "a\nb"},
    {"Filter-Id": ""},
    {"Filter-Id": True},
    {"Filter-Id": {"nested": 1}},
    {"Session-Timeout": -1},
    {"Cisco-AVPair": []},
    {f"A-{i}": "x" for i in range(33)},
])
def test_reply_attributes_rejected(raw):
    with pytest.raises(ValueError):
        validate_reply_attributes(raw)


def test_decision_digest_tracks_what_the_nas_sees():
    a = Decision(PolicyAction.PERMIT, 1, "p", "ok", vlan=10, reply_attributes={"Filter-Id": "x"})
    b = Decision(PolicyAction.PERMIT, 2, "other name", "other reason", vlan=10, reply_attributes={"Filter-Id": "x"})
    c = Decision(PolicyAction.PERMIT, 1, "p", "ok", vlan=20, reply_attributes={"Filter-Id": "x"})
    assert a.digest() == b.digest()
    assert a.digest() != c.digest()
    assert a.accepted
