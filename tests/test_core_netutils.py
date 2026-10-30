import pytest

from naco.core.netutils import (
    ip_in_any,
    is_randomized_mac,
    normalize_mac,
    parse_called_station,
    parse_client_address,
    parse_ip,
)


@pytest.mark.parametrize("value", [
    "aa:bb:cc:dd:ee:ff", "AA:BB:CC:DD:EE:FF", "aa-bb-cc-dd-ee-ff", "aabb.ccdd.eeff", "AABBCCDDEEFF",
    "  aa:bb:cc:dd:ee:ff  ",
    "aabb-ccdd-eeff", "AABB-CCDD-EEFF",  # Huawei, H3C, HPE Comware
    "aabbcc-ddeeff", "AABBCC-DDEEFF",    # ArubaOS-Switch (ProCurve) single-dash
    "AABB:CCDD:EEFF", "AABBCC:DDEEFF", "AA BB CC DD EE FF",  # MikroTik radius-mac-format
    "aa.bb.cc.dd.ee.ff",                 # Ruckus ICX
])
def test_normalize_mac_accepts_common_forms(value):
    assert normalize_mac(value) == "aa:bb:cc:dd:ee:ff"


@pytest.mark.parametrize("value", [
    None, "", "alice", "aa:bb:cc:dd:ee", "aa:bb-cc:dd:ee:ff", "aabbccddeeffaa", "gg:bb:cc:dd:ee:ff",
    "aa:bb:cc:dd:ee:ff:00", "aabb.ccdd.eeff.0011", "aabb-ccdd.eeff", "aabbc-cddeeff", "aabb-ccddeeff",
    "aa:bb:cc:dd:ee-ff", "aabb ccdd-eeff", "aa  bb cc dd ee ff",
])
def test_normalize_mac_rejects_everything_else(value):
    assert normalize_mac(value) is None


def test_randomized_mac():
    assert is_randomized_mac("da:a1:19:00:00:01")
    assert not is_randomized_mac("00:1b:63:00:00:01")


@pytest.mark.parametrize("value,expected", [
    ("AA-BB-CC-DD-EE-FF:Guest", ("aa:bb:cc:dd:ee:ff", "Guest")),
    ("aa:bb:cc:dd:ee:ff:Corp WiFi", ("aa:bb:cc:dd:ee:ff", "Corp WiFi")),
    ("AA-BB-CC-DD-EE-FF", ("aa:bb:cc:dd:ee:ff", None)),
    ("AA-BB-CC-DD-EE-FF:", ("aa:bb:cc:dd:ee:ff", None)),
    ("AABBCCDDEEFF:Guest", ("aa:bb:cc:dd:ee:ff", "Guest")),
    ("aabb.ccdd.eeff:Corp", ("aa:bb:cc:dd:ee:ff", "Corp")),
    ("aabb-ccdd-eeff:Corp", ("aa:bb:cc:dd:ee:ff", "Corp")),
    ("aa:bb:cc:dd:ee:ff:a:b", ("aa:bb:cc:dd:ee:ff", "a:b")),
    ("not a station", (None, None)),
    ("", (None, None)),
])
def test_parse_called_station(value, expected):
    assert parse_called_station(value) == expected


def test_parse_ip():
    assert parse_ip(" 10.0.0.1 ") == "10.0.0.1"
    assert parse_ip("2001:db8::1") == "2001:db8::1"
    assert parse_ip("10.0.0.300") is None
    assert parse_ip(None) is None


@pytest.mark.parametrize("value,expected", [
    ("10.0.0.5", "10.0.0.5"), (" 10.0.20.0/24 ", "10.0.20.0/24"), ("10.0.20.5/32", "10.0.20.5"),
    ("10.1.0.0/16", "10.1.0.0/16"), ("2001:db8:1::/64", "2001:db8:1::/64"), ("2001:db8::7/128", "2001:db8::7"),
])
def test_client_address_is_an_ip_or_a_network(value, expected):
    assert parse_client_address(value) == expected


@pytest.mark.parametrize("value,message", [
    ("10.0.20.5/24", "10.0.20.0/24"),       # host bits set: say which network was meant
    ("10.0.0.0/8", "/16"), ("0.0.0.0/0", "/16"), ("2001:db8::/32", "/48"),
    ("10.0.0.300", "IP address"), ("", "IP address"),
])
def test_client_address_refuses(value, message):
    with pytest.raises(ValueError, match=message):
        parse_client_address(value)


def test_ip_in_any():
    assert ip_in_any("10.1.2.3", ["192.168.0.0/16", "10.0.0.0/8"])
    assert not ip_in_any("11.0.0.1", ["10.0.0.0/8"])
    assert not ip_in_any("garbage", ["0.0.0.0/0"])
    assert ip_in_any("2001:db8::5", ["2001:db8::/32"])
