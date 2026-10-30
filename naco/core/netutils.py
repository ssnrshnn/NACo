"""MAC, IP and RADIUS station-id parsing."""
from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable

_MAC_FORMS = (
    re.compile(r"^[0-9a-f]{2}([:-])[0-9a-f]{2}(?:\1[0-9a-f]{2}){4}$", re.I),  # aa:bb:.. / AA-BB-..
    re.compile(r"^[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}$", re.I),              # aabb.ccdd.eeff
    re.compile(r"^[0-9a-f]{12}$", re.I),                                        # aabbccddeeff
)
_STATION = re.compile(r"^([0-9a-f]{2}(?:[:-][0-9a-f]{2}){5})(?::(.*))?$", re.I | re.S)


def normalize_mac(value: str | None) -> str | None:
    """Return ``aa:bb:cc:dd:ee:ff`` for a well-formed MAC, else ``None``."""
    if not value:
        return None
    value = value.strip()
    if not any(form.match(value) for form in _MAC_FORMS):
        return None
    raw = re.sub(r"[^0-9a-fA-F]", "", value).lower()
    return ":".join(raw[i:i + 2] for i in range(0, 12, 2))


def is_randomized_mac(mac: str) -> bool:
    """Locally administered bit set — phones' per-network private addresses."""
    norm = normalize_mac(mac)
    return norm is not None and bool(int(norm[1], 16) & 0x2)


def parse_called_station(value: str | None) -> tuple[str | None, str | None]:
    """Split ``Called-Station-Id`` ("AA-BB-CC-DD-EE-FF:SSID") into (mac, ssid)."""
    if not value:
        return None, None
    m = _STATION.match(value.strip())
    if not m:
        return None, None
    ssid = (m.group(2) or "").strip() or None
    return normalize_mac(m.group(1)), (ssid[:64] if ssid else None)


def parse_ip(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def ip_in_any(ip: str, networks: Iterable[str]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for net in networks:
        try:
            if addr in ipaddress.ip_network(net, strict=False):
                return True
        except ValueError:
            continue
    return False
