"""What each kind of NAS needs in a Disconnect-Request (RFC 5176) to find a session.

Every value is the one the NAS itself reported in accounting, so whatever is
sent matches; vendors differ in which attributes they accept at all — an
attribute a NAS does not expect makes some of them answer NAK.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Vendor:
    label: str
    # Session and NAS identification attributes, named by the SessionIds field
    # (naco.radius.coa) that holds the value the NAS reported.
    identify: tuple[str, ...] = ("acct_session_id", "user_name", "calling_station_id", "nas_ip_address",
                                 "nas_identifier")
    coa_port: int = 3799
    event_timestamp: bool = True
    message_authenticator: bool = True


VENDORS: dict[str, Vendor] = {
    # Everything RFC 5176 and hostapd-based access points (UniFi, many others) accept.
    "standard": Vendor("Standard (RFC 5176) — Huawei, H3C/Comware, MikroTik, UniFi, Omada, others"),
    "cisco": Vendor("Cisco IOS-XE / Catalyst 9800", identify=("acct_session_id", "calling_station_id",
                                                              "audit_session_id")),
    "meraki": Vendor("Cisco Meraki", identify=("calling_station_id", "nas_ip_address", "audit_session_id"),
                     coa_port=1700, event_timestamp=False),
    # AOS-CX requires a NAS identifier and User-Name; AOS-S refuses an
    # Event-Timestamp ahead of its own clock by even a second.
    "aruba": Vendor("HPE Aruba Networking (AOS-CX, AOS-S, AOS 8/10, Instant)", event_timestamp=False),
    "juniper": Vendor("Juniper", identify=("acct_session_id", "user_name", "calling_station_id", "nas_ip_address"),
                      event_timestamp=False),
    "fortinet": Vendor("Fortinet", identify=("user_name", "calling_station_id", "nas_ip_address")),
    "extreme": Vendor("Extreme Networks", identify=("calling_station_id", "nas_ip_address"), event_timestamp=False),
    "ruckus-icx": Vendor("Ruckus ICX", identify=("calling_station_id", "nas_ip_address"), event_timestamp=False,
                         message_authenticator=False),
}
DEFAULT_VENDOR = "standard"


def vendor(key: str | None) -> Vendor:
    return VENDORS.get(key or DEFAULT_VENDOR, VENDORS[DEFAULT_VENDOR])
