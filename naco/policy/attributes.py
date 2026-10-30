"""Validation of per-policy RADIUS reply attributes.

Names are bare dictionary names: a list or request qualifier ("control:",
"outer.") would let a policy rewrite FreeRADIUS' own control flow. Attributes
NACo manages itself (VLAN tunnel attributes) or that belong to the protocol
machinery are refused. Values never carry FreeRADIUS expansions.
"""
from __future__ import annotations

import re
from typing import Any

_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,63}$")
_FORBIDDEN = {
    "tunnel-type", "tunnel-medium-type", "tunnel-private-group-id",
    "message-authenticator", "eap-message", "state", "proxy-state",
    "user-password", "chap-password", "auth-type",
}
_FORBIDDEN_PREFIXES = ("ms-mppe-", "freeradius-", "naco-")
_MAX_ATTRS = 32
_MAX_VALUES = 10
_MAX_LEN = 253


def _check_value(name: str, value: Any) -> str | int:
    if isinstance(value, bool):
        raise ValueError(f"{name}: booleans are not RADIUS values")
    if isinstance(value, int):
        if not 0 <= value <= 0xFFFFFFFF:
            raise ValueError(f"{name}: integer out of range")
        return value
    if isinstance(value, str):
        if not value or len(value) > _MAX_LEN:
            raise ValueError(f"{name}: value must be 1-{_MAX_LEN} characters")
        if "%{" in value:
            raise ValueError(f"{name}: '%{{' expansions are not allowed")
        if any(ord(c) < 0x20 or ord(c) == 0x7F for c in value):
            raise ValueError(f"{name}: control characters are not allowed")
        return value
    raise ValueError(f"{name}: value must be a string, an integer, or a list of them")


def validate_reply_attributes(raw: dict[str, Any] | None) -> dict[str, Any]:
    if not raw:
        return {}
    if not isinstance(raw, dict):
        raise ValueError("reply attributes must be an object")
    if len(raw) > _MAX_ATTRS:
        raise ValueError(f"at most {_MAX_ATTRS} reply attributes")
    out: dict[str, Any] = {}
    for name, value in raw.items():
        if not isinstance(name, str) or not _NAME.match(name):
            raise ValueError(f"invalid attribute name {name!r}")
        lowered = name.lower()
        if lowered in _FORBIDDEN or lowered.startswith(_FORBIDDEN_PREFIXES):
            raise ValueError(f"{name} cannot be set by a policy")
        if isinstance(value, list):
            if not 1 <= len(value) <= _MAX_VALUES:
                raise ValueError(f"{name}: 1-{_MAX_VALUES} values")
            out[name] = [_check_value(name, v) for v in value]
        else:
            out[name] = _check_value(name, value)
    return out
