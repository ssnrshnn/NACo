"""Encoding shared with FreeRADIUS' rlm_rest module.

Requests arrive in rlm_rest's JSON format::

    {"User-Name": {"type": "string", "value": ["alice"]}, ...}

Replies use the extended object form with ``do_xlat: false`` so FreeRADIUS
never expands a value (a shared secret or attribute containing ``%{`` stays
literal).
"""
from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any


def loads(body: bytes) -> Any:
    """Parse an rlm_rest body so every string reads the same on every CPU.

    FreeRADIUS 3.2 writes bytes from 0x80 up into the JSON as they are where
    C's char is unsigned (arm64), but as one \\u00XX escape per byte where it
    is signed (x86-64): "ö" arrives as "Ã¶". Raw bytes need not be valid
    UTF-8 (octets attributes), hence surrogateescape. A body with no byte from
    0x80 up holds every such byte escaped, or none at all, so its U+0080 to
    U+00FF characters are those bytes and are decoded here as UTF-8.
    """
    data = json.loads((body or b"{}").decode("utf-8", errors="surrogateescape"))
    return _from_escaped_bytes(data) if body.isascii() else data


def _from_escaped_bytes(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return value.encode("latin-1").decode("utf-8", errors="surrogateescape")
        except UnicodeEncodeError:  # beyond U+00FF: not a byte escape
            return value
    if isinstance(value, list):
        return [_from_escaped_bytes(item) for item in value]
    if isinstance(value, dict):
        return {key: _from_escaped_bytes(item) for key, item in value.items()}
    return value


def _text(value: object) -> str:
    """Text with any undecodable bytes (surrogate-escaped) turned into U+FFFD."""
    text = str(value)
    return text.encode("utf-8", "surrogateescape").decode("utf-8", "replace")


class Attrs:
    def __init__(self, values: dict[str, list[str]]) -> None:
        self._values = {k.lower(): v for k, v in values.items()}

    @classmethod
    def parse(cls, body: Any) -> Attrs:
        if not isinstance(body, dict):
            raise ValueError("request body must be a JSON object")
        values: dict[str, list[str]] = {}
        for name, entry in body.items():
            if not isinstance(name, str):
                raise ValueError("attribute names must be strings")
            if isinstance(entry, dict):
                if entry.get("type") == "octets":
                    continue  # binary protocol attributes: never used, not text
                raw = entry.get("value")
            else:
                raw = entry
            if raw is None:
                continue
            items = raw if isinstance(raw, list) else [raw]
            values[name] = [_text(v) for v in items if v is not None and not isinstance(v, (dict, list))]
        return cls(values)

    @classmethod
    def of(cls, **values: str | int | list[str]) -> Attrs:
        """Build from keyword arguments (tests): ``User_Name="x"`` → ``User-Name``."""
        out: dict[str, list[str]] = {}
        for key, value in values.items():
            out[key.replace("_", "-")] = [str(v) for v in value] if isinstance(value, list) else [str(value)]
        return cls(out)

    def all(self, name: str) -> list[str]:
        return list(self._values.get(name.lower(), []))

    def get(self, name: str) -> str | None:
        found = self._values.get(name.lower())
        return found[0] if found else None

    def int(self, name: str) -> int | None:
        value = self.get(name)
        try:
            return int(value) if value is not None else None
        except ValueError:
            return None


def reply(attrs: Mapping[str, str | int | list[str | int]]) -> dict[str, Any]:
    return {name: {"value": value, "do_xlat": False} for name, value in attrs.items()}


def vlan_attributes(vlan: int) -> dict[str, str]:
    """RFC 3580 dynamic VLAN assignment."""
    return {
        "Tunnel-Type": "VLAN",
        "Tunnel-Medium-Type": "IEEE-802",
        "Tunnel-Private-Group-Id": str(vlan),
    }
