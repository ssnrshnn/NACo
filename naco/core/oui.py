"""MAC vendor lookup from the bundled IEEE MA-L registry (scripts/update-oui.py)."""
from __future__ import annotations

import gzip
from functools import lru_cache
from importlib import resources

from naco.core.netutils import is_randomized_mac, normalize_mac


@lru_cache(maxsize=1)
def _table() -> dict[str, str]:
    data = resources.files("naco").joinpath("data/oui.csv.gz").read_bytes()
    table: dict[str, str] = {}
    for line in gzip.decompress(data).decode("utf-8").splitlines():
        prefix, _, name = line.partition(",")
        if prefix:
            table[prefix] = name
    return table


def vendor_for(mac: str) -> str:
    """Organisation name for ``mac``'s OUI; "" when unknown or randomised."""
    norm = normalize_mac(mac)
    if norm is None or is_randomized_mac(norm):
        return ""
    return _table().get(norm.replace(":", "")[:6].upper(), "")
