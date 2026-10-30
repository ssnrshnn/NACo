#!/usr/bin/env python3
"""Refresh naco/data/oui.csv.gz from the IEEE MA-L registry.

Output format: one "AABBCC,Organization Name" line per assignment, sorted.
Run before a release:  python3 scripts/update-oui.py
"""
from __future__ import annotations

import csv
import gzip
import io
import sys
import urllib.request
from pathlib import Path

URL = "https://standards-oui.ieee.org/oui/oui.csv"
OUT = Path(__file__).resolve().parent.parent / "naco" / "data" / "oui.csv.gz"


def main() -> int:
    req = urllib.request.Request(URL, headers={"User-Agent": "naco-oui-updater"})
    with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310 — fixed https URL
        text = resp.read().decode("utf-8", errors="replace")
    rows = {}
    for row in csv.DictReader(io.StringIO(text)):
        prefix = (row.get("Assignment") or "").strip().upper()
        name = " ".join((row.get("Organization Name") or "").split())
        if len(prefix) == 6 and name:
            rows[prefix] = name.replace(",", " ")
    if len(rows) < 10000:
        print(f"refusing to write: only {len(rows)} entries parsed", file=sys.stderr)
        return 1
    OUT.parent.mkdir(parents=True, exist_ok=True)
    body = "".join(f"{k},{v}\n" for k, v in sorted(rows.items())).encode()
    OUT.write_bytes(gzip.compress(body, compresslevel=9, mtime=0))
    print(f"wrote {len(rows)} entries to {OUT} ({OUT.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
