#!/usr/bin/env python3
"""Refresh naco/data/radius-attributes.txt.gz from FreeRADIUS' dictionaries.

Policies may only name attributes FreeRADIUS knows — it silently drops the
rest — so NACo checks names against the dictionaries of the FreeRADIUS image
it ships with. Run after changing the FROM line in deploy/freeradius/Dockerfile:

    python3 scripts/update-radius-dictionary.py      (needs Docker)

Output: one "Name<TAB>type" line per attribute, as FreeRADIUS spells it.
"""
from __future__ import annotations

import gzip
import io
import re
import subprocess
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "naco" / "data" / "radius-attributes.txt.gz"
LOCAL = ROOT / "deploy" / "freeradius" / "raddb" / "dictionary"


def image() -> str:
    text = (ROOT / "deploy" / "freeradius" / "Dockerfile").read_text()
    match = re.search(r"^FROM\s+(\S+)", text, re.MULTILINE)
    if not match:
        raise SystemExit("no FROM line in deploy/freeradius/Dockerfile")
    return match.group(1)


def read_share(img: str) -> dict[str, str]:
    raw = subprocess.run(["docker", "run", "--rm", "--entrypoint", "tar", img,  # noqa: S603, S607
                          "-C", "/opt/share/freeradius", "-cf", "-", "."],
                         check=True, capture_output=True).stdout
    files: dict[str, str] = {}
    with tarfile.open(fileobj=io.BytesIO(raw)) as tar:
        for member in tar.getmembers():
            handle = tar.extractfile(member) if member.isfile() else None
            if handle is not None:
                files[Path(member.name).name] = handle.read().decode("utf-8", errors="replace")
    return files


def attributes(files: dict[str, str], name: str, seen: set[str]) -> dict[str, str]:
    """Follow $INCLUDE from ``name`` exactly as FreeRADIUS does."""
    if name in seen or name not in files:
        return {}
    seen.add(name)
    out: dict[str, str] = {}
    for line in files[name].splitlines():
        fields = line.split("#", 1)[0].split()
        if not fields:
            continue
        if fields[0] == "$INCLUDE" and len(fields) > 1:
            out.update(attributes(files, Path(fields[1]).name, seen))
        elif fields[0] == "ATTRIBUTE" and len(fields) >= 4:
            out[fields[1]] = fields[3]
    return out


def main() -> int:
    img = image()
    files = read_share(img)
    found = attributes(files, "dictionary", set())
    files["local"] = LOCAL.read_text()
    found.update(attributes(files, "local", set()))
    if len(found) < 5000:
        print(f"only {len(found)} attributes found in {img} — refusing to write", file=sys.stderr)
        return 1
    body = "".join(f"{n}\t{t}\n" for n, t in sorted(found.items(), key=lambda item: item[0].lower()))
    OUT.write_bytes(gzip.compress(body.encode(), mtime=0))
    print(f"{len(found)} attributes from {img} → {OUT.relative_to(ROOT)} ({OUT.stat().st_size // 1024} KiB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
