"""CSP regression guard: templates must not use inline event handlers.

The admin UI ships a strict nonce-based Content-Security-Policy
(``script-src 'self' 'nonce-…'``). Browsers refuse inline handler
attributes (``onclick=`` etc.) under that policy — the nonce only
whitelists ``<script>`` *blocks*. Every handler must therefore be wired
with ``addEventListener`` / event delegation inside a nonce'd script.

This test failed for 13 templates when the bug was found (all buttons
silently dead); it keeps anyone from re-introducing an inline handler.
"""
from __future__ import annotations

import re
from pathlib import Path

import naco

TEMPLATE_DIRS = [
    Path(naco.__file__).parent / "web" / "templates",
    Path(naco.__file__).parent / "portal" / "templates",
]

# Any on<event>= attribute in an HTML tag (also catches handlers embedded
# in JS template literals used with innerHTML — same CSP restriction).
_INLINE_HANDLER = re.compile(r"\son[a-z]+\s*=\s*[\"'`]", re.IGNORECASE)


def test_templates_have_no_inline_event_handlers():
    offenders: list[str] = []
    for tdir in TEMPLATE_DIRS:
        for tpl in sorted(tdir.glob("*.html")):
            for lineno, line in enumerate(tpl.read_text().splitlines(), 1):
                if _INLINE_HANDLER.search(line):
                    offenders.append(f"{tpl.name}:{lineno}: {line.strip()[:100]}")
    assert not offenders, (
        "Inline event handlers are blocked by the nonce-based CSP "
        "(script-src has no 'unsafe-inline'). Use addEventListener inside "
        "a nonce'd <script> block instead:\n" + "\n".join(offenders)
    )
