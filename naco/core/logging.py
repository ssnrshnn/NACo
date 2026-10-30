"""Logging setup.

* Everything goes to stdout (``docker compose logs``), as text or JSON.
* ``RedactionFilter`` sits on every *handler*, so it also covers records that
  propagate up from child loggers (a filter on the root logger would not).
* The ``naco.trail`` logger carries the security trail — authentication
  decisions, TACACS+ events, audit entries — and is additionally forwarded to
  syslog (RFC 5424) when configured.
"""
from __future__ import annotations

import json
import logging
import logging.handlers
import re
import socket
import sys
from datetime import UTC, datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from naco.config import SyslogConfig

TRAIL_LOGGER = "naco.trail"

_REDACTIONS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]+"), r"\1 ***"),
    (re.compile(r"\bnaco_[A-Za-z0-9_-]{8,}"), "naco_***"),
    (re.compile(
        r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|key|authorization|totp[_-]?code)"
        r"([\"']?\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|[^\s,;&}]+)"
    ), r"\1\2***"),
)


def redact(text: str) -> str:
    for pattern, repl in _REDACTIONS:
        text = pattern.sub(repl, text)
    return text


class RedactionFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # malformed %-args: keep the raw template
            message = str(record.msg)
        record.msg = redact(message)
        record.args = None
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        doc = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            doc["exc"] = self.formatException(record.exc_info)
        return json.dumps(doc, ensure_ascii=False)


class Rfc5424Formatter(logging.Formatter):
    """Body after the ``<PRI>`` that SysLogHandler prepends."""

    def __init__(self) -> None:
        super().__init__()
        self._host = socket.gethostname() or "-"

    def format(self, record: logging.LogRecord) -> str:
        ts = datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds")
        return f"1 {ts} {self._host} naco - - - {record.getMessage()}"


_TEXT_FORMAT = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"


def _syslog_handler(cfg: SyslogConfig) -> logging.Handler | None:
    socktype = socket.SOCK_DGRAM if cfg.protocol == "udp" else socket.SOCK_STREAM
    try:
        handler = logging.handlers.SysLogHandler(
            address=(cfg.host, cfg.port),
            facility=logging.handlers.SysLogHandler.facility_names.get(cfg.facility, 16),
            socktype=socktype,
        )
    except OSError as exc:
        logging.getLogger(__name__).warning("syslog %s:%d unreachable (%s) — forwarding disabled",
                                            cfg.host, cfg.port, exc)
        return None
    handler.append_nul = cfg.protocol == "udp"
    handler.setFormatter(Rfc5424Formatter())
    return handler


def setup_logging(level: str = "INFO", fmt: str = "text", syslog: SyslogConfig | None = None) -> None:
    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)
        h.close()
    root.setLevel(level)

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(JsonFormatter() if fmt == "json" else logging.Formatter(_TEXT_FORMAT))
    console.addFilter(RedactionFilter())
    root.addHandler(console)

    trail = logging.getLogger(TRAIL_LOGGER)
    for h in list(trail.handlers):
        trail.removeHandler(h)
        h.close()
    if syslog is not None and syslog.enabled:
        handler = _syslog_handler(syslog)
        if handler is not None:
            handler.addFilter(RedactionFilter())
            trail.addHandler(handler)

    # Quiet chatty libraries; uvicorn's access log is replaced by our own.
    for name in ("uvicorn.access", "aiosqlite", "sqlalchemy.engine"):
        logging.getLogger(name).setLevel(logging.WARNING)


def trail() -> logging.Logger:
    return logging.getLogger(TRAIL_LOGGER)
