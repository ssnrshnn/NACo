"""
NACo Logging
===============
Structured logging with optional forwarding to:

  1. Console (stdout)  — always on
  2. File              — /var/log/naco/naco.log  (configurable)
  3. Syslog            — local Unix socket (/dev/log) OR remote UDP/TCP syslog
  4. Graylog / GELF    — UDP or TCP to a Graylog server (standard port 12201)
  5. Webhook           — HTTP POST batches of JSON log records to any URL
                         (works with Slack incoming webhooks, Loki push API,
                          custom SIEM endpoints, n8n, etc.)

All forwarding targets are configured under log_forwarding: in config.yaml
and can be toggled live from the Web UI (Settings → Log Forwarding tab).
After saving, call setup_logging() again to re-apply handlers.
"""
from __future__ import annotations

import json
import logging
import logging.handlers
import queue
import socket
import sys
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from naco.config import AppConfig

# Module-level queue + worker used by the async webhook handler
_webhook_queue: queue.Queue[logging.LogRecord] = queue.Queue(maxsize=2000)
_webhook_worker_started = False


# ---------------------------------------------------------------------------
# Secret-redaction filter — runs on every log record before it hits any
# handler. Designed to be defence-in-depth: callers should not be logging
# secrets in the first place, but if they do (e.g. an unhandled exception
# from urllib3 with a `Authorization: Bearer <token>` line, or a misconfigured
# debug ``log.info("auth body: %s", body)``), the filter scrubs the obvious
# patterns. The regex set is intentionally narrow — we'd rather miss some
# obscure leak than blanket-redact half the message and lose forensic value.
# ---------------------------------------------------------------------------

import re as _re

_SECRET_PATTERNS: tuple[tuple[_re.Pattern[str], str], ...] = (
    # Bearer tokens (RFC 6750) — `Authorization: Bearer abc123` and bare
    # `Bearer abc123` strings that some libraries log directly.
    (_re.compile(r"(?i)(authorization\s*[:=]\s*)(bearer\s+)([A-Za-z0-9._\-+/=]{6,})"),
     r"\1\2***REDACTED***"),
    (_re.compile(r"(?i)\b(bearer\s+)([A-Za-z0-9._\-+/=]{16,})"),
     r"\1***REDACTED***"),
    # `password=`, `password: ` (case-insensitive). Allow alphanumerics and
    # common punctuation in the value; stop at whitespace, quotes, commas.
    (_re.compile(r"(?i)\b(password\s*[:=]\s*['\"]?)([^\s'\"&,)}]+)"),
     r"\1***REDACTED***"),
    # `secret=`, `secret: ` — RADIUS / TACACS shared secrets, API secrets.
    (_re.compile(r"(?i)\b(secret\s*[:=]\s*['\"]?)([^\s'\"&,)}]+)"),
     r"\1***REDACTED***"),
    # `api_key=` / `api-key=` / `apikey=` / `key=` when preceded by api/auth.
    (_re.compile(r"(?i)\b((?:api[_-]?|auth[_-]?)key\s*[:=]\s*['\"]?)([^\s'\"&,)}]+)"),
     r"\1***REDACTED***"),
    # `bind_password=` / `bindPassword:` — LDAP service-account credential.
    (_re.compile(r"(?i)\b(bind[_-]?password\s*[:=]\s*['\"]?)([^\s'\"&,)}]+)"),
     r"\1***REDACTED***"),
    # `totp_secret=` / `pending_totp_secret=` — TOTP provisioning secrets.
    (_re.compile(r"(?i)\b(totp[_-]?secret\s*[:=]\s*['\"]?)([A-Z2-7]{16,})"),
     r"\1***REDACTED***"),
    (_re.compile(r"(?i)\b(pending[_-]?totp[_-]?secret\s*[:=]\s*['\"]?)([A-Z2-7]{16,})"),
     r"\1***REDACTED***"),
    # JWT tokens — three dot-separated base64url segments, ~10+ chars each.
    # Match conservatively (start-of-token marker is hard to nail without
    # false positives). We require the header to begin with `eyJ` (decoded
    # `{"`) which is universal for HS256/RS256 JWTs.
    (_re.compile(r"\b(eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,})"),
     r"***REDACTED_JWT***"),
)


class SecretRedactionFilter(logging.Filter):
    """``logging.Filter`` that scrubs known secret patterns from log records.

    Applied to the root logger by :func:`setup_logging`, so every handler
    (console, file, syslog, Graylog, webhook) gets a redacted copy. The
    redaction edits :pyattr:`logging.LogRecord.msg` in place *after* the
    record has been formatted (`record.getMessage()`) so format-string
    arguments are interpolated before we scrub.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            text = record.getMessage()
        except Exception:
            # If formatting itself fails we let the record through unchanged —
            # otherwise we'd silently swallow logs because of a buggy format string.
            return True

        original = text
        for pattern, replacement in _SECRET_PATTERNS:
            text = pattern.sub(replacement, text)

        if text != original:
            # ``msg`` is what handlers ultimately format; clearing ``args``
            # ensures we don't re-interpolate the now-redacted string with
            # the raw arguments (which may still contain the secret).
            record.msg = text
            record.args = None

        return True


# ---------------------------------------------------------------------------
# GELF Handler  (Graylog Extended Log Format — RFC-compatible)
# ---------------------------------------------------------------------------

class GELFHandler(logging.Handler):
    """
    Sends log records as GELF JSON to a Graylog server via UDP or TCP.

    GELF spec: https://docs.graylog.org/docs/gelf
    """
    _LEVEL_MAP = {
        logging.DEBUG:    7,
        logging.INFO:     6,
        logging.WARNING:  4,
        logging.ERROR:    3,
        logging.CRITICAL: 2,
    }

    def __init__(self, host: str, port: int, protocol: str = "udp") -> None:
        super().__init__()
        self._host = host
        self._port = port
        self._udp = protocol.lower() != "tcp"
        self._lock = threading.Lock()
        self._sock: socket.socket | None = None
        self._connect()

    def _connect(self) -> None:
        try:
            if self._udp:
                self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            else:
                self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._sock.settimeout(3)
                self._sock.connect((self._host, self._port))
        except OSError as exc:
            self._sock = None
            self._fallback_warning(f"GELF connect failed: {exc}")

    def _fallback_warning(self, msg: str) -> None:
        sys.stderr.write(f"[NACo/GELF] {msg}\n")

    def emit(self, record: logging.LogRecord) -> None:
        try:
            payload = {
                "version":       "1.1",
                "host":          socket.gethostname(),
                "short_message": record.getMessage(),
                "timestamp":     record.created,
                "level":         self._LEVEL_MAP.get(record.levelno, 6),
                "_logger":       record.name,
                "_level_name":   record.levelname,
                "_pid":          record.process,
                "_thread":       record.thread,
            }
            if record.exc_info:
                payload["full_message"] = logging.Formatter().formatException(record.exc_info)

            raw = json.dumps(payload).encode("utf-8")

            with self._lock:
                if self._sock is None:
                    self._connect()
                if self._sock is None:
                    return
                if self._udp:
                    self._sock.sendto(raw, (self._host, self._port))
                else:
                    # GELF TCP requires a null-byte terminator
                    self._sock.sendall(raw + b"\x00")
        except Exception as exc:
            self._fallback_warning(f"emit failed: {exc}")
            with self._lock:
                try:
                    if self._sock is not None:
                        self._sock.close()
                except Exception:
                    pass
                self._sock = None

    def close(self) -> None:
        with self._lock:
            try:
                if self._sock is not None:
                    self._sock.close()
            except Exception:
                pass
        super().close()


# ---------------------------------------------------------------------------
# Webhook Handler (async batching)
# ---------------------------------------------------------------------------

class WebhookHandler(logging.Handler):
    """
    Queues log records and POSTs them in batches to an HTTP/HTTPS endpoint.

    Payload format:
        POST <url>
        Content-Type: application/json
        {
            "source": "NACo",
            "host": "<hostname>",
            "records": [
                {
                    "timestamp": "2026-04-02T10:30:00Z",
                    "level":     "WARNING",
                    "logger":    "naco.radius.server",
                    "message":   "Auth failed for user alice",
                    "pid":       1234
                },
                ...
            ]
        }

    Compatible with:
      - Slack incoming webhooks  (wrap `records[0].message` in Slack block format
        using a proxy / n8n workflow)
      - Grafana Loki push API    (add `Content-Type: application/json` header)
      - Custom SIEM / alerting endpoints
      - n8n, Zapier, Make webhooks
    """

    def __init__(
        self,
        url: str,
        level: int,
        timeout: float,
        headers: dict[str, str],
        batch_size: int,
        batch_interval: float,
    ) -> None:
        super().__init__(level)
        self._url = url
        self._timeout = timeout
        self._headers = {"Content-Type": "application/json", **headers}
        self._batch_size = batch_size
        self._batch_interval = batch_interval
        self._q = _webhook_queue
        self._start_worker()

    def _start_worker(self) -> None:
        global _webhook_worker_started
        if _webhook_worker_started:
            return
        _webhook_worker_started = True
        t = threading.Thread(
            target=self._worker_loop,
            name="naco-webhook-log",
            daemon=True,
        )
        t.start()

    def _worker_loop(self) -> None:
        import urllib.error
        import urllib.request

        hostname = socket.gethostname()
        batch: list[logging.LogRecord] = []
        last_flush = time.monotonic()
        consecutive_failures = 0
        _MAX_BACKOFF = 300  # cap at 5 minutes

        while True:
            # Drain up to batch_size records, waiting at most batch_interval
            try:
                timeout = max(0.1, self._batch_interval - (time.monotonic() - last_flush))
                record = self._q.get(timeout=timeout)
                batch.append(record)
                # drain any additional records already in the queue
                while len(batch) < self._batch_size:
                    try:
                        batch.append(self._q.get_nowait())
                    except queue.Empty:
                        break
            except queue.Empty:
                pass

            elapsed = time.monotonic() - last_flush
            # Exponential backoff: wait longer between retries on repeated failures
            backoff_delay = min(self._batch_interval * (2 ** consecutive_failures), _MAX_BACKOFF)
            if batch and (len(batch) >= self._batch_size or elapsed >= backoff_delay):
                payload = json.dumps({
                    "source":  "NACo",
                    "host":    hostname,
                    "records": [
                        {
                            "timestamp": datetime.fromtimestamp(r.created, UTC)
                                         .strftime("%Y-%m-%dT%H:%M:%SZ"),
                            "level":     r.levelname,
                            "logger":    r.name,
                            "message":   r.getMessage(),
                            "pid":       r.process,
                        }
                        for r in batch
                    ],
                }).encode("utf-8")

                req = urllib.request.Request(
                    self._url,
                    data=payload,
                    headers=self._headers,
                    method="POST",
                )
                try:
                    with urllib.request.urlopen(req, timeout=self._timeout):
                        pass
                    consecutive_failures = 0  # reset on success
                except Exception as exc:
                    consecutive_failures = min(consecutive_failures + 1, 8)
                    sys.stderr.write(f"[NACo/Webhook] POST failed (attempt {consecutive_failures}): {exc}\n")

                batch.clear()
                last_flush = time.monotonic()

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self._q.put_nowait(record)
        except queue.Full:
            pass  # drop silently to avoid blocking the callers


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_SYSLOG_FACILITIES = {
    "kern": 0, "user": 1, "mail": 2, "daemon": 3, "auth": 4,
    "syslog": 5, "lpr": 6, "news": 7, "uucp": 8, "cron": 9,
    "local0": 16, "local1": 17, "local2": 18, "local3": 19,
    "local4": 20, "local5": 21, "local6": 22, "local7": 23,
}


def _remove_handlers(root: logging.Logger) -> None:
    """Remove all non-propagated handlers so we can re-apply them cleanly."""
    for h in root.handlers[:]:
        try:
            h.close()
        except Exception:
            pass
        root.removeHandler(h)


_record_factory_installed = False


def _install_request_id_record_factory() -> None:
    """Ensure every log record — from any logger — carries ``request_id``.

    A record factory (unlike a logger-level filter) also covers records
    emitted by third-party loggers such as ``sqlalchemy.engine`` and
    ``uvicorn.*`` that propagate to the root handlers. Idempotent.
    """
    global _record_factory_installed
    if _record_factory_installed:
        return
    _record_factory_installed = True

    from naco.core.request_id import get_request_id

    old_factory = logging.getLogRecordFactory()

    def _factory(*args, **kwargs):
        record = old_factory(*args, **kwargs)
        if not hasattr(record, "request_id"):
            try:
                record.request_id = get_request_id() or "-"
            except Exception:
                record.request_id = "-"
        return record

    logging.setLogRecordFactory(_factory)


def setup_logging(cfg: AppConfig | None = None) -> logging.Logger:
    """
    Configure all log handlers based on config.

    Can be called multiple times — removes existing handlers first so
    settings changes from the Web UI take effect without restarting.

    Log files written to /var/log/naco/:
      naco.log  — main application log (all namespaces, INFO+)
      auth.log     — RADIUS + TACACS+ events only, JSON-per-line
      access.log   — HTTP access log (uvicorn.access)
    """
    if cfg is None:
        from naco.config import get_config
        cfg = get_config()

    # ``request_id`` is interpolated by every formatter; the record factory
    # installed below splices it onto each record. We render it
    # as ``[rid: <id>]`` only when it isn't the placeholder "-" so log
    # lines emitted during application start-up stay readable.
    fmt = "%(asctime)s [%(levelname)-8s] [%(request_id)s] %(name)s — %(message)s"
    datefmt = "%Y-%m-%d %H:%M:%S"
    formatter = logging.Formatter(fmt, datefmt=datefmt)

    root = logging.getLogger()
    _remove_handlers(root)
    root.setLevel(cfg.server.log_level.upper())

    # Centralised secret-redaction filter — applied to the *root* logger so
    # every handler inherits it. Prevents accidental leakage of bearer
    # tokens, RADIUS shared secrets, passwords, LDAP bind credentials, and
    # API/master keys into logs / syslog / Graylog / webhooks.
    root.addFilter(SecretRedactionFilter())

    # Request-correlation — splice ``record.request_id`` from the
    # ``naco.core.request_id`` contextvar onto every log record so the
    # formatter above can reference ``%(request_id)s``.
    #
    # This must be a log-record *factory*, not a filter on the root logger:
    # logger-level filters do not run for records that merely *propagate* to
    # root from third-party loggers (``sqlalchemy.engine``, ``uvicorn`` …),
    # and any such record used to crash every handler with
    # ``Formatting field not found in record: 'request_id'``.
    _install_request_id_record_factory()

    # ── 1. Console ────────────────────────────────────────────────────────
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(formatter)
    root.addHandler(ch)

    # ── 2. File — main log ────────────────────────────────────────────────
    log_path = Path(cfg.server.log_file)
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        fh = logging.handlers.RotatingFileHandler(
            log_path,
            maxBytes=10 * 1024 * 1024,   # 10 MB per file
            backupCount=5,
            encoding="utf-8",
        )
        fh.setFormatter(formatter)
        root.addHandler(fh)
    except OSError as exc:
        # PermissionError, read-only filesystem (Kubernetes
        # readOnlyRootFilesystem), missing mount — stdout logging stays up.
        root.warning("Cannot write to log file %s (%s) — file logging disabled",
                     log_path, exc)

    # ── 3. File — auth.log (RADIUS + TACACS+ events, JSON per line) ──────
    auth_log_path = log_path.parent / "auth.log"
    ah = _make_rotating(
        auth_log_path,
        max_bytes=10 * 1024 * 1024,
        backup_count=10,            # keep 10 × 10 MB = up to 100 MB of auth history
        formatter=_JsonAuthFormatter(),
        log_filter=_AuthFilter(),
    )
    if ah:
        root.addHandler(ah)

    # ── 4. File — access.log (HTTP requests, uvicorn.access logger) ───────
    access_log_path = log_path.parent / "access.log"
    access_fmt = logging.Formatter(
        '%(asctime)s %(message)s',
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    uvicorn_access = logging.getLogger("uvicorn.access")
    # Remove any existing file handler we previously added to avoid duplicates
    for _h in uvicorn_access.handlers[:]:
        if isinstance(_h, logging.handlers.RotatingFileHandler):
            _h.close()
            uvicorn_access.removeHandler(_h)
    uvicorn_access.propagate = True   # still goes to root / console

    al = _make_rotating(
        access_log_path,
        max_bytes=10 * 1024 * 1024,
        backup_count=5,
        formatter=access_fmt,
    )
    if al:
        # Attach directly to uvicorn.access so only HTTP lines go here
        uvicorn_access.addHandler(al)

    lf = cfg.log_forwarding

    # ── 5. Syslog ─────────────────────────────────────────────────────────
    if lf.syslog.enabled:
        try:
            facility = _SYSLOG_FACILITIES.get(lf.syslog.facility.lower(), 16)
            addr = lf.syslog.address.strip()

            if addr.startswith("/") or addr == "/dev/log":
                # Local Unix domain socket
                sh = logging.handlers.SysLogHandler(
                    address=addr,
                    facility=facility,
                )
            else:
                # Remote syslog: address may be "host:port" or just "host"
                if ":" in addr:
                    host, port_str = addr.rsplit(":", 1)
                    port = int(port_str)
                else:
                    host = addr
                    port = lf.syslog.port

                socktype = (
                    socket.SOCK_STREAM
                    if lf.syslog.protocol.lower() == "tcp"
                    else socket.SOCK_DGRAM
                )
                sh = logging.handlers.SysLogHandler(
                    address=(host, port),
                    facility=facility,
                    socktype=socktype,
                )

            sh.setFormatter(
                logging.Formatter(
                    "naco[%(process)d]: %(levelname)s %(name)s — %(message)s"
                )
            )
            root.addHandler(sh)
            root.info("Syslog forwarding enabled → %s", lf.syslog.address)
        except Exception as exc:
            root.warning("Syslog handler setup failed: %s", exc)

    # ── 6. Graylog / GELF ─────────────────────────────────────────────────
    if lf.graylog.enabled:
        try:
            gh = GELFHandler(
                host=lf.graylog.host,
                port=lf.graylog.port,
                protocol=lf.graylog.protocol,
            )
            root.addHandler(gh)
            root.info(
                "Graylog/GELF forwarding enabled → %s:%d (%s)",
                lf.graylog.host, lf.graylog.port, lf.graylog.protocol.upper(),
            )
        except Exception as exc:
            root.warning("Graylog handler setup failed: %s", exc)

    # ── 7. Webhook ────────────────────────────────────────────────────────
    if lf.webhook.enabled and lf.webhook.url:
        # SSRF guard: refuse to forward logs to an RFC 1918 / cloud-metadata
        # target unless the operator explicitly allowlisted it. A web admin
        # with /settings/save access can otherwise re-point log forwarding at
        # the EC2 / GCP metadata service and exfiltrate IAM credentials.
        try:
            from naco.core.netutils import UrlPolicyError, validate_outbound_url
            validate_outbound_url(lf.webhook.url, allowlist=cfg.security.webhook_allowlist)
        except UrlPolicyError as exc:
            root.warning(
                "Webhook forwarding disabled — URL %s rejected by SSRF policy: %s",
                lf.webhook.url, exc,
            )
        else:
            try:
                level_int = getattr(logging, lf.webhook.level.upper(), logging.WARNING)
                wh = WebhookHandler(
                    url=lf.webhook.url,
                    level=level_int,
                    timeout=lf.webhook.timeout_seconds,
                    headers=lf.webhook.headers,
                    batch_size=lf.webhook.batch_size,
                    batch_interval=lf.webhook.batch_interval_seconds,
                )
                root.addHandler(wh)
                root.info("Webhook forwarding enabled → %s (level: %s)", lf.webhook.url, lf.webhook.level)
            except Exception as exc:
                root.warning("Webhook handler setup failed: %s", exc)

    return root


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)


# ---------------------------------------------------------------------------
# Auth event log  (structured JSON, one record per line)
# ---------------------------------------------------------------------------

class _AuthFilter(logging.Filter):
    """Pass only records from RADIUS / TACACS+ auth namespaces."""
    _PREFIXES = ("naco.radius", "naco.tacacs")

    def filter(self, record: logging.LogRecord) -> bool:
        return any(record.name.startswith(p) for p in self._PREFIXES)


class _JsonAuthFormatter(logging.Formatter):
    """Format each auth-related record as a single JSON line."""

    def format(self, record: logging.LogRecord) -> str:
        return json.dumps({
            "ts":      self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level":   record.levelname,
            "logger":  record.name,
            "msg":     record.getMessage(),
            "pid":     record.process,
        })


def _make_rotating(path: Path, max_bytes: int, backup_count: int,
                   formatter: logging.Formatter,
                   log_filter: logging.Filter | None = None) -> logging.handlers.RotatingFileHandler | None:
    """Create a RotatingFileHandler; return None on permission error."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        h = logging.handlers.RotatingFileHandler(
            path, maxBytes=max_bytes, backupCount=backup_count, encoding="utf-8",
        )
        h.setFormatter(formatter)
        if log_filter:
            h.addFilter(log_filter)
        return h
    except OSError as exc:
        # Permission denied or read-only filesystem — skip file logging.
        sys.stderr.write(f"[NACo] Cannot write to {path} ({exc}) — skipping\n")
        return None


def send_test_log(target: str) -> tuple[bool, str]:
    """
    Fire a test log message to a specific target.
    Returns (success, message).
    Called from the Web UI "Test" button.
    """
    from naco.config import get_config
    cfg = get_config()
    lf = cfg.log_forwarding

    if target == "syslog":
        if not lf.syslog.enabled:
            return False, "Syslog forwarding is not enabled."
        try:
            addr = lf.syslog.address.strip()
            if addr.startswith("/"):
                s = logging.handlers.SysLogHandler(address=addr)
            else:
                host, port = (addr.rsplit(":", 1) if ":" in addr else (addr, str(lf.syslog.port)))
                s = logging.handlers.SysLogHandler(address=(host, int(port)))
            s.emit(logging.makeLogRecord({
                "levelno": logging.INFO,
                "levelname": "INFO",
                "name": "naco.test",
                "msg": "NACo syslog test message",
                "args": (),
                "exc_info": None,
            }))
            s.close()
            return True, f"Test message sent to syslog ({lf.syslog.address})"
        except Exception as exc:
            return False, f"Syslog test failed: {exc}"

    elif target == "graylog":
        if not lf.graylog.enabled:
            return False, "Graylog forwarding is not enabled."
        try:
            gh = GELFHandler(lf.graylog.host, lf.graylog.port, lf.graylog.protocol)
            r = logging.makeLogRecord({
                "levelno": logging.INFO, "levelname": "INFO",
                "name": "naco.test", "msg": "NACo Graylog/GELF test message",
                "args": (), "exc_info": None, "created": time.time(),
                "process": 0, "thread": 0,
            })
            gh.emit(r)
            gh.close()
            return True, f"Test GELF packet sent to {lf.graylog.host}:{lf.graylog.port}"
        except Exception as exc:
            return False, f"Graylog test failed: {exc}"

    elif target == "webhook":
        if not lf.webhook.enabled or not lf.webhook.url:
            return False, "Webhook forwarding is not enabled or URL is empty."
        # SSRF policy gate before opening the connection.
        try:
            from naco.core.netutils import UrlPolicyError, validate_outbound_url
            validate_outbound_url(lf.webhook.url, allowlist=cfg.security.webhook_allowlist)
        except UrlPolicyError as exc:
            return False, f"Webhook URL rejected by SSRF policy: {exc}"
        import urllib.error
        import urllib.request
        payload = json.dumps({
            "source": "NACo",
            "host": socket.gethostname(),
            "records": [{
                "timestamp": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "level": "INFO",
                "logger": "naco.test",
                "message": "NACo webhook test message",
                "pid": 0,
            }],
        }).encode("utf-8")
        headers = {"Content-Type": "application/json", **lf.webhook.headers}
        req = urllib.request.Request(lf.webhook.url, data=payload, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=lf.webhook.timeout_seconds) as resp:
                status = resp.status
            return True, f"Webhook POST → HTTP {status}"
        except urllib.error.HTTPError as exc:
            return False, f"Webhook test failed: HTTP {exc.code} {exc.reason}"
        except Exception as exc:
            return False, f"Webhook test failed: {exc}"

    return False, f"Unknown target: {target}"

