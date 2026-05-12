# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.1] — 2026-05-12

Critical security hot-fixes (Phase 0). Upgrade promptly if you expose
EAP REST hooks, use TOTP enrollment via the API, run `nacoctl backup` on
PostgreSQL, or rely on profiler-discovered devices being implicitly trusted.

### Security

- **EAP `/api/v1/eap/auth`** rejects empty, null, and whitespace-only
  passwords before policy evaluation (previously a mis-sent empty
  password could bypass local password verification).
- **EAP event bus** publishes proper `Event(...)` objects (fixes a
  runtime `TypeError` on auth success/failure).
- **TOTP enrollment** stores the pending shared secret in
  `admin_users.pending_totp_secret` after `POST /auth/totp/setup`.
  `POST /auth/totp/verify` accepts **only** a JSON body `{"code":"…"}`
  — the `secret` query parameter is removed so secrets never appear in
  access logs or Referer headers.
- **`nacoctl backup` / `restore`** pass the PostgreSQL password via
  `PGPASSWORD` and use discrete `-h/-p/-U/-d` arguments instead of
  embedding credentials in the `pg_dump` / `psql` argv (visible in
  `ps` output on Linux).
- **Device inventory** defaults new rows to `authorized=false`
  (profiler-discovered endpoints require explicit operator approval).
  Existing rows are unchanged; Alembic migration `0003_phase0` updates
  the column default for new inserts.

### Added

- Alembic revision `0003_phase0_totp_pending_device_default`.
- Regression tests: `tests/test_eap_auth_bypass.py`,
  `tests/test_totp_setup.py`, `tests/test_cli_backup_secrets.py`,
  `tests/test_device_default_deny.py`.

## [Unreleased]

### Added — Phase 1 security hardening

- **Role-based access control** for admin accounts. Three roles —
  `SUPERUSER`, `OPERATOR`, `VIEWER` — enforced via a new
  `require_role()` FastAPI dependency on every REST endpoint and via
  `_require_role()` on the admin UI. Admin-CRUD, secret rotation, and
  YAML settings are now `SUPERUSER`-only; CRUD of users / groups /
  devices / policies is `OPERATOR`+; GETs are `VIEWER`+.
- **Last-SUPERUSER guard**: the role-change and delete-admin endpoints
  refuse to demote or delete the last enabled `SUPERUSER`, preventing
  operators from locking themselves out of the admin surface.
- **403 page** for browser-facing forbidden responses (HTML for
  browsers, JSON for XHR/API).
- **Per-account lockout** — 10 consecutive failures inside a 5-minute
  window locks a username for 15 minutes regardless of source IP.
  Redis-backed atomic Lua script; in-process fallback for unit tests.
  Cleared on successful login.
- **Atomic rate limiter** — replaces the previous check + INCR race
  with a single `EVAL` Lua script so the IP counter cannot be passed
  by two concurrent attackers.
- **SSRF guard** for outbound webhook and log-forwarding URLs
  (`naco.core.netutils.validate_outbound_url`). Refuses RFC 1918,
  loopback, link-local, multicast, and known cloud-metadata hosts
  (AWS / Azure / GCP / Alibaba / Equinix Metal) unless the operator
  explicitly allowlists a CIDR via `security.webhook_allowlist`.
- **Strict CSP nonce** for the admin UI — `'unsafe-inline'` removed
  from `script-src`. Every inline `<script>` now carries
  `nonce="{{ csp_nonce() }}"`.
- **HSTS** — `Strict-Transport-Security: max-age=31536000;
  includeSubDomains` sent on every HTTPS response.
- **TACACS+ connection caps** — global (default 256) and per-peer
  (default 32) limits configurable via `tacacs.max_connections` /
  `tacacs.max_connections_per_peer`. Prevents a single chatty or
  hostile NAS from exhausting the server.
- **X-Request-ID middleware** mints a correlation UUID per request
  (or honours one supplied by a trusted proxy), echoes it on the
  response, propagates it through a `ContextVar`, and splices it onto
  every log record as `record.request_id`.
- **Centralised log redaction** filter scrubs `password=`, `secret=`,
  `Bearer <token>`, `bind_password=`, `api_key=`, `totp_secret=`, and
  JWT-shaped strings from every log record before it reaches any
  handler.
- `nacoctl rehash-passwords` — audit-mode CLI that surfaces admin
  bcrypt hashes still at a sub-baseline cost factor.
- Phase 1 test coverage: RBAC enforcement, constant-time login,
  account lockout, SSRF policy, log redaction, request-ID
  middleware.

### Changed

- **bcrypt cost factor** bumped from 12 to 13 for new hashes.
  Existing hashes keep working; `verify_password` reads the cost from
  the stored hash. Successful logins opportunistically re-hash any
  sub-baseline password silently (the user sees nothing).
- **Constant-time login** — Web UI, REST API, TACACS+ ASCII / PAP,
  and EAP REST `/auth` now invoke `dummy_verify()` on the
  "user not found" branch so unknown-username response time matches
  known-username-wrong-password. Closes the bcrypt-cost
  enumeration oracle.
- **CSRF middleware** rewritten — replaces the brittle multipart
  regex (which truncated tokens containing `-`) with a proper
  boundary-aware parser plus an ASGI receive-channel replay so
  downstream `Form(...)` handlers still see the body intact.
- **Web admin password change** — cross-account password changes
  now require `SUPERUSER` (was: any authenticated admin); same-account
  changes unchanged.
- **Admin users template** — adds a role badge, role-change modal,
  and CSRF tokens on all forms.

### Security

- See `SECURITY.md` for the updated threat-model matrix covering
  RBAC, lockout, atomic rate limiting, SSRF, secret redaction,
  HSTS / CSP, TACACS+ caps, and request-ID injection.

## [2.0.0] — 2026-05-12

NACo 2.0.0 is a **clean break** from the now-archived
[RaspISE](https://github.com/your-org/raspise) project. The codebase,
schema, configuration layout, container surface, and ops model have all
been redesigned. There is **no upgrade path**; new deployments are the
only supported migration.

### Added

- **Container-native deployment**: production Docker Compose stack with
  PostgreSQL 16, Redis 7, and Caddy as the TLS-terminating reverse
  proxy. Optional profiles for FreeRADIUS (EAP) and the Prometheus /
  Grafana / Loki observability stack.
- **Single FastAPI app**: the admin UI, REST API, and captive portal
  now share one uvicorn process, one lifespan, and one OpenAPI surface
  (`/api/v1/docs`).
- **PostgreSQL as the default database** — async via `asyncpg`. SQLite
  remains supported for local dev.
- **Redis-backed rate limiting** with a sliding-window algorithm.
- **Cookie-based portal CSRF** (HttpOnly, SameSite=Strict). Replaces
  the IP-derived HMAC, which broke through NAT.
- **RFC 3579 Message-Authenticator validation** on every Access-Request
  (CVE-2024-3596 / BlastRADIUS mitigation). Per-NAS opt-out is
  available but disabled by default.
- **RFC 3580 MAB enforcement** — `User-Password` must equal `User-Name`
  must equal the MAC. Compromised NAS devices cannot bypass MAB by
  spraying random passwords.
- **RFC 5176 CoA response-authenticator verification** before any
  side-effect on the session table.
- **Independent secrets for sessions, API JWTs, and CSRF tokens**. A
  leak of one no longer compromises the others.
- **`X-Forwarded-For` support** scoped to `server.trusted_proxies` so
  rate limiting and audit logs reflect the real client when behind
  Caddy or another reverse proxy.
- **Admin-audit-log retention** — 365 days by default, configurable.
- **EAP via FreeRADIUS sidecar** with bearer-token-authenticated
  callbacks under `/api/v1/eap/*`.
- **CI pipeline** (GitHub Actions) covering ruff, mypy, pytest on the
  3.11/3.12 matrix, integration tests with `radclient`, multi-arch
  Docker build, and `pip-audit`.
- **`nacoctl backup` / `restore`** that works on both PostgreSQL
  (`pg_dump` / `psql`) and SQLite (file copy).

### Changed

- The project is renamed from **RaspISE** to **NACo**. Python package,
  CLI binaries, environment variables (`NACO_*`), config schema, and
  container images all use the new name.
- The default RADIUS server is now `pyrad.server.Server` wrapped in an
  executor thread bridged to the asyncio loop. A `run_radius_server_async`
  entry point makes the integration explicit.
- The policy engine starts **default-deny**. The previous
  Default-Permit-All seed has been removed.
- The web admin, REST API, and captive portal share a single host and
  port (`server.host` / `server.port`). The historical three-uvicorn
  layout is gone.
- VLAN attribute parsing uses a proper prefix check and rejects malformed
  values instead of `str(value).lstrip("0x")`, which corrupted values
  like `"x10"` into `"1"`.

### Removed

- **All Raspberry Pi specifics**: the TFT display manager, the
  `raspise-display` systemd service, `spidev` / `RPi.GPIO` / `adafruit-*`
  / `st7789` dependencies, and the `setup_display.sh` installer.
- **`scripts/install.sh` & friends** — replaced by Docker Compose.
- **`systemd/` units** — replaced by container lifecycles.
- **`raspise/radius/eap_tls.py`** — EAP is delegated to FreeRADIUS.
- **The `web` / `api` / `portal` host/port configuration triplet** — a
  single `server.host` / `server.port` replaces it (a compatibility
  shim exposes the legacy attributes for transitional code).
- The build artefact directory `raspise.egg-info/` and a stray 14 MB
  PostScript `sys` file that shouldn't have been in git.

### Security

- BlastRADIUS (CVE-2024-3596) — mitigated by default through
  Message-Authenticator enforcement; opt-out per NAS.
- RADIUS-MAB password bypass — closed by RFC 3580 enforcement.
- CoA spoofing — closed by response-authenticator verification.
- Session-token / API-token escalation — closed by splitting the
  signing secrets.

[Unreleased]: https://github.com/your-org/naco/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/your-org/naco/releases/tag/v2.0.0
