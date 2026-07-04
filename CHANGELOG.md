# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Encrypted secrets at rest** — NAS shared secrets, TACACS+ keys, and
  admin TOTP seeds are now encrypted with AES-256-GCM before hitting the
  database (`enc:v1:` envelope, new `EncryptedString` column type). The
  master key comes from `NACO_MASTER_KEY` (base64 or hex, 32 bytes) or a
  `NACO_MASTER_KEY_FILE` mount; `quickstart.sh` generates one on fresh
  installs and adds one on upgrades. Reads accept both encrypted and
  legacy plaintext values, so enabling encryption is zero-downtime:
  rows encrypt on next write, or all at once with
  `nacoctl encrypt-secrets` (idempotent). `nacoctl rotate-master-key`
  re-encrypts everything under a new key (`NACO_MASTER_KEY_OLD` → new
  `NACO_MASTER_KEY`). Migration `0007` widens the affected columns.
  Without a key configured behaviour is unchanged (plaintext, with a
  startup warning).

- **Placeholder-secret startup guard** — with `server.debug: false`
  (the default), NACo now refuses to boot while
  `session_secret`/`api_secret`/`csrf_secret`/`admin_password`, the
  TACACS+ key, or any RADIUS/TACACS client secret still carries a
  placeholder default. `nacoctl check-config` reports the same findings
  as warnings.
- **Encrypted backups** — `nacoctl backup --age-recipient <age1…|ssh-pub>`
  (repeatable) encrypts the snapshot with
  [age](https://age-encryption.org);
  `nacoctl restore --age-identity <keyfile>` decrypts transparently.
  The `age` binary ships in the container image.

### Fixed

- `nacoctl backup` was broken against the default compose stack: the
  image shipped bookworm's `pg_dump` 15, which aborts on the
  `postgres:16` service ("server version mismatch"). The image now
  installs `postgresql-client-16` from PGDG.
- README documented `nacoctl backup --out/--in`; real options are
  `--output`/`--input`.
- `nacoctl db-upgrade` failed inside the official container: it only
  looked for `alembic.ini` next to a source checkout, and Alembic's
  online mode required a synchronous DB driver (psycopg2) that the
  image doesn't ship. The command now also finds `/app/alembic.ini`
  and falls back to the app's async drivers (asyncpg / aiosqlite).
- `docker-compose.yml` default image tag pointed at the never-published
  `:2.0.0`; now `:latest`.

## [2.1.0] — 2026-07-04

### Added

- **Multi-vendor reply attributes** — policies can attach standard or
  vendor-specific RADIUS attributes (`reply_attributes` JSON column,
  migration `0006`) to the Access-Accept: `Aruba-User-Role`,
  `Cisco-AVPair`, `Mikrotik-Rate-Limit`, WISPr bandwidth caps, and more.
  Exposed in the policy API and the *Policies* UI; also honoured on the
  FreeRADIUS EAP path via `rlm_rest`.
- Bundled RADIUS dictionary now ships VSA definitions for Cisco, Aruba,
  HPE, Juniper, Fortinet, MikroTik, Ruckus, Extreme, Huawei, Palo Alto,
  Arista, and WISPr.
- `docs/VENDORS.md` — per-vendor NAS configuration guide (802.1X/MAB,
  dynamic VLAN, CoA, TACACS+).
- Admin UI branding: NACo logo as favicon, sidebar brand, and login mark.
- **One-line install** — `curl -fsSL …/install.sh | bash` clones and
  boots the stack. `quickstart.sh` gained preflight checks (Docker
  daemon, Compose v2, openssl, port-conflict warnings), pulls the
  prebuilt GHCR image instead of building locally (build remains the
  offline fallback), and waits for the health endpoint before printing
  the endpoints.
- **Published container images** — new `release.yml` workflow pushes
  multi-arch (amd64 + arm64) images to `ghcr.io/ssnrshnn/naco` on every
  main push (`:latest`) and version tag (`:X.Y.Z`, `:X.Y`, `:X`).
- **802.1X out of the box** — the FreeRADIUS EAP sidecar is now part of
  the default stack (`COMPOSE_PROFILES=eap`; opt out with
  `./quickstart.sh --no-eap`). It listens on 2812/2813 next to NACo's
  built-in 1812/1813, and `quickstart.sh` auto-generates the bearer
  token plus a self-signed CA/server certificate. Supported methods:
  EAP-TTLS+PAP, PEAP+GTC, EAP-TLS (PEAP-MSCHAPv2 excluded — the bcrypt
  store cannot serve NT hashes). Setting `NACO_EAP_BEARER_TOKEN`
  auto-enables the `/api/v1/eap/*` endpoints.

### Fixed — FreeRADIUS sidecar could never boot

- The whole-directory `raddb` mount hid the image's `radiusd.conf`;
  config files now overlay-mount individually onto the stock config.
- `${VAR}` was used where FreeRADIUS requires `$ENV{VAR}` (bearer
  token, REST URL, NAS shared secret).
- The referenced image tag `3.2-alpine` does not exist on Docker Hub
  (now pinned to `3.2.10-alpine`).
- FreeRADIUS and NACo both claimed UDP 1812/1813 under host
  networking; the sidecar now listens on 2812/2813. Configuration
  verified with `radiusd -XC` in the container.
- The bearer token was configured via a `headers { }` block that
  rlm_rest 3.x silently ignores (every REST call to NACo got 401);
  the token is now injected per call with
  `update control { &REST-HTTP-Header += … }` — verified live
  (FreeRADIUS → `/api/v1/eap/authorize` → 200).

### Added

- **NAS client REST API** — `GET/POST/PUT/DELETE /api/v1/nas` (secrets
  are write-only, never returned). The README example finally matches
  reality; changes are hot-reloaded by the RADIUS server within 30 s.
- **Manual device registration** — `POST /api/v1/devices` plus an
  *Add Device* button on the Devices page, so a MAC can be
  pre-authorized for MAB without waiting for the passive profiler to
  discover it. New devices still default to Blocked.
- Login page and sidebar now use a transparent circular emblem
  extracted from the logo (no more solid square tile); favicon updated
  to match.

### Fixed

- **Every inline button in the admin UI was dead under the nonce-based
  CSP.** The Phase 1 CSP (`script-src 'self' 'nonce-…'`, no
  `'unsafe-inline'`) makes browsers refuse inline `onclick=`/`onchange=`/
  `onsubmit=` attributes — the nonce only whitelists `<script>` blocks.
  27 handlers across 13 templates were silently broken (Add Condition /
  Attribute / Rule, deletes, device toggles, secret reveals, delete
  confirmations). All handlers are now wired via a CSP-safe delegation
  layer in `base.html` (`data-action` dispatch, `data-confirm` form
  guard); a regression test bans inline handlers in templates.
- **Profiler could never sniff in the official container.** The image
  runs as uid 10001 and `cap_add: NET_RAW` grants the capability to
  the bounding set only — a non-root process cannot open raw sockets
  unless the binary carries file capabilities. The Dockerfile now
  `setcap cap_net_raw+eip` on the Python binary. The profiler also
  stops retrying (with an actionable message) after repeated
  permission errors instead of error-looping forever.
- **First NAS added via the UI was never picked up.** The 30 s NAS
  hot-reload only ran inside `HandleAuthPacket`, but pyrad drops
  packets from unknown hosts *before* that handler — so on a fresh
  install (zero known clients) the reload could never fire and every
  request was dropped until restart. A background refresh task now
  reloads DB clients every 30 s regardless of traffic.

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

### Changed — single-file deployment

- **One `docker-compose.yml`, at the repository root.** The four-file
  layout (`deploy/docker-compose.yml` + `.eap.yml` + `.obs.yml` +
  `docker-compose.local.yml`) is consolidated into a single file using
  compose profiles: `docker compose up -d` starts the core stack;
  `--profile eap` adds FreeRADIUS; `--profile obs` adds
  Prometheus/Grafana/Loki/Promtail. Profiles can be pinned via
  `COMPOSE_PROFILES` in `.env`. The only remaining extra file is the
  contributor-only `deploy/docker-compose.dev.yml` override.
- **`./quickstart.sh`** — one-command bootstrap: generates `.env` with
  strong random secrets (never overwrites an existing one), starts the
  stack, prints the admin password and endpoints.
- **`config/config.yaml` is now tracked** with production-sane defaults.
  Previously the compose stack mounted `./config` but the file was
  untracked — a fresh `git clone && docker compose up` crashed with
  `FileNotFoundError` on `/etc/naco/config.yaml`.
- **Fixed: core stack could not reach Postgres/Redis.** The `naco`
  service uses host networking and dials `127.0.0.1:5432/6379`, but the
  compose file never published those ports; they are now bound to the
  host loopback only (`127.0.0.1:5432:5432`, `127.0.0.1:6379:6379`).
- **Removed dead legacy config shims** (`_LegacyWebView`,
  `_LegacyApiView`, `cfg.web`, `cfg.api`, `server.secret_key`) — zero
  remaining call sites.

### Added — Phase 2 correctness & scale

- **Captive-portal guest sessions now grant MAB access.** The RADIUS
  MAB path consults `guest_sessions`: a MAC with a live, unexpired
  registration is accepted and lands on the guest VLAN via the new
  `GUEST_SESSION` fallthrough (an explicit DENY policy still wins).
  Previously the documented portal flow was not wired to RADIUS at
  all — registered guests were rejected with "Unknown MAC".
- **Accounting Gigawords support** — `Acct-Input/Output-Gigawords`
  (RFC 2869) are combined with the 32-bit octet counters, and
  `active_sessions.bytes_in/out` widened to `BigInteger`
  (migration `0005_bigint_counters`). Sessions over 4 GiB no longer
  misreport / overflow.
- **Interim-Update session recovery** — an Interim-Update for an
  unknown session (NACo restarted, Start packet lost) now recreates
  the `ActiveSession` row instead of being dropped.
- Regression tests: guest-session expiry, guest-MAB linkage,
  Gigawords parsing (`tests/test_guest_sessions.py`).

### Fixed — Phase 2 correctness & scale

- **Guest sessions never expired.** Four SQLAlchemy filters used
  Python identity (`GuestSession.active is True`), which evaluates to
  a constant `False` instead of a SQL predicate — the expiry sweep,
  portal `/status`, portal re-registration, and the dashboard guest
  counter all silently matched nothing.
- **bcrypt no longer blocks the event loop.** All async
  authentication paths (RADIUS PAP, TACACS+ ASCII/PAP, EAP REST hook,
  REST `/auth/login`, Web UI login, admin password change) now verify
  through `asyncio.to_thread`. A single bcrypt at cost 13 costs
  300–500 ms of CPU; running it inline froze the admin UI, portal,
  and every other in-flight connection per authentication and capped
  throughput at ~2–3 auth/s.
- **RADIUS PAP unknown-user path** now spends the constant-time
  `dummy_verify` cycle like every other auth surface (username
  enumeration hardening).
- **NAS client hot-reload** picks up secret *changes* and removes
  deleted/disabled clients (previously only additions were applied;
  a rotated secret or revoked NAS stayed live until restart).
- `reset_all()` in the rate limiter no longer leaves an unawaited
  coroutine when called inside a running event loop.

### Changed

- **`StrEnum` migration** — all model enums (`AuthMethod`,
  `PolicyAction`, `AdminRole`, …) now inherit `enum.StrEnum`
  (Python 3.11+): `str(AuthMethod.PAP)` is `"PAP"` instead of
  `"AuthMethod.PAP"`, which removes a class of log/JSON formatting
  surprises. Stored DB values are unchanged.
- **Ruff-clean tree** — `ruff check naco tests` passes with the
  configured rule set (E712 truthiness filters, unused imports,
  StrEnum, unpacked-variable hygiene).
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

## [2.0.0] — 2026-05-12

NACo 2.0.0 is a **clean break** from the now-archived
[RaspISE](https://github.com/ssnrshnn/raspise) project. The codebase,
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

[Unreleased]: https://github.com/ssnrshnn/naco/compare/v2.1.0...HEAD
[2.1.0]: https://github.com/ssnrshnn/naco/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/ssnrshnn/naco/releases/tag/v2.0.0
