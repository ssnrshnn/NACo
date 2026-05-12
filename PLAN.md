# NACo — Post-2.0.0 Improvement Plan

This is the follow-up plan to the v2.0.0 migration. Work is organised into
**five phases**, ordered by importance. Phase 0 ships as a hot-fix patch
release; everything below is opportunistic and can slip without breaking
anything in production.

Legend:

- **Severity / impact** — `crit` = exploitable now · `high` = real risk
  but mitigated · `med` = bug / DX · `low` = polish
- **Effort** — `S` = < 1 day · `M` = 1-3 days · `L` = 1-2 weeks
- **Release** — which version each phase ships in

Each task is written so it can be checked off independently; a phase is
"done" when every item in it is shipped and tested.

---

## Phase 0 — Critical security hot-fix → v2.0.1 (target: this week)

The goal here is **a same-week patch release**. Nothing in this phase is
optional and nothing else should be bundled with it — keep the diff small
so reviewers can audit it line-by-line.

| # | Task | Sev | Effort | Files |
|---|------|-----|--------|-------|
| 0.1 | Fix EAP `/auth` authentication bypass when password is empty | crit | S | `naco/radius/freeradius_routes.py` |
| 0.2 | Fix `bus.publish(EventType, dict)` runtime crash → use `Event(...)` | crit | S | `naco/radius/freeradius_routes.py` |
| 0.3 | Move TOTP setup secret to a DB column; remove `secret` query param from `/auth/totp/verify` | crit | S | `naco/api/routes.py`, `naco/db/models.py`, alembic migration |
| 0.4 | Stop passing the DB URL with embedded password to `pg_dump` / `psql` argv — use `PGPASSWORD` env | crit | S | `naco/cli.py` |
| 0.5 | Default `Device.authorized=False`; profiler-discovered devices land in a triage queue | crit | S | `naco/db/models.py`, alembic migration, `naco/web/templates/devices.html` |
| 0.6 | Regression tests for each of the above | high | S | `tests/test_eap_auth_bypass.py`, `tests/test_totp_setup.py`, `tests/test_cli_backup_secrets.py` |
| 0.7 | Tag and release `v2.0.1`; publish a security advisory referencing 0.1, 0.2, 0.3 | high | S | git tag, CHANGELOG.md, SECURITY.md |

**Acceptance:** all new tests pass in CI; `pip-audit` clean; manual EAP
proxy run rejects empty-password requests.

---

## Phase 1 — Security hardening → v2.0.2 (target: 2-3 weeks)

Real but non-exploitable-today issues. Bundle them so the SECURITY.md
threat model becomes accurate.

| # | Task | Sev | Effort | Notes |
|---|------|-----|--------|-------|
| 1.1 | Add RBAC: `superuser` vs `operator` vs `viewer`. `require_role()` dependency. Enforce on admin-CRUD, secret rotation, `/settings/save`, policy delete | crit | M | New column `AdminUser.role`; migration; UI badge |
| 1.2 | Constant-time auth path so missing users still run a dummy bcrypt — kills username enumeration on TACACS+, API login, and EAP `/auth` | high | S | `naco/api/auth.py`, `naco/tacacs/server.py`, `naco/radius/freeradius_routes.py` |
| 1.3 | Account-level lockout (10 consecutive failures → 15 min). Track per-username failures in Redis | high | S | `naco/core/ratelimit.py` |
| 1.4 | Rate-limiter atomicity — replace check+incr with a Lua `INCR` script; remove walrus dead code | high | S | `naco/core/ratelimit.py`, `tests/test_ratelimit_race.py` |
| 1.5 | Webhook URL SSRF guard — block RFC 1918, link-local, `169.254.169.254`, `metadata.google.internal` unless explicitly allowlisted | high | S | `naco/core/webhooks.py`, `naco/core/logger.py` |
| 1.6 | Replace the multipart CSRF body-regex with proper `python-multipart` parse on a cloned receive channel | high | M | `naco/web/app.py` |
| 1.7 | TACACS+ per-source-IP connection cap + global cap; reject when above | med | S | `naco/tacacs/server.py` |
| 1.8 | Set `Strict-Transport-Security` in the security-headers middleware; remove `'unsafe-inline'` for scripts using a CSP nonce | med | M | `naco/web/app.py`, all templates |
| 1.9 | `X-Request-ID` middleware; log it on every record | med | S | new `naco/core/request_id.py` |
| 1.10 | Bump bcrypt cost to 13 for new hashes; add a one-shot `nacoctl rehash-passwords` to upgrade existing rows on next successful login | low | S | `naco/api/auth.py` |
| 1.11 | Centralised log-redaction filter — scrub `password=`, `Bearer `, `secret=`, `key=` from any log record | high | S | `naco/core/logger.py` |
| 1.12 | Update SECURITY.md threat model to match what 0.x + 1.x actually defend against | low | S | `SECURITY.md` |

**Acceptance:** all new tests pass; `nacoctl check-config` warns when
RBAC is mis-configured (e.g. zero superusers); penetration-style
test suite (`tests/security/`) green.

---

## Phase 2 — Secret encryption + config hygiene → v2.1.0 (target: 4-6 weeks)

The single biggest production-credibility item: stop storing NAS shared
secrets in plaintext. Big enough to warrant its own minor release.

| # | Task | Sev | Effort | Notes |
|---|------|-----|--------|-------|
| 2.1 | `EncryptedString` SQLAlchemy column type (AES-GCM via `cryptography.fernet`); master key from `NACO_MASTER_KEY` env or file mount | crit | M | new `naco/db/types.py` |
| 2.2 | Migrate `NasClient.secret`, `TacacsClient.key`, `LdapConfig.bind_password`, `AdminUser.totp_secret`, `AdminUser.pending_totp_secret` to `EncryptedString` | crit | M | alembic data migration that decrypts-old / encrypts-new in one pass |
| 2.3 | Key rotation: `nacoctl rotate-master-key --new <hex>` re-encrypts every encrypted row in a single transaction | high | M | `naco/cli.py` |
| 2.4 | Refuse to start when secrets are placeholders **and** `server.debug=False` (production safety net) | high | S | `naco/app.py` lifespan |
| 2.5 | Whitelist additional env-vars for secrets so YAML can stay redacted: `NACO_LDAP_BIND_PASSWORD`, `NACO_EAP_BEARER_TOKEN`, `NACO_TACACS_KEY`, `NACO_MASTER_KEY` | high | S | `naco/config/__init__.py` |
| 2.6 | Backup encryption — `nacoctl backup --age-recipient <pubkey>` (and `--gpg-recipient`) pipes pg_dump through `age` / `gpg`; restore detects the magic header and decrypts | high | M | `naco/cli.py`, README |
| 2.7 | Remove `_LegacyWebView` / `_LegacyApiView` shims; migrate `cfg.api.token_expire_minutes` → `cfg.server.token_expire_minutes` | low | S | `naco/config/__init__.py`, `naco/api/routes.py` |
| 2.8 | Doc/code drift sweep — `naco/api/auth.py`, `naco/web/app.py`, `naco/api/routes.py` module docstrings | low | S | grep / fix |
| 2.9 | Tests: encrypt round-trip, key rotation, wrong-key startup failure, backup encryption round-trip | high | M | `tests/test_encrypted_column.py`, `tests/test_backup_encryption.py` |

**Acceptance:** `pg_dump` output contains no plaintext shared secrets;
`nacoctl rotate-master-key` re-encrypts a populated DB and the app
restarts cleanly with the new key.

---

## Phase 3 — Operability features → v2.2.0 (target: 6-10 weeks)

The "missing for day-two ops" tier. None of this is security, all of it
is "you'll add it the first time you actually run NACo for a customer".

| # | Task | Sev | Effort | Notes |
|---|------|-----|--------|-------|
| 3.1 | `ApiToken` model + `/api/v1/tokens` CRUD: name, scopes, hash, expires_at, last_used_at. Bearer-auth path checks both JWT and ApiToken tables | high | M | new `naco/api/tokens.py` |
| 3.2 | Wire `VlanMapping` into the policy engine — a policy can resolve VLAN from the user's group instead of hard-coding it | high | S | `naco/policy/engine.py`, `naco/db/models.py:Policy.vlan_source` |
| 3.3 | Per-NAS / per-realm policy scoping — add `Policy.nas_filter` (CIDR list) | high | S | `naco/policy/engine.py`, schema migration |
| 3.4 | CoA bulk endpoints: `POST /api/v1/sessions/disconnect?nas_ip=...`, `POST /api/v1/users/{id}/sessions/disconnect` | med | S | `naco/api/routes.py` |
| 3.5 | CoA on policy change — when an admin saves a policy that affects active sessions, queue Disconnect-Request for each | med | M | `naco/api/routes.py:update_policy`, new `naco/radius/coa_queue.py` |
| 3.6 | Self-service password change for end users (`User` not `AdminUser`); UI page gated on `must_change_password` | med | M | new `naco/portal/user_self_service.py` or extend portal |
| 3.7 | `nacoctl rotate-secrets` — generate fresh `session_secret`/`api_secret`/`csrf_secret`, write back to YAML, suggest a restart | med | S | `naco/cli.py` |
| 3.8 | `nacoctl add-admin --username --password --superuser` | low | S | `naco/cli.py` |
| 3.9 | `nacoctl test-radius --user --password --nas-ip` synthetic auth probe for monitoring | low | S | `naco/cli.py` |
| 3.10 | `nacoctl test-tacacs --user --password --nas-ip` ditto | low | S | `naco/cli.py` |
| 3.11 | Health endpoint split: `/api/v1/health/live` (always 200 unless process is dying) + `/api/v1/health/ready` (DB + Redis + RADIUS port bound) | med | S | `naco/api/routes.py` |
| 3.12 | First-boot wizard — `/setup` route gated by a one-time token printed to stdout on first start, walks operator through admin password + secrets | med | M | new `naco/web/setup.py` |
| 3.13 | CSV import/export for users + devices + NAS clients (REST endpoints + UI buttons) | med | M | `naco/api/routes.py`, UI |

**Acceptance:** the new endpoints have OpenAPI examples; the `nacoctl
test-radius` exit code is usable from a Nagios/Icinga check.

---

## Phase 4 — Scale, observability, polish → v2.3.0 (target: 10-14 weeks)

For deployments that actually have RADIUS volume — the "this thing is
running in prod and we need to see inside it" tier.

| # | Task | Sev | Effort | Notes |
|---|------|-----|--------|-------|
| 4.1 | OpenTelemetry tracing — `opentelemetry-instrumentation-fastapi`, `-sqlalchemy`, `-httpx`. Manual spans around `policy_engine.evaluate` and the RADIUS handler | med | M | new `naco/core/tracing.py`, deploy/docker-compose.obs.yml |
| 4.2 | Per-NAS Prometheus labels on `naco_radius_requests_total` (capped to known NAS clients to avoid cardinality blow-up) | med | S | `naco/core/metrics.py` |
| 4.3 | `auth_logs` & `tacacs_logs` monthly partitioning in Postgres (with a maintenance job that creates next month's partition) | med | M | alembic migration, `naco/db/maintenance.py` |
| 4.4 | Profiler write coalescing — debounce DEVICE_UPDATED to one upsert per MAC per 5 sec | med | S | `naco/profiler/profiler.py` |
| 4.5 | Move profiler `_VENDOR_PATTERNS` to a DB-backed editable table | low | M | new model, UI page |
| 4.6 | Replace blocking `pyrad` server with `pyrad.server_async`; remove the thread-pool bridge | med | M | `naco/radius/server.py` |
| 4.7 | Grafana alert rules in `deploy/grafana/alerts/` — auth-failure spike, RADIUS down, DB p99 latency, Redis down, log retention stuck | med | S | YAML rules + provisioning |
| 4.8 | Active-passive HA deployment guide in `docs/HA.md` — keepalived/VRRP example, shared Postgres + Redis | low | M | docs only |
| 4.9 | Soft-delete + tombstone columns on `AdminUser`, `User`, `Policy`, `NasClient` (`deleted_at`); audit_log retention extended | low | M | alembic migration |
| 4.10 | Shadow / dry-run policy mode — `Policy.shadow=True` evaluates but doesn't act; logged as `result=SHADOW` | med | M | `naco/policy/engine.py`, `naco/db/models.py:AuthLog` |
| 4.11 | Doc sweep — README, OpenAPI examples, screenshots refresh | low | S | docs |

**Acceptance:** Grafana dashboard shows per-NAS request rate; the
alert-rules YAML import cleanly into Prometheus; a synthetic 1k-req/s
RADIUS load test stays under 50 ms p99.

---

## Phase 5 — Major new capabilities (post-v2.3, scope TBD)

This is the roadmap tier — each item is a release of its own and the
order will shift based on what users actually ask for.

- **OAuth / OIDC admin SSO** (Keycloak, Okta, Authentik, Google) — likely
  v3.0 because the AdminUser model needs reshaping.
- **Captive-portal sponsor workflow** — employee approves a guest before
  the session goes live; per-MAC sponsor links; time-of-day quotas.
- **Native multi-tenant** — `Tenant` foreign key on every resource;
  per-tenant admin scoping; mTLS between tenant proxies and core.
- **Active-active HA** — leader election via Postgres advisory locks;
  CoA dispatched by the leader; shared Redis-backed accounting cache.
- **Built-in CA for EAP-TLS** — automate device-cert issuance + revocation
  so you don't have to run FreeRADIUS + an ADCS just for 802.1X-cert auth.
- **NAC posture checks** — pluggable agents (or agentless via DHCP
  fingerprint + nmap) that gate VLAN assignment on patch state.

---

## How the phases compose

```
v2.0.0 (released)
   │
   ├── Phase 0 ──▶ v2.0.1   (security hot-fix)
   │
   ├── Phase 1 ──▶ v2.0.2   (security hardening)
   │
   ├── Phase 2 ──▶ v2.1.0   (encrypted secrets, no plaintext at rest)
   │
   ├── Phase 3 ──▶ v2.2.0   (operability — RBAC tokens, CoA, ops CLI)
   │
   ├── Phase 4 ──▶ v2.3.0   (scale + observability + perf)
   │
   └── Phase 5 ──▶ v3.0+    (SSO, multi-tenant, posture, HA-active-active)
```

Phases 0–2 should be done strictly in order — each one builds on the
previous one's tests and migrations. Phases 3 and 4 can interleave once
the security floor is set. Phase 5 items are independent and can ship in
any order or as separate forks.

---

## What I'm NOT planning to do

For the record, things I considered and consciously dropped:

- **Rewrite in Rust / Go** — discussed in chat. The Python codebase is
  well within its performance envelope for the target deployments
  (≤ 5k auths/sec); a rewrite buys nothing for the time it costs.
- **Replace pyrad entirely** — the async server in 4.6 is enough; a
  hand-rolled RADIUS stack is a six-month project for almost no win.
- **Build our own EAP stack** — FreeRADIUS via `rlm_rest` is the correct
  trade-off; reimplementing EAP-TLS state machines would be a footgun.
- **Replace FastAPI / SQLAlchemy / Jinja2** — they're not the bottleneck
  and the migration cost would dwarf any benefit.

---

## Open questions for you

Before I start Phase 0, I need decisions on:

1. **Hot-fix release cadence** — patch release this week, or batch 0+1
   together into v2.1.0 in 3-4 weeks? Patch release is safer.
2. **RBAC role model** — three roles (`superuser`/`operator`/`viewer`)
   or a permission-bitmask system that scales further? Roles are
   simpler to implement and audit; bitmasks are more flexible.
3. **Master-key storage** — env var only, file mount only, or both? File
   mount is friendlier in Kubernetes; env is friendlier in docker-compose.
4. **Secret-encryption migration path** — destructive (re-enter all
   secrets) or transparent (encrypt-in-place with a one-shot migration)?
   Transparent is more work but operator-friendly.
