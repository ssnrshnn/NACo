# Roadmap

Direction only — order and scope shift based on user feedback.
Anything already shipped lives in [`CHANGELOG.md`](../CHANGELOG.md).

## v2.2.0 — secrets-at-rest leftovers & day-two operability

Shipped in the encrypted-secrets work (post-2.1.0): `EncryptedString`
(AES-256-GCM) for NAS secrets / TACACS+ keys / TOTP seeds, master key via
`NACO_MASTER_KEY`(`_FILE`), lazy encrypt-on-write plus
`nacoctl encrypt-secrets`, `nacoctl rotate-master-key`, placeholder-secret
startup refusal (`server.debug=false`), and age-encrypted backups
(`nacoctl backup --age-recipient` / `restore --age-identity`).

Shipped in the day-two-ops work: CoA on policy change
(`radius.coa_on_policy_change`), bulk CoA disconnect
(`POST /api/v1/sessions/disconnect`), `/health/live` vs `/health/ready`
split, CSV import/export for users/devices/NAS, and
`nacoctl test-radius` / `test-tacacs` synthetic probes.

- API tokens with scopes (`/api/v1/tokens`)
- First-boot setup wizard

## v2.3.0 — scale & observability

- Async RADIUS server (replace the pyrad thread bridge)
- Policy caching with invalidation on save
- Per-NAS Prometheus labels; Grafana alert rules
- `auth_logs` partitioning; profiler write coalescing
- OpenTelemetry tracing

## v3.x — major capabilities

- OIDC admin SSO (Keycloak / Authentik / Okta)
- Built-in CA for EAP-TLS (step-ca integration)
- Fingerbank-based device profiling
- Captive-portal sponsor workflow
- Active-active HA; native multi-tenant
- NAC posture checks

## Non-goals

- Rewriting in Rust/Go — Python is within its envelope for the target
  scale (≤ 5k auth/s)
- A hand-rolled EAP stack — FreeRADIUS via `rlm_rest` is the right
  trade-off
- Replacing FastAPI / SQLAlchemy / Jinja2
