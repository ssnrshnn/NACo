# Roadmap

Direction only — order and scope shift based on user feedback.
Anything already shipped lives in [`CHANGELOG.md`](../CHANGELOG.md).

## v2.1.0 — encrypted secrets at rest

The single biggest production-credibility item: stop storing NAS shared
secrets, TACACS+ keys, LDAP bind passwords, and TOTP secrets in plaintext.

- `EncryptedString` SQLAlchemy type (AES-GCM), master key via
  `NACO_MASTER_KEY` env or file mount
- Transparent encrypt-in-place migration; `nacoctl rotate-master-key`
- Refuse to start with placeholder secrets when `server.debug=false`
- Encrypted backups: `nacoctl backup --age-recipient <pubkey>`

## v2.2.0 — day-two operability

- API tokens with scopes (`/api/v1/tokens`)
- Health split: `/health/live` vs `/health/ready`
- CoA on policy change (disconnect affected sessions)
- Bulk CoA endpoints; CSV import/export for users/devices/NAS
- `nacoctl test-radius` / `test-tacacs` synthetic probes for monitoring
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
