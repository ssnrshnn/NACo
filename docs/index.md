# NACo — open-source NAC & AAA

NACo is a modern, container-native open-source Network Access Control & AAA
server. It replaces commercial NACs (Cisco ISE, Aruba ClearPass, FortiNAC)
with a focused, auditable stack that runs anywhere Docker runs.


> **Heads-up — NACo is a clean v2.0.0 fork of the now-archived RaspISE project.**
> There is **no upgrade path** from RaspISE. The schema, configuration
> layout, secrets, and container surface have all changed. See
> [`CHANGELOG.md`](https://github.com/ssnrshnn/NACo/blob/main/CHANGELOG.md) for the full rationale.

---

| Area                 | Capability                                                                 |
| -------------------- | -------------------------------------------------------------------------- |
| RADIUS               | PAP, CHAP, MAB (RFC 3580) + RFC 3579 Message-Authenticator (BlastRADIUS)   |
| RADIUS accounting    | Start / Stop / Interim-Update with active-session tracking                 |
| Change of Authorization | RFC 5176 Disconnect & CoA with response-authenticator verification       |
| EAP                  | Delegated to FreeRADIUS sidecar via REST hooks (`/api/v1/eap/*`)            |
| TACACS+              | RFC 8907 authentication, authorization & accounting                         |
| Policy engine        | Default-deny attribute rules: user, group, MAC OUI, NAS, time-of-day, VLAN |
| Vendor interop       | Dynamic VLAN via RFC 3580 + per-policy VSAs (Cisco, Aruba, Juniper, Fortinet, MikroTik, …) — see [Vendor attributes](VENDORS.md) |
| Identity sources     | Local DB (bcrypt), LDAP / Active Directory with auto-provisioning          |
| Captive guest portal | Cookie-CSRF, MAC-bound timed sessions, Wi-Fi QR code provisioning           |
| Device profiling     | Passive DHCP / mDNS fingerprinting with OUI-based classification           |
| Admin UI             | FastAPI + Jinja2, TOTP-protected, full audit log                            |
| REST API             | OpenAPI 3 (Swagger at `/api/v1/docs`), JWT-bearer auth                      |
| Observability        | Prometheus metrics, structured JSON logs, Loki/Grafana profile             |
| Deployment           | Docker Compose stack — Postgres, Redis, Caddy (auto-TLS), optional sidecars |

---

## Architecture

```text
┌─────────────┐      RADIUS / TACACS+      ┌───────────────────────┐
│  switch/AP  │ ────────────────────────► │       NACo            │ ──► PostgreSQL
└─────────────┘                            │  (single FastAPI app) │
       ▲                                   │                       │ ──► Redis
       │ EAP                               │  /            Admin UI │
       │                                   │  /api/v1      REST API │
       ▼                                   │  /portal      Captive  │
┌─────────────┐  REST  /api/v1/eap/*       │  /metrics     Prom OpenMetrics
│  FreeRADIUS │ ─────────────────────────► │  RADIUS 1812 / 1813    │
│   sidecar   │                            │  TACACS+ 49            │
└─────────────┘                            │  CoA    3799           │
                                           └──────────┬────────────┘
                                                      │
                                       Caddy reverse proxy (auto-TLS)
                                                      │
                                                      ▼
                                                  operators
```

A **single** Uvicorn process hosts the admin UI, the REST API, the
captive portal, and the OpenMetrics endpoint. RADIUS, TACACS+, and the
device profiler run as supervised asyncio tasks inside the same app.
FreeRADIUS is opt-in and used only for EAP outer-method termination
(EAP-TLS / PEAP / EAP-TTLS) — the policy decision still happens in NACo.

---

## Next steps

- [Install NACo](install.md) — one command, batteries included.
- [Configure it](configuration.md) — YAML + env overrides.
- [Point your switches at it](nas-setup.md).
