# NACo — Network Access Control

NACo is a modern, container-native open-source Network Access Control & AAA
server. It replaces commercial NACs (Cisco ISE, Aruba ClearPass, FortiNAC)
with a focused, auditable stack that runs anywhere Docker runs.

[![CI](https://github.com/your-org/naco/actions/workflows/ci.yml/badge.svg)](https://github.com/your-org/naco/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> **Heads-up — NACo is a clean v2.0.0 fork of the now-archived RaspISE project.**
> There is **no upgrade path** from RaspISE. The schema, configuration
> layout, secrets, and container surface have all changed. See
> [`CHANGELOG.md`](CHANGELOG.md) for the full rationale.

---

## Table of contents

- [Features](#features)
- [Architecture](#architecture)
- [Quick start](#quick-start)
- [Configuration](#configuration)
- [Network access — NAS / switch setup](#network-access--nas--switch-setup)
- [EAP via FreeRADIUS sidecar](#eap-via-freeradius-sidecar)
- [Observability stack](#observability-stack)
- [Backup & restore](#backup--restore)
- [Security model](#security-model)
- [Contributing](#contributing)
- [License](#license)

---

## Features

| Area                 | Capability                                                                 |
| -------------------- | -------------------------------------------------------------------------- |
| RADIUS               | PAP, CHAP, MAB (RFC 3580) + RFC 3579 Message-Authenticator (BlastRADIUS)   |
| RADIUS accounting    | Start / Stop / Interim-Update with active-session tracking                 |
| Change of Authorization | RFC 5176 Disconnect & CoA with response-authenticator verification       |
| EAP                  | Delegated to FreeRADIUS sidecar via REST hooks (`/api/v1/eap/*`)            |
| TACACS+              | RFC 8907 authentication, authorization & accounting                         |
| Policy engine        | Default-deny attribute rules: user, group, MAC OUI, NAS, time-of-day, VLAN |
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

## Quick start

### Prerequisites

- Docker 24+
- Docker Compose v2 (`docker compose`, not the legacy `docker-compose`)
- One free public DNS name if you want Caddy to provision Let's Encrypt
  certificates automatically (otherwise the stack falls back to a
  self-signed certificate).

### 60-second launch

```bash
git clone https://github.com/your-org/naco.git
cd naco

# Generate strong secrets and edit any other settings
cp .env.example .env
sed -i \
    -e "s/__SESSION__/$(openssl rand -hex 32)/" \
    -e "s/__API__/$(openssl rand -hex 32)/"     \
    -e "s/__CSRF__/$(openssl rand -hex 32)/"    \
    -e "s/__POSTGRES__/$(openssl rand -hex 24)/" \
    .env

docker compose -f deploy/docker-compose.yml up -d
docker compose -f deploy/docker-compose.yml logs -f naco
```

Then open:

- Admin UI:  `https://<your-host>/`  (default login `admin` /
  `${NACO_ADMIN_PASSWORD}` — **change at first login**)
- REST API:  `https://<your-host>/api/v1/docs`
- Portal:     `http://<your-host>/portal` (captive portals must be HTTP)
- Metrics:   `https://<your-host>/api/v1/metrics`

### Optional profiles

```bash
# Add FreeRADIUS for EAP-TLS / PEAP / EAP-TTLS
docker compose -f deploy/docker-compose.yml \
               -f deploy/docker-compose.eap.yml up -d

# Add Prometheus + Grafana + Loki + Promtail
docker compose -f deploy/docker-compose.yml \
               -f deploy/docker-compose.obs.yml up -d
```

---

## Configuration

NACo reads YAML from the path in `$NACO_CONFIG` (default
`/etc/naco/config.yaml`). Every section is validated by Pydantic — startup
fails loudly on unknown keys or wrong types.

A documented [`naco/config/config.yaml`](naco/config/config.yaml) ships in
the image. The full schema is generated from the Pydantic models in
[`naco/config/__init__.py`](naco/config/__init__.py) — keep that file as
the source of truth.

### Most-changed knobs

| Key                                 | Purpose                                              | Default                                  |
| ----------------------------------- | ---------------------------------------------------- | ---------------------------------------- |
| `server.session_secret`             | Signs admin session cookies                          | *unset, must rotate*                     |
| `server.api_secret`                 | Signs API JWTs                                       | *unset, must rotate*                     |
| `server.csrf_secret`                | HMAC for admin-UI CSRF tokens                        | *unset, must rotate*                     |
| `server.trusted_proxies`            | CIDRs allowed to set `X-Forwarded-For`               | `127.0.0.1/32, ::1/128, 172.16.0.0/12`   |
| `database.url`                      | SQLAlchemy URL (PostgreSQL or SQLite)                | `postgresql+asyncpg://naco:naco@postgres/naco` |
| `cache.url`                         | Redis URL for rate limiting & sessions               | `redis://redis:6379/0`                   |
| `radius.require_message_authenticator` | Drop Access-Requests without a valid MA           | `true` (BlastRADIUS mitigation)          |
| `eap.bearer_token`                  | Auth token for FreeRADIUS `rlm_rest` callbacks       | *unset until you enable EAP*             |

Every secret can also be passed via `${NACO_*}` environment variables (see
[`.env.example`](.env.example)).

---

## Network access — NAS / switch setup

Configure your NAS (switch, AP, firewall) for RADIUS:

| Field             | Value                                              |
| ----------------- | -------------------------------------------------- |
| Auth Server       | `<naco-host>:1812`                                 |
| Acct Server       | `<naco-host>:1813`                                 |
| Shared Secret     | the value from `radius.clients[].secret`           |
| CoA Server        | `<naco-host>:3799`                                 |
| Message-Authenticator | **enabled** (mandatory by default)              |

Then add the NAS in NACo so its IP and secret are known:

```bash
# Either via UI: Settings → NAS Clients → Add
# Or via API:
curl -X POST https://<naco>/api/v1/nas \
     -H "Authorization: Bearer $TOKEN" \
     -d '{"name":"core-sw01","ip_address":"10.0.0.1","secret":"…"}'
```

**TACACS+** uses the same `tacacs.clients` block:

```yaml
tacacs:
  enabled: true
  key: "tacacs_default"
  clients:
    - address: "10.0.0.1"
      key:     "tacacs_per_device_secret"
```

---

## EAP via FreeRADIUS sidecar

NACo's built-in RADIUS server intentionally **does not** implement EAP —
that family is large and security-sensitive enough to deserve a dedicated
project. Enable the optional `eap` profile instead:

```bash
docker compose -f deploy/docker-compose.yml \
               -f deploy/docker-compose.eap.yml up -d
```

The bundled FreeRADIUS container terminates EAP-TLS / PEAP / EAP-TTLS and
calls NACo back over HTTP for the authorisation decision:

```text
NAS ──RADIUS+EAP──► FreeRADIUS ──REST──► NACo policy engine
              ◄────RADIUS Accept/Reject─◄────VLAN/policy────
```

Configuration lives in [`deploy/freeradius/`](deploy/freeradius/). The
shared bearer token must be set in **both** `eap.bearer_token` (NACo
config) and `mods-available/rest` (FreeRADIUS).

---

## Observability stack

The `obs` compose profile spins up Prometheus, Grafana, Loki, and Promtail
pre-wired to NACo:

- **Prometheus** scrapes `https://<naco>/api/v1/metrics` every 15 s.
- **Loki** ingests container logs via Promtail (`naco`, `freeradius`,
  `caddy`, …).
- **Grafana** is provisioned with a default NACo dashboard:
  authentication rate, RADIUS / TACACS+ latency, active sessions, policy
  rejections.

```bash
docker compose -f deploy/docker-compose.yml \
               -f deploy/docker-compose.obs.yml up -d
open http://localhost:3000   # admin / admin (change on first login)
```

---

## Backup & restore

Use the bundled `nacoctl` CLI from inside the container:

```bash
# Backup — works for both Postgres and SQLite
docker compose exec naco nacoctl backup --out /backups/naco-$(date +%F).sql.gz

# Restore (DESTRUCTIVE)
docker compose exec naco nacoctl restore --in /backups/naco-2026-05-12.sql.gz
```

For Postgres deployments, the same tool wraps `pg_dump` / `psql`; for
SQLite it copies the file. Either way the backup is portable across NACo
v2.x.

---

## Security model

NACo is **default-deny**:

1. A new install ships with **no permit policies**. Every authentication
   is rejected until you create policies — there is no implicit "Default
   Permit-All" entry.
2. RADIUS Access-Requests without a valid Message-Authenticator are
   dropped (CVE-2024-3596 / BlastRADIUS mitigation).
3. MAB requires `User-Password == User-Name == MAC` (RFC 3580). A
   compromised NAS cannot bypass MAB by guessing passwords.
4. The admin UI, API, and portal use **three independent secrets**
   (`session_secret`, `api_secret`, `csrf_secret`). A leak of one does not
   compromise the others.
5. All admin actions are persisted in `admin_audit_logs` for 365 days by
   default.

See [`SECURITY.md`](SECURITY.md) for the full threat model, reporting
procedure, and CVE coordination policy.

---

## Contributing

We welcome issues and pull requests. Start with
[`CONTRIBUTING.md`](CONTRIBUTING.md) for the test matrix, lint rules, and
release cadence.

---

## License

NACo is released under the [MIT License](LICENSE).
