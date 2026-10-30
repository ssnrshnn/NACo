<p align="center"><img src="naco/web/static/img/emblem-192.png" width="96" alt=""></p>

# NACo — network access control for small and medium organizations

NACo decides who and what may join your wired and wireless network, which
VLAN they land in, and who may log in to your switches. It runs on one Linux
host with Docker Compose, keeps everything in one SQLite file, and is set up
in a few minutes.

[![CI](https://github.com/ssnrshnn/NACo/actions/workflows/ci.yml/badge.svg)](https://github.com/ssnrshnn/NACo/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## What it does

| | |
|---|---|
| **802.1X** | EAP-TLS (certificates), EAP-TTLS/PAP and PEAP/GTC (passwords), plain PAP |
| **MAB** | MAC authentication for printers, phones and other devices without a supplicant; new devices wait in *pending* until approved |
| **Policies** | Ordered rules on user, group, device, vendor, method, switch, SSID and time of day → permit with a VLAN and reply attributes, or deny. Anything unmatched is denied. A simulator shows which rule wins and why |
| **Change of Authorization** | Edit a policy, block a device or disable a user and only the sessions whose decision actually changed are disconnected (RFC 5176) |
| **Identity** | Local users and LDAP / Active Directory (LDAPS or StartTLS, nested groups, group mapping) |
| **Guest portal** | Central web authentication: guests accept the terms (optionally with an access code) and are moved to the guest policy |
| **TACACS+** | Device administration for switch logins (RFC 8907): privilege levels and per-command authorization by group, full accounting |
| **Admin panel** | Fast, keyboard-friendly, live (dashboard, sessions and logs update by themselves), light and dark, works on a phone; mandatory two-factor sign-in; roles *viewer*, *operator*, *superuser*; API tokens; complete audit log |
| **Operations** | One-command install, online backups (age-encryptable), master-key rotation, CSV import/export, syslog, Prometheus metrics |

## How it fits together

```text
 switches, APs ──RADIUS 1812/1813──► FreeRADIUS ──internal REST──┐
 (802.1X, MAB)                      (EAP, TLS)                   │
                                                                 ▼
 switch logins ──TACACS+ 49──────────────────────────────────►  NACo  ──► SQLite
                                                                 ▲
 admins ──HTTPS 443──► Caddy ──────────────────────────────────┘
 guests ──HTTP 80───►  (TLS, portal)        CoA/Disconnect ──► switches :3799
```

- **FreeRADIUS** speaks RADIUS and EAP and nothing else: every switch lookup,
  password check and decision is a call to NACo's internal API, which never
  leaves the private Docker network.
- **NACo** (Python, FastAPI) holds the policies, users, devices, sessions and
  logs, runs TACACS+, serves the panel and the guest portal, and sends CoA.
- **Caddy** terminates HTTPS — with a Let's Encrypt certificate or its own CA.

All three containers run read-only, without capabilities, as unprivileged
users where the image allows it.

## Install

You need a Linux host (2 CPU, 2 GB RAM is plenty for ~5,000 devices) with
Docker Engine and the Compose plugin, and `openssl`.

```bash
git clone https://github.com/ssnrshnn/NACo.git && cd NACo
./quickstart.sh
```

`quickstart.sh` asks for the address administrators will use, writes `.env`
with fresh secrets, creates the EAP certificate authority and the RADIUS
server certificate, builds and starts the stack, and prints where to sign in
together with a one-time admin password. The first sign-in asks for a new
password and sets up an authenticator app.

Details — Let's Encrypt, released images, firewalls, upgrades — are in
[docs/install.md](docs/install.md).

## First steps

1. **RADIUS clients** — add each switch, AP or controller with its IP address
   and a shared secret (16+ characters). Configure the device as shown in
   [docs/network-devices.md](docs/network-devices.md).
2. **Groups and users** — create groups such as `staff`; add users or connect
   LDAP / Active Directory in `config/config.yaml`.
3. **Policies** — e.g. *group is staff → permit, VLAN 20*; *MAB and device is
   approved and type is printer → permit, VLAN 40*. Try them in the
   **Simulator** before a switch does.
4. **Devices** — new MAC addresses appear as *pending*; approve or block them.
5. Watch **Sessions** and **Logs**: every decision says which rule made it.

## Ports

| Port | Protocol | Used by |
|---|---|---|
| 443 | TCP | Admin panel and REST API (HTTPS) |
| 80 | TCP | Guest portal, redirect to HTTPS, Let's Encrypt |
| 1812 / 1813 | UDP | RADIUS authentication / accounting |
| 49 | TCP | TACACS+ |
| 3799 | UDP, outgoing | CoA / Disconnect to switches |

## Documentation

| | |
|---|---|
| [Install and upgrade](docs/install.md) | requirements, quickstart, TLS, released images, upgrades |
| [First deployment](docs/pilot.md) | a safe pilot: one port, monitor mode, NACo unreachable, enforcing |
| [Network devices](docs/network-devices.md) | Cisco, Aruba, Juniper, HPE, Fortinet, MikroTik, UniFi, … |
| [Policies](docs/policies.md) | how a decision is made, conditions, reply attributes, CoA |
| [802.1X and certificates](docs/eap.md) | EAP methods, the EAP CA, client certificates, Windows |
| [Guest portal](docs/guest-portal.md) | central web authentication and what the network must provide |
| [TACACS+](docs/tacacs.md) | switch logins, privilege levels, command sets |
| [Configuration](docs/configuration.md) | every setting in `config.yaml` and `.env` |
| [Operations](docs/operations.md) | backup, restore, key rotation, lost 2FA, logs, metrics |
| [Security](docs/security.md) | what NACo protects and how; reporting vulnerabilities |

The REST API is described by `https://<host>/api/v1/openapi.json` (OpenAPI 3,
for signed-in administrators and API tokens); tokens are created under
**API tokens** with a role of their own.

## Development

```bash
python3.12 -m venv .venv && . .venv/bin/activate
pip install -r requirements.lock && pip install -e '.[dev]'
pytest                       # unit and API tests
pytest -m e2e tests/e2e      # real FreeRADIUS, RADIUS and EAP clients (Docker)
pytest -m ui tests/ui        # the admin panel in a browser (Playwright)
ruff check . && mypy naco
NACO_DEV=1 naco              # run locally on :8080 with development secrets
```

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License and history

MIT — see [LICENSE](LICENSE). NACo 3 is a rewrite of NACo 2 (itself a fork of
RaspISE); there is no upgrade path from 2.x. See [CHANGELOG.md](CHANGELOG.md).
