# Changelog

All notable changes to NACo. Versions follow [Semantic Versioning](https://semver.org).

## Unreleased

### Fixed

- Firefox refused the admin panel with `SEC_ERROR_BAD_SIGNATURE` on
  machines that trust another Caddy's root CA: NACo's CA had Caddy's
  default name. Its root and intermediates are now named uniquely; see
  [install](docs/install.md#trusting-the-https-certificate) to renew the CA
  of an existing installation.
- First sign-in no longer asks for the password again right after it was
  chosen, on the two-factor step.

## 3.0.1 — 2026-10-30

### Fixed

- HTTPS failed when `NACO_HOST` is an IP address: browsers send no SNI to an
  IP, and Caddy looked for a certificate for its container's own address.
- `quickstart.sh` takes `NACO_IMAGE` and `NACO_RADIUS_IMAGE` from the
  environment on a first install, so released images need no hand-written
  `.env`.

## 3.0.0 — 2026-10-30

NACo 3 is a rewrite for one job — network access control on a single host
for small and medium organizations — done simply and safely. It is a clean
start: there is no upgrade path from 2.x; install 3.0 next to it and move
users, devices and switches over with CSV import.

### Architecture

- **FreeRADIUS 3.2 is the only RADIUS front door** (1812/1813) for 802.1X,
  MAB and PAP; NACo decides everything through an internal REST API that is
  never published. NACo's own RADIUS server is gone, as are the separate EAP
  ports.
- **SQLite only** (WAL), one database file, one baseline migration applied
  at start-up. PostgreSQL and Redis are gone.
- **Three containers** — Caddy, FreeRADIUS, NACo — read-only, without
  capabilities, unprivileged; `quickstart.sh` sets everything up, including
  the EAP certificate authority.

### Added

- EAP-TLS decisions by policy: the certificate's CN must be an enabled user.
- Change of Authorization disconnects only the sessions whose decision
  actually changed (policy edits, device approval/blocking, user changes,
  guest expiry).
- TACACS+ device-administration profiles: privilege level and command set
  per group; whole-command-line rules with a default; `enable` capped at the
  group's level.
- Guest portal (central web authentication) that identifies the device from
  its RADIUS session instead of trusting the browser.
- New admin panel: live dashboard and logs, policy editor with simulator and
  drag-and-drop ordering, command palette, light/dark themes, mobile layout,
  no third-party code; mandatory TOTP with recovery codes; audit log page;
  API tokens with roles; CSV import/export.
- Reply attribute names are checked against FreeRADIUS' dictionaries.
- `nacoctl`: config check, password/2FA reset, online backups through
  stdin/stdout (encrypt them with age on the host), restore with integrity
  check, master key rotation.
- Released images are multi-arch, scanned, signed with cosign and shipped
  with SBOM and provenance; CI runs end-to-end tests against real
  FreeRADIUS, RADIUS and EAP clients and the panel in a browser.

### Removed

- DHCP/mDNS profiler (needed raw network access; device types are set by
  administrators), OIDC sign-in, Graylog/Loki/webhook integrations,
  PostgreSQL/Redis, the systemd and settings pages.

### Security

Fixed in the rewrite, among others:

- TTLS/PEAP decisions could fail open or reject everyone; EAP-TLS bypassed
  policies, disabled users and logging.
- TACACS+: any network user could `enable` to privilege 15; command rules
  ignored arguments; deleted clients kept working until restart; no read
  timeout. **The TACACS+ body obfuscation used the key and session id in the
  wrong order (RFC 8907 §4.5)** — standard clients could not interoperate.
- Guest portal authorized a MAC address taken from the form.
- MAB was recognized by the user-name format alone.
- Viewers could read secrets; signed-out or deleted administrators kept
  access; `X-Forwarded-For` was trusted from anyone; the EAP hooks, metrics
  and OpenAPI were reachable from the internet.
- Disabled users could still sign in through LDAP; LDAP certificates were
  not verified.
- Regular-expression policy conditions allowed ReDoS (now wildcard patterns).
- CSV exports allowed formula injection; the log redaction filter was
  ineffective; backups were world-readable.
- Scripts were loaded from a CDN without integrity checks.
- CI actions were not pinned; images were published before CI passed and
  were not signed.

## 2.x and earlier

See the [2.3.0 changelog](https://github.com/ssnrshnn/NACo/blob/v2.3.0/CHANGELOG.md).
