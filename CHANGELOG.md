# Changelog

All notable changes to NACo. Versions follow [Semantic Versioning](https://semver.org).

## Unreleased

Three devices were run against NACo in a lab — MikroTik RouterOS 7.25,
Extreme Switch Engine 33.6.1 and hostapd 2.11 — and their pages now say
what was seen there.

### Fixed

- **TACACS+ logins on Extreme Switch Engine.** It asks for privilege 15 in
  every login, authorization and command request; NACo refused everyone
  below level 15. The level a device asks for is now checked only for
  `enable`; the session gets the group's level from shell authorization,
  and commands are checked against the group's command set.

### Changed

- For EAP-TTLS and PEAP, the Access-Accept carries the name NACo verified
  inside the tunnel as User-Name (RFC 2865 §5.1), so devices that honour it
  show and account the real user instead of `anonymous`.

### Documentation

- MikroTik: Disconnect works on dot1x ports; leave `reauth-period` unset on
  MAC-authentication ports — RouterOS 7.25 re-authenticates a quiet device
  with an empty User-Name and then keeps the port blocked; ports leave the
  server-fail VLAN only when they authenticate again.
- Extreme: Disconnect needs ONEPolicy (`configure policy maptable response
  tunnel` keeps NACo's VLANs), which rules out the service-unavailable
  VLAN; that VLAN needs `database-order radius` for MAC clients; 33.6.1
  sends Message-Authenticator in MAC authentication and no interim
  accounting; levels and command authorization over TACACS+.

## 3.1.0 — 2026-10-30

Support for the network devices most organizations run, from each vendor's
documentation: a [page per vendor](docs/network-devices.md#vendors) — Cisco,
Meraki, HPE Aruba Networking, HPE Comware/H3C, Juniper, Huawei, Fortinet,
Extreme, Ruckus, Dell, MikroTik, UniFi and TP-Link Omada.

### Added

- **Device type per RADIUS client.** Disconnect-Requests carry the session
  and NAS identifiers that vendor accepts (AOS-CX requires a NAS identifier
  and User-Name; Extreme and Ruckus ICX only Calling-Station-Id and
  NAS-IP-Address; Juniper nothing but identifiers; Cisco and Meraki match
  audit-session-id), with the values the device reported. Sessions now keep
  NAS-IP-Address, NAS-Identifier and Cisco's audit-session-id. The CoA port
  defaults to the type's (Meraki 1700).
- **A RADIUS client can be a network** (at most /16, /48 for IPv6) for
  platforms that send RADIUS from every access point or switch — UniFi,
  Omada, Meraki, Mist, Instant, SmartZone. The exact address wins over a
  network; disconnects go to the device itself.
- **TACACS+ for other vendors' services.** A group lists
  `service: attribute=value` lines — Juniper `junos-exec`, Fortinet
  `fortigate`, Dell OS10 `ppp`, NX-OS and Comware roles on `shell`.
  Previously any service but `shell` was refused.
- MAB in every MAC notation (Huawei/H3C `aabb-ccdd-eeff`, ArubaOS-Switch
  `aabbcc-ddeeff`, MikroTik `AABB:CCDD:EEFF`, Ruckus ICX `aa.bb.cc.dd.ee.ff`,
  …), and with an empty or no password (MikroTik, UniFi, Omada; CHAP MAC
  authentication of ArubaOS-Switch).
- The SSID is read from `Called-Station-SSID`, `Aruba-Essid-Name`,
  `Ruckus-SSID`, `Fortinet-SSID`, `Trapeze-SSID`, `TP-CAPWAP-SSID` and
  Cisco's `cisco-wlan-ssid` when `Called-Station-Id` has none.

### Changed

- Status-Server probes are answered only while NACo can decide, so a switch
  that probes (Ruckus ICX by default) fails over at once.
- Database migration 0002 runs at start-up.

## 3.0.2 — 2026-10-30

### Fixed

- Firefox refused the admin panel with `SEC_ERROR_BAD_SIGNATURE` on
  machines that trust another Caddy's root CA: NACo's CA had Caddy's
  default name. Its root and intermediates are now named uniquely; see
  [install](docs/install.md#trusting-the-https-certificate) to renew the CA
  of an existing installation.
- First sign-in no longer asks for the password again right after it was
  chosen, on the two-factor step.

### Changed

- When NACo cannot be asked (stopped, restarting, timing out or answering an
  error), FreeRADIUS no longer rejects: it does not answer, so switches mark
  the server dead and apply their server-dead action (e.g. a critical VLAN)
  instead of refusing every new login and re-authentication. Nobody is ever
  let in without NACo's decision.

### Added

- [First deployment](docs/pilot.md): a pilot step by step — one port in
  monitor mode, what the switch does when NACo cannot be reached, then
  enforcement and Change of Authorization.

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
