# Security

What NACo protects, how, and what remains your responsibility. To report a
vulnerability, see [SECURITY.md](../SECURITY.md).

## Exposure

Only four things are reachable from the network:

| Port | Who answers | Protection |
|---|---|---|
| 443/tcp | Caddy → NACo | TLS; signed-in administrators or API tokens |
| 80/tcp | Caddy → NACo | guest portal only; everything else redirects |
| 1812–1813/udp | FreeRADIUS | registered clients only, per-client secret, Message-Authenticator |
| 49/tcp | NACo TACACS+ | registered clients only, per-client key, connection limits |

NACo's internal API (FreeRADIUS' only way to ask for decisions) and its web
port are never published; the internal API additionally requires a 256-bit
token. NACo trusts `X-Forwarded-For` only from Caddy's fixed address.

## Administrators

- Two-factor authentication (TOTP) is **mandatory**: a new administrator can
  do nothing but change the initial password and enroll an authenticator.
  One-time recovery codes are stored as bcrypt hashes; a used TOTP code
  cannot be replayed.
- Sign-in is limited per address (10 per 5 minutes by default). Wrong
  passwords slow down further attempts for that account *from that address*,
  so nobody can lock an administrator out from elsewhere; failures from many
  addresses slow the account down everywhere. Every failure gets the same
  message. RADIUS (per account and device) and TACACS+ logins are slowed
  down the same way.
- Sessions: random 256-bit tokens stored only as hashes, `HttpOnly`,
  `Secure`, `SameSite=Lax` cookies, idle (30 min) and absolute (12 h)
  timeouts. Changing the password or 2FA ends the other sessions.
- Every state-changing request from a browser session needs the session's
  CSRF token, and requests that announce another origin (`Origin`,
  `Sec-Fetch-Site`) are refused.
- Roles: **viewer** (read), **operator** (also users, devices, sessions,
  guests, imports, the audit log), **superuser** (everything, including
  policies, network devices, secrets, administrators and tokens).
  API tokens carry a role of their own, are shown once and stored hashed.
- Revealing a stored secret, and every other change, is written to the audit
  log with before/after values (secrets masked) and can be forwarded to
  syslog.

The panel loads no third-party code: a strict Content-Security-Policy
without inline scripts or styles, `frame-ancestors 'none'`, HSTS and the
usual hardening headers are always sent.

## Stored secrets

| What | How |
|---|---|
| User and administrator passwords | bcrypt (cost 12) |
| RADIUS secrets, TACACS+ keys, TOTP seeds | AES-256-GCM under `NACO_MASTER_KEY`, bound to their table and column |
| API and session tokens | SHA-256 hashes |
| `.env`, the EAP CA key | files readable only by their owner; never inside an image |

Backups contain the hashes and the encrypted secrets; they are useless for
the secrets without the master key, but treat them as confidential (or use
`--age-recipient`). `nacoctl rotate-master-key` replaces the master key.

## RADIUS and EAP

- Requests from unknown addresses are ignored; a client is looked up in
  NACo and must be enabled.
- Message-Authenticator is required on every Access-Request (BlastRADIUS,
  CVE-2024-3596) unless a client is explicitly marked legacy.
- Shared secrets must be at least 16 characters.
- MAB is accepted only when the user name equals the Calling-Station-Id.
- EAP uses TLS 1.2 with strong ciphers; PEAP-MSCHAPv2, which would need
  reversible password hashes, is not offered. An Access-Reject never carries
  EAP-Success.
- EAP-TLS certificates must belong to an enabled NACo user, so disabling
  the user revokes the certificate.
- Anything that is not explicitly permitted by a policy is denied; if the
  policy set cannot be loaded, every request is denied.

## Containers

All containers run with a read-only root file system, no Linux capabilities
(Caddy keeps only the one to bind ports 80/443), `no-new-privileges`, and an
init process. NACo runs as uid 10001 and FreeRADIUS as uid 1812. Python
dependencies are installed from a hash-locked file as binary wheels only;
released images are built in CI, scanned, signed with Sigstore and come with
an SBOM and provenance.

## Your part

- **MAC addresses can be spoofed.** Give MAB devices only the access they
  need (e.g. a printer VLAN with ACLs), prefer 802.1X wherever possible.
- **TACACS+ obfuscation is not strong encryption** (RFC 8907 says so): keep
  TACACS+ on a management network.
- **The guest portal is plain HTTP** by design; nothing secret is sent
  through it. Isolate the onboarding and guest VLANs.
- Configure supplicants to **verify the RADIUS server certificate** (see
  [eap.md](eap.md)) — otherwise a fake access point can collect passwords.
- Whoever controls the Docker host controls NACo: keep it patched, limit SSH
  and `docker` group membership, and back up `.env` and `secrets/` securely.
- Keep NACo, the images and the host's time (NTP) up to date.
