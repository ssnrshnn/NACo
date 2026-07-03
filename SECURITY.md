# Security Policy

NACo controls who can talk to your network. Security is not a feature —
it is the entire reason this project exists. Please take vulnerability
reports seriously and report them privately.

## Supported versions

| Version | Status                  |
| ------- | ----------------------- |
| 2.x     | Active — full support   |
| 1.x     | RaspISE — end-of-life, **no security fixes** |

Anyone running v1 / [RaspISE](https://github.com/ssnrshnn/raspise)
should migrate. NACo v2 is a clean break; there is no upgrade path and
no patches will be backported.

## Reporting a vulnerability

**Do not file public GitHub issues for security bugs.**

Email **<security@example.invalid>** (replace with the maintainer alias
for your fork). Include:

1. A clear description of the issue.
2. Affected versions / commits.
3. A proof-of-concept request, packet capture, or test case if possible.
4. Your suggested CVSS score and disclosure timeline.

We acknowledge within **3 working days** and aim to ship a fix within
**30 days** for High / Critical reports. We will request a CVE ID once
the fix is available.

## Threat model

NACo is designed against the following attacker classes:

| Attacker                              | Defence                                                                 |
| ------------------------------------- | ----------------------------------------------------------------------- |
| Off-link attacker spoofing RADIUS     | Per-client shared secret + RFC 3579 Message-Authenticator (mandatory)   |
| On-path attacker (BlastRADIUS / CVE-2024-3596) | Same — Access-Requests without a valid MA are dropped (`radius.require_message_authenticator: true`) |
| Compromised NAS bypassing MAB         | RFC 3580 enforced — `User-Password == User-Name == MAC`                 |
| Forged CoA / Disconnect responses     | Response-Authenticator (RFC 5176 §3.3) verified before action           |
| Compromised admin session cookie      | `session_secret` is independent of `api_secret`; cannot mint API tokens |
| Compromised admin API token           | `api_secret` is independent of `session_secret`; cannot impersonate UI  |
| Username-enumeration via login timing | Constant-time bcrypt fallback on the "unknown user" branch (`dummy_verify`) for Web, API, TACACS+ and EAP `/auth` |
| Credential stuffing / password spray  | IP rate limit (5/5 min) **and** per-username lockout (10 failures → 15 min) — Redis-backed Lua `INCR` so check + increment is atomic |
| Privilege escalation via stolen low-tier admin | Three-role RBAC (`SUPERUSER`/`OPERATOR`/`VIEWER`) — only SUPERUSER can manage admins, rotate shared secrets, or edit YAML; "last superuser" guard prevents the role-change UI from locking the system out |
| Cookie-bearing CSRF against admin UI  | Per-session HMAC token, double-submit pattern; body parser rebuilt to use `python-multipart`-style boundary parsing so URL-safe base64 tokens with `-` aren't truncated |
| Bearer-token CSRF                     | N/A — `Authorization: Bearer` is never sent automatically by the browser; CSRF middleware exempts bearer-auth POSTs explicitly |
| CSRF against captive portal           | Per-visitor cookie token (HttpOnly, SameSite=Strict)                     |
| Source-IP spoofing behind a proxy     | Honoured only when peer is in `server.trusted_proxies`                  |
| Default-permit lateral movement       | Default-deny policy engine — no implicit Permit-All                     |
| EAP REST empty / whitespace password  | `/api/v1/eap/auth` rejects before LDAP/policy; events use `Event(...)` (v2.0.1) |
| TOTP secret in URL / Referer leakage  | Pending enrollment stored in `pending_totp_secret`; `POST /auth/totp/verify` takes JSON `code` only (v2.0.1) |
| Unknown device implicit network access | Profiler-created `Device` rows default `authorized=false` until approved in UI (v2.0.1) |
| Webhook URL SSRF (admin → metadata)   | `naco.core.netutils.validate_outbound_url` refuses RFC 1918 / link-local / loopback / metadata hosts unless explicitly allowlisted in `security.webhook_allowlist` — applies to event webhooks **and** log-forwarding webhooks |
| Secret leak via log lines             | Root-logger `SecretRedactionFilter` scrubs `password=`, `bind_password=`, `secret=`, `Bearer <token>`, `eyJ...` JWTs from every log record before it reaches console / file / syslog / Graylog / webhook handlers |
| Inline-`<script>` XSS in admin UI     | Strict CSP with per-request nonce — `'unsafe-inline'` removed from `script-src` (Phase 1.8) |
| Forced HTTP downgrade                  | `Strict-Transport-Security: max-age=31536000; includeSubDomains` set on HTTPS responses (Phase 1.8) |
| TACACS+ resource exhaustion           | Global (default 256) and per-peer (default 32) connection caps configurable via `tacacs.max_connections` / `tacacs.max_connections_per_peer` (Phase 1.7) |
| Inbound `X-Request-ID` injection      | Only honoured when the immediate peer is in `server.trusted_proxies`; length-capped at 128 chars (Phase 1.9) |
| Database credential leak              | Postgres user runs unprivileged; secrets in env, not in repo; `pg_dump`/`psql` invocations switched off command-line URLs (Phase 0)             |
| Container escape via `pcap`           | Capabilities scoped to `CAP_NET_RAW` only on the profiler service        |

### Cryptographic baseline (Phase 1.10)

* Admin passwords stored as bcrypt with cost factor **13** for new hashes.
* `verify_password` reads the cost from the stored hash, so existing
  lower-cost hashes keep working.
* On every successful login, `needs_rehash()` checks the stored cost and
  silently re-hashes at the new baseline (opportunistic upgrade).
* `nacoctl rehash-passwords --dry-run` surfaces accounts still on a
  sub-baseline cost so operators can force-reset them if those users
  rarely log in.

### Forensic correlation (Phase 1.9)

Every HTTP request is tagged with an `X-Request-ID` (UUID4 hex, or
upstream-set when the proxy is trusted). The ID is:

* echoed back in the response header so clients can quote it,
* stored in a `ContextVar` so log lines from `await`-spawned children
  carry it,
* spliced onto every `logging.LogRecord` as `record.request_id` (rendered
  as `[<id>]` in every formatter), and
* available in route code via `request.state.request_id`.

## Hardening checklist

When deploying to production:

1. Rotate **all** placeholder secrets in `config.yaml` / `.env`. The
   startup banner names any insecure values it detects.
2. Pin the container to a specific digest, not `latest`.
3. Run behind Caddy (or another TLS-terminating proxy) — never expose
   the FastAPI port directly.
4. Restrict ingress on UDP 1812 / 1813 / 3799 to known NAS ranges using
   the host firewall.
5. Mount `deploy/data/postgres`, `deploy/data/redis`, and
   `deploy/data/caddy` from encrypted storage.
6. Forward logs to a tamper-resistant sink (Loki + Object Lock, or a
   SIEM) rather than relying on local disk.
7. Schedule `nacoctl backup` to off-host storage at least daily.

## Out-of-scope reports

The following are **not** vulnerabilities in NACo:

- Default placeholder passwords in `config.yaml` / `.env.example` — they
  exist explicitly to be replaced.
- Behaviour of the FreeRADIUS sidecar (report upstream to FreeRADIUS).
- Issues that only manifest in unsupported configurations (e.g. running
  as root, disabling Message-Authenticator validation).
- Findings that require an attacker to already possess valid admin
  credentials.
