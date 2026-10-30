# Configuration

NACo has two places for settings:

- **`.env`** — secrets and deployment values, read by Docker Compose
  (written by `quickstart.sh`).
- **`config/config.yaml`** — behaviour, mounted read-only into the NACo
  container together with anything else in `config/` (such as an LDAP CA).

Everything is validated when NACo starts: an unknown key, a wrong type or a
missing secret stops it with a message that names the problem
(`docker compose logs naco`). Check a change before restarting with
`docker compose run --rm naco nacoctl check-config`, then apply it with
`docker compose restart naco`.

## `.env`

| Variable | |
|---|---|
| `NACO_HOST` | name or IP address of the admin panel; also the RADIUS server certificate's name |
| `NACO_TLS` | an e-mail address (Let's Encrypt) or `internal` (Caddy's own CA) |
| `NACO_MASTER_KEY` | 32 random bytes, base64 or hex — encrypts stored secrets. **Losing it makes switch secrets, TACACS+ keys and 2FA seeds unreadable** |
| `NACO_INTERNAL_TOKEN` | 32+ characters — FreeRADIUS' credential for NACo's internal API |
| `NACO_ADMIN_PASSWORD` | the first administrator's password; only used while there is none |
| `NACO_LDAP_BIND_PASSWORD` | the LDAP service account's password |
| `NACO_IMAGE`, `NACO_RADIUS_IMAGE` | released images to run instead of local builds |
| `TZ` | container time zone (logs) |
| `NACO_SUBNET`, `NACO_IP_*` | the internal Docker network; change only if it overlaps your LAN |

Each secret may instead be read from a file by setting `<NAME>_FILE`
(for Docker secrets). Values still reading `REPLACE_ME` are refused.

## `config/config.yaml`

The shipped file lists the common settings with their defaults. All keys:

### server

| Key | Default | |
|---|---|---|
| `name` | `NACo` | shown in the panel and on the sign-in page |
| `timezone` | `UTC` | for the panel and for *time* policy conditions |
| `log_level` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `log_format` | `text` | or `json` |

### security

| Key | Default | |
|---|---|---|
| `require_totp` | `true` | administrators must use two-factor authentication |
| `session_idle_minutes` | `30` | sign-out after inactivity (5–1440) |
| `session_max_hours` | `12` | absolute session lifetime (1–168) |
| `login_max_attempts` | `10` | sign-in attempts per address … |
| `login_window_seconds` | `300` | … per this window |

### radius

| Key | Default | |
|---|---|---|
| `nas_secret_min_length` | `16` | minimum shared-secret length for RADIUS clients |
| `coa_timeout_seconds` | `2` | wait for a disconnect acknowledgement … |
| `coa_retries` | `3` | … this many times |
| `stale_session_hours` | `24` | sessions without accounting for this long are closed |

### tacacs

| Key | Default | |
|---|---|---|
| `enabled` | `true` | TACACS+ on host port 49 |
| `max_connections` | `256` | concurrent connections in total |
| `max_connections_per_client` | `32` | per device |
| `idle_timeout_seconds` | `30` | idle connections are closed |

### portal

See [guest-portal.md](guest-portal.md): `enabled`, `organization`, `terms`,
`access_code`, `session_hours` (8), `match_window_minutes` (15).

### ldap

| Key | Default | |
|---|---|---|
| `enabled` | `false` | |
| `servers` | — | `ldaps://dc1.example.com`, tried in order |
| `ca_file` | system CAs | e.g. `/etc/naco/ad-ca.pem` for `config/ad-ca.pem` |
| `start_tls` | `false` | for `ldap://` servers |
| `allow_insecure` | `false` | permit `ldap://` without StartTLS — passwords in clear text |
| `bind_dn` | — | service account (password: `NACO_LDAP_BIND_PASSWORD`) |
| `base_dn` | — | where users are searched |
| `user_filter` | `(sAMAccountName={username})` | must contain `{username}` |
| `group_attribute` | `memberOf` | |
| `nested_groups` | `false` | follow nested AD groups |
| `group_map` | `[]` | ordered `{ldap_group, group}` pairs; the first match sets the user's NACo group |
| `timeout_seconds` | `5` | |

Certificates are always verified, including the host name. A user who signs
in through LDAP for the first time is added to NACo with source *LDAP*; with a
`group_map`, their group is refreshed from the directory at every login.
Disabling such a user
in NACo blocks them without asking the directory.

### syslog

| Key | Default | |
|---|---|---|
| `enabled` | `false` | send every decision, TACACS+ event and audit record |
| `host`, `port` | —, `514` | the collector |
| `protocol` | `udp` | or `tcp` |
| `facility` | `local0` | |

Messages are RFC 5424; secrets never appear in logs.

### retention

| Key | Default | |
|---|---|---|
| `auth_log_days` | `90` | RADIUS decisions |
| `tacacs_log_days` | `90` | TACACS+ records |
| `audit_log_days` | `365` | administrator actions |
