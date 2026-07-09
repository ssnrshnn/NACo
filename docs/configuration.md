# Configuration

NACo reads YAML from the path in `$NACO_CONFIG` (default
`/etc/naco/config.yaml`). Every section is validated by Pydantic — startup
fails loudly on unknown keys or wrong types.

The deployment config lives at [`config/config.yaml`](https://github.com/ssnrshnn/NACo/blob/main/config/config.yaml)
in the repository root — Docker Compose mounts that directory to
`/etc/naco`, so edits take effect on the next `docker compose restart naco`.
The full schema is defined by the Pydantic models in
[`naco/config/__init__.py`](https://github.com/ssnrshnn/NACo/blob/main/naco/config/__init__.py) — that file is the
source of truth.

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
| `radius.coa_on_policy_change`       | Disconnect affected sessions when a policy changes    | `true`                                   |
| `eap.bearer_token`                  | Auth token for FreeRADIUS `rlm_rest` callbacks       | *unset until you enable EAP*             |

Every secret can also be passed via `${NACO_*}` environment variables (see
[`.env.example`](https://github.com/ssnrshnn/NACo/blob/main/.env.example)).

---
