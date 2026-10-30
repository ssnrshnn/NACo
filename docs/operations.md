# Operations

All commands run in the NACo directory on the host.

## Everyday

```bash
docker compose ps                      # are all three containers up and healthy?
docker compose logs -f naco            # decisions, TACACS+, audit, errors
docker compose logs -f freeradius      # RADIUS/EAP protocol problems
docker compose restart naco            # after editing config/config.yaml
```

The panel's **System** page shows versions, uptime, database size, when
FreeRADIUS last asked NACo something, and the active settings. **Logs** and
**Audit** hold every decision and every administrator action.

## nacoctl

`nacoctl` runs inside the NACo container:

```bash
docker compose exec naco nacoctl --help
```

| Command | |
|---|---|
| `check-config` | validate `config.yaml` and the secrets |
| `reset-password <admin>` | new temporary password for an administrator (printed once) |
| `reset-totp <admin>` | remove an administrator's two-factor setup (lost phone) |
| `backup [-o FILE\|-] [--age-recipient KEY]` | online backup of the database |
| `restore FILE\|- --yes [--age-identity FILE]` | replace the database with a backup |
| `rotate-master-key --new-key-file FILE\|-` | re-encrypt stored secrets with a new master key |

`-` means standard output or input, so files move between the host and the
container without ownership problems. Changes made by `nacoctl` are recorded
in the audit log; secrets are never passed as arguments, where they would
show in the process list.

## Backups

```bash
docker compose exec naco nacoctl backup
# → /backups/naco-20261030-020000.db in the naco_backups volume
```

The backup is consistent while NACo runs. It holds password hashes and
encrypted secrets, so treat it as confidential — or encrypt it for an
[age](https://age-encryption.org) key, whose private half stays elsewhere:

```bash
docker compose exec naco nacoctl backup --age-recipient age1q…
```

Straight to a file on the host (or pipe it anywhere):

```bash
docker compose exec -T naco nacoctl backup -o - --age-recipient age1q… > naco-$(date +%F).db.age
```

Nightly, keeping two weeks in the volume (crontab of a user in the `docker` group):

```cron
0 2 * * *  cd /opt/NACo && docker compose exec -T naco nacoctl backup --age-recipient age1q… >/dev/null && docker compose exec -T naco sh -c 'ls -t /backups/naco-* | tail -n +15 | xargs -r rm --'
```

Copy backups off the host (`docker compose cp naco:/backups/<file> .`).
A restore also needs **`.env`** (the master key) and, for EAP, **`secrets/ca/`**
and **`deploy/freeradius/certs/`** — back those up once, separately and
securely.

## Restore

```bash
docker compose stop naco
docker compose run --rm -T naco nacoctl restore - --yes < naco-2026-10-30.db
docker compose start naco
```

An encrypted backup is decrypted on the way in:
`age -d -i key.txt naco-2026-10-30.db.age | docker compose run --rm -T naco nacoctl restore - --yes`.
A backup still in the volume is restored by name:
`docker compose run --rm naco nacoctl restore /backups/naco-20261030-020000.db --yes`.
The restored database is checked for integrity and migrated to the running
version. On a new host, restore `.env`, `secrets/` and
`deploy/freeradius/certs/` first, then run `./quickstart.sh`, then restore.

## Rotating the master key

```bash
docker compose exec naco nacoctl backup
openssl rand -base64 32 > new.key && chmod 600 new.key
docker compose stop naco
docker compose run --rm -T naco nacoctl rotate-master-key --new-key-file - < new.key
# put the new key into NACO_MASTER_KEY in .env, then:
docker compose up -d && shred -u new.key
```

## Locked out

- **Forgot a password** — another superuser resets it under
  *Administrators*, or: `docker compose exec naco nacoctl reset-password admin`.
- **Lost the authenticator** — use a recovery code at sign-in; otherwise
  another superuser resets 2FA, or `nacoctl reset-totp admin`.
- **Too many attempts** — sign-in is throttled per address and per account;
  wait a few minutes.

## Metrics

NACo exports Prometheus metrics on its internal port, reachable only inside
the Docker network:

| Metric | |
|---|---|
| `naco_radius_decisions_total` | authorization decisions by result and method |
| `naco_radius_accounting_total` | accounting requests |
| `naco_radius_sessions` | active RADIUS sessions |
| `naco_coa_requests_total` | Disconnect-Requests sent, by outcome |
| `naco_tacacs_requests_total` | TACACS+ requests |
| `naco_aaa_request_seconds` | latency of FreeRADIUS → NACo calls |

To scrape them, run Prometheus in the same network, e.g. in a
`docker-compose.override.yml`:

```yaml
services:
  prometheus:
    image: prom/prometheus           # pin the version you test with
    volumes: ["./prometheus.yml:/etc/prometheus/prometheus.yml:ro"]
    networks: [naco]
    ports: ["127.0.0.1:9090:9090"]
```

with the target `naco:8081` and `metrics_path: /metrics`.

## Housekeeping NACo does by itself

- Old RADIUS, TACACS+ and audit records are pruned after the retention
  periods in `config.yaml`.
- RADIUS sessions without accounting for `radius.stale_session_hours` are
  closed; expired guest registrations and administrator sessions are removed
  (and affected network sessions re-evaluated).
- The database is optimized periodically; it uses SQLite's WAL mode and stays
  in the `naco_data` volume.
