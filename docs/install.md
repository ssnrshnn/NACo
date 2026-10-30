# Install and upgrade

## Requirements

- A Linux host — a VM is fine — with a fixed IP address. 2 CPU cores and
  2 GB RAM serve about 5,000 devices; the database grows by roughly
  1 MB per 3,000 authentications and old logs are pruned automatically.
- Docker Engine 24 or newer with the Compose plugin (`docker compose`),
  and `openssl`.
- Reachability: switches → host on UDP 1812/1813 and TCP 49; host → switches
  on UDP 3799 (CoA); administrators → TCP 443; guests → TCP 80.
- Correct time (NTP): two-factor codes and certificates depend on it.

Docker Desktop on macOS or Windows is good for a look around, not for
production: its port forwarding hides the switches' real addresses and drops
fragmented UDP, which large EAP-TLS packets need.

## Quickstart

```bash
git clone https://github.com/ssnrshnn/NACo.git && cd NACo
./quickstart.sh
```

It asks for the name or IP address administrators will use, and — for a
public DNS name — an e-mail address for Let's Encrypt. Without one, Caddy
issues the HTTPS certificate from its own CA. Non-interactive:

```bash
./quickstart.sh --host nac.example.com --email it@example.com
./quickstart.sh --host 10.0.0.5 --yes
```

What it creates:

| Path | Contents | Keep it |
|---|---|---|
| `.env` | host name, TLS mode, `NACO_MASTER_KEY`, `NACO_INTERNAL_TOKEN`, initial admin password (mode 0600) | **private**, back it up |
| `secrets/ca/` | the EAP certificate authority (`ca.key`, `ca.pem`) | **private**, back it up |
| `deploy/freeradius/certs/` | RADIUS server certificate and key, CA certificate | key readable only by FreeRADIUS |
| Docker volumes `naco_naco_data`, `naco_naco_backups`, `naco_caddy_data` | database, backups, Caddy's certificates | |

Running `quickstart.sh` again is safe: existing secrets, certificates and
data are kept; it rebuilds and restarts.

The first sign-in uses `admin` and the password printed at the end (also in
`.env` as `NACO_ADMIN_PASSWORD`; it is only used while the database has no
administrator). NACo then asks for a new password and sets up two-factor
authentication; until that is done nothing else is reachable.

### Trusting the HTTPS certificate

With Let's Encrypt there is nothing to do. With Caddy's own CA, export its
root certificate once and install it on administrators' machines (or in
your organization's trust store):

```bash
docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt naco-root.crt
```

The root is named *NACo Root* followed by a number, so it never collides
with another Caddy's root that a machine already trusts. Installations
from 3.0.0 or 3.0.1 still use Caddy's default name, which makes Firefox
report `SEC_ERROR_BAD_SIGNATURE` on machines that trust another Caddy root.
To give them a new CA (administrators then trust the new root):

```bash
docker compose exec caddy rm -rf /data/caddy/pki /data/caddy/certificates/local
docker compose restart caddy
```

### Changing the address later

Edit `NACO_HOST` (and `NACO_TLS`) in `.env`, then `docker compose up -d`.
The RADIUS server certificate names the old address; that only matters to
supplicants that check the server name — re-create it by moving
`deploy/freeradius/certs/` aside and running `./quickstart.sh` again (the CA
stays the same, so devices keep trusting it).

## Released images

Instead of building locally, use the signed images from GitHub Container
Registry, both with the same version. On a new host:

```bash
NACO_IMAGE=ghcr.io/ssnrshnn/naco:3.1.0 \
NACO_RADIUS_IMAGE=ghcr.io/ssnrshnn/naco-freeradius:3.1.0 ./quickstart.sh
```

`quickstart.sh` writes both into `.env` and pulls instead of building; on an
existing installation, change them in `.env` and run it again. Verify a
signature with:

```bash
cosign verify ghcr.io/ssnrshnn/naco:3.1.0 \
  --certificate-identity-regexp '^https://github.com/ssnrshnn/NACo/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Firewall

Allow only what the table in the README lists. NACo's internal API (8081)
and its web port (8080) are never published; Caddy is the only way in over
HTTP(S). Ports are published on **IPv4** only: Docker would carry IPv6
connections to the IPv4 containers through a proxy that hides the client's
address, which NACo needs to recognize switches, guests and sign-in sources. If the host runs a firewall such as `ufw`, remember that Docker
publishes ports through its own iptables rules — restrict sources with
Docker's `DOCKER-USER` chain or an upstream firewall.

## Upgrading

```bash
docker compose exec naco nacoctl backup        # always first
git pull                                       # or change the image tags in .env
./quickstart.sh
```

Database migrations run automatically when NACo starts. Read
[CHANGELOG.md](../CHANGELOG.md) before a major version.

## Uninstalling

```bash
docker compose down            # keeps the data volumes
docker compose down -v         # removes the database, backups and Caddy's certificates
```
