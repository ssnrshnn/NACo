# 802.1X and certificates

## Methods

| Method | Credentials | Good for |
|---|---|---|
| **EAP-TLS** | a client certificate | managed laptops and phones — no passwords, strongest |
| **EAP-TTLS / PAP** | user name and password inside TLS | Windows 10+, macOS, iOS, Android, Linux; works with LDAP / AD |
| **PEAP / GTC** | user name and password inside TLS | Android, Linux and supplicants that offer GTC |
| PAP | user name and password | switches and VPN gateways that authenticate users themselves |

**PEAP-MSCHAPv2 is not supported.** It needs password hashes that can be
reversed to the NT hash; NACo keeps only bcrypt hashes and checks AD
passwords with an LDAP bind. Windows supports EAP-TTLS/PAP natively since
Windows 8 — or use EAP-TLS.

All TLS-based methods use TLS 1.2 with strong ciphers.

## The EAP certificate authority

`quickstart.sh` creates a private CA in `secrets/ca/` (kept out of every
container) and signs the RADIUS server certificate with it
(`deploy/freeradius/certs/`, CN and SAN = `NACO_HOST`).

**Supplicants must check the server certificate**, or anyone can run a fake
access point and collect passwords. Configure every device to:

- trust `secrets/ca/ca.pem` — and only it — for 802.1X, and
- expect the server name `NACO_HOST`.

Distribute both with your MDM, Group Policy (*Wireless/Wired Network
Policies → Protected EAP / EAP-TTLS → Trusted Root CA, Connect to these
servers*) or a configuration profile.

## Client certificates (EAP-TLS)

```bash
scripts/issue-client-cert.sh alice           # → secrets/clients/alice.p12 (+ import password)
scripts/issue-client-cert.sh laptop-0042 730 # valid for 730 days (default 365)
```

The certificate's common name must be the name of an **enabled NACo user**;
EAP-TLS is then decided by that user's group and policies like any other
login. Create a user per machine (e.g. `laptop-0042` in group `laptops`) for
device certificates.

There is no revocation list: to cut a certificate off, disable or delete its
user in NACo — the next authentication is rejected, and if the user had a
session it is disconnected.

## Using your own PKI

To use certificates from an enterprise CA (AD CS, step-ca, …), replace the
three files in `deploy/freeradius/certs/`:

| File | Contents |
|---|---|
| `server.pem` | RADIUS server certificate (+ intermediates), with *serverAuth* |
| `server.key` | its private key, unencrypted |
| `ca.pem` | the CA certificates that issue **client** certificates (EAP-TLS) |

Then give the key to FreeRADIUS alone and restart it:

```bash
sudo chown 1812:1812 deploy/freeradius/certs/server.key
sudo chmod 600 deploy/freeradius/certs/server.key
docker compose restart freeradius
```

## Troubleshooting

- **The supplicant rejects the server** — it does not trust the CA or expects
  another server name; check the profile.
- **EAP-TLS times out** — large certificate chains need IP fragmentation
  between switch and NACo; make sure no firewall drops UDP fragments.
  (Docker Desktop on macOS/Windows drops them — use Linux.)
- **"unknown user" for EAP-TLS** — the certificate CN has no matching NACo
  user, or the user is disabled.
- **EAP fails after the password** — *Logs* shows NACo's reason; if there is
  no entry, run `docker compose logs freeradius`.
