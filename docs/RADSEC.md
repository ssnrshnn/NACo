# RadSec — RADIUS over TLS (RFC 6614)

Plain RADIUS trusts a UDP shared secret and MD5 — weaknesses that the
BlastRADIUS attack (CVE-2024-3596) made practical to exploit. RadSec wraps
RADIUS in mutually-authenticated TLS on **2083/tcp**, so every NAS proves
itself with a client certificate and everything on the wire is encrypted.

NACo terminates RadSec in the FreeRADIUS sidecar (compose profile `eap`,
on by default). Decrypted requests flow into the same virtual server as
UDP: EAP is handled by FreeRADIUS, PAP/MAB are delegated to NACo's policy
engine over `/api/v1/eap/*` — a RadSec NAS gets identical policy decisions
to a UDP NAS.

```
NAS ── TLS (2083/tcp, mutual auth) ──> FreeRADIUS sidecar ──> NACo policy engine
NAS ── UDP 1812 (legacy)           ──> NACo built-in RADIUS
```

## Server side

Nothing to enable — `deploy/freeradius/raddb/sites-available/radsec` is
mounted by `docker-compose.yml` whenever the `eap` profile runs, and
reuses the CA/server certificates `quickstart.sh` generates under
`deploy/freeradius/certs/`. The listener requires a client certificate
chained to that CA, so it is inert for anyone else.

To disable RadSec, remove the `sites-enabled/radsec` volume line from the
`freeradius` service.

To use an existing PKI instead of the quickstart CA, replace
`certs/ca.pem`, `certs/server.pem` and `certs/server.key` and restart the
sidecar.

## Issuing a NAS client certificate

Each RadSec NAS needs a certificate signed by the CA in
`deploy/freeradius/certs/ca.pem`:

```bash
cd deploy/freeradius/certs

# key + CSR on behalf of the NAS (or import a CSR the NAS generated)
openssl req -new -newkey rsa:2048 -nodes \
    -keyout switch01.key -subj "/CN=switch01.example.net" -out switch01.csr

# sign it with the NACo CA
openssl x509 -req -in switch01.csr -CA ca.pem -CAkey ca.key \
    -CAcreateserial -days 825 -out switch01.pem
```

Install `switch01.pem`, `switch01.key` and `ca.pem` on the NAS.

## NAS configuration notes

- Point the NAS at port **2083/tcp** on the NACo host.
- The RADIUS shared secret for RadSec is the fixed string `radsec`
  (RFC 6614 §2.3) — authentication comes from the TLS client certificate,
  not the secret.
- Cisco IOS-XE: `radius server <name>` → `transport tls port 2083` +
  trustpoint configuration. Aruba AOS-CX: `radius-server host <ip> tls`.
  Consult your vendor's RadSec guide; most enterprise gear from the last
  decade supports it.

## Verifying

```bash
# handshake with a client cert (stays connected = mutual TLS accepted)
openssl s_client -connect <host>:2083 \
    -CAfile ca.pem -cert switch01.pem -key switch01.key

# without a client certificate the connection is refused after the
# handshake — the listener never parses RADIUS from unauthenticated peers
```

Config validation: `docker compose exec freeradius radiusd -XC`.

## Kubernetes

The Helm chart's host-networked DaemonSets currently cover NACo's
built-in UDP RADIUS; running the FreeRADIUS sidecar (EAP + RadSec) in
Kubernetes is on the roadmap. Until then, terminate RadSec on the
compose-based edge or with an external FreeRADIUS pointed at NACo's
`/api/v1/eap/*` hooks.
