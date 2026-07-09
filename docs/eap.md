# 802.1X / EAP

NACo's built-in RADIUS server intentionally **does not** implement EAP —
that family is large and security-sensitive enough to deserve a dedicated
project. Instead the stack ships a FreeRADIUS sidecar, **enabled by
default**, that terminates the EAP tunnel on ports **2812/2813** and calls
NACo back over HTTP for every identity and policy decision:

```text
NAS ──RADIUS+EAP :2812──► FreeRADIUS ──REST──► NACo policy engine
                  ◄──RADIUS Accept/Reject──◄────VLAN/policy────
```

`./quickstart.sh` wires everything: bearer token, NAS shared secret, and a
self-signed CA + server certificate (replace with your PKI for
production). Supported methods: **EAP-TTLS + PAP**, **PEAP + GTC**, and
**EAP-TLS**. PEAP-MSCHAPv2 is deliberately unsupported — it requires
reversible NT password hashes, and NACo stores bcrypt only.

Port split: point 802.1X switches/SSIDs at `2812`, MAB/PAP-only gear at
`1812` (NACo built-in, Message-Authenticator enforced). Opt out with
`./quickstart.sh --no-eap` or by removing `eap` from `COMPOSE_PROFILES`
in `.env`. Details in [`deploy/freeradius/`](https://github.com/ssnrshnn/NACo/blob/main/deploy/freeradius/).

---
