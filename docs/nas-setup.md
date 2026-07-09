# NAS / switch setup

Per-vendor configuration examples (Cisco, Aruba, Juniper, Fortinet,
MikroTik, UniFi, Extreme, Ruckus, HPE, Palo Alto) live in
[Vendor attributes](VENDORS.md). The generic recipe:

| Field             | Value                                              |
| ----------------- | -------------------------------------------------- |
| Auth Server       | `<naco-host>:1812` (PAP/CHAP/MAB) · `:2812` (802.1X/EAP) |
| Acct Server       | `<naco-host>:1813` · `:2813` (802.1X/EAP)          |
| Shared Secret     | the value from `radius.clients[].secret`           |
| CoA Server        | `<naco-host>:3799`                                 |
| Message-Authenticator | **enabled** (mandatory by default)              |

Then add the NAS in NACo so its IP and secret are known:

```bash
# Either via UI: Settings → NAS Clients → Add
# Or via API:
curl -X POST https://<naco>/api/v1/nas \
     -H "Authorization: Bearer $TOKEN" \
     -d '{"name":"core-sw01","ip_address":"10.0.0.1","secret":"…"}'
```

**TACACS+** uses the same `tacacs.clients` block:

```yaml
tacacs:
  enabled: true
  key: "tacacs_default"
  clients:
    - address: "10.0.0.1"
      key:     "tacacs_per_device_secret"
```

---
