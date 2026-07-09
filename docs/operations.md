# Day-two operations

**Policy changes propagate immediately.** When a policy is created,
edited, or deleted, NACo finds the active sessions the rule applies to and
sends their NASes RFC 5176 Disconnect-Requests, so clients re-authenticate
under the new rules instead of keeping stale access until the next
re-auth. On by default; turn off with `radius.coa_on_policy_change: false`.

**Bulk disconnect** any slice of the session table:

```bash
curl -X POST https://<naco>/api/v1/sessions/disconnect \
     -H "Authorization: Bearer $TOKEN" \
     -d '{"username": "alice"}'          # or mac_address / nas_ip / "all": true
# → Disconnect sent to 2 session(s): 2 acked, 0 failed, 0 skipped
```

**CSV import/export** for users, devices, and NAS clients:

```bash
# Inventory snapshots (exports never contain password hashes or secrets)
curl -H "Authorization: Bearer $TOKEN" https://<naco>/api/v1/users/export.csv
curl -H "Authorization: Bearer $TOKEN" https://<naco>/api/v1/devices/export.csv
curl -H "Authorization: Bearer $TOKEN" https://<naco>/api/v1/nas/export.csv

# Bulk onboarding — create-only: existing rows are skipped, never overwritten
curl -X POST -H "Authorization: Bearer $TOKEN" \
     -F "file=@users.csv" https://<naco>/api/v1/users/import
# → {"created": 40, "skipped": 2, "errors": ["line 7: …"]}
```

Import columns: users `username,password,email,full_name,group,enabled`
(`group` is a group *name* that must exist) · devices
`mac_address,hostname,device_type,notes,authorized` · NAS
`name,ip_address,secret,description,enabled` (`secret` required, ≥ 16
chars). Every row is validated by the same Pydantic models as the JSON
API.

**API tokens** give automation (CI, monitoring, scripts) long-lived
credentials without sharing an admin login. Each token carries a role
ceiling (`VIEWER` / `OPERATOR` / `SUPERUSER`) enforced by the same RBAC
as admin accounts; only a SHA-256 digest is stored, and the raw value is
shown once, at creation. Tokens cannot mint or revoke other tokens.

```bash
curl -X POST https://<naco>/api/v1/tokens \
     -H "Authorization: Bearer $ADMIN_JWT" \
     -d '{"name": "ci-deploy", "role": "OPERATOR", "expires_days": 90}'
# → {"token": "naco_…", …}    ← store it; it is never shown again

curl https://<naco>/api/v1/users -H "Authorization: Bearer naco_…"
```

**Synthetic AAA probes** exercise the full protocol path (socket →
parsing → policy engine → reply) — what a NAS actually experiences,
beyond what `/health/*` can see:

```bash
docker compose exec naco nacoctl test-radius            # PAP Access-Request
docker compose exec naco nacoctl test-tacacs            # TACACS+ PAP login
# RADIUS probe: Access-Reject in 4.2 ms
```

With the default `--expect any`, a Reject is healthy — it proves the
server parsed the request and evaluated policy. Use
`--expect accept --username u --password p` to also validate a real
credential. Exit codes are monitoring-friendly: `0` expectation met,
`1` server answered with the other outcome, `2` no response. The probe's
source IP must be a registered NAS (the in-container `127.0.0.1` works
out of the box once a localhost NAS exists).

---
