# Observability

The `obs` compose profile spins up Prometheus, Grafana, Loki, and Promtail
pre-wired to NACo:

- **Prometheus** scrapes `https://<naco>/api/v1/metrics` every 15 s.
- **Loki** ingests container logs via Promtail (`naco`, `freeradius`,
  `caddy`, …).
- **Grafana** is provisioned with a default NACo dashboard:
  authentication rate, RADIUS / TACACS+ latency, active sessions, policy
  rejections.

```bash
docker compose --profile obs up -d
open http://localhost:3000   # admin / ${GRAFANA_ADMIN_PASSWORD}
```

**Health probes** are split so orchestrators restart NACo only when NACo
itself is broken:

| Endpoint               | Purpose                                                        |
| ---------------------- | -------------------------------------------------------------- |
| `/api/v1/health/live`  | Liveness — 200 whenever the process serves HTTP; touches no dependency. Point restart probes here. |
| `/api/v1/health/ready` | Readiness — 200 only when the database answers; 503 otherwise. Redis state is reported but non-gating. Gate traffic here. |
| `/api/v1/health`       | Back-compat alias of `ready`.                                  |

---
