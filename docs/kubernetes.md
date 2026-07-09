# Kubernetes (Helm)

Deploys [NACo](https://github.com/ssnrshnn/naco) on Kubernetes as
**horizontally-scalable roles** instead of one all-in-one process:

| Role       | Workload            | Networking            | Scale                       |
|------------|---------------------|-----------------------|-----------------------------|
| `api`      | Deployment          | ClusterIP + Ingress   | N replicas (HPA)            |
| `workers`  | Deployment          | ClusterIP             | **1** (singleton loops)     |
| `radius`   | DaemonSet           | `hostNetwork` (UDP)   | 1 per selected node         |
| `tacacs`   | DaemonSet           | `hostNetwork` (TCP)   | 1 per selected node         |
| `profiler` | DaemonSet           | `hostNetwork` + NET_RAW | 1 per selected node       |

The split is driven by the `NACO_ROLES` env var (see `naco/config`): every pod
runs the same image, and the chart sets the role per workload. The HTTP server,
Prometheus metrics collector, and policy-cache invalidation subscriber run in
**every** pod; RADIUS/TACACS/profiler and the maintenance loops are gated by role.

Why this shape:

- **API scales freely.** It is stateless — session/JWT/CSRF are signed tokens,
  rate-limiting and policy-cache invalidation go through Redis — so you can run
  as many replicas as you like behind a Service/Ingress with an HPA.
- **`workers` is a singleton.** Guest-session expiry, log retention, stale
  session cleanup and webhook dispatch must not run in parallel, so they live in
  a single-replica Deployment (`strategy: Recreate`).
- **RADIUS/TACACS use `hostNetwork`.** NAS devices address them by node IP and
  NACo sees the real client source address (essential for per-NAS policy and
  CoA). They are DaemonSets so every "auth node" carries them.

## Prerequisites

- Kubernetes 1.23+ and Helm 3.8+.
- An **external** PostgreSQL and Redis (this chart does not bundle them). Redis
  is required when running more than one API replica.
- For `serviceMonitor.enabled`: the Prometheus Operator CRDs.

## Install

```bash
# 1. Create the credentials Secret yourself (recommended for production).
kubectl create namespace naco
kubectl -n naco create secret generic naco-secrets \
  --from-literal=NACO_DB_URL='postgresql+asyncpg://naco:PASS@pg-host:5432/naco' \
  --from-literal=NACO_REDIS_URL='redis://redis-host:6379/0' \
  --from-literal=NACO_SESSION_SECRET="$(openssl rand -hex 32)" \
  --from-literal=NACO_API_SECRET="$(openssl rand -hex 32)" \
  --from-literal=NACO_CSRF_SECRET="$(openssl rand -hex 32)" \
  --from-literal=NACO_ADMIN_PASSWORD="$(openssl rand -base64 24)" \
  --from-literal=NACO_MASTER_KEY="$(openssl rand -hex 32)"

# 2. Install, pointing at that Secret.
helm install naco ./deploy/helm/naco \
  --namespace naco \
  --set secrets.existingSecret=naco-secrets
```

For a quick trial you can instead let the chart create the Secret from
`secrets.values` — but never commit real values; override them via
`--set`, `--set-file`, sealed-secrets, or an external secrets operator.

## Common configuration

```yaml
# values-prod.yaml
image:
  tag: "2.2.0"

secrets:
  existingSecret: naco-secrets

api:
  autoscaling: { enabled: true, minReplicas: 3, maxReplicas: 20 }
  ingress:
    enabled: true
    className: nginx
    hosts:
      - host: naco.corp.example.com
        paths: [{ path: /, pathType: Prefix }]
    tls:
      - secretName: naco-tls
        hosts: [naco.corp.example.com]

radius:
  enabled: true
  nodeSelector: { naco.io/role: auth }   # pin RADIUS to labelled nodes

tacacs:
  enabled: true
  nodeSelector: { naco.io/role: auth }

serviceMonitor:
  enabled: true
```

```bash
helm upgrade --install naco ./deploy/helm/naco -n naco -f values-prod.yaml
```

## Notes & caveats

- **Distinct host ports.** Each host-networked role still serves HTTP for
  health/metrics, so they use distinct host ports (`radius.httpPort=8080`,
  `tacacs.httpPort=8081`, `profiler.httpPort=8082`) to avoid colliding when
  scheduled on the same node. Change them if those ports are taken.
- **DaemonSet metrics.** The bundled `ServiceMonitor` scrapes the API Service.
  To scrape RADIUS/TACACS/profiler pods, add a `PodMonitor` targeting the
  `app.kubernetes.io/component` label and the `http` port (Prometheus Operator).
- **Migrations.** A `pre-install`/`pre-upgrade` hook Job runs
  `nacoctl db-upgrade` (`alembic upgrade head`) before any new pod starts —
  the safe pattern for multi-replica rollouts (`migrations.enabled`, default
  true). The app also runs an idempotent `init_db()` on startup as a safety net.
- **DB connection pool.** Each replica keeps its own pool
  (`config.database.pool_size` + `max_overflow`). Keep
  `replicas × (pool_size + max_overflow)` under Postgres `max_connections`, or
  set `config.database.pgbouncer: true` and point `NACO_DB_URL` at a PgBouncer
  transaction-pooling endpoint (the chart then uses `NullPool` and disables the
  asyncpg prepared-statement cache automatically).
- **Read-only rootfs.** All roles run non-root (uid 10001) with a read-only
  root filesystem and an `emptyDir` mounted at `/tmp`.

## Values

See [`values.yaml`](https://github.com/ssnrshnn/NACo/blob/main/deploy/helm/naco/values.yaml) for the full, commented list.
