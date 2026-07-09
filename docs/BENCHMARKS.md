# RADIUS throughput benchmarks

Reproducible with [`bench/radius_bench.py`](../bench/radius_bench.py), an
asyncio load generator that keeps a fixed number of authentications in
flight and reports throughput plus latency percentiles.

```bash
# server under test: single NACo replica, PostgreSQL 16 backend
python bench/radius_bench.py --host 127.0.0.1 --port 1812 \
    --secret <secret> --mac aa:bb:cc:dd:ee:ff --concurrency 32 --duration 15
```

## v2.3 asyncio-native server vs v2.2 thread-bridge server

Environment: one NACo process (defaults), PostgreSQL 16 in Docker, loopback
UDP, Linux laptop-class hardware (single node, client and server sharing
the machine). MAB = MAC Authentication Bypass with a policy match and
dynamic VLAN in the Access-Accept; every request writes an auth-log row.

### Steady state — 32 concurrent MAB authentications

| server | auth/s | p50 | p95 | p99 |
|---|---|---|---|---|
| v2.2 (pyrad thread bridge) | 319 | 99 ms | 104 ms | 109 ms |
| v2.3 (asyncio-native) | 367 | 79 ms | 108 ms | 134 ms |

Single-request latency (concurrency 1) is ~3 ms p50 on both; the flat
percentile curve of the old server is the signature of a fully serialized
handler.

### Mixed load — 32 MAB + 4 concurrent bcrypt-heavy PAP requests

PAP requests for unknown users cost one deliberate bcrypt verification
(constant-time behaviour). On the old server that work blocked the single
packet thread; on the asyncio server it only occupies its own task.

| server | MAB auth/s | MAB p50 | MAB p99 |
|---|---|---|---|
| v2.2 (pyrad thread bridge) | **14** | 2 289 ms | 2 812 ms |
| v2.3 (asyncio-native) | **330** | 83 ms | 189 ms |

Four slow password checks were enough to collapse the old server to 4 % of
its throughput and push median latency past most NAS retransmit timeouts
(commonly 2–5 s) — i.e. real deployments would see authentication storms.
The async server is effectively unaffected (23× the throughput, 27× lower
median latency under identical load).

Numbers are from 2026-07-09 on commit `437a814`. Rerun on your own
hardware before capacity planning; scale-out guidance (multiple `radius`
role replicas) lives in [`deploy/helm/naco`](../deploy/helm/naco).
