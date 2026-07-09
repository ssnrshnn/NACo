# syntax=docker/dockerfile:1.7
# ─────────────────────────────────────────────────────────────────────────────
# NACo — production image
#
#   * Multi-stage: builder pre-compiles wheels, runtime ships only what's needed.
#   * Multi-arch (linux/amd64, linux/arm64) via `docker buildx`.
#   * Runs as an unprivileged user (uid 10001).
#   * Includes `pg_dump` / `psql` for `nacoctl backup`/`restore`.
#   * Exposes only the TCP HTTP port; RADIUS/TACACS+ are UDP/49 and are
#     reached via `network_mode: host` in compose.
# ─────────────────────────────────────────────────────────────────────────────
ARG PYTHON_VERSION=3.12

FROM python:${PYTHON_VERSION}-slim-bookworm AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential libffi-dev libssl-dev libpq-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY requirements.txt ./
RUN pip install --upgrade pip wheel \
 && pip install --prefix=/install -r requirements.txt

COPY pyproject.toml README.md ./
COPY naco ./naco
COPY alembic ./alembic
COPY alembic.ini ./
RUN pip install --prefix=/install --no-deps .


# ─────────────────────────────────────────────────────────────────────────────
FROM python:${PYTHON_VERSION}-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    NACO_CONFIG=/etc/naco/config.yaml \
    PATH="/usr/local/bin:${PATH}"

# Runtime libs:
#   • libpq5      — required by asyncpg / psycopg
#   • postgresql-client — pg_dump/psql for `nacoctl backup|restore`
#   • libpcap0.8  — Scapy DHCP/ARP sniffer (only effective with NET_RAW)
#   • tini        — PID-1 zombie reaper / signal proxy
#   • age         — encrypted backups (`nacoctl backup --age-recipient`)
#   • postgresql-client-16 from PGDG — must match the compose `postgres:16`
#     service; bookworm's own client is v15 and pg_dump aborts on a newer
#     server ("server version mismatch").
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      libpq5 libpcap0.8 tini ca-certificates libcap2-bin age \
 && python3 -c "import urllib.request; urllib.request.urlretrieve('https://www.postgresql.org/media/keys/ACCC4CF8.asc', '/usr/share/keyrings/pgdg.asc')" \
 && echo "deb [signed-by=/usr/share/keyrings/pgdg.asc] https://apt.postgresql.org/pub/repos/apt bookworm-pgdg main" \
      > /etc/apt/sources.list.d/pgdg.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends postgresql-client-16 \
 && rm -rf /var/lib/apt/lists/*

# The profiler sniffs DHCP/ARP with raw sockets. `cap_add: NET_RAW` on the
# container grants the capability to the *bounding set* only — a non-root
# process still can't open AF_PACKET sockets unless the binary carries file
# capabilities. The caps live on a dedicated interpreter copy
# (`python3-netraw`, used when the profiler role runs) instead of the main
# python3: a binary carrying file capabilities cannot exec under
# `allowPrivilegeEscalation: false` (no_new_privs), which would crashloop
# every capability-dropped Kubernetes pod at `exec python`.
RUN cp "$(readlink -f /usr/local/bin/python3)" /usr/local/bin/python3-netraw \
 && setcap cap_net_raw+eip /usr/local/bin/python3-netraw

# Unprivileged runtime user.
RUN groupadd --system --gid 10001 naco \
 && useradd  --system --uid 10001 --gid 10001 --no-create-home --shell /sbin/nologin naco

WORKDIR /app
COPY --from=builder /install /usr/local
COPY --from=builder /build/naco       /app/naco
COPY --from=builder /build/alembic    /app/alembic
COPY --from=builder /build/alembic.ini /app/alembic.ini

RUN mkdir -p /etc/naco /var/lib/naco /var/log/naco \
 && chown -R naco:naco /etc/naco /var/lib/naco /var/log/naco /app

USER naco:naco

EXPOSE 8080/tcp 1812/udp 1813/udp 3799/udp 49/tcp

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request,sys;\
sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/api/v1/health', timeout=3).status==200 else 1)"

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python", "-m", "naco.main"]
