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
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      libpq5 postgresql-client libpcap0.8 tini ca-certificates \
 && rm -rf /var/lib/apt/lists/*

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
