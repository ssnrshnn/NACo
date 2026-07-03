#!/usr/bin/env bash
# NACo quickstart — one command from clone to running stack.
#
#   ./quickstart.sh                # core stack (naco + postgres + redis + caddy)
#   ./quickstart.sh --eap          # + FreeRADIUS sidecar for EAP-TLS/PEAP/TTLS
#   ./quickstart.sh --obs          # + Prometheus/Grafana/Loki
#   ./quickstart.sh --eap --obs    # everything
#
# On first run this generates a .env with strong random secrets. Re-running
# never overwrites an existing .env.
set -euo pipefail
cd "$(dirname "$0")"

PROFILES=()
for arg in "$@"; do
    case "$arg" in
        --eap) PROFILES+=("eap") ;;
        --obs) PROFILES+=("obs") ;;
        -h|--help) grep '^#' "$0" | head -10; exit 0 ;;
        *) echo "Unknown option: $arg (use --eap / --obs)"; exit 1 ;;
    esac
done

if ! docker compose version >/dev/null 2>&1; then
    echo "ERROR: Docker Compose v2 is required (the 'docker compose' plugin, not legacy docker-compose)." >&2
    exit 1
fi

rand() { openssl rand -hex "$1" 2>/dev/null || python3 -c "import secrets;print(secrets.token_hex($1))"; }

if [[ ! -f .env ]]; then
    echo "==> Generating .env with fresh random secrets"
    ADMIN_PASSWORD="$(rand 12)"
    sed -e "s|^NACO_DB_PASSWORD=.*|NACO_DB_PASSWORD=$(rand 24)|" \
        -e "s|^NACO_SESSION_SECRET=.*|NACO_SESSION_SECRET=$(rand 32)|" \
        -e "s|^NACO_API_SECRET=.*|NACO_API_SECRET=$(rand 32)|" \
        -e "s|^NACO_CSRF_SECRET=.*|NACO_CSRF_SECRET=$(rand 32)|" \
        -e "s|^NACO_ADMIN_PASSWORD=.*|NACO_ADMIN_PASSWORD=${ADMIN_PASSWORD}|" \
        -e "s|^NACO_EAP_BEARER_TOKEN=.*|NACO_EAP_BEARER_TOKEN=$(rand 32)|" \
        -e "s|^NACO_FREERADIUS_SHARED_SECRET=.*|NACO_FREERADIUS_SHARED_SECRET=$(rand 32)|" \
        .env.example > .env
    chmod 600 .env
    echo "    Initial admin login:  admin / ${ADMIN_PASSWORD}"
    echo "    (also stored in .env as NACO_ADMIN_PASSWORD — change it after first login)"
else
    echo "==> Using existing .env"
fi

COMPOSE_ARGS=()
for p in "${PROFILES[@]:-}"; do
    [[ -n "$p" ]] && COMPOSE_ARGS+=(--profile "$p")
done

echo "==> Starting NACo (profiles: ${PROFILES[*]:-none})"
docker compose "${COMPOSE_ARGS[@]:-}" up -d

DOMAIN="$(grep -E '^NACO_DOMAIN=' .env | cut -d= -f2)"
DOMAIN="${DOMAIN:-localhost}"
echo
echo "NACo is starting. Endpoints:"
echo "  Admin UI   https://${DOMAIN}/"
echo "  REST API   https://${DOMAIN}/api/v1/docs"
echo "  Portal     http://${DOMAIN}/portal"
[[ " ${PROFILES[*]:-} " == *" obs "* ]] && echo "  Grafana    http://localhost:3000"
echo
echo "Follow logs with:  docker compose logs -f naco"
