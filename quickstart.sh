#!/usr/bin/env bash
# NACo quickstart — one command from clone to running stack.
#
#   ./quickstart.sh                # naco + postgres + redis + caddy + FreeRADIUS (EAP)
#   ./quickstart.sh --no-eap       # skip the FreeRADIUS 802.1X sidecar
#   ./quickstart.sh --obs          # + Prometheus/Grafana/Loki
#
# On first run this generates a .env with strong random secrets and a
# self-signed EAP TLS certificate authority. Re-running never overwrites
# an existing .env or existing certificates.
set -euo pipefail
cd "$(dirname "$0")"

EAP=1
OBS=0
for arg in "$@"; do
    case "$arg" in
        --no-eap) EAP=0 ;;
        --eap)    EAP=1 ;;   # kept for backwards compatibility (now the default)
        --obs)    OBS=1 ;;
        -h|--help) grep '^#' "$0" | head -10; exit 0 ;;
        *) echo "Unknown option: $arg (use --no-eap / --obs)"; exit 1 ;;
    esac
done

PROFILES=""
[[ "$EAP" == 1 ]] && PROFILES="eap"
[[ "$OBS" == 1 ]] && PROFILES="${PROFILES:+$PROFILES,}obs"

# ── Preflight ───────────────────────────────────────────────────────────────
err() { echo "ERROR: $*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 \
    || err "Docker is required — https://docs.docker.com/engine/install/"
docker info >/dev/null 2>&1 \
    || err "Docker daemon is not running (or you lack permission — try adding your user to the 'docker' group)"
docker compose version >/dev/null 2>&1 \
    || err "Docker Compose v2 is required (the 'docker compose' plugin, not legacy docker-compose)"
command -v openssl >/dev/null 2>&1 \
    || err "openssl is required (used to generate secrets and EAP certificates)"

# Warn (don't fail) about ports something else is already holding.
if command -v ss >/dev/null 2>&1; then
    for spec in "tcp 443" "tcp 8080" "udp 1812" "udp 1813" "udp 3799"; do
        proto=${spec% *}; port=${spec#* }
        flag="-tln"; [[ "$proto" == udp ]] && flag="-uln"
        if ss "$flag" 2>/dev/null | grep -qE "[:.]${port}\b"; then
            echo "WARNING: ${proto}/${port} is already in use — NACo will fail to bind it unless that service stops."
        fi
    done
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
        -e "s|^NACO_MASTER_KEY=.*|NACO_MASTER_KEY=$(rand 32)|" \
        -e "s|^NACO_EAP_BEARER_TOKEN=.*|NACO_EAP_BEARER_TOKEN=$(rand 32)|" \
        -e "s|^NACO_FREERADIUS_SHARED_SECRET=.*|NACO_FREERADIUS_SHARED_SECRET=$(rand 32)|" \
        -e "s|^#*COMPOSE_PROFILES=.*|COMPOSE_PROFILES=${PROFILES}|" \
        .env.example > .env
    chmod 600 .env
    echo "    Initial admin login:  admin / ${ADMIN_PASSWORD}"
    echo "    (also stored in .env as NACO_ADMIN_PASSWORD — change it after first login)"
else
    echo "==> Using existing .env"
    if [[ -n "$PROFILES" ]] && grep -qE "^COMPOSE_PROFILES=" .env; then
        sed -i "s|^COMPOSE_PROFILES=.*|COMPOSE_PROFILES=${PROFILES}|" .env
    elif [[ -n "$PROFILES" ]]; then
        printf '\nCOMPOSE_PROFILES=%s\n' "$PROFILES" >> .env
    fi
    # Upgrades from < v2.2: add the secrets-at-rest master key if missing.
    if ! grep -qE "^NACO_MASTER_KEY=" .env; then
        echo "==> Adding NACO_MASTER_KEY to .env (encrypts stored secrets at rest)"
        printf '\nNACO_MASTER_KEY=%s\n' "$(rand 32)" >> .env
        echo "    Run 'docker compose exec naco nacoctl encrypt-secrets' after start"
        echo "    to encrypt existing rows. BACK THIS KEY UP with your .env."
    fi
fi

# ── EAP TLS certificates ────────────────────────────────────────────────────
# Self-signed CA + server certificate for FreeRADIUS (EAP-TLS/TTLS/PEAP).
# Replace with PKI-issued certs for production; supplicants must trust ca.pem.
CERTDIR="deploy/freeradius/certs"
if [[ "$EAP" == 1 && ! -f "$CERTDIR/server.pem" ]]; then
    echo "==> Generating self-signed EAP certificates in $CERTDIR"
    mkdir -p "$CERTDIR"
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
        -keyout "$CERTDIR/ca.key" -out "$CERTDIR/ca.pem" \
        -subj "/O=NACo/CN=NACo EAP CA" >/dev/null 2>&1
    openssl req -newkey rsa:2048 -nodes \
        -keyout "$CERTDIR/server.key" -out "$CERTDIR/server.csr" \
        -subj "/O=NACo/CN=naco-eap" >/dev/null 2>&1
    openssl x509 -req -days 825 \
        -in "$CERTDIR/server.csr" -CA "$CERTDIR/ca.pem" -CAkey "$CERTDIR/ca.key" \
        -CAcreateserial -out "$CERTDIR/server.pem" \
        -extfile <(printf "extendedKeyUsage=serverAuth\nsubjectAltName=DNS:naco-eap") >/dev/null 2>&1
    rm -f "$CERTDIR/server.csr" "$CERTDIR/ca.srl"
    # RFC 7919 ffdhe2048 — standardised group, avoids minutes of `openssl dhparam`
    cat > "$CERTDIR/dh" <<'DHEOF'
-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
ssbzSibBsu/6iGtCOGEoXJf//////////wIBAg==
-----END DH PARAMETERS-----
DHEOF
    # FreeRADIUS runs as UID 101 (radiusd) in the container — keys must be readable.
    chmod 644 "$CERTDIR"/ca.pem "$CERTDIR"/server.pem "$CERTDIR"/dh
    chmod 640 "$CERTDIR"/ca.key "$CERTDIR"/server.key
    chgrp 101 "$CERTDIR"/server.key 2>/dev/null || chmod 644 "$CERTDIR"/server.key
    echo "    CA cert for supplicants:  $CERTDIR/ca.pem"
fi

# Prefer the prebuilt GHCR image over a local multi-minute build; compose
# falls back to `build:` automatically when the pull fails (e.g. offline).
echo "==> Pulling images (falls back to a local build if unavailable)"
COMPOSE_PROFILES="$PROFILES" docker compose pull --ignore-buildable 2>/dev/null || true
COMPOSE_PROFILES="$PROFILES" docker compose pull naco 2>/dev/null \
    || echo "    Prebuilt image not available — building locally (one-time, a few minutes)"

echo "==> Starting NACo (profiles: ${PROFILES:-none})"
COMPOSE_PROFILES="$PROFILES" docker compose up -d

if command -v curl >/dev/null 2>&1; then
    echo -n "==> Waiting for NACo to become healthy"
    for _ in $(seq 1 30); do
        if curl -fsS -m 2 http://127.0.0.1:8080/api/v1/health >/dev/null 2>&1; then
            echo " — up!"
            break
        fi
        echo -n "."
        sleep 2
    done
    echo
fi

DOMAIN="$(grep -E '^NACO_DOMAIN=' .env | cut -d= -f2)"
DOMAIN="${DOMAIN:-localhost}"
echo
echo "NACo is starting. Endpoints:"
echo "  Admin UI   https://${DOMAIN}/"
echo "  REST API   https://${DOMAIN}/api/v1/docs"
echo "  Portal     http://${DOMAIN}/portal"
echo "  RADIUS     ${DOMAIN}:1812/1813 (PAP/CHAP/MAB)   CoA 3799"
[[ "$EAP" == 1 ]] && echo "  802.1X     ${DOMAIN}:2812/2813 (EAP-TLS/TTLS/PEAP via FreeRADIUS)"
[[ "$OBS" == 1 ]] && echo "  Grafana    http://localhost:3000"
echo
echo "Follow logs with:  docker compose logs -f naco"
