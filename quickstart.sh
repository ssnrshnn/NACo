#!/usr/bin/env bash
# NACo quickstart: secrets, certificates, build and start — then how to sign in.
#
#   ./quickstart.sh                         asks for the address to use
#   ./quickstart.sh --host nac.example.com --email it@example.com
#   ./quickstart.sh --host 10.0.0.5 --yes  (IP → Caddy's own CA)
#
# Safe to re-run: an existing .env and existing certificates are kept.
set -euo pipefail
cd "$(dirname "$0")"

HOST="" EMAIL="" YES=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) HOST="$2"; shift 2 ;;
    --email) EMAIL="$2"; shift 2 ;;
    --yes|-y) YES=1; shift ;;
    -h|--help) sed -n '2,8p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

command -v docker >/dev/null || fail "Docker is required — https://docs.docker.com/engine/install/"
docker info >/dev/null 2>&1 || fail "the Docker daemon is not running (or you may not use it)"
docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 is required (the 'docker compose' plugin)"
command -v openssl >/dev/null || fail "openssl is required"

is_ip() { [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ || "$1" == *:* ]]; }
default_host() {
  { hostname -I 2>/dev/null | awk '{print $1}'; ipconfig getifaddr en0 2>/dev/null; } | grep -m1 . || echo localhost
}

# ── .env ────────────────────────────────────────────────────────────────────
if [[ ! -f .env ]]; then
  if [[ -z "$HOST" ]]; then
    HOST="$(default_host)"
    if [[ $YES -eq 0 && -t 0 ]]; then
      read -r -p "Address administrators will use [$HOST]: " answer
      HOST="${answer:-$HOST}"
    fi
  fi
  if [[ -z "$EMAIL" && $YES -eq 0 && -t 0 ]] && ! is_ip "$HOST" && [[ "$HOST" == *.* ]]; then
    read -r -p "E-mail for a Let's Encrypt certificate (empty = NACo's own CA): " EMAIL
  fi
  TLS="${EMAIL:-internal}"
  say "Writing .env with fresh secrets"
  umask 077
  cat > .env <<ENV
NACO_HOST=$HOST
NACO_TLS=$TLS
NACO_MASTER_KEY=$(openssl rand -base64 32)
NACO_INTERNAL_TOKEN=$(openssl rand -hex 32)
NACO_ADMIN_PASSWORD=$(openssl rand -base64 24 | tr -dc 'A-Za-z0-9' | cut -c1-20)
NACO_LDAP_BIND_PASSWORD=
TZ=${TZ:-UTC}
NACO_SUBNET=172.30.0.0/24
NACO_IP_CADDY=172.30.0.10
NACO_IP_RADIUS=172.30.0.11
NACO_IP_APP=172.30.0.12
NACO_IMAGE=${NACO_IMAGE:-}
NACO_RADIUS_IMAGE=${NACO_RADIUS_IMAGE:-}
ENV
  umask 022
else
  say "Using the existing .env"
fi
env_get() { grep -E "^$1=" .env | tail -1 | cut -d= -f2- || true; }
HOST="$(env_get NACO_HOST)"
TLS="$(env_get NACO_TLS)"
ADMIN_PASSWORD="$(env_get NACO_ADMIN_PASSWORD)"
RADIUS_IMAGE="$(env_get NACO_RADIUS_IMAGE)"

# ── EAP certificates ────────────────────────────────────────────────────────
CA=secrets/ca CERTS=deploy/freeradius/certs
if [[ ! -f "$CERTS/server.pem" ]]; then
  say "Creating an EAP certificate authority and the RADIUS server certificate"
  mkdir -p "$CA" "$CERTS"
  chmod 700 secrets "$CA"
  if [[ ! -f "$CA/ca.key" ]]; then
    openssl req -x509 -newkey rsa:3072 -nodes -days 3650 -sha256 -keyout "$CA/ca.key" -out "$CA/ca.pem" \
      -subj "/O=NACo/CN=NACo EAP CA" -addext "basicConstraints=critical,CA:true" \
      -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
    chmod 600 "$CA/ca.key"
  fi
  san="DNS:$HOST"; is_ip "$HOST" && san="IP:$HOST"
  openssl req -newkey rsa:3072 -nodes -sha256 -keyout "$CERTS/server.key" -out "$CERTS/server.csr" \
    -subj "/O=NACo/CN=$HOST" 2>/dev/null
  openssl x509 -req -sha256 -days 825 -in "$CERTS/server.csr" -CA "$CA/ca.pem" -CAkey "$CA/ca.key" \
    -CAcreateserial -out "$CERTS/server.pem" \
    -extfile <(printf "basicConstraints=CA:false\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=%s\n" "$san") 2>/dev/null
  cp "$CA/ca.pem" "$CERTS/ca.pem"
  rm -f "$CERTS/server.csr" "$CA/ca.srl"
  NEED_CHOWN=1
fi

# ── build and start ─────────────────────────────────────────────────────────
if [[ -n "$(env_get NACO_IMAGE)" ]]; then
  say "Pulling the released images"
  docker compose pull -q naco freeradius caddy
else
  say "Building images (first run takes a few minutes)"
  docker compose build --pull -q
  docker compose pull -q caddy
fi
if [[ "${NEED_CHOWN:-0}" == 1 ]]; then
  # FreeRADIUS runs as uid 1812: its key must be readable by it and nobody else.
  docker run --rm --user 0 --entrypoint sh -v "$PWD/$CERTS:/c" "${RADIUS_IMAGE:-naco-freeradius:local}" \
    -c 'chown 1812:1812 /c/server.key && chmod 600 /c/server.key && chmod 644 /c/*.pem'
fi
say "Starting NACo"
docker compose up -d --wait

cat <<DONE

  NACo is running.

  Admin panel      https://$HOST/
  First sign-in    admin / $ADMIN_PASSWORD   (you choose a new password and set up 2FA)
  RADIUS           $HOST:1812 (auth) and :1813 (accounting) — add switches under "RADIUS clients"
  TACACS+          $HOST:49
  Guest portal     http://$HOST/portal
  EAP CA (devices) $CA/ca.pem — make supplicants trust it; client certificates:
                   scripts/issue-client-cert.sh <user>
DONE
if [[ "$TLS" == internal ]]; then
  cat <<DONE
  HTTPS uses NACo's own CA. Export it and trust it on admin machines:
                   docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt naco-root.crt
DONE
fi
echo
