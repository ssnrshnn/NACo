#!/usr/bin/env bash
# Issue an EAP-TLS client certificate from NACo's CA (created by quickstart.sh).
#
#   scripts/issue-client-cert.sh alice            → secrets/clients/alice.p12
#   scripts/issue-client-cert.sh laptop-42 730    (days, default 365)
#
# The certificate's CN must match a NACo user (a person, or a user you
# create for a machine) — EAP-TLS is then decided by that user's policies.
set -euo pipefail
cd "$(dirname "$0")/.."
NAME="${1:?usage: scripts/issue-client-cert.sh <user> [days]}"
DAYS="${2:-365}"
CA=secrets/ca OUT=secrets/clients
[[ -f "$CA/ca.key" ]] || { echo "no CA in $CA — run ./quickstart.sh first" >&2; exit 1; }
[[ "$NAME" =~ ^[A-Za-z0-9._@-]+$ ]] || { echo "use letters, digits and . _ @ - only" >&2; exit 2; }
umask 077
mkdir -p "$OUT"
openssl req -newkey rsa:2048 -nodes -sha256 -keyout "$OUT/$NAME.key" -out "$OUT/$NAME.csr" \
  -subj "/O=NACo/CN=$NAME" 2>/dev/null
openssl x509 -req -sha256 -days "$DAYS" -in "$OUT/$NAME.csr" -CA "$CA/ca.pem" -CAkey "$CA/ca.key" \
  -CAcreateserial -out "$OUT/$NAME.pem" \
  -extfile <(printf "basicConstraints=CA:false\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n") 2>/dev/null
PASS="$(openssl rand -base64 18 | tr -dc 'A-Za-z0-9' | cut -c1-16)"
openssl pkcs12 -export -inkey "$OUT/$NAME.key" -in "$OUT/$NAME.pem" -certfile "$CA/ca.pem" \
  -name "$NAME" -out "$OUT/$NAME.p12" -passout "pass:$PASS"
rm -f "$OUT/$NAME.csr" "$CA/ca.srl"
echo "Created $OUT/$NAME.p12 (import password: $PASS) — valid for $DAYS days."
