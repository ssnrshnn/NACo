#!/usr/bin/env bash
# NACo one-liner installer.
#
#   curl -fsSL https://raw.githubusercontent.com/ssnrshnn/NACo/main/install.sh | bash
#
# Clones (or updates) the repository into ./naco and hands off to
# quickstart.sh, which generates secrets + EAP certificates and starts the
# Docker Compose stack. Extra arguments are passed through:
#
#   curl -fsSL …/install.sh | bash -s -- --no-eap
set -euo pipefail

REPO="${NACO_REPO:-https://github.com/ssnrshnn/NACo.git}"
DIR="${NACO_DIR:-naco}"

err() { echo "ERROR: $*" >&2; exit 1; }

command -v git >/dev/null 2>&1 || err "git is required"
command -v docker >/dev/null 2>&1 || err "Docker is required — https://docs.docker.com/engine/install/"
docker info >/dev/null 2>&1 || err "Docker daemon is not running (or you lack permission — try adding your user to the 'docker' group)"
docker compose version >/dev/null 2>&1 || err "Docker Compose v2 is required (the 'docker compose' plugin)"

if [[ -d "$DIR/.git" ]]; then
    echo "==> Updating existing checkout in ./$DIR"
    git -C "$DIR" pull --ff-only
else
    echo "==> Cloning NACo into ./$DIR"
    git clone --depth 1 "$REPO" "$DIR"
fi

cd "$DIR"
exec ./quickstart.sh "$@"
