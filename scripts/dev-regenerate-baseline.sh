#!/usr/bin/env sh
# Pre-release only: rebuild the single v3 baseline migration from the models.
# After v3.0.0 ships, schema changes get new revisions instead.
set -eu
cd "$(dirname "$0")/.."
rm -f dev.db naco/db/migrations/versions/0001_v3_baseline.py
NACO_DEV=1 alembic -c alembic.ini revision --autogenerate -m "v3 baseline" --rev-id 0001
rm -f dev.db
