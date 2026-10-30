# Contributing

Thank you for helping. NACo values a small, readable code base over many
features: before a large change, open an issue to talk about it.

## Set up

```bash
python3.12 -m venv .venv && . .venv/bin/activate
pip install -r requirements.lock && pip install -e '.[dev]'
NACO_DEV=1 naco                  # http://127.0.0.1:8080 with development secrets
```

`NACO_DEV=1` replaces missing secrets with fixed development values; never
use it in production. The first administrator's password is printed in the
log (or set `NACO_ADMIN_PASSWORD`).

## Checks

Everything CI runs, locally:

```bash
ruff check .
mypy naco
pytest                           # unit and API tests (seconds)
pytest -m e2e tests/e2e          # FreeRADIUS + RADIUS/EAP clients in Docker (minutes)
pytest -m ui tests/ui            # the panel in Chromium: playwright install chromium
shellcheck quickstart.sh scripts/*.sh
```

Every API route is covered by `tests/api/test_access_matrix.py`: a new route
must be added to its role table, and state-changing routes must write to the
audit log.

## Conventions

- Python 3.12 with type hints; `ruff check .` and `mypy naco` must pass.
- Comments explain *why*; keep them short. Match the surrounding code.
- The panel is plain ES modules and CSS — no build step, no third-party
  scripts, nothing inline (the Content-Security-Policy forbids it).
- One concern per commit, message in the imperative
  (`fix(portal): …`, `feat(tacacs): …`, `docs: …`).

## Database changes

Change `naco/db/models.py`, then generate a migration:

```bash
alembic upgrade head                                   # a scratch dev.db at today's schema
alembic revision --autogenerate -m "describe the change"
```

Review it (SQLite needs batch operations; `render_as_batch` is on) and keep
`tests/test_migrations.py` green — it fails when models and migrations drift.

## Dependencies

Runtime dependencies are pinned with hashes in `requirements.lock`:

```bash
uv pip compile pyproject.toml --universal --python-version 3.12 --generate-hashes -o requirements.lock
```

Add a dependency only when the standard library or an existing one cannot
do the job. FreeRADIUS' attribute names for policy validation come from its
image: after changing `deploy/freeradius/Dockerfile`, run
`python3 scripts/update-radius-dictionary.py`.

## Releases

Bump `naco/__init__.py`, add a `## X.Y.Z — date` section to `CHANGELOG.md`,
merge, then tag `vX.Y.Z`. The release workflow runs CI again and publishes
signed images and the GitHub release.

## Security

Report vulnerabilities privately — see [SECURITY.md](SECURITY.md).
