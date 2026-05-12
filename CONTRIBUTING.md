# Contributing to NACo

Thanks for your interest in NACo. This project handles authentication
for production networks, so we hold patches to a higher bar than most
hobby code. Please read this whole document before opening a PR.

## Code of conduct

Be kind. Be precise. Engage with the actual diff, not with the contributor.

## Getting set up

```bash
git clone https://github.com/your-org/naco.git
cd naco
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

For full-stack development including Postgres, Redis, and Caddy:

```bash
docker compose -f deploy/docker-compose.yml \
               -f deploy/docker-compose.dev.yml up
```

The dev compose file mounts the working tree, runs `uvicorn --reload`,
and rebuilds on every file change.

## Test matrix

NACo ships **three** test tiers; PRs must pass tier 1 + 2. CI runs all
three.

| Tier | Command                                              | When                |
| ---- | ---------------------------------------------------- | ------------------- |
| 1. Unit         | `pytest -m "not integration"`              | Every PR             |
| 2. Lint         | `ruff check naco tests` + `mypy naco`      | Every PR             |
| 3. Integration  | `pytest -m integration tests/integration`  | CI only — needs `freeradius-utils`, Postgres, Redis |

New features must add unit tests in `tests/test_*.py`. Anything that
touches the on-wire protocols (RADIUS, TACACS+, EAP-REST) must add an
integration test under `tests/integration/`.

## Commit hygiene

- One logical change per commit.
- Subject ≤ 72 chars, imperative mood: `Fix VLAN parser for hex strings`.
- Body wrapped at 72 chars. Explain *why*, not *what*.
- Reference the issue: `Refs #123` / `Fixes #123`.

Squash before merging — we prefer a linear history.

## Code style

- Format: `ruff format naco tests` (configured in `pyproject.toml`).
- Lint: `ruff check naco tests`.
- Types: `mypy naco` — warnings allowed, errors not.
- Async-first: avoid mixing blocking I/O into async paths; if you must,
  wrap with `loop.run_in_executor`.
- No `print()` — use the loggers in `naco.core.logger`.

### Conventions

- Module docstrings are required and should describe **purpose**, not
  list contents.
- Pydantic for any external input. SQLAlchemy ORM for database. No
  hand-rolled SQL except in migrations.
- One FastAPI app per file is fine; the consolidated app is built in
  [`naco/app.py`](naco/app.py) — keep its surface small.
- Background tasks created in the lifespan must use
  `_create_monitored_task` so exceptions are surfaced.

## Database migrations

When you touch `naco/db/models.py`:

```bash
alembic revision --autogenerate -m "add column X to users"
```

Review the generated file — autogeneration misses constraints and
server-side defaults. Migrations must be reversible.

We have **one** baseline migration (`0001_initial.py`). All future
migrations are incremental; do **not** flatten history.

## Security disclosures

If you discover a vulnerability, follow [`SECURITY.md`](SECURITY.md)
instead of opening a public issue.

## Release process

NACo follows [SemVer](https://semver.org):

- **Major** — breaking config / schema / CLI changes.
- **Minor** — new features, fully backwards-compatible config / schema.
- **Patch** — bug fixes and security patches only.

Release flow:

1. Open a release PR bumping `pyproject.toml`, `naco/__init__.py`, and
   `CHANGELOG.md`.
2. Once merged, tag: `git tag -s v2.x.y -m "NACo v2.x.y"` and push.
3. CI builds the multi-arch container image and publishes to GHCR.
4. Sign the release notes with the project GPG key.

## Where to ask

- **Bugs / feature requests** — GitHub issues.
- **Security** — `security@example.invalid` (replace with your fork's
  alias).
- **Architectural questions** — open a discussion before writing code.
