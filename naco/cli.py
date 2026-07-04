"""NACo CLI management commands.

Usage:
    nacoctl reset-password --username admin
    nacoctl check-config
    nacoctl backup --output /tmp/naco-backup.sql.gz
    nacoctl restore --input /tmp/naco-backup.sql.gz
    nacoctl db-upgrade
"""
from __future__ import annotations

import asyncio
import shutil
import sys
from pathlib import Path

import click
from sqlalchemy.engine import make_url

from naco.config import get_config


def _sqlite_path_from_url(db_url: str) -> Path:
    """Extract the filesystem path from a SQLite URL, or exit with error."""
    try:
        url = make_url(db_url)
    except Exception as exc:
        click.secho(f"Invalid database URL: {exc}", fg="red")
        sys.exit(1)
    if url.get_backend_name() != "sqlite":
        click.secho("Only SQLite databases are supported for this command.", fg="red")
        sys.exit(1)
    # url.database is the path portion (None for :memory:)
    if not url.database:
        click.secho("In-memory databases cannot be backed up/restored.", fg="red")
        sys.exit(1)
    return Path(url.database)


@click.group()
def cli():
    """NACo management commands."""


def _check_deep(cfg) -> None:
    """Test database and Redis connectivity, reporting results to stdout."""
    click.echo()
    click.secho("Deep connectivity checks:", bold=True)

    # ── Database ──────────────────────────────────────────────────────
    db_ok = False
    try:
        async def _probe_db():
            from sqlalchemy import text
            from sqlalchemy.ext.asyncio import create_async_engine as _cae

            engine = _cae(cfg.database.url, pool_pre_ping=True)
            async with engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
            await engine.dispose()

        asyncio.run(_probe_db())
        click.secho("  Database    : reachable", fg="green")
        db_ok = True
    except Exception as exc:
        click.secho(f"  Database    : UNREACHABLE — {exc}", fg="red")

    # ── Redis ─────────────────────────────────────────────────────────
    redis_ok = False
    redis_url = cfg.cache.url
    if redis_url:
        try:
            import redis as _redis
            client = _redis.Redis.from_url(redis_url, decode_responses=True, socket_timeout=3.0)
            client.ping()
            client.close()
            click.secho("  Redis       : reachable", fg="green")
            redis_ok = True
        except Exception as exc:
            click.secho(f"  Redis       : UNREACHABLE — {exc}", fg="red")
    else:
        click.secho("  Redis       : not configured (cache.url is empty)", fg="yellow")

    if not db_ok or not redis_ok:
        click.echo()
        click.secho("One or more deep checks failed.", fg="red")
        sys.exit(1)
    else:
        click.echo()
        click.secho("All deep checks passed.", fg="green")


@cli.command("check-config")
@click.option(
    "--deep/--no-deep", default=False,
    help="Also test database and Redis connectivity (requires running services).",
)
def check_config(deep: bool):
    """Validate the configuration file and print a summary.

    With ``--deep``, also verifies that PostgreSQL / SQLite and Redis are
    reachable. This is useful as a pre-flight check before ``docker compose
    up`` or as a liveness probe from a scheduler.
    """
    try:
        cfg = get_config()
    except Exception as exc:
        click.secho(f"Config error: {exc}", fg="red")
        sys.exit(1)

    click.secho("Configuration OK", fg="green")
    click.echo(f"  Server name : {cfg.server.name}")
    click.echo(f"  Database    : {cfg.database.url}")
    click.echo(f"  RADIUS      : {'enabled' if cfg.radius.enabled else 'disabled'}")
    click.echo(f"  TACACS+     : {'enabled' if cfg.tacacs.enabled else 'disabled'}")
    click.echo(f"  Portal      : {'enabled' if cfg.portal.enabled else 'disabled'}")
    click.echo(f"  Profiler    : {'enabled' if cfg.profiler.enabled else 'disabled'}")

    _PLACEHOLDERS = {
        "change_me", "",
        "CHANGE_ME_session_secret_32_bytes_hex",
        "CHANGE_ME_api_secret_32_bytes_hex",
        "CHANGE_ME_csrf_secret_32_bytes_hex",
        "change_me_session_secret", "change_me_api_secret", "change_me_csrf_secret",
    }
    has_warnings = False
    if cfg.server.session_secret in _PLACEHOLDERS:
        click.secho("  WARNING: server.session_secret is still a placeholder!", fg="yellow")
        has_warnings = True
    if cfg.server.api_secret in _PLACEHOLDERS:
        click.secho("  WARNING: server.api_secret is still a placeholder!", fg="yellow")
        has_warnings = True
    if cfg.server.csrf_secret in _PLACEHOLDERS:
        click.secho("  WARNING: server.csrf_secret is still a placeholder!", fg="yellow")
        has_warnings = True
    if cfg.server.admin_password in ("NACo@admin1", "CHANGE_ME_initial_admin_password", "admin"):
        click.secho("  WARNING: server.admin_password is still a placeholder!", fg="yellow")
        has_warnings = True

    if not cfg.server.debug and has_warnings:
        click.secho(
            "  ERROR: placeholder secrets with debug=False will prevent startup!",
            fg="red",
        )

    if deep:
        _check_deep(cfg)


@cli.command("reset-password")
@click.option("--username", default="admin", help="Admin username to reset.")
@click.option("--password", prompt=True, hide_input=True, confirmation_prompt=True, help="New password.")
def reset_password(username: str, password: str):
    """Reset an admin user's password."""
    if len(password) < 8:
        click.secho("Password must be at least 8 characters.", fg="red")
        sys.exit(1)
    if not any(c.isalpha() for c in password):
        click.secho("Password must contain at least one letter.", fg="red")
        sys.exit(1)
    if not any(c.isdigit() for c in password):
        click.secho("Password must contain at least one digit.", fg="red")
        sys.exit(1)

    async def _reset():
        from sqlalchemy import select

        from naco.api.auth import hash_password
        from naco.db.database import _get_session_factory, init_db
        from naco.db.models import AdminUser

        await init_db()
        factory = _get_session_factory()
        async with factory() as db:
            user = (await db.execute(
                select(AdminUser).where(AdminUser.username == username)
            )).scalar_one_or_none()
            if not user:
                click.secho(f"Admin user '{username}' not found.", fg="red")
                sys.exit(1)
            user.password_hash = hash_password(password)
            await db.commit()
            click.secho(f"Password reset for '{username}'.", fg="green")

    asyncio.run(_reset())


def _backend(db_url: str) -> str:
    try:
        return make_url(db_url).get_backend_name()
    except Exception:
        return ""


def postgresql_cli_env_and_argv(async_or_sync_url: str) -> tuple[dict[str, str], list[str]]:
    """Build ``(env_overlay, argv_suffix)`` for ``pg_dump`` / ``psql``.

    The database password is passed **only** via the ``PGPASSWORD``
    environment variable so it never appears in process listings (Phase 0).

    ``argv_suffix`` is ``['-h', host, '-p', port, '-U', user, '-d', db]``.
    Callers prepend ``['pg_dump', ...]`` or ``['psql', ...]`` as appropriate.
    """
    import os

    sync = async_or_sync_url.replace("postgresql+asyncpg", "postgresql", 1)
    url = make_url(sync)
    env = os.environ.copy()
    if url.password not in (None, ""):
        env["PGPASSWORD"] = str(url.password)
    else:
        env.pop("PGPASSWORD", None)

    host = url.host or "127.0.0.1"
    port = str(url.port or 5432)
    user = url.username or ""
    database = url.database or ""
    common = ["-h", host, "-p", port, "-U", user, "-d", database]
    return env, common


@cli.command("backup")
@click.option(
    "--output", "-o", required=True, type=click.Path(),
    help="Backup file (e.g. backup.sql.gz for Postgres, backup.db for SQLite).",
)
def backup(output: str):
    """Snapshot the database to a portable file.

    PostgreSQL → invokes ``pg_dump`` and gzips the result.
    SQLite     → copies the .db file (and any -wal/-shm sidecars).
    """
    import gzip
    import subprocess

    cfg = get_config()
    backend = _backend(cfg.database.url)
    dst = Path(output)
    dst.parent.mkdir(parents=True, exist_ok=True)

    if backend == "sqlite":
        src = _sqlite_path_from_url(cfg.database.url)
        if not src.exists():
            click.secho(f"Database file not found: {src}", fg="red")
            sys.exit(1)
        shutil.copy2(src, dst)
        for suffix in ("-wal", "-shm"):
            wal = src.with_name(src.name + suffix)
            if wal.exists():
                shutil.copy2(wal, dst.with_name(dst.name + suffix))
        click.secho(f"SQLite snapshot written to {dst}", fg="green")
        return

    if backend == "postgresql":
        env, common = postgresql_cli_env_and_argv(cfg.database.url)
        try:
            proc = subprocess.run(
                ["pg_dump", "--format=plain", "--clean", "--if-exists", *common],
                capture_output=True, check=True, env=env,
            )
        except FileNotFoundError:
            click.secho("pg_dump not found — install the `postgresql-client` package.", fg="red")
            sys.exit(1)
        except subprocess.CalledProcessError as exc:
            click.secho(f"pg_dump failed: {exc.stderr.decode(errors='replace')}", fg="red")
            sys.exit(1)
        opener = gzip.open if str(dst).endswith(".gz") else open
        with opener(dst, "wb") as f:
            f.write(proc.stdout)
        click.secho(f"PostgreSQL snapshot written to {dst}", fg="green")
        return

    click.secho(f"Unsupported database backend: {backend or 'unknown'}", fg="red")
    sys.exit(1)


@cli.command("restore")
@click.option("--input", "-i", "input_file", required=True, type=click.Path(exists=True),
              help="Backup file to restore.")
@click.confirmation_option(prompt="This will overwrite the current database. Continue?")
def restore(input_file: str):
    """Restore from a snapshot created by `nacoctl backup`."""
    import gzip
    import subprocess

    cfg = get_config()
    backend = _backend(cfg.database.url)

    if backend == "sqlite":
        _SQLITE_MAGIC = b"SQLite format 3\000"
        try:
            with open(input_file, "rb") as f:
                header = f.read(16)
            if header[:16] != _SQLITE_MAGIC:
                click.secho("Input file is not a valid SQLite database.", fg="red")
                sys.exit(1)
        except OSError as exc:
            click.secho(f"Cannot read input file: {exc}", fg="red")
            sys.exit(1)

        dst = _sqlite_path_from_url(cfg.database.url)
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(input_file, dst)
        click.secho(f"Restored SQLite database from {input_file}", fg="green")
        return

    if backend == "postgresql":
        env, common = postgresql_cli_env_and_argv(cfg.database.url)
        opener = gzip.open if input_file.endswith(".gz") else open
        try:
            with opener(input_file, "rb") as f:
                data = f.read()
            subprocess.run(
                ["psql", "--quiet", *common],
                input=data, check=True, env=env,
            )
        except FileNotFoundError:
            click.secho("psql not found — install the `postgresql-client` package.", fg="red")
            sys.exit(1)
        except subprocess.CalledProcessError as exc:
            click.secho(f"psql restore failed (exit {exc.returncode})", fg="red")
            sys.exit(1)
        click.secho(f"Restored PostgreSQL database from {input_file}", fg="green")
        return

    click.secho(f"Unsupported database backend: {backend or 'unknown'}", fg="red")
    sys.exit(1)


@cli.command("db-upgrade")
def db_upgrade():
    """Run Alembic migrations (upgrade to head)."""
    try:
        from alembic.config import Config

        from alembic import command
    except ImportError:
        click.secho("alembic is not installed. Run: pip install alembic", fg="red")
        sys.exit(1)

    # Locate alembic.ini: next to a source checkout of this package, in the
    # container WORKDIR (/app), or in the current directory.
    candidates = [
        Path(__file__).resolve().parent.parent / "alembic.ini",
        Path("/app/alembic.ini"),
        Path.cwd() / "alembic.ini",
    ]
    ini_path = next((p for p in candidates if p.exists()), None)
    if ini_path is None:
        click.secho(
            "alembic.ini not found (looked in: "
            + ", ".join(str(p) for p in candidates) + ")", fg="red",
        )
        sys.exit(1)

    alembic_cfg = Config(str(ini_path))
    command.upgrade(alembic_cfg, "head")
    click.secho("Database upgraded to latest migration.", fg="green")


@cli.command("rehash-passwords")
@click.option(
    "--dry-run/--no-dry-run", default=True,
    help="Show what would be re-hashed without touching the database (default: dry-run).",
)
@click.option(
    "--target-cost", default=13, type=click.IntRange(min=10, max=15),
    help="Target bcrypt cost factor. Hashes already at this cost are skipped.",
)
def rehash_passwords(dry_run: bool, target_cost: int):
    """Identify admin password hashes below the current bcrypt cost.

    Bcrypt hashes carry their cost factor in the second field of the hash
    string (``$2b$13$...``). When the project bumps :data:`naco.api.auth._BCRYPT_ROUNDS`
    upward (Phase 1.10 → 13), existing rows keep working at their old cost
    because ``checkpw`` reads the cost from the stored hash. They become
    inconsistent with the current security baseline though, so this command
    surfaces them and *flags* them as needing a re-hash on next login.

    We don't (and can't) re-hash without the cleartext password, so the
    only options are:

      1. ``nacoctl reset-password --username <user>`` — operator picks a new
         password, which is hashed at the new cost.
      2. Wait for the user to log in; an opportunistic re-hash on
         successful auth (planned for Phase 1.13) will upgrade the cost
         automatically.

    This command makes (2) auditable: it lists the affected rows so the
    operator knows who's still on a sub-baseline cost factor.
    """
    import re
    bcrypt_cost_re = re.compile(r"^\$2[abxy]\$(\d{2})\$")

    async def _scan():
        from sqlalchemy import select

        from naco.db.database import _get_session_factory, init_db
        from naco.db.models import AdminUser

        await init_db()
        factory = _get_session_factory()
        async with factory() as db:
            users = (await db.execute(
                select(AdminUser).order_by(AdminUser.username)
            )).scalars().all()

            stale: list[tuple[str, int]] = []
            unparseable: list[str] = []
            for u in users:
                m = bcrypt_cost_re.match(u.password_hash or "")
                if not m:
                    unparseable.append(u.username)
                    continue
                cost = int(m.group(1))
                if cost < target_cost:
                    stale.append((u.username, cost))

            click.echo(f"Scanned {len(users)} admin user(s); target cost = {target_cost}")
            if unparseable:
                click.secho(
                    f"  {len(unparseable)} hash(es) couldn't be parsed (corrupt or non-bcrypt):",
                    fg="yellow",
                )
                for name in unparseable:
                    click.echo(f"    - {name}")

            if not stale:
                click.secho("All hashes are already at the target cost or higher.", fg="green")
                return

            click.secho(
                f"Found {len(stale)} admin hash(es) below target cost:", fg="yellow",
            )
            for name, cost in stale:
                click.echo(f"    - {name}: cost={cost}")

            if dry_run:
                click.echo(
                    "\nDry run — no changes made. To force a re-hash, run "
                    "`nacoctl reset-password --username <user>` for each account, "
                    "or wait for them to log in (auto-upgrade on success)."
                )
            else:
                click.secho(
                    "\nNon-dry-run mode is currently advisory: bcrypt cannot "
                    "re-hash without the cleartext password. Use the "
                    "reset-password command per user, or enable opportunistic "
                    "re-hash-on-login in a future release.",
                    fg="cyan",
                )

    asyncio.run(_scan())


# ---------------------------------------------------------------------------
# Secrets-at-rest management (see naco/core/secrets.py)
# ---------------------------------------------------------------------------

# (table, column) pairs stored via the EncryptedString type. Raw SQL is used
# on purpose: the ORM would transparently decrypt on read and re-encrypt on
# write, hiding which form is actually on disk.
_ENCRYPTED_COLUMNS = [
    ("nas_clients", "secret"),
    ("tacacs_clients", "key"),
    ("admin_users", "totp_secret"),
    ("admin_users", "pending_totp_secret"),
]


async def _rewrite_secrets(transform) -> dict[str, int]:
    """Apply ``transform(stored_value) -> new_value | None`` to every secret."""
    from sqlalchemy import text

    from naco.db.database import _get_session_factory, init_db

    await init_db()
    factory = _get_session_factory()
    counts: dict[str, int] = {}
    async with factory() as db:
        for table, col in _ENCRYPTED_COLUMNS:
            rows = (await db.execute(
                text(f"SELECT id, {col} FROM {table} WHERE {col} IS NOT NULL")  # noqa: S608
            )).all()
            changed = 0
            for rid, stored in rows:
                new = transform(stored)
                if new is not None and new != stored:
                    await db.execute(
                        text(f"UPDATE {table} SET {col} = :v WHERE id = :id"),  # noqa: S608
                        {"v": new, "id": rid},
                    )
                    changed += 1
            counts[f"{table}.{col}"] = changed
        await db.commit()
    return counts


@cli.command("encrypt-secrets")
def encrypt_secrets():
    """Encrypt all plaintext NAS secrets, TACACS+ keys and TOTP seeds in place.

    Requires NACO_MASTER_KEY (or NACO_MASTER_KEY_FILE). Values that are
    already encrypted are left untouched, so the command is idempotent.
    """
    from naco.core import secrets as sx

    key = sx.get_master_key()
    if key is None:
        click.secho("NACO_MASTER_KEY is not set — nothing to encrypt with. "
                    "Generate one with `openssl rand -base64 32`.", fg="red")
        sys.exit(1)

    def _transform(stored: str) -> str | None:
        return None if sx.is_encrypted(stored) else sx.encrypt(stored, key)

    counts = asyncio.run(_rewrite_secrets(_transform))
    total = sum(counts.values())
    for loc, n in counts.items():
        click.echo(f"    {loc}: {n} encrypted")
    click.secho(f"Done — {total} value(s) encrypted.", fg="green")


@cli.command("rotate-master-key")
def rotate_master_key():
    """Re-encrypt every stored secret under a new master key.

    Set NACO_MASTER_KEY to the NEW key and NACO_MASTER_KEY_OLD to the key
    currently protecting the data, then run this command. Plaintext values
    (from before encryption was enabled) are encrypted under the new key too.
    """
    import os as _os

    from naco.core import secrets as sx

    new_key = sx.get_master_key()
    if new_key is None:
        click.secho("NACO_MASTER_KEY (the new key) is not set.", fg="red")
        sys.exit(1)
    old_material = _os.environ.get("NACO_MASTER_KEY_OLD")
    if not old_material:
        click.secho("NACO_MASTER_KEY_OLD (the current key) is not set.", fg="red")
        sys.exit(1)
    old_key = sx._parse_key(old_material)

    def _transform(stored: str) -> str:
        plaintext = sx.decrypt(stored, old_key) if sx.is_encrypted(stored) else stored
        return sx.encrypt(plaintext, new_key)

    counts = asyncio.run(_rewrite_secrets(_transform))
    total = sum(counts.values())
    for loc, n in counts.items():
        click.echo(f"    {loc}: {n} re-encrypted")
    click.secho(f"Done — {total} value(s) now under the new key. "
                "Update NACO_MASTER_KEY everywhere and drop "
                "NACO_MASTER_KEY_OLD.", fg="green")


if __name__ == "__main__":
    cli()
