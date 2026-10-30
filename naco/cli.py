"""nacoctl — operations from the shell (inside the container).

    docker compose exec naco nacoctl backup
    docker compose exec naco nacoctl reset-password admin

Backups stream through standard output and input (``-o -`` / ``restore -``),
so files never need to be copied into the container with the right owner.

Secrets are never taken as command-line arguments (they would show in `ps`).
"""
from __future__ import annotations

import asyncio
import os
import secrets
import shutil
import sqlite3
import sys
import tempfile
from collections.abc import Callable, Coroutine
from datetime import datetime
from pathlib import Path
from typing import Any

import click
from sqlalchemy import delete, select, text

from naco import __version__
from naco.config import ConfigError, get_config, get_secrets, parse_master_key
from naco.core import secrets as crypto
from naco.core.passwords import hash_password
from naco.db.engine import dispose_engine, init_engine, session_factory
from naco.db.migrate import upgrade_head
from naco.db.models import ActorType, AdminSession, AdminUser, AuditLog

# Every column holding an EncryptedString: (table, column) — the AAD is "table.column".
ENCRYPTED_COLUMNS = [
    ("admin_users", "totp_secret"), ("admin_users", "totp_pending_secret"),
    ("nas_clients", "secret"), ("tacacs_clients", "key"),
]


def _run(coro_fn: Callable[[], Coroutine[Any, Any, Any]]) -> Any:
    async def wrapper() -> Any:
        init_engine(get_config().database.path)
        try:
            return await coro_fn()
        finally:
            await dispose_engine()
    return asyncio.run(wrapper())


def _fail(message: str) -> None:
    click.secho(message, fg="red", err=True)
    raise SystemExit(1)


def _audit(db: Any, action: str, target: str = "", changes: dict[str, Any] | None = None) -> None:
    db.add(AuditLog(actor=os.environ.get("USER", "nacoctl")[:64], actor_type=ActorType.CLI, action=action,
                    target_type="admin" if target else "", target_name=target[:128], changes=changes or {}))


@click.group()
@click.version_option(__version__, prog_name="nacoctl")
def cli() -> None:
    """NACo command-line administration."""


# ── configuration ──────────────────────────────────────────────────────────

@cli.command("check-config")
def check_config() -> None:
    """Validate config.yaml and the secrets in the environment."""
    try:
        cfg = get_config()
        get_secrets()
    except ConfigError as exc:
        _fail(f"✗ {exc}")
    click.secho("✓ configuration and secrets are valid", fg="green")
    click.echo(f"  database   {cfg.database.path}")
    click.echo(f"  timezone   {cfg.server.timezone}")
    click.echo(f"  TACACS+    {'on :' + str(cfg.tacacs.port) if cfg.tacacs.enabled else 'off'}")
    click.echo(f"  portal     {'on' if cfg.portal.enabled else 'off'}")
    click.echo(f"  LDAP       {', '.join(cfg.ldap.servers) if cfg.ldap.enabled else 'off'}")
    click.echo(f"  2FA        {'required' if cfg.security.require_totp else 'optional'}")


# ── administrators ─────────────────────────────────────────────────────────

@cli.command("reset-password")
@click.argument("username")
def reset_password(username: str) -> None:
    """Give an administrator a new temporary password (printed once)."""
    password = secrets.token_urlsafe(15)

    async def go() -> bool:
        async with session_factory()() as db:
            admin = (await db.execute(select(AdminUser).where(AdminUser.username == username.lower()))).scalar_one_or_none()
            if admin is None:
                return False
            admin.password_hash = await hash_password(password)
            admin.must_change_password = True
            admin.enabled = True
            await db.execute(delete(AdminSession).where(AdminSession.admin_id == admin.id))
            _audit(db, "admin.password_reset", admin.username)
            await db.commit()
            return True

    if not _run(go):
        _fail(f"no administrator named {username}")
    click.echo(f"Temporary password for {username.lower()}: {password}")
    click.echo("It must be changed at the next sign-in. Existing sessions were ended.")


@cli.command("reset-totp")
@click.argument("username")
def reset_totp(username: str) -> None:
    """Remove an administrator's two-factor authentication (lost phone)."""
    async def go() -> bool:
        async with session_factory()() as db:
            admin = (await db.execute(select(AdminUser).where(AdminUser.username == username.lower()))).scalar_one_or_none()
            if admin is None:
                return False
            admin.totp_secret = admin.totp_pending_secret = None
            admin.totp_last_step, admin.recovery_codes = None, []
            await db.execute(delete(AdminSession).where(AdminSession.admin_id == admin.id))
            _audit(db, "admin.totp_reset", admin.username)
            await db.commit()
            return True

    if not _run(go):
        _fail(f"no administrator named {username}")
    click.echo(f"Two-factor authentication removed for {username.lower()}; they enroll again at next sign-in.")


# ── backup / restore ───────────────────────────────────────────────────────

def _sqlite_copy(source: str, target: Path) -> None:
    """Consistent online copy (includes the WAL), written 0600."""
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.close(fd)
    src = sqlite3.connect(f"file:{source}?mode=ro", uri=True)
    dst = sqlite3.connect(target)
    try:
        src.backup(dst)
    finally:
        dst.close()
        src.close()
    os.chmod(target, 0o600)


# Every age file starts with one of these (binary or ASCII-armored).
AGE_MAGIC = (b"age-encryption.org/", b"-----BEGIN AGE ENCRYPTED FILE-----")


@cli.command()
@click.option("--output", "-o", type=click.Path(dir_okay=False, allow_dash=True, path_type=Path),
              help="File, or - for standard output. Default: /backups/naco-<timestamp>.db")
def backup(output: Path | None) -> None:
    """Back up the database (safe while NACo runs).

    \b
    docker compose exec naco nacoctl backup
    docker compose exec -T naco nacoctl backup -o - > naco.db
    docker compose exec -T naco nacoctl backup -o - | age -r age1… > naco.db.age
    """
    cfg = get_config()
    if not Path(cfg.database.path).exists():
        _fail(f"no database at {cfg.database.path}")
    to_stdout = output is not None and str(output) == "-"
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    target = output or Path("/backups") / f"naco-{stamp}.db"
    if not to_stdout:
        target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        plain = Path(tmp) / "naco.db" if to_stdout else target
        _sqlite_copy(cfg.database.path, plain)
        if to_stdout:
            stream = sys.stdout.buffer
            with open(plain, "rb") as handle:
                shutil.copyfileobj(handle, stream)
            stream.flush()
    click.echo(f"Backup written to {'standard output' if to_stdout else target}", err=to_stdout)
    click.secho("It contains encrypted secrets and password hashes — keep it private, "
                "and remember it needs the same NACO_MASTER_KEY.", fg="yellow", err=to_stdout)


@cli.command()
@click.argument("source", type=click.Path(exists=True, dir_okay=False, allow_dash=True, path_type=Path))
@click.option("--yes", is_flag=True, help="Confirm overwriting the current database.")
def restore(source: Path, yes: bool) -> None:
    """Replace the database with a backup — a file, or - for standard input.
    Stop NACo first:

    \b
    docker compose stop naco
    docker compose run --rm -T naco nacoctl restore - --yes < naco.db
    docker compose start naco
    """
    if not yes:
        _fail("restoring replaces every user, device and policy — re-run with --yes (and NACo stopped)")
    target = Path(get_config().database.path)
    with tempfile.TemporaryDirectory(dir=target.parent) as tmp:
        received, plain = Path(tmp) / "received", Path(tmp) / "restore.db"
        if str(source) == "-":
            with open(received, "wb") as handle:
                shutil.copyfileobj(sys.stdin.buffer, handle)
        else:
            shutil.copyfile(source, received)
        with open(received, "rb") as handle:
            if handle.read(64).startswith(AGE_MAGIC):
                _fail("this backup is encrypted — decrypt it on the way in: "
                      "age -d -i key.txt FILE | docker compose run --rm -T naco nacoctl restore - --yes")
        received.rename(plain)
        conn = sqlite3.connect(plain)
        try:
            ok = conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
            conn.execute("PRAGMA journal_mode=DELETE")  # fold any WAL into the file
        except sqlite3.DatabaseError:
            ok = False
        finally:
            conn.close()
        if not ok:
            _fail("the backup is not a valid NACo database")
        for suffix in ("-wal", "-shm"):
            Path(f"{target}{suffix}").unlink(missing_ok=True)
        os.chmod(plain, 0o600)
        os.replace(plain, target)
    upgrade_head(str(target))
    click.echo(f"Restored {'the backup' if str(source) == '-' else source.name}. "
               "Start NACo again: docker compose start naco")


# ── key rotation ───────────────────────────────────────────────────────────

@cli.command("rotate-master-key")
@click.option("--new-key-file", required=True, type=click.Path(exists=True, dir_okay=False, allow_dash=True),
              help="File holding the new 32-byte key (base64 or hex), or - for standard input.")
def rotate_master_key(new_key_file: str) -> None:
    """Re-encrypt every stored secret with a new NACO_MASTER_KEY. Stop NACo first:

    \b
    docker compose run --rm -T naco nacoctl rotate-master-key --new-key-file - < new.key
    """
    material = sys.stdin.read() if new_key_file == "-" else Path(new_key_file).read_text()
    new_key = parse_master_key(material)
    old_key = get_secrets().master_key
    if new_key == old_key:
        _fail("the new key is the current key")

    async def go() -> int:
        changed = 0
        async with session_factory()() as db:
            for table, column in ENCRYPTED_COLUMNS:
                rows = (await db.execute(text(f"SELECT id, {column} FROM {table} WHERE {column} IS NOT NULL"))).all()  # noqa: S608 — fixed identifiers
                for ident, value in rows:
                    plain = crypto.decrypt(value, aad=f"{table}.{column}", key=old_key)
                    await db.execute(text(f"UPDATE {table} SET {column} = :v WHERE id = :i"),  # noqa: S608
                                     {"v": crypto.encrypt(plain, aad=f"{table}.{column}", key=new_key), "i": ident})
                    changed += 1
            _audit(db, "system.master_key_rotated", changes={"secrets": changed})
            await db.commit()
        return changed

    count = _run(go)
    click.echo(f"Re-encrypted {count} secrets. Now set NACO_MASTER_KEY to the new key in .env and start NACo.")


def main() -> None:  # pragma: no cover
    try:
        cli()
    except ConfigError as exc:
        click.secho(str(exc), fg="red", err=True)
        sys.exit(2)


if __name__ == "__main__":  # pragma: no cover
    main()
