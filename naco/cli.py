"""nacoctl — operations from the shell (inside the container).

    docker compose exec naco nacoctl backup
    docker compose exec naco nacoctl reset-password admin

Secrets are never taken as command-line arguments (they would show in `ps`).
"""
from __future__ import annotations

import asyncio
import os
import secrets
import shutil
import sqlite3
import subprocess
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


def _age() -> str:
    path = shutil.which("age")
    if path is None:
        _fail("the `age` tool is not installed")
    return str(path)


@cli.command()
@click.option("--output", "-o", type=click.Path(dir_okay=False, path_type=Path),
              help="Default: /backups/naco-<timestamp>.db[.age]")
@click.option("--age-recipient", "recipient", help="Encrypt for this age public key (age1…).")
def backup(output: Path | None, recipient: str | None) -> None:
    """Back up the database (safe while NACo runs)."""
    cfg = get_config()
    if not Path(cfg.database.path).exists():
        _fail(f"no database at {cfg.database.path}")
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    output = output or Path("/backups") / f"naco-{stamp}.db{'.age' if recipient else ''}"
    output.parent.mkdir(parents=True, exist_ok=True)
    if recipient:
        with tempfile.TemporaryDirectory() as tmp:
            plain = Path(tmp) / "naco.db"
            _sqlite_copy(cfg.database.path, plain)
            subprocess.run([_age(), "-r", recipient, "-o", str(output), str(plain)], check=True)  # noqa: S603
        os.chmod(output, 0o600)
    else:
        _sqlite_copy(cfg.database.path, output)
    click.echo(f"Backup written to {output}")
    if not recipient:
        click.secho("It contains encrypted secrets and password hashes — keep it private, "
                    "and remember it needs the same NACO_MASTER_KEY.", fg="yellow")


@cli.command()
@click.argument("source", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--age-identity", "identity", type=click.Path(exists=True, dir_okay=False),
              help="age private key file, for .age backups.")
@click.option("--yes", is_flag=True, help="Confirm overwriting the current database.")
def restore(source: Path, identity: str | None, yes: bool) -> None:
    """Replace the database with a backup. Stop NACo first:

    docker compose stop naco && docker compose run --rm naco nacoctl restore /backups/FILE --yes
    """
    if not yes:
        _fail("restoring replaces every user, device and policy — re-run with --yes (and NACo stopped)")
    target = Path(get_config().database.path)
    with tempfile.TemporaryDirectory(dir=target.parent) as tmp:
        plain = Path(tmp) / "restore.db"
        if source.suffix == ".age":
            if identity is None:
                _fail("this backup is encrypted — pass --age-identity")
            subprocess.run([_age(), "-d", "-i", str(identity), "-o", str(plain), str(source)], check=True)  # noqa: S603
        else:
            shutil.copyfile(source, plain)
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
    click.echo(f"Restored {source.name}. Start NACo again: docker compose start naco")


# ── key rotation ───────────────────────────────────────────────────────────

@cli.command("rotate-master-key")
@click.option("--new-key-file", required=True, type=click.Path(exists=True, dir_okay=False),
              help="File holding the new 32-byte key (base64 or hex).")
def rotate_master_key(new_key_file: str) -> None:
    """Re-encrypt every stored secret with a new NACO_MASTER_KEY. Stop NACo first."""
    new_key = parse_master_key(Path(new_key_file).read_text())
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
