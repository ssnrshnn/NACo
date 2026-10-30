import asyncio
import base64
import os
import stat

import pytest
from click.testing import CliRunner
from sqlalchemy import select, text

from naco import config
from naco.cli import cli
from naco.core import secrets as crypto
from naco.core.passwords import hash_password_sync, verify_password_sync
from naco.db.engine import dispose_engine, init_engine, session_factory
from naco.db.migrate import upgrade_head
from naco.db.models import ActorType, AdminSession, AdminUser, AuditLog, NasClient, User
from tests.conftest import TEST_MASTER_KEY


def run(coro):
    async def wrapped():
        init_engine()
        try:
            return await coro()
        finally:
            await dispose_engine()
    return asyncio.run(wrapped())


@pytest.fixture
def db_path(tmp_path):
    path = os.environ["NACO_DATABASE_PATH"]
    upgrade_head(path)

    async def seed():
        async with session_factory()() as db:
            admin = AdminUser(username="root", password_hash=hash_password_sync("x" * 12), must_change_password=False,
                              totp_secret="JBSWY3DPEHPK3PXP")
            db.add(admin)
            await db.flush()
            db.add(AdminSession(token_hash="h" * 64, admin_id=admin.id, csrf_token="c",
                                expires_at=__import__("naco.core.timeutil", fromlist=["utcnow"]).utcnow()))
            db.add(NasClient(name="sw1", ip_address="10.0.0.1", secret="nas-secret-value-1"))
            db.add(User(username="alice", password_hash="x"))
            await db.commit()
    run(seed)
    return path


def invoke(*args):
    result = CliRunner().invoke(cli, list(args), catch_exceptions=False)
    return result


def test_check_config(db_path, tmp_path, monkeypatch):
    assert "valid" in invoke("check-config").output
    bad = tmp_path / "bad.yaml"
    bad.write_text("nope: 1\n")
    monkeypatch.setenv("NACO_CONFIG", str(bad))
    config.reset_caches()
    result = invoke("check-config")
    assert result.exit_code == 1 and "nope" in result.output


def test_reset_password_and_totp(db_path):
    out = invoke("reset-password", "ROOT").output
    temp = out.split(": ", 1)[1].splitlines()[0]

    async def check():
        async with session_factory()() as db:
            admin = (await db.execute(select(AdminUser))).scalar_one()
            assert admin.must_change_password and verify_password_sync(temp, admin.password_hash)
            assert (await db.execute(select(AdminSession))).first() is None
            audit = (await db.execute(select(AuditLog))).scalar_one()
            assert (audit.actor_type, audit.action) == (ActorType.CLI, "admin.password_reset")
    run(check)
    invoke("reset-totp", "root")

    async def no_totp():
        async with session_factory()() as db:
            assert (await db.execute(select(AdminUser.totp_secret))).scalar_one() is None
    run(no_totp)
    assert invoke("reset-password", "ghost").exit_code == 1


def test_backup_and_restore_roundtrip(db_path, tmp_path):
    backup = tmp_path / "out" / "b.db"
    assert invoke("backup", "-o", str(backup)).exit_code == 0
    assert stat.S_IMODE(backup.stat().st_mode) == 0o600

    async def drop_alice():
        async with session_factory()() as db:
            await db.execute(text("DELETE FROM users"))
            await db.commit()
    run(drop_alice)

    assert invoke("restore", str(backup)).exit_code == 1  # needs --yes
    assert invoke("restore", str(backup), "--yes").exit_code == 0

    async def alice_back():
        async with session_factory()() as db:
            assert (await db.execute(select(User.username))).scalar_one() == "alice"
            assert (await db.execute(select(NasClient))).scalar_one().secret == "nas-secret-value-1"
    run(alice_back)
    assert not os.path.exists(db_path + "-wal") or os.path.getsize(db_path + "-wal") == 0


def test_backup_to_stdout_and_restore_from_stdin(db_path):
    out = CliRunner().invoke(cli, ["backup", "-o", "-"], catch_exceptions=False)
    assert out.exit_code == 0 and out.stdout_bytes.startswith(b"SQLite format 3\x00")

    async def drop_users():
        async with session_factory()() as db:
            await db.execute(text("DELETE FROM users"))
            await db.commit()
    run(drop_users)
    result = CliRunner().invoke(cli, ["restore", "-", "--yes"], input=out.stdout_bytes, catch_exceptions=False)
    assert result.exit_code == 0, result.output

    async def alice_back():
        async with session_factory()() as db:
            assert (await db.execute(select(User.username))).scalar_one() == "alice"
    run(alice_back)


def test_restore_recognizes_encrypted_backups(db_path):
    result = CliRunner().invoke(cli, ["restore", "-", "--yes"],
                                input=b"age-encryption.org/v1\n-> X25519 abc\n", catch_exceptions=False)
    assert result.exit_code == 1 and "encrypted" in result.output


def test_restore_refuses_garbage(db_path, tmp_path):
    junk = tmp_path / "junk.db"
    junk.write_bytes(b"not a database" * 100)
    result = invoke("restore", str(junk), "--yes")
    assert result.exit_code == 1 and "not a valid" in result.output


def test_rotate_master_key(db_path, tmp_path, monkeypatch):
    new_key = bytes(range(100, 132))
    key_file = tmp_path / "new.key"
    key_file.write_text(base64.b64encode(new_key).decode())
    assert "Re-encrypted 2 secrets" in invoke("rotate-master-key", "--new-key-file", str(key_file)).output

    async def raw():
        async with session_factory()() as db:
            return (await db.execute(text("SELECT secret FROM nas_clients"))).scalar_one()
    stored = run(raw)
    assert crypto.decrypt(stored, aad="nas_clients.secret", key=new_key) == "nas-secret-value-1"
    with pytest.raises(crypto.SecretError):
        crypto.decrypt(stored, aad="nas_clients.secret", key=TEST_MASTER_KEY)


def test_rotate_master_key_from_stdin(db_path):
    new_key = bytes(range(100, 132)).hex()
    result = CliRunner().invoke(cli, ["rotate-master-key", "--new-key-file", "-"], input=new_key + "\n",
                                catch_exceptions=False)
    assert "Re-encrypted 2 secrets" in result.output
