"""Secrets-at-rest: naco.core.secrets + the EncryptedString column type."""
from __future__ import annotations

import base64

import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from naco.core import secrets as sx

KEY_B64 = base64.b64encode(b"\x01" * 32).decode()
OTHER_KEY_B64 = base64.b64encode(b"\x02" * 32).decode()


@pytest.fixture
def master_key(monkeypatch):
    monkeypatch.setenv("NACO_MASTER_KEY", KEY_B64)
    sx.reset_key_cache()
    yield base64.b64decode(KEY_B64)
    sx.reset_key_cache()


@pytest.fixture
def no_master_key(monkeypatch):
    monkeypatch.delenv("NACO_MASTER_KEY", raising=False)
    monkeypatch.delenv("NACO_MASTER_KEY_FILE", raising=False)
    sx.reset_key_cache()
    yield
    sx.reset_key_cache()


# ── core helpers ────────────────────────────────────────────────────────────

def test_roundtrip(master_key):
    ct = sx.encrypt("s3cret-radius-key")
    assert ct.startswith("enc:v1:")
    assert sx.decrypt(ct) == "s3cret-radius-key"


def test_ciphertext_is_nondeterministic(master_key):
    assert sx.encrypt("same") != sx.encrypt("same")  # fresh nonce every call


def test_plaintext_passthrough_on_read(master_key):
    # Legacy rows written before encryption was enabled read unchanged.
    assert sx.decrypt("legacy-plaintext") == "legacy-plaintext"


def test_no_key_encrypt_is_noop(no_master_key):
    assert sx.encrypt("value") == "value"


def test_encrypted_value_without_key_raises(no_master_key):
    blob = sx.encrypt("x", key=b"\x01" * 32)
    with pytest.raises(sx.MasterKeyError):
        sx.decrypt(blob)


def test_wrong_key_raises(master_key):
    blob = sx.encrypt("x", key=base64.b64decode(OTHER_KEY_B64))
    with pytest.raises(sx.MasterKeyError):
        sx.decrypt(blob)


def test_key_parsing_hex_and_base64():
    hex_key = "ab" * 32
    assert sx._parse_key(hex_key) == bytes.fromhex(hex_key)
    assert sx._parse_key(KEY_B64) == b"\x01" * 32
    with pytest.raises(sx.MasterKeyError):
        sx._parse_key("too-short")


def test_key_file_takes_precedence(monkeypatch, tmp_path):
    keyfile = tmp_path / "master.key"
    keyfile.write_text(OTHER_KEY_B64)
    monkeypatch.setenv("NACO_MASTER_KEY", KEY_B64)
    monkeypatch.setenv("NACO_MASTER_KEY_FILE", str(keyfile))
    sx.reset_key_cache()
    try:
        assert sx.get_master_key() == b"\x02" * 32
    finally:
        sx.reset_key_cache()


# ── EncryptedString column type ─────────────────────────────────────────────

async def _session():
    from naco.db.database import Base

    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    return engine, async_sessionmaker(engine, expire_on_commit=False)


async def test_nas_secret_encrypted_on_disk(master_key):
    from naco.db.models import NasClient

    engine, factory = await _session()
    async with factory() as db:
        db.add(NasClient(name="sw1", ip_address="192.0.2.1", secret="radius-shared-secret"))
        await db.commit()

        # ORM read → decrypted plaintext.
        row = (await db.execute(select(NasClient))).scalar_one()
        assert row.secret == "radius-shared-secret"

        # Raw read → encrypted envelope, plaintext absent.
        stored = (await db.execute(text("SELECT secret FROM nas_clients"))).scalar_one()
        assert stored.startswith("enc:v1:")
        assert "radius-shared-secret" not in stored
    await engine.dispose()


async def test_legacy_plaintext_row_still_reads(master_key):
    from naco.db.models import TacacsClient

    engine, factory = await _session()
    async with factory() as db:
        # Simulate a pre-encryption row written as plaintext.
        await db.execute(text(
            "INSERT INTO tacacs_clients (name, ip_address, key, description, enabled) "
            "VALUES ('rtr1', '192.0.2.2', 'legacy-tacacs-key', '', 1)"
        ))
        await db.commit()
        row = (await db.execute(select(TacacsClient))).scalar_one()
        assert row.key == "legacy-tacacs-key"
    await engine.dispose()


async def test_totp_none_roundtrip(master_key):
    from naco.db.models import AdminUser

    engine, factory = await _session()
    async with factory() as db:
        db.add(AdminUser(username="op", password_hash="x", totp_secret=None))
        await db.commit()
        row = (await db.execute(select(AdminUser))).scalar_one()
        assert row.totp_secret is None
        row.totp_secret = "JBSWY3DPEHPK3PXP"
        await db.commit()
        stored = (await db.execute(
            text("SELECT totp_secret FROM admin_users")
        )).scalar_one()
        assert stored.startswith("enc:v1:")
    await engine.dispose()


async def test_without_key_stores_plaintext_and_reads_back(no_master_key):
    from naco.db.models import NasClient

    engine, factory = await _session()
    async with factory() as db:
        db.add(NasClient(name="sw2", ip_address="192.0.2.3", secret="plain-secret"))
        await db.commit()
        stored = (await db.execute(text("SELECT secret FROM nas_clients"))).scalar_one()
        assert stored == "plain-secret"
        row = (await db.execute(select(NasClient))).scalar_one()
        assert row.secret == "plain-secret"
    await engine.dispose()


# ── envelope sizing (guards the String(512) column width) ──────────────────

def test_envelope_fits_column(master_key):
    longest = "x" * 128  # old column limit == longest legal plaintext
    assert len(sx.encrypt(longest)) <= 512
