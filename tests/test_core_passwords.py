import pytest

from naco.core import passwords


@pytest.fixture(autouse=True)
def fast_bcrypt(monkeypatch):
    monkeypatch.setattr(passwords, "BCRYPT_ROUNDS", 4)
    passwords._dummy_hash.cache_clear()


async def test_hash_and_verify():
    h = await passwords.hash_password("correct horse")
    assert h.startswith("$2")
    assert await passwords.verify_password("correct horse", h)
    assert not await passwords.verify_password("wrong", h)


async def test_unknown_user_never_matches():
    assert not await passwords.verify_password("anything", None)


async def test_malformed_hash_does_not_raise():
    assert not await passwords.verify_password("x", "not-a-bcrypt-hash")


def test_too_long_password_cannot_be_set():
    with pytest.raises(ValueError, match="72 bytes"):
        passwords.hash_password_sync("x" * 73)


async def test_too_long_password_never_matches():
    h = passwords.hash_password_sync("y" * 72)
    assert not await passwords.verify_password("y" * 72 + "extra", h)


def test_validators():
    passwords.validate_admin_password("a-strong-admin-pw")
    with pytest.raises(ValueError, match="12"):
        passwords.validate_admin_password("short")
    passwords.validate_user_password("eightchr")
    with pytest.raises(ValueError, match="8"):
        passwords.validate_user_password("seven77")
