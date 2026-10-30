import pytest

from naco.core.secrets import SecretError, decrypt, encrypt

KEY = bytes(range(32))
OTHER = bytes(range(1, 33))


def test_roundtrip():
    token = encrypt("s3cret", aad="nas_clients.secret", key=KEY)
    assert token.startswith("enc:v2:")
    assert "s3cret" not in token
    assert decrypt(token, aad="nas_clients.secret", key=KEY) == "s3cret"


def test_unicode_roundtrip():
    assert decrypt(encrypt("şifre-✓", aad="a.b", key=KEY), aad="a.b", key=KEY) == "şifre-✓"


def test_nonce_is_random():
    assert encrypt("x", aad="a.b", key=KEY) != encrypt("x", aad="a.b", key=KEY)


def test_wrong_aad_fails():
    token = encrypt("s3cret", aad="nas_clients.secret", key=KEY)
    with pytest.raises(SecretError):
        decrypt(token, aad="admin_users.totp_secret", key=KEY)


def test_wrong_key_fails():
    token = encrypt("s3cret", aad="a.b", key=KEY)
    with pytest.raises(SecretError):
        decrypt(token, aad="a.b", key=OTHER)


@pytest.mark.parametrize("value", ["plaintext", "enc:v1:AAAA", "enc:v2:not-base64!!", "enc:v2:AAAA"])
def test_malformed_or_plaintext_is_rejected(value):
    with pytest.raises(SecretError):
        decrypt(value, aad="a.b", key=KEY)


def test_default_key_comes_from_environment():
    from tests.conftest import TEST_MASTER_KEY
    token = encrypt("v", aad="a.b")
    assert decrypt(token, aad="a.b", key=TEST_MASTER_KEY) == "v"
