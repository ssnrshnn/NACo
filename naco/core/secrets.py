"""AES-256-GCM encryption for secrets the server must be able to read back.

NAS shared secrets, TACACS+ keys and TOTP seeds are needed in plaintext at
runtime, so they cannot be hashed. They are stored as::

    enc:v2:<base64(nonce || ciphertext || tag)>

The associated data names the column a value belongs to (``"table.column"``),
so a ciphertext copied into a different column fails to decrypt. Plaintext is
never accepted on read.
"""
from __future__ import annotations

import base64
import binascii
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_PREFIX = "enc:v2:"
_NONCE_LEN = 12


class SecretError(RuntimeError):
    """A stored secret is malformed or cannot be decrypted with this key."""


def _key(key: bytes | None) -> bytes:
    if key is not None:
        return key
    from naco.config import get_secrets
    return get_secrets().master_key


def encrypt(plaintext: str, *, aad: str, key: bytes | None = None) -> str:
    nonce = os.urandom(_NONCE_LEN)
    blob = AESGCM(_key(key)).encrypt(nonce, plaintext.encode(), aad.encode())
    return _PREFIX + base64.b64encode(nonce + blob).decode()


def decrypt(token: str, *, aad: str, key: bytes | None = None) -> str:
    if not token.startswith(_PREFIX):
        raise SecretError("value is not an encrypted secret")
    try:
        raw = base64.b64decode(token[len(_PREFIX):], validate=True)
    except (binascii.Error, ValueError) as exc:
        raise SecretError("encrypted secret is not valid base64") from exc
    if len(raw) < _NONCE_LEN + 16:
        raise SecretError("encrypted secret is truncated")
    try:
        plain = AESGCM(_key(key)).decrypt(raw[:_NONCE_LEN], raw[_NONCE_LEN:], aad.encode())
    except InvalidTag as exc:
        raise SecretError(f"cannot decrypt {aad} — wrong NACO_MASTER_KEY or tampered value") from exc
    return plain.decode()
