"""Application-layer encryption for secrets at rest.

NAS shared secrets, TACACS+ keys, and TOTP seeds must be readable by the
server (RADIUS/TACACS+ need the plaintext to validate authenticators), so
password-style hashing is not an option. Instead they are encrypted with
AES-256-GCM under a single master key and stored as::

    enc:v1:<base64(nonce || ciphertext || tag)>

The master key is supplied via the environment:

* ``NACO_MASTER_KEY``       — base64 (44 chars) or hex (64 chars) of 32 bytes
* ``NACO_MASTER_KEY_FILE``  — path to a file containing the same (for
  Docker/K8s secret mounts; takes precedence when both are set)

Behaviour without a key is deliberately forgiving so existing installs keep
working: values are stored in plaintext and a warning is logged once. Reads
are always tolerant of both forms — a value without the ``enc:`` prefix is
returned as-is — which makes enabling encryption a lazy, zero-downtime
operation (rows encrypt on next write, or all at once via
``nacoctl encrypt-secrets``).
"""
from __future__ import annotations

import base64
import binascii
import logging
import os
from functools import lru_cache

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger("naco.secrets")

_PREFIX = "enc:v1:"
_NONCE_LEN = 12  # 96-bit nonce, the GCM recommendation


class MasterKeyError(RuntimeError):
    """Raised when an encrypted value cannot be decrypted."""


def _parse_key(material: str) -> bytes:
    material = material.strip()
    for decode in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            key = decode(material)
            if len(key) == 32:
                return key
        except (binascii.Error, ValueError):
            pass
    try:
        key = bytes.fromhex(material)
        if len(key) == 32:
            return key
    except ValueError:
        pass
    raise MasterKeyError(
        "NACO_MASTER_KEY must be 32 bytes, encoded as base64 or hex "
        "(e.g. `openssl rand -base64 32`)"
    )


def _load_key_from_env() -> bytes | None:
    path = os.environ.get("NACO_MASTER_KEY_FILE")
    if path:
        with open(path) as f:
            return _parse_key(f.read())
    material = os.environ.get("NACO_MASTER_KEY")
    if material:
        return _parse_key(material)
    return None


@lru_cache(maxsize=1)
def get_master_key() -> bytes | None:
    """Master key from the environment, or ``None`` when not configured."""
    key = _load_key_from_env()
    if key is None:
        logger.warning(
            "NACO_MASTER_KEY is not set — NAS secrets, TACACS+ keys and TOTP "
            "seeds will be stored in PLAINTEXT. Generate one with "
            "`openssl rand -base64 32` and set it in the environment."
        )
    return key


def is_encrypted(value: str) -> bool:
    return value.startswith(_PREFIX)


def encrypt(plaintext: str, key: bytes | None = None) -> str:
    """Encrypt ``plaintext``; returns it unchanged when no key is configured."""
    key = key if key is not None else get_master_key()
    if key is None:
        return plaintext
    nonce = os.urandom(_NONCE_LEN)
    blob = AESGCM(key).encrypt(nonce, plaintext.encode(), None)
    return _PREFIX + base64.b64encode(nonce + blob).decode()


def decrypt(value: str, key: bytes | None = None) -> str:
    """Decrypt an ``enc:v1:`` value; plaintext values pass through as-is."""
    if not is_encrypted(value):
        return value
    key = key if key is not None else get_master_key()
    if key is None:
        raise MasterKeyError(
            "database contains an encrypted secret but NACO_MASTER_KEY is not "
            "set — restore the key this instance was configured with"
        )
    try:
        raw = base64.b64decode(value[len(_PREFIX):])
        plain = AESGCM(key).decrypt(raw[:_NONCE_LEN], raw[_NONCE_LEN:], None)
    except Exception as exc:  # InvalidTag, truncated blob, bad base64 …
        raise MasterKeyError(
            "failed to decrypt a stored secret — wrong NACO_MASTER_KEY?"
        ) from exc
    return plain.decode()


def reset_key_cache() -> None:
    """Drop the cached key (tests / after rotating env vars in-process)."""
    get_master_key.cache_clear()
