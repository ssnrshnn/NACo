"""Custom SQLAlchemy column types."""
from __future__ import annotations

from sqlalchemy import String, TypeDecorator

from naco.core import secrets


class EncryptedString(TypeDecorator):
    """String column transparently encrypted at rest (AES-256-GCM).

    * **Writes** encrypt when ``NACO_MASTER_KEY`` is configured, otherwise
      store plaintext (a startup warning covers this case).
    * **Reads** decrypt ``enc:v1:`` values and pass legacy plaintext
      through unchanged, so turning encryption on is a lazy migration —
      run ``nacoctl encrypt-secrets`` to convert existing rows at once.

    The declared length must leave room for the encryption envelope
    (nonce + tag + base64 + prefix ≈ plaintext × 1.4 + 50 chars).
    """

    impl = String
    cache_ok = True

    def __init__(self, length: int = 512):
        super().__init__(length)

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        return secrets.encrypt(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        return secrets.decrypt(value)
