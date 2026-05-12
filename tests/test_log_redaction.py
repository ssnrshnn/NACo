"""Phase 1.11 — Log redaction filter.

We exercise the regex set directly via a real ``logging.LogRecord`` so the
test runs without setting up the whole logging chain. The filter must:

* Scrub bearer tokens, passwords, secrets, API keys, LDAP bind passwords,
  TOTP secrets, and JWT-shaped strings.
* Leave non-sensitive payloads untouched.
* Survive bad format strings (return True even if ``getMessage`` raises).
"""
from __future__ import annotations

import logging

import pytest

from naco.core.logger import SecretRedactionFilter


def _make_record(msg: str, *args) -> logging.LogRecord:
    return logging.LogRecord(
        name="naco.test", level=logging.INFO, pathname=__file__,
        lineno=1, msg=msg, args=args, exc_info=None,
    )


def _filter_message(msg: str, *args) -> str:
    rec = _make_record(msg, *args)
    SecretRedactionFilter().filter(rec)
    return rec.getMessage()


class TestBasicPatterns:
    def test_redacts_bearer_token(self):
        out = _filter_message("Authorization: Bearer abc123def456ghi789")
        assert "abc123def456" not in out
        assert "REDACTED" in out

    def test_redacts_bare_bearer_token(self):
        out = _filter_message("Got token: Bearer xyzabcdef1234567890")
        assert "xyzabcdef1234567890" not in out
        assert "REDACTED" in out

    def test_redacts_password_assign(self):
        out = _filter_message('password="hunter2-letme-in!"')
        assert "hunter2" not in out

    def test_redacts_password_colon(self):
        out = _filter_message("password: SuperSecret1234")
        assert "SuperSecret1234" not in out

    def test_redacts_secret(self):
        out = _filter_message("secret=cisco123 (radius shared)")
        assert "cisco123" not in out

    def test_redacts_api_key(self):
        out = _filter_message("api_key=sk_live_abcd1234efgh5678")
        assert "sk_live_abcd1234" not in out

    def test_redacts_bind_password(self):
        out = _filter_message("ldap bind_password = ad_service_pw!")
        assert "ad_service_pw" not in out

    def test_redacts_totp_secret(self):
        out = _filter_message("totp_secret=JBSWY3DPEHPK3PXP")
        assert "JBSWY3DPEHPK3PXP" not in out

    def test_redacts_jwt(self):
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiJ9.signaturepart"
        out = _filter_message(f"got jwt: {jwt}")
        assert "eyJhbGciOiJIUzI1NiI" not in out
        assert "REDACTED_JWT" in out


class TestNonSensitiveUntouched:
    @pytest.mark.parametrize("msg", [
        "Started TACACS+ listener on 0.0.0.0:49",
        "client 10.0.0.5 connected",
        "policy 'guest-vlan' matched device aa:bb:cc:dd:ee:ff",
        "queue depth = 12, retries = 0",
    ])
    def test_unchanged(self, msg):
        assert _filter_message(msg) == msg


class TestFormatArgsScrubbed:
    def test_args_replaced_after_redaction(self):
        """When we redact a message, ``record.args`` is cleared — otherwise
        the handler would re-interpolate using the raw arguments and
        re-insert the secret.
        """
        rec = _make_record("user=%s password=%s", "alice", "supersecret123")
        SecretRedactionFilter().filter(rec)
        # After the filter, getMessage should yield the redacted form.
        out = rec.getMessage()
        assert "supersecret123" not in out


class TestBadFormatString:
    def test_filter_passes_record_through_on_format_error(self):
        # Mismatched %s count would normally raise inside getMessage(); the
        # filter should swallow the error and still return True (i.e. don't
        # drop the record on the floor).
        rec = _make_record("expected two args: %s %s", "only-one")
        # The filter itself must not raise.
        assert SecretRedactionFilter().filter(rec) is True
