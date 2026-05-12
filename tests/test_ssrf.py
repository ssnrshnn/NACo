"""Phase 1.5 — Webhook URL SSRF guard.

Tests :func:`naco.core.netutils.validate_outbound_url` and the wrapper
:func:`is_safe_outbound_url`. We don't exercise DNS resolution against
real names (would make tests flaky and depend on network availability);
hostnames already-resolvable as literal IPs cover the high-value paths.
"""
from __future__ import annotations

import pytest

from naco.core.netutils import (
    UrlPolicyError, is_safe_outbound_url, validate_outbound_url,
)


# ---------------------------------------------------------------------------
# Scheme allowlist.
# ---------------------------------------------------------------------------

class TestSchemeFilter:
    @pytest.mark.parametrize("url", [
        "file:///etc/passwd",
        "gopher://1.2.3.4/",
        "ftp://example.com/",
        "javascript:alert(1)",
        "data:text/html,evil",
    ])
    def test_non_http_schemes_rejected(self, url):
        with pytest.raises(UrlPolicyError):
            validate_outbound_url(url)


# ---------------------------------------------------------------------------
# Private / loopback / link-local refused unless allowlisted.
# ---------------------------------------------------------------------------

class TestPrivateRangeRefusal:
    @pytest.mark.parametrize("url", [
        "http://127.0.0.1/",
        "http://10.0.0.1/",
        "http://10.42.0.50:8080/foo",
        "http://172.16.0.1/",
        "http://192.168.1.1/",
        "http://169.254.169.254/latest/meta-data/",      # AWS / OpenStack
        "http://100.100.100.200/",                        # Alibaba metadata
        "http://[::1]/",
        "http://[fe80::1]/",
    ])
    def test_blocked_by_default(self, url):
        with pytest.raises(UrlPolicyError):
            validate_outbound_url(url)

    def test_metadata_hostname_blocked(self):
        # The string `metadata.google.internal` is in the metadata
        # denylist — we don't try to resolve it.
        with pytest.raises(UrlPolicyError):
            validate_outbound_url("http://metadata.google.internal/")

    def test_allowlist_overrides(self):
        # An operator with an internal SIEM at 10.42.0.50 must be able to
        # opt in via the allowlist.
        validate_outbound_url(
            "http://10.42.0.50:8080/ingest",
            allowlist=["10.42.0.0/24"],
        )

    def test_allowlist_doesnt_open_other_ranges(self):
        with pytest.raises(UrlPolicyError):
            validate_outbound_url(
                "http://192.168.1.1/",
                allowlist=["10.42.0.0/24"],
            )

    def test_allowlist_does_not_unban_metadata_host_literal(self):
        # The string-match against `metadata.google.internal` runs before
        # the CIDR allowlist, so allowlisting `0.0.0.0/0` still doesn't
        # unblock the metadata hostname.
        with pytest.raises(UrlPolicyError):
            validate_outbound_url(
                "http://metadata.google.internal/",
                allowlist=["0.0.0.0/0"],
            )


# ---------------------------------------------------------------------------
# Public hosts are accepted.
# ---------------------------------------------------------------------------

class TestPublicHostsAccepted:
    @pytest.mark.parametrize("url", [
        "https://8.8.8.8/",
        "https://1.1.1.1/v1/log",
        "http://93.184.216.34/",   # example.com IP
    ])
    def test_public_ip_accepted(self, url):
        # No exception → accepted.
        validate_outbound_url(url)


# ---------------------------------------------------------------------------
# Empty / malformed handling.
# ---------------------------------------------------------------------------

class TestMalformedUrls:
    def test_empty_rejected(self):
        with pytest.raises(UrlPolicyError):
            validate_outbound_url("")

    def test_no_host_rejected(self):
        with pytest.raises(UrlPolicyError):
            validate_outbound_url("http://")

    def test_wrapper_returns_bool(self):
        assert is_safe_outbound_url("https://8.8.8.8/") is True
        assert is_safe_outbound_url("http://127.0.0.1/") is False
