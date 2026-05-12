"""Network helpers that don't fit anywhere else.

Right now this is mostly the **SSRF guard** used by anywhere admin-supplied
URLs are dialled out to (event webhooks, log-forwarding HTTP webhooks,
LDAP fail-safety hooks in future). It refuses to talk to:

* Private / RFC 1918 / RFC 4193 / loopback / link-local addresses
* Cloud-provider instance-metadata endpoints (AWS, Azure, GCP, Alibaba,
  Oracle, Hetzner Cloud)
* ``file://``, ``gopher://`` and other non-HTTP schemes
* Hostnames that resolve *only* to the above

An optional allowlist (``cache.webhook_allowlist``, list of CIDRs) lets
operators explicitly opt back in for legitimate intranet integrations,
e.g. an internal SIEM at ``10.0.0.50``. Allowlist takes precedence over the
deny rules.

This is a *defence-in-depth* layer — the primary defence is RBAC (only a
SUPERUSER can write webhook URLs). But once a webhook URL is in YAML it
gets dialled on every matching event, so the validator runs at *dispatch*
time, not (only) at save time.
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse


# ──────────────────────────────────────────────────────────────────────────
# Hard-coded denylist of cloud-metadata hosts (case-insensitive substring
# match on the hostname). These are usually reachable from any compute
# instance and exfiltrate IAM credentials to whoever can hit them.
# ──────────────────────────────────────────────────────────────────────────

_METADATA_HOSTS = {
    "169.254.169.254",                   # AWS / OpenStack / DigitalOcean / Alibaba
    "fd00:ec2::254",                     # AWS IPv6
    "metadata.google.internal",          # GCP
    "metadata.azure.com",                # Azure
    "metadata.platformequinix.com",      # Equinix Metal
    "100.100.100.200",                   # Alibaba Cloud
}

_ALLOWED_SCHEMES = {"http", "https"}


class UrlPolicyError(ValueError):
    """Raised by :func:`validate_outbound_url` when a URL is rejected."""


def _is_private_addr(addr: str) -> bool:
    """Return ``True`` for any IP we never want NACo to dial out to."""
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    # ``is_private`` already covers RFC 1918, RFC 4193 (ULA), loopback,
    # and link-local. We add unspecified (0.0.0.0 / ::) and multicast for
    # completeness.
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_unspecified
        or ip.is_multicast
        or ip.is_reserved
    )


def _matches_allowlist(addr: str, allowlist: list[str]) -> bool:
    """Return ``True`` if *addr* falls inside any CIDR in *allowlist*."""
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    for entry in allowlist or []:
        try:
            net = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            continue
        if ip in net:
            return True
    return False


def validate_outbound_url(url: str, *, allowlist: list[str] | None = None) -> None:
    """Raise :class:`UrlPolicyError` if *url* is unsafe to dial out to.

    Resolution policy:

    1. Reject empty/null URLs.
    2. Reject non-HTTP(S) schemes outright.
    3. Reject explicit cloud-metadata hostnames before any DNS lookup —
       this also covers operators who try to circumvent the resolver with
       ``http://metadata.google.internal.evil.example.com`` redirects (we
       only match exact hostnames, but the DNS resolution step below
       catches resolved redirects too).
    4. Resolve the hostname; reject if *any* resolved address falls into
       a denied range and is *not* in the allowlist.

    Pass ``allowlist`` to permit specific intranet ranges, e.g.
    ``["10.42.0.0/24"]``.
    """
    if not url:
        raise UrlPolicyError("URL must not be empty")

    parsed = urlparse(url.strip())
    if parsed.scheme.lower() not in _ALLOWED_SCHEMES:
        raise UrlPolicyError(f"Scheme {parsed.scheme!r} not allowed (must be http or https)")

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        raise UrlPolicyError("URL has no host")

    if hostname in _METADATA_HOSTS:
        raise UrlPolicyError(f"Host {hostname!r} is a known cloud-metadata endpoint")

    # If the URL host is already a literal IP, validate it directly.
    try:
        ipaddress.ip_address(hostname)
        addrs = [hostname]
    except ValueError:
        # Otherwise resolve. ``getaddrinfo`` returns one tuple per family;
        # we pull the address out of [4][0] which is portable across
        # AF_INET / AF_INET6.
        try:
            results = socket.getaddrinfo(hostname, None)
        except socket.gaierror as exc:
            raise UrlPolicyError(f"Cannot resolve host {hostname!r}: {exc}")
        addrs = list({r[4][0] for r in results})

    allowlist = allowlist or []
    for addr in addrs:
        if _matches_allowlist(addr, allowlist):
            continue
        if addr in _METADATA_HOSTS or _is_private_addr(addr):
            raise UrlPolicyError(
                f"Host {hostname!r} resolves to {addr!r}, which is in a "
                "private/loopback/link-local/metadata range. Add the CIDR "
                "to ``cache.webhook_allowlist`` to permit it explicitly."
            )


def is_safe_outbound_url(url: str, *, allowlist: list[str] | None = None) -> bool:
    """Boolean wrapper around :func:`validate_outbound_url` for call sites
    that prefer ``if not is_safe_outbound_url(...): skip``.
    """
    try:
        validate_outbound_url(url, allowlist=allowlist)
        return True
    except UrlPolicyError:
        return False
