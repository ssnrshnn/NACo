"""LDAP / Active Directory: search-then-bind authentication and group lookup.

* Encrypted transport only (``ldaps://`` or StartTLS) with certificate
  verification, unless ``allow_insecure`` is set explicitly.
* Several servers form a failover pool, tried in order.
* The user search must match exactly one entry; the filter value is
  RFC 4515-escaped. Empty passwords never reach a bind (an empty simple bind
  is an *unauthenticated* bind that many servers accept).
* ``LdapError`` means "the directory could not answer" — callers fail closed —
  while ``None`` means "these credentials are not valid".
"""
from __future__ import annotations

import asyncio
import logging
import ssl
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from ldap3 import AUTO_BIND_NONE, FIRST, NONE, SUBTREE, Connection, Server, ServerPool, Tls
from ldap3.core.exceptions import LDAPException
from ldap3.utils.conv import escape_filter_chars

from naco.config import LdapConfig

log = logging.getLogger(__name__)

IN_CHAIN_RULE = "1.2.840.113556.1.4.1941"  # AD transitive membership

Connect = Callable[[str | None, str | None], Connection]


class LdapError(RuntimeError):
    """The directory is unreachable or misconfigured."""


@dataclass(frozen=True)
class LdapUser:
    dn: str
    email: str
    full_name: str
    group_dns: tuple[str, ...]


def _first(attrs: dict[str, list[Any]], name: str) -> str:
    for key, values in attrs.items():
        if key.lower() == name.lower() and values:
            return str(values[0])
    return ""


def _all(attrs: dict[str, list[Any]], name: str) -> list[str]:
    for key, values in attrs.items():
        if key.lower() == name.lower():
            return [str(v) for v in values]
    return []


def map_group(cfg: LdapConfig, group_dns: tuple[str, ...] | list[str]) -> str | None:
    """First configured mapping the user belongs to (DNs compare case-insensitively)."""
    present = {dn.lower() for dn in group_dns}
    for mapping in cfg.group_map:
        if mapping.ldap_group.lower() in present:
            return mapping.group
    return None


class LdapDirectory:
    def __init__(self, cfg: LdapConfig, bind_password: str, connect: Connect | None = None) -> None:
        self.cfg = cfg
        self._bind_password = bind_password
        self._connect = connect or self._default_connect

    # -- transport --------------------------------------------------------

    def _server_pool(self) -> ServerPool:
        servers = []
        for uri in self.cfg.servers:
            host = urlsplit(uri).hostname or ""
            # ldap3 verifies the chain *and* the hostname after the handshake.
            tls = Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=self.cfg.ca_file or None, sni=host)
            servers.append(Server(uri, use_ssl=uri.lower().startswith("ldaps://"), tls=tls, get_info=NONE,
                                  connect_timeout=self.cfg.timeout_seconds))
        return ServerPool(servers, FIRST, active=True, exhaust=60)

    def _default_connect(self, user: str | None, password: str | None) -> Connection:
        conn = Connection(
            self._server_pool(), user=user, password=password, auto_bind=AUTO_BIND_NONE,
            receive_timeout=self.cfg.timeout_seconds, read_only=True, raise_exceptions=False,
        )
        conn.open()
        if self.cfg.start_tls and not conn.start_tls():
            conn.unbind()
            raise LdapError("StartTLS negotiation failed")
        return conn

    # -- operations -------------------------------------------------------

    def _find_user(self, conn: Connection, username: str) -> tuple[str, dict[str, list[Any]]] | None:
        query = self.cfg.user_filter.replace("{username}", escape_filter_chars(username))
        conn.search(
            self.cfg.base_dn, query, SUBTREE, size_limit=2,
            attributes=[self.cfg.group_attribute, "mail", "displayName", "cn"],
        )
        entries = conn.entries
        if len(entries) != 1:
            if len(entries) > 1:
                log.warning("LDAP: filter %s matched more than one entry — refusing", query)
            return None
        return str(entries[0].entry_dn), entries[0].entry_attributes_as_dict

    def _groups(self, conn: Connection, dn: str, attrs: dict[str, list[Any]]) -> list[str]:
        if self.cfg.nested_groups:
            conn.search(self.cfg.base_dn, f"(member:{IN_CHAIN_RULE}:={escape_filter_chars(dn)})",
                        SUBTREE, attributes=[])
            return [str(e.entry_dn) for e in conn.entries]
        return _all(attrs, self.cfg.group_attribute)

    def authenticate(self, username: str, password: str) -> LdapUser | None:
        if not username or not password:
            return None
        try:
            service = self._connect(self.cfg.bind_dn or None, self._bind_password or None)
            try:
                if not service.bind():
                    raise LdapError("service account bind failed — check ldap.bind_dn and NACO_LDAP_BIND_PASSWORD")
                found = self._find_user(service, username)
                if found is None:
                    return None
                dn, attrs = found
                groups = self._groups(service, dn, attrs)
            finally:
                service.unbind()

            user_conn = self._connect(dn, password)
            try:
                if not user_conn.bind():
                    return None
            finally:
                user_conn.unbind()
        except LDAPException as exc:
            raise LdapError(f"directory error: {exc}") from exc

        full_name = _first(attrs, "displayName") or _first(attrs, "cn")
        return LdapUser(dn=dn, email=_first(attrs, "mail"), full_name=full_name, group_dns=tuple(groups))


async def ldap_authenticate(username: str, password: str) -> LdapUser | None:
    from naco.config import get_config, get_secrets

    cfg = get_config().ldap
    if not cfg.enabled:
        return None
    directory = LdapDirectory(cfg, get_secrets().ldap_bind_password)
    return await asyncio.to_thread(directory.authenticate, username, password)
