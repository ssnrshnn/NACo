"""
NACo LDAP / Active Directory authentication helper.
======================================================
Verifies user credentials with a bind against an LDAP/AD directory and
resolves group membership for auto-provisioning.

Enterprise directory features:

* **Failover pool** — ``ldap.servers`` lists multiple domain controllers;
  they are tried in order and the first reachable one serves the request.
* **Nested groups** — ``ldap.nested_groups`` resolves transitive
  membership via the AD matching rule ``LDAP_MATCHING_RULE_IN_CHAIN``
  (plain ``memberOf`` only lists direct groups).
* **StartTLS / LDAPS** — ``ldap.start_tls`` upgrades a plain connection
  before any bind; ``ldaps://`` URIs / ``use_ssl`` do implicit TLS.

Usage::

    from naco.auth.ldap import ldap_authenticate

    result = await ldap_authenticate("alice", "s3cret")
    if result is not None:
        # result = {"dn": "...", "groups": ["admins"], "email": "alice@..."}
"""
from __future__ import annotations

import asyncio
import importlib.util
from typing import Any

from naco.config import get_config
from naco.core.logger import get_logger

log = get_logger(__name__)

#: OID of Microsoft's transitive-membership matching rule.
_IN_CHAIN_RULE = "1.2.840.113556.1.4.1941"


# ---------------------------------------------------------------------------
# Pure helpers (unit-tested without a directory)
# ---------------------------------------------------------------------------

def server_uris(cfg) -> list[str]:
    """The failover pool: ``servers`` when set, else the legacy ``server``."""
    pool = [s.strip() for s in cfg.servers if s and s.strip()]
    if pool:
        return pool
    return [cfg.server] if cfg.server else []


def nested_group_filter(user_dn: str) -> str:
    """AD filter matching every group *user_dn* belongs to, transitively."""
    # Escape RFC 4515 special characters in the DN before embedding it.
    escaped = (
        user_dn.replace("\\", "\\5c")
        .replace("*", "\\2a")
        .replace("(", "\\28")
        .replace(")", "\\29")
        .replace("\x00", "\\00")
    )
    return f"(member:{_IN_CHAIN_RULE}:={escaped})"


def map_groups(cfg, group_dns: list[str]) -> list[str]:
    """Map directory group DNs to NACo group names.

    Case-insensitive on the DN (DNs are), ordered by ``group_map`` so the
    map expresses provisioning priority.
    """
    present = {dn.lower() for dn in group_dns}
    return [
        naco_group
        for dn, naco_group in cfg.group_map.items()
        if dn.lower() in present
    ]


# ---------------------------------------------------------------------------
# Directory operations
# ---------------------------------------------------------------------------

async def ldap_authenticate(username: str, password: str) -> dict[str, Any] | None:
    """
    Authenticate *username* / *password* against the configured directory.

    Returns a dict with user attributes on success, or ``None`` on failure.
    The dict contains:
      - ``dn``:     the user's distinguished name
      - ``groups``: list of NACo group names (resolved via ``group_map``)
      - ``email``:  user's mail attribute (if present)
    """
    cfg = get_config().ldap
    if not cfg.enabled:
        return None

    if importlib.util.find_spec("ldap3") is None:
        log.warning("ldap3 package not installed — LDAP auth unavailable (pip install ldap3)")
        return None

    # Run the blocking LDAP operations in a thread to avoid blocking asyncio
    return await asyncio.to_thread(_ldap_auth_sync, cfg, username, password)


def _make_server_pool(cfg):
    """Build an ldap3 ServerPool trying the configured URIs in order."""
    import ldap3
    from ldap3 import FIRST, Server, ServerPool

    servers = []
    for uri in server_uris(cfg):
        # cfg.port applies only when the URI does not carry its own port
        # (ldaps:// URIs default to 636 inside ldap3 when port is None).
        host_part = uri.split("://", 1)[-1]
        explicit_port = ":" in host_part
        is_ldaps = uri.startswith("ldaps://")
        servers.append(Server(
            uri,
            port=None if (explicit_port or is_ldaps) else cfg.port,
            use_ssl=cfg.use_ssl or is_ldaps,
            get_info=ldap3.NONE,
            connect_timeout=cfg.connect_timeout,
        ))
    if not servers:
        raise ValueError("ldap.enabled is true but no servers are configured")
    # FIRST + active: always prefer the first server, skip dead ones, retry
    # them on later requests.
    return ServerPool(servers, FIRST, active=1, exhaust=False)


def _connect(cfg, pool, user: str | None, password: str | None):
    """Open (and optionally StartTLS-upgrade) a bound connection."""
    from ldap3 import Connection

    conn = Connection(
        pool, user=user, password=password,
        auto_bind=False, receive_timeout=cfg.connect_timeout * 2,
    )
    conn.open()
    if cfg.start_tls and not cfg.use_ssl:
        conn.start_tls()
    if not conn.bind():
        conn.unbind()
        return None
    return conn


def _resolve_nested_groups(cfg, conn, user_dn: str) -> list[str]:
    """All groups (direct + transitive) containing *user_dn* — AD only."""
    from ldap3 import SUBTREE

    conn.search(
        search_base=cfg.base_dn,
        search_filter=nested_group_filter(user_dn),
        search_scope=SUBTREE,
        attributes=["distinguishedName"],
    )
    return [str(entry.entry_dn) for entry in conn.entries]


def _ldap_auth_sync(cfg, username: str, password: str) -> dict[str, Any] | None:
    import ldap3
    from ldap3 import ALL_ATTRIBUTES, SUBTREE

    try:
        pool = _make_server_pool(cfg)

        # 1. Bind with service account to search for the user
        conn = _connect(cfg, pool, cfg.bind_dn, cfg.bind_password)
        if conn is None:
            log.warning("LDAP service-account bind failed (check bind_dn/bind_password)")
            return None

        search_filter = cfg.user_filter.replace(
            "{username}", ldap3.utils.conv.escape_filter_chars(username)
        )
        conn.search(
            search_base=cfg.base_dn,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=ALL_ATTRIBUTES,
        )

        if not conn.entries:
            log.debug("LDAP: user %r not found with filter %s", username, search_filter)
            conn.unbind()
            return None

        user_entry = conn.entries[0]
        user_dn = str(user_entry.entry_dn)

        # 2. Resolve group membership (while the service connection is open)
        group_dns: list[str] = []
        if cfg.nested_groups:
            group_dns = _resolve_nested_groups(cfg, conn, user_dn)
        elif cfg.group_attribute:
            member_of = getattr(user_entry, cfg.group_attribute, None)
            if member_of:
                group_dns = [str(dn) for dn in member_of.values]
        conn.unbind()

        # 3. Bind as the user to verify the password
        user_conn = _connect(cfg, pool, user_dn, password)
        if user_conn is None:
            log.debug("LDAP bind failed for user %r — wrong password", username)
            return None
        user_conn.unbind()

        groups = map_groups(cfg, group_dns) if cfg.group_map else []

        # 4. Extract email
        email = ""
        if hasattr(user_entry, "mail"):
            vals = user_entry.mail.values
            email = str(vals[0]) if vals else ""

        log.info("LDAP auth success: user=%r dn=%r groups=%r", username, user_dn, groups)
        return {"dn": user_dn, "groups": groups, "email": email}

    except ldap3.core.exceptions.LDAPBindError:
        log.debug("LDAP bind failed for user %r — wrong password", username)
        return None
    except ldap3.core.exceptions.LDAPException as exc:
        log.warning("LDAP error for user %r: %s", username, exc)
        return None
    except Exception as exc:
        log.warning("LDAP unexpected error for %r: %s", username, exc)
        return None


async def ldap_auto_provision(
    username: str, ldap_result: dict[str, Any], db
) -> None:
    """
    Create or update a local User record based on LDAP auth result.
    Maps the first matching LDAP group to a NACo group — and since policy
    conditions match on that group's name, directory membership drives the
    policy engine directly.
    """
    import secrets

    from sqlalchemy import select

    from naco.api.auth import hash_password
    from naco.db.models import Group, User

    user = (await db.execute(
        select(User).where(User.username == username)
    )).scalar_one_or_none()

    # Resolve group_id from LDAP groups
    group_id = None
    for gname in ldap_result.get("groups", []):
        g = (await db.execute(select(Group).where(Group.name == gname))).scalar_one_or_none()
        if g:
            group_id = g.id
            break

    if user is None:
        # Auto-provision: create local user with random password (LDAP will always auth)
        user = User(
            username=username,
            password_hash=hash_password(secrets.token_urlsafe(32)),
            email=ldap_result.get("email", ""),
            group_id=group_id,
            enabled=True,
        )
        db.add(user)
        log.info("Auto-provisioned LDAP user %r into group_id=%s", username, group_id)
    else:
        # Update group mapping if changed
        if group_id and user.group_id != group_id:
            user.group_id = group_id
    await db.commit()
