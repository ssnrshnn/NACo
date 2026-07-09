"""
OIDC admin SSO — pure-logic tests.

The HTTP round-trips (discovery, token exchange, JWKS) are exercised
against a stub; here we pin the security-relevant pieces: state
signing/validation, role mapping from claims, and user provisioning.
"""
from __future__ import annotations

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from naco.db.models import AdminRole, AdminUser
from naco.web import oidc

# ---------------------------------------------------------------------------
# State token (CSRF for the authorization round-trip)
# ---------------------------------------------------------------------------

def test_state_roundtrip():
    state = oidc.make_state("secret-key")
    assert oidc.check_state("secret-key", state) is True


def test_state_rejects_tampering():
    state = oidc.make_state("secret-key")
    assert oidc.check_state("secret-key", state + "x") is False
    assert oidc.check_state("other-key", state) is False
    assert oidc.check_state("secret-key", "") is False


def test_state_expires():
    state = oidc.make_state("secret-key", now=1000.0)
    assert oidc.check_state("secret-key", state, now=1000.0 + oidc.STATE_TTL + 1) is False


# ---------------------------------------------------------------------------
# Role mapping
# ---------------------------------------------------------------------------

def _cfg(**overrides):
    from naco.config import OidcConfig
    return OidcConfig(**overrides)


def test_role_from_mapped_group():
    cfg = _cfg(role_claim="groups", role_map={
        "naco-admins": "SUPERUSER", "naco-ops": "OPERATOR",
    })
    claims = {"groups": ["staff", "naco-ops"]}
    assert oidc.resolve_role(cfg, claims) == AdminRole.OPERATOR


def test_role_highest_wins_when_multiple_match():
    cfg = _cfg(role_claim="groups", role_map={
        "naco-admins": "SUPERUSER", "naco-ops": "OPERATOR",
    })
    claims = {"groups": ["naco-ops", "naco-admins"]}
    assert oidc.resolve_role(cfg, claims) == AdminRole.SUPERUSER


def test_role_defaults_when_no_match():
    cfg = _cfg(default_role="VIEWER")
    assert oidc.resolve_role(cfg, {"groups": ["random"]}) == AdminRole.VIEWER


def test_role_none_when_no_match_and_no_default():
    cfg = _cfg(default_role="")
    assert oidc.resolve_role(cfg, {"groups": ["random"]}) is None


def test_role_claim_as_string_value():
    cfg = _cfg(role_claim="role", role_map={"admin": "SUPERUSER"})
    assert oidc.resolve_role(cfg, {"role": "admin"}) == AdminRole.SUPERUSER


# ---------------------------------------------------------------------------
# Provisioning
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_provision_creates_admin_user(db: AsyncSession):
    cfg = _cfg(default_role="VIEWER")
    claims = {"preferred_username": "alice", "email": "alice@example.com"}
    user = await oidc.provision_user(db, cfg, claims)
    assert user is not None
    assert user.username == "alice"
    assert user.role == AdminRole.VIEWER
    assert user.enabled

    row = (await db.execute(
        select(AdminUser).where(AdminUser.username == "alice")
    )).scalar_one()
    # SSO users get an unusable password hash — local login impossible.
    assert row.password_hash.startswith("!oidc!")


@pytest.mark.asyncio
async def test_provision_updates_existing_role(db: AsyncSession):
    cfg = _cfg(role_claim="groups", role_map={"naco-admins": "SUPERUSER"},
               default_role="VIEWER")
    await oidc.provision_user(db, cfg, {"preferred_username": "bob"})
    user = await oidc.provision_user(
        db, cfg, {"preferred_username": "bob", "groups": ["naco-admins"]}
    )
    assert user is not None
    assert user.role == AdminRole.SUPERUSER


@pytest.mark.asyncio
async def test_provision_denied_without_role(db: AsyncSession):
    """No matching group and no default role → access denied, no user row."""
    cfg = _cfg(default_role="")
    user = await oidc.provision_user(db, cfg, {"preferred_username": "mallory"})
    assert user is None
    row = (await db.execute(
        select(AdminUser).where(AdminUser.username == "mallory")
    )).scalar_one_or_none()
    assert row is None


@pytest.mark.asyncio
async def test_provision_rejects_disabled_user(db: AsyncSession):
    """A locally-disabled admin cannot re-enter via SSO."""
    cfg = _cfg(default_role="VIEWER")
    user = await oidc.provision_user(db, cfg, {"preferred_username": "carol"})
    assert user is not None
    user.enabled = False
    await db.commit()
    again = await oidc.provision_user(db, cfg, {"preferred_username": "carol"})
    assert again is None


@pytest.mark.asyncio
async def test_provision_requires_username_claim(db: AsyncSession):
    cfg = _cfg(default_role="VIEWER")
    assert await oidc.provision_user(db, cfg, {"email": "x@y.z"}) is None
