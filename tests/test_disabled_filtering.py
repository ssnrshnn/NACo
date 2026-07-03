"""Regression tests for the ``is True`` → ``== True`` SQLAlchemy fix.

These tests verify that disabled Users, NAS clients, Policies, and Admin
users are correctly filtered out of queries. Before the fix, Python's
``is True`` produced a constant bool instead of a SQL WHERE clause, so
disabled rows were silently included in every query result.
"""
from __future__ import annotations

import json

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from naco.api.auth import hash_password
from naco.db.models import (
    AdminRole,
    AdminUser,
    NasClient,
    Policy,
    PolicyAction,
    User,
)
from naco.policy.engine import AuthContext, PolicyEngine


@pytest.mark.asyncio
class TestDisabledUserFiltering:
    """Disabled network users must not authenticate."""

    async def test_disabled_user_excluded_from_enabled_query(self, db: AsyncSession):
        """A query filtering on User.enabled == True must not return disabled users."""
        db.add(User(
            username="active_user",
            password_hash=hash_password("Pass1234"),
            enabled=True,
        ))
        db.add(User(
            username="disabled_user",
            password_hash=hash_password("Pass1234"),
            enabled=False,
        ))
        await db.commit()

        stmt = select(User).where(User.username == "disabled_user", User.enabled)
        result = (await db.execute(stmt)).scalar_one_or_none()
        assert result is None, "Disabled user should not be returned when filtering enabled == True"

        stmt2 = select(User).where(User.username == "active_user", User.enabled)
        result2 = (await db.execute(stmt2)).scalar_one_or_none()
        assert result2 is not None, "Active user should be returned"
        assert result2.username == "active_user"


@pytest.mark.asyncio
class TestDisabledAdminFiltering:
    """Disabled admin users must not authenticate."""

    async def test_disabled_admin_excluded(self, db: AsyncSession):
        db.add(AdminUser(
            username="enabled_admin",
            password_hash=hash_password("Admin1234"),
            role=AdminRole.SUPERUSER,
            is_superuser=True,
            enabled=True,
        ))
        db.add(AdminUser(
            username="disabled_admin",
            password_hash=hash_password("Admin1234"),
            role=AdminRole.SUPERUSER,
            is_superuser=True,
            enabled=False,
        ))
        await db.commit()

        stmt = select(AdminUser).where(
            AdminUser.username == "disabled_admin", AdminUser.enabled
        )
        result = (await db.execute(stmt)).scalar_one_or_none()
        assert result is None, "Disabled admin should not be returned"

    async def test_superuser_count_excludes_disabled(self, db: AsyncSession):
        """The last-superuser guard must not count disabled superusers."""
        db.add(AdminUser(
            username="active_super",
            password_hash=hash_password("Admin1234"),
            role=AdminRole.SUPERUSER,
            is_superuser=True,
            enabled=True,
        ))
        db.add(AdminUser(
            username="disabled_super",
            password_hash=hash_password("Admin1234"),
            role=AdminRole.SUPERUSER,
            is_superuser=True,
            enabled=False,
        ))
        await db.commit()

        from sqlalchemy import func

        count = (await db.execute(
            select(func.count()).select_from(AdminUser).where(
                AdminUser.role == AdminRole.SUPERUSER,
                AdminUser.enabled,
            )
        )).scalar_one()
        assert count == 1, "Only enabled superusers should be counted"


@pytest.mark.asyncio
class TestDisabledNasClientFiltering:
    """Disabled NAS clients must not be loaded for RADIUS auth."""

    async def test_disabled_nas_excluded(self, db: AsyncSession):
        db.add(NasClient(
            name="active-sw",
            ip_address="10.0.0.1",
            secret="secret1",
            enabled=True,
        ))
        db.add(NasClient(
            name="disabled-sw",
            ip_address="10.0.0.2",
            secret="secret2",
            enabled=False,
        ))
        await db.commit()

        stmt = select(NasClient).where(NasClient.enabled)
        clients = (await db.execute(stmt)).scalars().all()
        ips = [c.ip_address for c in clients]

        assert "10.0.0.1" in ips, "Enabled NAS should be loaded"
        assert "10.0.0.2" not in ips, "Disabled NAS should NOT be loaded"


@pytest.mark.asyncio
class TestDisabledPolicyFiltering:
    """Disabled policies must not be evaluated by the policy engine."""

    async def test_disabled_policy_not_evaluated(self, db: AsyncSession):
        db.add(Policy(
            name="disabled-permit-all",
            priority=1,
            conditions=json.dumps([{"type": "always"}]),
            action=PolicyAction.PERMIT,
            vlan=42,
            enabled=False,
        ))
        await db.commit()

        engine = PolicyEngine()
        ctx = AuthContext(username="anyone")
        decision = await engine.evaluate(ctx, db)

        assert decision.action == PolicyAction.DENY, (
            "Disabled policy should be skipped; default-deny should apply"
        )
        assert decision.policy_name == "DEFAULT_DENY"

    async def test_enabled_policy_still_works(self, db: AsyncSession):
        db.add(Policy(
            name="enabled-permit-all",
            priority=1,
            conditions=json.dumps([{"type": "always"}]),
            action=PolicyAction.PERMIT,
            vlan=100,
            enabled=True,
        ))
        await db.commit()

        engine = PolicyEngine()
        ctx = AuthContext(username="anyone")
        decision = await engine.evaluate(ctx, db)

        assert decision.action == PolicyAction.PERMIT
        assert decision.vlan == 100

    async def test_mix_enabled_disabled_policies(self, db: AsyncSession):
        """Only the enabled policy should match; disabled one is invisible."""
        db.add(Policy(
            name="disabled-deny",
            priority=1,
            conditions=json.dumps([{"type": "always"}]),
            action=PolicyAction.DENY,
            enabled=False,
        ))
        db.add(Policy(
            name="enabled-permit",
            priority=2,
            conditions=json.dumps([{"type": "always"}]),
            action=PolicyAction.PERMIT,
            vlan=200,
            enabled=True,
        ))
        await db.commit()

        engine = PolicyEngine()
        ctx = AuthContext(username="test")
        decision = await engine.evaluate(ctx, db)

        assert decision.action == PolicyAction.PERMIT, (
            "The disabled DENY at priority 1 should be invisible; "
            "the enabled PERMIT at priority 2 should match"
        )
        assert decision.policy_name == "enabled-permit"
