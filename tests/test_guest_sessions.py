"""Captive-portal guest sessions — expiry and MAB integration.

Regression tests for two bugs found in review:

1. ``GuestSession.active is True`` (Python identity, always False) was used
   in SQLAlchemy ``where()`` clauses — the expiry loop, the portal ``/status``
   endpoint, and the re-registration path silently matched nothing, so guest
   sessions never expired and status checks always reported inactive.
2. The RADIUS MAB path never consulted guest sessions at all, so a
   registered guest's MAC was still rejected — the documented portal flow
   ("the device MAC is authorised for the session duration") did not work.
"""
from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from naco.core.utils import utcnow
from naco.db.models import AuthResult, Device, GuestSession


def _guest(mac: str, *, hours: float = 8, active: bool = True) -> GuestSession:
    return GuestSession(
        token=f"tok-{mac.replace(':', '')}-{hours}-{active}",
        email="guest@test.local",
        full_name="Guest User",
        mac_address=mac,
        expires_at=utcnow() + timedelta(hours=hours),
        active=active,
    )


# ---------------------------------------------------------------------------
# Expiry sweep
# ---------------------------------------------------------------------------

class TestGuestSessionExpiry:
    @pytest.mark.asyncio
    async def test_overdue_sessions_are_deactivated(self, db: AsyncSession):
        from naco.portal.app import expire_overdue_guest_sessions

        db.add(_guest("aa:bb:cc:00:00:01", hours=-1))   # overdue
        db.add(_guest("aa:bb:cc:00:00:02", hours=4))    # still valid
        await db.commit()

        expired = await expire_overdue_guest_sessions(db)
        assert expired == 1

        rows = (await db.execute(select(GuestSession))).scalars().all()
        by_mac = {r.mac_address: r.active for r in rows}
        assert by_mac["aa:bb:cc:00:00:01"] is False
        assert by_mac["aa:bb:cc:00:00:02"] is True

    @pytest.mark.asyncio
    async def test_inactive_sessions_untouched(self, db: AsyncSession):
        from naco.portal.app import expire_overdue_guest_sessions

        db.add(_guest("aa:bb:cc:00:00:03", hours=-2, active=False))
        await db.commit()
        assert await expire_overdue_guest_sessions(db) == 0


# ---------------------------------------------------------------------------
# MAB ↔ guest-session linkage
# ---------------------------------------------------------------------------

class TestGuestSessionMab:
    @pytest.mark.asyncio
    async def test_active_session_detected(self, db: AsyncSession):
        from naco.radius.server import _has_active_guest_session

        db.add(_guest("de:ad:be:ef:00:01"))
        await db.commit()
        assert await _has_active_guest_session(db, "de:ad:be:ef:00:01") is True

    @pytest.mark.asyncio
    async def test_expired_or_inactive_sessions_ignored(self, db: AsyncSession):
        from naco.radius.server import _has_active_guest_session

        db.add(_guest("de:ad:be:ef:00:02", hours=-1))               # expired
        db.add(_guest("de:ad:be:ef:00:03", active=False))           # deactivated
        await db.commit()
        assert await _has_active_guest_session(db, "de:ad:be:ef:00:02") is False
        assert await _has_active_guest_session(db, "de:ad:be:ef:00:03") is False
        assert await _has_active_guest_session(db, "") is False

    @pytest.mark.asyncio
    async def test_mab_accepts_guest_session_mac(
        self, db: AsyncSession, monkeypatch: pytest.MonkeyPatch
    ):
        """An unknown MAC with a live guest session passes the MAB check."""
        import naco.radius.server as radius_server
        from tests.conftest import _TestSession

        monkeypatch.setattr(radius_server, "AsyncSessionLocal", _TestSession)

        db.add(_guest("de:ad:be:ef:00:04"))
        await db.commit()

        server = radius_server.NACoRadiusServer()
        result, reason = await server._check_device_authorized("de:ad:be:ef:00:04")
        assert result == AuthResult.SUCCESS
        assert "Guest" in reason

    @pytest.mark.asyncio
    async def test_mab_still_rejects_unknown_mac(
        self, db: AsyncSession, monkeypatch: pytest.MonkeyPatch
    ):
        import naco.radius.server as radius_server
        from tests.conftest import _TestSession

        monkeypatch.setattr(radius_server, "AsyncSessionLocal", _TestSession)

        server = radius_server.NACoRadiusServer()
        result, reason = await server._check_device_authorized("00:11:22:33:44:55")
        assert result == AuthResult.FAILURE
        assert reason == "Unknown MAC"

    @pytest.mark.asyncio
    async def test_mab_still_rejects_unauthorized_inventory_device(
        self, db: AsyncSession, monkeypatch: pytest.MonkeyPatch
    ):
        """Profiler-discovered (unauthorized) devices without a guest session
        stay rejected — the default-deny posture is unchanged."""
        import naco.radius.server as radius_server
        from tests.conftest import _TestSession

        monkeypatch.setattr(radius_server, "AsyncSessionLocal", _TestSession)

        db.add(Device(mac_address="00:11:22:33:44:66", authorized=False))
        await db.commit()

        server = radius_server.NACoRadiusServer()
        result, reason = await server._check_device_authorized("00:11:22:33:44:66")
        assert result == AuthResult.FAILURE
        assert reason == "MAC not authorised"
