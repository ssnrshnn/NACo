from datetime import timedelta

import pytest
from sqlalchemy import func, select

from naco import config
from naco.bootstrap import ensure_admin
from naco.config import ConfigError
from naco.core.passwords import verify_password_sync
from naco.core.timeutil import utcnow
from naco.db.models import (
    ActorType,
    AdminRole,
    AdminSession,
    AdminUser,
    AuditLog,
    AuthLog,
    AuthResult,
    GuestRegistration,
    RadiusSession,
)
from naco.maintenance import ACTIVE_SESSIONS, maintenance_pass
from naco.radius import reevaluate


async def test_first_admin_from_environment(app_db, monkeypatch):
    monkeypatch.setenv("NACO_ADMIN_PASSWORD", "a-long-initial-password")
    config.reset_caches()
    assert await ensure_admin() == "a-long-initial-password"
    async with app_db() as db:
        admin = (await db.execute(select(AdminUser))).scalar_one()
    assert admin.username == "admin" and admin.role is AdminRole.SUPERUSER and admin.must_change_password
    assert verify_password_sync("a-long-initial-password", admin.password_hash)
    assert await ensure_admin() is None  # only once


async def test_first_admin_generated_and_printed(app_db, capsys):
    password = await ensure_admin()
    assert password and len(password) >= 12
    assert password in capsys.readouterr().out


async def test_weak_initial_password_is_refused(app_db, monkeypatch):
    monkeypatch.setenv("NACO_ADMIN_PASSWORD", "short")
    config.reset_caches()
    with pytest.raises(ConfigError, match="12"):
        await ensure_admin()


async def test_maintenance_pass(app_db, monkeypatch):
    scheduled = []
    monkeypatch.setattr(reevaluate.reevaluator, "schedule", scheduled.append)
    now = utcnow()
    async with app_db() as db:
        admin = AdminUser(username="a", password_hash="x")
        db.add(admin)
        await db.flush()
        db.add_all([
            AuthLog(result=AuthResult.ACCEPT, timestamp=now - timedelta(days=91)),
            AuthLog(result=AuthResult.ACCEPT, timestamp=now - timedelta(days=1)),
            AuditLog(actor="a", actor_type=ActorType.ADMIN, action="x", timestamp=now - timedelta(days=400)),
            AdminSession(token_hash="1" * 64, admin_id=admin.id, csrf_token="c", expires_at=now - timedelta(1)),
            AdminSession(token_hash="2" * 64, admin_id=admin.id, csrf_token="c", expires_at=now + timedelta(1),
                         last_seen_at=now - timedelta(hours=2)),
            AdminSession(token_hash="3" * 64, admin_id=admin.id, csrf_token="c", expires_at=now + timedelta(1),
                         last_seen_at=now),
            RadiusSession(nas_ip="1", acct_session_id="old", updated_at=now - timedelta(hours=25)),
            RadiusSession(nas_ip="1", acct_session_id="new", updated_at=now),
            GuestRegistration(mac_address="aa:bb:cc:dd:ee:ff", expires_at=now - timedelta(seconds=30)),
        ])
        await db.commit()

    result = await maintenance_pass(since=now - timedelta(minutes=1), now=now)
    assert result.pruned == 2 and result.guests_expired == 1
    assert scheduled == ["guest registrations expired"]
    assert ACTIVE_SESSIONS.value() == 1
    async with app_db() as db:
        assert (await db.execute(select(func.count()).select_from(AuthLog))).scalar_one() == 1
        assert (await db.execute(select(AdminSession.token_hash))).scalars().all() == ["3" * 64]
        assert (await db.execute(select(RadiusSession.acct_session_id))).scalars().all() == ["new"]
