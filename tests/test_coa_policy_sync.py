"""CoA session synchronisation (naco.radius.coa_sync) + bulk disconnect API.

Covers:
* sessions_matching_conditions — same semantics as the policy engine for
  every condition type (always / username / mac / nas_ip / group / device_type)
* disconnect_sessions — summary bookkeeping with a mocked RFC 5176 sender
* schedule_policy_coa — honours radius.coa_on_policy_change
* POST /api/v1/sessions/disconnect — filter validation + end-to-end flow
"""
from __future__ import annotations

import asyncio

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

import naco.radius.coa_sync as coa_sync
from naco.db.models import ActiveSession, AdminUser, Device, Group, NasClient, User

pytestmark = pytest.mark.asyncio


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _session(**kw) -> ActiveSession:
    defaults = {
        "session_id": f"acct-{kw.get('username', 'x')}-{kw.get('mac_address', '')}",
        "username": "alice",
        "mac_address": "aa:bb:cc:dd:ee:01",
        "nas_ip": "10.0.0.1",
    }
    defaults.update(kw)
    return ActiveSession(**defaults)


# ---------------------------------------------------------------------------
# sessions_matching_conditions
# ---------------------------------------------------------------------------

class TestSessionsMatchingConditions:
    async def test_always_matches_everything(self, db: AsyncSession):
        db.add_all([_session(session_id="s1"), _session(session_id="s2", username="bob")])
        await db.commit()
        matched = await coa_sync.sessions_matching_conditions(
            [{"type": "always"}], db
        )
        assert len(matched) == 2

    async def test_username_equals(self, db: AsyncSession):
        db.add_all([
            _session(session_id="s1", username="alice"),
            _session(session_id="s2", username="bob"),
        ])
        await db.commit()
        matched = await coa_sync.sessions_matching_conditions(
            [{"type": "username", "op": "equals", "value": "alice"}], db
        )
        assert [s.username for s in matched] == ["alice"]

    async def test_mac_in_list(self, db: AsyncSession):
        db.add_all([
            _session(session_id="s1", mac_address="aa:bb:cc:dd:ee:01"),
            _session(session_id="s2", mac_address="aa:bb:cc:dd:ee:02"),
        ])
        await db.commit()
        matched = await coa_sync.sessions_matching_conditions(
            [{"type": "mac", "op": "in", "value": ["AA-BB-CC-DD-EE-02"]}], db
        )
        assert [s.mac_address for s in matched] == ["aa:bb:cc:dd:ee:02"]

    async def test_nas_ip_equals(self, db: AsyncSession):
        db.add_all([
            _session(session_id="s1", nas_ip="10.0.0.1"),
            _session(session_id="s2", nas_ip="10.0.0.2"),
        ])
        await db.commit()
        matched = await coa_sync.sessions_matching_conditions(
            [{"type": "nas_ip", "op": "equals", "value": "10.0.0.2"}], db
        )
        assert [s.nas_ip for s in matched] == ["10.0.0.2"]

    async def test_group_resolved_from_user_record(self, db: AsyncSession):
        grp = Group(name="employees")
        db.add(grp)
        await db.flush()
        db.add(User(username="alice", password_hash="x", group_id=grp.id))
        db.add(User(username="bob", password_hash="x"))
        db.add_all([
            _session(session_id="s1", username="alice"),
            _session(session_id="s2", username="bob"),
        ])
        await db.commit()
        matched = await coa_sync.sessions_matching_conditions(
            [{"type": "group", "op": "in", "value": ["employees"]}], db
        )
        assert [s.username for s in matched] == ["alice"]

    async def test_device_type_resolved_from_inventory(self, db: AsyncSession):
        db.add(Device(mac_address="aa:bb:cc:dd:ee:01", device_type="printer"))
        db.add_all([
            _session(session_id="s1", mac_address="aa:bb:cc:dd:ee:01"),
            _session(session_id="s2", mac_address="aa:bb:cc:dd:ee:02"),  # unknown
        ])
        await db.commit()
        matched = await coa_sync.sessions_matching_conditions(
            [{"type": "device_type", "value": ["printer"]}], db
        )
        assert [s.mac_address for s in matched] == ["aa:bb:cc:dd:ee:01"]

    async def test_conditions_as_json_text(self, db: AsyncSession):
        """SQLite stores Policy.conditions as JSON text — must still parse."""
        db.add(_session(session_id="s1"))
        await db.commit()
        matched = await coa_sync.sessions_matching_conditions('[{"type": "always"}]', db)
        assert len(matched) == 1

    async def test_garbage_conditions_match_nothing(self, db: AsyncSession):
        """Unparseable conditions must fail safe — never a mass disconnect."""
        db.add(_session(session_id="s1"))
        await db.commit()
        assert await coa_sync.sessions_matching_conditions("{not json", db) == []
        assert await coa_sync.sessions_matching_conditions({"type": "always"}, db) == []

    async def test_empty_conditions_match_everything(self, db: AsyncSession):
        """Engine semantics: empty condition list = match-all policy."""
        db.add(_session(session_id="s1"))
        await db.commit()
        assert len(await coa_sync.sessions_matching_conditions([], db)) == 1
        assert len(await coa_sync.sessions_matching_conditions(None, db)) == 1


# ---------------------------------------------------------------------------
# disconnect_sessions — summary bookkeeping (sender mocked)
# ---------------------------------------------------------------------------

class TestDisconnectSessions:
    async def test_summary_acked_failed_skipped(self, db: AsyncSession, monkeypatch):
        db.add(NasClient(name="sw1", ip_address="10.0.0.1",
                         secret="a-strong-shared-secret", enabled=True))
        await db.commit()

        sessions = [
            _session(session_id="ok-1"),                      # NAS known → acked
            _session(session_id="nak-1", username="bob"),     # NAS known → NAK
            _session(session_id="no-nas", nas_ip=""),         # no NAS IP → skipped
            _session(session_id="no-secret", nas_ip="10.9.9.9"),  # unknown NAS → skipped
        ]

        async def fake_send(nas_ip, session_id, username="", secret="", **kw):
            assert secret == "a-strong-shared-secret"
            return {"success": session_id != "nak-1", "code": 41, "message": ""}

        monkeypatch.setattr(coa_sync, "send_disconnect_request", fake_send)
        summary = await coa_sync.disconnect_sessions(sessions, db)
        assert summary == {"total": 4, "acked": 1, "failed": 1, "skipped": 2}

    async def test_config_fallback_secret(self, db: AsyncSession, monkeypatch):
        """No NasClient row — secret comes from radius.clients in config
        (test_config.yaml defines 127.0.0.1 / testing123)."""
        seen = {}

        async def fake_send(nas_ip, session_id, username="", secret="", **kw):
            seen["secret"] = secret
            return {"success": True, "code": 41, "message": ""}

        monkeypatch.setattr(coa_sync, "send_disconnect_request", fake_send)
        summary = await coa_sync.disconnect_sessions(
            [_session(session_id="s1", nas_ip="127.0.0.1")], db
        )
        assert summary["acked"] == 1
        assert seen["secret"] == "testing123"


# ---------------------------------------------------------------------------
# schedule_policy_coa — config gate
# ---------------------------------------------------------------------------

class TestSchedulePolicyCoa:
    async def test_disabled_flag_schedules_nothing(self, monkeypatch):
        from naco.config import get_config
        cfg = get_config().model_copy(deep=True)
        cfg.radius.coa_on_policy_change = False
        monkeypatch.setattr(coa_sync, "get_config", lambda: cfg)

        called = False

        async def fake_task(sets):
            nonlocal called
            called = True

        monkeypatch.setattr(coa_sync, "coa_after_policy_change", fake_task)
        coa_sync.schedule_policy_coa([{"type": "always"}])
        await asyncio.sleep(0)
        assert not called

    async def test_enabled_flag_runs_task(self, monkeypatch):
        from naco.config import get_config
        cfg = get_config().model_copy(deep=True)
        cfg.radius.coa_on_policy_change = True
        monkeypatch.setattr(coa_sync, "get_config", lambda: cfg)

        received = []

        async def fake_task(sets):
            received.append(sets)
            return {"total": 0, "acked": 0, "failed": 0, "skipped": 0}

        monkeypatch.setattr(coa_sync, "coa_after_policy_change", fake_task)
        coa_sync.schedule_policy_coa([{"type": "always"}], [{"type": "username"}])
        await asyncio.sleep(0)
        assert received == [[[{"type": "always"}], [{"type": "username"}]]]


# ---------------------------------------------------------------------------
# POST /api/v1/sessions/disconnect
# ---------------------------------------------------------------------------

class TestBulkDisconnectApi:
    async def test_empty_filter_rejected(self, client: AsyncClient, admin_user: AdminUser, admin_token: str):
        r = await client.post("/api/v1/sessions/disconnect", json={}, headers=_auth(admin_token))
        assert r.status_code == 422

    async def test_invalid_mac_rejected(self, client: AsyncClient, admin_user: AdminUser, admin_token: str):
        r = await client.post(
            "/api/v1/sessions/disconnect",
            json={"mac_address": "not-a-mac"}, headers=_auth(admin_token),
        )
        assert r.status_code == 422

    async def test_no_matching_sessions(self, client: AsyncClient, admin_user: AdminUser, admin_token: str):
        r = await client.post(
            "/api/v1/sessions/disconnect",
            json={"username": "ghost"}, headers=_auth(admin_token),
        )
        assert r.status_code == 200
        assert "No matching" in r.json()["message"]

    async def test_filtered_disconnect(
        self, client: AsyncClient, db: AsyncSession,
        admin_user: AdminUser, admin_token: str, monkeypatch,
    ):
        db.add(NasClient(name="sw1", ip_address="10.0.0.1",
                         secret="a-strong-shared-secret", enabled=True))
        db.add_all([
            _session(session_id="s1", username="alice"),
            _session(session_id="s2", username="alice", mac_address="aa:bb:cc:dd:ee:02"),
            _session(session_id="s3", username="bob"),
        ])
        await db.commit()

        sent = []

        async def fake_send(nas_ip, session_id, username="", secret="", **kw):
            sent.append(session_id)
            return {"success": True, "code": 41, "message": ""}

        monkeypatch.setattr(coa_sync, "send_disconnect_request", fake_send)
        r = await client.post(
            "/api/v1/sessions/disconnect",
            json={"username": "alice"}, headers=_auth(admin_token),
        )
        assert r.status_code == 200, r.text
        assert "2 session(s): 2 acked" in r.json()["message"]
        assert sorted(sent) == ["s1", "s2"]

    async def test_viewer_forbidden(self, client: AsyncClient, admin_user: AdminUser, admin_token: str, db: AsyncSession):
        from naco.api.auth import hash_password
        from naco.db.models import AdminRole
        db.add(AdminUser(username="viewer", password_hash=hash_password("Viewer1234"),
                         role=AdminRole.VIEWER, enabled=True))
        await db.commit()
        login = await client.post("/api/v1/auth/login",
                                  json={"username": "viewer", "password": "Viewer1234"})
        token = login.json()["access_token"]
        r = await client.post("/api/v1/sessions/disconnect",
                              json={"all": True}, headers=_auth(token))
        assert r.status_code == 403
