"""Liveness vs readiness probe split (/health/live, /health/ready, /health)."""
from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

pytestmark = pytest.mark.asyncio


class TestLiveness:
    async def test_live_returns_200_without_db(self):
        """Liveness must not touch any dependency — no DB override needed."""
        from naco.api import create_api_app

        app = create_api_app()
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            r = await ac.get("/api/v1/health/live")
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "alive"
        assert "version" in body


class TestReadiness:
    async def test_ready_ok_with_working_db(self, client: AsyncClient):
        r = await client.get("/api/v1/health/ready")
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "ok"
        assert body["database"] == "connected"
        assert "redis" in body
        assert "services" in body

    async def test_health_alias_matches_ready(self, client: AsyncClient):
        alias = await client.get("/api/v1/health")
        ready = await client.get("/api/v1/health/ready")
        assert alias.status_code == ready.status_code == 200
        assert alias.json() == ready.json()

    async def test_ready_503_when_db_down(self):
        """A broken DB session must flip readiness to 503 (but not liveness)."""
        from naco.api import create_api_app
        from naco.db import get_db

        class _BrokenSession:
            async def execute(self, *a, **kw):
                raise RuntimeError("db is down")

        app = create_api_app()

        async def _broken_db():
            yield _BrokenSession()

        app.dependency_overrides[get_db] = _broken_db
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            ready = await ac.get("/api/v1/health/ready")
            live = await ac.get("/api/v1/health/live")
        assert ready.status_code == 503
        assert ready.json()["database"] == "error"
        assert live.status_code == 200
