"""Guest portal (CWA): the device is identified by its RADIUS session, never by the form."""
from datetime import timedelta

import pytest
from sqlalchemy import select

from naco.core.timeutil import utcnow
from naco.db.models import Device, DeviceStatus, GuestRegistration, RadiusSession
from naco.portal import app as portal
from naco.radius import reevaluate
from tests.conftest import write_config

CLIENT_IP = "203.0.113.7"  # the test client's address (tests/api/conftest.py)
MAC = "aa:bb:cc:00:00:07"


@pytest.fixture(autouse=True)
def _reset():
    portal.reset_rate_limit()


@pytest.fixture
def scheduled(monkeypatch):
    calls = []
    monkeypatch.setattr(reevaluate.reevaluator, "schedule", calls.append)
    return calls


async def add_session(sf, *, ip=CLIENT_IP, mac=MAC, age=timedelta(0)):
    async with sf() as db:
        db.add(RadiusSession(nas_ip="10.0.0.1", acct_session_id=f"S-{mac}", mac_address=mac, framed_ip=ip,
                             updated_at=utcnow() - age))
        await db.commit()


async def open_form(api) -> str:
    r = await api.get("/portal")
    assert r.status_code == 200 and "Accept the terms" in r.text
    return r.cookies["naco_portal"]


async def test_unknown_device_waits(api):
    r = await api.get("/portal")
    assert "Recognising your device" in r.text and 'http-equiv="refresh"' in r.text
    await add_session(api.sf, age=timedelta(minutes=30))  # older than match_window_minutes
    assert "Recognising" in (await api.get("/portal/")).text


async def test_registration_uses_the_session_mac_not_the_form(api, scheduled):
    await add_session(api.sf)
    token = await open_form(api)
    r = await api.post("/portal/register", data={"csrf": token, "accept": "yes", "full_name": "Ada",
                                                  "mac": "11:22:33:44:55:66"})
    assert r.status_code == 200 and "all set" in r.text
    async with api.sf() as db:
        (reg,) = (await db.execute(select(GuestRegistration))).scalars()
        device = (await db.execute(select(Device))).scalar_one()
    assert (reg.mac_address, reg.client_ip, reg.full_name, reg.created_by) == (MAC, CLIENT_IP, "Ada", "portal")
    assert timedelta(hours=7, minutes=59) < reg.expires_at - reg.created_at <= timedelta(hours=8)
    assert device.mac_address == MAC and device.status is DeviceStatus.PENDING
    assert scheduled == [f"portal registration {MAC}"]


async def test_csrf_and_terms_are_required(api, scheduled):
    await add_session(api.sf)
    token = await open_form(api)
    assert (await api.post("/portal/register", data={"csrf": "forged", "accept": "yes"})).status_code == 403
    cross = await api.post("/portal/register", data={"csrf": token, "accept": "yes"},
                           headers={"Origin": "http://evil.example"})
    assert cross.status_code == 403
    no_terms = await api.post("/portal/register", data={"csrf": token})
    assert no_terms.status_code == 422 and "accept the terms" in no_terms.text
    assert scheduled == []


async def test_access_code(api, tmp_path, monkeypatch, scheduled):
    write_config(tmp_path, monkeypatch, "portal:\n  access_code: 'Sesame-42'\n  organization: Acme\n")
    await add_session(api.sf)
    token = await open_form(api)
    page = await api.get("/portal")
    assert "Access code" in page.text and "Acme" in page.text
    token = page.cookies["naco_portal"]
    wrong = await api.post("/portal/register", data={"csrf": token, "accept": "yes", "code": "nope"})
    assert wrong.status_code == 422 and "access code" in wrong.text
    ok = await api.post("/portal/register", data={"csrf": token, "accept": "yes", "code": " Sesame-42 "})
    assert ok.status_code == 200


async def test_blocked_device_cannot_register(api, scheduled):
    await add_session(api.sf)
    async with api.sf() as db:
        db.add(Device(mac_address=MAC, status=DeviceStatus.BLOCKED))
        await db.commit()
    r = await api.get("/portal")
    assert r.status_code == 403 and "not available" in r.text


async def test_rate_limit(api):
    await add_session(api.sf)
    token = await open_form(api)
    for _ in range(10):
        await api.post("/portal/register", data={"csrf": token})
    assert (await api.post("/portal/register", data={"csrf": token, "accept": "yes"})).status_code == 429


async def test_portal_can_be_disabled(api, tmp_path, monkeypatch):
    write_config(tmp_path, monkeypatch, "portal:\n  enabled: false\n")
    assert (await api.get("/portal")).status_code == 404


async def test_pages_have_a_strict_csp(api):
    r = await api.get("/portal")
    csp = r.headers["content-security-policy"]
    assert "script-src 'self'" in csp and "unsafe-inline" not in csp and "frame-ancestors 'none'" in csp
    assert (await api.get("/static/css/portal.css")).status_code == 200
