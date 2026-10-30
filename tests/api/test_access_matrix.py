"""Generic guarantees over every API route — new routes are covered automatically.

* every non-public route has exactly one role gate (``require``);
* every state-changing route records to the audit trail;
* with a real session, each role gets 403 exactly where its rank is too low;
* cookie-authenticated state changes without the CSRF token are refused.
"""
from __future__ import annotations

import re
from typing import Any

import httpx
import pytest

from naco.api.audit import audit_trail
from naco.api.router import PUBLIC_ROUTES, iter_api_routes
from naco.db.models import AdminRole
from naco.web.app import create_public_app
from tests.api.conftest import BASE, code, make_admin, sign_in

MUTATING = {"POST", "PUT", "PATCH", "DELETE"}
READ_ONLY_POSTS = {("POST", "/api/v1/policies/simulate")}
# Not exercised in the live matrix: ends the caller's own session / streams forever.
NOT_CALLED = {("POST", "/api/v1/auth/logout"), ("GET", "/api/v1/events")}


def _calls(dependant: Any) -> list[Any]:
    out = []
    for dep in dependant.dependencies:
        out.append(dep.call)
        out.extend(_calls(dep))
    return out


def gate(route: Any) -> tuple[AdminRole, bool] | None:
    gates = [c for c in _calls(route.dependant) if hasattr(c, "naco_role")]
    assert len(gates) <= 1, f"{route.path}: more than one role gate"
    return (gates[0].naco_role, gates[0].naco_setup_allowed) if gates else None


ROUTES = list(iter_api_routes())

V, O, S = AdminRole.VIEWER, AdminRole.OPERATOR, AdminRole.SUPERUSER  # noqa: E741 — table shorthand
SETUP = "setup"  # reachable before first-login setup (password change / TOTP) is finished

# The access matrix (spec §4.3) — the single source of truth. A new route must be added here.
EXPECTED: dict[tuple[str, str], tuple[AdminRole, str | None]] = {
    ("POST", "/api/v1/auth/logout"): (V, SETUP),
    ("GET", "/api/v1/auth/me"): (V, SETUP),
    ("POST", "/api/v1/auth/password"): (V, SETUP),
    ("POST", "/api/v1/auth/totp/setup"): (V, SETUP),
    ("POST", "/api/v1/auth/totp/confirm"): (V, SETUP),
    ("POST", "/api/v1/auth/totp/disable"): (V, SETUP),
    ("GET", "/api/v1/auth/sessions"): (V, SETUP),
    ("DELETE", "/api/v1/auth/sessions/{session_id}"): (V, SETUP),
    ("GET", "/api/v1/users"): (V, None),
    ("GET", "/api/v1/users/{user_id}"): (V, None),
    ("POST", "/api/v1/users"): (O, None),
    ("PATCH", "/api/v1/users/{user_id}"): (O, None),
    ("DELETE", "/api/v1/users/{user_id}"): (O, None),
    ("GET", "/api/v1/groups"): (V, None),
    ("POST", "/api/v1/groups"): (S, None),
    ("PATCH", "/api/v1/groups/{group_id}"): (S, None),
    ("DELETE", "/api/v1/groups/{group_id}"): (S, None),
    ("GET", "/api/v1/devices"): (V, None),
    ("GET", "/api/v1/devices/{device_id}"): (V, None),
    ("POST", "/api/v1/devices"): (O, None),
    ("PATCH", "/api/v1/devices/{device_id}"): (O, None),
    ("POST", "/api/v1/devices/bulk"): (O, None),
    ("DELETE", "/api/v1/devices/{device_id}"): (O, None),
    ("GET", "/api/v1/policies"): (V, None),
    ("GET", "/api/v1/policies/{policy_id}"): (V, None),
    ("POST", "/api/v1/policies"): (S, None),
    ("PATCH", "/api/v1/policies/{policy_id}"): (S, None),
    ("DELETE", "/api/v1/policies/{policy_id}"): (S, None),
    ("POST", "/api/v1/policies/reorder"): (S, None),
    ("POST", "/api/v1/policies/simulate"): (V, None),
    ("GET", "/api/v1/nas"): (V, None),
    ("POST", "/api/v1/nas"): (S, None),
    ("PATCH", "/api/v1/nas/{nas_id}"): (S, None),
    ("GET", "/api/v1/nas/{nas_id}/secret"): (S, None),
    ("DELETE", "/api/v1/nas/{nas_id}"): (S, None),
    ("GET", "/api/v1/tacacs-clients"): (V, None),
    ("POST", "/api/v1/tacacs-clients"): (S, None),
    ("PATCH", "/api/v1/tacacs-clients/{client_id}"): (S, None),
    ("GET", "/api/v1/tacacs-clients/{client_id}/key"): (S, None),
    ("DELETE", "/api/v1/tacacs-clients/{client_id}"): (S, None),
    ("GET", "/api/v1/command-sets"): (V, None),
    ("POST", "/api/v1/command-sets"): (S, None),
    ("PATCH", "/api/v1/command-sets/{set_id}"): (S, None),
    ("DELETE", "/api/v1/command-sets/{set_id}"): (S, None),
    ("GET", "/api/v1/sessions"): (V, None),
    ("POST", "/api/v1/sessions/{session_id}/disconnect"): (O, None),
    ("POST", "/api/v1/sessions/disconnect"): (O, None),
    ("GET", "/api/v1/guests"): (V, None),
    ("POST", "/api/v1/guests"): (O, None),
    ("DELETE", "/api/v1/guests/{guest_id}"): (O, None),
    ("GET", "/api/v1/logs/auth"): (V, None),
    ("GET", "/api/v1/logs/tacacs"): (V, None),
    ("GET", "/api/v1/audit"): (O, None),
    ("GET", "/api/v1/admins"): (S, None),
    ("POST", "/api/v1/admins"): (S, None),
    ("PATCH", "/api/v1/admins/{admin_id}"): (S, None),
    ("POST", "/api/v1/admins/{admin_id}/reset-password"): (S, None),
    ("POST", "/api/v1/admins/{admin_id}/reset-totp"): (S, None),
    ("DELETE", "/api/v1/admins/{admin_id}"): (S, None),
    ("GET", "/api/v1/tokens"): (S, None),
    ("POST", "/api/v1/tokens"): (S, None),
    ("DELETE", "/api/v1/tokens/{token_id}"): (S, None),
    ("GET", "/api/v1/export/{kind}.csv"): (V, None),
    ("POST", "/api/v1/import/users"): (O, None),
    ("POST", "/api/v1/import/devices"): (O, None),
    ("POST", "/api/v1/import/nas"): (S, None),
    ("GET", "/api/v1/dashboard"): (V, None),
    ("GET", "/api/v1/system"): (V, None),
    ("GET", "/api/v1/openapi.json"): (V, None),
    ("GET", "/api/v1/events"): (V, None),
}


def test_route_inventory_is_non_trivial():
    assert len(ROUTES) > 60


@pytest.mark.parametrize("method,path,route", ROUTES, ids=[f"{m} {p}" for m, p, _ in ROUTES])
def test_every_route_matches_the_access_matrix(method, path, route):
    if (method, path) in PUBLIC_ROUTES:
        assert gate(route) is None
        return
    assert (method, path) in EXPECTED, f"{method} {path} is missing from the access matrix"
    role, setup = EXPECTED[(method, path)]
    assert gate(route) == (role, setup == SETUP), f"{method} {path}: gate differs from the access matrix"


def test_matrix_has_no_stale_entries():
    live = {(m, p) for m, p, _ in ROUTES}
    assert set(EXPECTED) <= live, f"routes gone: {set(EXPECTED) - live}"


@pytest.mark.parametrize("method,path,route", ROUTES, ids=[f"{m} {p}" for m, p, _ in ROUTES])
def test_every_change_is_audited(method, path, route):
    if method not in MUTATING or (method, path) in PUBLIC_ROUTES | READ_ONLY_POSTS:
        return
    assert audit_trail in _calls(route.dependant), f"{method} {path} does not record to the audit trail"


def _concrete(path: str) -> str:
    return re.sub(r"\{(\w+)\}", lambda m: "users" if m.group(1) == "kind" else "999999", path)


async def _client(sf, username: str, role: AdminRole, offset: int) -> httpx.AsyncClient:
    await make_admin(sf, username, role)
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=create_public_app()), base_url=BASE)
    await sign_in(client, username, totp_code=code(offset=offset))
    return client


async def test_role_matrix_and_csrf_with_real_sessions(api):
    clients = {
        AdminRole.VIEWER: await _client(api.sf, "v", AdminRole.VIEWER, -1),
        AdminRole.OPERATOR: await _client(api.sf, "o", AdminRole.OPERATOR, 0),
        AdminRole.SUPERUSER: await _client(api.sf, "s", AdminRole.SUPERUSER, 1),
    }
    problems = []
    try:
        for method, path, route in ROUTES:
            if (method, path) in PUBLIC_ROUTES | NOT_CALLED:
                continue
            required, _ = gate(route)
            url = _concrete(path)
            kwargs = {"json": {}} if method in MUTATING else {}
            for role, client in clients.items():
                r = await client.request(method, url, **kwargs)
                denied = r.status_code == 403 and r.json()["error"]["code"] == "forbidden"
                if role.allows(required) == denied:
                    problems.append(f"{role.value:9} {method} {path} -> {r.status_code} {r.text[:80]}")

            # Same session, no CSRF header: every state change must be refused.
            if method in MUTATING:
                superuser = clients[AdminRole.SUPERUSER]
                csrf = superuser.headers.pop("X-CSRF-Token")
                r = await superuser.request(method, url, **kwargs)
                superuser.headers["X-CSRF-Token"] = csrf
                if r.status_code != 403 or r.json()["error"]["code"] != "csrf":
                    problems.append(f"no-csrf   {method} {path} -> {r.status_code}")

            # Nobody signed in: always 401.
            anon = await api.request(method, url, **kwargs)
            if anon.status_code != 401:
                problems.append(f"anonymous {method} {path} -> {anon.status_code}")
    finally:
        for client in clients.values():
            await client.aclose()
    assert not problems, "\n".join(problems)
