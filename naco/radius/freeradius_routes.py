"""
First-class EAP REST integration
================================
Mounted on the consolidated NACo app at ``/api/v1/eap/*``.

When FreeRADIUS is deployed as the outer RADIUS listener (EAP-PEAP, EAP-TLS,
EAP-TTLS), its ``rlm_rest`` module calls these endpoints to delegate the
*identity verification + authorisation + accounting* phases to NACo. NACo
remains the single source of truth for users, policies, and sessions; only
the EAP state machine itself runs inside FreeRADIUS.

Authentication
--------------
All endpoints require the bearer token configured under ``eap.bearer_token``.
Because FreeRADIUS lives in a sibling Docker container, the legacy
"127.0.0.1 only" check is no longer sufficient — it would either reject
every legitimate request (FreeRADIUS appears as the docker bridge gateway)
or open the endpoint to every container on the network. A shared secret
gives us a clean, container-friendly auth model.
"""
from __future__ import annotations

from datetime import datetime, timezone

import bcrypt
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import delete as sa_delete, select, update as sa_update
from sqlalchemy.ext.asyncio import AsyncSession

from naco.config import get_config
from naco.core.events import Event, EventType, bus
from naco.core.logger import get_logger
from naco.core.utils import normalise_mac
from naco.db import get_db
from naco.db.models import (
    ActiveSession, AuthLog, AuthMethod, AuthResult, User,
)
from naco.policy.engine import AuthContext, engine as policy_engine

log = get_logger(__name__)

router = APIRouter(prefix="/api/v1/eap", tags=["EAP / FreeRADIUS"])


# ---------------------------------------------------------------------------
# Auth dependency
# ---------------------------------------------------------------------------

def _require_eap_bearer(request: Request) -> None:
    cfg = get_config().eap
    if not cfg.enabled:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "EAP integration disabled")
    if not cfg.bearer_token:
        log.error("eap.bearer_token is empty — refusing all EAP requests")
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "EAP integration not configured")

    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing bearer token")
    presented = auth.split(" ", 1)[1].strip()
    # Constant-time compare to avoid timing side-channels.
    import hmac as _hmac
    if not _hmac.compare_digest(presented, cfg.bearer_token):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid bearer token")


# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------

class EapAuthRequest(BaseModel):
    username: str
    password: str | None = None
    nas_ip: str | None = None
    nas_port: str | None = None
    calling_station_id: str | None = None
    called_station_id: str | None = None


class EapAuthorizeRequest(BaseModel):
    username: str
    nas_ip: str | None = None
    calling_station_id: str | None = None


class EapAccountingRequest(BaseModel):
    status_type: str | None = None
    username: str | None = None
    session_id: str | None = None
    nas_ip: str | None = None
    framed_ip: str | None = None
    calling_station: str | None = None
    input_octets: str | None = None
    output_octets: str | None = None
    session_time: str | None = None


# ---------------------------------------------------------------------------
# Authenticate (rlm_rest "auth" hook)
# ---------------------------------------------------------------------------

@router.post("/auth", dependencies=[Depends(_require_eap_bearer)])
async def eap_auth(body: EapAuthRequest, db: AsyncSession = Depends(get_db)):
    """Verify identity and run the NACo policy engine.

    Authentication outcomes:

    1. Empty / missing password → reject (closes the pre-2.0.1 bypass where
       a missing password fell through to the policy engine).
    2. Local user with matching bcrypt hash → accept.
    3. Local user with wrong password → reject (bcrypt always runs).
    4. No local user → spend a constant-time bcrypt cycle, then try LDAP;
       if LDAP authenticates, auto-provision and continue.
    5. Anything else → reject.

    All reject branches also call :func:`dummy_verify` once on the unknown-user
    path so timing doesn't leak whether a username exists locally.
    """
    from naco.api.auth import dummy_verify

    mac = _calling_station_to_mac(body.calling_station_id)

    # Outcome 1 — defence in depth. FreeRADIUS shouldn't normally hand us an
    # empty password, but a bug or misconfiguration upstream must NOT result
    # in an unauthenticated Access-Accept.
    pwd = (body.password or "").strip()
    if not pwd:
        await _log_auth(db, body.username, mac, body.nas_ip or "",
                        AuthResult.FAILURE, "Empty password", "")
        return {"Reply-Message": "Access denied"}

    user = (await db.execute(
        select(User).where(User.username == body.username, User.enabled == True)
    )).scalar_one_or_none()

    if user is None:
        # Outcome 4 — pay the bcrypt cost so this branch looks the same as
        # outcome 3 to a remote observer.
        dummy_verify(pwd)

        from naco.auth.ldap import ldap_authenticate, ldap_auto_provision
        ldap_result = await ldap_authenticate(body.username, pwd)
        if ldap_result is not None:
            await ldap_auto_provision(body.username, ldap_result, db)
            user = (await db.execute(
                select(User).where(User.username == body.username, User.enabled == True)
            )).scalar_one_or_none()

        if user is None:
            await _log_auth(db, body.username, mac, body.nas_ip or "",
                            AuthResult.FAILURE, "Unknown user", "")
            return {"Reply-Message": "Access denied"}
    else:
        # Outcome 3 — wrong password always runs the bcrypt comparison.
        if not bcrypt.checkpw(pwd.encode(), user.password_hash.encode()):
            await _log_auth(db, body.username, mac, body.nas_ip or "",
                            AuthResult.FAILURE, "Wrong password", "")
            return {"Reply-Message": "Access denied"}

    group_name = ""
    if user.group_id:
        from sqlalchemy.orm import selectinload
        u2 = (await db.execute(
            select(User).options(selectinload(User.group)).where(User.id == user.id)
        )).scalar_one()
        group_name = u2.group.name if u2.group else ""

    ctx = AuthContext(
        username=body.username, mac_address=mac, nas_ip=body.nas_ip or "",
        auth_method="EAP", group_name=group_name,
    )
    decision = await policy_engine.evaluate(ctx, db)

    if decision.action.value == "DENY":
        await _log_auth(db, body.username, mac, body.nas_ip or "", AuthResult.FAILURE,
                        decision.reason or "Policy denied", decision.policy_name or "")
        await bus.publish(Event(EventType.AUTH_FAILURE, data={
            "username": body.username, "mac": mac, "reason": decision.reason,
        }))
        return {"Reply-Message": decision.reason or "Access denied"}

    await _log_auth(db, body.username, mac, body.nas_ip or "", AuthResult.SUCCESS,
                    "", decision.policy_name or "")
    await bus.publish(Event(EventType.AUTH_SUCCESS, data={
        "username": body.username, "mac": mac, "vlan": decision.vlan,
    }))

    response: dict = {"Reply-Message": "Welcome", "control:Auth-Type": "Accept"}
    if decision.vlan:
        response.update({
            "Tunnel-Type":              "13",
            "Tunnel-Medium-Type":       "6",
            "Tunnel-Private-Group-Id":  str(decision.vlan),
        })
    return response


# ---------------------------------------------------------------------------
# Authorize (rlm_rest "authorize" hook)
# ---------------------------------------------------------------------------

@router.post("/authorize", dependencies=[Depends(_require_eap_bearer)])
async def eap_authorize(body: EapAuthorizeRequest, db: AsyncSession = Depends(get_db)):
    """Pre-authentication policy lookup — returns VLAN/permit hints to FreeRADIUS."""
    mac = _calling_station_to_mac(body.calling_station_id)

    group_name = ""
    user = (await db.execute(
        select(User).where(User.username == body.username, User.enabled == True)
    )).scalar_one_or_none()
    if user and user.group_id:
        from sqlalchemy.orm import selectinload
        u2 = (await db.execute(
            select(User).options(selectinload(User.group)).where(User.id == user.id)
        )).scalar_one()
        group_name = u2.group.name if u2.group else ""

    ctx = AuthContext(
        username=body.username, mac_address=mac, nas_ip=body.nas_ip or "",
        auth_method="EAP", group_name=group_name,
    )
    decision = await policy_engine.evaluate(ctx, db)

    if decision.action.value in ("PERMIT", "GUEST"):
        resp: dict = {"control:Auth-Type": "EAP"}
        if decision.vlan:
            resp.update({
                "Tunnel-Type":              "13",
                "Tunnel-Medium-Type":       "6",
                "Tunnel-Private-Group-Id":  str(decision.vlan),
            })
        return resp
    return {"Reply-Message": "Not authorized"}


# ---------------------------------------------------------------------------
# Accounting (rlm_rest "accounting" hook)
# ---------------------------------------------------------------------------

@router.post("/accounting", dependencies=[Depends(_require_eap_bearer)])
async def eap_accounting(body: EapAccountingRequest, db: AsyncSession = Depends(get_db)):
    """Record Start/Stop/Interim-Update in the active_sessions table."""
    status = (body.status_type or "").lower()
    sid = body.session_id or ""

    if "start" in status and sid:
        mac = _calling_station_to_mac(body.calling_station)
        db.add(ActiveSession(
            session_id=sid,
            username=body.username or "",
            mac_address=mac,
            ip_address=body.framed_ip or "",
            nas_ip=body.nas_ip or "",
        ))
        await db.commit()

    elif ("stop" in status or "interim" in status) and sid:
        vals: dict = {}
        if body.input_octets:
            try:
                vals["bytes_in"] = int(body.input_octets)
            except ValueError:
                pass
        if body.output_octets:
            try:
                vals["bytes_out"] = int(body.output_octets)
            except ValueError:
                pass
        if vals:
            await db.execute(
                sa_update(ActiveSession)
                .where(ActiveSession.session_id == sid)
                .values(**vals)
            )
        if "stop" in status:
            await db.execute(
                sa_delete(ActiveSession).where(ActiveSession.session_id == sid)
            )
        await db.commit()

    return {"ok": True}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _calling_station_to_mac(raw: str | None) -> str:
    if not raw:
        return ""
    try:
        return normalise_mac(raw)
    except ValueError:
        return raw


async def _log_auth(
    db: AsyncSession,
    username: str,
    mac: str,
    nas_ip: str,
    result: AuthResult,
    reason: str,
    policy_name: str,
) -> None:
    db.add(AuthLog(
        username=username,
        mac_address=mac,
        nas_ip=nas_ip,
        result=result,
        reason=reason,
        policy_name=policy_name,
        auth_method=AuthMethod.PEAP,
    ))
    await db.commit()
