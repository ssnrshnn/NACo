"""API token management (/api/v1/tokens).

Long-lived bearer credentials for automation (CI, monitoring, scripts),
scoped to a role ceiling enforced by the same RBAC as admin accounts.

Security properties:
* Only the SHA-256 digest is stored; the raw ``naco_…`` value is returned
  exactly once, in the create response.
* SUPERUSER-only, and refused when the caller *is* a token — a leaked
  token must not be able to mint replacements for itself.
* Deleting a token revokes it immediately (no JWT-style grace window).
"""
from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from naco.api._audit import audit
from naco.api.auth import API_TOKEN_PREFIX, hash_api_token, require_role
from naco.api.schemas import StatusResponse
from naco.db import get_db
from naco.db.models import AdminRole, AdminUser, ApiToken

router = APIRouter(prefix="/api/v1", tags=["API tokens"])


class TokenCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=64, pattern=r"^[a-zA-Z0-9._\-]+$")
    role: AdminRole = AdminRole.VIEWER
    # None = never expires. Prefer setting one for anything long-lived.
    expires_days: int | None = Field(None, ge=1, le=3650)


class TokenOut(BaseModel):
    id: int
    name: str
    prefix: str
    role: AdminRole
    created_by: str
    created_at: datetime
    expires_at: datetime | None
    last_used_at: datetime | None
    enabled: bool

    model_config = {"from_attributes": True}


class TokenCreated(TokenOut):
    token: str  # the raw value — shown only in this response


def _forbid_token_callers(admin: AdminUser) -> None:
    if getattr(admin, "via_api_token", False):
        raise HTTPException(403, "API tokens cannot manage API tokens")


@router.get("/tokens", response_model=list[TokenOut])
async def list_tokens(
    db: AsyncSession = Depends(get_db),
    _:  AdminUser    = Depends(require_role(AdminRole.SUPERUSER)),
):
    rows = (await db.execute(select(ApiToken).order_by(ApiToken.name))).scalars().all()
    return [TokenOut.model_validate(r) for r in rows]


@router.post("/tokens", response_model=TokenCreated, status_code=201)
async def create_token(
    body: TokenCreate,
    db: AsyncSession = Depends(get_db),
    admin: AdminUser = Depends(require_role(AdminRole.SUPERUSER)),
):
    """Mint a token. The raw value appears only in this response — store it."""
    _forbid_token_callers(admin)

    exists = (await db.execute(
        select(ApiToken).where(ApiToken.name == body.name)
    )).scalar_one_or_none()
    if exists:
        raise HTTPException(409, f"Token named {body.name!r} already exists")

    raw = API_TOKEN_PREFIX + secrets.token_urlsafe(32)
    tok = ApiToken(
        name=body.name,
        token_hash=hash_api_token(raw),
        prefix=raw[:10],
        role=body.role,
        created_by=admin.username,
        expires_at=(datetime.now(UTC) + timedelta(days=body.expires_days)
                    if body.expires_days else None),
    )
    db.add(tok)
    await audit(db, admin, "CREATE", "api_token", body.name,
                f"role={body.role.value} expires_days={body.expires_days}")
    await db.commit()
    await db.refresh(tok)
    return TokenCreated(**TokenOut.model_validate(tok).model_dump(), token=raw)


@router.delete("/tokens/{token_id}", response_model=StatusResponse)
async def delete_token(
    token_id: int,
    db: AsyncSession = Depends(get_db),
    admin: AdminUser = Depends(require_role(AdminRole.SUPERUSER)),
):
    """Revoke a token immediately."""
    _forbid_token_callers(admin)

    tok = (await db.execute(
        select(ApiToken).where(ApiToken.id == token_id)
    )).scalar_one_or_none()
    if not tok:
        raise HTTPException(404, "Token not found")
    await audit(db, admin, "DELETE", "api_token", tok.name)
    await db.delete(tok)
    await db.commit()
    return StatusResponse(status="ok", message=f"Token {tok.name!r} revoked")
