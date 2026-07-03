"""User CRUD endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from naco.api._audit import audit
from naco.api.auth import hash_password, require_role
from naco.api.schemas import StatusResponse, UserCreate, UserOut, UserUpdate
from naco.db import get_db
from naco.db.models import AdminRole, AdminUser, User

router = APIRouter(prefix="/api/v1", tags=["Users"])


@router.get("/users", response_model=list[UserOut])
async def list_users(
    skip: int = 0, limit: int = Query(50, le=200),
    db: AsyncSession = Depends(get_db),
    _:  AdminUser    = Depends(require_role(AdminRole.VIEWER)),
):
    stmt   = select(User).options(selectinload(User.group)).offset(skip).limit(limit)
    result = (await db.execute(stmt)).scalars().all()
    out    = []
    for u in result:
        d = UserOut.model_validate(u)
        d.group_name = u.group.name if u.group else None
        out.append(d)
    return out


@router.post("/users", response_model=UserOut, status_code=201)
async def create_user(
    body: UserCreate,
    db:   AsyncSession = Depends(get_db),
    admin: AdminUser   = Depends(require_role(AdminRole.OPERATOR)),
):
    existing = (await db.execute(select(User).where(User.username == body.username))).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=409, detail="Username already exists")

    user = User(
        username      = body.username,
        password_hash = hash_password(body.password),
        email         = body.email,
        full_name     = body.full_name,
        group_id      = body.group_id,
        enabled       = body.enabled,
    )
    db.add(user)
    await audit(db, admin, "CREATE", "user", "", f"username={body.username}")
    await db.commit()
    await db.refresh(user)
    return UserOut.model_validate(user)


@router.get("/users/{user_id}", response_model=UserOut)
async def get_user(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    _:  AdminUser    = Depends(require_role(AdminRole.VIEWER)),
):
    stmt = select(User).options(selectinload(User.group)).where(User.id == user_id)
    user = (await db.execute(stmt)).scalar_one_or_none()
    if not user:
        raise HTTPException(404, "User not found")
    d = UserOut.model_validate(user)
    d.group_name = user.group.name if user.group else None
    return d


@router.put("/users/{user_id}", response_model=UserOut)
async def update_user(
    user_id: int,
    body:    UserUpdate,
    db:      AsyncSession = Depends(get_db),
    _:       AdminUser    = Depends(require_role(AdminRole.OPERATOR)),
):
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not user:
        raise HTTPException(404, "User not found")
    if body.email     is not None: user.email     = body.email
    if body.full_name is not None: user.full_name = body.full_name
    if body.group_id  is not None: user.group_id  = body.group_id
    if body.enabled   is not None: user.enabled   = body.enabled
    if body.password  is not None: user.password_hash = hash_password(body.password)
    await db.commit()
    await db.refresh(user)
    return UserOut.model_validate(user)


@router.delete("/users/{user_id}", response_model=StatusResponse)
async def delete_user(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    admin: AdminUser = Depends(require_role(AdminRole.OPERATOR)),
):
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not user:
        raise HTTPException(404, "User not found")
    await audit(db, admin, "DELETE", "user", str(user_id), f"username={user.username}")
    await db.delete(user)
    await db.commit()
    return StatusResponse(status="ok", message=f"User {user_id} deleted")
