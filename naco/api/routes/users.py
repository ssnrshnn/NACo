"""Network users (802.1X / PAP / TACACS+ identities) and their groups.

Users in a group with a device-admin profile can log in to switches over
TACACS+, so only a SUPERUSER may create, change, delete or move users into
or out of such groups — otherwise an OPERATOR could reset a network admin's
password and take over their switch access.
"""
from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, Query, Response
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from naco.api.audit import AuditTrail, audit_trail, diff
from naco.api.common import Page, Paging, commit_or_conflict, flush_or_conflict, get_or_404, like, snapshot
from naco.api.deps import Principal, operator, superuser, viewer
from naco.api.errors import ApiError
from naco.auth.identity import canonical_username
from naco.core.passwords import hash_password, validate_user_password
from naco.db.engine import get_db
from naco.db.models import AdminRole, CommandSet, Group, Policy, User, UserSource
from naco.radius.reevaluate import reevaluator

router = APIRouter(tags=["users & groups"])

USER_FIELDS = ["username", "email", "full_name", "group_id", "enabled"]
GROUP_FIELDS = ["name", "description", "device_admin_privilege", "command_set_id"]


# ── users ──────────────────────────────────────────────────────────────────

class UserOut(BaseModel):
    id: int
    username: str
    source: UserSource
    email: str
    full_name: str
    group_id: int | None
    group_name: str | None
    enabled: bool
    created_at: datetime
    last_login_at: datetime | None


class UserCreate(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(max_length=72)
    email: str = Field("", max_length=128)
    full_name: str = Field("", max_length=128)
    group_id: int | None = None
    enabled: bool = True

    @field_validator("username")
    @classmethod
    def _username(cls, v: str) -> str:
        name = canonical_username(v)
        if not name or any(c.isspace() for c in name):
            raise ValueError("usernames are 1-64 characters without spaces")
        return name


class UserUpdate(BaseModel):
    email: str | None = Field(None, max_length=128)
    full_name: str | None = Field(None, max_length=128)
    group_id: int | None = None
    enabled: bool | None = None
    password: str | None = Field(None, max_length=72)


def _out(user: User, group: Group | None) -> UserOut:
    return UserOut(id=user.id, username=user.username, source=user.source, email=user.email,
                   full_name=user.full_name, group_id=user.group_id, group_name=group.name if group else None,
                   enabled=user.enabled, created_at=user.created_at, last_login_at=user.last_login_at)


async def _group(db: AsyncSession, group_id: int | None) -> Group | None:
    if group_id is None:
        return None
    group = await db.get(Group, group_id)
    if group is None:
        raise ApiError(422, "group does not exist")
    return group


def _guard_device_admin(principal: Principal, *groups: Group | None) -> None:
    if principal.role.allows(AdminRole.SUPERUSER):
        return
    if any(g is not None and g.device_admin_privilege is not None for g in groups):
        raise ApiError(403, "users of device-admin groups are managed by a SUPERUSER")


def _password(value: str) -> str:
    try:
        validate_user_password(value)
    except ValueError as exc:
        raise ApiError(422, str(exc)) from exc
    return value


@router.get("/users", response_model=Page[UserOut])
async def list_users(q: str = Query("", max_length=64), group_id: int | None = None,
                     enabled: bool | None = None, paging: Paging = Depends(),
                     _: Principal = Depends(viewer), db: AsyncSession = Depends(get_db)) -> Page[UserOut]:
    query = select(User, Group).outerjoin(Group, User.group_id == Group.id).order_by(User.username)
    if q:
        query = query.where(or_(User.username.ilike(like(q), escape="\\"), User.full_name.ilike(like(q), escape="\\"),
                                User.email.ilike(like(q), escape="\\")))
    if group_id is not None:
        query = query.where(User.group_id == group_id)
    if enabled is not None:
        query = query.where(User.enabled.is_(enabled))
    rows, total = await paging.fetch(db, query)
    return Page(items=[_out(u, g) for u, g in rows], total=total, page=paging.page, per_page=paging.per_page)


@router.get("/users/{user_id}", response_model=UserOut)
async def get_user(user_id: int, _: Principal = Depends(viewer), db: AsyncSession = Depends(get_db)) -> UserOut:
    user = await get_or_404(db, User, user_id, "user")
    return _out(user, await _group(db, user.group_id))


@router.post("/users", response_model=UserOut, status_code=201)
async def create_user(body: UserCreate, principal: Principal = Depends(operator),
                      audit: AuditTrail = Depends(audit_trail)) -> UserOut:
    db = audit.db
    digest = await hash_password(_password(body.password))  # before the first query: no lock held meanwhile
    group = await _group(db, body.group_id)
    _guard_device_admin(principal, group)
    user = User(username=body.username, source=UserSource.LOCAL,
                password_hash=digest, email=body.email,
                full_name=body.full_name, group_id=body.group_id, enabled=body.enabled)
    db.add(user)
    await flush_or_conflict(db, f"user {body.username} already exists")
    audit.record("user.create", "user", user.id, user.username, snapshot(user, USER_FIELDS))
    await commit_or_conflict(db, f"user {body.username} already exists")
    return _out(user, group)


@router.patch("/users/{user_id}", response_model=UserOut)
async def update_user(user_id: int, body: UserUpdate, principal: Principal = Depends(operator),
                      audit: AuditTrail = Depends(audit_trail)) -> UserOut:
    db = audit.db
    changes = body.model_dump(exclude_unset=True)
    # Hash before the first query, so no lock is held meanwhile.
    digest = await hash_password(_password(changes["password"])) if changes.get("password") is not None else None
    user = await get_or_404(db, User, user_id, "user")
    current = await _group(db, user.group_id)
    target = await _group(db, changes["group_id"]) if "group_id" in changes else current
    _guard_device_admin(principal, current, target)
    before = snapshot(user, USER_FIELDS)
    for field in ("email", "full_name", "enabled"):
        if changes.get(field) is not None:
            setattr(user, field, changes[field])
    if "group_id" in changes:
        user.group_id = changes["group_id"]
    secret_changed = []
    if digest is not None:
        if user.source is not UserSource.LOCAL:
            raise ApiError(422, "LDAP users sign in with their directory password")
        user.password_hash = digest
        secret_changed = ["password"]
    after = snapshot(user, USER_FIELDS)
    delta = diff(before, after)
    delta.update({f: ["***", "***"] for f in secret_changed})
    audit.record("user.update", "user", user.id, user.username, delta)
    await db.commit()
    if {"enabled", "group_id"} & delta.keys():
        reevaluator.schedule(f"user {user.username} changed")
    return _out(user, target)


@router.delete("/users/{user_id}", status_code=204)
async def delete_user(user_id: int, principal: Principal = Depends(operator),
                      audit: AuditTrail = Depends(audit_trail)) -> Response:
    db = audit.db
    user = await get_or_404(db, User, user_id, "user")
    _guard_device_admin(principal, await _group(db, user.group_id))
    await db.delete(user)
    audit.record("user.delete", "user", user_id, user.username)
    await db.commit()
    reevaluator.schedule(f"user {user.username} deleted")
    return Response(status_code=204)


# ── groups ─────────────────────────────────────────────────────────────────

class GroupOut(BaseModel):
    id: int
    name: str
    description: str
    device_admin_privilege: int | None
    command_set_id: int | None
    members: int


class GroupIn(BaseModel):
    name: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9 ._-]*$")
    description: str = Field("", max_length=255)
    device_admin_privilege: int | None = Field(None, ge=1, le=15)
    command_set_id: int | None = None


class GroupUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9 ._-]*$")
    description: str | None = Field(None, max_length=255)
    device_admin_privilege: int | None = Field(None, ge=1, le=15)
    command_set_id: int | None = None


async def _members(db: AsyncSession, group_id: int) -> int:
    return (await db.execute(select(func.count()).select_from(User).where(User.group_id == group_id))).scalar_one()


async def _referencing_policies(db: AsyncSession, name: str) -> list[str]:
    hits = []
    for policy in (await db.execute(select(Policy))).scalars():
        for cond in policy.conditions or []:
            if cond.get("type") == "group" and name.casefold() in {str(v).casefold() for v in cond.get("value", [])}:
                hits.append(policy.name)
                break
    return hits


async def _check_command_set(db: AsyncSession, command_set_id: int | None) -> None:
    if command_set_id is not None and await db.get(CommandSet, command_set_id) is None:
        raise ApiError(422, "command set does not exist")


@router.get("/groups", response_model=list[GroupOut])
async def list_groups(_: Principal = Depends(viewer), db: AsyncSession = Depends(get_db)) -> list[GroupOut]:
    counts = dict((await db.execute(select(User.group_id, func.count()).group_by(User.group_id))).all())
    groups = (await db.execute(select(Group).order_by(Group.name))).scalars()
    return [GroupOut(id=g.id, name=g.name, description=g.description, device_admin_privilege=g.device_admin_privilege,
                     command_set_id=g.command_set_id, members=counts.get(g.id, 0)) for g in groups]


@router.post("/groups", response_model=GroupOut, status_code=201)
async def create_group(body: GroupIn, _: Principal = Depends(superuser),
                       audit: AuditTrail = Depends(audit_trail)) -> GroupOut:
    db = audit.db
    await _check_command_set(db, body.command_set_id)
    group = Group(**body.model_dump())
    db.add(group)
    await flush_or_conflict(db, f"group {body.name} already exists")
    audit.record("group.create", "group", group.id, group.name, snapshot(group, GROUP_FIELDS))
    await commit_or_conflict(db, f"group {body.name} already exists")
    return GroupOut(**snapshot(group, GROUP_FIELDS), id=group.id, members=0)


@router.patch("/groups/{group_id}", response_model=GroupOut)
async def update_group(group_id: int, body: GroupUpdate, _: Principal = Depends(superuser),
                       audit: AuditTrail = Depends(audit_trail)) -> GroupOut:
    db = audit.db
    group = await get_or_404(db, Group, group_id, "group")
    changes = body.model_dump(exclude_unset=True)
    if "name" in changes and changes["name"] != group.name and (refs := await _referencing_policies(db, group.name)):
        raise ApiError(409, f"group is used by policies: {', '.join(refs)} — update them first")
    if "command_set_id" in changes:
        await _check_command_set(db, changes["command_set_id"])
    before = snapshot(group, GROUP_FIELDS)
    for key, value in changes.items():
        if key == "name" and value is None:
            continue
        setattr(group, key, value)
    audit.record("group.update", "group", group.id, group.name, diff(before, snapshot(group, GROUP_FIELDS)))
    await commit_or_conflict(db, "a group with that name already exists")
    return GroupOut(**snapshot(group, GROUP_FIELDS), id=group.id, members=await _members(db, group.id))


@router.delete("/groups/{group_id}", status_code=204)
async def delete_group(group_id: int, _: Principal = Depends(superuser),
                       audit: AuditTrail = Depends(audit_trail)) -> Response:
    db = audit.db
    group = await get_or_404(db, Group, group_id, "group")
    if refs := await _referencing_policies(db, group.name):
        raise ApiError(409, f"group is used by policies: {', '.join(refs)} — update them first")
    await db.delete(group)
    audit.record("group.delete", "group", group_id, group.name)
    await db.commit()
    reevaluator.schedule(f"group {group.name} deleted")
    return Response(status_code=204)
