"""Network devices NACo talks to: RADIUS NAS clients (via FreeRADIUS), TACACS+
clients, and TACACS+ command sets. Shared secrets are write-only except for
an explicit, audited reveal by a SUPERUSER."""
from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Response
from pydantic import AfterValidator, BaseModel, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from naco.api.audit import AuditTrail, audit_trail, diff
from naco.api.common import commit_or_conflict, flush_or_conflict, get_or_404, snapshot
from naco.api.deps import Principal, superuser, viewer
from naco.api.errors import ApiError
from naco.config import get_config
from naco.core.netutils import parse_client_address, parse_ip
from naco.db.engine import get_db
from naco.db.models import CommandAction, CommandRule, CommandSet, Group, NasClient, TacacsClient
from naco.radius.vendors import DEFAULT_VENDOR, VENDORS

router = APIRouter(tags=["network devices"])

NAS_FIELDS = ["name", "ip_address", "vendor", "coa_port", "require_message_authenticator", "description", "enabled"]
TAC_FIELDS = ["name", "ip_address", "description", "enabled"]
NAME_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9 ._-]*$"


def _ip(value: str) -> str:
    ip = parse_ip(value)
    if ip is None:
        raise ValueError("not an IP address")
    return ip


def _secret(value: str) -> str:
    minimum = get_config().radius.nas_secret_min_length
    if len(value) < minimum:
        raise ValueError(f"must be at least {minimum} characters")
    if any(ord(c) < 0x21 or ord(c) > 0x7E for c in value):
        raise ValueError("use printable ASCII without spaces (what switches accept)")
    return value


IpAddress = Annotated[str, AfterValidator(_ip)]
ClientAddress = Annotated[str, AfterValidator(parse_client_address)]
SharedSecret = Annotated[str, Field(max_length=128), AfterValidator(_secret)]


# ── RADIUS NAS clients ─────────────────────────────────────────────────────

def _vendor(value: str) -> str:
    if value not in VENDORS:
        raise ValueError(f"unknown vendor; one of {', '.join(VENDORS)}")
    return value


VendorKey = Annotated[str, AfterValidator(_vendor)]


class NasOut(BaseModel):
    id: int
    name: str
    ip_address: str
    vendor: str
    coa_port: int
    require_message_authenticator: bool
    description: str
    enabled: bool
    created_at: datetime


class NasIn(BaseModel):
    name: str = Field(min_length=1, max_length=64, pattern=NAME_PATTERN)
    ip_address: ClientAddress
    secret: SharedSecret
    vendor: VendorKey = DEFAULT_VENDOR
    coa_port: int | None = Field(None, ge=1, le=65535)  # default: the vendor's
    require_message_authenticator: bool = True
    description: str = Field("", max_length=255)
    enabled: bool = True


class NasUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=64, pattern=NAME_PATTERN)
    ip_address: ClientAddress | None = None
    secret: SharedSecret | None = None
    vendor: VendorKey | None = None
    coa_port: int | None = Field(None, ge=1, le=65535)
    require_message_authenticator: bool | None = None
    description: str | None = Field(None, max_length=255)
    enabled: bool | None = None


class SecretOut(BaseModel):
    secret: str


def nas_out(n: NasClient) -> NasOut:
    return NasOut(**snapshot(n, NAS_FIELDS), id=n.id, created_at=n.created_at)


class VendorOut(BaseModel):
    key: str
    label: str
    coa_port: int


@router.get("/nas/vendors", response_model=list[VendorOut])
async def list_vendors(_: Principal = Depends(viewer)) -> list[VendorOut]:
    """Kinds of NAS, which decide what a Disconnect-Request carries."""
    return [VendorOut(key=k, label=v.label, coa_port=v.coa_port) for k, v in VENDORS.items()]


@router.get("/nas", response_model=list[NasOut])
async def list_nas(_: Principal = Depends(viewer), db: AsyncSession = Depends(get_db)) -> list[NasOut]:
    return [nas_out(n) for n in (await db.execute(select(NasClient).order_by(NasClient.name))).scalars()]


@router.post("/nas", response_model=NasOut, status_code=201)
async def create_nas(body: NasIn, _: Principal = Depends(superuser),
                     audit: AuditTrail = Depends(audit_trail)) -> NasOut:
    data = body.model_dump()
    data["coa_port"] = data["coa_port"] or VENDORS[body.vendor].coa_port
    nas = NasClient(**data)
    audit.db.add(nas)
    await flush_or_conflict(audit.db, "a NAS with that name or address already exists")
    audit.record("nas.create", "nas", nas.id, nas.name, {**snapshot(nas, NAS_FIELDS), "secret": "***"})
    await commit_or_conflict(audit.db, "a NAS with that name or address already exists")
    return nas_out(nas)


@router.patch("/nas/{nas_id}", response_model=NasOut)
async def update_nas(nas_id: int, body: NasUpdate, _: Principal = Depends(superuser),
                     audit: AuditTrail = Depends(audit_trail)) -> NasOut:
    nas = await get_or_404(audit.db, NasClient, nas_id, "NAS")
    before = snapshot(nas, NAS_FIELDS)
    changes = {k: v for k, v in body.model_dump(exclude_unset=True).items() if v is not None}
    for key, value in changes.items():
        setattr(nas, key, value)
    delta = diff(before, snapshot(nas, NAS_FIELDS))
    if "secret" in changes:
        delta["secret"] = ["***", "***"]
    audit.record("nas.update", "nas", nas.id, nas.name, delta)
    await commit_or_conflict(audit.db, "a NAS with that name or address already exists")
    return nas_out(nas)


@router.get("/nas/{nas_id}/secret", response_model=SecretOut)
async def reveal_nas_secret(nas_id: int, _: Principal = Depends(superuser),
                            audit: AuditTrail = Depends(audit_trail)) -> SecretOut:
    nas = await get_or_404(audit.db, NasClient, nas_id, "NAS")
    audit.record("nas.secret_viewed", "nas", nas.id, nas.name)
    await audit.db.commit()
    return SecretOut(secret=nas.secret)


@router.delete("/nas/{nas_id}", status_code=204)
async def delete_nas(nas_id: int, _: Principal = Depends(superuser),
                     audit: AuditTrail = Depends(audit_trail)) -> Response:
    nas = await get_or_404(audit.db, NasClient, nas_id, "NAS")
    await audit.db.delete(nas)
    audit.record("nas.delete", "nas", nas_id, nas.name)
    await audit.db.commit()
    return Response(status_code=204)


# ── TACACS+ clients ────────────────────────────────────────────────────────

class TacacsOut(BaseModel):
    id: int
    name: str
    ip_address: str
    description: str
    enabled: bool
    created_at: datetime


class TacacsIn(BaseModel):
    name: str = Field(min_length=1, max_length=64, pattern=NAME_PATTERN)
    ip_address: IpAddress
    key: SharedSecret
    description: str = Field("", max_length=255)
    enabled: bool = True


class TacacsUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=64, pattern=NAME_PATTERN)
    ip_address: IpAddress | None = None
    key: SharedSecret | None = None
    description: str | None = Field(None, max_length=255)
    enabled: bool | None = None


class KeyOut(BaseModel):
    key: str


def tac_out(t: TacacsClient) -> TacacsOut:
    return TacacsOut(**snapshot(t, TAC_FIELDS), id=t.id, created_at=t.created_at)


@router.get("/tacacs-clients", response_model=list[TacacsOut])
async def list_tacacs(_: Principal = Depends(viewer), db: AsyncSession = Depends(get_db)) -> list[TacacsOut]:
    return [tac_out(t) for t in (await db.execute(select(TacacsClient).order_by(TacacsClient.name))).scalars()]


@router.post("/tacacs-clients", response_model=TacacsOut, status_code=201)
async def create_tacacs(body: TacacsIn, _: Principal = Depends(superuser),
                        audit: AuditTrail = Depends(audit_trail)) -> TacacsOut:
    client = TacacsClient(**body.model_dump())
    audit.db.add(client)
    await flush_or_conflict(audit.db, "a TACACS+ client with that name or address already exists")
    audit.record("tacacs_client.create", "tacacs_client", client.id, client.name,
                 {**snapshot(client, TAC_FIELDS), "key": "***"})
    await commit_or_conflict(audit.db, "a TACACS+ client with that name or address already exists")
    return tac_out(client)


@router.patch("/tacacs-clients/{client_id}", response_model=TacacsOut)
async def update_tacacs(client_id: int, body: TacacsUpdate, _: Principal = Depends(superuser),
                        audit: AuditTrail = Depends(audit_trail)) -> TacacsOut:
    client = await get_or_404(audit.db, TacacsClient, client_id, "TACACS+ client")
    before = snapshot(client, TAC_FIELDS)
    changes = {k: v for k, v in body.model_dump(exclude_unset=True).items() if v is not None}
    for key, value in changes.items():
        setattr(client, key, value)
    delta = diff(before, snapshot(client, TAC_FIELDS))
    if "key" in changes:
        delta["key"] = ["***", "***"]
    audit.record("tacacs_client.update", "tacacs_client", client.id, client.name, delta)
    await commit_or_conflict(audit.db, "a TACACS+ client with that name or address already exists")
    return tac_out(client)


@router.get("/tacacs-clients/{client_id}/key", response_model=KeyOut)
async def reveal_tacacs_key(client_id: int, _: Principal = Depends(superuser),
                            audit: AuditTrail = Depends(audit_trail)) -> KeyOut:
    client = await get_or_404(audit.db, TacacsClient, client_id, "TACACS+ client")
    audit.record("tacacs_client.key_viewed", "tacacs_client", client.id, client.name)
    await audit.db.commit()
    return KeyOut(key=client.key)


@router.delete("/tacacs-clients/{client_id}", status_code=204)
async def delete_tacacs(client_id: int, _: Principal = Depends(superuser),
                        audit: AuditTrail = Depends(audit_trail)) -> Response:
    client = await get_or_404(audit.db, TacacsClient, client_id, "TACACS+ client")
    await audit.db.delete(client)
    audit.record("tacacs_client.delete", "tacacs_client", client_id, client.name)
    await audit.db.commit()
    return Response(status_code=204)


# ── command sets ───────────────────────────────────────────────────────────

class RuleIO(BaseModel):
    action: CommandAction
    pattern: str = Field(min_length=1, max_length=256)

    @field_validator("pattern")
    @classmethod
    def _printable(cls, v: str) -> str:
        v = " ".join(v.split())
        if not v or any(ord(c) < 0x20 for c in v):
            raise ValueError("patterns are printable text")
        return v


class CommandSetOut(BaseModel):
    id: int
    name: str
    description: str
    default_action: CommandAction
    rules: list[RuleIO]
    groups: int


class CommandSetIn(BaseModel):
    name: str = Field(min_length=1, max_length=64, pattern=NAME_PATTERN)
    description: str = Field("", max_length=255)
    default_action: CommandAction = CommandAction.DENY
    rules: list[RuleIO] = Field(default_factory=list, max_length=500)


class CommandSetUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=64, pattern=NAME_PATTERN)
    description: str | None = Field(None, max_length=255)
    default_action: CommandAction | None = None
    rules: list[RuleIO] | None = Field(None, max_length=500)


async def _cs_out(db: AsyncSession, cs: CommandSet) -> CommandSetOut:
    await db.refresh(cs, ["rules"])
    groups = (await db.execute(select(func.count()).select_from(Group)
                               .where(Group.command_set_id == cs.id))).scalar_one()
    return CommandSetOut(id=cs.id, name=cs.name, description=cs.description, default_action=cs.default_action,
                         rules=[RuleIO(action=r.action, pattern=r.pattern) for r in cs.rules], groups=groups)


def _rules_snapshot(rules: list[RuleIO] | list[CommandRule]) -> list[str]:
    return [f"{r.action.value} {r.pattern}" for r in rules]


@router.get("/command-sets", response_model=list[CommandSetOut])
async def list_command_sets(_: Principal = Depends(viewer), db: AsyncSession = Depends(get_db)) -> list[CommandSetOut]:
    sets = list((await db.execute(select(CommandSet).order_by(CommandSet.name))).scalars())
    return [await _cs_out(db, cs) for cs in sets]


@router.post("/command-sets", response_model=CommandSetOut, status_code=201)
async def create_command_set(body: CommandSetIn, _: Principal = Depends(superuser),
                             audit: AuditTrail = Depends(audit_trail)) -> CommandSetOut:
    cs = CommandSet(name=body.name, description=body.description, default_action=body.default_action,
                    rules=[CommandRule(position=i, action=r.action, pattern=r.pattern) for i, r in enumerate(body.rules)])
    audit.db.add(cs)
    await flush_or_conflict(audit.db, f"command set {body.name} already exists")
    audit.record("command_set.create", "command_set", cs.id, cs.name,
                 {"default_action": cs.default_action.value, "rules": _rules_snapshot(body.rules)})
    await commit_or_conflict(audit.db, f"command set {body.name} already exists")
    return await _cs_out(audit.db, cs)


@router.patch("/command-sets/{set_id}", response_model=CommandSetOut)
async def update_command_set(set_id: int, body: CommandSetUpdate, _: Principal = Depends(superuser),
                             audit: AuditTrail = Depends(audit_trail)) -> CommandSetOut:
    db = audit.db
    cs = await get_or_404(db, CommandSet, set_id, "command set")
    await db.refresh(cs, ["rules"])
    before = {"name": cs.name, "description": cs.description, "default_action": cs.default_action.value,
              "rules": _rules_snapshot(cs.rules)}
    if body.name is not None:
        cs.name = body.name
    if body.description is not None:
        cs.description = body.description
    if body.default_action is not None:
        cs.default_action = body.default_action
    if body.rules is not None:
        cs.rules = [CommandRule(position=i, action=r.action, pattern=r.pattern) for i, r in enumerate(body.rules)]
    after = {"name": cs.name, "description": cs.description, "default_action": cs.default_action.value,
             "rules": _rules_snapshot(body.rules) if body.rules is not None else before["rules"]}
    audit.record("command_set.update", "command_set", cs.id, cs.name, diff(before, after))
    await commit_or_conflict(db, "a command set with that name already exists")
    return await _cs_out(db, cs)


@router.delete("/command-sets/{set_id}", status_code=204)
async def delete_command_set(set_id: int, _: Principal = Depends(superuser),
                             audit: AuditTrail = Depends(audit_trail)) -> Response:
    cs = await get_or_404(audit.db, CommandSet, set_id, "command set")
    used = (await audit.db.execute(select(Group.name).where(Group.command_set_id == cs.id))).scalars().all()
    if used:
        raise ApiError(409, f"command set is used by groups: {', '.join(used)}")
    await audit.db.delete(cs)
    audit.record("command_set.delete", "command_set", set_id, cs.name)
    await audit.db.commit()
    return Response(status_code=204)
