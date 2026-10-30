"""Device-administration decisions: who may log in, to which privilege level,
and which commands they may run.

Network access (RADIUS policies) and device administration are separate:
only members of a group with a device-admin profile ever pass here, and a
missing command match falls to the command set's default (DENY unless
configured otherwise) — never to RADIUS policies.
"""
from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatchcase

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from naco.auth.identity import UserInfo
from naco.db.models import CommandAction, CommandRule, CommandSet


@dataclass(frozen=True)
class Verdict:
    allowed: bool
    reason: str


def admin_rights(user: UserInfo | None) -> Verdict:
    if user is None:
        return Verdict(False, "unknown user")
    if not user.enabled:
        return Verdict(False, "user disabled")
    if user.device_admin_privilege is None:
        return Verdict(False, "no device-administration rights")
    return Verdict(True, "ok")


def privilege_allowed(user: UserInfo, requested: int) -> Verdict:
    granted = user.device_admin_privilege or 0
    if requested > granted:
        return Verdict(False, f"privilege {requested} requested, {granted} granted")
    return Verdict(True, "ok")


def parse_args(args: list[str]) -> tuple[dict[str, str], list[str]]:
    """AV pairs → (single-valued attributes, ordered cmd-arg values).

    Optional pairs use '*' instead of '='; both are accepted.
    """
    attrs: dict[str, str] = {}
    cmd_args: list[str] = []
    for pair in args:
        sep = min((i for i in (pair.find("="), pair.find("*")) if i > 0), default=-1)
        if sep < 0:
            continue
        key, value = pair[:sep].strip().lower(), pair[sep + 1:]
        if key == "cmd-arg":
            cmd_args.append(value)
        else:
            attrs.setdefault(key, value)
    return attrs, cmd_args


def command_line(cmd: str, cmd_args: list[str]) -> str:
    """'show' + ['running-config', '<cr>'] → 'show running-config'."""
    words = [cmd, *(a for a in cmd_args if a != "<cr>")]
    return " ".join(" ".join(words).split())


@dataclass(frozen=True)
class CompiledCommandSet:
    name: str
    default: CommandAction
    rules: tuple[tuple[CommandAction, str], ...]


async def load_command_set(db: AsyncSession, command_set_id: int | None) -> CompiledCommandSet | None:
    if command_set_id is None:
        return None
    cs = await db.get(CommandSet, command_set_id)
    if cs is None:
        return None
    rules = (await db.execute(select(CommandRule).where(CommandRule.command_set_id == cs.id)
                              .order_by(CommandRule.position))).scalars()
    return CompiledCommandSet(cs.name, cs.default_action, tuple((r.action, r.pattern) for r in rules))


def command_allowed(line: str, command_set: CompiledCommandSet | None) -> Verdict:
    """First matching rule wins; no match → the set's default. No set → allowed."""
    if command_set is None:
        return Verdict(True, "no command set: privilege level governs")
    folded = line.casefold()
    for action, pattern in command_set.rules:
        if fnmatchcase(folded, " ".join(pattern.split()).casefold()):
            return Verdict(action is CommandAction.PERMIT, f"{action.value.lower()} by rule '{pattern}'")
    return Verdict(command_set.default is CommandAction.PERMIT,
                   f"{command_set.default.value.lower()} by default of {command_set.name}")
