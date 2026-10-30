"""Policy conditions: a closed set of typed, validated predicates.

Every condition is validated when a policy is saved, so evaluation never
meets a malformed rule. Text comparisons are case-insensitive. Patterns are
shell-style globs (``*``, ``?``) — no regular expressions, so no ReDoS.
"""
from __future__ import annotations

from datetime import time
from fnmatch import fnmatchcase
from typing import Annotated, Any, Literal
from zoneinfo import ZoneInfo

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    TypeAdapter,
    ValidationError,
    field_validator,
    model_validator,
)

from naco.core.netutils import normalize_mac
from naco.policy.context import AUTH_METHODS, DEVICE_STATES, AuthContext

MAX_CONDITIONS = 20
MAX_ITEMS = 500
MAX_TEXT = 128
DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")

AuthMethodName = Literal["EAP-TLS", "EAP-TTLS", "PEAP", "PAP", "MAB"]
DeviceStateName = Literal["approved", "pending", "guest"]
DayName = Literal["mon", "tue", "wed", "thu", "fri", "sat", "sun"]

assert set(AUTH_METHODS) == set(AuthMethodName.__args__)  # type: ignore[attr-defined]
assert set(DEVICE_STATES) == set(DeviceStateName.__args__)  # type: ignore[attr-defined]


def _fold(value: str | None) -> str:
    return (value or "").casefold()


def _text(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{what} must be a non-empty string")
    value = value.strip()
    if len(value) > MAX_TEXT:
        raise ValueError(f"{what} must be at most {MAX_TEXT} characters")
    return value


def _text_list(value: Any, what: str) -> list[str]:
    if not isinstance(value, list) or not value:
        raise ValueError(f"{what} must be a non-empty list")
    if len(value) > MAX_ITEMS:
        raise ValueError(f"{what} may hold at most {MAX_ITEMS} entries")
    return [_text(v, what) for v in value]


def _glob(pattern: str, value: str | None) -> bool:
    return value is not None and fnmatchcase(_fold(value), _fold(pattern))


class _Cond(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    def label(self) -> str:
        return self.type  # type: ignore[attr-defined, no-any-return]


class _TextCondition(_Cond):
    """Shared shape for conditions over one free-text context field."""

    op: str
    value: str | list[str]

    @model_validator(mode="after")
    def _shape(self) -> _TextCondition:
        if self.op in ("in", "not_in"):
            object.__setattr__(self, "value", _text_list(self.value, f"{self.type}.value"))  # type: ignore[attr-defined]
        else:
            object.__setattr__(self, "value", _text(self.value, f"{self.type}.value"))  # type: ignore[attr-defined]
        return self

    def _test(self, actual: str | None) -> bool:
        v = self.value
        if self.op == "equals":
            return actual is not None and _fold(actual) == _fold(v)  # type: ignore[arg-type]
        if self.op == "not_equals":
            return _fold(actual) != _fold(v)  # type: ignore[arg-type]
        if self.op == "in":
            return actual is not None and _fold(actual) in {_fold(x) for x in v}
        if self.op == "not_in":
            return _fold(actual) not in {_fold(x) for x in v}
        if self.op == "matches":
            return _glob(v, actual)  # type: ignore[arg-type]
        raise AssertionError(self.op)

    def label(self) -> str:
        shown = ", ".join(self.value) if isinstance(self.value, list) else self.value
        return f"{self.type} {self.op} {shown}"  # type: ignore[attr-defined]


class AlwaysCond(_Cond):
    type: Literal["always"]

    def test(self, ctx: AuthContext, tz: ZoneInfo) -> bool:
        return True


class UsernameCond(_TextCondition):
    type: Literal["username"]
    op: Literal["equals", "not_equals", "in", "matches"]

    def test(self, ctx: AuthContext, tz: ZoneInfo) -> bool:
        return self._test(ctx.username or None)


class GroupCond(_TextCondition):
    type: Literal["group"]
    op: Literal["in", "not_in"]

    def test(self, ctx: AuthContext, tz: ZoneInfo) -> bool:
        return self._test(ctx.group)


class DeviceTypeCond(_TextCondition):
    type: Literal["device_type"]
    op: Literal["in", "not_in"]

    def test(self, ctx: AuthContext, tz: ZoneInfo) -> bool:
        return self._test(ctx.device_type or None)


class VendorCond(_TextCondition):
    type: Literal["vendor"]
    op: Literal["in", "matches"]

    def test(self, ctx: AuthContext, tz: ZoneInfo) -> bool:
        return self._test(ctx.vendor or None)


class NasCond(_TextCondition):
    type: Literal["nas"]
    op: Literal["in", "not_in"]

    def test(self, ctx: AuthContext, tz: ZoneInfo) -> bool:
        return self._test(ctx.nas_name or None)


class SsidCond(_TextCondition):
    type: Literal["ssid"]
    op: Literal["in", "not_in", "matches"]

    def test(self, ctx: AuthContext, tz: ZoneInfo) -> bool:
        return self._test(ctx.ssid)


class AuthMethodCond(_Cond):
    type: Literal["auth_method"]
    op: Literal["in"] = "in"
    value: list[AuthMethodName] = Field(min_length=1)

    def test(self, ctx: AuthContext, tz: ZoneInfo) -> bool:
        return ctx.auth_method in self.value

    def label(self) -> str:
        return f"auth_method in {', '.join(self.value)}"


class DeviceStatusCond(_Cond):
    type: Literal["device_status"]
    op: Literal["in"] = "in"
    value: list[DeviceStateName] = Field(min_length=1)

    def test(self, ctx: AuthContext, tz: ZoneInfo) -> bool:
        return ctx.device_status in self.value

    def label(self) -> str:
        return f"device_status in {', '.join(self.value)}"


class MacCond(_Cond):
    type: Literal["mac"]
    op: Literal["equals", "in", "matches"]
    value: str | list[str]

    @model_validator(mode="after")
    def _shape(self) -> MacCond:
        if self.op == "matches":
            pattern = _text(self.value, "mac pattern").lower()
            if any(c not in "0123456789abcdef:*?-" for c in pattern):
                raise ValueError("mac pattern may contain hex digits, ':', '-', '*' and '?' only")
            object.__setattr__(self, "value", pattern.replace("-", ":"))
            return self
        items = _text_list(self.value, "mac.value") if self.op == "in" else [_text(self.value, "mac.value")]
        normalized = []
        for item in items:
            mac = normalize_mac(item)
            if mac is None:
                raise ValueError(f"invalid MAC address {item!r}")
            normalized.append(mac)
        object.__setattr__(self, "value", normalized if self.op == "in" else normalized[0])
        return self

    def test(self, ctx: AuthContext, tz: ZoneInfo) -> bool:
        if ctx.mac is None:
            return False
        if self.op == "equals":
            return ctx.mac == self.value
        if self.op == "in":
            return ctx.mac in self.value
        assert isinstance(self.value, str)
        return fnmatchcase(ctx.mac, self.value)

    def label(self) -> str:
        shown = ", ".join(self.value) if isinstance(self.value, list) else self.value
        return f"mac {self.op} {shown}"


class TimeCond(_Cond):
    type: Literal["time"]
    op: Literal["between"] = "between"
    start: str
    end: str
    days: list[DayName] = Field(default_factory=lambda: list(DAYS), min_length=1)  # type: ignore[arg-type]

    @field_validator("start", "end")
    @classmethod
    def _hhmm(cls, v: str) -> str:
        try:
            parsed = time.fromisoformat(v)
        except ValueError as exc:
            raise ValueError("times must be HH:MM") from exc
        if parsed.second or parsed.microsecond or len(v) != 5:
            raise ValueError("times must be HH:MM")
        return v

    def test(self, ctx: AuthContext, tz: ZoneInfo) -> bool:
        local = ctx.now.astimezone(tz)
        if DAYS[local.weekday()] not in self.days:
            return False
        now = local.time().replace(second=0, microsecond=0)
        start, end = time.fromisoformat(self.start), time.fromisoformat(self.end)
        if start <= end:
            return start <= now <= end
        return now >= start or now <= end  # overnight window

    def label(self) -> str:
        days = "" if len(self.days) == 7 else f" on {', '.join(self.days)}"
        return f"time {self.start}-{self.end}{days}"


Condition = Annotated[
    AlwaysCond | UsernameCond | GroupCond | AuthMethodCond | DeviceStatusCond | DeviceTypeCond
    | MacCond | VendorCond | NasCond | SsidCond | TimeCond,
    Field(discriminator="type"),
]
_ADAPTER: TypeAdapter[list[Condition]] = TypeAdapter(list[Condition])


def parse_conditions(raw: Any) -> list[Condition]:
    if raw is None:
        raw = []
    if not isinstance(raw, list):
        raise ValueError("conditions must be a list")
    if len(raw) > MAX_CONDITIONS:
        raise ValueError(f"a policy may have at most {MAX_CONDITIONS} conditions")
    try:
        return _ADAPTER.validate_python(raw)
    except ValidationError as exc:
        first = exc.errors()[0]
        where = ".".join(str(p) for p in first["loc"])
        raise ValueError(f"conditions.{where}: {first['msg']}") from exc


def dump_conditions(conditions: list[Condition]) -> list[dict[str, Any]]:
    return [c.model_dump() for c in conditions]


def condition_matches(cond: Condition, ctx: AuthContext, tz: ZoneInfo) -> bool:
    return cond.test(ctx, tz)
