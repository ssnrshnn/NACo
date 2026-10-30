"""What the engine decides on, and what it decides."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from naco.core.timeutil import utcnow
from naco.db.models import PolicyAction

AUTH_METHODS = ("EAP-TLS", "EAP-TTLS", "PEAP", "PAP", "MAB")
DEVICE_STATES = ("approved", "pending", "guest")


@dataclass(frozen=True)
class AuthContext:
    auth_method: str
    username: str = ""
    group: str | None = None
    mac: str | None = None
    device_status: str | None = None
    device_type: str = ""
    vendor: str = ""
    nas_name: str = ""
    nas_ip: str = ""
    ssid: str | None = None
    now: datetime = field(default_factory=utcnow)


@dataclass(frozen=True)
class Decision:
    action: PolicyAction
    policy_id: int | None
    policy_name: str
    reason: str
    vlan: int | None = None
    reply_attributes: dict[str, Any] = field(default_factory=dict)

    @property
    def accepted(self) -> bool:
        return self.action is PolicyAction.PERMIT

    def digest(self) -> str:
        """Stable fingerprint of what the NAS is told — CoA compares these."""
        doc = {"action": self.action.value, "vlan": self.vlan, "attrs": self.reply_attributes}
        return hashlib.sha256(json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def deny(reason: str, policy_id: int | None = None, policy_name: str = "") -> Decision:
    return Decision(PolicyAction.DENY, policy_id, policy_name, reason)
