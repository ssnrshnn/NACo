"""Turn "who/what is asking" into a policy context — shared by live
authorization and CoA re-evaluation so both apply identical hard rules."""
from __future__ import annotations

from datetime import datetime

from naco.auth.identity import UserInfo
from naco.db.models import Device, DeviceStatus
from naco.policy.context import AuthContext, Decision, deny


def device_state(device: Device | None, is_guest: bool) -> str | None:
    if device is None:
        return "guest" if is_guest else None
    if device.status is DeviceStatus.APPROVED:
        return "approved"
    if device.status is DeviceStatus.PENDING:
        return "guest" if is_guest else "pending"
    return None  # blocked never reaches policy evaluation


def subject_context(*, method: str, username: str, user: UserInfo | None, mac: str | None,
                    device: Device | None, is_guest: bool, nas_name: str, nas_ip: str,
                    ssid: str | None, now: datetime) -> AuthContext | Decision:
    """An ``AuthContext`` to evaluate, or the hard-rule ``Decision`` that ends it."""
    if method != "MAB":
        if not username:
            return deny("no authenticated identity")
        if user is None:
            return deny("unknown user")
        if not user.enabled:
            return deny("user disabled")
    if device is not None and device.status is DeviceStatus.BLOCKED:
        return deny("device blocked")
    return AuthContext(
        auth_method=method, username=username if method != "MAB" else "",
        group=user.group_name if user else None, mac=mac, device_status=device_state(device, is_guest),
        device_type=device.device_type if device else "", vendor=device.vendor if device else "",
        nas_name=nas_name, nas_ip=nas_ip, ssid=ssid, now=now,
    )
