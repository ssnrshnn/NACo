"""Seed the e2e NACo database (piped into `python -` inside the naco container)."""
import asyncio

from naco.core.passwords import hash_password_sync
from naco.db.engine import init_engine, session_factory
from naco.db.models import Device, DeviceStatus, Group, NasClient, Policy, PolicyAction, User


async def main() -> None:
    init_engine()
    async with session_factory()() as db:
        staff = Group(name="staff")
        db.add(staff)
        await db.flush()
        db.add_all([
            NasClient(name="e2e-switch", ip_address="172.31.250.20", secret="e2e-nas-shared-secret"),
            User(username="alice", password_hash=hash_password_sync('pa"ss\\wörd'), group_id=staff.id),
            User(username="bob", password_hash=hash_password_sync("bob-password"), enabled=False,
                 group_id=staff.id),
            User(username="erin", password_hash=hash_password_sync("Tünel\\şifre!"), group_id=staff.id),
            User(username="carol", password_hash=hash_password_sync("carol-password"), group_id=staff.id),
            Device(mac_address="02:00:00:00:00:40", status=DeviceStatus.APPROVED, device_type="printer"),
            Device(mac_address="02:00:00:00:00:99", status=DeviceStatus.BLOCKED),
            Policy(name="no-carol", priority=5, action=PolicyAction.DENY,
                   conditions=[{"type": "username", "op": "equals", "value": "carol"}]),
            Policy(name="staff", priority=10, action=PolicyAction.PERMIT, vlan=10,
                   reply_attributes={"Filter-Id": "staff-acl"},
                   conditions=[{"type": "group", "op": "in", "value": ["staff"]}]),
            Policy(name="printers", priority=20, action=PolicyAction.PERMIT, vlan=40,
                   conditions=[{"type": "auth_method", "value": ["MAB"]},
                               {"type": "device_status", "value": ["approved"]}]),
            Policy(name="onboarding", priority=30, action=PolicyAction.PERMIT, vlan=99,
                   conditions=[{"type": "auth_method", "value": ["MAB"]},
                               {"type": "device_status", "value": ["pending"]}]),
        ])
        await db.commit()

asyncio.run(main())
