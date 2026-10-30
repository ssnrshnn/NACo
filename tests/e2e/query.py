"""Print NACo state as JSON (piped into `python -` inside the naco container)."""
import asyncio
import json

from sqlalchemy import select

from naco.db.engine import init_engine, session_factory
from naco.db.models import AuthLog, Device, RadiusSession


async def main() -> None:
    init_engine()
    async with session_factory()() as db:
        logs = (await db.execute(select(AuthLog).order_by(AuthLog.id.desc()).limit(5))).scalars()
        sessions = (await db.execute(select(RadiusSession))).scalars()
        devices = (await db.execute(select(Device))).scalars()
        print(json.dumps({
            "logs": [{"result": r.result.value, "username": r.username, "mac": r.mac_address,
                      "method": r.auth_method, "reason": r.reason, "policy": r.policy_name, "vlan": r.vlan}
                     for r in logs],
            "sessions": [{"sid": s.acct_session_id, "username": s.username, "vlan": s.vlan,
                          "framed_ip": s.framed_ip} for s in sessions],
            "devices": {d.mac_address: d.status.value for d in devices},
        }))

asyncio.run(main())
