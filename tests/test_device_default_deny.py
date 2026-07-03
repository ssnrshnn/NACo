"""Phase 0.5 — New devices default to unauthorised until an operator approves."""
from __future__ import annotations

from naco.db.models import Device


def test_device_model_column_default_is_false():
    """The SQLAlchemy insert-default must be False so DB-level INSERTs
    without an explicit ``authorized`` value land as blocked."""
    col = Device.__table__.c.authorized
    assert col.default.arg is False


async def test_device_persisted_defaults_to_unauthorised(db):
    """A Device flushed without setting ``authorized`` must persist as False."""
    d = Device(mac_address="aa:bb:cc:dd:ee:ff")
    db.add(d)
    await db.flush()
    await db.refresh(d)
    assert d.authorized is False
