"""Phase 0.5 — New devices default to unauthorised until an operator approves."""
from __future__ import annotations

from naco.db.models import Device


def test_device_model_defaults_to_unauthorised():
    d = Device(mac_address="aa:bb:cc:dd:ee:ff")
    assert d.authorized is False
