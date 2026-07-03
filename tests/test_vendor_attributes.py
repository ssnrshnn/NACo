"""Vendor compatibility — VSA dictionary + per-policy RADIUS reply attributes.

Covers the three layers of the feature:

1. the bundled dictionary parses and exposes the vendor attributes,
2. ``PolicyEngine.evaluate`` surfaces ``Policy.reply_attributes`` on the
   decision (dict, JSON-text, and invalid-JSON forms),
3. ``NACoRadiusServer._attach_reply_attributes`` encodes them onto an
   Access-Accept and never raises on bad input, and
4. the API schema rejects malformed attribute maps (including the
   ``control:``-prefix injection that would reach FreeRADIUS via rlm_rest).
"""
from __future__ import annotations

import json

import pydantic
import pyrad.packet
import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from naco.api.schemas import PolicyCreate
from naco.db.models import Policy, PolicyAction
from naco.policy.engine import AuthContext, PolicyEngine
from naco.radius.server import NACoRadiusServer

SECRET = b"testing123"


@pytest.fixture(scope="module")
def server() -> NACoRadiusServer:
    return NACoRadiusServer()


def _accept(server: NACoRadiusServer) -> pyrad.packet.AuthPacket:
    pkt = pyrad.packet.AuthPacket(
        secret=SECRET, id=1, dict=server.dict, code=pyrad.packet.AccessAccept
    )
    pkt.authenticator = b"\x11" * 16
    return pkt


# ---------------------------------------------------------------------------
# Dictionary — vendor attributes resolve and encode
# ---------------------------------------------------------------------------

class TestVendorDictionary:
    @pytest.mark.parametrize("attr", [
        "Cisco-AVPair", "Aruba-User-Role", "Aruba-User-Vlan",
        "Fortinet-Group-Name", "Mikrotik-Rate-Limit", "Ruckus-User-Groups",
        "PaloAlto-Admin-Role", "Juniper-Local-User-Name",
        "WISPr-Bandwidth-Max-Down", "Extreme-Netlogin-Vlan",
        "HP-Privilege-Level", "Huawei-Exec-Privilege", "Arista-AVPair",
    ])
    def test_vsa_known(self, server: NACoRadiusServer, attr: str):
        assert attr in server.dict.attributes

    def test_string_vsa_encodes(self, server: NACoRadiusServer):
        pkt = _accept(server)
        pkt.AddAttribute("Aruba-User-Role", "employee")
        assert len(pkt.RequestPacket()) > 20  # header + VSA present

    def test_integer_vsa_encodes(self, server: NACoRadiusServer):
        pkt = _accept(server)
        pkt.AddAttribute("WISPr-Bandwidth-Max-Down", 10_000_000)
        assert len(pkt.RequestPacket()) > 20


# ---------------------------------------------------------------------------
# Policy engine — reply_attributes surface on the decision
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestEngineReplyAttributes:
    async def test_dict_reply_attributes(self, db: AsyncSession):
        db.add(Policy(
            name="aruba-role",
            priority=1,
            conditions=json.dumps([{"type": "always"}]),
            action=PolicyAction.PERMIT,
            reply_attributes={"Aruba-User-Role": "employee",
                              "Cisco-AVPair": ["shell:priv-lvl=15"]},
            enabled=True,
        ))
        await db.commit()

        decision = await PolicyEngine().evaluate(AuthContext(username="a"), db)
        assert decision.action == PolicyAction.PERMIT
        assert decision.reply_attributes == {
            "Aruba-User-Role": "employee",
            "Cisco-AVPair": ["shell:priv-lvl=15"],
        }

    async def test_json_text_reply_attributes(self, db: AsyncSession):
        db.add(Policy(
            name="text-attrs",
            priority=1,
            conditions=json.dumps([{"type": "always"}]),
            action=PolicyAction.PERMIT,
            reply_attributes=json.dumps({"Filter-Id": "staff"}),
            enabled=True,
        ))
        await db.commit()

        decision = await PolicyEngine().evaluate(AuthContext(username="a"), db)
        assert decision.reply_attributes == {"Filter-Id": "staff"}

    async def test_invalid_json_reply_attributes_ignored(self, db: AsyncSession):
        db.add(Policy(
            name="broken-attrs",
            priority=1,
            conditions=json.dumps([{"type": "always"}]),
            action=PolicyAction.PERMIT,
            reply_attributes="NOT JSON",
            enabled=True,
        ))
        await db.commit()

        decision = await PolicyEngine().evaluate(AuthContext(username="a"), db)
        assert decision.action == PolicyAction.PERMIT
        assert decision.reply_attributes == {}

    async def test_no_reply_attributes_defaults_empty(self, db: AsyncSession):
        db.add(Policy(
            name="plain",
            priority=1,
            conditions=json.dumps([{"type": "always"}]),
            action=PolicyAction.PERMIT,
            enabled=True,
        ))
        await db.commit()

        decision = await PolicyEngine().evaluate(AuthContext(username="a"), db)
        assert decision.reply_attributes == {}


# ---------------------------------------------------------------------------
# RADIUS server — attributes land on the Access-Accept
# ---------------------------------------------------------------------------

class TestAttachReplyAttributes:
    def test_attaches_string_and_multivalue(self, server: NACoRadiusServer):
        reply = _accept(server)
        server._attach_reply_attributes(reply, {
            "Aruba-User-Role": "employee",
            "Cisco-AVPair": ["shell:priv-lvl=15", "url-redirect=http://x"],
        }, "alice")
        assert reply["Aruba-User-Role"] == ["employee"]
        assert reply["Cisco-AVPair"] == ["shell:priv-lvl=15", "url-redirect=http://x"]

    def test_integer_attr_from_json_string(self, server: NACoRadiusServer):
        """JSON often carries integers as strings — must coerce."""
        reply = _accept(server)
        server._attach_reply_attributes(reply, {"Session-Timeout": "3600"}, "alice")
        assert reply["Session-Timeout"] == [3600]

    def test_unknown_attribute_skipped_without_raising(self, server: NACoRadiusServer):
        reply = _accept(server)
        server._attach_reply_attributes(
            reply, {"No-Such-Attribute": "x", "Filter-Id": "ok"}, "alice"
        )
        assert reply["Filter-Id"] == ["ok"]

    def test_empty_and_none_are_noops(self, server: NACoRadiusServer):
        reply = _accept(server)
        server._attach_reply_attributes(reply, {}, "alice")
        server._attach_reply_attributes(reply, None, "alice")


# ---------------------------------------------------------------------------
# API schema — validation of the reply_attributes map
# ---------------------------------------------------------------------------

class TestSchemaValidation:
    def _policy(self, attrs) -> PolicyCreate:
        return PolicyCreate(name="p", reply_attributes=attrs)

    def test_valid_map_accepted(self):
        p = self._policy({"Aruba-User-Role": "employee", "Session-Timeout": 3600,
                          "Cisco-AVPair": ["a=1", "b=2"]})
        assert p.reply_attributes["Session-Timeout"] == 3600

    def test_control_prefix_injection_rejected(self):
        with pytest.raises(pydantic.ValidationError):
            self._policy({"control:Auth-Type": "Accept"})

    def test_bad_name_rejected(self):
        with pytest.raises(pydantic.ValidationError):
            self._policy({"Bad Name!": "x"})

    def test_non_scalar_value_rejected(self):
        with pytest.raises(pydantic.ValidationError):
            self._policy({"Filter-Id": {"nested": "dict"}})

    def test_empty_list_rejected(self):
        with pytest.raises(pydantic.ValidationError):
            self._policy({"Filter-Id": []})

    def test_overlong_value_rejected(self):
        with pytest.raises(pydantic.ValidationError):
            self._policy({"Filter-Id": "x" * 254})

    def test_too_many_attributes_rejected(self):
        with pytest.raises(pydantic.ValidationError):
            self._policy({f"Attr-{i}": "v" for i in range(33)})

    def test_none_allowed(self):
        assert self._policy(None).reply_attributes is None
