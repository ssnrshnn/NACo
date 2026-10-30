from datetime import UTC, datetime
from zoneinfo import ZoneInfo

from naco.db.models import Policy, PolicyAction
from naco.policy.context import AuthContext
from naco.policy.engine import DEFAULT_DENY_REASON, compile_policy, decide, evaluate, explain

TZ = ZoneInfo("UTC")


def ctx(**kw):
    base = {"auth_method": "PEAP", "username": "alice", "group": "staff",
            "now": datetime(2026, 10, 28, 10, 0, tzinfo=UTC)}
    base.update(kw)
    return AuthContext(**base)


def pol(id_, name, priority, action, conditions, vlan=None, attrs=None, enabled=True):
    return Policy(id=id_, name=name, priority=priority, action=action, conditions=conditions,
                  vlan=vlan, reply_attributes=attrs or {}, enabled=enabled)


STAFF = [{"type": "group", "op": "in", "value": ["staff"]}]


def test_no_policies_means_deny():
    d = decide([], ctx(), TZ)
    assert not d.accepted
    assert d.reason == DEFAULT_DENY_REASON
    assert d.policy_id is None


def test_first_match_wins_in_given_order():
    policies = [
        compile_policy(pol(1, "deny-bob", 10, PolicyAction.DENY,
                           [{"type": "username", "op": "equals", "value": "bob"}])),
        compile_policy(pol(2, "staff", 20, PolicyAction.PERMIT, STAFF, vlan=10, attrs={"Filter-Id": "staff"})),
        compile_policy(pol(3, "everyone", 30, PolicyAction.PERMIT, [{"type": "always"}], vlan=99)),
    ]
    d = decide(policies, ctx(), TZ)
    assert d.accepted and d.vlan == 10 and d.policy_name == "staff"
    assert d.reply_attributes == {"Filter-Id": "staff"}
    assert not decide(policies, ctx(username="bob"), TZ).accepted
    assert decide(policies, ctx(group="contractors"), TZ).vlan == 99


def test_empty_condition_list_matches_everything():
    d = decide([compile_policy(pol(1, "all", 1, PolicyAction.PERMIT, []))], ctx(), TZ)
    assert d.accepted and d.vlan is None


def test_explain_reports_every_condition():
    policies = [compile_policy(pol(1, "staff-peap", 1, PolicyAction.PERMIT, [
        *STAFF, {"type": "auth_method", "value": ["EAP-TLS"]}]))]
    (trace,) = explain(policies, ctx(), TZ)
    assert trace.matched is False
    assert trace.conditions == [("group in staff", True), ("auth_method in EAP-TLS", False)]


async def test_evaluate_reads_enabled_policies_in_priority_order(db):
    db.add_all([
        pol(None, "late-permit", 50, PolicyAction.PERMIT, [{"type": "always"}], vlan=50),
        pol(None, "early-deny", 5, PolicyAction.DENY, STAFF),
        pol(None, "disabled", 1, PolicyAction.PERMIT, [{"type": "always"}], vlan=1, enabled=False),
    ])
    await db.commit()
    assert not (await evaluate(db, ctx())).accepted
    assert (await evaluate(db, ctx(group="ops"))).vlan == 50


async def test_evaluate_fails_closed_on_a_corrupt_policy(db):
    db.add_all([
        pol(None, "permit-all", 1, PolicyAction.PERMIT, [{"type": "always"}], vlan=10),
        pol(None, "corrupt", 2, PolicyAction.DENY, [{"type": "nonsense"}]),
    ])
    await db.commit()
    d = await evaluate(db, ctx())
    assert not d.accepted
    assert d.reason == "policy configuration error"
