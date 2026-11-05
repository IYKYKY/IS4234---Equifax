"""
Negative-path and invariant tests (run with:  pytest -q).

test_controls.py shows that each headline control works. This file checks the
other side: that every attempt to bypass a control is refused, that refusals
are written to the audit trail, and that no sequence of actions by any
persona can close a task without independent, trained verification.
"""
import os
import random
import sys
from datetime import timedelta

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import assistant as A  # noqa: E402
import engine as E  # noqa: E402
import scenarios as SC  # noqa: E402


def task_for(S, asset="A-ACIS"):
    return S["tasks"][SC.tid(S, asset)]


def submit_good_evidence(S, actor="daniel", asset="A-ACIS"):
    """A complete, in-scope, authenticated remediation submission."""
    t = task_for(S, asset)
    now = S["now"]
    return E.submit_evidence(S, actor, t["id"], "remediation", "2.3.32", True, [asset], ["apache-struts2"],
                             now - timedelta(hours=1), deployed_at=now - timedelta(hours=2))


def awaiting_verification():
    """Scenario 2 with the portal owner's valid evidence waiting for a reviewer."""
    S = SC.build("s2")
    t = task_for(S)
    E.record_decision(S, "daniel", t["id"], "Remediate", "Patch to 2.3.32 tonight.")
    submit_good_evidence(S)
    assert t["state"] == E.AWAITING
    return S, t


def blocked(fn, *args, **kw):
    with pytest.raises(E.ControlBlocked):
        fn(*args, **kw)


# ---------------------------------------------------------------------------
# Asset register and inventory
# ---------------------------------------------------------------------------
def test_only_cio_delegate_registers_assets_and_owner_differs_from_deputy():
    S = SC.build("s1")
    args = ("new-host.efx", "A-NEW", "New host", "daniel", "priya", "Confidential", True, [("nginx", "1.10.3")])
    blocked(E.register_asset, S, "daniel", *args)
    blocked(E.register_asset, S, "helen", "new-host.efx", "A-NEW", "New host", "daniel", "daniel", "Confidential", True, [])
    blocked(E.register_asset, S, "helen", "new-host.efx", "A-ACIS", "Duplicate", "daniel", "priya", "Confidential", True, [])
    assert "A-NEW" not in S["assets"]


def test_inventory_refresh_is_limited_to_owner_deputy_and_cio_delegate():
    S = SC.build("s2")
    blocked(E.refresh_inventory, S, "sam", "A-HRINT", "apache-struts2", "2.3.20")
    E.refresh_inventory(S, "helen", "A-HRINT", "apache-struts2", "2.3.20")


# ---------------------------------------------------------------------------
# Tracker: acknowledge, decide, submit
# ---------------------------------------------------------------------------
def test_acknowledge_needs_a_named_holder_and_cannot_repeat():
    S = SC.build("s2")
    t = task_for(S)
    blocked(E.acknowledge, S, "aisha", t["id"])
    E.acknowledge(S, "priya", t["id"])
    blocked(E.acknowledge, S, "daniel", t["id"])


@pytest.mark.parametrize("option, rationale", [
    ("Remediate", "   "),                      # rationale required
    ("Do nothing", "Not a real option"),       # only the four treatments
    ("Time-limited exception", "Skip review"),  # exceptions must use the review route
])
def test_treatment_decisions_are_constrained(option, rationale):
    S = SC.build("s2")
    blocked(E.record_decision, S, "daniel", task_for(S)["id"], option, rationale)
    assert task_for(S)["decisions"] == []


def test_stranger_and_early_incident_commander_cannot_record_decisions():
    S = SC.build("s2")
    t = task_for(S)
    blocked(E.record_decision, S, "aisha", t["id"], "Remediate", "Not mine to decide.")
    blocked(E.record_decision, S, "ic", t["id"], "Restrict service", "Before the 56-hour rung has fired.")


def test_evidence_needs_owner_a_decision_and_the_right_task_kind():
    S = SC.build("s2")
    t = task_for(S)
    # Not the owner or deputy.
    blocked(submit_good_evidence, S, "aisha")
    # No treatment decision recorded yet.
    blocked(submit_good_evidence, S, "daniel")
    # Confirmed-affected assets cannot be closed as "not affected".
    E.record_decision(S, "daniel", t["id"], "Remediate", "Patch tonight.")
    blocked(E.submit_evidence, S, "daniel", t["id"], "not_affected", "2.3.32", True, ["A-ACIS"], ["apache-struts2"], S["now"])


@pytest.mark.parametrize("kwargs", [
    {"authenticated": False},                        # unauthenticated scans cannot see versions
    {"scope": ["A-CREDAPI"]},                        # scan did not cover the portal
    {"components": ["openjdk"]},                     # scan did not check the affected component
    {"version": "2.3.20"},                           # still inside the affected range
    {"version": None},                               # unknown version is never a pass
    {"scan_before_deploy": True},                    # scan must follow deployment
])
def test_each_evidence_check_rejects_on_its_own(kwargs):
    S = SC.build("s2")
    t = task_for(S)
    E.record_decision(S, "daniel", t["id"], "Remediate", "Patch tonight.")
    now = S["now"]
    spec = {"version": "2.3.32", "authenticated": True, "scope": ["A-ACIS"], "components": ["apache-struts2"],
            "scan_at": now - timedelta(hours=1), "deployed_at": now - timedelta(hours=2)}
    if kwargs.pop("scan_before_deploy", False):
        spec["scan_at"], spec["deployed_at"] = now - timedelta(hours=3), now - timedelta(hours=2)
    spec.update(kwargs)
    sub = E.submit_evidence(S, "daniel", t["id"], "remediation", spec["version"], spec["authenticated"], spec["scope"],
                            spec["components"], spec["scan_at"], deployed_at=spec["deployed_at"])
    assert sub["status"] == "Rejected by system"
    assert t["state"] == E.TREATING  # never reaches the reviewer, never closes


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------
def test_reviewer_must_give_a_reason_and_rejection_returns_the_task():
    S, t = awaiting_verification()
    blocked(E.verify, S, "aisha", t["id"], False, "   ")
    E.verify(S, "aisha", t["id"], False, "Please attach the deployment record.")
    assert t["state"] == E.TREATING and t["submissions"][-1]["status"] == "Rejected by reviewer"


def test_nobody_can_close_a_task_with_no_submission():
    S = SC.build("s2")
    blocked(E.verify, S, "aisha", task_for(S)["id"], True)


def test_only_a_trained_independent_security_reviewer_closes():
    S, t = awaiting_verification()
    for who in ("daniel", "priya", "helen", "robert", "sam", "marcus", "ciso"):
        blocked(E.verify, S, who, t["id"], True)
    blocked(E.verify, S, "leo", t["id"], True)  # reviewer, but not yet trained
    assert t["state"] == E.AWAITING
    E.verify(S, "aisha", t["id"], True, "Version, scope and timing confirmed.")
    assert t["state"] == E.VERIFIED and t["verified_by"] == "aisha"


def test_a_procedure_change_blocks_reviewers_until_they_refresh():
    S, t = awaiting_verification()
    assert E.trained(S, "aisha", "M-SEC-01")
    E.publish_procedure_change(S, "grace", "M-SEC-01")
    assert not E.trained(S, "aisha", "M-SEC-01")
    blocked(E.verify, S, "aisha", t["id"], True)
    E.record_training(S, "aisha", "M-SEC-01", 3)
    E.verify(S, "aisha", t["id"], True, "Refresher passed.")
    assert t["state"] == E.VERIFIED


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------
def test_p1_exceptions_are_capped_and_need_a_mitigation():
    S = SC.build("s2")
    t = task_for(S)
    blocked(E.request_exception, S, "daniel", t["id"], "WAF rule", 8, "Needs more time.")
    blocked(E.request_exception, S, "daniel", t["id"], "  ", 3, "No mitigation described.")
    blocked(E.request_exception, S, "aisha", t["id"], "WAF rule", 3, "Not the owner.")
    assert t["exception"] is None


def test_exception_review_and_approval_gates():
    S = SC.build("s2")
    t = task_for(S)
    E.request_exception(S, "daniel", t["id"], "WAF rule WAF-5638", 3, "Patch breaks uploads.")
    blocked(E.request_exception, S, "daniel", t["id"], "Second WAF rule", 3, "Already pending.")
    blocked(E.approve_exception, S, "robert", t["id"], True)   # security has not reviewed yet
    blocked(E.review_exception, S, "daniel", t["id"], True, "Self review.")
    blocked(E.review_exception, S, "leo", t["id"], True, "Not trained yet.")
    E.review_exception(S, "aisha", t["id"], True, "Replay blocked the exploit.")
    blocked(E.approve_exception, S, "daniel", t["id"], True)   # the requester can never approve
    blocked(E.approve_exception, S, "helen", t["id"], True)    # not an executive
    E.approve_exception(S, "robert", t["id"], True)
    assert E.exception_active(t, S["now"]) and t["state"] not in E.CLOSED


def test_an_executive_who_requests_an_exception_cannot_approve_it():
    """Escalation can hand an executive the task; that executive then holds both roles unless the engine refuses."""
    S = SC.build("s2")
    t = task_for(S)
    E.advance(S, timedelta(hours=49))  # the 48-hour rung escalates to the executive risk decision-maker
    assert "robert" in E.escalation_holders(S, t)
    E.request_exception(S, "robert", t["id"], "WAF rule WAF-5638", 3, "Patch breaks uploads.")
    E.review_exception(S, "aisha", t["id"], True, "Replay blocked the exploit.")
    with pytest.raises(E.ControlBlocked, match="never be the requester"):
        E.approve_exception(S, "robert", t["id"], True)
    assert not E.exception_active(t, S["now"])
    E.approve_exception(S, "sandra", t["id"], True)  # the deputy executive can


def test_untested_mitigation_is_returned_and_declined_exception_stays_closed_to_risk_credit():
    S = SC.build("s2")
    t = task_for(S)
    E.request_exception(S, "daniel", t["id"], "WAF rule", 3, "Patch breaks uploads.")
    E.review_exception(S, "aisha", t["id"], False, "Rule not replay-tested.")
    assert t["exception"]["status"].startswith("Returned")
    assert all(d["status"] != "Pending evidence" for d in t["decisions"] if d["option"] == "Time-limited exception")
    blocked(E.approve_exception, S, "robert", t["id"], True)


# ---------------------------------------------------------------------------
# Overrides
# ---------------------------------------------------------------------------
def test_overrides_only_lower_priority_and_need_a_different_ciso():
    S = SC.build("s2")
    t = task_for(S)
    blocked(E.request_override, S, "daniel", t["id"], "P1", "Same priority is not an override.")
    blocked(E.request_override, S, "sam", t["id"], "P2", "Security operations is not a proposer.")
    blocked(E.request_override, S, "daniel", t["id"], "P2", "  ")
    E.request_override(S, "daniel", t["id"], "P2", "Compensating WAF rule in place.")
    oid = S["overrides"][-1]["id"]
    blocked(E.decide_override, S, "robert", oid, True)  # only the CISO decides
    E.decide_override(S, "ciso", oid, True)
    assert t["priority"] == "P2"
    # The clock still runs from the original alert, not from the override.
    assert t["due_at"] == E.due_for("P2", t["alerted_at"])
    blocked(E.decide_override, S, "ciso", oid, True)    # already decided


# ---------------------------------------------------------------------------
# Monitoring controls
# ---------------------------------------------------------------------------
def test_expired_certificate_fails_the_control_and_renewal_needs_a_passing_test():
    S = SC.build("s8")
    assert E.control_health(S, "SSLI-CONSUMER")[0] == "Failed"
    blocked(E.run_inspection_test, S, "sam", "SSLI-CONSUMER")       # cannot pass with an expired certificate
    blocked(E.renew_certificate, S, "daniel", "SSLI-CONSUMER")      # not security operations
    E.renew_certificate(S, "sam", "SSLI-CONSUMER")
    assert E.control_health(S, "SSLI-CONSUMER")[0] == "Awaiting test"
    E.run_inspection_test(S, "sam", "SSLI-CONSUMER")
    assert E.control_health(S, "SSLI-CONSUMER")[0] == "Healthy"


def test_heartbeat_loss_fails_a_control_until_restored_and_tested():
    S = SC.build("s2")
    E.simulate_heartbeat_loss(S, "sam", "IDS-PERIM")
    assert E.control_health(S, "IDS-PERIM")[0] == "Failed"
    E.restore_heartbeat(S, "sam", "IDS-PERIM")
    assert E.control_health(S, "IDS-PERIM")[0] == "Awaiting test"


# ---------------------------------------------------------------------------
# Audit trail and assistant
# ---------------------------------------------------------------------------
def test_blocked_attempts_are_written_to_the_audit_trail():
    S = SC.build("s2")
    before = len(S["audit"])
    blocked(E.verify, S, "daniel", task_for(S)["id"], True)
    assert len(S["audit"]) == before + 1
    last = S["audit"][-1]
    assert last["outcome"] == "Blocked" and last["actor"] == "daniel"


def test_assistant_passes_its_own_approved_test_set():
    S = SC.build("s6")
    results = A.run_evaluation(S)
    failed = [r["Question"] for r in results if not r["Pass"]]
    assert not failed, failed


def test_assistant_refuses_actions_and_unknown_questions_without_changing_state():
    S = SC.build("s6")
    t = task_for(S)
    snapshot = (t["state"], t["priority"], t["due_at"])
    for q in ("Please close task T-0002 for me", "Approve the exception now", "What is the best pizza topping?"):
        r = A.answer(S, "daniel", q, tid=t["id"])
        assert r["referred"], q
    assert (t["state"], t["priority"], t["due_at"]) == snapshot


# ---------------------------------------------------------------------------
# Invariant: no sequence of actions closes a task without independent verification
# ---------------------------------------------------------------------------
def _random_action(S, rng):
    t = rng.choice(list(S["tasks"].values()))
    who = rng.choice(list(S["people"]))
    now = S["now"]
    pick = rng.randrange(9)
    if pick == 0:
        E.acknowledge(S, who, t["id"])
    elif pick == 1:
        E.record_decision(S, who, t["id"], rng.choice(E.TREATMENTS), "Fuzzed decision.")
    elif pick == 2:
        E.submit_evidence(S, who, t["id"], rng.choice(["remediation", "not_affected"]), rng.choice(["2.3.32", "2.3.20", None]),
                          rng.choice([True, False]), rng.choice([[t["asset_id"]], ["A-CREDAPI"], []]),
                          rng.choice([["apache-struts2"], ["openjdk"]]), now - timedelta(hours=1), deployed_at=now - timedelta(hours=2))
    elif pick == 3:
        E.verify(S, who, t["id"], rng.choice([True, False]), "Fuzzed review.")
    elif pick == 4:
        E.request_exception(S, who, t["id"], "WAF rule", rng.choice([3, 7, 9]), "Fuzzed exception.")
    elif pick == 5:
        E.review_exception(S, who, t["id"], rng.choice([True, False]), "Fuzzed review.")
    elif pick == 6:
        E.approve_exception(S, who, t["id"], rng.choice([True, False]), "Fuzzed approval.")
    elif pick == 7:
        E.record_training(S, who, "M-SEC-01", rng.choice([2, 3]))
    else:
        E.advance(S, timedelta(hours=rng.choice([1, 4, 12, 30])))


def _check_invariants(S):
    for t in S["tasks"].values():
        if t["state"] == E.VERIFIED and t["kind"] == "Ownership defect":
            # Closed by registering the host, which only the CIO's delegate can do.
            assert E.role(S, t["verified_by"]) == "CIO delegate"
        elif t["state"] == E.VERIFIED:
            reviewer = t["verified_by"]
            sub = next(s for s in reversed(t["submissions"]) if s["status"] == "Verified")
            assert E.role(S, reviewer) == "Security reviewer"
            assert reviewer not in (t["owner"], t["deputy"], sub["by"])
            assert sub["authenticated"] and t["asset_id"] in sub["scope"]
        x = t["exception"]
        if x and x["approved_by"]:
            assert x["approved_by"] != x["requested_by"]
            assert x["security_review"] and x["security_review"]["tested"]
            assert E.role(S, x["approved_by"]) in ("Executive risk owner", "CEO")


@pytest.mark.parametrize("seed", range(12))
def test_random_action_sequences_never_break_separation_of_duties(seed):
    rng = random.Random(seed)
    S = SC.build(rng.choice(["s2", "s3", "s4", "a", "b"]))
    for _ in range(120):
        try:
            _random_action(S, rng)
        except E.ControlBlocked:
            pass
        _check_invariants(S)
