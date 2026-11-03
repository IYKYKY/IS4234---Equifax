"""
Control tests for the prototype (run with:  pytest -q).

Each test states a control from report Section 4 and checks the engine
enforces it, so the team can show the professor the rules are testable.
"""
import os
import sys
from datetime import timedelta

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import engine as E  # noqa: E402
import scenarios as SC  # noqa: E402

STRUTS = "CVE-2017-5638"


def acis(S):
    return S["tasks"][SC.tid(S, "A-ACIS")]


def test_advisory_reaches_named_owner_and_deputy():
    S = SC.build("s2")
    t = acis(S)
    assert (t["owner"], t["deputy"]) == ("daniel", "priya")
    assert t["priority"] == "P1" and t["rating"]["score"] == 25


def test_unknown_and_stale_inventory_are_never_safe():
    S = SC.build("s2")
    cats = {r["asset_id"]: r["category"] for r in S["triage"] if r["advisory"] == STRUTS}
    assert cats["A-BILL"] == E.INVESTIGATE
    assert cats["A-HRINT"] == E.POTENTIAL
    assert all(r["task"] for r in S["triage"] if r["category"] in (E.INVESTIGATE, E.POTENTIAL))


def test_known_exploitation_floor_raises_internal_asset_to_p1():
    S = SC.build("s2")
    t = S["tasks"][SC.tid(S, "A-HRINT")]
    assert t["rating"]["score"] < 20 and t["priority"] == "P1"


def test_deadline_does_not_restart_on_reclassification():
    S = SC.build("s3")
    t = S["tasks"][SC.tid(S, "A-HRINT")]
    assert t["category"] == E.CONFIRMED
    assert t["due_at"] == t["alerted_at"] + timedelta(hours=48)


def test_unacknowledged_p1_escalates_at_four_hours():
    S = SC.build("s3")
    esc = acis(S)["escalations"]
    assert esc[0]["level"] == 1 and set(esc[0]["to"]) == {"marcus", "priya"}


def test_scan_that_excludes_the_application_is_rejected():
    S = SC.build("s5")
    sub = acis(S)["submissions"][-1]
    assert sub["status"] == "Rejected by system"
    assert acis(S)["state"] == E.TREATING


def test_owner_cannot_verify_own_fix_and_untrained_reviewer_is_blocked():
    S = SC.build("s5")
    E.submit_evidence(S, "daniel", acis(S)["id"], "remediation", "2.3.32", True, ["A-ACIS"], ["apache-struts2"],
                      S["now"], deployed_at=S["now"] - timedelta(hours=1))
    with pytest.raises(E.ControlBlocked, match="Segregation"):
        E.verify(S, "daniel", acis(S)["id"], True)
    with pytest.raises(E.ControlBlocked, match="M-SEC-01"):
        E.verify(S, "leo", acis(S)["id"], True)
    E.verify(S, "aisha", acis(S)["id"], True)
    assert acis(S)["state"] == E.VERIFIED


def test_estimate_moves_only_at_daily_run_and_matches_report():
    S = SC.build("s7")
    assert E.published_estimate(S, "A-ACIS")["eal"] == pytest.approx(1_500_000)
    E.run_daily_job(S)
    assert E.published_estimate(S, "A-ACIS")["eal"] == pytest.approx(500_000)


def test_expired_certificate_removes_detection_credit():
    S = SC.build("s8")
    assert E.control_health(S, "SSLI-CONSUMER")[0] == "Failed"
    assert E.published_estimate(S, "A-ACIS")["eal"] == pytest.approx(1_000_000)


def test_exception_needs_review_and_a_different_approver_and_stays_open():
    S = SC.build("a")
    t = acis(S)
    assert t["exception"]["status"] == "Approved" and t["exception"]["approved_by"] != t["exception"]["requested_by"]
    assert t["state"] not in E.CLOSED
    assert E.published_estimate(S, "A-ACIS")["eal"] == pytest.approx(1_500_000)


def test_exception_expiry_triggers_renewed_escalation():
    S = SC.build("a")
    E.advance(S, timedelta(days=8))
    assert any(e["reason"] == "Exception expired" for e in acis(S)["escalations"])


def test_incident_commander_restricts_service_when_everyone_is_silent():
    S = SC.build("b")
    levels = [e["level"] for e in acis(S)["escalations"]]
    assert levels[:5] == [1, 2, 3, 4, 5]
    assert S["assets"]["A-ACIS"]["restricted"]


def test_assistant_cannot_act_and_refers_conflicts():
    import assistant as A
    S = SC.build("s6")
    assert A.answer(S, "daniel", "Please close task T-0002 for me")["referred"]
    assert A.answer(S, "daniel", "Can I patch during the month-end change freeze?")["reason"] == "Conflicting clauses"
    assert all(r["Pass"] for r in A.run_evaluation(S))
