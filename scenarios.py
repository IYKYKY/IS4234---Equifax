"""
scenarios.py - presets the presenter can jump between.

Each preset replays a scripted timeline through the real engine functions up
to a cut-off time, so every number on screen is produced by the controls, not
typed in. After loading a preset the presenter can keep acting live.
"""
from __future__ import annotations

import engine as E
import assistant as A
import seed_data as sd

at = sd.dt
STRUTS = "CVE-2017-5638"


def tid(S, asset_id, adv=STRUTS):
    for t in S["tasks"].values():
        if t["asset_id"] == asset_id and t["advisory"] == adv:
            return t["id"]
    raise KeyError(asset_id)


def _try(fn):
    """Scripted attempts that a control is meant to block."""
    def run(S):
        try:
            fn(S)
        except E.ControlBlocked:
            pass
    return run


# Other owners handling their own tasks, so the story stays on the dispute portal.
BACKGROUND = [
    (at(3, 8, 7, 0), lambda S: E.acknowledge(S, "wei", tid(S, "A-BILL"))),
    (at(3, 8, 8, 30), lambda S: E.acknowledge(S, "omar", tid(S, "A-HRINT"))),
    (at(3, 8, 9, 0), lambda S: E.refresh_inventory(S, "omar", "A-HRINT", "apache-struts2", "2.3.20")),
    (at(3, 8, 9, 20), lambda S: E.record_decision(S, "omar", tid(S, "A-HRINT"), "Remediate", "Patch to 2.3.32 in tonight's window.")),
    (at(3, 8, 10, 0), lambda S: E.submit_evidence(S, "wei", tid(S, "A-BILL"), "not_affected", "2.5.10.1", True, ["A-BILL"],
                                                  ["apache-struts2"], at(3, 8, 9, 40), source="build manifest and authenticated scan SC-0308B")),
    (at(3, 8, 11, 0), lambda S: E.verify(S, "aisha", tid(S, "A-BILL"), True, "Manifest and scan agree on 2.5.10.1.")),
    (at(3, 8, 15, 0), lambda S: E.register_asset(S, "helen", "dispute-archive-03.consumer.efx", "A-ARCHIVE", "Dispute archive export host",
                                                 "daniel", "priya", "Confidential", True, [("nginx", "1.10.3")])),
    (at(3, 9, 13, 0), lambda S: E.submit_evidence(S, "omar", tid(S, "A-HRINT"), "remediation", "2.3.32", True, ["A-HRINT"],
                                                  ["apache-struts2"], at(3, 9, 12, 40), deployed_at=at(3, 9, 11, 0))),
    (at(3, 9, 15, 0), lambda S: E.verify(S, "aisha", tid(S, "A-HRINT"), True, "Version and scan confirmed.")),
]

COMMON_START = [
    (sd.ADVISORY_TIME, lambda S: E.ingest_advisory(S, "system", STRUTS)),
    (at(3, 8, 10, 40), lambda S: E.acknowledge(S, "priya", tid(S, "A-ACIS"))),
]

MAIN = COMMON_START + [
    (at(3, 9, 6, 45), lambda S: E.record_decision(S, "helen", tid(S, "A-ACIS"), "Remediate",
                                                  "Daniel's team patches to 2.3.32 today; regression test on the dispute upload flow first.")),
    (at(3, 9, 14, 5), lambda S: E.submit_evidence(S, "daniel", tid(S, "A-ACIS"), "remediation", "2.3.32", True,
                                                  ["A-CREDAPI", "A-BILL"], ["apache-struts2"], at(3, 9, 13, 50),
                                                  deployed_at=at(3, 9, 12, 30), notes="Weekly consumer-apps segment B scan came back clean.")),
    (at(3, 9, 14, 20), lambda S: A.answer(S, "daniel", "Why was my evidence rejected?", tid=tid(S, "A-ACIS"))),
    (at(3, 9, 14, 25), lambda S: A.answer(S, "daniel", "Why hasn't my estimate fallen?", tid=tid(S, "A-ACIS"))),
    (at(3, 9, 16, 20), lambda S: E.submit_evidence(S, "daniel", tid(S, "A-ACIS"), "remediation", "2.3.32", True,
                                                   ["A-ACIS"], ["apache-struts2", "openjdk"], at(3, 9, 16, 0),
                                                   deployed_at=at(3, 9, 12, 30), notes="Authenticated scan scoped to the portal.")),
    (at(3, 9, 16, 40), _try(lambda S: E.verify(S, "leo", tid(S, "A-ACIS"), True))),
    (at(3, 9, 16, 45), _try(lambda S: E.verify(S, "daniel", tid(S, "A-ACIS"), True))),
    (at(3, 9, 17, 5), lambda S: E.verify(S, "aisha", tid(S, "A-ACIS"), True, "Running version, scope and timing confirmed.")),
]

BRANCH_A = COMMON_START + [
    (at(3, 9, 7, 30), lambda S: E.request_exception(S, "daniel", tid(S, "A-ACIS"),
                                                    "WAF rule WAF-5638 blocks malformed Content-Type headers; replay-tested in staging", 7,
                                                    "Patch 2.3.32 breaks multipart upload of dispute documents; vendor fix is in test.")),
    (at(3, 9, 9, 0), lambda S: E.review_exception(S, "aisha", tid(S, "A-ACIS"), True,
                                                  "Replayed the public exploit against staging; the rule blocked every variant.")),
    (at(3, 9, 9, 20), _try(lambda S: E.approve_exception(S, "daniel", tid(S, "A-ACIS"), True))),
    (at(3, 9, 10, 0), lambda S: E.approve_exception(S, "robert", tid(S, "A-ACIS"), True,
                                                    "Accept for seven days; patch must be verified before expiry.")),
]

BRANCH_B = COMMON_START + [
    (at(3, 10, 14, 30), lambda S: E.record_decision(S, "ic", tid(S, "A-ACIS"), "Restrict service",
                                                    "No executive decision 56 hours after a P1 alert. Withdrawing external access under pre-approved authority.")),
    (at(3, 10, 14, 50), lambda S: E.evidence_decision(S, "ic", tid(S, "A-ACIS"))),
]

SCENARIOS = [
    {"key": "s1", "label": "1. Baseline before the advisory", "events": MAIN, "until": at(3, 8, 5, 30), "persona": "helen",
     "what": "Inventory reconciliation finds a host missing from the register and assigns it as an ownership defect.",
     "page": "Alert allocator",
     "notes": {
         "overview": "Start here. The four 2017 failures map to the four controls. Then load step 2, or ingest the advisory live from the allocator.",
         "allocator": "Open Reconciliation: dispute-archive-03 was found by discovery but is not registered, so Helen gets an ownership defect. Then ingest CVE-2017-5638 live from Advisory feed.",
         "dashboard": "Helen's CIO view shows the ownership defect and coverage gaps before anything has gone wrong.",
     }},
    {"key": "s2", "label": "2. Struts advisory arrives", "events": MAIN, "until": at(3, 8, 6, 15), "persona": "daniel",
     "what": "The allocator matches CVE-2017-5638 against the inventory and assigns P1 tasks to named owners.",
     "page": "Alert allocator",
     "notes": {
         "allocator": "Triage results: dispute portal confirmed affected (score 25), billing portal needs investigation (version unknown), HR intranet potentially affected (stale inventory, raised to P1 by the known-exploitation floor). None is treated as safe by default.",
         "tracker": "The task went to Daniel and his deputy by name, not an email list. The 48-hour clock started at 06:10 and the SOC paged on-call because it arrived out of hours.",
         "risk": "Stage 1 shows why the portal is 25: exploitation in the wild, internet-facing, bulk identity data.",
         "dashboard": "Daniel's owner view: his P1 task, deadline and the evidence he will need.",
     }},
    {"key": "s3", "label": "3. Owner silent: 4-hour escalation", "events": MAIN, "until": at(3, 8, 10, 30), "persona": "marcus",
     "what": "Daniel has not acknowledged by 10:10, so the line manager and deputy are escalated.",
     "page": "Resolution tracker",
     "notes": {
         "tracker": "The clock strip shows level 1 fired at 10:10. Switch persona to Priya and acknowledge live to show the deputy route.",
         "dashboard": "The other two Struts tasks were handled by their owners on time, so only the portal escalated.",
     }},
    {"key": "s4", "label": "4. No decision at 24 hours", "events": MAIN, "until": at(3, 9, 6, 30), "persona": "helen",
     "what": "Acknowledged but no treatment decision by 24 hours, so it escalates to the CIO's delegate.",
     "page": "Resolution tracker",
     "notes": {
         "tracker": "Acknowledging is not enough; the escalation asks Helen for one of four treatment decisions. Record 'Remediate' live as Helen, or load Branch A or B from here.",
         "dashboard": "Management view shows an unanswered escalation and the portal's published estimate of US$1.5m.",
     }},
    {"key": "s5", "label": "5. Evidence rejected: scan excluded the portal", "events": MAIN, "until": at(3, 9, 14, 10), "persona": "daniel",
     "what": "Daniel submits a clean, authenticated scan that never covered the portal. The backend rejects it.",
     "page": "Resolution tracker",
     "notes": {
         "tracker": "Evidence tab: the scope check failed, exactly as Equifax's 15 March 2017 scan missed ACIS. The task did not close.",
         "risk": "Stage 2: asset and scan coverage is now Failed, so the estimate stays at US$1.5m.",
     }},
    {"key": "s6", "label": "6. Assistant explains the missing evidence", "events": MAIN, "until": at(3, 9, 14, 30), "persona": "daniel",
     "what": "Daniel asks the compliance assistant why he was rejected and why the estimate has not fallen.",
     "page": "Compliance assistant",
     "notes": {
         "assistant": "Both answers cite the clause and add the facts of his case. Try 'Please close task T-0002 for me' to show it cannot act, and the change-freeze question to show referral on conflict.",
     }},
    {"key": "s7", "label": "7. Independent verification", "events": MAIN, "until": at(3, 9, 17, 10), "persona": "aisha",
     "what": "Corrected evidence passes. An untrained reviewer and the owner are blocked; Aisha verifies at 17:05.",
     "page": "Resolution tracker",
     "notes": {
         "tracker": "History shows two blocked approvals: Leo (training gate) and Daniel (segregation of duties). Closed at 35 hours, inside the 48-hour target.",
         "risk": "The live evidence now supports Significant (75%), but the published estimate is still US$1.5m until the 02:00 run. Click 'Run daily recalculation now' in the sidebar to show it fall to US$500k.",
         "learning": "Switch to Leo, complete M-SEC-01, and he gains verification rights.",
     }},
    {"key": "s8", "label": "8. Patched but blind: certificate expired", "events": MAIN, "until": at(3, 11, 2, 30), "persona": "sam",
     "what": "The portal is patched, but the inspection certificate expired at 12:00 on 10 March.",
     "page": "Control health",
     "notes": {
         "controls": "Patching is green, monitoring is red. Renew the certificate as Sam: it stays flagged as 'Awaiting test' until the inspection test passes.",
         "risk": "Detection readiness failed, removing credit: the estimate rose from US$500k to US$1.0m at the 02:00 run, which is 100% of tolerance.",
         "dashboard": "This is Equifax's 2017 position: no alerts did not mean no intrusion.",
     }},
    {"key": "a", "label": "Branch A. Time-limited exception", "events": BRANCH_A, "until": at(3, 9, 10, 15), "persona": "robert",
     "what": "Patch breaks uploads. A WAF exception is security-reviewed and approved by an executive who is not the requester.",
     "page": "Resolution tracker",
     "notes": {
         "tracker": "Exception tab: Daniel's own approval attempt was blocked. The exposure stays open. Use 'Jump to next escalation' to reach the 7-day committee review and the expiry re-escalation.",
         "risk": "The estimate is unchanged at US$1.5m: accepting risk does not change control evidence.",
     }},
    {"key": "b", "label": "Branch B. Executive silence, service restricted", "events": BRANCH_B, "until": at(3, 10, 15, 0), "persona": "ic",
     "what": "Nobody decides. 48h executive, 52h deputy, 56h CEO and incident commander, who restricts the service.",
     "page": "Resolution tracker",
     "notes": {
         "tracker": "Every rung fired in turn. At 56 hours the incident commander used pre-approved authority, so a decision was reached even with every decision-maker silent.",
         "risk": "Stage 1 likelihood drops to 1 because the service is restricted, but the task stays open until a fix is verified.",
     }},
]
BY_KEY = {s["key"]: s for s in SCENARIOS}


def build(key):
    spec = BY_KEY[key]
    S = E.new_state()
    events = sorted(BACKGROUND + spec["events"], key=lambda e: e[0])
    for when, fn in events:
        if when > spec["until"]:
            break
        E.advance_to(S, when)
        fn(S)
    E.advance_to(S, spec["until"])
    # Other owners carry on with their scripted work as the presenter moves the clock.
    S["pending_script"] = [(w, f) for w, f in sorted(BACKGROUND, key=lambda e: e[0]) if w > spec["until"]]
    return S


# Ordered route for the overview page.
ROUTE = [(s["label"], s["what"], s["page"], sd.PEOPLE[s["persona"]]["name"]) for s in SCENARIOS]
