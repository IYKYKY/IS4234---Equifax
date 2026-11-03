"""
engine.py - the controls behind the prototype.

Section 4 of the report says the backend, not the interface, enforces the
rules. This module is that backend: no Streamlit imports, every action is a
plain function that either changes the state or raises ControlBlocked, and
every attempt (allowed or blocked) is written to the audit trail.

State is a plain dict so it can be deep-copied for scenario presets and
replaced by PostgreSQL tables in the production design (report 4.8).
"""
from __future__ import annotations

import copy
import random
import re
from datetime import datetime, timedelta

import seed_data as sd


class ControlBlocked(Exception):
    """A backend control refused the action. The attempt is already logged."""


# ---------------------------------------------------------------------------
# Vocabulary
# ---------------------------------------------------------------------------
ASSIGNED, ACKED, TREATING, AWAITING = "Assigned", "Acknowledged", "In treatment", "Awaiting verification"
VERIFIED, NOT_AFFECTED = "Verified closed", "Closed (not affected)"
CLOSED = {VERIFIED, NOT_AFFECTED}
LIFECYCLE = [ASSIGNED, ACKED, TREATING, AWAITING, VERIFIED]

CONFIRMED = "Confirmed affected"
INVESTIGATE = "Requires investigation"
POTENTIAL = "Potentially affected (stale inventory)"
NOT_AFF = "Not affected"
ABSENT = "Component not present"

TREATMENTS = ["Remediate", "Temporary protection", "Restrict service", "Time-limited exception"]

CLASS_IMPACT = {"Public": 1, "Internal": 2, "Confidential": 3, "Sensitive consumer": 4, "Bulk sensitive identity": 5}
IMPACT_TEXT = {1: "Public information, negligible disruption", 2: "Limited internal information",
               3: "Confidential information", 4: "Sensitive consumer information or important service",
               5: "Bulk sensitive identity information"}
STALE_DAYS = 7

SLA = {"P1": ("hours", 48), "P2": ("hours", 168), "P3": ("bdays", 30), "P4": ("bdays", 90), "Unassessed": ("hours", 48)}
PRIORITY_ORDER = {"P1": 1, "Unassessed": 1, "P2": 2, "P3": 3, "P4": 4}

# Escalation route. P1 follows Table 4.2 of the report exactly; the other
# ladders are proportional and illustrative.
_RUNG_SPEC = [
    ("not_acknowledged", ["line_manager", "deputy"], "Acknowledge and confirm the owner"),
    ("no_decision", ["cio_delegate"], "Record one of the four treatment decisions"),
    ("not_closed_no_exception", ["exec"], "Record a decision within 4 hours"),
    ("no_exec_decision", ["exec_deputy"], "Record a decision within 4 hours"),
    ("no_exec_decision", ["ceo", "incident_commander"], "Restrict the service or record a decision"),
    ("open", ["committee_chair"], "Review before or at the next committee meeting"),
]
LADDER_AFTER = {
    "P1": ("hours", [4, 24, 48, 52, 56, 168]),
    "Unassessed": ("hours", [4, 24, 48, 52, 56, 168]),
    "P2": ("hours", [24, 72, 168, 172, 176, 336]),
    "P3": ("bdays", [2, 5, 30, 31, 32, 45]),
    "P4": ("bdays", [5, 10, 90, 91, 92, 120]),
}

FACTORS = {
    "patch": "Patch verification",
    "coverage": "Asset and scan coverage",
    "priv": "Privileged access",
    "network": "Network restrictions",
    "detection": "Detection readiness",
}
BANDS = [("Minor", 0.25), ("Moderate", 0.50), ("Significant", 0.75), ("Nearly complete", 0.95)]
MODEL_VERSION = "RQ model 1.2"
RUBRIC_VERSION = "Rubric 0.3 (CISO approved, pending calibration)"
DAILY_JOB_HOUR = 2
RECON_HOUR = 5
GATES = {"verify": "M-SEC-01", "exception_review": "M-SEC-01", "exception_approve": "M-RISK-01"}


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
def new_state():
    S = {
        "now": sd.SIM_START,
        "people": copy.deepcopy(sd.PEOPLE),
        "directory": dict(sd.DIRECTORY),
        "assets": copy.deepcopy(sd.ASSETS),
        "inventory": copy.deepcopy(sd.INVENTORY),
        "discovery": copy.deepcopy(sd.DISCOVERY),
        "advisories": copy.deepcopy(sd.ADVISORIES),
        "ingested": {},
        "triage": [],
        "tasks": {},
        "controls": copy.deepcopy(sd.CONTROLS),
        "evidence": copy.deepcopy(sd.EVIDENCE),
        "assumptions": copy.deepcopy(sd.ASSUMPTIONS),
        "estimates": [],
        "last_job_run": None,
        "last_recon": None,
        "training": copy.deepcopy(sd.TRAINING),
        "module_versions": {m: d["version"] for m, d in sd.MODULES.items()},
        "audit": copy.deepcopy(sd.PRIOR_AUDIT),
        "assistant_log": [],
        "overrides": [],
        "seq": {"task": 0, "exc": 0, "ovr": 0, "sub": 0},
    }
    for c in S["controls"].values():
        c["notified"] = set()
        if c["cert_expires"]:
            for d in sd.CERT_WARNING_DAYS:
                if c["cert_expires"] - timedelta(days=d) <= S["now"]:
                    c["notified"].add(d)
    return S


def name(S, pid):
    if pid == "system":
        return "System"
    p = S["people"].get(pid)
    return p["name"] if p else pid


def role(S, pid):
    return S["people"].get(pid, {}).get("role", "")


def log(S, actor, action, obj="", detail="", outcome="Done"):
    S["audit"].append({"at": S["now"], "actor": actor, "action": action, "object": obj,
                       "detail": detail, "outcome": outcome})


def _block(S, actor, action, obj, reason):
    log(S, actor, action, obj, reason, "Blocked")
    raise ControlBlocked(reason)


def _next_id(S, kind, prefix):
    S["seq"][kind] += 1
    return f"{prefix}-{S['seq'][kind]:04d}"


# ---------------------------------------------------------------------------
# Time helpers
# ---------------------------------------------------------------------------
def add_business_days(start, n):
    d, added = start, 0
    while added < n:
        d += timedelta(days=1)
        if d.weekday() < 5:
            added += 1
    return d


def _offset(start, unit, amount):
    return start + timedelta(hours=amount) if unit == "hours" else add_business_days(start, amount)


def due_for(priority, alerted_at):
    unit, amount = SLA[priority]
    return _offset(alerted_at, unit, amount)


def is_out_of_hours(t):
    return t.weekday() >= 5 or t.hour < 8 or t.hour >= 18


def _next_daily(after, hour):
    t = after.replace(hour=hour, minute=0, second=0, microsecond=0)
    return t if t > after else t + timedelta(days=1)


# ---------------------------------------------------------------------------
# Versions and inventory
# ---------------------------------------------------------------------------
def vkey(v):
    return tuple((0, int(p)) if p.isdigit() else (1, p) for p in re.findall(r"\d+|[a-z]+", str(v).lower()))


def in_affected_range(version, ranges):
    if version in (None, "", "unknown"):
        return None
    return any(vkey(lo) <= vkey(version) <= vkey(hi) for lo, hi in ranges)


def inventory_for(S, asset_id):
    return [r for r in S["inventory"] if r["asset_id"] == asset_id]


def inventory_age_days(S, asset_id):
    at = S["assets"][asset_id].get("inventory_at")
    return None if at is None else (S["now"] - at).total_seconds() / 86400


def classify(S, asset_id, adv):
    """Place an asset in one of the report's categories for an advisory (4.3.1)."""
    age = inventory_age_days(S, asset_id)
    rows = [r for r in inventory_for(S, asset_id) if r["component"] == adv["component"]]
    if age is None or age > STALE_DAYS:
        found = rows[0]["version"] if rows else "no current record"
        return POTENTIAL, found, f"Software inventory is {'missing' if age is None else f'{age:.0f} days old'}; treated as potentially affected"
    if not rows:
        return ABSENT, "-", "Component not in current inventory"
    v = rows[0]["version"]
    hit = in_affected_range(v, adv["affected"])
    if hit is None:
        return INVESTIGATE, "unknown", "Component present but version unknown"
    if hit:
        return CONFIRMED, v, f"Version {v} is inside the affected range"
    return NOT_AFF, v, f"Version {v} is outside the affected range"


# ---------------------------------------------------------------------------
# Stage 1: risk matrix (4.4.1)
# ---------------------------------------------------------------------------
def band_for_score(score):
    if score >= 20:
        return "P1"
    if score >= 12:
        return "P2"
    if score >= 6:
        return "P3"
    return "P4"


def rate_exposure(S, asset_id, adv, category):
    a = S["assets"][asset_id]
    reasons = []
    if a.get("classification") not in CLASS_IMPACT or a.get("internet_facing") is None:
        return {"likelihood": None, "impact": None, "score": None, "priority": "Unassessed", "floor": None,
                "reasons": ["Classification or exposure missing, so the exposure is Unassessed (handled on the P1 clock)"]}
    impact = max(CLASS_IMPACT[a["classification"]], a.get("service_impact", 1))
    reasons.append(f"Impact {impact}: {a['classification']} data"
                   + (f", service importance {a.get('service_impact')}" if a.get("service_impact", 1) > CLASS_IMPACT[a["classification"]] else ""))
    if a.get("restricted"):
        likelihood = 1
        reasons.append("Likelihood 1: service restricted, validated isolation leaves no attack path")
    elif a["internet_facing"]:
        if adv["exploited_in_wild"]:
            likelihood, why = 5, "exploitation observed in the wild and the service is internet-facing"
        elif adv["public_exploit"]:
            likelihood, why = 4, "usable public exploit and an internet-facing attack path"
        else:
            likelihood, why = 3, "internet-facing path but limited exploitation evidence"
        reasons.append(f"Likelihood {likelihood}: {why}")
    else:
        if adv["exploited_in_wild"] or adv["public_exploit"]:
            likelihood, why = 3, "internal service; plausible path through lateral movement"
        else:
            likelihood, why = 2, "internal service; exploitation needs several tested restrictions overcome"
        reasons.append(f"Likelihood {likelihood}: {why}")
    score = likelihood * impact
    priority = band_for_score(score)
    floor = None
    if adv["exploited_in_wild"] and priority != "P1":
        floor = "Known exploitation: raised to at least P1"
    elif adv["cvss"] >= 9 and a["internet_facing"] and category == CONFIRMED and priority != "P1":
        floor = "Critical vulnerability on an internet-facing service: raised to at least P1"
    if floor and not a.get("restricted"):
        priority = "P1"
        reasons.append(floor)
    if category in (INVESTIGATE, POTENTIAL):
        reasons.append(f"{category}: rated as if affected, because unknown is never safe")
    return {"likelihood": likelihood, "impact": impact, "score": score, "priority": priority,
            "floor": floor, "reasons": reasons}


# ---------------------------------------------------------------------------
# Allocator (4.3.1)
# ---------------------------------------------------------------------------
def _build_ladder(priority, alerted_at):
    unit, afters = LADDER_AFTER[priority]
    rungs = []
    for i, ((cond, to, req), after) in enumerate(zip(_RUNG_SPEC, afters)):
        rungs.append({"level": i + 1, "after": after, "unit": unit, "at": _offset(alerted_at, unit, after),
                      "condition": cond, "to_roles": to, "required": req, "status": "Pending",
                      "anchor": 2 if cond == "no_exec_decision" else None})
    return rungs


def _create_task(S, kind, asset_id, adv_id, category, rating, alerted_at, note):
    a = S["assets"][asset_id] if asset_id in S["assets"] else None
    tid = _next_id(S, "task", "T")
    priority = rating["priority"] if rating else "P2"
    t = {
        "id": tid, "kind": kind, "asset_id": asset_id, "advisory": adv_id, "category": category,
        "owner": a["owner"] if a else S["directory"]["cio_delegate"],
        "deputy": a["deputy"] if a else None,
        "priority": priority, "rating": rating, "alerted_at": alerted_at,
        "due_at": due_for(priority, alerted_at) if kind != "Ownership defect" else alerted_at + timedelta(hours=72),
        "state": ASSIGNED, "acknowledged_at": None, "acknowledged_by": None,
        "decisions": [], "submissions": [], "exception": None, "escalations": [],
        "ladder": _build_ladder(priority, alerted_at) if kind != "Ownership defect" else [],
        "closed_at": None, "verified_by": None, "note": note,
    }
    S["tasks"][tid] = t
    who = name(S, t["owner"]) + (f" and deputy {name(S, t['deputy'])}" if t["deputy"] else "")
    log(S, "system", "Task assigned", tid, f"{kind} for {asset_id}: {priority}, due {t['due_at']:%d %b %H:%M}. Sent to {who}.", "System")
    if priority in ("P1", "P2", "Unassessed") and is_out_of_hours(S["now"]) and kind != "Ownership defect":
        log(S, "system", "On-call paged", tid, "Outside business hours: 24-hour SOC paged the on-call engineer and duty manager.", "System")
    return t


def ingest_advisory(S, actor, adv_id):
    if adv_id in S["ingested"]:
        _block(S, actor, "Ingest advisory", adv_id, "This advisory has already been ingested and triaged.")
    S["ingested"][adv_id] = {"at": S["now"], "by": actor}
    log(S, actor, "Ingest advisory", adv_id, S["advisories"][adv_id]["title"])
    for asset_id in S["assets"]:
        _triage_one(S, adv_id, asset_id, S["now"])
    process_due(S)


def _triage_one(S, adv_id, asset_id, alerted_at):
    adv = S["advisories"][adv_id]
    category, found, why = classify(S, asset_id, adv)
    row = {"advisory": adv_id, "asset_id": asset_id, "category": category, "version_found": found,
           "why": why, "task": None, "at": S["now"]}
    if category in (CONFIRMED, INVESTIGATE, POTENTIAL):
        rating = rate_exposure(S, asset_id, adv, category)
        kind = {"Confirmed affected": "Remediation", "Requires investigation": "Investigation"}.get(category, "Potentially affected")
        t = _create_task(S, kind, asset_id, adv_id, category, rating, alerted_at, why)
        row["task"] = t["id"]
    S["triage"].append(row)


def coverage_indicators(S):
    internet = [a for a, d in S["assets"].items() if d.get("internet_facing")]
    current = [a for a in internet if inventory_age_days(S, a) is not None and inventory_age_days(S, a) <= STALE_DAYS]
    unregistered = [d for d in S["discovery"] if d["asset_id"] is None]
    triaged = []
    for adv in S["ingested"]:
        open_unknown = [t for t in S["tasks"].values() if t["advisory"] == adv and t["state"] not in CLOSED
                        and t["category"] in (INVESTIGATE, POTENTIAL)]
        triaged.append(not open_unknown)
    return {
        "internet_current": (len(current), len(internet)),
        "unregistered": len(unregistered),
        "advisories_triaged": (sum(triaged), len(triaged)),
    }


def run_reconciliation(S, actor="system"):
    S["last_recon"] = S["now"]
    found = 0
    for d in S["discovery"]:
        if d["asset_id"] is None and not any(t["kind"] == "Ownership defect" and t["asset_id"] == d["host"] for t in S["tasks"].values()):
            found += 1
            tid = _next_id(S, "task", "T")
            S["tasks"][tid] = {
                "id": tid, "kind": "Ownership defect", "asset_id": d["host"], "advisory": None, "category": "Unregistered asset",
                "owner": S["directory"]["cio_delegate"], "deputy": None, "priority": "P2", "rating": None,
                "alerted_at": S["now"], "due_at": S["now"] + timedelta(hours=72 if d["internet_facing"] else 168),
                "state": ASSIGNED, "acknowledged_at": None, "acknowledged_by": None, "decisions": [], "submissions": [],
                "exception": None, "escalations": [], "ladder": [], "closed_at": None, "verified_by": None,
                "note": f"Found by {d['source'].lower()} but absent from the asset register. {d.get('fingerprint', '')}",
            }
            log(S, "system", "Ownership defect", tid, f"Unregistered host {d['host']} assigned to {name(S, S['directory']['cio_delegate'])} for registration.", "System")
    log(S, actor, "Inventory reconciliation", "", f"Register and inventories compared with discovery and deployment records. {found} new unregistered asset(s).", "System" if actor == "system" else "Done")


def register_asset(S, actor, host, asset_id, asset_name, owner, deputy, classification, internet_facing, components):
    if role(S, actor) != "CIO delegate":
        _block(S, actor, "Register asset", host, "Only the CIO's delegate can register assets and assign owners.")
    if owner == deputy:
        _block(S, actor, "Register asset", host, "Owner and deputy must be different people.")
    if asset_id in S["assets"]:
        _block(S, actor, "Register asset", host, f"Asset ID {asset_id} already exists.")
    S["assets"][asset_id] = {"name": asset_name, "owner": owner, "deputy": deputy, "line_manager": "marcus",
                             "risk_owner": S["directory"]["exec"], "legal_entity": "Equifax Inc. (US)",
                             "classification": classification, "service_impact": 1, "internet_facing": internet_facing,
                             "inventory_at": S["now"], "host": host, "restricted": False}
    for comp, ver in components:
        S["inventory"].append({"asset_id": asset_id, "component": comp, "version": ver or None})
    for d in S["discovery"]:
        if d["host"] == host:
            d["asset_id"] = asset_id
    for t in S["tasks"].values():
        if t["kind"] == "Ownership defect" and t["asset_id"] == host and t["state"] not in CLOSED:
            t["state"], t["closed_at"], t["verified_by"] = VERIFIED, S["now"], actor
    log(S, actor, "Register asset", asset_id, f"{host} registered as {asset_name}; owner {name(S, owner)}, deputy {name(S, deputy)}.")
    # Re-run every ingested advisory against the new asset, keeping the original alert time.
    for adv_id, info in S["ingested"].items():
        _triage_one(S, adv_id, asset_id, info["at"])
    process_due(S)


def refresh_inventory(S, actor, asset_id, component, version):
    a = S["assets"][asset_id]
    if actor not in (a["owner"], a["deputy"]) and role(S, actor) != "CIO delegate":
        _block(S, actor, "Refresh inventory", asset_id, "Only the asset owner, deputy or CIO's delegate can refresh the inventory.")
    rows = [r for r in S["inventory"] if r["asset_id"] == asset_id and r["component"] == component]
    if rows:
        rows[0]["version"] = version or None
    else:
        S["inventory"].append({"asset_id": asset_id, "component": component, "version": version or None})
    a["inventory_at"] = S["now"]
    log(S, actor, "Refresh inventory", asset_id, f"{component} recorded as {version or 'unknown'}; inventory now current.")
    # Reclassify open potentially-affected tasks. The deadline does not restart.
    for t in S["tasks"].values():
        if t["asset_id"] == asset_id and t["state"] not in CLOSED and t["category"] in (POTENTIAL, INVESTIGATE):
            adv = S["advisories"][t["advisory"]]
            cat, found, why = classify(S, asset_id, adv)
            if cat == CONFIRMED:
                t["category"], t["kind"] = CONFIRMED, "Remediation"
                log(S, "system", "Reclassified", t["id"], f"Now confirmed affected ({found}). Deadline unchanged: {t['due_at']:%d %b %H:%M}.", "System")
            elif cat in (NOT_AFF, ABSENT):
                t["category"], t["kind"] = INVESTIGATE, "Investigation"
                log(S, "system", "Reclassified", t["id"], f"Refreshed inventory shows {found}. Needs reviewer confirmation before closing as not affected.", "System")
            elif cat == INVESTIGATE:
                t["category"], t["kind"] = INVESTIGATE, "Investigation"
                log(S, "system", "Reclassified", t["id"], "Version still unknown; investigation required.", "System")


# ---------------------------------------------------------------------------
# Tracker actions (4.3.2)
# ---------------------------------------------------------------------------
def _task(S, tid):
    return S["tasks"][tid]


def escalation_holders(S, t):
    holders = set()
    for e in t["escalations"]:
        holders.update(e["to"])
    return holders


def acknowledge(S, actor, tid):
    t = _task(S, tid)
    allowed = {t["owner"], t["deputy"]} | escalation_holders(S, t)
    if actor not in allowed:
        _block(S, actor, "Acknowledge", tid, "Only the named owner, deputy or an escalation recipient can acknowledge this task.")
    if t["state"] != ASSIGNED:
        _block(S, actor, "Acknowledge", tid, f"Task is already {t['state'].lower()}.")
    t["state"], t["acknowledged_at"], t["acknowledged_by"] = ACKED, S["now"], actor
    log(S, actor, "Acknowledge", tid, f"Owner confirmed as {name(S, t['owner'])}.")


def _valid_decision(t, now):
    for d in t["decisions"]:
        if d["status"] == "Evidenced" or (d["status"] == "Pending evidence" and d["due_at"] >= now):
            return True
    if t["kind"] in ("Investigation", "Potentially affected") and t["submissions"]:
        return True
    return False


def record_decision(S, actor, tid, option, rationale):
    t = _task(S, tid)
    allowed = {t["owner"], t["deputy"]} | escalation_holders(S, t) | {S["directory"]["ceo"], S["directory"]["incident_commander"]}
    if actor not in allowed:
        _block(S, actor, "Record treatment decision", tid, "Only the owner, deputy or someone this task was escalated to can record a decision.")
    if t["state"] in CLOSED:
        _block(S, actor, "Record treatment decision", tid, "Task is already closed.")
    if option not in TREATMENTS:
        _block(S, actor, "Record treatment decision", tid, "Choose one of the four treatment options.")
    if option == "Restrict service" and actor == S["directory"]["incident_commander"]:
        holders = escalation_holders(S, t)
        if actor not in holders:
            _block(S, actor, "Record treatment decision", tid, "The incident commander's restriction authority applies once the 56-hour escalation has fired.")
    if not rationale.strip():
        _block(S, actor, "Record treatment decision", tid, "A rationale is required for every treatment decision.")
    if option == "Time-limited exception":
        _block(S, actor, "Record treatment decision", tid, "Use 'Request exception' so the mitigation goes through security review and executive approval.")
    due = {"Remediate": max(t["due_at"], S["now"] + timedelta(hours=4)),
           "Temporary protection": S["now"] + timedelta(hours=24),
           "Restrict service": S["now"] + timedelta(hours=4)}[option]
    t["decisions"].append({"option": option, "by": actor, "at": S["now"], "due_at": due, "rationale": rationale,
                           "status": "Pending evidence", "evidenced_at": None})
    if t["state"] in (ASSIGNED, ACKED):
        if t["state"] == ASSIGNED:
            t["acknowledged_at"], t["acknowledged_by"] = S["now"], actor
        t["state"] = TREATING
    log(S, actor, "Record treatment decision", tid, f"{option}, evidence due {due:%d %b %H:%M}. {rationale}")


def evidence_checks(S, t, sub):
    adv = S["advisories"][t["advisory"]]
    checks = []
    if sub["type"] == "remediation":
        hit = in_affected_range(sub["version"], adv["affected"])
        checks.append(("Running version outside the affected range", hit is False,
                       f"Running version {sub['version'] or 'not provided'}" + (" is still affected" if hit else "")))
    else:
        hit = in_affected_range(sub["version"], adv["affected"])
        checks.append(("Observed version is known and outside the affected range", hit is False,
                       f"Observed version {sub['version'] or 'not provided'} from {sub.get('source', 'unspecified source')}"))
    checks.append(("Scan was authenticated", bool(sub["authenticated"]),
                   "Authenticated scan" if sub["authenticated"] else "Unauthenticated scans cannot see installed component versions"))
    in_scope = t["asset_id"] in sub["scope"]
    checks.append(("Scan scope includes the affected application", in_scope,
                   "Scope: " + (", ".join(sub["scope"]) if sub["scope"] else "empty")
                   + ("" if in_scope else f". {t['asset_id']} was not scanned")))
    comp_ok = adv["component"] in sub["components"]
    checks.append(("Scan covered the affected component", comp_ok,
                   "Components checked: " + (", ".join(sub["components"]) if sub["components"] else "none")))
    if sub["type"] == "remediation":
        after = sub["scan_at"] is not None and sub["deployed_at"] is not None and sub["scan_at"] > sub["deployed_at"]
        checks.append(("Scan performed after deployment", after,
                       f"Deployed {sub['deployed_at']:%d %b %H:%M}, scanned {sub['scan_at']:%d %b %H:%M}" if sub["scan_at"] and sub["deployed_at"] else "Timestamps missing"))
    return checks


def submit_evidence(S, actor, tid, sub_type, version, authenticated, scope, components, scan_at, deployed_at=None, source="", notes=""):
    t = _task(S, tid)
    if actor not in (t["owner"], t["deputy"]):
        _block(S, actor, "Submit evidence", tid, "Only the named owner or deputy can submit closure evidence.")
    if t["state"] in CLOSED or t["state"] == AWAITING:
        _block(S, actor, "Submit evidence", tid, f"Task is {t['state'].lower()}.")
    if sub_type == "remediation" and t["state"] != TREATING:
        _block(S, actor, "Submit evidence", tid, "Record a treatment decision before submitting remediation evidence.")
    if sub_type == "not_affected" and t["kind"] == "Remediation":
        _block(S, actor, "Submit evidence", tid, "This asset is confirmed affected; it cannot be closed as not affected.")
    sub = {"id": _next_id(S, "sub", "E"), "type": sub_type, "by": actor, "at": S["now"], "version": version,
           "authenticated": authenticated, "scope": list(scope), "components": list(components),
           "scan_at": scan_at, "deployed_at": deployed_at, "source": source, "notes": notes,
           "status": None, "review": None}
    sub["checks"] = evidence_checks(S, t, sub)
    failed = [c for c in sub["checks"] if not c[1]]
    t["submissions"].append(sub)
    if failed:
        sub["status"] = "Rejected by system"
        reasons = "; ".join(f"{c[0]} failed ({c[2]})" for c in failed)
        if t["asset_id"] in S["evidence"] and t["asset_id"] not in sub["scope"]:
            S["evidence"][t["asset_id"]]["coverage"] = {"status": "Failed", "ref": f"{sub['id']}: submitted scan excluded {t['asset_id']}",
                                                       "tested_at": S["now"], "max_age_days": 30}
        log(S, actor, "Submit evidence", tid, f"{sub['id']} rejected automatically: {reasons}", "Blocked")
        return sub
    sub["status"] = "Pending review"
    t["state"] = AWAITING
    log(S, actor, "Submit evidence", tid, f"{sub['id']} passed automated checks; awaiting independent verification.")
    return sub


def trained(S, pid, module_id):
    rec = S["training"].get(pid, {}).get(module_id)
    return bool(rec and rec["passed"] and rec["version"] == S["module_versions"][module_id])


def verify(S, actor, tid, approve=True, reason=""):
    t = _task(S, tid)
    action = "Approve closure" if approve else "Reject submission"
    if t["state"] != AWAITING:
        _block(S, actor, action, tid, "There is no submission awaiting verification.")
    sub = t["submissions"][-1]
    if actor in (sub["by"], t["owner"], t["deputy"]):
        _block(S, actor, action, tid, "Segregation of duties: the person who remediated or owns the asset cannot verify it.")
    if role(S, actor) != "Security reviewer":
        _block(S, actor, action, tid, f"{name(S, actor)} is not a security reviewer. Only the second line verifies closures.")
    if not trained(S, actor, GATES["verify"]):
        _block(S, actor, action, tid, f"{name(S, actor)} has not passed the current version of {GATES['verify']}. Complete it in the Learning centre to gain verification rights.")
    if not approve:
        if not reason.strip():
            _block(S, actor, action, tid, "Give the owner a reason for the rejection.")
        sub["status"], sub["review"] = "Rejected by reviewer", {"by": actor, "at": S["now"], "reason": reason}
        t["state"] = TREATING
        log(S, actor, action, tid, f"{sub['id']} returned to owner: {reason}")
        return
    sub["checks"] = evidence_checks(S, t, sub)
    failed = [c for c in sub["checks"] if not c[1]]
    if failed:
        _block(S, actor, action, tid, "Evidence fails: " + "; ".join(c[0] for c in failed))
    sub["status"], sub["review"] = "Verified", {"by": actor, "at": S["now"], "reason": reason}
    t["state"] = VERIFIED if sub["type"] == "remediation" else NOT_AFFECTED
    t["closed_at"], t["verified_by"] = S["now"], actor
    for d in t["decisions"]:
        if d["status"] == "Pending evidence" and d["option"] == "Remediate":
            d["status"], d["evidenced_at"] = "Evidenced", S["now"]
    if t["exception"] and t["exception"]["status"] == "Approved":
        t["exception"]["status"] = "Closed (exposure fixed)"
    if t["asset_id"] in S["evidence"]:
        S["evidence"][t["asset_id"]]["coverage"] = {"status": "Passed", "ref": f"{sub['id']}: authenticated scan of {t['asset_id']} covering {', '.join(sub['components'])}",
                                                   "tested_at": sub["scan_at"], "max_age_days": 30}
    log(S, actor, action, tid, f"{sub['id']} verified by an independent, trained reviewer. Task {t['state'].lower()}.")


def evidence_decision(S, actor, tid):
    """Evidence a temporary protection (security reviewer) or a restriction (owner or incident commander)."""
    t = _task(S, tid)
    pending = [d for d in t["decisions"] if d["status"] == "Pending evidence" and d["option"] in ("Temporary protection", "Restrict service")]
    if not pending:
        _block(S, actor, "Evidence decision", tid, "No temporary protection or restriction is awaiting evidence.")
    d = pending[-1]
    if d["option"] == "Temporary protection":
        if role(S, actor) != "Security reviewer" or actor == d["by"]:
            _block(S, actor, "Evidence decision", tid, "An independent security reviewer must confirm the temporary protection was tested.")
        detail = "Temporary protection tested and confirmed in place."
    else:
        if actor not in (t["owner"], t["deputy"], S["directory"]["incident_commander"]):
            _block(S, actor, "Evidence decision", tid, "Only the owner, deputy or incident commander can confirm the service is restricted.")
        S["assets"][t["asset_id"]]["restricted"] = True
        t["rating"] = rate_exposure(S, t["asset_id"], S["advisories"][t["advisory"]], t["category"])
        detail = "Service restricted; external access withdrawn. Exposure stays open until the fix is verified."
    d["status"], d["evidenced_at"] = "Evidenced", S["now"]
    log(S, actor, "Evidence decision", tid, detail)


# ---------------------------------------------------------------------------
# Exceptions (4.3.2)
# ---------------------------------------------------------------------------
def request_exception(S, actor, tid, mitigation, days, rationale):
    t = _task(S, tid)
    if actor not in ({t["owner"], t["deputy"]} | escalation_holders(S, t)):
        _block(S, actor, "Request exception", tid, "Only the owner, deputy or an escalation recipient can request an exception.")
    if t["state"] in CLOSED:
        _block(S, actor, "Request exception", tid, "Task is already closed.")
    if t["exception"] and t["exception"]["status"] in ("Pending security review", "Pending executive approval", "Approved"):
        _block(S, actor, "Request exception", tid, "An exception is already pending or active on this task.")
    limit = 7 if t["priority"] in ("P1", "Unassessed") else 30
    if days > limit:
        _block(S, actor, "Request exception", tid, f"{t['priority']} exceptions are limited to {limit} days.")
    if not mitigation.strip() or not rationale.strip():
        _block(S, actor, "Request exception", tid, "Describe the mitigation and the reason for the exception.")
    t["exception"] = {"id": _next_id(S, "exc", "X"), "requested_by": actor, "requested_at": S["now"], "mitigation": mitigation,
                      "days": days, "rationale": rationale, "status": "Pending security review",
                      "security_review": None, "approved_by": None, "approved_at": None, "expires_at": None}
    t["decisions"].append({"option": "Time-limited exception", "by": actor, "at": S["now"], "due_at": S["now"] + timedelta(hours=24),
                           "rationale": rationale, "status": "Pending evidence", "evidenced_at": None})
    if t["state"] in (ASSIGNED, ACKED):
        t["state"] = TREATING
    log(S, actor, "Request exception", tid, f"{t['exception']['id']}: {days} days with mitigation '{mitigation}'. Approval due within 24 hours.")


def review_exception(S, actor, tid, tested, note):
    t = _task(S, tid)
    x = t["exception"]
    if not x or x["status"] != "Pending security review":
        _block(S, actor, "Review exception mitigation", tid, "No exception is waiting for security review.")
    if role(S, actor) != "Security reviewer":
        _block(S, actor, "Review exception mitigation", tid, "Only a security reviewer can assess the mitigation.")
    if actor == x["requested_by"]:
        _block(S, actor, "Review exception mitigation", tid, "The requester cannot review their own mitigation.")
    if not trained(S, actor, GATES["exception_review"]):
        _block(S, actor, "Review exception mitigation", tid, f"{name(S, actor)} has not passed the current version of {GATES['exception_review']}.")
    x["security_review"] = {"by": actor, "at": S["now"], "tested": tested, "note": note}
    if tested:
        x["status"] = "Pending executive approval"
        log(S, actor, "Review exception mitigation", tid, f"Mitigation tested and effective. {note}")
    else:
        x["status"] = "Returned: mitigation untested"
        for d in t["decisions"]:
            if d["option"] == "Time-limited exception" and d["status"] == "Pending evidence":
                d["status"] = "Lapsed"
        log(S, actor, "Review exception mitigation", tid, f"Mitigation not shown to work; request returned. {note}")


def approve_exception(S, actor, tid, approve=True, note=""):
    t = _task(S, tid)
    x = t["exception"]
    action = "Approve exception" if approve else "Decline exception"
    if not x or x["status"] != "Pending executive approval":
        _block(S, actor, action, tid, "Security must review the mitigation before an executive can decide.")
    if actor == x["requested_by"]:
        _block(S, actor, action, tid, "The approver can never be the requester.")
    if role(S, actor) not in ("Executive risk owner", "CEO"):
        _block(S, actor, action, tid, f"{name(S, actor)} is not an authorised business executive. Only executives accept risk.")
    if not trained(S, actor, GATES["exception_approve"]):
        _block(S, actor, action, tid, f"{name(S, actor)} has not passed the current version of {GATES['exception_approve']}.")
    for d in t["decisions"]:
        if d["option"] == "Time-limited exception" and d["status"] == "Pending evidence":
            d["status"], d["evidenced_at"] = ("Evidenced", S["now"]) if approve else ("Lapsed", None)
    if not approve:
        x["status"] = "Declined"
        log(S, actor, action, tid, note or "Exception declined.")
        return
    x["status"], x["approved_by"], x["approved_at"] = "Approved", actor, S["now"]
    x["expires_at"] = S["now"] + timedelta(days=x["days"])
    log(S, actor, action, tid, f"Approved until {x['expires_at']:%d %b %H:%M}. The exposure stays open and the estimate is unchanged. {note}")


def exception_active(t, now):
    x = t["exception"]
    return bool(x and x["status"] == "Approved" and x["expires_at"] > now)


# ---------------------------------------------------------------------------
# Downward priority overrides (4.4.1)
# ---------------------------------------------------------------------------
def request_override(S, actor, tid, new_priority, reason):
    t = _task(S, tid)
    if actor not in (t["owner"], t["deputy"]) and role(S, actor) not in ("Security reviewer", "CIO delegate"):
        _block(S, actor, "Request priority override", tid, "Only the owner, deputy, a security reviewer or the CIO's delegate can propose an override.")
    if PRIORITY_ORDER.get(new_priority, 0) <= PRIORITY_ORDER.get(t["priority"], 0):
        _block(S, actor, "Request priority override", tid, "Overrides here are for lowering priority; raising it needs no approval.")
    if not reason.strip():
        _block(S, actor, "Request priority override", tid, "Explain why the matrix overstates this exposure.")
    oid = _next_id(S, "ovr", "O")
    S["overrides"].append({"id": oid, "task": tid, "from": t["priority"], "to": new_priority, "by": actor,
                           "at": S["now"], "reason": reason, "status": "Pending CISO approval", "decided_by": None})
    log(S, actor, "Request priority override", tid, f"{oid}: {t['priority']} to {new_priority}. {reason}")


def decide_override(S, actor, oid, approve):
    o = next(o for o in S["overrides"] if o["id"] == oid)
    action = "Approve override" if approve else "Decline override"
    if o["status"] != "Pending CISO approval":
        _block(S, actor, action, oid, "This override has already been decided.")
    if role(S, actor) != "CISO":
        _block(S, actor, action, oid, "Downward overrides need separate approval by the CISO.")
    if actor == o["by"]:
        _block(S, actor, action, oid, "The requester cannot approve their own override.")
    o["status"], o["decided_by"] = ("Approved" if approve else "Declined"), actor
    if approve:
        t = _task(S, o["task"])
        t["priority"] = o["to"]
        t["due_at"] = due_for(o["to"], t["alerted_at"])
        old = {r["level"]: r["status"] for r in t["ladder"]}
        t["ladder"] = _build_ladder(o["to"], t["alerted_at"])
        for r in t["ladder"]:
            if old.get(r["level"]) in ("Fired", "Skipped"):
                r["status"] = old[r["level"]]
        t["rating"]["override"] = f"{o['from']} lowered to {o['to']} by {name(S, actor)}: {o['reason']}"
    log(S, actor, action, o["task"], f"{oid} {o['status'].lower()}.")


# ---------------------------------------------------------------------------
# Monitoring control health
# ---------------------------------------------------------------------------
def control_health(S, cid):
    c = S["controls"][cid]
    now = S["now"]
    reasons = []
    if not c["heartbeat_ok"]:
        return "Failed", ["No heartbeat: the device is not reporting"]
    if c["cert_expires"] and c["cert_expires"] <= now:
        gap = now - c["cert_expires"]
        ago = f"{gap.days} days ago" if gap.days else f"{int(gap.total_seconds() // 3600)} hours ago"
        return "Failed", [f"Certificate expired {c['cert_expires']:%d %b %Y %H:%M} ({ago}). Encrypted traffic is not being inspected"]
    if c["awaiting_test"]:
        return "Awaiting test", ["Restored but not yet tested; detection is unproven"]
    if c["last_test"] is None or (now - c["last_test"]).days > c["test_max_age_days"]:
        return "Test overdue", [f"Inspection test older than {c['test_max_age_days']} days"]
    if c["cert_expires"] and (c["cert_expires"] - now).days < 30:
        reasons.append(f"Certificate expires {c['cert_expires']:%d %b %H:%M}")
        return "Warning", reasons
    return "Healthy", ["Heartbeat current, certificate valid, inspection test passed"]


def renew_certificate(S, actor, cid, days_valid=365):
    if role(S, actor) not in ("Security operations", "CISO"):
        _block(S, actor, "Renew certificate", cid, "Security operations renews inspection certificates.")
    c = S["controls"][cid]
    c["cert_expires"] = S["now"] + timedelta(days=days_valid)
    c["awaiting_test"] = True
    c["notified"] = set()
    log(S, actor, "Renew certificate", cid, f"New certificate valid to {c['cert_expires']:%d %b %Y}. Control stays flagged until an inspection test passes.")


def run_inspection_test(S, actor, cid):
    if role(S, actor) not in ("Security operations", "Security reviewer", "CISO"):
        _block(S, actor, "Run inspection test", cid, "Security operations or a security reviewer runs inspection tests.")
    c = S["controls"][cid]
    if not c["heartbeat_ok"] or (c["cert_expires"] and c["cert_expires"] <= S["now"]):
        log(S, actor, "Run inspection test", cid, "Test failed: test traffic was not inspected.", "Blocked")
        raise ControlBlocked("Inspection test failed: the device cannot inspect traffic until the certificate and heartbeat are restored.")
    c["last_test"], c["awaiting_test"] = S["now"], False
    log(S, actor, "Run inspection test", cid, "Test traffic seeded and detected. Control healthy.")


def simulate_heartbeat_loss(S, actor, cid):
    S["controls"][cid]["heartbeat_ok"] = False
    log(S, "system", "Monitoring alert", cid, "Heartbeat lost. Immediate alert to SOC and CISO.", "System")


def restore_heartbeat(S, actor, cid):
    S["controls"][cid]["heartbeat_ok"] = True
    S["controls"][cid]["awaiting_test"] = True
    log(S, actor, "Restore heartbeat", cid, "Device reporting again; awaiting inspection test.")


# ---------------------------------------------------------------------------
# Stage 2: quantitative estimate (4.4.2)
# ---------------------------------------------------------------------------
def _effective(ev, now):
    if ev["status"] == "Passed" and ev.get("tested_at") and (now - ev["tested_at"]).days > ev["max_age_days"]:
        return "Stale", ev["ref"] + f" (older than {ev['max_age_days']} days)"
    return ev["status"], ev["ref"]


def factor_status(S, asset_id):
    now = S["now"]
    out = {}
    open_exp = [t for t in S["tasks"].values() if t["asset_id"] == asset_id and t["state"] not in CLOSED and t["kind"] != "Ownership defect"]
    closed = [t for t in S["tasks"].values() if t["asset_id"] == asset_id and t["state"] in CLOSED and t["kind"] != "Ownership defect"]
    if open_exp:
        out["patch"] = ("Failed", "Open exposure not verified: " + ", ".join(f"{t['id']} ({t['advisory']})" for t in open_exp))
    elif closed:
        last = max(closed, key=lambda t: t["closed_at"])
        out["patch"] = ("Passed", f"{last['id']} verified closed by {name(S, last['verified_by'])} on {last['closed_at']:%d %b %H:%M}")
    else:
        out["patch"] = _effective(S["evidence"][asset_id]["patch"], now)
    for k in ("coverage", "priv", "network"):
        out[k] = _effective(S["evidence"][asset_id][k], now)
    covering = [cid for cid, c in S["controls"].items() if asset_id in c["covers"] and c["type"] == "Encrypted traffic inspection"]
    if not covering:
        out["detection"] = ("Unknown", "No traffic inspection control covers this asset")
    else:
        states = {cid: control_health(S, cid)[0] for cid in covering}
        if any(s == "Failed" for s in states.values()):
            bad = [cid for cid, s in states.items() if s == "Failed"]
            out["detection"] = ("Failed", f"{', '.join(bad)} failed: {control_health(S, bad[0])[1][0]}")
        elif any(s in ("Awaiting test", "Test overdue") for s in states.values()):
            out["detection"] = ("Unknown", "Inspection control restored but not yet tested")
        else:
            out["detection"] = ("Passed", f"{', '.join(covering)} healthy; inspection test current")
    return out


def band_from_evidence(f):
    p = {k: f[k][0] == "Passed" for k in FACTORS}
    if all(p.values()):
        return "Nearly complete", 0.95, "All five factors passed"
    if p["patch"] and p["coverage"] and p["detection"] and (p["priv"] or p["network"]):
        return "Significant", 0.75, "Patch verified, coverage and detection passed, plus privileged access or network restriction"
    if p["patch"] and p["coverage"]:
        return "Moderate", 0.50, "Patch verified and coverage passed, but detection or containment evidence is missing"
    return "Minor", 0.25, "Patch verification or scan coverage has not passed"


def compute_estimate(S, asset_id):
    A = S["assumptions"].get(asset_id)
    f = factor_status(S, asset_id)
    band, ce, why = band_from_evidence(f)
    base = {"asset_id": asset_id, "run_at": S["now"], "factors": f, "band": band, "ce": ce, "band_reason": why,
            "model_version": MODEL_VERSION, "rubric_version": RUBRIC_VERSION, "inputs": dict(A or {})}
    if not A or any(A.get(k) is None for k in ("av", "ef", "aro")):
        base.update({"status": "Assessment incomplete", "eal": None, "low": None, "high": None, "utilisation": None})
        return base
    eal = A["av"] * A["ef"] * A["aro"] * (1 - ce)
    low = A["av"] * max(A["ef"] - 0.10, 0.05) * A["aro"] * 0.5 * (1 - ce)
    high = A["av"] * min(A["ef"] + 0.10, 1.0) * A["aro"] * 2.0 * (1 - ce)
    base.update({"status": "OK", "eal": eal, "low": low, "high": high,
                 "utilisation": eal / A["tolerance"] if A.get("tolerance") else None})
    return base


def run_daily_job(S, actor="system"):
    S["last_job_run"] = S["now"]
    changed = []
    for asset_id in S["assumptions"]:
        if asset_id not in S["assets"]:
            continue
        prev = published_estimate(S, asset_id)
        est = compute_estimate(S, asset_id)
        S["estimates"].append(est)
        if prev and prev["eal"] != est["eal"]:
            changed.append(f"{asset_id} {money(prev['eal'])} to {money(est['eal'])}")
    detail = "Recalculated all scenarios." + (" Changed: " + "; ".join(changed) if changed else " No evidence changes moved an estimate.")
    log(S, actor, "Daily risk recalculation", "", detail, "System" if actor == "system" else "Done")


def published_estimate(S, asset_id):
    for e in reversed(S["estimates"]):
        if e["asset_id"] == asset_id:
            return e
    return None


def estimate_history(S, asset_id):
    return [e for e in S["estimates"] if e["asset_id"] == asset_id]


def money(x):
    if x is None:
        return "Assessment incomplete"
    if abs(x) >= 1_000_000:
        return f"US${x / 1_000_000:,.2f}m"
    return f"US${x / 1_000:,.0f}k"


# ---------------------------------------------------------------------------
# The clock: escalations, lapses, expiries, scheduled jobs
# ---------------------------------------------------------------------------
def _rung_condition(S, t, rung):
    now = S["now"]
    if t["state"] in CLOSED:
        return False
    c = rung["condition"]
    if c == "not_acknowledged":
        return t["state"] == ASSIGNED
    if c == "no_decision":
        return not _valid_decision(t, now)
    if c == "not_closed_no_exception":
        return not exception_active(t, now)
    if c == "no_exec_decision":
        anchor = next((r for r in t["ladder"] if r["level"] == 3), None)
        if not anchor or anchor["status"] != "Fired" or exception_active(t, now):
            return False
        since = anchor.get("fired_at", anchor["at"])
        return not any(d["at"] >= since for d in t["decisions"])
    if c == "renewal_follow_up":
        return not any(d["at"] >= rung["since"] for d in t["decisions"]) and not exception_active(t, now)
    if c == "open":
        return True
    return False


def _resolve(S, t, roles):
    a = S["assets"].get(t["asset_id"], {})
    out = []
    for r in roles:
        if r == "line_manager":
            out.append(a.get("line_manager", "marcus"))
        elif r == "deputy":
            if t["deputy"]:
                out.append(t["deputy"])
        elif r == "exec":
            out.append(a.get("risk_owner", S["directory"]["exec"]))
        else:
            out.append(S["directory"][r])
    return out


def _fire(S, t, rung, reason=None):
    to = _resolve(S, t, rung["to_roles"])
    rung["status"], rung["fired_at"] = "Fired", S["now"]
    t["escalations"].append({"level": rung["level"], "at": S["now"], "to": to, "required": rung["required"],
                             "reason": reason or rung["condition"]})
    log(S, "system", "Escalated", t["id"], f"Level {rung['level']} to {', '.join(name(S, p) for p in to)}. Required: {rung['required']}.", "System")


def _scheduled_events(S, until):
    now = S["now"]
    ev = []
    for t in S["tasks"].values():
        if t["state"] in CLOSED:
            continue
        for r in t["ladder"]:
            if r["status"] == "Pending" and r["at"] <= until:
                ev.append((max(r["at"], now), 2, "rung", (t["id"], r)))
        for d in t["decisions"]:
            if d["status"] == "Pending evidence" and d["due_at"] < until:
                ev.append((max(d["due_at"], now), 1, "lapse", (t["id"], d)))
        x = t["exception"]
        if x and x["status"] == "Approved" and x["expires_at"] <= until:
            ev.append((max(x["expires_at"], now), 1, "expiry", t["id"]))
    for cid, c in S["controls"].items():
        if c["cert_expires"]:
            for d in sd.CERT_WARNING_DAYS:
                at = c["cert_expires"] - timedelta(days=d)
                if d not in c["notified"] and at <= until:
                    ev.append((max(at, now), 0, "cert_warning", (cid, d)))
            if "expired" not in c["notified"] and c["cert_expires"] <= until:
                ev.append((max(c["cert_expires"], now), 0, "cert_expired", cid))
    job = _next_daily(S["last_job_run"] or now - timedelta(days=1), DAILY_JOB_HOUR)
    if S["last_job_run"] is None:
        job = _next_daily(now, DAILY_JOB_HOUR) if now.hour >= DAILY_JOB_HOUR else now.replace(hour=DAILY_JOB_HOUR, minute=0)
    if job <= until:
        ev.append((max(job, now), 3, "daily_job", None))
    recon = _next_daily(S["last_recon"] or now - timedelta(days=1), RECON_HOUR)
    if S["last_recon"] is None:
        recon = now.replace(hour=RECON_HOUR, minute=0) if now.hour < RECON_HOUR else _next_daily(now, RECON_HOUR)
    if recon <= until:
        ev.append((max(recon, now), 3, "recon", None))
    for i, (when, fn) in enumerate(S.get("pending_script", [])):
        if when <= until:
            ev.append((max(when, now), 4, "script", i))
    ev.sort(key=lambda e: (e[0], e[1]))
    return ev


def _handle(S, kind, payload):
    if kind == "rung":
        tid, rung = payload
        t = S["tasks"][tid]
        if _rung_condition(S, t, rung):
            _fire(S, t, rung)
        else:
            rung["status"] = "Skipped"
    elif kind == "lapse":
        tid, d = payload
        t = S["tasks"][tid]
        d["status"] = "Lapsed"
        log(S, "system", "Decision lapsed", tid, f"{d['option']} was not evidenced by {d['due_at']:%d %b %H:%M}. Escalation resumed.", "System")
        level = max([e["level"] for e in t["escalations"]] + [1]) + 1
        level = min(max(level, 2), 5)
        spec = _RUNG_SPEC[level - 1]
        _fire(S, t, {"level": level, "to_roles": spec[1], "required": spec[2], "condition": "lapse", "status": "Pending"},
              reason="Decision lapsed")
    elif kind == "expiry":
        t = S["tasks"][payload]
        t["exception"]["status"] = "Expired"
        log(S, "system", "Exception expired", t["id"], "Exception expired with the exposure still open. Renewed escalation.", "System")
        spec = _RUNG_SPEC[2]
        _fire(S, t, {"level": 3, "to_roles": spec[1], "required": spec[2], "condition": "expiry", "status": "Pending"},
              reason="Exception expired")
        for lvl, hrs in ((4, 4), (5, 8)):
            s = _RUNG_SPEC[lvl - 1]
            t["ladder"].append({"level": lvl, "after": None, "unit": "hours", "at": S["now"] + timedelta(hours=hrs),
                                "condition": "renewal_follow_up", "since": S["now"], "to_roles": s[1], "required": s[2],
                                "status": "Pending", "anchor": None})
    elif kind == "cert_warning":
        cid, d = payload
        S["controls"][cid]["notified"].add(d)
        log(S, "system", "Monitoring alert", cid, f"Certificate expires in {d} day{'s' if d > 1 else ''}. Sent to Security operations and the CISO.", "System")
    elif kind == "cert_expired":
        S["controls"][payload]["notified"].add("expired")
        log(S, "system", "Monitoring alert", payload,
            "Certificate expired: encrypted traffic is no longer inspected. Immediate alert to SOC and CISO; control health failed.", "System")
    elif kind == "script":
        # Background owners keep acting on schedule after a preset is loaded.
        _, fn = S["pending_script"].pop(payload)
        try:
            fn(S)
        except Exception:  # the presenter may have changed the story; skip actions that no longer apply
            pass
    elif kind == "daily_job":
        run_daily_job(S)
    elif kind == "recon":
        run_reconciliation(S)


def _step(S, target):
    events = _scheduled_events(S, target)
    if not events:
        return False
    at, _, kind, payload = events[0]
    S["now"] = at
    _handle(S, kind, payload)
    return True


def advance_to(S, target):
    """Move the simulated clock forward, processing every scheduled event in order."""
    if target < S["now"]:
        return
    for _ in range(5000):
        if not _step(S, target):
            break
    S["now"] = target


def advance(S, delta):
    advance_to(S, S["now"] + delta)


def process_due(S):
    advance_to(S, S["now"])


VISIBLE_EVENTS = {"Escalated", "Monitoring alert", "Decision lapsed", "Exception expired"}


def next_interesting_time(S, horizon_days=30):
    """Dry-run the clock on a copy and return when the next escalation or alert would actually fire."""
    C = copy.deepcopy(S)
    end = C["now"] + timedelta(days=horizon_days)
    for _ in range(5000):
        n = len(C["audit"])
        if not _step(C, end):
            return None, None
        new = [a for a in C["audit"][n:] if a["action"] in VISIBLE_EVENTS]
        if new:
            return C["now"], new[0]["action"]
    return None, None


# ---------------------------------------------------------------------------
# Read models for the dashboard and audit views
# ---------------------------------------------------------------------------
def open_exposures(S):
    return [t for t in S["tasks"].values() if t["state"] not in CLOSED and t["kind"] != "Ownership defect"]


def overdue(S):
    return [t for t in S["tasks"].values() if t["state"] not in CLOSED and t["due_at"] < S["now"]]


def unanswered_escalations(S):
    out = []
    for t in S["tasks"].values():
        if t["state"] in CLOSED or not t["escalations"]:
            continue
        last = t["escalations"][-1]
        if not any(d["at"] >= last["at"] for d in t["decisions"]) and not (last["level"] == 1 and t["state"] != ASSIGNED):
            out.append((t, last))
    return out


def failed_controls(S):
    return [cid for cid in S["controls"] if control_health(S, cid)[0] in ("Failed", "Awaiting test", "Test overdue")]


def total_published_eal(S):
    vals = [published_estimate(S, a) for a in S["assumptions"]]
    return sum(v["eal"] for v in vals if v and v["eal"] is not None)


def closure_quality(S):
    closed = [t for t in S["tasks"].values() if t["state"] in CLOSED and t["kind"] != "Ownership defect"]
    within = [t for t in closed if t["closed_at"] <= t["due_at"]]
    late_open = [t for t in open_exposures(S) if t["due_at"] < S["now"]]
    rejected = sum(1 for t in S["tasks"].values() for s in t["submissions"] if s["status"] == "Rejected by system")
    blocked_approvals = sum(1 for a in S["audit"] if a["outcome"] == "Blocked" and a["action"] in ("Approve closure", "Approve exception"))
    denom = len(closed) + len(late_open)
    return {"closed": len(closed), "within_sla": len(within), "late_open": len(late_open),
            "verified_rate": (len(within) / denom) if denom else None,
            "rejected_submissions": rejected, "blocked_approvals": blocked_approvals}


def approvers_trained(S):
    rows = []
    for pid, p in S["people"].items():
        if p["role"] == "Security reviewer":
            rows.append((pid, GATES["verify"], trained(S, pid, GATES["verify"])))
        elif p["role"] in ("Executive risk owner", "CEO"):
            rows.append((pid, GATES["exception_approve"], trained(S, pid, GATES["exception_approve"])))
    return rows


def audit_sample(S, n=5, seed=7):
    pool = []
    for t in S["tasks"].values():
        if t["state"] in CLOSED:
            pool.append(("Closed task", t["id"], t))
        for d in t["decisions"]:
            pool.append(("Treatment decision", t["id"], d))
        if t["exception"]:
            pool.append(("Exception", t["id"], t["exception"]))
    rng = random.Random(seed)
    return rng.sample(pool, min(n, len(pool)))


def record_training(S, pid, module_id, score):
    passed = score == 3
    S["training"].setdefault(pid, {})[module_id] = {"version": S["module_versions"][module_id], "date": S["now"],
                                                    "score": score, "passed": passed}
    log(S, pid, "Training assessment", module_id, f"Scored {score}/3 on version {S['module_versions'][module_id]}: {'passed' if passed else 'not passed'}.")
    return passed


def publish_procedure_change(S, actor, module_id):
    major, minor = S["module_versions"][module_id].split(".")
    S["module_versions"][module_id] = f"{major}.{int(minor) + 1}"
    log(S, actor, "Publish procedure change", module_id, f"Module now version {S['module_versions'][module_id]}. Existing approvers need a refresher.")
