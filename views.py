"""
views.py - Streamlit pages. Each page reads the simulated state, renders it,
and calls engine functions for actions. Pages never decide whether an action
is allowed; they show what the engine decided.
"""
from __future__ import annotations

from datetime import datetime, time, timedelta
from statistics import median

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

import assistant as A
import engine as E
import scenarios as SC
import seed_data as sd

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------
def S():
    return st.session_state.sim


def me():
    return st.session_state.actor


def nm(pid):
    return E.name(S(), pid) if pid else "-"


def ts(t):
    return "-" if t is None else t.strftime("%a %d %b %Y, %H:%M") + " ET"


def short(t):
    return "-" if t is None else t.strftime("%d %b %H:%M")


def dur(delta):
    secs = int(delta.total_seconds())
    sign = "-" if secs < 0 else ""
    secs = abs(secs)
    d, rem = divmod(secs, 86400)
    h, rem = divmod(rem, 3600)
    m = rem // 60
    return f"{sign}{d} d {h} h" if d else f"{sign}{h} h {m:02d} m"


GREEN = {"Verified closed", "Closed (not affected)", "Passed", "Healthy", "Evidenced", "Verified", "Done", "Not affected",
         "Component not present", "Trained", "Yes", "Closed (exposure fixed)"}
RED = {"Failed", "Blocked", "Rejected by system", "Rejected by reviewer", "Lapsed", "Expired", "Overdue", "Confirmed affected",
       "P1", "Not trained", "Fired", "No"}
ORANGE = {"Warning", "Awaiting test", "Test overdue", "Pending evidence", "Pending review", "Awaiting verification", "In treatment",
          "Pending security review", "Pending executive approval", "Approved", "Requires investigation",
          "Potentially affected (stale inventory)", "P2", "Stale", "Refresher due", "Unassessed", "Assessment incomplete",
          "Pending CISO approval"}
BLUE = {"Assigned", "Acknowledged", "P3", "System"}
HEX = {"green": "#1F6B3F", "red": "#9B2117", "orange": "#8A5A00", "blue": "#1F4A8A", "gray": "#4B5563"}


def color_for(status):
    s = str(status)
    if s in GREEN:
        return "green"
    if s in RED:
        return "red"
    if s in ORANGE:
        return "orange"
    if s in BLUE:
        return "blue"
    return "gray"


def esc(text):
    """Escape dollar signs so Streamlit Markdown does not read US$ amounts as LaTeX."""
    return str(text).replace("$", "\\$")


def badge(text, color=None):
    return f":{color or color_for(text)}-badge[{text}]"


def styled(df, cols):
    def cell(v):
        c = color_for(v)
        return f"color: {HEX[c]}; font-weight: 600" if c != "gray" or v in ("Unknown", "Skipped") else ""
    present = [c for c in cols if c in df.columns]
    return df.style.map(cell, subset=present) if present and len(df) else df


def table(df, status_cols=(), height=None, wrap=False):
    """Interactive grid by default; wrap=True renders a static table so long text stays readable."""
    if wrap:
        st.table(styled(df, status_cols), hide_index=True, border="horizontal")
        return
    kw = {"hide_index": True, "width": "stretch"}
    if height:
        kw["height"] = height
    st.dataframe(styled(df, status_cols), **kw)


def show_flash():
    f = st.session_state.pop("flash", None)
    if not f:
        return
    kind, msg = f
    if kind == "blocked":
        st.error(esc(f"Blocked by a control: {msg}"), icon=":material/block:")
    else:
        st.success(esc(msg), icon=":material/check_circle:")


def do(fn, *args, ok="Done.", **kw):
    """Run an engine action as the current persona, then rerun to refresh every panel."""
    try:
        fn(S(), *args, **kw)
        st.session_state.flash = ("ok", ok)
    except E.ControlBlocked as exc:
        st.session_state.flash = ("blocked", str(exc))
    st.rerun()


def notes(page_key):
    if not st.session_state.get("show_notes"):
        return
    spec = SC.BY_KEY[st.session_state.scenario]
    note = spec["notes"].get(page_key)
    if note:
        st.info(esc(note), icon=":material/co_present:")


def acting_line():
    p = S()["people"][me()]
    st.caption(f"Acting as {p['name']}, {p['role']}. Switch persona in the sidebar to act as someone else.")


def task_label(t):
    s = S()
    a = s["assets"].get(t["asset_id"], {}).get("name", t["asset_id"])
    return f"{t['id']}  {a}  ({t['priority']}, {t['state'].lower()})"


def default_task_index(tasks):
    for i, t in enumerate(tasks):
        if t["asset_id"] == "A-ACIS":
            return i
    return 0


def pick_task(label, tasks, key):
    """Select a task by ID (stable across reruns) and return the task dict."""
    s = S()
    labels = {t["id"]: task_label(t) for t in tasks}
    tid = st.selectbox(label, list(labels), index=default_task_index(tasks), key=key, format_func=labels.get)
    return s["tasks"][tid]


def to_dt(d, t):
    return datetime.combine(d, t)


# ---------------------------------------------------------------------------
# Overview
# ---------------------------------------------------------------------------
def page_overview():
    show_flash()
    st.title("Every known vulnerability reaches a named owner, and closes only on evidence")
    st.markdown(
        "A technology prototype for Group 20's Equifax case. It replays March 2017 with synthetic data: "
        "the Apache Struts advisory arrives at 06:10 on 8 March, and you can follow what this design would have done "
        "before attackers reached the dispute portal on 13 May.")
    notes("overview")

    st.subheader("The four 2017 failures and the controls that answer them")
    rows = [
        ("Ownership", "Patch instruction went to an outdated email list; the ACIS owner was not on it.",
         "Advisories are matched to the asset register and assigned to a named owner and deputy. Reconciliation finds hosts missing from the register.",
         "Alert allocator"),
        ("Enforcement", "Missing the 48-hour deadline had no consequence.",
         "Escalation route with recorded treatment decisions, named deputies and pre-approved authority to restrict the service.",
         "Resolution tracker"),
        ("Verification", "A scan missed ACIS and the issue was treated as closed.",
         "Closure needs a fixed running version and an authenticated, in-scope scan after deployment, confirmed by an independent, trained reviewer.",
         "Resolution tracker"),
        ("Detection", "The traffic inspection certificate had expired about 19 months earlier.",
         "Monitoring health is tracked apart from patching. A failed detection control removes risk credit.",
         "Control health, Risk calculator"),
    ]
    table(pd.DataFrame(rows, columns=["Failure", "What happened in 2017", "What the prototype does", "Where to see it"]), wrap=True)

    st.subheader("Demo route")
    st.caption("Pick a step in the sidebar. Each step replays the timeline through the real controls up to that moment; after loading you can keep acting live.")
    table(pd.DataFrame(SC.ROUTE, columns=["Step", "What happens", "Best page", "Suggested persona"]), wrap=True)

    c1, c2 = st.columns(2)
    with c1:
        with st.expander("Intended users and the decisions they make", expanded=False):
            st.markdown(
                "- **Application owners** acknowledge tasks, choose a treatment and submit closure evidence.\n"
                "- **Security reviewers** verify fixes and test exception mitigations (second line).\n"
                "- **CIO's delegate** owns the asset register and records decisions when owners stall.\n"
                "- **Executive risk owners** accept or decline residual risk; the CISO approves downward overrides.\n"
                "- **Compliance** answers referred questions and maintains the knowledge base.\n"
                "- **Internal audit and the joint committee** sample closures and review the quarterly pack (third line and board).")
        with st.expander("How it is built", expanded=False):
            st.markdown(
                "- `engine.py` holds every rule: matching, scoring, state transitions, segregation of duties, training gates, "
                "escalation timing and the daily recalculation. The interface only calls it.\n"
                "- `scenarios.py` replays scripted timelines through those same functions.\n"
                "- `assistant.py` retrieves clauses from a controlled knowledge base and cites them; Claude can phrase answers if an API key is configured.\n"
                "- Production target from report 4.8: FastAPI backend, PostgreSQL, restricted evidence storage and a scheduled worker, "
                "fed by the CMDB, software inventory (SBOM), scanner, PKI and HR directory.")
    with c2:
        with st.expander("Feasibility", expanded=False):
            st.markdown(
                "- **Technical:** uses data Equifax already holds (asset register, software inventory, scanner output, certificate inventory). The hard part is integration quality, not algorithms.\n"
                "- **Operational:** adds an evidence step to each closure and needs an on-call rota for P1 owners and reviewers.\n"
                "- **Organisational:** CIO and CISO must agree system ownership; the executive committee must pre-approve the incident commander's restriction authority.\n"
                "- **Economic:** the illustrative scenario lowers modelled exposure by US\\$1.0m a year per critical application. That is an estimate, not a saving, set against build and run costs and a 2019 settlement of at least US\\$575m.")
        with st.expander("Known limitations", expanded=False):
            st.markdown(
                "- Controls are only as good as the asset inventory; reconciliation reduces but cannot remove blind spots.\n"
                "- Loss assumptions and the effectiveness rubric are uncalibrated and need Equifax's own incident data.\n"
                "- Deadlines and indicators can drive gaming and alert fatigue.\n"
                "- No software prevents a determined management override; board oversight and internal audit remain essential.\n"
                "- Prototype only: synthetic data, no login, state lives in the browser session and resets on refresh.")


# ---------------------------------------------------------------------------
# Dashboard (4.2)
# ---------------------------------------------------------------------------
def kpi_row(s):
    cov = E.coverage_indicators(s)
    opens = E.open_exposures(s)
    p1 = [t for t in opens if t["priority"] in ("P1", "Unassessed")]
    exc = [t for t in s["tasks"].values() if E.exception_active(t, s["now"])]
    failed = E.failed_controls(s)
    unans = E.unanswered_escalations(s)
    c = st.columns(4)
    c[0].metric("Open P1 exposures", len(p1), border=True)
    c[1].metric("Overdue tasks", len(E.overdue(s)), border=True)
    c[2].metric("Open exceptions", len(exc), border=True, help="Approved exceptions still count as open exposures.")
    c[3].metric("Controls not healthy", f"{len(failed)} of {len(s['controls'])}", border=True)
    c = st.columns(4)
    c[0].metric("Annual loss estimate", E.money(E.total_published_eal(s)), border=True,
                help="Sum of the latest 02:00 run across scenarios. Scenarios do not overlap, so they are not double counted.")
    c[1].metric("Inventory current", f"{cov['internet_current'][0]} of {cov['internet_current'][1]}", border=True,
                help="Internet-facing assets whose software inventory is no older than seven days.")
    c[2].metric("Unregistered assets", cov["unregistered"], border=True)
    c[3].metric("Unanswered escalations", len(unans), border=True)


def patch_table(s, tasks):
    rows = []
    for t in tasks:
        late = t["state"] not in E.CLOSED and t["due_at"] < s["now"]
        rows.append({"Task": t["id"], "Asset": t["asset_id"], "Priority": t["priority"],
                     "State": "Overdue" if late else t["state"], "Due": short(t["due_at"]),
                     "Escalation": max([e["level"] for e in t["escalations"]], default=0)})
    return pd.DataFrame(rows)


def control_table(s, full=True):
    rows = []
    for cid, c in s["controls"].items():
        status, reasons = E.control_health(s, cid)
        row = {"Control": cid, "Status": status, "Detail": reasons[0]}
        if full:
            row = {"Control": cid, "Name": c["name"], "Covers": ", ".join(c["covers"]), "Status": status, "Detail": reasons[0]}
        rows.append(row)
    return pd.DataFrame(rows)


def task_summary(t):
    s = S()
    a = s["assets"].get(t["asset_id"], {})
    st.markdown(f"**{t['id']}**  {a.get('name', t['asset_id'])}  " + " ".join(
        [badge(t["priority"]), badge(t["state"]), badge(t["category"])]))
    c = st.columns(4)
    c[0].markdown(f"**Owner**  \n{nm(t['owner'])}")
    c[1].markdown(f"**Deputy**  \n{nm(t['deputy'])}")
    c[2].markdown(f"**Original alert**  \n{short(t['alerted_at'])}")
    c[3].markdown(f"**Deadline (fixed)**  \n{short(t['due_at'])}")
    if t["decisions"]:
        table(pd.DataFrame([{"Decision": d["option"], "By": nm(d["by"]), "At": short(d["at"]), "Evidence due": short(d["due_at"]),
                             "Status": d["status"]} for d in t["decisions"]]), ["Status"])
    if t["escalations"]:
        table(pd.DataFrame([{"Level": e["level"], "At": short(e["at"]), "To": ", ".join(nm(p) for p in e["to"]),
                             "Required": e["required"]} for e in t["escalations"]]))
    if t["exception"]:
        x = t["exception"]
        st.markdown(f"Exception {x['id']}: {badge(x['status'])} requested by {nm(x['requested_by'])}, "
                    f"{x['days']} days. Expires {short(x['expires_at'])}.")


def page_dashboard():
    show_flash()
    s = S()
    pid = me()
    p = s["people"][pid]
    st.title("Integrated dashboard")
    st.caption(f"{p['name']}, {p['role']}. Simulated time {ts(s['now'])}. Each role sees the panels it acts on.")
    notes("dashboard")
    kpi_row(s)

    left, right = st.columns(2)
    with left:
        st.subheader("Patching status")
        tasks = sorted([t for t in s["tasks"].values() if t["kind"] != "Ownership defect"], key=lambda t: t["id"])
        if tasks:
            table(patch_table(s, tasks), ["Priority", "State"])
        else:
            st.caption("No exposures yet. Ingest an advisory from the Alert allocator.")
    with right:
        st.subheader("Monitoring health")
        table(control_table(s, full=False), ["Status"], wrap=True)
        st.caption("Shown separately on purpose: a patched application behind a failed inspection device is still exposed.")

    st.divider()
    r = p["role"]
    if r in ("Application owner", "Line manager"):
        _owner_view(s, pid, r)
    elif r == "Security reviewer":
        _reviewer_view(s, pid)
    elif r == "Compliance officer":
        _compliance_view(s)
    elif r == "CIO delegate":
        _cio_view(s, pid)
    elif r == "Board committee":
        _board_view(s)
    elif r == "Internal audit":
        _audit_view(s)
    elif r == "Security operations":
        st.subheader("Controls needing action")
        bad = [cid for cid in E.failed_controls(s)]
        st.write("Nothing failing." if not bad else ", ".join(bad) + ". Open Control health to restore and test.")
    else:
        _management_view(s, pid)

    st.divider()
    st.subheader("Drill into a record")
    all_tasks = sorted(s["tasks"].values(), key=lambda t: t["id"])
    if all_tasks:
        t = pick_task("Record", all_tasks, "dash_drill")
        task_summary(t)


def _owner_view(s, pid, r):
    st.subheader("Your tasks")
    mine = [t for t in s["tasks"].values() if pid in (t["owner"], t["deputy"])
            or (r == "Line manager" and s["assets"].get(t["asset_id"], {}).get("line_manager") == pid)]
    open_mine = [t for t in mine if t["state"] not in E.CLOSED]
    if not open_mine:
        st.write("No open tasks assigned to you or your deputies.")
    for t in open_mine:
        with st.container(border=True):
            left = t["due_at"] - s["now"]
            st.markdown(f"**{t['id']}** {s['assets'].get(t['asset_id'], {}).get('name', t['asset_id'])}  "
                        + badge(t["priority"]) + " " + badge(t["state"])
                        + f"  \nDue {short(t['due_at'])}, " + (f"{dur(left)} left" if left.total_seconds() > 0 else f"overdue by {dur(-left)}"))
            if t["kind"] == "Remediation":
                st.caption("Evidence you will need: running version outside the affected range; authenticated scan whose scope includes this "
                           "application and the affected component; scan taken after deployment; an independent reviewer. [POL-VM-01 §4.2]")
            elif t["kind"] != "Ownership defect":
                st.caption("Unknown or stale is never safe: confirm the version from a current source, or refresh the inventory. [POL-VM-01 §3.6]")
    st.caption("Open the Resolution tracker to act on a task.")


def _reviewer_view(s, pid):
    st.subheader("Waiting for verification")
    waiting = [t for t in s["tasks"].values() if t["state"] == E.AWAITING]
    if waiting:
        table(pd.DataFrame([{"Task": t["id"], "Asset": t["asset_id"], "Submitted by": nm(t["submissions"][-1]["by"]),
                             "Submitted": short(t["submissions"][-1]["at"]), "Priority": t["priority"]} for t in waiting]), ["Priority"])
    else:
        st.write("Nothing waiting.")
    ex = [t for t in s["tasks"].values() if t["exception"] and t["exception"]["status"] == "Pending security review"]
    st.subheader("Exception mitigations to test")
    st.write(", ".join(t["id"] for t in ex) if ex else "None pending.")
    ok = E.trained(s, pid, E.GATES["verify"])
    st.markdown("Your verification rights: " + (badge("Trained") if ok else badge("Not trained") + " Complete M-SEC-01 in the Learning centre."))


def _compliance_view(s):
    st.subheader("Exception requests")
    ex = [t for t in s["tasks"].values() if t["exception"]]
    if ex:
        table(pd.DataFrame([{"Task": t["id"], "Exception": t["exception"]["id"], "Status": t["exception"]["status"],
                             "Requested by": nm(t["exception"]["requested_by"]), "Days": t["exception"]["days"]} for t in ex]), ["Status"])
    else:
        st.write("No exception requests.")
    st.subheader("Questions referred to Compliance")
    ref = [e for e in s["assistant_log"] if e["referred"]]
    if ref:
        table(pd.DataFrame([{"At": short(e["at"]), "From": nm(e["persona"]), "Question": e["question"], "Reason": e["reason"]} for e in ref]))
    else:
        st.write("None yet.")
    cites = pd.Series([c for e in s["assistant_log"] for c in e["citations"]]).value_counts()
    if len(cites):
        st.subheader("Most consulted clauses")
        st.caption("Recurring questions point to procedures that are unclear in practice.")
        table(cites.rename_axis("Clause").reset_index(name="Times cited"))


def _cio_view(s, pid):
    st.subheader("Ownership defects")
    od = [t for t in s["tasks"].values() if t["kind"] == "Ownership defect"]
    if od:
        table(pd.DataFrame([{"Task": t["id"], "Host": t["asset_id"], "State": t["state"], "Registration due": short(t["due_at"]),
                             "Note": t["note"]} for t in od]), ["State"], wrap=True)
    else:
        st.write("None.")
    st.subheader("Escalated to you")
    esc = [(t, e) for t in s["tasks"].values() for e in t["escalations"] if pid in e["to"] and t["state"] not in E.CLOSED]
    if esc:
        table(pd.DataFrame([{"Task": t["id"], "Level": e["level"], "At": short(e["at"]), "Required": e["required"],
                             "Answered": "Yes" if any(d["at"] >= e["at"] for d in t["decisions"]) else "No"} for t, e in esc]), ["Answered"])
    else:
        st.write("Nothing escalated to you.")


def _management_view(s, pid):
    st.subheader("Decisions waiting for you")
    rows = []
    for t, e in E.unanswered_escalations(s):
        if pid in e["to"]:
            rows.append({"Item": t["id"], "Type": f"Escalation level {e['level']}", "Since": short(e["at"]), "Required": e["required"]})
    for t in s["tasks"].values():
        if t["exception"] and t["exception"]["status"] == "Pending executive approval" and E.role(s, pid) in ("Executive risk owner", "CEO"):
            rows.append({"Item": t["id"], "Type": "Exception approval", "Since": short(t["exception"]["security_review"]["at"]),
                         "Required": "Accept or decline the residual risk"})
    for o in s["overrides"]:
        if o["status"] == "Pending CISO approval" and E.role(s, pid) == "CISO":
            rows.append({"Item": o["task"], "Type": f"Priority override {o['from']} to {o['to']}", "Since": short(o["at"]), "Required": "Approve or decline"})
    if rows:
        table(pd.DataFrame(rows))
    else:
        st.write("Nothing waiting for you.")
    st.subheader("Financial exposure against tolerance")
    exposure_table(s)


def exposure_table(s):
    rows = []
    for a, A_ in s["assumptions"].items():
        pub = E.published_estimate(s, a)
        if not pub:
            continue
        rows.append({"Asset": a, "Scenario": A_["scenario"], "Band": pub["band"], "Published estimate": E.money(pub["eal"]),
                     "Tolerance": E.money(A_["tolerance"]) if A_.get("tolerance") else "-",
                     "Utilisation": f"{pub['utilisation']:.0%}" if pub["utilisation"] is not None else "Assessment incomplete",
                     "Last run": short(pub["run_at"])})
    table(pd.DataFrame(rows), ["Utilisation"], wrap=True)


def committee_pack(s):
    cov = E.coverage_indicators(s)
    q = E.closure_quality(s)
    lines = [f"# Joint Audit and Technology Committee: vulnerability assurance pack",
             f"As at {ts(s['now'])} (synthetic prototype data)", "",
             "## Indicators",
             f"- Verified closures within deadline: {q['within_sla']} of {q['closed'] + q['late_open']} "
             f"({(q['verified_rate'] or 0):.0%})",
             f"- Closure attempts rejected for insufficient evidence: {q['rejected_submissions']}",
             f"- Approvals blocked by segregation of duties or training gates: {q['blocked_approvals']}",
             f"- Internet-facing assets with current inventory: {cov['internet_current'][0]} of {cov['internet_current'][1]}",
             f"- Unregistered assets found and open: {cov['unregistered']}",
             f"- Unanswered escalations: {len(E.unanswered_escalations(s))}",
             f"- Approved exceptions still open: {sum(1 for t in s['tasks'].values() if E.exception_active(t, s['now']))}",
             f"- Monitoring controls not healthy: {', '.join(E.failed_controls(s)) or 'none'}",
             f"- Published annual loss estimate: {E.money(E.total_published_eal(s))}", "",
             "## Open exposures"]
    for t in E.open_exposures(s):
        lines.append(f"- {t['id']} {t['asset_id']} {t['priority']} {t['state']}, due {short(t['due_at'])}, escalation level "
                     f"{max([e['level'] for e in t['escalations']], default=0)}")
    lines += ["", "Measured by verified closures, not closed tickets. Maturity scores are not used as evidence."]
    return "\n".join(lines)


def _board_view(s):
    st.subheader("Quarterly committee pack")
    st.caption("Verified closure rates, coverage, unanswered escalations and approved exceptions, rather than self-reported maturity scores.")
    pack = committee_pack(s)
    st.markdown(esc(pack.split("## Open exposures")[0].split("## Indicators")[1]))
    st.download_button("Download committee pack", pack, file_name="committee_pack.md", mime="text/markdown")
    exposure_table(s)


def _audit_view(s):
    st.subheader("Third-line sample")
    st.caption("Internal audit samples closed tasks, treatment decisions and exception approvals each quarter. Full sampling is on the Audit and evaluation page.")
    q = E.closure_quality(s)
    c = st.columns(3)
    c[0].metric("Closed tasks", q["closed"])
    c[1].metric("Rejected submissions", q["rejected_submissions"])
    c[2].metric("Blocked approvals", q["blocked_approvals"])


# ---------------------------------------------------------------------------
# Alert allocator (4.3.1)
# ---------------------------------------------------------------------------
def page_allocator():
    show_flash()
    s = S()
    st.title("Alert allocator")
    st.caption("Matches each advisory to the software inventory and assigns work to the named owner and deputy of every matching asset.")
    notes("allocator")
    acting_line()
    tabs = st.tabs(["Advisory feed", "Triage results", "Asset register and inventory", "Reconciliation"])

    with tabs[0]:
        for adv_id, adv in s["advisories"].items():
            with st.container(border=True):
                done = s["ingested"].get(adv_id)
                st.markdown(f"**{adv_id}**  {adv['title']}  " + badge(f"CVSS {adv['cvss']}", "red" if adv["cvss"] >= 9 else "orange"))
                ranges = ", ".join(f"{lo} to {hi}" for lo, hi in adv["affected"])
                st.caption(f"Component {adv['component']}. Affected {ranges}. Fixed in {adv['fixed']}. "
                           f"Public exploit: {'yes' if adv['public_exploit'] else 'no'}. Exploited in the wild: "
                           f"{'yes' if adv['exploited_in_wild'] else 'no'}. Source: {adv['source']}.")
                if done:
                    st.markdown(f"Ingested {short(done['at'])} by {nm(done['by'])}. " + badge("Triaged", "green"))
                elif st.button("Ingest and triage", key=f"ing_{adv_id}"):
                    do(E.ingest_advisory, me(), adv_id, ok=f"{adv_id} triaged. Tasks assigned to named owners.")

    with tabs[1]:
        if not s["ingested"]:
            st.write("Nothing ingested yet. Ingest an advisory from the feed to see the allocator work.")
        else:
            adv_id = st.selectbox("Advisory", list(s["ingested"]), key="tri_adv")
            rows = []
            for r in s["triage"]:
                if r["advisory"] != adv_id:
                    continue
                t = s["tasks"].get(r["task"]) if r["task"] else None
                a = s["assets"][r["asset_id"]]
                rows.append({"Asset": f"{r['asset_id']} {a['name']}", "Owner and deputy": f"{nm(a['owner'])} / {nm(a['deputy'])}",
                             "Category at triage": r["category"], "Version found": r["version_found"], "Why": r["why"],
                             "Priority": t["priority"] if t else "-", "Task": r["task"] or "No task",
                             "Task now": t["state"] if t else "-"})
            table(pd.DataFrame(rows), ["Category at triage", "Priority", "Task now"], wrap=True)
            st.caption("Three working categories, none of them safe by default: confirmed affected gets remediation; unknown version gets an "
                       "investigation that closes only with evidence; stale or missing inventory is potentially affected until refreshed.")

    with tabs[2]:
        reg = []
        for aid, a in s["assets"].items():
            age = E.inventory_age_days(s, aid)
            reg.append({"Asset": aid, "Name": a["name"], "Owner": nm(a["owner"]), "Deputy": nm(a["deputy"]),
                        "Legal entity": a["legal_entity"], "Data": a["classification"], "Internet-facing": "Yes" if a["internet_facing"] else "No",
                        "Inventory age": "missing" if age is None else f"{age:.1f} days",
                        "Inventory": "Stale" if age is None or age > E.STALE_DAYS else "Current"})
        table(pd.DataFrame(reg), ["Inventory"])
        inv = pd.DataFrame([{"Asset": r["asset_id"], "Component": r["component"], "Version": r["version"] or "unknown"} for r in s["inventory"]])
        st.markdown("**Software inventory**")
        table(inv)
        with st.form("refresh_inv"):
            st.markdown("**Refresh an inventory record**")
            c = st.columns(3)
            aid = c[0].selectbox("Asset", list(s["assets"]))
            comp = c[1].text_input("Component", "apache-struts2")
            ver = c[2].text_input("Version (blank if unknown)", "")
            if st.form_submit_button("Refresh inventory"):
                do(E.refresh_inventory, me(), aid, comp.strip(), ver.strip(), ok=f"Inventory for {aid} refreshed. Open tasks were reclassified; deadlines unchanged.")

    with tabs[3]:
        cov = E.coverage_indicators(s)
        c = st.columns(3)
        c[0].metric("Internet-facing with current inventory", f"{cov['internet_current'][0]} of {cov['internet_current'][1]}")
        c[1].metric("Unregistered assets", cov["unregistered"])
        c[2].metric("Advisories fully triaged", f"{cov['advisories_triaged'][0]} of {cov['advisories_triaged'][1]}")
        st.caption(f"Last reconciliation {short(s['last_recon'])}. Runs daily for internet-facing systems at 05:00.")
        disc = pd.DataFrame([{"Host": d["host"], "Seen by": d["source"], "Internet-facing": "Yes" if d["internet_facing"] else "No",
                              "In register": d["asset_id"] or "No", "Fingerprint": d.get("fingerprint", "")} for d in s["discovery"]])
        table(disc, ["In register"])
        if st.button("Run reconciliation now"):
            do(E.run_reconciliation, me(), ok="Reconciliation complete.")
        unreg = [d for d in s["discovery"] if d["asset_id"] is None]
        if unreg:
            with st.form("register"):
                st.markdown("**Register an unregistered host** (CIO's delegate)")
                host = st.selectbox("Host", [d["host"] for d in unreg])
                c = st.columns(3)
                new_id = c[0].text_input("Asset ID", "A-ARCHIVE")
                new_name = c[1].text_input("Name", "Dispute archive export host")
                cls = c[2].selectbox("Data classification", list(E.CLASS_IMPACT), index=2)
                c = st.columns(3)
                people = {p: v["name"] for p, v in s["people"].items() if v["role"] == "Application owner"}
                owner = c[0].selectbox("Owner", list(people), format_func=people.get)
                deputy = c[1].selectbox("Deputy", list(people), index=1, format_func=people.get)
                inet = c[2].checkbox("Internet-facing", True)
                comps = st.text_input("Components found (component version; separated by semicolons)", "nginx 1.10.3")
                if st.form_submit_button("Register and assign owner"):
                    parsed = []
                    for part in comps.split(";"):
                        bits = part.strip().split()
                        if bits:
                            parsed.append((bits[0], bits[1] if len(bits) > 1 else None))
                    do(E.register_asset, me(), host, new_id.strip(), new_name.strip(), owner, deputy, cls, inet, parsed,
                       ok=f"{host} registered. Every ingested advisory was re-run against it using the original alert times.")


# ---------------------------------------------------------------------------
# Resolution tracker (4.3.2)
# ---------------------------------------------------------------------------
def clock_strip(t):
    s = S()
    rungs = sorted(t["ladder"], key=lambda r: r["at"])
    if not rungs:
        return
    start = t["alerted_at"]
    closed = t["state"] in E.CLOSED
    end = t["closed_at"] if closed else s["now"]
    points = [start] + [r["at"] for r in rungs]
    n = len(rungs)

    def pos(x):
        if x <= points[0]:
            return 0.0
        for i in range(1, len(points)):
            if x <= points[i]:
                span = (points[i] - points[i - 1]).total_seconds() or 1
                return ((i - 1) + (x - points[i - 1]).total_seconds() / span) / n
        return 1.0

    overdue = not closed and s["now"] > t["due_at"]
    state_cls = "closed" if closed else ("overdue" if overdue else "running")
    elapsed = dur(end - start)
    if closed:
        right = f"closed {dur(t['due_at'] - t['closed_at'])} before the deadline" if t["closed_at"] <= t["due_at"] else f"closed {dur(t['closed_at'] - t['due_at'])} late"
    elif overdue:
        right = f"overdue by {dur(s['now'] - t['due_at'])}"
    else:
        right = f"{dur(t['due_at'] - s['now'])} to the {t['priority']} deadline"
    cells = []
    for r in rungs:
        unit = "h" if r["unit"] == "hours" else "bd"
        label = f"{r['after']} {unit}" if r.get("after") is not None else "renewal"
        who = ", ".join(nm(p) for p in E._resolve(s, t, r["to_roles"]))
        if r["status"] == "Fired":
            status, cls = f"Escalated {short(r.get('fired_at'))}", "fired"
        elif r["status"] == "Skipped":
            status, cls = "Not needed", "skipped"
        else:
            status, cls = f"Due {short(r['at'])}", "pending"
        cells.append(f"<div class='rung {cls}'><div class='rt'>{label}</div><div class='rw'>{who}</div><div class='rs'>{status}</div></div>")
    html = (f"<div class='clock {state_cls}'>"
            f"<div class='clock-head'><span class='clock-big'>{elapsed}</span><span class='clock-sub'>since the advisory at {short(start)}</span>"
            f"<span class='clock-right'>{right}</span></div>"
            f"<div class='track'><div class='fill' style='width:{pos(end) * 100:.1f}%'></div>"
            f"<div class='deadline' style='left:{pos(t['due_at']) * 100:.1f}%' title='Deadline'></div></div>"
            f"<div class='rungs'>{''.join(cells)}</div></div>")
    st.markdown(html, unsafe_allow_html=True)


def lifecycle(t):
    states = E.LIFECYCLE if t["state"] != E.NOT_AFFECTED else [E.ASSIGNED, E.ACKED, E.AWAITING, E.NOT_AFFECTED]
    idx = states.index(t["state"]) if t["state"] in states else 0
    parts = []
    for i, st_name in enumerate(states):
        cls = "done" if i < idx else ("now" if i == idx else "todo")
        parts.append(f"<span class='step {cls}'>{st_name}</span>")
    st.markdown("<div class='steps'>" + "<span class='sep'>›</span>".join(parts) + "</div>", unsafe_allow_html=True)


def page_tracker():
    show_flash()
    s = S()
    st.title("Resolution tracker")
    notes("tracker")
    tasks = sorted([t for t in s["tasks"].values()], key=lambda t: t["id"])
    if not tasks:
        st.write("No tasks yet. Ingest an advisory in the Alert allocator, or load step 2 from the sidebar.")
        return
    show_all = st.toggle("Include closed tasks", value=True, key="trk_all")
    pool = tasks if show_all else [t for t in tasks if t["state"] not in E.CLOSED]
    if not pool:
        st.write("No open tasks.")
        return
    t = pick_task("Task", pool, "trk_sel")
    a = s["assets"].get(t["asset_id"], {})
    st.markdown(f"### {a.get('name', t['asset_id'])}")
    st.markdown(" ".join([badge(t["priority"]), badge(t["state"]), badge(t["category"]), badge(t["kind"], "gray")])
                + f"  \nOwner {nm(t['owner'])}, deputy {nm(t['deputy'])}. Advisory {t['advisory'] or '-'}. "
                  f"Alerted {ts(t['alerted_at'])}; deadline {ts(t['due_at'])}, fixed from the alert time.")
    clock_strip(t)
    lifecycle(t)
    acting_line()

    tabs = st.tabs(["Actions", "Evidence", "Decisions and escalations", "Exception", "History"])
    with tabs[0]:
        _tracker_actions(s, t)
    with tabs[1]:
        if not t["submissions"]:
            st.write("No evidence submitted yet.")
        for sub in reversed(t["submissions"]):
            with st.container(border=True):
                st.markdown(f"**{sub['id']}** submitted by {nm(sub['by'])} at {short(sub['at'])}  " + badge(sub["status"]))
                table(pd.DataFrame([{"Check": c[0], "Result": "Passed" if c[1] else "Failed", "Detail": c[2]} for c in sub["checks"]]), ["Result"], wrap=True)
                if sub.get("notes"):
                    st.caption(f"Owner's note: {sub['notes']}")
                if sub.get("review"):
                    st.caption(f"Reviewed by {nm(sub['review']['by'])} at {short(sub['review']['at'])}. {sub['review']['reason']}")
    with tabs[2]:
        st.markdown("**Treatment decisions**")
        if t["decisions"]:
            table(pd.DataFrame([{"Decision": d["option"], "By": nm(d["by"]), "At": short(d["at"]), "Evidence due": short(d["due_at"]),
                                 "Status": d["status"], "Rationale": d["rationale"]} for d in t["decisions"]]), ["Status"], wrap=True)
        else:
            st.write("None recorded.")
        st.markdown("**Escalation route**")
        if t["ladder"]:
            table(pd.DataFrame([{"Level": r["level"], "Time": short(r["at"]), "Trigger": _trigger_text(r["condition"]),
                                 "Escalated to": ", ".join(nm(p) for p in E._resolve(s, t, r["to_roles"])),
                                 "Required response": r["required"], "Status": r["status"]} for r in sorted(t["ladder"], key=lambda r: r["at"])]), ["Status"], wrap=True)
            st.caption("P1 and P2 run in calendar hours, including nights and weekends. P3 and P4 use business days.")
    with tabs[3]:
        x = t["exception"]
        if not x:
            st.write("No exception requested. An approved exception would still count as an open exposure.")
        else:
            st.markdown(f"**{x['id']}** " + badge(x["status"]))
            st.markdown(f"Requested by {nm(x['requested_by'])} at {short(x['requested_at'])} for {x['days']} days.  \n"
                        f"Mitigation: {x['mitigation']}  \nReason: {x['rationale']}")
            if x["security_review"]:
                r = x["security_review"]
                st.markdown(f"Security review by {nm(r['by'])} at {short(r['at'])}: "
                            + ("mitigation tested and effective. " if r["tested"] else "mitigation not shown to work. ") + r["note"])
            if x["approved_by"]:
                st.markdown(f"Approved by {nm(x['approved_by'])} at {short(x['approved_at'])}; expires {ts(x['expires_at'])}. "
                            "The exposure stays open and the estimate does not change.")
    with tabs[4]:
        hist = [e for e in s["audit"] if e["object"] == t["id"]]
        table(pd.DataFrame([{"At": short(e["at"]), "Who": nm(e["actor"]), "Action": e["action"], "Outcome": e["outcome"],
                             "Detail": e["detail"]} for e in hist]), ["Outcome"], wrap=True)


def _trigger_text(c):
    return {"not_acknowledged": "Not acknowledged", "no_decision": "No recorded treatment decision",
            "not_closed_no_exception": "Not verified closed and no approved exception", "no_exec_decision": "Executive decision not recorded",
            "open": "Exposure still open", "renewal_follow_up": "No decision after exception expiry"}.get(c, c)


def _tracker_actions(s, t):
    if t["state"] in E.CLOSED:
        st.success(f"{t['state']} at {short(t['closed_at'])}, verified by {nm(t['verified_by'])}.")
        return
    if t["kind"] == "Ownership defect":
        st.write("Register this host in the Alert allocator (Reconciliation tab) to close the ownership defect.")
        return
    adv = s["advisories"][t["advisory"]]
    if t["state"] == E.ASSIGNED:
        if st.button("Acknowledge and confirm owner", type="primary"):
            do(E.acknowledge, me(), t["id"], ok="Acknowledged.")

    if t["state"] == E.AWAITING:
        sub = t["submissions"][-1]
        st.markdown(f"**Verify {sub['id']}**  submitted by {nm(sub['by'])}. Automated checks: "
                    + ("all passed." if all(c[1] for c in sub["checks"]) else "some failed."))
        c = st.columns([1, 2])
        if c[0].button("Approve closure", type="primary"):
            do(E.verify, me(), t["id"], True, "Checks confirmed.", ok="Verified closed. The estimate will update at the next 02:00 run.")
        with c[1].form("reject"):
            reason = st.text_input("Reason for returning it", "")
            if st.form_submit_button("Return to owner"):
                do(E.verify, me(), t["id"], False, reason, ok="Returned to the owner.")
        return

    pending = [d for d in t["decisions"] if d["status"] == "Pending evidence" and d["option"] in ("Temporary protection", "Restrict service")]
    if pending:
        label = "Confirm the temporary protection was tested" if pending[-1]["option"] == "Temporary protection" else "Confirm the service is restricted"
        if st.button(label):
            do(E.evidence_decision, me(), t["id"], ok="Decision evidenced.")

    with st.expander("Record a treatment decision", expanded=t["state"] == E.ACKED):
        with st.form(f"dec_{t['id']}"):
            opt = st.radio("Decision", ["Remediate", "Temporary protection", "Restrict service"], horizontal=True)
            why = st.text_area("Rationale", "", height=70)
            st.caption("For a time-limited exception, use the exception request below so it is reviewed and approved.")
            if st.form_submit_button("Record decision"):
                do(E.record_decision, me(), t["id"], opt, why, ok=f"{opt} recorded with its own evidence due date.")

    if t["kind"] == "Remediation":
        with st.expander("Submit remediation evidence", expanded=t["state"] == E.TREATING):
            with st.form(f"sub_{t['id']}"):
                c = st.columns(2)
                ver = c[0].text_input("Running version now", "2.3.32")
                auth = c[1].checkbox("Scan was authenticated", True)
                scope = st.multiselect("Scan scope (assets the scan covered)", list(s["assets"]), default=[t["asset_id"]])
                comps = st.multiselect("Components the scan checked", sorted({r["component"] for r in s["inventory"]}), default=[adv["component"]])
                c = st.columns(4)
                dep_d = c[0].date_input("Deployed on", s["now"].date())
                dep_t = c[1].time_input("Deployed at", (s["now"] - timedelta(hours=2)).time().replace(second=0, microsecond=0), step=timedelta(minutes=5))
                scan_d = c[2].date_input("Scanned on", s["now"].date())
                scan_t = c[3].time_input("Scanned at", (s["now"] - timedelta(minutes=10)).time().replace(second=0, microsecond=0), step=timedelta(minutes=5))
                note = st.text_input("Note", "")
                if st.form_submit_button("Submit evidence"):
                    do(E.submit_evidence, me(), t["id"], "remediation", ver.strip(), auth, scope, comps, to_dt(scan_d, scan_t),
                       deployed_at=to_dt(dep_d, dep_t), notes=note, ok="Submitted. If automated checks passed it now waits for an independent reviewer.")
            st.caption("Try removing the application from the scope to see the backend reject it.")
    else:
        with st.expander("Submit not-affected evidence", expanded=t["state"] == E.ACKED):
            with st.form(f"na_{t['id']}"):
                c = st.columns(2)
                ver = c[0].text_input("Observed version", "")
                src = c[1].text_input("Source of the version", "build manifest and authenticated scan")
                auth = st.checkbox("Scan was authenticated", True)
                scope = st.multiselect("Scan scope", list(s["assets"]), default=[t["asset_id"]])
                comps = st.multiselect("Components checked", sorted({r["component"] for r in s["inventory"]}), default=[adv["component"]])
                c = st.columns(2)
                scan_d = c[0].date_input("Scanned on", s["now"].date())
                scan_t = c[1].time_input("Scanned at", (s["now"] - timedelta(minutes=10)).time().replace(second=0, microsecond=0), step=timedelta(minutes=5))
                if st.form_submit_button("Submit evidence"):
                    do(E.submit_evidence, me(), t["id"], "not_affected", ver.strip(), auth, scope, comps, to_dt(scan_d, scan_t),
                       source=src, ok="Submitted for independent confirmation.")
            st.caption("If the asset turns out to be affected, refresh its inventory in the Alert allocator; the task becomes remediation with the same deadline.")

    x = t["exception"]
    with st.expander("Exception", expanded=bool(x and x["status"].startswith("Pending"))):
        if not x or x["status"] in ("Declined", "Expired", "Returned: mitigation untested"):
            with st.form(f"exc_{t['id']}"):
                mit = st.text_input("Mitigation", "WAF rule blocking malformed Content-Type headers")
                limit = 7 if t["priority"] in ("P1", "Unassessed") else 30
                days = st.slider("Days", 1, 30, min(7, limit))
                why = st.text_area("Why the fix cannot be applied now", "", height=70)
                st.caption(f"{t['priority']} exceptions are limited to {limit} days.")
                if st.form_submit_button("Request exception"):
                    do(E.request_exception, me(), t["id"], mit, days, why, ok="Exception requested. It needs security review, then an executive who is not you.")
        elif x["status"] == "Pending security review":
            with st.form(f"rev_{t['id']}"):
                tested = st.radio("Was the mitigation shown to work?", ["Yes, tested and effective", "No, untested or ineffective"])
                note = st.text_input("Test note", "")
                if st.form_submit_button("Record security review"):
                    do(E.review_exception, me(), t["id"], tested.startswith("Yes"), note, ok="Security review recorded.")
        elif x["status"] == "Pending executive approval":
            c = st.columns(2)
            if c[0].button("Approve exception", type="primary"):
                do(E.approve_exception, me(), t["id"], True, ok="Exception approved. The exposure stays open.")
            if c[1].button("Decline exception"):
                do(E.approve_exception, me(), t["id"], False, ok="Exception declined.")
        else:
            st.write(f"Exception {x['status'].lower()}. Expires {ts(x['expires_at'])}.")


# ---------------------------------------------------------------------------
# Risk calculator (4.4)
# ---------------------------------------------------------------------------
BAND_COLORS = ["#E7ECF3", "#F6E7B8", "#F2C48D", "#E89A8F"]  # P4, P3, P2, P1


def heatmap(s, highlight=None):
    z = [[["P4", "P3", "P2", "P1"].index(E.band_for_score(l * i)) for i in range(1, 6)] for l in range(1, 6)]
    text = [[str(l * i) for i in range(1, 6)] for l in range(1, 6)]
    cs = [[0, BAND_COLORS[0]], [0.25, BAND_COLORS[0]], [0.25, BAND_COLORS[1]], [0.5, BAND_COLORS[1]],
          [0.5, BAND_COLORS[2]], [0.75, BAND_COLORS[2]], [0.75, BAND_COLORS[3]], [1, BAND_COLORS[3]]]
    fig = go.Figure(go.Heatmap(z=z, x=list(range(1, 6)), y=list(range(1, 6)), text=text, texttemplate="%{text}",
                               colorscale=cs, zmin=0, zmax=3, showscale=False, hoverinfo="skip",
                               textfont={"color": "#56637A", "size": 12}))
    pts = [t for t in s["tasks"].values() if t.get("rating") and t["rating"].get("score")]
    seen = {}
    xs, ys, labels, colors = [], [], [], []
    for t in pts:
        r = t["rating"]
        k = (r["impact"], r["likelihood"])
        n = seen.get(k, 0)
        seen[k] = n + 1
        xs.append(r["impact"] - 0.25 + 0.25 * (n % 3))
        ys.append(r["likelihood"] - 0.12 - 0.25 * (n // 3))
        labels.append(f"{t['id']} {t['asset_id']}")
        colors.append("#13233F" if t["id"] == highlight else "#5B6B84")
    if xs:
        fig.add_trace(go.Scatter(x=xs, y=ys, mode="markers+text", text=[l.split()[1].replace("A-", "") for l in labels], textposition="bottom center",
                                 marker={"size": 11, "color": colors, "line": {"width": 1, "color": "white"}},
                                 textfont={"size": 10, "color": "#13233F"}, hovertext=labels, hoverinfo="text"))
    fig.update_layout(height=380, margin={"l": 10, "r": 10, "t": 10, "b": 10}, showlegend=False,
                      xaxis={"title": "Impact", "dtick": 1, "range": [0.5, 5.5]},
                      yaxis={"title": "Likelihood", "dtick": 1, "range": [0.5, 5.5]},
                      plot_bgcolor="white", font={"family": "Public Sans, sans-serif"})
    return fig


def page_risk():
    show_flash()
    s = S()
    st.title("Risk assessment calculator")
    st.caption("Stage one sets how fast to act. Stage two estimates what is at stake and refreshes once a day from collected evidence.")
    notes("risk")
    acting_line()
    tabs = st.tabs(["Stage 1: priority matrix", "Stage 2: financial exposure"])

    with tabs[0]:
        rated = sorted([t for t in s["tasks"].values() if t.get("rating")], key=lambda t: t["id"])
        if not rated:
            st.write("No rated exposures yet. Ingest an advisory first.")
        else:
            t = pick_task("Exposure", rated, "risk_task")
            r = t["rating"]
            left, right = st.columns([1, 1])
            with left:
                c = st.columns(4)
                c[0].metric("Likelihood", r["likelihood"] if r["likelihood"] is not None else "-")
                c[1].metric("Impact", r["impact"] if r["impact"] is not None else "-")
                c[2].metric("Score", r["score"] if r["score"] is not None else "-")
                c[3].metric("Priority", t["priority"])
                st.markdown("**Why this score**")
                for line in r["reasons"]:
                    st.markdown(f"- {line}")
                if r.get("override"):
                    st.markdown(f"- Override: {r['override']}")
                st.markdown(f"Deadline {ts(t['due_at'])}.")
                table(pd.DataFrame([("P1", "20 to 25", "48 hours"), ("P2", "12 to 19", "7 days"), ("P3", "6 to 11", "30 business days"),
                                    ("P4", "1 to 5", "90 business days")], columns=["Priority", "Score", "Target"]), ["Priority"])
                st.caption("Known exploitation, or a confirmed critical flaw on an internet-facing service, is at least P1. Missing data gives Unassessed, never a low score.")
            with right:
                st.plotly_chart(heatmap(s, t["id"]), width="stretch", config={"displayModeBar": False})
            with st.expander("Request a downward override"):
                with st.form("ovr"):
                    lower = [p for p in ("P2", "P3", "P4") if E.PRIORITY_ORDER[p] > E.PRIORITY_ORDER.get(t["priority"], 0)]
                    newp = st.selectbox("Lower to", lower or ["P4"])
                    why = st.text_area("Why the matrix overstates this exposure", "", height=70)
                    if st.form_submit_button("Request override"):
                        do(E.request_override, me(), t["id"], newp, why, ok="Override requested. It needs separate approval by the CISO.")
            pend = [o for o in s["overrides"]]
            if pend:
                st.markdown("**Override requests**")
                table(pd.DataFrame([{"ID": o["id"], "Task": o["task"], "Change": f"{o['from']} to {o['to']}", "By": nm(o["by"]),
                                     "Reason": o["reason"], "Status": o["status"]} for o in pend]), ["Status"])
                waiting = [o for o in pend if o["status"] == "Pending CISO approval"]
                if waiting:
                    oid = st.selectbox("Decide", [o["id"] for o in waiting], format_func=lambda i: f"{i} {next(o for o in waiting if o['id'] == i)['task']}")
                    o = next(o for o in waiting if o["id"] == oid)
                    c = st.columns(2)
                    if c[0].button("Approve override"):
                        do(E.decide_override, me(), o["id"], True, ok="Override approved; deadline recalculated from the original alert time.")
                    if c[1].button("Decline override"):
                        do(E.decide_override, me(), o["id"], False, ok="Override declined.")

    with tabs[1]:
        assets = [a for a in s["assumptions"] if a in s["assets"]]
        aid = st.selectbox("Scenario", assets, format_func=lambda a: f"{a}  {s['assets'][a]['name']}", key="rq_asset")
        A_ = s["assumptions"][aid]
        pub = E.published_estimate(s, aid)
        live = E.compute_estimate(s, aid)
        st.caption(A_["scenario"])
        c = st.columns(4)
        c[0].metric("Published estimate", E.money(pub["eal"]) if pub else "Not yet run", border=True,
                    help=f"From the {short(pub['run_at'])} run" if pub else None)
        c[1].metric("Control effectiveness", f"{pub['band']} ({pub['ce']:.0%})" if pub else "-", border=True)
        c[2].metric("Tolerance utilisation", f"{pub['utilisation']:.0%}" if pub and pub["utilisation"] is not None else "Assessment incomplete", border=True,
                    help="Estimated annual loss divided by approved annual risk tolerance. Above 100% means exposure exceeds appetite, not a probability of breach.")
        c[3].metric("Last run", short(pub["run_at"]) if pub else "-", border=True,
                    help="Runs daily at 02:00. Urgent events still alert immediately.")
        if pub and live["eal"] != pub["eal"]:
            st.warning(esc(f"Evidence has changed since the last run. At the next 02:00 run the estimate becomes {E.money(live['eal'])} "
                           f"({live['band']}). Time passing alone never moves it."), icon=":material/schedule:")
        if live["status"] == "Assessment incomplete":
            st.warning("Assessment incomplete: an approved business assumption is missing, so no figure is shown rather than a misleading zero.")
        else:
            st.markdown(esc(f"**Calculation from the published run**  \n"
                            f"US${A_['av']:,.0f} asset value × {A_['ef']:.2f} exposure factor × {A_['aro']:.2f} per year × "
                            f"(1 − {pub['ce']:.2f}) = **{E.money(pub['eal'])}** a year  \n"
                            f"Sensitivity range {E.money(pub['low'])} to {E.money(pub['high'])}. Tolerance {E.money(A_['tolerance'])}."))
        rows = []
        for k, label in E.FACTORS.items():
            ps = pub["factors"][k][0] if pub else "-"
            rows.append({"Factor": label, "Published": ps, "Live now": live["factors"][k][0], "Evidence": live["factors"][k][1]})
        table(pd.DataFrame(rows), ["Published", "Live now"], wrap=True)
        st.caption("Unknown never counts as a pass. A stale or failed test removes the credit it supported. Approving an exception changes none of these.")
        with st.expander("Effectiveness rubric and model record"):
            st.markdown(
                f"{E.RUBRIC_VERSION}, {E.MODEL_VERSION}. Passing four of five tests does not mean 80% effective; the rubric maps evidence to bands.\n\n"
                "- **Nearly complete, 95%:** all five factors passed.\n"
                "- **Significant, 75%:** patch verified, coverage and detection passed, plus privileged access or network restriction.\n"
                "- **Moderate, 50%:** patch verified and coverage passed.\n"
                "- **Minor, 25%:** otherwise.\n\n"
                f"Assumptions approved by {A_['approved_by']}" + (f" on {A_['approved_on']:%d %b %Y}." if A_["approved_on"] else "."))
        hist = E.estimate_history(s, aid)
        if len(hist) > 0 and hist[-1]["eal"] is not None:
            df = pd.DataFrame([{"Run": h["run_at"], "Estimate": h["eal"]} for h in hist if h["eal"] is not None])
            fig = go.Figure(go.Scatter(x=df["Run"], y=df["Estimate"], mode="lines+markers", line={"shape": "hv", "color": "#2457A6"}))
            fig.add_hline(y=A_["tolerance"], line_dash="dot", line_color="#9B2117", annotation_text="Tolerance", annotation_position="top left")
            fig.update_layout(height=260, margin={"l": 10, "r": 10, "t": 20, "b": 10}, yaxis={"title": "US$ per year", "rangemode": "tozero"},
                              plot_bgcolor="white", font={"family": "Public Sans, sans-serif"})
            st.markdown("**Published estimate by daily run**")
            st.plotly_chart(fig, width="stretch", config={"displayModeBar": False})


# ---------------------------------------------------------------------------
# Control health
# ---------------------------------------------------------------------------
def page_controls():
    show_flash()
    s = S()
    st.title("Control health")
    st.caption("Monitoring controls are tracked apart from patching. A control stays flagged until it is restored and tested.")
    notes("controls")
    acting_line()
    blind = []
    for aid in s["assumptions"]:
        if aid not in s["assets"]:
            continue
        f = E.factor_status(s, aid)
        if f["patch"][0] == "Passed" and f["detection"][0] != "Passed":
            blind.append((aid, f["detection"][1]))
    for aid, why in blind:
        st.error(f"{s['assets'][aid]['name']}: patching is complete but monitoring has failed. {why}", icon=":material/visibility_off:")
    table(control_table(s), ["Status"], wrap=True)

    cid = st.selectbox("Control", list(s["controls"]), format_func=lambda c: f"{c}  {s['controls'][c]['name']}", key="ctl_sel")
    c = s["controls"][cid]
    status, reasons = E.control_health(s, cid)
    st.markdown(badge(status) + "  " + reasons[0])
    cols = st.columns(4)
    cols[0].markdown(f"**Certificate expires**  \n{ts(c['cert_expires']) if c['cert_expires'] else 'No certificate'}")
    cols[1].markdown(f"**Last inspection test**  \n{ts(c['last_test'])}")
    cols[2].markdown(f"**Heartbeat**  \n{'Reporting' if c['heartbeat_ok'] else 'Lost'}")
    cols[3].markdown(f"**Covers**  \n{', '.join(c['covers'])}")
    b = st.columns(4)
    if c["cert_expires"] and b[0].button("Renew certificate"):
        do(E.renew_certificate, me(), cid, ok="Certificate renewed. The control stays flagged until an inspection test passes.")
    if b[1].button("Run inspection test"):
        do(E.run_inspection_test, me(), cid, ok="Inspection test passed. Control healthy.")
    if c["heartbeat_ok"]:
        if b[2].button("Simulate heartbeat loss"):
            do(E.simulate_heartbeat_loss, me(), cid, ok="Heartbeat loss simulated; immediate alert raised.")
    elif b[2].button("Restore heartbeat"):
        do(E.restore_heartbeat, me(), cid, ok="Heartbeat restored; awaiting test.")

    st.subheader("Monitoring alerts")
    alerts = [e for e in s["audit"] if e["action"] in ("Monitoring alert", "Renew certificate", "Run inspection test", "Restore heartbeat")]
    table(pd.DataFrame([{"At": short(e["at"]), "Control": e["object"], "Who": nm(e["actor"]), "Event": e["action"], "Detail": e["detail"]}
                        for e in reversed(alerts)]), wrap=True)
    st.caption("Certificate warnings go out at 30, 7 and 1 days. Expiry fails the control immediately, without waiting for the daily risk run.")


# ---------------------------------------------------------------------------
# Compliance assistant (4.5)
# ---------------------------------------------------------------------------
SUGGESTED = ["Why was my evidence rejected?", "What evidence do I need before closing a P1 task?", "Why hasn't my estimate fallen?",
             "Can I patch during the month-end change freeze?", "Please close task T-0002 for me", "Who decides if nobody responds?"]


def page_assistant():
    show_flash()
    s = S()
    st.title("Compliance assistant")
    st.caption("Answers come only from approved documents and cite the clause. It cannot close tasks, approve exceptions or change ratings.")
    notes("assistant")
    acting_line()
    key = st.secrets.get("ANTHROPIC_API_KEY") if _has_secrets() else None
    model = st.secrets.get("ANTHROPIC_MODEL", "claude-haiku-5-5") if _has_secrets() else None
    tabs = st.tabs(["Ask", "Knowledge base", "Interaction log", "Evaluation"])
    with tabs[0]:
        c = st.columns([2, 1])
        tasks = sorted(s["tasks"].values(), key=lambda t: t["id"])
        labels = {None: "No case", **{t["id"]: task_label(t) for t in tasks}}
        case_id = c[0].selectbox("Case context (optional)", list(labels), index=(1 + default_task_index(tasks)) if tasks else 0,
                                 format_func=labels.get, key="as_case")
        case = s["tasks"][case_id] if case_id else None
        mode = c[1].radio("Answer mode", ["Grounded retrieval", "Claude, grounded"], index=0,
                          help="Claude mode needs ANTHROPIC_API_KEY in Streamlit secrets. Retrieval and referral rules run first in both modes.",
                          disabled=not key)
        cols = st.columns(3)
        for i, q in enumerate(SUGGESTED):
            if cols[i % 3].button(q, key=f"sq_{i}", width="stretch"):
                A.answer(s, me(), q, tid=case["id"] if case else None, use_llm=(mode == "Claude, grounded"), api_key=key, model=model)
                st.rerun()
        with st.form("ask", clear_on_submit=True):
            q = st.text_input("Your question", "")
            if st.form_submit_button("Ask") and q.strip():
                A.answer(s, me(), q, tid=case["id"] if case else None, use_llm=(mode == "Claude, grounded"), api_key=key, model=model)
                st.rerun()
        for e in reversed(s["assistant_log"][-8:]):
            with st.chat_message("user", avatar=":material/person:"):
                st.markdown(esc(f"**{nm(e['persona'])}**, {short(e['at'])}: {e['question']}"))
            with st.chat_message("assistant", avatar=":material/policy:"):
                st.markdown(esc(e["answer"]))
                meta = []
                if e["citations"]:
                    meta.append("Cited: " + "; ".join(e["citations"]))
                if e["referred"]:
                    meta.append(f"Referred to Compliance ({e['reason']})")
                meta.append(e["mode"])
                st.caption(". ".join(meta))
    with tabs[1]:
        table(pd.DataFrame([{"Clause": f"{c['doc']} §{c['section']}", "Document": c["title"], "Version": c["version"],
                             "Heading": c["heading"], "Text": c["text"]} for c in sd.KNOWLEDGE_BASE]), wrap=True)
        st.caption("Internal policies are synthetic. Regulatory entries paraphrase the FTC Safeguards Rule and SEC disclosure rules cited in the report.")
    with tabs[2]:
        if s["assistant_log"]:
            table(pd.DataFrame([{"At": short(e["at"]), "Who": nm(e["persona"]), "Question": e["question"], "Case": e["task"] or "-",
                                 "Cited": "; ".join(e["citations"]) or "-", "Referred": "Yes" if e["referred"] else "No", "Mode": e["mode"]}
                                for e in s["assistant_log"]]))
        else:
            st.write("No questions yet.")
    with tabs[3]:
        st.caption("Scored against questions whose answers Compliance has approved: does it cite the right clause, and does it refer when it should?")
        if st.button("Run evaluation"):
            st.session_state.eval_results = A.run_evaluation(s)
        res = st.session_state.get("eval_results")
        if res:
            passed = sum(r["Pass"] for r in res)
            st.metric("Test questions passed", f"{passed} of {len(res)}")
            df = pd.DataFrame(res)
            for col in ("Citation correct", "Referral correct", "Pass"):
                df[col] = df[col].map({True: "Passed", False: "Failed"})
            table(df, ["Citation correct", "Referral correct", "Pass"])


def _has_secrets():
    try:
        return "ANTHROPIC_API_KEY" in st.secrets
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Learning centre (4.6)
# ---------------------------------------------------------------------------
def page_learning():
    show_flash()
    s = S()
    st.title("Learning centre")
    st.caption("Short scenario modules. Verifying fixes and approving risk are locked until the relevant module is passed at its current version.")
    notes("learning")
    acting_line()
    pid = me()
    r = E.role(s, pid)
    relevant = [m for m, d in sd.MODULES.items() if r in d["for_roles"]] or list(sd.MODULES)
    mid = st.selectbox("Module", relevant + [m for m in sd.MODULES if m not in relevant],
                       format_func=lambda m: f"{m}  {sd.MODULES[m]['title']}", key="lc_mod")
    mod = sd.MODULES[mid]
    rec = s["training"].get(pid, {}).get(mid)
    cur = s["module_versions"][mid]
    status = "Trained" if E.trained(s, pid, mid) else ("Refresher due" if rec and rec["passed"] else "Not trained")
    st.markdown(f"Version {cur}. Your status: {badge(status)}" + (f"  Grants: {mod['gates']}." if mod["gates"] else ""))
    with st.container(border=True):
        st.markdown(f"**Scenario.** {mod['scenario']}")
        with st.form(f"quiz_{mid}"):
            answers = []
            for i, q in enumerate(mod["questions"]):
                answers.append(st.radio(f"{i + 1}. {q['q']}", range(len(q["options"])), format_func=lambda k, q=q: q["options"][k],
                                        index=None, key=f"q_{mid}_{i}"))
            if st.form_submit_button("Submit answers"):
                score = sum(1 for a, q in zip(answers, mod["questions"]) if a == q["answer"])
                passed = E.record_training(s, pid, mid, score)
                st.session_state.flash = ("ok" if passed else "blocked",
                                          f"{score} of 3 correct. " + ("Passed: rights granted." if passed else "All three are needed to pass; try again."))
                st.rerun()

    st.subheader("Approval rights across the organisation")
    rows = []
    for p, mod_id, ok in E.approvers_trained(s):
        held = s["training"].get(p, {}).get(mod_id)
        rows.append({"Person": nm(p), "Role": E.role(s, p), "Module": mod_id, "Version held": held["version"] if held else "-",
                     "Current version": s["module_versions"][mod_id],
                     "Status": "Trained" if ok else ("Refresher due" if held and held["passed"] else "Not trained")})
    table(pd.DataFrame(rows), ["Status"])
    with st.expander("Publish a material procedure change"):
        st.caption("A material change raises the module version. Everyone holding the old version needs a refresher before approving again.")
        m2 = st.selectbox("Module to update", list(sd.MODULES), key="lc_pub")
        if st.button("Publish change"):
            do(E.publish_procedure_change, me(), m2, ok=f"{m2} updated. Approvers on the old version are now blocked until they refresh.")


# ---------------------------------------------------------------------------
# Audit and evaluation (4.7, 4.8)
# ---------------------------------------------------------------------------
def page_audit():
    show_flash()
    s = S()
    st.title("Audit and evaluation")
    notes("audit")
    tabs = st.tabs(["Audit trail", "Internal audit sample", "Committee pack", "2017 versus this design", "Evaluation"])
    with tabs[0]:
        df = pd.DataFrame([{"At": e["at"], "Who": nm(e["actor"]), "Action": e["action"], "Object": e["object"], "Outcome": e["outcome"],
                            "Detail": e["detail"]} for e in s["audit"]])
        outcomes = st.multiselect("Outcome", ["Done", "Blocked", "System"], default=["Done", "Blocked", "System"])
        view = df[df["Outcome"].isin(outcomes)].sort_values("At", ascending=False)
        view = view.assign(At=view["At"].dt.strftime("%d %b %H:%M"))
        table(view, ["Outcome"], height=420)
        st.download_button("Download audit trail (CSV)", df.to_csv(index=False), "audit_trail.csv", "text/csv")
        st.caption("Blocked attempts are recorded as well as completed actions, so audit can see who tried to bypass a control.")
    with tabs[1]:
        seed = st.number_input("Sampling seed", 1, 999, 7)
        n = st.slider("Sample size", 1, 10, 5)
        sample = E.audit_sample(s, n, int(seed))
        rows = []
        for kind, tid_, obj in sample:
            if kind == "Closed task":
                detail = f"Closed {short(obj['closed_at'])} by {nm(obj['verified_by'])}; {len(obj['submissions'])} submission(s)"
                ok = "Verified" if obj["verified_by"] else "Failed"
            elif kind == "Treatment decision":
                detail = f"{obj['option']} by {nm(obj['by'])}, due {short(obj['due_at'])}"
                ok = obj["status"]
            else:
                detail = f"{obj['id']} requested by {nm(obj['requested_by'])}, approved by {nm(obj['approved_by'])}"
                ok = obj["status"]
            rows.append({"Type": kind, "Task": tid_, "Detail": detail, "Status": ok})
        if rows:
            table(pd.DataFrame(rows), ["Status"])
        else:
            st.write("Nothing to sample yet.")
        st.caption("Repeated findings go to the Audit Committee; internal audit also commissions periodic independent validation of maturity claims.")
    with tabs[2]:
        pack = committee_pack(s)
        st.markdown(esc(pack))
        st.download_button("Download committee pack", pack, "committee_pack.md", "text/markdown", key="pack2")
    with tabs[3]:
        _comparison(s)
    with tabs[4]:
        _evaluation(s)


def _first(s, pred):
    for e in s["audit"]:
        if pred(e):
            return e
    return None


def _comparison(s):
    acis = next((t for t in s["tasks"].values() if t["asset_id"] == "A-ACIS" and t["advisory"] == SC.STRUTS), None)
    rows = [("Advisory reaches the right person",
             "9 Mar: email to an outdated list of 400+ staff; the ACIS developer was not on it (PSI, 2019).",
             f"{short(acis['alerted_at'])}: P1 task assigned to {nm(acis['owner'])} and deputy {nm(acis['deputy'])}." if acis else "Not yet ingested.")]
    if acis:
        esc = "; ".join(f"level {e['level']} at {short(e['at'])}" for e in acis["escalations"]) or "none needed"
        rows.append(("Inaction has consequences", "Patching relied on an 'honor system'; no follow-up.", f"Escalations: {esc}."))
        rej = [x for x in acis["submissions"] if x["status"] == "Rejected by system"]
        rows.append(("A scan that missed the app is not closure",
                     "15 Mar: scan failed to flag ACIS and nobody checked the patch.",
                     f"{len(rej)} submission(s) rejected for scope or evidence gaps." + (f" Verified closed {short(acis['closed_at'])} by {nm(acis['verified_by'])}." if acis["closed_at"] else " Not yet verified.")))
        if acis["closed_at"]:
            lead = sd.ATTACK_DATE_2017 - acis["closed_at"]
            rows.append(("Before the attackers arrived", "13 May: attackers first access ACIS.", f"Exposure closed {lead.days} days earlier."))
    cert = _first(s, lambda e: e["object"] == "SSLI-CONSUMER" and "expired" in e["detail"].lower())
    rows.append(("A blind sensor is visible", "Inspection certificate had expired about 19 months earlier; intrusion ran for 76 days.",
                 f"Expiry alerted immediately at {short(cert['at'])} and control health failed." if cert else "Warnings issued at 30 and 7 days; expiry not reached yet in this step."))
    table(pd.DataFrame(rows, columns=["Question", "Equifax 2017", "This replay"]), wrap=True)
    st.caption("2017 facts as documented in the report (PSI, 2019; House Oversight Committee, 2018). Replay values are computed live from the current step.")


def _evaluation(s):
    st.caption("Measures from the report's evaluation plan, computed from the current simulated state.")
    found, expected = 0, 0
    for adv in s["ingested"]:
        for aid in sd.GROUND_TRUTH_AFFECTED.get(adv, set()):
            expected += 1
            if any(t["asset_id"] == aid and t["advisory"] == adv and t["owner"] == s["assets"][aid]["owner"] for t in s["tasks"].values()):
                found += 1
    unsafe = sum(1 for r in s["triage"] if r["category"] in (E.INVESTIGATE, E.POTENTIAL) and not r["task"])
    acks = [(t["acknowledged_at"] - t["alerted_at"]).total_seconds() / 3600 for t in s["tasks"].values()
            if t["acknowledged_at"] and t["priority"] == "P1" and t["kind"] != "Ownership defect"]
    q = E.closure_quality(s)
    trained = E.approvers_trained(s)
    c = st.columns(3)
    c[0].metric("Affected assets assigned to the named owner", f"{found} of {expected}" if expected else "-")
    c[1].metric("Unknown or stale assets left without a task", unsafe)
    c[2].metric("Median P1 acknowledgement", f"{median(acks):.1f} h" if acks else "-")
    c = st.columns(3)
    c[0].metric("Closures verified within deadline", f"{q['within_sla']} of {q['closed'] + q['late_open']}" if q["closed"] + q["late_open"] else "-")
    c[1].metric("Unsupported closure attempts blocked", q["rejected_submissions"] + q["blocked_approvals"])
    c[2].metric("Approvers trained on current version", f"{sum(1 for _, _, ok in trained if ok)} of {len(trained)}")
    st.subheader("Planned A/B exercise")
    st.markdown(
        "Compare this dashboard with a manual email-and-spreadsheet workflow on matched synthetic cases. "
        "The main outcome is the share of cases correctly handled within the simulated deadline; secondary outcomes are "
        "acknowledgement time, unsupported closures accepted, and agreement between two assessors rating the same exposures. "
        "The assistant is evaluated separately on the Compliance-approved test set (see the Compliance assistant page). "
        "No A/B results are shown here because the exercise has not been run.")
