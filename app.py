"""
app.py - entry point.  Run locally with:  streamlit run app.py

The sidebar holds the presenter's controls: which demo step is loaded, which
persona you are acting as, and the simulated clock. No login: personas are a
demo switcher, and every permission is still enforced in engine.py.
"""
from datetime import timedelta

import streamlit as st

import engine as E
import scenarios as SC
import views as V

st.set_page_config(page_title="Equifax vulnerability assurance prototype", page_icon=":material/verified_user:", layout="wide")

CSS = """
<style>
h1 { font-weight: 700; letter-spacing: -0.01em; max-width: 30ch; line-height: 1.15; }
.clock { border: 1px solid #D5DBE3; border-radius: 6px; padding: 14px 16px 10px; margin: 10px 0 12px; background: #FFFFFF; }
.clock-head { display: flex; align-items: baseline; gap: 12px; flex-wrap: wrap; margin-bottom: 10px; }
.clock-big { font-size: 2.1rem; font-weight: 700; font-variant-numeric: tabular-nums; color: #13233F; line-height: 1; }
.clock-sub { color: #56637A; }
.clock-right { margin-left: auto; font-weight: 600; font-variant-numeric: tabular-nums; }
.clock.running .clock-right { color: #1F4A8A; }
.clock.overdue .clock-right, .clock.overdue .clock-big { color: #9B2117; }
.clock.closed .clock-right { color: #1F6B3F; }
.track { position: relative; height: 10px; background: #EDF0F4; border-radius: 5px; }
.fill { position: absolute; left: 0; top: 0; bottom: 0; border-radius: 5px; background: #2457A6; }
.clock.overdue .fill { background: #B3261E; }
.clock.closed .fill { background: #2F7D4E; }
.deadline { position: absolute; top: -5px; width: 2px; height: 20px; background: #13233F; }
.rungs { display: flex; margin-top: 6px; }
.rung { flex: 1; text-align: right; padding: 4px 0 0 6px; border-right: 2px solid #D5DBE3; padding-right: 6px; min-width: 0; }
.rung .rt { font-weight: 700; font-variant-numeric: tabular-nums; }
.rung .rw { font-size: 0.78rem; color: #56637A; overflow-wrap: anywhere; }
.rung .rs { font-size: 0.78rem; font-variant-numeric: tabular-nums; }
.rung.fired { border-right-color: #B3261E; }
.rung.fired .rs { color: #9B2117; font-weight: 600; }
.rung.skipped { opacity: 0.55; }
.steps { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; margin: 4px 0 8px; font-size: 0.9rem; }
.step { padding: 2px 10px; border-radius: 999px; border: 1px solid #D5DBE3; color: #56637A; }
.step.done { background: #EDF0F4; color: #13233F; }
.step.now { background: #13233F; color: #FFFFFF; border-color: #13233F; font-weight: 600; }
.sep { color: #9AA4B2; }
.simclock { font-variant-numeric: tabular-nums; font-weight: 700; font-size: 1.05rem; color: #13233F; }
@media (max-width: 640px) { .rungs { flex-wrap: wrap; } .rung { flex: 0 0 33%; } .clock-right { margin-left: 0; } }
</style>
"""
st.markdown(CSS, unsafe_allow_html=True)


def load_scenario():
    key = st.session_state.scenario
    st.session_state.sim = SC.build(key)
    st.session_state.actor = SC.BY_KEY[key]["persona"]
    st.session_state.pop("eval_results", None)
    for k in ("trk_sel", "risk_task", "dash_drill", "as_case"):
        st.session_state.pop(k, None)


if "sim" not in st.session_state:
    # Optional deep link for presenters, e.g. ?step=s7&as=aisha
    qp = st.query_params
    st.session_state.scenario = qp.get("step") if qp.get("step") in SC.BY_KEY else "s2"
    st.session_state.show_notes = qp.get("notes", "on") != "off"
    load_scenario()
    if qp.get("as") in st.session_state.sim["people"]:
        st.session_state.actor = qp.get("as")

pages = [
    st.Page(V.page_overview, title="Start here", icon=":material/flag:", default=True),
    st.Page(V.page_dashboard, title="Dashboard", icon=":material/space_dashboard:", url_path="dashboard"),
    st.Page(V.page_allocator, title="Alert allocator", icon=":material/call_split:", url_path="allocator"),
    st.Page(V.page_tracker, title="Resolution tracker", icon=":material/timer:", url_path="tracker"),
    st.Page(V.page_risk, title="Risk calculator", icon=":material/calculate:", url_path="risk"),
    st.Page(V.page_controls, title="Control health", icon=":material/sensors:", url_path="controls"),
    st.Page(V.page_assistant, title="Compliance assistant", icon=":material/policy:", url_path="assistant"),
    st.Page(V.page_learning, title="Learning centre", icon=":material/school:", url_path="learning"),
    st.Page(V.page_audit, title="Audit and evaluation", icon=":material/fact_check:", url_path="audit"),
]
nav = st.navigation(pages)

with st.sidebar:
    st.selectbox("Demo step", [s["key"] for s in SC.SCENARIOS], key="scenario", on_change=load_scenario,
                 format_func=lambda k: SC.BY_KEY[k]["label"])
    spec = SC.BY_KEY[st.session_state.scenario]
    st.caption(f"{spec['what']} Best viewed on: {spec['page']}.")
    S = st.session_state.sim
    st.selectbox("Acting as", list(S["people"]), key="actor",
                 format_func=lambda p: f"{S['people'][p]['name']} ({S['people'][p]['role']})")
    st.markdown(f"<div class='simclock'>{S['now']:%a %d %b %Y, %H:%M} ET</div>", unsafe_allow_html=True)
    nxt, kind = E.next_interesting_time(S)
    c = st.columns(3)
    if c[0].button("+1 h", width="stretch"):
        E.advance(S, timedelta(hours=1)); st.rerun()
    if c[1].button("+4 h", width="stretch"):
        E.advance(S, timedelta(hours=4)); st.rerun()
    if c[2].button("+1 day", width="stretch"):
        E.advance(S, timedelta(days=1)); st.rerun()
    if st.button("Jump to next escalation or alert", width="stretch", disabled=nxt is None,
                 help=f"Next scheduled event: {nxt:%d %b %H:%M}" if nxt else "Nothing scheduled"):
        E.advance_to(S, nxt + timedelta(minutes=1)); st.rerun()
    if st.button("Run daily recalculation now", width="stretch", help="The job normally runs at 02:00. Use this to show the estimate move without waiting."):
        E.run_daily_job(S, actor=st.session_state.actor); st.rerun()
    st.button("Reset this step", width="stretch", on_click=load_scenario)
    st.toggle("Presenter notes", key="show_notes")
    st.caption("Synthetic data. Prototype for IS4234 Group 20.")

nav.run()
