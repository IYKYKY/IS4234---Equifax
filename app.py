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
import ui as UI

st.set_page_config(page_title="Equifax vulnerability assurance prototype", page_icon=":material/verified_user:", layout="wide")

UI.apply_theme()


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
nav = st.navigation({
    "Workspace": pages[:2],
    "Manage exposure": pages[2:6],
    "Assurance & oversight": pages[6:],
})
PAGE_BY_TITLE = {p.title: p for p in pages}
st.session_state.ui_pages = PAGE_BY_TITLE
STEP_KEYS = [s["key"] for s in SC.SCENARIOS]


def go_step(delta):
    """Load the neighbouring demo step and open the page it is best viewed on."""
    i = STEP_KEYS.index(st.session_state.scenario) + delta
    if 0 <= i < len(STEP_KEYS):
        st.session_state.scenario = STEP_KEYS[i]
        load_scenario()
        st.session_state.goto = SC.BY_KEY[STEP_KEYS[i]]["page"]


goto = st.session_state.pop("goto", None)
if goto in PAGE_BY_TITLE:
    st.switch_page(PAGE_BY_TITLE[goto])

with st.sidebar:
    st.markdown('<div class="sidebar-label">DEMONSTRATION WORKSPACE</div>', unsafe_allow_html=True)
    st.selectbox("Demo step", STEP_KEYS, key="scenario", on_change=load_scenario,
                 format_func=lambda k: SC.BY_KEY[k]["label"])
    pos = STEP_KEYS.index(st.session_state.scenario)
    c = st.columns(2)
    c[0].button("Back", icon=":material/arrow_back:", width="stretch", disabled=pos == 0,
                on_click=go_step, args=(-1,), help="Loads the previous demo step and opens its page.")
    c[1].button("Next", icon=":material/arrow_forward:", width="stretch", disabled=pos == len(STEP_KEYS) - 1,
                on_click=go_step, args=(1,), help="Loads the next demo step and opens its page.")
    spec = SC.BY_KEY[st.session_state.scenario]
    st.caption(f"{spec['what']} Best viewed on: {spec['page']}.")
    S = st.session_state.sim
    st.selectbox("Acting as", list(S["people"]), key="actor",
                 format_func=lambda p: f"{S['people'][p]['name']} ({S['people'][p]['role']})")
    st.markdown(f"<div class='simclock'>{S['now']:%a %d %b %Y, %H:%M} ET</div>", unsafe_allow_html=True)
    with st.expander("Simulation controls", expanded=False):
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

UI.workspace_header()
nav.run()
UI.footer()

