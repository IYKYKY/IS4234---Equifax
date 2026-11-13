"""Shared Equifax-inspired presentation; no permissions or control logic lives here."""
from base64 import b64encode
from html import escape
from pathlib import Path

import streamlit as st

ROOT = Path(__file__).resolve().parent
BURGUNDY = "#981E32"
CHARCOAL = "#333E48"
TEAL = "#007298"
CHART_FONT = "Open Sans, Arial, sans-serif"


def stylesheet():
    # Bundle the source website's typeface so demos do not rely on Google Fonts
    # or a participant's browser being able to contact a third-party font CDN.
    faces = []
    for name, weight in (("Regular", 400), ("Semibold", 600), ("Bold", 700)):
        data = b64encode((ROOT / "assets" / "fonts" / f"OpenSans-{name}.woff").read_bytes()).decode("ascii")
        faces.append(f"@font-face{{font-family:'Open Sans';src:url(data:font/woff;base64,{data}) format('woff');font-weight:{weight};font-style:normal;font-display:swap}}")
    return "<style>" + "\n".join(faces) + (ROOT / "assets" / "theme.css").read_text() + "</style>"


def apply_theme():
    st.markdown(stylesheet(), unsafe_allow_html=True)
    st.logo(str(ROOT / "assets" / "equifax-logo.svg"), size="large")


def workspace_header():
    st.markdown(
        '<div class="workspace-header"><div><span class="workspace-name">Vulnerability Assurance</span>'
        '<span class="workspace-context">Governance · Risk · Compliance</span></div>'
        '<span class="prototype-tag">CONSULTING PROTOTYPE</span></div>',
        unsafe_allow_html=True,
    )


def page_heading(title, section):
    st.markdown(f'<div class="eyebrow">{escape(section)}</div>', unsafe_allow_html=True)
    st.title(title)


def overview_hero():
    st.markdown('''<section class="assurance-hero" aria-label="Vulnerability assurance introduction">
<div class="hero-copy"><div class="eyebrow">DATA &amp; IT GOVERNANCE</div>
<h1>Clear ownership.<br>Confident assurance.</h1>
<p>Every known vulnerability reaches a named owner.<br class="desktop-break"> Every closure is backed by independently verified evidence.</p>
<span class="hero-caption">A proposed control framework for the Equifax case</span></div>
<div class="assurance-model" aria-label="Three lines of defence">
<div class="model-label">ACCOUNTABILITY AT EVERY STEP</div>
<div class="model-step"><span class="model-number">01</span><div><strong>Own &amp; remediate</strong><span>Application Operations · First line</span></div></div>
<div class="model-step"><span class="model-number">02</span><div><strong>Independently verify</strong><span>Security &amp; Compliance · Second line</span></div></div>
<div class="model-step"><span class="model-number">03</span><div><strong>Challenge &amp; oversee</strong><span>Internal Audit · Third line</span></div></div>
</div></section>''', unsafe_allow_html=True)


def capability_cards():
    cards = (
        ("01", "Named accountability", "Match advisories to assets, assign an owner and deputy, and escalate missed deadlines."),
        ("02", "Evidence-led closure", "Require an in-scope scan, a fixed running version and an independent, trained reviewer."),
        ("03", "Visible residual risk", "Track monitoring failures separately and link risk estimates to verified control evidence."),
    )
    with st.container():
        columns = st.columns(3)
        for column, (number, title, body) in zip(columns, cards):
            with column:
                st.markdown(f'<div class="capability-card"><span class="card-number">{number}</span><h3>{title}</h3><p>{body}</p></div>', unsafe_allow_html=True)


def footer():
    st.markdown('<footer class="workspace-footer"><strong>IS4234 · Group 20</strong><span>Equifax case study · Synthetic data · Academic consulting prototype</span></footer>', unsafe_allow_html=True)
