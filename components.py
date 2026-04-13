"""Shared UI components for 80 — IAM Audit Tool. Dark premium theme."""

import streamlit as st

GLOBAL_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap');

:root {
  --navy:     #080f1e;
  --navy-2:   #0d1628;
  --navy-3:   #111f38;
  --navy-4:   #1a2f52;
  --navy-5:   #1F3864;
  --ice:      #4d9fff;
  --ice-glow: rgba(77,159,255,0.12);
  --white:    #ffffff;
  --off:      #c8d8ef;
  --muted:    #5a7394;
  --green:    #00d4a0;
  --red:      #ff4d5e;
  --amber:    #ffb347;
  --border:   rgba(255,255,255,0.06);
  --border-2: rgba(255,255,255,0.11);
}

/* ── KILL ALL STREAMLIT CHROME ──────────────────────────────────────────── */
#MainMenu, footer, [data-testid="stDecoration"],
[data-testid="stToolbar"], [data-testid="stStatusWidget"] {
  display: none !important;
}

/* ── FULL APP DARK ──────────────────────────────────────────────────────── */
html, body,
[data-testid="stAppViewContainer"],
[data-testid="stApp"],
.main, section.main {
  background: var(--navy) !important;
  color: var(--off) !important;
  font-family: 'Inter', system-ui, sans-serif !important;
}

.block-container {
  padding-top: 1.5rem !important;
  padding-left: 2.5rem !important;
  padding-right: 2.5rem !important;
  max-width: 1100px !important;
}

/* ── SIDEBAR ────────────────────────────────────────────────────────────── */
[data-testid="stSidebar"],
[data-testid="stSidebar"] > div:first-child {
  background: var(--navy-2) !important;
  border-right: 1px solid var(--border) !important;
}
[data-testid="stSidebarNav"] a {
  color: var(--muted) !important;
  font-size: 13px !important;
  font-weight: 500 !important;
  border-radius: 8px !important;
  padding: 9px 14px !important;
}
[data-testid="stSidebarNav"] a:hover,
[data-testid="stSidebarNav"] a[aria-current="page"] {
  background: var(--ice-glow) !important;
  color: var(--ice) !important;
}

/* ── HEADINGS ───────────────────────────────────────────────────────────── */
h1,h2,h3,h4,h5,h6 {
  color: var(--white) !important;
  font-family: 'Inter', sans-serif !important;
  font-weight: 800 !important;
  letter-spacing: -0.025em !important;
}
p, li, div { color: var(--off) !important; font-family: 'Inter', sans-serif !important; }

/* ── METRIC CARDS ───────────────────────────────────────────────────────── */
[data-testid="stMetric"] {
  background: var(--navy-3) !important;
  border: 1px solid var(--border-2) !important;
  border-radius: 14px !important;
  padding: 22px 24px !important;
}
[data-testid="stMetricLabel"] p {
  color: var(--muted) !important;
  font-size: 11px !important;
  font-weight: 600 !important;
  letter-spacing: 0.08em !important;
  text-transform: uppercase !important;
}
[data-testid="stMetricValue"] {
  color: var(--white) !important;
  font-size: 30px !important;
  font-weight: 900 !important;
  letter-spacing: -0.04em !important;
}
[data-testid="stMetricDelta"] { display:none !important; }

/* ── BUTTONS ────────────────────────────────────────────────────────────── */
.stButton > button {
  background: var(--navy-4) !important;
  color: var(--off) !important;
  border: 1px solid var(--border-2) !important;
  border-radius: 8px !important;
  font-family: 'Inter', sans-serif !important;
  font-weight: 600 !important;
  font-size: 13px !important;
  transition: all 0.18s !important;
}
.stButton > button:hover {
  border-color: var(--ice) !important;
  color: var(--white) !important;
}
.stButton > button[kind="primary"] {
  background: var(--ice) !important;
  border-color: var(--ice) !important;
  color: var(--navy) !important;
  font-weight: 700 !important;
}

/* ── PAGE LINK (nav) ────────────────────────────────────────────────────── */
[data-testid="stPageLink"] a,
[data-testid="stPageLink"] p {
  color: var(--muted) !important;
  font-size: 13px !important;
  font-weight: 600 !important;
  text-decoration: none !important;
  font-family: 'Inter', sans-serif !important;
}

/* ── INPUTS ─────────────────────────────────────────────────────────────── */
.stSelectbox > div > div,
.stTextInput > div > div > input,
.stNumberInput > div > div > input {
  background: var(--navy-3) !important;
  color: var(--white) !important;
  border: 1px solid var(--border-2) !important;
  border-radius: 8px !important;
}

/* ── FILE UPLOADER ──────────────────────────────────────────────────────── */
[data-testid="stFileUploader"] {
  background: var(--navy-3) !important;
  border: 1px dashed var(--border-2) !important;
  border-radius: 14px !important;
}

/* ── EXPANDER ───────────────────────────────────────────────────────────── */
[data-testid="stExpander"] {
  background: var(--navy-3) !important;
  border: 1px solid var(--border) !important;
  border-radius: 10px !important;
}

/* ── TABS ───────────────────────────────────────────────────────────────── */
[data-baseweb="tab-list"] {
  background: var(--navy-2) !important;
  border-bottom: 1px solid var(--border) !important;
}
[data-baseweb="tab"] {
  color: var(--muted) !important;
  font-weight: 600 !important;
  font-size: 13px !important;
  font-family: 'Inter', sans-serif !important;
}
[aria-selected="true"][data-baseweb="tab"] {
  color: var(--ice) !important;
  background: var(--ice-glow) !important;
}

/* ── ALERTS ─────────────────────────────────────────────────────────────── */
.stSuccess { background: rgba(0,212,160,0.08) !important; border-left: 3px solid var(--green) !important; border-radius: 8px !important; }
.stWarning { background: rgba(255,179,71,0.08) !important; border-left: 3px solid var(--amber) !important; border-radius: 8px !important; }
.stError   { background: rgba(255,77,94,0.08)  !important; border-left: 3px solid var(--red)   !important; border-radius: 8px !important; }
.stInfo    { background: var(--ice-glow)        !important; border-left: 3px solid var(--ice)   !important; border-radius: 8px !important; }

/* ── PROGRESS ───────────────────────────────────────────────────────────── */
[data-testid="stProgressBar"] > div { background: var(--navy-3) !important; }
[data-testid="stProgressBar"] > div > div { background: var(--ice) !important; }

/* ── DIVIDER ────────────────────────────────────────────────────────────── */
hr { border-color: var(--border) !important; opacity:1 !important; }

/* ── SCROLLBAR ──────────────────────────────────────────────────────────── */
::-webkit-scrollbar { width:5px; height:5px; }
::-webkit-scrollbar-track { background: var(--navy-2); }
::-webkit-scrollbar-thumb { background: var(--navy-5); border-radius:3px; }

/* ── CODE ───────────────────────────────────────────────────────────────── */
code, pre {
  background: var(--navy-2) !important;
  color: var(--ice) !important;
  border: 1px solid var(--border) !important;
  border-radius: 6px !important;
}
</style>
"""


def inject_css():
    st.markdown(GLOBAL_CSS, unsafe_allow_html=True)


def render_header(active="Home"):
    """
    Pure Streamlit header — no HTML, no iframes, no routing issues.
    Uses st.columns for layout. Works on Streamlit Cloud.
    """
    inject_css()

    left, mid, right = st.columns([2, 4, 2])

    with left:
        st.markdown("""
<div style="display:flex;align-items:center;gap:12px;padding:8px 0;">
  <div style="
    width:40px;height:40px;
    background:#1F3864;
    border-radius:10px;
    display:flex;align-items:center;justify-content:center;
    border:1px solid rgba(255,255,255,0.15);
    flex-shrink:0;
  ">
    <span style="font-size:18px;font-weight:900;color:#fff;
      letter-spacing:-1px;font-family:'Inter',sans-serif;">80</span>
  </div>
  <div>
    <div style="font-size:16px;font-weight:800;color:#ffffff;
      letter-spacing:-0.03em;font-family:'Inter',sans-serif;line-height:1;">80</div>
    <div style="font-size:9px;font-weight:600;color:#4d9fff;
      letter-spacing:0.12em;text-transform:uppercase;
      font-family:'Inter',sans-serif;margin-top:2px;">IAM Audit Tool</div>
  </div>
</div>
""", unsafe_allow_html=True)

    with mid:
        # Native st.page_link — the ONLY reliable nav on Streamlit Cloud
        n1, n2, n3, n4 = st.columns(4)
        with n1:
            st.page_link("pages/home.py",       label="Home",       icon="🏠")
        with n2:
            st.page_link("pages/tool.py",        label="Tool",       icon="🛡️")
        with n3:
            st.page_link("pages/about.py",       label="About",      icon="📋")
        with n4:
            st.page_link("pages/how_to_use.py",  label="How to Use", icon="📖")

    with right:
        st.markdown("""
<div style="text-align:right;padding:8px 0;">
  <span style="font-size:11px;color:rgba(255,255,255,0.2);
    font-family:'Inter',sans-serif;letter-spacing:0.04em;">IAM · 2026</span>
</div>
""", unsafe_allow_html=True)

    st.markdown("""
<div style="border-bottom:1px solid rgba(255,255,255,0.07);margin:4px 0 28px;"></div>
""", unsafe_allow_html=True)


def render_sidebar_brand():
    """Clean sidebar brand — logo and name only."""
    inject_css()
    st.markdown("""
<div style="padding:16px 0 20px;border-bottom:1px solid rgba(255,255,255,0.06);
  margin-bottom:16px;">
  <div style="display:flex;align-items:center;gap:11px;">
    <div style="
      width:36px;height:36px;background:#1F3864;border-radius:9px;
      display:flex;align-items:center;justify-content:center;
      border:1px solid rgba(255,255,255,0.14);flex-shrink:0;
    ">
      <span style="font-size:16px;font-weight:900;color:#fff;
        font-family:'Inter',sans-serif;letter-spacing:-1px;">80</span>
    </div>
    <div>
      <div style="font-size:15px;font-weight:800;color:#ffffff;
        font-family:'Inter',sans-serif;letter-spacing:-0.03em;">80</div>
      <div style="font-size:9px;font-weight:600;color:#4d9fff;
        letter-spacing:0.1em;text-transform:uppercase;
        font-family:'Inter',sans-serif;margin-top:2px;">IAM Audit Tool</div>
    </div>
  </div>
</div>
""", unsafe_allow_html=True)


def stat_card(number, label, sublabel="", color="#4d9fff"):
    return f"""
<div style="
  background:#111f38;border:1px solid rgba(255,255,255,0.07);
  border-radius:14px;padding:24px 20px;text-align:center;
  border-top:2px solid {color};
">
  <div style="font-size:36px;font-weight:900;color:#ffffff;
    letter-spacing:-0.04em;font-family:'Inter',sans-serif;line-height:1;">{number}</div>
  <div style="font-size:11px;font-weight:700;color:{color};
    letter-spacing:0.07em;text-transform:uppercase;
    font-family:'Inter',sans-serif;margin-top:8px;">{label}</div>
  {f'<div style="font-size:10px;color:#5a7394;font-family:Inter,sans-serif;margin-top:4px;">{sublabel}</div>' if sublabel else ''}
</div>"""


def section_header(title, subtitle=""):
    sub = f'<div style="font-size:13px;color:#5a7394;font-family:Inter,sans-serif;margin-top:5px;">{subtitle}</div>' if subtitle else ''
    return f"""
<div style="margin:40px 0 20px;">
  <div style="display:flex;align-items:center;gap:12px;margin-bottom:6px;">
    <div style="width:3px;height:22px;background:#4d9fff;border-radius:2px;flex-shrink:0;"></div>
    <div style="font-size:19px;font-weight:800;color:#ffffff;
      letter-spacing:-0.025em;font-family:Inter,sans-serif;">{title}</div>
  </div>
  {sub}
</div>"""

