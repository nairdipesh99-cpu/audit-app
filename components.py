"""Shared UI components for 80 — IAM Audit Tool. Dark premium theme v2."""

import streamlit as st
import streamlit.components.v1 as _stc

GLOBAL_CSS = """
<style>
/* Inter font — system fallback if CDN blocked */

:root {
  --navy:      #080f1e;
  --navy-2:    #0d1628;
  --navy-3:    #111f38;
  --navy-4:    #1a2f52;
  --navy-5:    #1F3864;
  --ice:       #4d9fff;
  --ice-dim:   #1a3a6e;
  --ice-glow:  rgba(77,159,255,0.12);
  --white:     #ffffff;
  --off:       #c8d8ef;
  --muted:     #5a7394;
  --green:     #00d4a0;
  --red:       #ff4d5e;
  --amber:     #ffb347;
  --border:    rgba(255,255,255,0.06);
  --border-2:  rgba(255,255,255,0.11);
  --radius:    10px;
  --radius-lg: 16px;
}

/* ── KILL STREAMLIT DEFAULT CHROME ──────────────────────────────────────── */
#MainMenu, footer, [data-testid="stDecoration"],
[data-testid="stToolbar"], [data-testid="stStatusWidget"],
header[data-testid="stHeader"],
[data-testid="stSidebarNavItems"],
[data-testid="stPageLink"],
section[data-testid="stSidebarContent"] [data-testid="stMarkdownContainer"] > div > p:first-child
{ display:none !important; }

/* Hide Streamlit auto page title at top of content */
[data-testid="stAppViewBlockContainer"] > div:first-child h1 { display:none !important; }

/* Hide the navigation header shown by st.navigation */
[data-testid="stSidebarNavSeparator"] { display:none !important; }

/* ── FULL APP BACKGROUND ────────────────────────────────────────────────── */
html, body,
[data-testid="stAppViewContainer"],
[data-testid="stApp"],
.main, section.main,
.block-container {
  background: var(--navy) !important;
  color: var(--off) !important;
  font-family: 'Inter', system-ui, sans-serif !important;
}

/* ── REMOVE DEFAULT TOP PADDING (our header takes that space) ───────────── */
.block-container {
  padding-top: 0 !important;
  padding-left: 2.5rem !important;
  padding-right: 2.5rem !important;
  max-width: 1140px !important;
}

/* ── SIDEBAR ────────────────────────────────────────────────────────────── */
[data-testid="stSidebar"],
[data-testid="stSidebar"] > div:first-child {
  background: var(--navy-2) !important;
  border-right: 1px solid var(--border) !important;
}
[data-testid="stSidebarNav"] { padding-top: 8px !important; }
[data-testid="stSidebarNav"] a {
  color: var(--muted) !important;
  font-size: 13px !important;
  font-weight: 500 !important;
  border-radius: 8px !important;
  padding: 9px 14px !important;
  transition: all 0.18s !important;
}
[data-testid="stSidebarNav"] a:hover,
[data-testid="stSidebarNav"] a[aria-selected="true"] {
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
p, li { color: var(--off) !important; font-family: 'Inter', sans-serif !important; }

/* ── METRICS ────────────────────────────────────────────────────────────── */
[data-testid="stMetric"] {
  background: var(--navy-3) !important;
  border: 1px solid var(--border-2) !important;
  border-radius: var(--radius-lg) !important;
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
  background: var(--navy-5) !important;
  border-color: var(--ice) !important;
  color: var(--white) !important;
  box-shadow: 0 0 18px var(--ice-glow) !important;
}
.stButton > button[kind="primary"] {
  background: var(--ice) !important;
  border-color: var(--ice) !important;
  color: var(--navy) !important;
  font-weight: 700 !important;
}
.stButton > button[kind="primary"]:hover {
  background: #6db8ff !important;
  box-shadow: 0 0 28px rgba(77,159,255,0.45) !important;
}

/* ── INPUTS ─────────────────────────────────────────────────────────────── */
.stSelectbox > div > div,
.stTextInput > div > div > input,
.stNumberInput > div > div > input {
  background: var(--navy-3) !important;
  color: var(--white) !important;
  border: 1px solid var(--border-2) !important;
  border-radius: 8px !important;
  font-family: 'Inter', sans-serif !important;
}

/* ── FILE UPLOADER ──────────────────────────────────────────────────────── */
[data-testid="stFileUploader"] {
  background: var(--navy-3) !important;
  border: 1px dashed var(--border-2) !important;
  border-radius: var(--radius-lg) !important;
}
[data-testid="stFileUploaderDropzone"] { background: transparent !important; }

/* ── EXPANDER ───────────────────────────────────────────────────────────── */
[data-testid="stExpander"] {
  background: var(--navy-3) !important;
  border: 1px solid var(--border) !important;
  border-radius: var(--radius) !important;
}

/* ── DATAFRAME ──────────────────────────────────────────────────────────── */
[data-testid="stDataFrame"] {
  background: var(--navy-3) !important;
  border: 1px solid var(--border) !important;
  border-radius: var(--radius) !important;
}

/* ── TABS ───────────────────────────────────────────────────────────────── */
[data-baseweb="tab-list"] {
  background: var(--navy-2) !important;
  border-bottom: 1px solid var(--border) !important;
  gap: 4px !important;
}
[data-baseweb="tab"] {
  color: var(--muted) !important;
  font-weight: 600 !important;
  font-size: 13px !important;
  font-family: 'Inter', sans-serif !important;
  border-radius: 6px 6px 0 0 !important;
}
[aria-selected="true"][data-baseweb="tab"] {
  color: var(--ice) !important;
  background: var(--ice-glow) !important;
}

/* ── ALERTS ─────────────────────────────────────────────────────────────── */
.stSuccess  { background: rgba(0,212,160,0.08)  !important; border-left: 3px solid var(--green) !important; border-radius: var(--radius) !important; }
.stWarning  { background: rgba(255,179,71,0.08)  !important; border-left: 3px solid var(--amber) !important; border-radius: var(--radius) !important; }
.stError    { background: rgba(255,77,94,0.08)   !important; border-left: 3px solid var(--red)   !important; border-radius: var(--radius) !important; }
.stInfo     { background: var(--ice-glow)         !important; border-left: 3px solid var(--ice)   !important; border-radius: var(--radius) !important; }

/* ── PROGRESS ───────────────────────────────────────────────────────────── */
[data-testid="stProgressBar"] > div { background: var(--navy-3) !important; }
[data-testid="stProgressBar"] > div > div { background: var(--ice) !important; }

/* ── DIVIDER ────────────────────────────────────────────────────────────── */
hr { border-color: var(--border) !important; opacity:1 !important; }

/* ── SCROLLBAR ──────────────────────────────────────────────────────────── */
::-webkit-scrollbar { width:5px; height:5px; }
::-webkit-scrollbar-track { background: var(--navy-2); }
::-webkit-scrollbar-thumb { background: var(--navy-5); border-radius:3px; }
::-webkit-scrollbar-thumb:hover { background: var(--ice-dim); }

/* ── CODE ───────────────────────────────────────────────────────────────── */
code, pre {
  background: var(--navy-2) !important;
  color: var(--ice) !important;
  font-family: 'JetBrains Mono', monospace !important;
  border: 1px solid var(--border) !important;
  border-radius: 6px !important;
}
</style>
"""

# ── NAV ITEMS (edit these to match your page names) ───────────────────────────
NAV_ITEMS = [
    ("Tool",       "🛡",  "/Tool"),
    ("About",      "📋", "/About"),
    ("How to Use", "📖", "/How_to_Use"),
]

def inject_css():
    # Use session state to avoid re-injecting on every rerun
    # but still inject on first load of each page
    if "css_injected" not in st.session_state:
        st.session_state.css_injected = False
    # Always inject — Streamlit clears it between pages
    st.markdown(GLOBAL_CSS, unsafe_allow_html=True)

def render_header(active="Home"):
    """
    Full custom header — suppresses Streamlit chrome entirely.
    Call at the very top of every page, before any other st.* call.
    """
    inject_css()

    nav_html = ""
    for label, icon, href in NAV_ITEMS:
        is_active = (label == active)
        color     = "#4d9fff" if is_active else "#5a7394"
        bg        = "rgba(77,159,255,0.1)" if is_active else "transparent"
        border    = "1px solid rgba(77,159,255,0.25)" if is_active else "1px solid transparent"
        nav_html += f"""
        <a href="{href}" target="_self" style="
          display:inline-flex;align-items:center;gap:6px;
          font-size:13px;font-weight:600;color:{color};
          font-family:'Inter',sans-serif;text-decoration:none;
          padding:7px 14px;border-radius:8px;
          background:{bg};border:{border};
          transition:all 0.18s;letter-spacing:0.01em;
        ">{icon} {label}</a>"""

    _stc.html(f"""
<div style="
  width:100%;
  background:rgba(8,15,30,0.95);
  backdrop-filter:blur(12px);
  -webkit-backdrop-filter:blur(12px);
  border-bottom:1px solid rgba(255,255,255,0.07);
  padding:0 0 0 0;
  margin-bottom:40px;
  position:sticky;top:0;z-index:999;
">
  <div style="
    max-width:1140px;margin:0 auto;
    display:flex;align-items:center;justify-content:space-between;
    padding:16px 2.5rem;
  ">

    <!-- LEFT: Logo -->
    <div style="display:flex;align-items:center;gap:14px;">
      <div style="
        width:42px;height:42px;
        background:#1F3864;
        border-radius:11px;
        display:flex;align-items:center;justify-content:center;
        border:1px solid rgba(255,255,255,0.15);
        box-shadow:0 2px 12px rgba(0,0,0,0.5),inset 0 1px 0 rgba(255,255,255,0.1);
        flex-shrink:0;
      ">
        <span style="
          font-size:19px;font-weight:900;color:#fff;
          letter-spacing:-1px;font-family:'Inter',sans-serif;
        ">80</span>
      </div>
      <div style="display:flex;flex-direction:column;gap:2px;">
        <span style="
          font-size:17px;font-weight:800;color:#ffffff;
          letter-spacing:-0.03em;font-family:'Inter',sans-serif;
          line-height:1;
        ">80</span>
        <span style="
          font-size:10px;font-weight:600;color:#4d9fff;
          letter-spacing:0.12em;text-transform:uppercase;
          font-family:'Inter',sans-serif;line-height:1;
        ">IAM Audit Tool</span>
      </div>
    </div>

    <!-- CENTRE: Nav -->
    <div style="display:flex;align-items:center;gap:4px;">
      {nav_html}
    </div>

    <!-- RIGHT: Minimal wordmark -->
    <div style="
      font-size:11px;font-weight:500;
      color:rgba(255,255,255,0.18);
      font-family:'Inter',sans-serif;
      letter-spacing:0.06em;
      white-space:nowrap;
    ">IAM · 2026</div>

  </div>
</div>


""", height=82, scrolling=False)

def render_sidebar_brand():
    """Premium dark sidebar brand block."""
    inject_css()
    st.markdown("""
<div style="padding:20px 4px 20px;border-bottom:1px solid rgba(255,255,255,0.06);margin-bottom:16px;">
  <div style="display:flex;align-items:center;gap:11px;margin-bottom:14px;">
    <div style="
      width:38px;height:38px;
      background:#1F3864;
      border-radius:10px;
      display:flex;align-items:center;justify-content:center;
      border:1px solid rgba(255,255,255,0.14);
      box-shadow:0 2px 10px rgba(0,0,0,0.4);
      flex-shrink:0;
    ">
      <span style="font-size:17px;font-weight:900;color:#fff;font-family:'Inter',sans-serif;letter-spacing:-1px;">80</span>
    </div>
    <div>
      <div style="font-size:16px;font-weight:800;color:#ffffff;font-family:'Inter',sans-serif;letter-spacing:-0.03em;line-height:1.1;">80</div>
      <div style="font-size:10px;font-weight:600;color:#4d9fff;letter-spacing:0.1em;text-transform:uppercase;font-family:'Inter',sans-serif;margin-top:2px;">IAM Audit Tool</div>
    </div>
  </div>

</div>
""", unsafe_allow_html=True)

def stat_card(number, label, sublabel="", color="#4d9fff"):
    return f"""
<div style="
  background:#111f38;
  border:1px solid rgba(255,255,255,0.07);
  border-radius:14px;
  padding:24px 20px;
  text-align:center;
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
    sub = f'<div style="font-size:13px;color:#5a7394;font-family:Inter,sans-serif;margin-top:5px;font-weight:400;">{subtitle}</div>' if subtitle else ''
    return f"""
<div style="margin:44px 0 22px;">
  <div style="display:flex;align-items:center;gap:12px;margin-bottom:6px;">
    <div style="width:3px;height:22px;background:#4d9fff;border-radius:2px;flex-shrink:0;box-shadow:0 0 8px rgba(77,159,255,0.5);"></div>
    <div style="font-size:19px;font-weight:800;color:#ffffff;
      letter-spacing:-0.025em;font-family:Inter,sans-serif;">{title}</div>
  </div>
  {sub}
</div>"""

