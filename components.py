"""Shared UI components for 80 — IAM Audit Tool. Dark premium theme."""

import streamlit as st

# ── Global CSS — injected once, applies everywhere ──────────────────────────
GLOBAL_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500&display=swap');

/* ── ROOT OVERRIDES ─────────────────────────────────────────────────────── */
:root {
  --navy:       #0B1628;
  --navy-2:     #111f38;
  --navy-3:     #1a2f52;
  --navy-4:     #1F3864;
  --navy-5:     #243b6e;
  --ice:        #4d9fff;
  --ice-dim:    #2a5f9e;
  --ice-glow:   rgba(77,159,255,0.15);
  --white:      #ffffff;
  --off-white:  #e8edf5;
  --muted:      #7a8fa6;
  --muted-2:    #4a5e78;
  --green:      #00c896;
  --green-dim:  rgba(0,200,150,0.15);
  --red:        #ff4757;
  --red-dim:    rgba(255,71,87,0.12);
  --amber:      #ffa502;
  --amber-dim:  rgba(255,165,2,0.12);
  --border:     rgba(255,255,255,0.07);
  --border-2:   rgba(255,255,255,0.12);
  --shadow:     0 4px 24px rgba(0,0,0,0.4);
  --shadow-sm:  0 2px 12px rgba(0,0,0,0.3);
  --radius:     10px;
  --radius-lg:  16px;
}

/* ── FULL APP BACKGROUND ───────────────────────────────────────────────── */
html, body, [data-testid="stAppViewContainer"],
[data-testid="stApp"], .main, .block-container {
  background: var(--navy) !important;
  color: var(--off-white) !important;
  font-family: 'Inter', sans-serif !important;
}

/* ── SIDEBAR ────────────────────────────────────────────────────────────── */
[data-testid="stSidebar"], [data-testid="stSidebar"] > div {
  background: var(--navy-2) !important;
  border-right: 1px solid var(--border) !important;
}
[data-testid="stSidebar"] * {
  color: var(--off-white) !important;
  font-family: 'Inter', sans-serif !important;
}
[data-testid="stSidebarNav"] a {
  color: var(--muted) !important;
  font-size: 13px !important;
  font-weight: 500 !important;
  padding: 8px 12px !important;
  border-radius: 6px !important;
  transition: all 0.2s !important;
}
[data-testid="stSidebarNav"] a:hover {
  background: var(--ice-glow) !important;
  color: var(--ice) !important;
}

/* ── TOP HEADER BAR ─────────────────────────────────────────────────────── */
[data-testid="stHeader"] {
  background: var(--navy) !important;
  border-bottom: 1px solid var(--border) !important;
}

/* ── BLOCK CONTAINER ────────────────────────────────────────────────────── */
.block-container {
  padding: 2rem 3rem !important;
  max-width: 1100px !important;
}

/* ── HEADINGS ───────────────────────────────────────────────────────────── */
h1, h2, h3, h4, h5, h6 {
  color: var(--white) !important;
  font-family: 'Inter', sans-serif !important;
  font-weight: 700 !important;
  letter-spacing: -0.02em !important;
}

/* ── PARAGRAPH / BODY TEXT ──────────────────────────────────────────────── */
p, li, span, label, div {
  color: var(--off-white) !important;
  font-family: 'Inter', sans-serif !important;
}

/* ── METRIC CARDS ───────────────────────────────────────────────────────── */
[data-testid="stMetric"] {
  background: var(--navy-3) !important;
  border: 1px solid var(--border-2) !important;
  border-radius: var(--radius) !important;
  padding: 20px 22px !important;
  transition: border-color 0.2s !important;
}
[data-testid="stMetric"]:hover {
  border-color: var(--ice-dim) !important;
}
[data-testid="stMetricLabel"] {
  color: var(--muted) !important;
  font-size: 11px !important;
  font-weight: 600 !important;
  letter-spacing: 0.06em !important;
  text-transform: uppercase !important;
}
[data-testid="stMetricValue"] {
  color: var(--white) !important;
  font-size: 28px !important;
  font-weight: 800 !important;
  letter-spacing: -0.03em !important;
}
[data-testid="stMetricDelta"] { display: none !important; }

/* ── BUTTONS ────────────────────────────────────────────────────────────── */
.stButton > button {
  background: var(--navy-3) !important;
  color: var(--off-white) !important;
  border: 1px solid var(--border-2) !important;
  border-radius: 8px !important;
  font-family: 'Inter', sans-serif !important;
  font-weight: 600 !important;
  font-size: 13px !important;
  padding: 10px 20px !important;
  transition: all 0.2s !important;
  letter-spacing: 0.01em !important;
}
.stButton > button:hover {
  background: var(--navy-4) !important;
  border-color: var(--ice) !important;
  color: var(--white) !important;
  box-shadow: 0 0 20px var(--ice-glow) !important;
}
.stButton > button[kind="primary"] {
  background: var(--ice) !important;
  border-color: var(--ice) !important;
  color: var(--navy) !important;
  font-weight: 700 !important;
}
.stButton > button[kind="primary"]:hover {
  background: #6db8ff !important;
  box-shadow: 0 0 30px rgba(77,159,255,0.4) !important;
}

/* ── SELECT / INPUT ─────────────────────────────────────────────────────── */
[data-testid="stSelectbox"], [data-testid="stTextInput"],
[data-testid="stNumberInput"], [data-testid="stDateInput"] {
  background: var(--navy-3) !important;
  border-radius: var(--radius) !important;
}
.stSelectbox > div > div, .stTextInput > div > div > input {
  background: var(--navy-3) !important;
  color: var(--white) !important;
  border: 1px solid var(--border-2) !important;
  border-radius: 8px !important;
}

/* ── FILE UPLOADER ──────────────────────────────────────────────────────── */
[data-testid="stFileUploader"] {
  background: var(--navy-3) !important;
  border: 1px dashed var(--border-2) !important;
  border-radius: var(--radius-lg) !important;
  padding: 12px !important;
  transition: border-color 0.2s !important;
}
[data-testid="stFileUploader"]:hover {
  border-color: var(--ice-dim) !important;
}
[data-testid="stFileUploaderDropzone"] {
  background: transparent !important;
}

/* ── EXPANDER ───────────────────────────────────────────────────────────── */
[data-testid="stExpander"] {
  background: var(--navy-3) !important;
  border: 1px solid var(--border) !important;
  border-radius: var(--radius) !important;
}
[data-testid="stExpander"] summary {
  color: var(--off-white) !important;
  font-weight: 600 !important;
}

/* ── DATAFRAME / TABLE ──────────────────────────────────────────────────── */
[data-testid="stDataFrame"], .stDataFrame {
  background: var(--navy-3) !important;
  border: 1px solid var(--border) !important;
  border-radius: var(--radius) !important;
}

/* ── TABS ───────────────────────────────────────────────────────────────── */
[data-testid="stTabs"] [data-baseweb="tab-list"] {
  background: var(--navy-2) !important;
  border-bottom: 1px solid var(--border) !important;
}
[data-testid="stTabs"] [data-baseweb="tab"] {
  color: var(--muted) !important;
  font-weight: 600 !important;
  font-size: 13px !important;
}
[data-testid="stTabs"] [aria-selected="true"] {
  color: var(--ice) !important;
  border-bottom: 2px solid var(--ice) !important;
}

/* ── PROGRESS BAR ───────────────────────────────────────────────────────── */
[data-testid="stProgressBar"] > div > div {
  background: var(--ice) !important;
}
[data-testid="stProgressBar"] > div {
  background: var(--navy-3) !important;
}

/* ── ALERTS ─────────────────────────────────────────────────────────────── */
[data-testid="stAlert"] {
  border-radius: var(--radius) !important;
  border: 1px solid var(--border-2) !important;
}

/* ── DIVIDER ────────────────────────────────────────────────────────────── */
hr {
  border-color: var(--border) !important;
  opacity: 1 !important;
}

/* ── SCROLLBAR ──────────────────────────────────────────────────────────── */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: var(--navy-2); }
::-webkit-scrollbar-thumb { background: var(--navy-5); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: var(--ice-dim); }

/* ── SPINNER ────────────────────────────────────────────────────────────── */
[data-testid="stSpinner"] { color: var(--ice) !important; }

/* ── CODE BLOCKS ────────────────────────────────────────────────────────── */
code, pre {
  background: var(--navy-2) !important;
  color: var(--ice) !important;
  font-family: 'JetBrains Mono', monospace !important;
  border: 1px solid var(--border) !important;
  border-radius: 6px !important;
}

/* ── TOOLTIP ────────────────────────────────────────────────────────────── */
[data-testid="stTooltipIcon"] { color: var(--muted) !important; }

/* ── CHECKBOX / RADIO ───────────────────────────────────────────────────── */
[data-testid="stCheckbox"] label, [data-testid="stRadio"] label {
  color: var(--off-white) !important;
}

/* ── COLUMNS SPACING ────────────────────────────────────────────────────── */
[data-testid="stHorizontalBlock"] { gap: 16px !important; }

/* ── SUCCESS / WARNING / ERROR BOXES ────────────────────────────────────── */
.stSuccess { background: var(--green-dim) !important; border-left: 3px solid var(--green) !important; }
.stWarning { background: var(--amber-dim) !important; border-left: 3px solid var(--amber) !important; }
.stError   { background: var(--red-dim)   !important; border-left: 3px solid var(--red)   !important; }
.stInfo    { background: var(--ice-glow)  !important; border-left: 3px solid var(--ice)   !important; }

/* ── HIDE STREAMLIT BRANDING ────────────────────────────────────────────── */
#MainMenu, footer, [data-testid="stDecoration"] { display: none !important; }
[data-testid="stToolbar"] { display: none !important; }

/* ── BADGE COMPONENT ────────────────────────────────────────────────────── */
.badge-critical { background:rgba(255,71,87,0.15);color:#ff4757;border:1px solid rgba(255,71,87,0.3);padding:3px 10px;border-radius:20px;font-size:11px;font-weight:700;letter-spacing:.05em;font-family:'Inter',sans-serif; }
.badge-high     { background:rgba(255,165,2,0.15);color:#ffa502;border:1px solid rgba(255,165,2,0.3);padding:3px 10px;border-radius:20px;font-size:11px;font-weight:700;letter-spacing:.05em;font-family:'Inter',sans-serif; }
.badge-medium   { background:rgba(77,159,255,0.15);color:#4d9fff;border:1px solid rgba(77,159,255,0.3);padding:3px 10px;border-radius:20px;font-size:11px;font-weight:700;letter-spacing:.05em;font-family:'Inter',sans-serif; }
.badge-clean    { background:rgba(0,200,150,0.15);color:#00c896;border:1px solid rgba(0,200,150,0.3);padding:3px 10px;border-radius:20px;font-size:11px;font-weight:700;letter-spacing:.05em;font-family:'Inter',sans-serif; }

/* ── CARD COMPONENT ─────────────────────────────────────────────────────── */
.card {
  background: var(--navy-3);
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  padding: 24px 28px;
  margin-bottom: 16px;
  transition: border-color 0.2s, box-shadow 0.2s;
}
.card:hover {
  border-color: var(--border-2);
  box-shadow: var(--shadow-sm);
}
.card-accent-red    { border-left: 3px solid var(--red)   !important; }
.card-accent-amber  { border-left: 3px solid var(--amber) !important; }
.card-accent-blue   { border-left: 3px solid var(--ice)   !important; }
.card-accent-green  { border-left: 3px solid var(--green) !important; }

/* ── FINDING ROW ────────────────────────────────────────────────────────── */
.finding-row {
  display: flex;
  align-items: flex-start;
  gap: 14px;
  padding: 14px 18px;
  background: var(--navy-3);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  margin-bottom: 8px;
  transition: border-color 0.2s;
}
.finding-row:hover { border-color: var(--border-2); }

/* ── NUMBER GLOW (for stats) ─────────────────────────────────────────────── */
.stat-number {
  font-size: 48px;
  font-weight: 900;
  color: var(--white);
  letter-spacing: -0.04em;
  font-family: 'Inter', sans-serif;
  line-height: 1;
}
.stat-label {
  font-size: 11px;
  font-weight: 600;
  color: var(--muted);
  letter-spacing: 0.08em;
  text-transform: uppercase;
  margin-top: 6px;
  font-family: 'Inter', sans-serif;
}
</style>
"""

def inject_css():
    """Inject global CSS. Call once per page at the top."""
    st.markdown(GLOBAL_CSS, unsafe_allow_html=True)


def render_header():
    """Premium dark header bar with logo and product name."""
    inject_css()
    st.markdown("""
<div style="
  display:flex;
  align-items:center;
  justify-content:space-between;
  padding:0 0 24px 0;
  border-bottom:1px solid rgba(255,255,255,0.07);
  margin-bottom:32px;
">
  <div style="display:flex;align-items:center;gap:16px;">
    <!-- Logo mark -->
    <div style="
      width:48px;height:48px;
      background:linear-gradient(135deg,#1F3864 0%,#2a4f8a 100%);
      border-radius:12px;
      display:flex;align-items:center;justify-content:center;
      border:1px solid rgba(255,255,255,0.12);
      box-shadow:0 4px 16px rgba(0,0,0,0.4);
      flex-shrink:0;
    ">
      <span style="font-size:22px;font-weight:900;color:#fff;letter-spacing:-1px;font-family:'Inter',sans-serif;">80</span>
    </div>
    <!-- Name + tagline -->
    <div>
      <div style="font-size:20px;font-weight:800;color:#ffffff;letter-spacing:-0.5px;font-family:'Inter',sans-serif;line-height:1.1;">80</div>
      <div style="font-size:11px;color:#4d9fff;font-weight:600;letter-spacing:0.1em;text-transform:uppercase;font-family:'Inter',sans-serif;margin-top:2px;">IAM Audit Tool</div>
    </div>
  </div>
  <!-- Right side — verified badge -->
  <div style="
    background:rgba(0,200,150,0.1);
    border:1px solid rgba(0,200,150,0.25);
    border-radius:20px;
    padding:6px 14px;
    display:flex;align-items:center;gap:6px;
  ">
    <div style="width:6px;height:6px;background:#00c896;border-radius:50%;box-shadow:0 0 8px rgba(0,200,150,0.6);"></div>
    <span style="font-size:11px;font-weight:700;color:#00c896;letter-spacing:0.05em;font-family:'Inter',sans-serif;">VERIFIED · 5,000 ACCOUNTS TESTED</span>
  </div>
</div>
""", unsafe_allow_html=True)


def render_sidebar_brand():
    """Premium dark sidebar brand block."""
    st.markdown("""
<div style="padding:16px 0 20px;border-bottom:1px solid rgba(255,255,255,0.07);margin-bottom:12px;">
  <div style="display:flex;align-items:center;gap:10px;margin-bottom:16px;">
    <div style="
      width:36px;height:36px;
      background:linear-gradient(135deg,#1F3864 0%,#2a4f8a 100%);
      border-radius:9px;
      display:flex;align-items:center;justify-content:center;
      border:1px solid rgba(255,255,255,0.12);
      flex-shrink:0;
    ">
      <span style="font-size:16px;font-weight:900;color:#fff;font-family:'Inter',sans-serif;">80</span>
    </div>
    <div>
      <div style="font-size:15px;font-weight:800;color:#ffffff;font-family:'Inter',sans-serif;line-height:1.1;">80</div>
      <div style="font-size:10px;color:#4d9fff;font-weight:600;letter-spacing:0.08em;text-transform:uppercase;font-family:'Inter',sans-serif;">IAM Audit Tool</div>
    </div>
  </div>
  <!-- Status pill -->
  <div style="
    background:rgba(0,200,150,0.1);
    border:1px solid rgba(0,200,150,0.2);
    border-radius:6px;
    padding:8px 12px;
    display:flex;align-items:center;gap:8px;
  ">
    <div style="width:5px;height:5px;background:#00c896;border-radius:50%;box-shadow:0 0 6px rgba(0,200,150,0.7);flex-shrink:0;"></div>
    <span style="font-size:10px;font-weight:600;color:#00c896;font-family:'Inter',sans-serif;letter-spacing:0.04em;">Engine verified · 5K stress tested</span>
  </div>
</div>
""", unsafe_allow_html=True)


def stat_card(number, label, sublabel="", accent_color="#4d9fff"):
    """Premium stat card with large number."""
    return f"""
<div style="
  background:#1a2f52;
  border:1px solid rgba(255,255,255,0.08);
  border-radius:14px;
  padding:24px 22px;
  text-align:center;
  border-top:2px solid {accent_color};
  transition:all 0.2s;
">
  <div style="font-size:38px;font-weight:900;color:#ffffff;letter-spacing:-0.04em;font-family:'Inter',sans-serif;line-height:1;">{number}</div>
  <div style="font-size:12px;font-weight:700;color:{accent_color};letter-spacing:0.06em;text-transform:uppercase;font-family:'Inter',sans-serif;margin-top:8px;">{label}</div>
  {f'<div style="font-size:10px;color:#4a5e78;font-family:Inter,sans-serif;margin-top:4px;">{sublabel}</div>' if sublabel else ''}
</div>"""


def section_header(title, subtitle=""):
    """Section header with accent line."""
    sub = f'<div style="font-size:13px;color:#7a8fa6;font-family:Inter,sans-serif;margin-top:6px;font-weight:400;">{subtitle}</div>' if subtitle else ''
    return f"""
<div style="margin:40px 0 24px;">
  <div style="display:flex;align-items:center;gap:12px;margin-bottom:8px;">
    <div style="width:3px;height:24px;background:#4d9fff;border-radius:2px;flex-shrink:0;"></div>
    <h2 style="font-size:20px;font-weight:800;color:#ffffff;letter-spacing:-0.03em;font-family:Inter,sans-serif;margin:0;">{title}</h2>
  </div>
  {sub}
</div>"""


def check_pill(label, color):
    """Small severity pill."""
    colors = {
        "critical": ("#ff4757", "rgba(255,71,87,0.15)"),
        "high":     ("#ffa502", "rgba(255,165,2,0.15)"),
        "medium":   ("#4d9fff", "rgba(77,159,255,0.15)"),
        "clean":    ("#00c896", "rgba(0,200,150,0.15)"),
    }
    fc, bg = colors.get(color.lower(), ("#7a8fa6", "rgba(122,143,166,0.15)"))
    return f'<span style="background:{bg};color:{fc};border:1px solid {fc}44;padding:3px 10px;border-radius:20px;font-size:11px;font-weight:700;letter-spacing:.05em;font-family:Inter,sans-serif;">{label}</span>'

