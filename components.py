"""Shared UI components for 80 — IAM Audit Tool. LED dark theme."""

import streamlit as st

GLOBAL_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap');

:root {
  --navy:       #080f1e;
  --navy-2:     #0d1628;
  --navy-3:     #111f38;
  --navy-4:     #1a2f52;
  --navy-5:     #1F3864;
  --ice:        #4d9fff;
  --ice-dim:    rgba(77,159,255,0.12);
  --ice-glow:   rgba(77,159,255,0.35);
  --white:      #ffffff;
  --off:        #c8d8ef;
  --muted:      #5a7394;
  --green:      #00d4a0;
  --green-glow: rgba(0,212,160,0.5);
  --red:        #ff4d5e;
  --red-glow:   rgba(255,77,94,0.5);
  --amber:      #ffb347;
  --amber-glow: rgba(255,179,71,0.5);
  --border:     rgba(255,255,255,0.06);
  --border-2:   rgba(255,255,255,0.11);
}

/* ── KILL STREAMLIT CHROME ──────────────────────────────────────────────── */
#MainMenu, footer, [data-testid="stDecoration"],
[data-testid="stToolbar"], [data-testid="stStatusWidget"],
[data-testid="stHeader"] { display: none !important; }
[data-testid="stAppViewContainer"] > section.main { padding-top: 0 !important; }

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
  padding-top: 2.5rem !important;
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
/* Hide Streamlit's auto nav links — we use our own header nav */
[data-testid="stSidebarNav"] {
  display: none !important;
}
/* Keep the sidebar collapse/expand toggle button visible */
[data-testid="collapsedControl"] {
  display: flex !important;
  background: var(--navy-2) !important;
  border-right: 1px solid var(--border) !important;
}
[data-testid="collapsedControl"] svg {
  fill: var(--muted) !important;
}

/* ── TYPOGRAPHY ─────────────────────────────────────────────────────────── */
h1,h2,h3,h4,h5,h6 {
  color: var(--white) !important; font-family: 'Inter', sans-serif !important;
  font-weight: 800 !important; letter-spacing: -0.025em !important;
}
p, li, div { color: var(--off) !important; font-family: 'Inter', sans-serif !important; }

/* ── LED METRIC CARDS ───────────────────────────────────────────────────── */
[data-testid="stMetric"] {
  background: var(--navy-3) !important;
  border: 1px solid var(--border-2) !important;
  border-radius: 14px !important; padding: 22px 24px !important;
  transition: box-shadow 0.3s !important;
}
[data-testid="stMetric"]:hover {
  box-shadow: 0 0 28px rgba(77,159,255,0.12) !important;
}
[data-testid="stMetricLabel"] p {
  color: var(--muted) !important; font-size: 11px !important;
  font-weight: 600 !important; letter-spacing: 0.08em !important; text-transform: uppercase !important;
}
[data-testid="stMetricValue"] {
  color: var(--white) !important; font-size: 30px !important;
  font-weight: 900 !important; letter-spacing: -0.04em !important;
  text-shadow: 0 0 20px rgba(77,159,255,0.5) !important;
}
[data-testid="stMetricDelta"] { display:none !important; }

/* ── BUTTONS ────────────────────────────────────────────────────────────── */
.stButton > button {
  background: var(--navy-4) !important; color: var(--off) !important;
  border: 1px solid var(--border-2) !important; border-radius: 8px !important;
  font-family: 'Inter', sans-serif !important; font-weight: 600 !important;
  font-size: 13px !important; transition: all 0.18s !important;
}
.stButton > button:hover {
  border-color: var(--ice) !important; color: var(--white) !important;
  box-shadow: 0 0 16px rgba(77,159,255,0.2) !important;
}
.stButton > button[kind="primary"] {
  background: var(--ice) !important; border-color: var(--ice) !important;
  color: var(--navy) !important; font-weight: 700 !important;
  box-shadow: 0 0 20px var(--ice-glow) !important;
}
.stButton > button[kind="primary"]:hover {
  box-shadow: 0 0 32px var(--ice-glow) !important;
}

/* ── PAGE LINK NAV ──────────────────────────────────────────────────────── */
[data-testid="stPageLink"] { display: flex !important; justify-content: center !important; }
[data-testid="stPageLink"] a {
  display: inline-flex !important; align-items: center !important; gap: 6px !important;
  color: #7a8fa6 !important; font-size: 13px !important; font-weight: 600 !important;
  text-decoration: none !important; font-family: 'Inter', sans-serif !important;
  padding: 7px 14px !important; border-radius: 8px !important;
  border: 1px solid transparent !important; transition: all 0.18s !important;
  white-space: nowrap !important; background: transparent !important;
}
[data-testid="stPageLink"] a:hover {
  color: #4d9fff !important; background: rgba(77,159,255,0.1) !important;
  border-color: rgba(77,159,255,0.2) !important;
  box-shadow: 0 0 14px rgba(77,159,255,0.2) !important;
}
[data-testid="stPageLink"] p { display: none !important; }

/* ── INPUTS ─────────────────────────────────────────────────────────────── */
.stSelectbox > div > div,
.stTextInput > div > div > input,
.stNumberInput > div > div > input {
  background: var(--navy-3) !important; color: var(--white) !important;
  border: 1px solid var(--border-2) !important; border-radius: 8px !important;
  transition: border-color 0.18s, box-shadow 0.18s !important;
}
.stTextInput > div > div > input:focus {
  border-color: var(--ice) !important;
  box-shadow: 0 0 0 2px rgba(77,159,255,0.15), 0 0 12px rgba(77,159,255,0.1) !important;
}

/* ── FILE UPLOADER ──────────────────────────────────────────────────────── */
[data-testid="stFileUploader"] {
  background: var(--navy-3) !important;
  border: 1px dashed rgba(77,159,255,0.25) !important;
  border-radius: 14px !important; transition: all 0.18s !important;
}
[data-testid="stFileUploader"]:hover {
  border-color: var(--ice) !important;
  box-shadow: 0 0 20px rgba(77,159,255,0.1) !important;
}

/* ── EXPANDER ───────────────────────────────────────────────────────────── */
[data-testid="stExpander"] {
  background: var(--navy-3) !important;
  border: 1px solid var(--border) !important; border-radius: 10px !important;
}

/* ── TABS ───────────────────────────────────────────────────────────────── */
[data-baseweb="tab-list"] {
  background: var(--navy-2) !important; border-bottom: 1px solid var(--border) !important;
}
[data-baseweb="tab"] {
  color: var(--muted) !important; font-weight: 600 !important;
  font-size: 13px !important; font-family: 'Inter', sans-serif !important;
}
[aria-selected="true"][data-baseweb="tab"] {
  color: var(--ice) !important; background: var(--ice-dim) !important;
  text-shadow: 0 0 10px var(--ice-glow) !important;
}

/* ── ALERTS ─────────────────────────────────────────────────────────────── */
.stSuccess { background:rgba(0,212,160,0.08) !important; border-left:3px solid var(--green) !important; border-radius:8px !important; box-shadow:0 0 12px rgba(0,212,160,0.06) !important; }
.stWarning { background:rgba(255,179,71,0.08) !important; border-left:3px solid var(--amber) !important; border-radius:8px !important; }
.stError   { background:rgba(255,77,94,0.08)  !important; border-left:3px solid var(--red)   !important; border-radius:8px !important; }
.stInfo    { background:var(--ice-dim)         !important; border-left:3px solid var(--ice)   !important; border-radius:8px !important; }

/* ── LED PROGRESS BAR ───────────────────────────────────────────────────── */
[data-testid="stProgressBar"] > div {
  background: var(--navy-3) !important; border-radius: 4px !important;
}
[data-testid="stProgressBar"] > div > div {
  background: linear-gradient(90deg, var(--ice), var(--green)) !important;
  border-radius: 4px !important;
  box-shadow: 0 0 10px var(--ice-glow), 0 0 20px rgba(77,159,255,0.2) !important;
}

/* ── DIVIDER ────────────────────────────────────────────────────────────── */
hr { border-color: var(--border) !important; opacity:1 !important; }

/* ── SCROLLBAR ──────────────────────────────────────────────────────────── */
::-webkit-scrollbar { width:5px; height:5px; }
::-webkit-scrollbar-track { background: var(--navy-2); }
::-webkit-scrollbar-thumb { background: var(--navy-5); border-radius:3px; }
::-webkit-scrollbar-thumb:hover { background: var(--ice); box-shadow: 0 0 6px var(--ice-glow); }

/* ── CODE ───────────────────────────────────────────────────────────────── */
code, pre {
  background: var(--navy-2) !important; color: var(--ice) !important;
  border: 1px solid var(--border) !important; border-radius: 6px !important;
  text-shadow: 0 0 8px rgba(77,159,255,0.3) !important;
}

/* ── LED ANIMATIONS ─────────────────────────────────────────────────────── */
@keyframes led-green {
  0%,100% { box-shadow: 0 0 5px #00d4a0, 0 0 10px rgba(0,212,160,0.7); }
  50%     { box-shadow: 0 0 10px #00d4a0, 0 0 24px rgba(0,212,160,0.4); }
}
@keyframes led-blue {
  0%,100% { box-shadow: 0 0 5px #4d9fff, 0 0 10px rgba(77,159,255,0.7); }
  50%     { box-shadow: 0 0 10px #4d9fff, 0 0 24px rgba(77,159,255,0.4); }
}
@keyframes led-red {
  0%,100% { box-shadow: 0 0 5px #ff4d5e, 0 0 10px rgba(255,77,94,0.7); }
  50%     { box-shadow: 0 0 10px #ff4d5e, 0 0 24px rgba(255,77,94,0.4); }
}
@keyframes led-amber {
  0%,100% { box-shadow: 0 0 5px #ffb347, 0 0 10px rgba(255,179,71,0.7); }
  50%     { box-shadow: 0 0 10px #ffb347, 0 0 24px rgba(255,179,71,0.4); }
}
@keyframes scan-line {
  0%   { transform: translateX(-100%); }
  100% { transform: translateX(400%); }
}
</style>
"""


def inject_css():
    st.markdown(GLOBAL_CSS, unsafe_allow_html=True)


def led_dot(color="green", size=8):
    """A pulsing LED dot. color: green | blue | red | amber"""
    colors = {
        "green": ("#00d4a0", "led-green"),
        "blue":  ("#4d9fff", "led-blue"),
        "red":   ("#ff4d5e", "led-red"),
        "amber": ("#ffb347", "led-amber"),
    }
    hex_c, anim = colors.get(color, colors["green"])
    return f"""<span style="
      display:inline-block;
      width:{size}px;height:{size}px;
      background:{hex_c};
      border-radius:50%;
      animation:{anim} 2s ease-in-out infinite;
      flex-shrink:0;
      vertical-align:middle;
    "></span>"""


def led_status_bar(status="idle"):
    """
    LED status bar shown on the Tool page.
    status: idle | scanning | complete | error
    """
    configs = {
        "idle":     ("#5a7394", "grey",  "–",       "Idle — ready to scan"),
        "scanning": ("#4d9fff", "blue",  "◉",       "Scanning in progress…"),
        "complete": ("#00d4a0", "green", "✓",       "Scan complete"),
        "error":    ("#ff4d5e", "red",   "✗",       "Error — check inputs"),
    }
    color, dot_color, symbol, label = configs.get(status, configs["idle"])
    dot = led_dot(dot_color, 8) if status != "idle" else f'<span style="display:inline-block;width:8px;height:8px;background:#5a7394;border-radius:50%;opacity:0.4;vertical-align:middle;"></span>'

    scan_animation = ""
    if status == "scanning":
        scan_animation = f"""
<div style="height:2px;background:rgba(255,255,255,0.06);border-radius:2px;
  margin-top:10px;overflow:hidden;position:relative;">
  <div style="position:absolute;top:0;left:0;height:100%;width:25%;
    background:linear-gradient(90deg,transparent,#4d9fff,transparent);
    border-radius:2px;
    animation:scan-line 1.5s ease-in-out infinite;">
  </div>
</div>"""

    return f"""
<div style="
  display:flex;align-items:center;gap:10px;
  background:#0d1628;
  border:1px solid {'rgba(77,159,255,0.25)' if status=='scanning' else 'rgba(255,255,255,0.07)'};
  border-radius:10px;padding:12px 18px;
  {'box-shadow:0 0 20px rgba(77,159,255,0.1);' if status=='scanning' else ''}
">
  {dot}
  <span style="font-size:13px;font-weight:600;color:{color};
    font-family:'Inter',sans-serif;letter-spacing:0.02em;">{label}</span>
</div>
{scan_animation}
"""


def render_header(active="Home"):
    """
    Pure Streamlit header using st.page_link for navigation.
    No iframes. No routing issues. Works on Streamlit Cloud.
    """
    inject_css()

    left, mid, right = st.columns([2, 5, 2])

    with left:
        # Logo with pulsing LED dot
        st.markdown(f"""
<div style="display:flex;align-items:center;gap:12px;padding:12px 0 8px;">
  <div style="position:relative;flex-shrink:0;">
    <div style="
      width:42px;height:42px;
      background:linear-gradient(135deg,#1F3864,#2a4f8a);
      border-radius:11px;
      display:flex;align-items:center;justify-content:center;
      border:1px solid rgba(255,255,255,0.18);
      box-shadow:0 2px 12px rgba(0,0,0,0.5);
    ">
      <span style="font-size:19px;font-weight:900;color:#fff;
        letter-spacing:-1px;font-family:'Inter',sans-serif;">80</span>
    </div>
    <!-- LED dot — bottom right of logo box -->
    <div style="
      position:absolute;bottom:-2px;right:-2px;
      width:9px;height:9px;
      background:#00d4a0;
      border-radius:50%;
      border:1.5px solid #080f1e;
      animation:led-green 2s ease-in-out infinite;
    "></div>
  </div>
  <div>
    <div style="font-size:17px;font-weight:800;color:#ffffff;
      letter-spacing:-0.03em;font-family:'Inter',sans-serif;line-height:1;">80</div>
    <div style="font-size:9px;font-weight:600;color:#4d9fff;
      letter-spacing:0.12em;text-transform:uppercase;
      font-family:'Inter',sans-serif;margin-top:3px;">IAM Audit Tool</div>
  </div>
</div>
""", unsafe_allow_html=True)

    with mid:
        st.markdown('<div style="padding:10px 0 6px;">', unsafe_allow_html=True)
        n1, n2, n3, n4 = st.columns(4)
        with n1:
            st.page_link("pages/home.py",       label="Home",       icon="🏠")
        with n2:
            st.page_link("pages/tool.py",        label="Tool",       icon="🛡️")
        with n3:
            st.page_link("pages/about.py",       label="About",      icon="📋")
        with n4:
            st.page_link("pages/how_to_use.py",  label="How to Use", icon="📖")
        st.markdown('</div>', unsafe_allow_html=True)

    with right:
        st.markdown(f"""
<div style="text-align:right;padding:12px 0 8px;
  display:flex;align-items:center;justify-content:flex-end;gap:8px;">
  {led_dot("blue", 6)}
  <span style="font-size:11px;color:rgba(255,255,255,0.22);
    font-family:'Inter',sans-serif;letter-spacing:0.04em;">IAM · 2026</span>
</div>
""", unsafe_allow_html=True)

    # LED accent line under header
    st.markdown("""
<div style="
  height:1px;
  background:linear-gradient(90deg,
    transparent 0%,
    rgba(77,159,255,0.3) 30%,
    rgba(0,212,160,0.3) 70%,
    transparent 100%);
  margin-bottom:28px;
  box-shadow:0 0 8px rgba(77,159,255,0.15);
"></div>
""", unsafe_allow_html=True)


def render_sidebar_brand():
    """Sidebar brand with LED dot."""
    inject_css()
    st.markdown(f"""
<div style="padding:16px 0 20px;
  border-bottom:1px solid rgba(255,255,255,0.06);margin-bottom:16px;">
  <div style="display:flex;align-items:center;gap:11px;">
    <div style="position:relative;flex-shrink:0;">
      <div style="
        width:36px;height:36px;background:#1F3864;border-radius:9px;
        display:flex;align-items:center;justify-content:center;
        border:1px solid rgba(255,255,255,0.14);
      ">
        <span style="font-size:16px;font-weight:900;color:#fff;
          font-family:'Inter',sans-serif;letter-spacing:-1px;">80</span>
      </div>
      <div style="
        position:absolute;bottom:-1px;right:-1px;
        width:7px;height:7px;background:#00d4a0;border-radius:50%;
        border:1.5px solid #0d1628;
        animation:led-green 2s ease-in-out infinite;
      "></div>
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
    """LED stat card with glowing number."""
    glow_map = {
        "#4d9fff": "rgba(77,159,255,0.5)",
        "#00d4a0": "rgba(0,212,160,0.5)",
        "#ffb347": "rgba(255,179,71,0.5)",
        "#ff4d5e": "rgba(255,77,94,0.5)",
    }
    glow = glow_map.get(color, "rgba(77,159,255,0.5)")
    return f"""
<div style="
  background:#111f38;
  border:1px solid rgba(255,255,255,0.07);
  border-radius:14px;padding:24px 20px;text-align:center;
  border-top:2px solid {color};
  box-shadow:0 0 0 rgba(0,0,0,0);
  transition:box-shadow 0.3s;
  position:relative;overflow:hidden;
">
  <!-- LED glow orb behind number -->
  <div style="
    position:absolute;top:50%;left:50%;
    transform:translate(-50%,-60%);
    width:80px;height:80px;
    background:radial-gradient(circle,{glow.replace('0.5','0.08')} 0%,transparent 70%);
    pointer-events:none;
  "></div>
  <div style="
    font-size:36px;font-weight:900;color:#ffffff;
    letter-spacing:-0.04em;font-family:'Inter',sans-serif;line-height:1;
    text-shadow:0 0 20px {glow};
    position:relative;
  ">{number}</div>
  <div style="
    font-size:11px;font-weight:700;color:{color};
    letter-spacing:0.07em;text-transform:uppercase;
    font-family:'Inter',sans-serif;margin-top:8px;
    text-shadow:0 0 10px {glow};
    position:relative;
  ">{label}</div>
  {f'<div style="font-size:10px;color:#5a7394;font-family:Inter,sans-serif;margin-top:4px;position:relative;">{sublabel}</div>' if sublabel else ''}
</div>"""


def section_header(title, subtitle=""):
    """Section header with LED accent line."""
    sub = f'<div style="font-size:13px;color:#5a7394;font-family:Inter,sans-serif;margin-top:5px;">{subtitle}</div>' if subtitle else ''
    return f"""
<div style="margin:40px 0 20px;">
  <div style="display:flex;align-items:center;gap:12px;margin-bottom:6px;">
    <div style="
      width:3px;height:22px;
      background:linear-gradient(180deg,#4d9fff,#00d4a0);
      border-radius:2px;flex-shrink:0;
      box-shadow:0 0 8px rgba(77,159,255,0.5);
    "></div>
    <div style="
      font-size:19px;font-weight:800;color:#ffffff;
      letter-spacing:-0.025em;font-family:Inter,sans-serif;
    ">{title}</div>
  </div>
  {sub}
</div>"""

