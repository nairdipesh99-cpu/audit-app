"""Shared UI components for 80 — IAM Audit Tool."""

import streamlit as st

GLOBAL_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap');

:root {
  --navy:    #080f1e;
  --navy-2:  #0d1628;
  --navy-3:  #111f38;
  --navy-4:  #1a2f52;
  --navy-5:  #1F3864;
  --ice:     #4d9fff;
  --white:   #ffffff;
  --off:     #c8d8ef;
  --muted:   #5a7394;
  --green:   #00d4a0;
  --red:     #ff4d5e;
  --amber:   #ffb347;
  --border:  rgba(255,255,255,0.07);
  --border-2:rgba(255,255,255,0.12);
}

/* ── FULL APP DARK ──────────────────────────────────────────────── */
html, body,
[data-testid="stApp"],
[data-testid="stAppViewContainer"],
.main, section.main,
.block-container {
  background: var(--navy) !important;
  color: var(--off) !important;
  font-family: 'Inter', system-ui, sans-serif !important;
}

.block-container {
  padding-top: 2rem !important;
  padding-left: 2rem !important;
  padding-right: 2rem !important;
  max-width: 1100px !important;
}

/* ── SIDEBAR ────────────────────────────────────────────────────── */
[data-testid="stSidebar"] {
  background: #0d1628 !important;
  border-right: 1px solid rgba(255,255,255,0.07) !important;
}
[data-testid="stSidebar"] * {
  color: var(--off) !important;
}
[data-testid="stSidebarNav"] a {
  color: var(--muted) !important;
  font-size: 13px !important;
  font-weight: 500 !important;
  border-radius: 8px !important;
  padding: 8px 12px !important;
}
[data-testid="stSidebarNav"] a:hover {
  background: rgba(77,159,255,0.1) !important;
  color: var(--ice) !important;
}

/* ── TYPOGRAPHY ─────────────────────────────────────────────────── */
h1,h2,h3,h4,h5,h6 {
  color: var(--white) !important;
  font-family: 'Inter', sans-serif !important;
  font-weight: 800 !important;
  letter-spacing: -0.025em !important;
}

/* ── METRIC CARDS ───────────────────────────────────────────────── */
[data-testid="stMetric"] {
  background: var(--navy-3) !important;
  border: 1px solid var(--border-2) !important;
  border-radius: 14px !important;
  padding: 20px 22px !important;
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
  font-size: 28px !important;
  font-weight: 900 !important;
}
[data-testid="stMetricDelta"] { display: none !important; }

/* ── BUTTONS ────────────────────────────────────────────────────── */
.stButton > button {
  background: var(--navy-4) !important;
  color: var(--off) !important;
  border: 1px solid var(--border-2) !important;
  border-radius: 8px !important;
  font-family: 'Inter', sans-serif !important;
  font-weight: 600 !important;
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
  box-shadow: 0 0 20px rgba(77,159,255,0.4) !important;
}

/* ── PAGE LINK ──────────────────────────────────────────────────── */
[data-testid="stPageLink"] a {
  color: var(--muted) !important;
  font-size: 13px !important;
  font-weight: 600 !important;
  text-decoration: none !important;
  padding: 6px 12px !important;
  border-radius: 8px !important;
  border: 1px solid transparent !important;
  transition: all 0.18s !important;
}
[data-testid="stPageLink"] a:hover {
  color: var(--ice) !important;
  background: rgba(77,159,255,0.1) !important;
  border-color: rgba(77,159,255,0.2) !important;
}

/* ── INPUTS ─────────────────────────────────────────────────────── */
.stSelectbox > div > div,
.stTextInput > div > div > input,
.stNumberInput > div > div > input {
  background: var(--navy-3) !important;
  color: var(--white) !important;
  border: 1px solid var(--border-2) !important;
  border-radius: 8px !important;
}

/* ── FILE UPLOADER ──────────────────────────────────────────────── */
[data-testid="stFileUploader"] {
  background: var(--navy-3) !important;
  border: 1px dashed rgba(77,159,255,0.3) !important;
  border-radius: 12px !important;
}

/* ── EXPANDER ───────────────────────────────────────────────────── */
[data-testid="stExpander"] {
  background: var(--navy-3) !important;
  border: 1px solid var(--border) !important;
  border-radius: 10px !important;
}

/* ── TABS ───────────────────────────────────────────────────────── */
[data-baseweb="tab-list"] {
  background: var(--navy-2) !important;
  border-bottom: 1px solid var(--border) !important;
}
[data-baseweb="tab"] {
  color: var(--muted) !important;
  font-weight: 600 !important;
  font-size: 13px !important;
}
[aria-selected="true"][data-baseweb="tab"] {
  color: var(--ice) !important;
}

/* ── ALERTS ─────────────────────────────────────────────────────── */
.stSuccess { background: rgba(0,212,160,0.08) !important; border-left: 3px solid var(--green) !important; border-radius: 8px !important; }
.stWarning { background: rgba(255,179,71,0.08) !important; border-left: 3px solid var(--amber) !important; border-radius: 8px !important; }
.stError   { background: rgba(255,77,94,0.08)  !important; border-left: 3px solid var(--red)   !important; border-radius: 8px !important; }
.stInfo    { background: rgba(77,159,255,0.08)  !important; border-left: 3px solid var(--ice)   !important; border-radius: 8px !important; }

/* ── PROGRESS ───────────────────────────────────────────────────── */
[data-testid="stProgressBar"] > div { background: var(--navy-3) !important; }
[data-testid="stProgressBar"] > div > div {
  background: linear-gradient(90deg, var(--ice), var(--green)) !important;
  box-shadow: 0 0 10px rgba(77,159,255,0.4) !important;
}

/* ── DIVIDER ────────────────────────────────────────────────────── */
hr { border-color: var(--border) !important; opacity: 1 !important; }

/* ── SCROLLBAR ──────────────────────────────────────────────────── */
::-webkit-scrollbar { width: 5px; height: 5px; }
::-webkit-scrollbar-track { background: var(--navy-2); }
::-webkit-scrollbar-thumb { background: var(--navy-5); border-radius: 3px; }

/* ── LED ANIMATIONS ─────────────────────────────────────────────── */
@keyframes led-green {
  0%,100% { box-shadow: 0 0 5px #00d4a0, 0 0 10px rgba(0,212,160,0.6); }
  50%     { box-shadow: 0 0 10px #00d4a0, 0 0 20px rgba(0,212,160,0.3); }
}
</style>
"""


def inject_css():
    st.markdown(GLOBAL_CSS, unsafe_allow_html=True)


def render_header(active="Home"):
    """Simple header using native Streamlit — no HTML, no iframes."""
    inject_css()
    col_logo, col_nav, col_right = st.columns([2, 6, 2])

    with col_logo:
        st.markdown("""
<div style="display:flex;align-items:center;gap:10px;padding:8px 0;">
  <div style="position:relative;flex-shrink:0;">
    <div style="width:40px;height:40px;background:linear-gradient(135deg,#1F3864,#2a4f8a);
      border-radius:10px;display:flex;align-items:center;justify-content:center;
      border:1px solid rgba(255,255,255,0.18);">
      <span style="font-size:18px;font-weight:900;color:#fff;letter-spacing:-1px;
        font-family:'Inter',sans-serif;">80</span>
    </div>
    <div style="position:absolute;bottom:-1px;right:-1px;width:8px;height:8px;
      background:#00d4a0;border-radius:50%;border:1.5px solid #080f1e;
      animation:led-green 2s ease-in-out infinite;"></div>
  </div>
  <div>
    <div style="font-size:16px;font-weight:800;color:#fff;
      letter-spacing:-0.03em;font-family:'Inter',sans-serif;line-height:1;">80</div>
    <div style="font-size:9px;font-weight:600;color:#4d9fff;letter-spacing:0.1em;
      text-transform:uppercase;font-family:'Inter',sans-serif;margin-top:2px;">IAM Audit Tool</div>
  </div>
</div>
""", unsafe_allow_html=True)

    with col_nav:
        n1, n2, n3, n4 = st.columns(4)
        with n1:
            st.page_link("pages/home.py",       label="Home",       icon="🏠")
        with n2:
            st.page_link("pages/tool.py",        label="Tool",       icon="🛡️")
        with n3:
            st.page_link("pages/about.py",       label="About",      icon="📋")
        with n4:
            st.page_link("pages/how_to_use.py",  label="How to Use", icon="📖")

    with col_right:
        st.markdown("""
<div style="text-align:right;padding:8px 0;">
  <span style="font-size:11px;color:rgba(255,255,255,0.2);
    font-family:'Inter',sans-serif;">IAM · 2026</span>
</div>
""", unsafe_allow_html=True)

    st.markdown("""
<div style="height:1px;background:linear-gradient(90deg,transparent,
  rgba(77,159,255,0.3),rgba(0,212,160,0.3),transparent);
  margin-bottom:24px;"></div>
""", unsafe_allow_html=True)


def render_sidebar_brand():
    """Sidebar brand — simple, no inject_css."""
    st.markdown("""
<div style="padding:12px 0 16px;border-bottom:1px solid rgba(255,255,255,0.07);
  margin-bottom:12px;">
  <div style="display:flex;align-items:center;gap:10px;">
    <div style="position:relative;flex-shrink:0;">
      <div style="width:34px;height:34px;background:#1F3864;border-radius:8px;
        display:flex;align-items:center;justify-content:center;
        border:1px solid rgba(255,255,255,0.15);">
        <span style="font-size:15px;font-weight:900;color:#fff;
          font-family:'Inter',sans-serif;letter-spacing:-1px;">80</span>
      </div>
      <div style="position:absolute;bottom:-1px;right:-1px;width:7px;height:7px;
        background:#00d4a0;border-radius:50%;border:1.5px solid #0d1628;
        animation:led-green 2s ease-in-out infinite;"></div>
    </div>
    <div>
      <div style="font-size:14px;font-weight:800;color:#fff;
        font-family:'Inter',sans-serif;">80</div>
      <div style="font-size:9px;font-weight:600;color:#4d9fff;
        letter-spacing:0.08em;text-transform:uppercase;
        font-family:'Inter',sans-serif;margin-top:1px;">IAM Audit Tool</div>
    </div>
  </div>
</div>
""", unsafe_allow_html=True)


def stat_card(number, label, sublabel="", color="#4d9fff"):
    glow = {"#4d9fff":"rgba(77,159,255,0.4)","#00d4a0":"rgba(0,212,160,0.4)",
            "#ffb347":"rgba(255,179,71,0.4)","#ff4d5e":"rgba(255,77,94,0.4)"}.get(color,"rgba(77,159,255,0.4)")
    return f"""
<div style="background:#111f38;border:1px solid rgba(255,255,255,0.07);
  border-radius:14px;padding:22px 18px;text-align:center;
  border-top:2px solid {color};">
  <div style="font-size:34px;font-weight:900;color:#fff;
    letter-spacing:-0.04em;font-family:'Inter',sans-serif;
    text-shadow:0 0 20px {glow};">{number}</div>
  <div style="font-size:11px;font-weight:700;color:{color};
    letter-spacing:0.07em;text-transform:uppercase;
    font-family:'Inter',sans-serif;margin-top:8px;
    text-shadow:0 0 10px {glow};">{label}</div>
  {f'<div style="font-size:10px;color:#5a7394;font-family:Inter,sans-serif;margin-top:4px;">{sublabel}</div>' if sublabel else ''}
</div>"""


def section_header(title, subtitle=""):
    sub = f'<div style="font-size:13px;color:#5a7394;font-family:Inter,sans-serif;margin-top:4px;">{subtitle}</div>' if subtitle else ''
    return f"""
<div style="margin:36px 0 18px;">
  <div style="display:flex;align-items:center;gap:12px;margin-bottom:4px;">
    <div style="width:3px;height:20px;background:linear-gradient(#4d9fff,#00d4a0);
      border-radius:2px;flex-shrink:0;box-shadow:0 0 8px rgba(77,159,255,0.5);"></div>
    <div style="font-size:18px;font-weight:800;color:#fff;
      letter-spacing:-0.025em;font-family:Inter,sans-serif;">{title}</div>
  </div>
  {sub}
</div>"""


def led_dot(color="green", size=8):
    colors = {"green":("#00d4a0","led-green"),"blue":("#4d9fff","led-blue"),
              "red":("#ff4d5e","led-red"),"amber":("#ffb347","led-amber")}
    hex_c, anim = colors.get(color, colors["green"])
    return f'<span style="display:inline-block;width:{size}px;height:{size}px;background:{hex_c};border-radius:50%;animation:{anim} 2s ease-in-out infinite;vertical-align:middle;flex-shrink:0;"></span>'


def led_status_bar(status="idle"):
    configs = {
        "idle":     ("#5a7394","–","Idle — ready to scan"),
        "scanning": ("#4d9fff","◉","Scanning in progress…"),
        "complete": ("#00d4a0","✓","Scan complete"),
        "error":    ("#ff4d5e","✗","Error — check inputs"),
    }
    color, symbol, label = configs.get(status, configs["idle"])
    dot = led_dot("blue" if status=="scanning" else "green" if status=="complete" else "red" if status=="error" else "green", 8)
    return f"""
<div style="display:flex;align-items:center;gap:10px;background:#0d1628;
  border:1px solid rgba(255,255,255,0.07);border-radius:10px;padding:10px 16px;">
  {dot}
  <span style="font-size:13px;font-weight:600;color:{color};
    font-family:'Inter',sans-serif;">{label}</span>
</div>"""

