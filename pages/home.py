"""80 — IAM Audit Tool | Home — Premium dark v2"""

import streamlit as st
from components import render_header, render_sidebar_brand, stat_card, section_header

with st.sidebar:
    render_sidebar_brand()

render_header(active="Home")

# ── HERO ─────────────────────────────────────────────────────────────────────
st.markdown("""
<div style="
  position:relative;
  background:linear-gradient(135deg,#0d1628 0%,#0a1220 100%);
  border:1px solid rgba(255,255,255,0.07);
  border-radius:20px;
  padding:60px 56px 56px;
  margin-bottom:32px;
  overflow:hidden;
">
  <!-- Watermark 80 -->
  <div style="
    position:absolute;right:-20px;top:-60px;
    font-size:320px;font-weight:900;
    color:rgba(255,255,255,0.018);
    font-family:'Inter',sans-serif;
    line-height:1;pointer-events:none;
    letter-spacing:-0.05em;user-select:none;
  ">80</div>

  <!-- Top glow -->
  <div style="
    position:absolute;top:-100px;right:80px;
    width:400px;height:300px;
    background:radial-gradient(circle,rgba(77,159,255,0.07) 0%,transparent 70%);
    pointer-events:none;
  "></div>

  <!-- Eyebrow pill -->
  <div style="
    display:inline-flex;align-items:center;gap:8px;
    background:rgba(77,159,255,0.08);
    border:1px solid rgba(77,159,255,0.2);
    border-radius:20px;padding:6px 16px;margin-bottom:24px;
  ">
    <div style="width:5px;height:5px;background:#4d9fff;border-radius:50%;
      box-shadow:0 0 10px rgba(77,159,255,0.9);"></div>
    <span style="font-size:11px;font-weight:700;color:#4d9fff;
      letter-spacing:0.1em;font-family:'Inter',sans-serif;
      text-transform:uppercase;">Built for IT Auditors &amp; Compliance Teams</span>
  </div>

  <!-- Main headline -->
  <div style="
    font-size:52px;font-weight:900;color:#ffffff;
    letter-spacing:-0.04em;line-height:1.05;
    font-family:'Inter',sans-serif;
    margin:0 0 20px 0;max-width:620px;
  ">80% of your IAM audit.<br>Done in <span style="color:#4d9fff;">10 minutes.</span></div>

  <!-- Subtext -->
  <div style="
    font-size:16px;color:#5a7394;line-height:1.75;
    max-width:500px;font-family:'Inter',sans-serif;
    margin:0 0 36px 0;
  ">Upload your HR Master and System Access files. 18 automated checks run
  simultaneously across every account — full population, not a sample.
  Findings mapped to SOX, ISO 27001, GDPR and PCI-DSS. Workpaper ready.</div>

  <!-- CTA row -->
  <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;">
    <a href="/Tool" target="_self" style="
      display:inline-flex;align-items:center;gap:8px;
      background:#4d9fff;color:#080f1e;
      font-size:14px;font-weight:700;letter-spacing:0.01em;
      padding:14px 30px;border-radius:10px;
      text-decoration:none;font-family:'Inter',sans-serif;
      box-shadow:0 4px 24px rgba(77,159,255,0.4);
      transition:all 0.18s;
    ">Run the audit &nbsp;→</a>
    <a href="/How_to_Use" target="_self" style="
      display:inline-flex;align-items:center;gap:8px;
      background:rgba(255,255,255,0.04);color:#c8d8ef;
      font-size:14px;font-weight:600;
      padding:14px 28px;border-radius:10px;
      text-decoration:none;font-family:'Inter',sans-serif;
      border:1px solid rgba(255,255,255,0.09);
      transition:all 0.18s;
    ">See how it works</a>
  </div>

  <!-- Trust note -->
  <div style="
    margin-top:28px;
    display:flex;align-items:center;gap:8px;
  ">
    <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
      <circle cx="7" cy="7" r="6.5" stroke="#00d4a0" stroke-opacity="0.4"/>
      <path d="M4 7l2 2 4-4" stroke="#00d4a0" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
    </svg>
    <span style="font-size:12px;color:#5a7394;font-family:'Inter',sans-serif;">
      Stress tested on 5,000 employees · 1,108 findings · zero false positives
    </span>
  </div>
</div>
""", unsafe_allow_html=True)

# ── STATS ─────────────────────────────────────────────────────────────────────
c1, c2, c3, c4 = st.columns(4)
with c1:
    st.markdown(stat_card("18", "Automated checks", "Simultaneous on every account"), unsafe_allow_html=True)
with c2:
    st.markdown(stat_card("4", "Frameworks cited", "SOX · ISO · GDPR · PCI", "#00d4a0"), unsafe_allow_html=True)
with c3:
    st.markdown(stat_card("9", "Workpaper sheets", "External auditor ready", "#ffb347"), unsafe_allow_html=True)
with c4:
    st.markdown(stat_card("100%", "Population tested", "Not a 25-account sample", "#ff4d5e"), unsafe_allow_html=True)

# ── WHAT IS 80 ────────────────────────────────────────────────────────────────
st.markdown(section_header("What is 80?",
    "The first IAM audit tool that tests every account — not a sample."),
    unsafe_allow_html=True)

st.markdown("""
<div style="
  background:#0d1628;
  border:1px solid rgba(255,255,255,0.07);
  border-left:3px solid #4d9fff;
  border-radius:16px;padding:32px 36px;
">
  <p style="font-size:15px;color:#c8d8ef;line-height:1.85;margin:0 0 16px;font-family:'Inter',sans-serif;">
    Every IAM audit has two parts. The first <strong style="color:#4d9fff;">80%</strong> is
    mechanical — cross-referencing HR records against system accounts, checking dormant
    logins, verifying MFA, flagging SoD violations, mapping findings to compliance
    frameworks, formatting workpapers. Time-consuming, repetitive, prone to human error.
  </p>
  <p style="font-size:15px;color:#c8d8ef;line-height:1.85;margin:0;font-family:'Inter',sans-serif;">
    The second <strong style="color:#ffffff;">20%</strong> is professional judgement —
    verifying findings, assessing materiality, writing the opinion. That is where your
    experience matters. <strong style="color:#4d9fff;">80 automates the first part entirely.</strong>
  </p>
</div>
""", unsafe_allow_html=True)

# ── BEFORE / AFTER ────────────────────────────────────────────────────────────
st.markdown(section_header("Manual sampling vs full population testing",
    "The gap between what 25 accounts shows and what every account shows."),
    unsafe_allow_html=True)

col1, col2 = st.columns(2, gap="medium")

before_items = [
    "6–10 working days for two auditors",
    "25–30 accounts tested out of thousands",
    "99.96% of accounts never checked",
    "Terminated employees missed if not sampled",
    "Framework references looked up manually",
    "Audit opinion drafted from scratch",
    "Legacy system data stuck in PDFs",
    "Contractor expiry checked one by one",
]
after_items = [
    "Results in under 10 minutes",
    "Every single account tested",
    "100% coverage — nothing untested",
    "Every terminated employee detected",
    "SOX, ISO 27001, GDPR, PCI-DSS cited per finding",
    "AI writes the professional audit memo",
    "AI extracts data from any legacy screenshot",
    "All contractors without expiry flagged instantly",
]

with col1:
    rows = "".join([f"""
<div style="display:flex;align-items:flex-start;gap:10px;padding:10px 0;
  border-bottom:1px solid rgba(255,255,255,0.04);">
  <span style="color:#ff4d5e;font-size:13px;flex-shrink:0;margin-top:1px;font-weight:700;">✗</span>
  <span style="font-size:13px;color:#5a7394;font-family:'Inter',sans-serif;line-height:1.5;">{item}</span>
</div>""" for item in before_items])
    st.markdown(f"""
<div style="background:#0d1628;border:1px solid rgba(255,77,94,0.18);
  border-top:2px solid #ff4d5e;border-radius:16px;padding:28px 28px 20px;">
  <div style="font-size:11px;font-weight:700;color:#ff4d5e;letter-spacing:0.1em;
    text-transform:uppercase;font-family:'Inter',sans-serif;margin-bottom:16px;">
    Manual sampling</div>
  {rows}
</div>""", unsafe_allow_html=True)

with col2:
    rows = "".join([f"""
<div style="display:flex;align-items:flex-start;gap:10px;padding:10px 0;
  border-bottom:1px solid rgba(255,255,255,0.04);">
  <span style="color:#00d4a0;font-size:13px;flex-shrink:0;margin-top:1px;font-weight:700;">✓</span>
  <span style="font-size:13px;color:#c8d8ef;font-family:'Inter',sans-serif;line-height:1.5;">{item}</span>
</div>""" for item in after_items])
    st.markdown(f"""
<div style="background:#0d1628;border:1px solid rgba(0,212,160,0.18);
  border-top:2px solid #00d4a0;border-radius:16px;padding:28px 28px 20px;">
  <div style="font-size:11px;font-weight:700;color:#00d4a0;letter-spacing:0.1em;
    text-transform:uppercase;font-family:'Inter',sans-serif;margin-bottom:16px;">
    With 80</div>
  {rows}
</div>""", unsafe_allow_html=True)

# ── 18 CHECKS ────────────────────────────────────────────────────────────────
st.markdown(section_header("18 checks — running simultaneously",
    "One consolidated finding per account, all issues listed together."),
    unsafe_allow_html=True)

checks = [
    ("Orphaned account",               "critical", "#ff4d5e", "rgba(255,77,94,0.1)",  "rgba(255,77,94,0.25)"),
    ("Terminated with active account", "critical", "#ff4d5e", "rgba(255,77,94,0.1)",  "rgba(255,77,94,0.25)"),
    ("Post-termination login",         "critical", "#ff4d5e", "rgba(255,77,94,0.1)",  "rgba(255,77,94,0.25)"),
    ("SoD violation",                  "critical", "#ff4d5e", "rgba(255,77,94,0.1)",  "rgba(255,77,94,0.25)"),
    ("RBAC violation",                 "critical", "#ff4d5e", "rgba(255,77,94,0.1)",  "rgba(255,77,94,0.25)"),
    ("Dormant account (90+ days)",     "high",     "#ffb347", "rgba(255,179,71,0.1)", "rgba(255,179,71,0.25)"),
    ("Privilege creep (4+ roles)",     "high",     "#ffb347", "rgba(255,179,71,0.1)", "rgba(255,179,71,0.25)"),
    ("Generic / shared account",       "high",     "#ffb347", "rgba(255,179,71,0.1)", "rgba(255,179,71,0.25)"),
    ("MFA not enabled",                "high",     "#ffb347", "rgba(255,179,71,0.1)", "rgba(255,179,71,0.25)"),
    ("Contractor without expiry",      "high",     "#ffb347", "rgba(255,179,71,0.1)", "rgba(255,179,71,0.25)"),
    ("Super-user outside IT",          "high",     "#ffb347", "rgba(255,179,71,0.1)", "rgba(255,179,71,0.25)"),
    ("Unauthorised privileged access", "high",     "#ffb347", "rgba(255,179,71,0.1)", "rgba(255,179,71,0.25)"),
    ("Registry review overdue",        "high",     "#ffb347", "rgba(255,179,71,0.1)", "rgba(255,179,71,0.25)"),
    ("Service / system account",       "medium",   "#4d9fff", "rgba(77,159,255,0.1)", "rgba(77,159,255,0.25)"),
    ("Password never expired",         "medium",   "#4d9fff", "rgba(77,159,255,0.1)", "rgba(77,159,255,0.25)"),
    ("Duplicate system account",       "medium",   "#4d9fff", "rgba(77,159,255,0.1)", "rgba(77,159,255,0.25)"),
    ("Excessive multi-system access",  "medium",   "#4d9fff", "rgba(77,159,255,0.1)", "rgba(77,159,255,0.25)"),
    ("Near-match email",               "medium",   "#4d9fff", "rgba(77,159,255,0.1)", "rgba(77,159,255,0.25)"),
]

cols = st.columns(3, gap="small")
for i, (name, sev, fc, bg, border) in enumerate(checks):
    with cols[i % 3]:
        st.markdown(f"""
<div style="background:{bg};border:1px solid {border};border-radius:10px;
  padding:11px 14px;margin-bottom:8px;
  display:flex;align-items:center;gap:9px;">
  <div style="width:6px;height:6px;background:{fc};border-radius:50%;
    flex-shrink:0;box-shadow:0 0 7px {fc}cc;"></div>
  <span style="font-size:12px;font-weight:600;color:#c8d8ef;
    font-family:'Inter',sans-serif;">{name}</span>
</div>""", unsafe_allow_html=True)

# ── WHO USES 80 ───────────────────────────────────────────────────────────────
st.markdown(section_header("Who uses 80"), unsafe_allow_html=True)

users = [
    ("Internal auditors", "Running periodic IAM reviews. 80 replaces manual Excel workbooks and makes full population testing the standard, not the exception.", "#4d9fff"),
    ("External auditors", "Conducting ISO 27001, SOX ITGC or PCI-DSS assessments. 80 produces workpaper-ready evidence and the 25-item sample your team needs in one click.", "#00d4a0"),
    ("IT security teams", "Running quarterly access recertification. 80 flags what needs attention before it becomes an audit finding — dormant accounts, SoD violations, expired contractor access.", "#ffb347"),
]
u1, u2, u3 = st.columns(3, gap="medium")
for col, (title, body, color) in zip([u1, u2, u3], users):
    with col:
        st.markdown(f"""
<div style="background:#0d1628;border:1px solid rgba(255,255,255,0.07);
  border-top:2px solid {color};border-radius:16px;padding:28px 24px;">
  <div style="font-size:14px;font-weight:700;color:#ffffff;
    font-family:'Inter',sans-serif;margin-bottom:12px;">{title}</div>
  <div style="font-size:13px;color:#5a7394;font-family:'Inter',sans-serif;
    line-height:1.75;">{body}</div>
</div>""", unsafe_allow_html=True)

# ── BOTTOM CTA ────────────────────────────────────────────────────────────────
st.markdown("<div style='margin-top:52px'></div>", unsafe_allow_html=True)
st.markdown("""
<div style="
  background:#0d1628;
  border:1px solid rgba(77,159,255,0.15);
  border-radius:20px;
  padding:52px 56px;
  text-align:center;
  position:relative;overflow:hidden;
">
  <div style="position:absolute;top:-120px;left:50%;transform:translateX(-50%);
    width:500px;height:300px;
    background:radial-gradient(circle,rgba(77,159,255,0.05) 0%,transparent 70%);
    pointer-events:none;"></div>

  <div style="font-size:30px;font-weight:900;color:#ffffff;
    letter-spacing:-0.03em;font-family:'Inter',sans-serif;margin-bottom:12px;">
    Ready to run your first audit?</div>
  <div style="font-size:15px;color:#5a7394;font-family:'Inter',sans-serif;
    margin-bottom:32px;max-width:420px;margin-left:auto;margin-right:auto;line-height:1.7;">
    No API. No IT project. No contract.<br>Five files. Ten minutes. Workpaper ready.</div>
  <div style="display:flex;gap:12px;justify-content:center;flex-wrap:wrap;">
    <a href="/Tool" target="_self" style="
      background:#4d9fff;color:#080f1e;
      font-size:14px;font-weight:700;
      padding:15px 34px;border-radius:10px;
      text-decoration:none;font-family:'Inter',sans-serif;
      box-shadow:0 4px 24px rgba(77,159,255,0.4);
    ">Run the audit →</a>
    <a href="/About" target="_self" style="
      background:rgba(255,255,255,0.05);color:#c8d8ef;
      font-size:14px;font-weight:600;
      padding:15px 30px;border-radius:10px;
      text-decoration:none;font-family:'Inter',sans-serif;
      border:1px solid rgba(255,255,255,0.09);
    ">About 80</a>
  </div>
</div>
""", unsafe_allow_html=True)

