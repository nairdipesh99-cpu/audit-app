"""80 — IAM Audit Tool | Home page — Premium dark theme"""

import streamlit as st
from components import render_header, render_sidebar_brand, stat_card, section_header, check_pill

with st.sidebar:
    render_sidebar_brand()

render_header()

# ── HERO ─────────────────────────────────────────────────────────────────────
st.markdown("""
<div style="
  position:relative;
  background:linear-gradient(135deg,#111f38 0%,#0d1a2e 60%,#0B1628 100%);
  border:1px solid rgba(255,255,255,0.08);
  border-radius:20px;
  padding:52px 52px 48px;
  margin-bottom:36px;
  overflow:hidden;
">
  <!-- Background 80 watermark -->
  <div style="
    position:absolute;right:-30px;top:-40px;
    font-size:280px;font-weight:900;color:rgba(255,255,255,0.025);
    font-family:'Inter',sans-serif;line-height:1;pointer-events:none;
    letter-spacing:-0.05em;
  ">80</div>

  <!-- Glow orb -->
  <div style="
    position:absolute;top:-60px;right:100px;
    width:300px;height:300px;
    background:radial-gradient(circle,rgba(77,159,255,0.08) 0%,transparent 70%);
    pointer-events:none;
  "></div>

  <!-- Eyebrow -->
  <div style="
    display:inline-flex;align-items:center;gap:8px;
    background:rgba(77,159,255,0.1);
    border:1px solid rgba(77,159,255,0.25);
    border-radius:20px;padding:5px 14px;margin-bottom:20px;
  ">
    <div style="width:5px;height:5px;background:#4d9fff;border-radius:50%;box-shadow:0 0 8px rgba(77,159,255,0.8);"></div>
    <span style="font-size:11px;font-weight:700;color:#4d9fff;letter-spacing:0.1em;font-family:'Inter',sans-serif;text-transform:uppercase;">Built for IT Auditors &amp; Compliance Teams</span>
  </div>

  <!-- Headline -->
  <h1 style="
    font-size:48px;font-weight:900;color:#ffffff;
    letter-spacing:-0.04em;line-height:1.05;
    font-family:'Inter',sans-serif;
    margin:0 0 18px 0;max-width:600px;
  ">80% of your IAM<br>audit. Done in<br><span style="color:#4d9fff;">10 minutes.</span></h1>

  <!-- Subtext -->
  <p style="
    font-size:16px;color:#7a8fa6;line-height:1.7;
    max-width:520px;font-family:'Inter',sans-serif;
    font-weight:400;margin:0 0 32px 0;
  ">Upload your HR Master and System Access files. 80 runs 18 automated checks,
  maps every finding to ISO 27001, SOX, GDPR and PCI-DSS, writes the audit opinion,
  and produces a workpaper-ready Excel report.</p>

  <!-- CTA buttons -->
  <div style="display:flex;gap:12px;flex-wrap:wrap;">
    <a href="/Tool" target="_self" style="
      background:#4d9fff;color:#0B1628;
      font-size:14px;font-weight:700;
      padding:13px 28px;border-radius:10px;
      text-decoration:none;font-family:'Inter',sans-serif;
      letter-spacing:0.01em;
      box-shadow:0 4px 20px rgba(77,159,255,0.35);
      transition:all 0.2s;display:inline-block;
    ">Run the audit →</a>
    <a href="/About" target="_self" style="
      background:rgba(255,255,255,0.05);color:#e8edf5;
      font-size:14px;font-weight:600;
      padding:13px 28px;border-radius:10px;
      text-decoration:none;font-family:'Inter',sans-serif;
      border:1px solid rgba(255,255,255,0.1);
      transition:all 0.2s;display:inline-block;
    ">Learn more</a>
  </div>
</div>
""", unsafe_allow_html=True)

# ── STATS ROW ─────────────────────────────────────────────────────────────────
c1, c2, c3, c4 = st.columns(4)
with c1:
    st.markdown(stat_card("18", "Automated checks", "Run simultaneously"), unsafe_allow_html=True)
with c2:
    st.markdown(stat_card("4", "Frameworks", "SOX · ISO · GDPR · PCI", "#00c896"), unsafe_allow_html=True)
with c3:
    st.markdown(stat_card("9", "Workpaper sheets", "Ready for external audit", "#ffa502"), unsafe_allow_html=True)
with c4:
    st.markdown(stat_card("5K+", "Stress tested", "Zero false positives", "#ff4757"), unsafe_allow_html=True)

# ── WHAT IS 80 ────────────────────────────────────────────────────────────────
st.markdown(section_header("What is 80?",
    "The first tool to automate full population IAM testing without a single API connection."),
    unsafe_allow_html=True)

st.markdown("""
<div style="
  background:#111f38;border:1px solid rgba(255,255,255,0.07);
  border-radius:16px;padding:32px 36px;margin-bottom:8px;
  border-left:3px solid #4d9fff;
">
  <p style="font-size:15px;color:#e8edf5;line-height:1.8;margin:0;font-family:'Inter',sans-serif;">
    Every IAM audit has two parts. The first <strong style="color:#4d9fff;">80%</strong> is mechanical —
    cross-referencing HR records against system accounts, checking for dormant logins, verifying MFA,
    flagging SoD violations, mapping findings to compliance frameworks, formatting workpapers.
    Time-consuming, repetitive, and prone to human error when done manually.
  </p>
  <p style="font-size:15px;color:#e8edf5;line-height:1.8;margin:16px 0 0;font-family:'Inter',sans-serif;">
    The second <strong style="color:#ffffff;">20%</strong> is professional judgement — verifying findings,
    assessing materiality, writing the opinion, managing the relationship. That is where an auditor's
    experience actually matters.
    <strong style="color:#4d9fff;">80 automates the first part entirely.</strong>
  </p>
</div>
""", unsafe_allow_html=True)

# ── BEFORE / AFTER ────────────────────────────────────────────────────────────
st.markdown(section_header("Manual audit vs 80",
    "The gap between what sampling finds and what full population testing finds."),
    unsafe_allow_html=True)

col1, col2 = st.columns(2)
with col1:
    st.markdown("""
<div style="background:#111f38;border:1px solid rgba(255,71,87,0.2);border-radius:16px;padding:28px;border-top:2px solid #ff4757;">
  <div style="font-size:12px;font-weight:700;color:#ff4757;letter-spacing:0.08em;text-transform:uppercase;font-family:'Inter',sans-serif;margin-bottom:18px;">Without 80</div>
""", unsafe_allow_html=True)
    items = [
        "Manual VLOOKUP across 1,000+ accounts — hours",
        "Random sampling misses 99.96% of accounts",
        "Framework references looked up manually",
        "Audit opinion drafted from scratch",
        "25-item sample takes another half day",
        "Legacy system data stuck in PDFs",
        "Terminated employees missed if not sampled",
        "Contractor expiry checked one by one",
    ]
    for item in items:
        st.markdown(f"""
<div style="display:flex;align-items:flex-start;gap:10px;padding:8px 0;border-bottom:1px solid rgba(255,255,255,0.04);">
  <span style="color:#ff4757;font-size:14px;flex-shrink:0;margin-top:1px;">✗</span>
  <span style="font-size:13px;color:#7a8fa6;font-family:'Inter',sans-serif;line-height:1.5;">{item}</span>
</div>""", unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)

with col2:
    st.markdown("""
<div style="background:#111f38;border:1px solid rgba(0,200,150,0.2);border-radius:16px;padding:28px;border-top:2px solid #00c896;">
  <div style="font-size:12px;font-weight:700;color:#00c896;letter-spacing:0.08em;text-transform:uppercase;font-family:'Inter',sans-serif;margin-bottom:18px;">With 80</div>
""", unsafe_allow_html=True)
    wins = [
        "Full population tested in under 10 minutes",
        "Every account checked across all 18 issue types",
        "SOX, ISO 27001, GDPR, PCI-DSS cited per finding",
        "AI writes the professional audit opinion",
        "25-item prioritised sample — one click",
        "AI extracts data from any legacy screenshot",
        "Every terminated employee detected automatically",
        "All contractors without expiry flagged instantly",
    ]
    for item in wins:
        st.markdown(f"""
<div style="display:flex;align-items:flex-start;gap:10px;padding:8px 0;border-bottom:1px solid rgba(255,255,255,0.04);">
  <span style="color:#00c896;font-size:14px;flex-shrink:0;margin-top:1px;">✓</span>
  <span style="font-size:13px;color:#e8edf5;font-family:'Inter',sans-serif;line-height:1.5;">{item}</span>
</div>""", unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)

# ── 18 CHECKS PREVIEW ────────────────────────────────────────────────────────
st.markdown(section_header("18 automated checks",
    "Running simultaneously. One consolidated finding per account."),
    unsafe_allow_html=True)

checks = [
    ("Orphaned account",               "critical"),
    ("Terminated with active account", "critical"),
    ("Post-termination login",         "critical"),
    ("SoD violation",                  "critical"),
    ("RBAC violation",                 "critical"),
    ("Dormant account (90+ days)",     "high"),
    ("Privilege creep (4+ roles)",     "high"),
    ("Generic / shared account",       "high"),
    ("MFA not enabled",                "high"),
    ("Contractor without expiry",      "high"),
    ("Super-user outside IT",          "high"),
    ("Unauthorised privileged access", "high"),
    ("Registry review overdue",        "high"),
    ("Service / system account",       "medium"),
    ("Password never expired",         "medium"),
    ("Duplicate system account",       "medium"),
    ("Excessive multi-system access",  "medium"),
    ("Near-match email",               "medium"),
]

cols = st.columns(3)
for i, (name, sev) in enumerate(checks):
    with cols[i % 3]:
        color_map = {
            "critical": ("#ff4757", "rgba(255,71,87,0.08)", "rgba(255,71,87,0.2)"),
            "high":     ("#ffa502", "rgba(255,165,2,0.08)",  "rgba(255,165,2,0.2)"),
            "medium":   ("#4d9fff", "rgba(77,159,255,0.08)", "rgba(77,159,255,0.2)"),
        }
        fc, bg, border = color_map[sev]
        st.markdown(f"""
<div style="
  background:{bg};border:1px solid {border};
  border-radius:10px;padding:12px 14px;margin-bottom:8px;
  display:flex;align-items:center;gap:10px;
">
  <div style="width:6px;height:6px;background:{fc};border-radius:50%;flex-shrink:0;box-shadow:0 0 6px {fc}88;"></div>
  <span style="font-size:12px;font-weight:600;color:#e8edf5;font-family:'Inter',sans-serif;">{name}</span>
</div>""", unsafe_allow_html=True)

# ── WHO USES 80 ───────────────────────────────────────────────────────────────
st.markdown(section_header("Who uses 80"), unsafe_allow_html=True)

users = [
    ("Internal auditors",
     "🔍",
     "#4d9fff",
     "Running periodic IAM reviews. 80 replaces manual Excel workbooks and makes full population testing the standard, not the exception."),
    ("External auditors",
     "📋",
     "#00c896",
     "Conducting ISO 27001, SOX ITGC or PCI-DSS assessments. 80 produces workpaper-ready evidence and the 25-item sample your team needs in one click."),
    ("IT security teams",
     "🛡️",
     "#ffa502",
     "Running quarterly access recertification. 80 flags what needs attention before it becomes an audit finding — dormant accounts, SoD violations, contractor access that never expired."),
]
u1, u2, u3 = st.columns(3)
for col, (title, icon, color, body) in zip([u1, u2, u3], users):
    with col:
        st.markdown(f"""
<div style="
  background:#111f38;
  border:1px solid rgba(255,255,255,0.07);
  border-radius:16px;padding:28px 24px;
  border-top:2px solid {color};
  height:100%;
">
  <div style="font-size:28px;margin-bottom:14px;">{icon}</div>
  <div style="font-size:14px;font-weight:700;color:#ffffff;font-family:'Inter',sans-serif;margin-bottom:10px;">{title}</div>
  <div style="font-size:13px;color:#7a8fa6;font-family:'Inter',sans-serif;line-height:1.7;">{body}</div>
</div>""", unsafe_allow_html=True)

# ── CTA ────────────────────────────────────────────────────────────────────────
st.markdown("<div style='margin-top:48px;'></div>", unsafe_allow_html=True)
st.markdown("""
<div style="
  background:linear-gradient(135deg,#111f38 0%,#0d1a2e 100%);
  border:1px solid rgba(77,159,255,0.2);
  border-radius:20px;
  padding:44px 52px;
  text-align:center;
  position:relative;overflow:hidden;
">
  <div style="position:absolute;top:-80px;left:50%;transform:translateX(-50%);width:400px;height:200px;background:radial-gradient(circle,rgba(77,159,255,0.06) 0%,transparent 70%);pointer-events:none;"></div>
  <div style="font-size:28px;font-weight:900;color:#ffffff;letter-spacing:-0.03em;font-family:'Inter',sans-serif;margin-bottom:10px;">Ready to run your first audit?</div>
  <div style="font-size:14px;color:#7a8fa6;font-family:'Inter',sans-serif;margin-bottom:28px;">No API. No IT project. No contract. Upload five files and get results in under 10 minutes.</div>
  <div style="display:flex;gap:12px;justify-content:center;flex-wrap:wrap;">
    <a href="/Tool" target="_self" style="background:#4d9fff;color:#0B1628;font-size:14px;font-weight:700;padding:14px 32px;border-radius:10px;text-decoration:none;font-family:'Inter',sans-serif;box-shadow:0 4px 20px rgba(77,159,255,0.35);">Run the audit →</a>
    <a href="/How_to_Use" target="_self" style="background:rgba(255,255,255,0.06);color:#e8edf5;font-size:14px;font-weight:600;padding:14px 32px;border-radius:10px;text-decoration:none;font-family:'Inter',sans-serif;border:1px solid rgba(255,255,255,0.1);">How it works</a>
  </div>
</div>
""", unsafe_allow_html=True)

