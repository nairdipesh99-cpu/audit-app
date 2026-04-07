"""80 — IAM Audit Tool | Home page"""

import streamlit as st
from components import render_header, render_sidebar_brand

with st.sidebar:
    render_sidebar_brand()

render_header()

# ── Hero section ──────────────────────────────────────────────────────────────
st.markdown("""
<div style="background:#1F3864;border-radius:12px;padding:40px 44px;margin-bottom:28px">
  <div style="font-size:13px;font-weight:500;color:#8fa8cc;letter-spacing:.08em;text-transform:uppercase;margin-bottom:10px">Built for IT Auditors</div>
  <div style="font-size:32px;font-weight:700;color:#ffffff;line-height:1.2;margin-bottom:14px;font-family:system-ui,sans-serif">
    80% of your IAM audit.<br>Done in 10 minutes.
  </div>
  <div style="font-size:15px;color:#b8ccdf;line-height:1.7;max-width:580px">
    Upload your HR Master and System Access files. 80 runs 15 automated checks,
    maps every finding to ISO 27001, SOX, GDPR and PCI-DSS, writes the audit opinion,
    and produces a workpaper-ready Excel report — all before your first coffee.
  </div>
</div>
""", unsafe_allow_html=True)

# ── Stats row ─────────────────────────────────────────────────────────────────
c1, c2, c3, c4 = st.columns(4)
c1.metric("Automated checks",    "15",   help="Run simultaneously on every account")
c2.metric("Compliance frameworks", "4",  help="SOX · ISO 27001 · GDPR · PCI-DSS")
c3.metric("Report sheets",       "9+",  help="Workpaper-ready Excel output")
c4.metric("Time to first result", "< 10 min", help="From upload to downloadable report")

st.divider()

# ── What is 80 ────────────────────────────────────────────────────────────────
st.markdown("### What is 80?")
st.markdown("""
Every IAM audit has two parts. The first 80% is mechanical — cross-referencing HR records 
against system accounts, checking for dormant logins, verifying MFA status, flagging SoD violations, 
mapping findings to compliance frameworks, formatting workpapers. This work is time-consuming, 
repetitive and prone to human error when done manually.

The second 20% is professional judgement — verifying individual findings with the client, 
assessing materiality, writing the opinion, managing the relationship. That is where an auditor's 
experience actually matters.

**80 automates the first part entirely.** You upload the data. 80 does the rest.
""")

st.divider()

# ── The problem it solves ─────────────────────────────────────────────────────
st.markdown("### The problem it solves")
col1, col2 = st.columns(2)

with col1:
    st.markdown("**Without 80**")
    for item in [
        "Manual VLOOKUP across 1,000+ accounts — hours of work",
        "Random sampling misses 70% of issues by design",
        "Framework references looked up manually for each finding",
        "Audit opinion drafted from scratch each engagement",
        "External auditors request a manual 25-item sample — more hours",
        "Legacy system data stuck in PDFs and screenshots",
    ]:
        st.markdown(f"— {item}")

with col2:
    st.markdown("**With 80**")
    for item in [
        "Full population tested in under 10 minutes",
        "Every account checked across all 15 issue types",
        "SOX, ISO 27001, GDPR, PCI-DSS cited automatically per finding",
        "AI writes the professional audit memo",
        "25-item prioritised sample with test instructions — one click",
        "AI extracts account data from any image or PDF",
    ]:
        st.markdown(f"✓ {item}")

st.divider()

# ── Who it is for ─────────────────────────────────────────────────────────────
st.markdown("### Who uses 80")
r1, r2, r3 = st.columns(3)
with r1:
    st.markdown("**Internal auditors**")
    st.markdown("Running periodic IAM reviews for your organisation. 80 replaces the manual Excel workbooks and makes full population testing the standard, not the exception.")
with r2:
    st.markdown("**External auditors**")
    st.markdown("Conducting ISO 27001, SOX ITGC or PCI-DSS assessments for clients. 80 produces workpaper-ready evidence and the 25-item sample your team needs in one click.")
with r3:
    st.markdown("**IT security teams**")
    st.markdown("Running quarterly access recertification reviews. 80 flags what needs attention before it becomes an audit finding — dormant accounts, SoD violations, contractor access that never expired.")

st.divider()

# ── CTA ───────────────────────────────────────────────────────────────────────
st.markdown("### Ready to start?")
b1, b2, b3 = st.columns(3)
with b1:
    if st.button("🛡️  Use the Tool", use_container_width=True, type="primary"):
        st.switch_page("pages/tool.py")
with b2:
    if st.button("📋  About 80", use_container_width=True):
        st.switch_page("pages/about.py")
with b3:
    if st.button("📖  How to Use", use_container_width=True):
        st.switch_page("pages/how_to_use.py")

