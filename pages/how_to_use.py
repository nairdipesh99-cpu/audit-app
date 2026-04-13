"""80 — IAM Audit Tool | How to Use"""

import streamlit as st
from components import inject_css, render_header, render_sidebar_brand, section_header

render_header(active="How to Use")

with st.sidebar:
    render_sidebar_brand()

# ── PAGE HERO ─────────────────────────────────────────────────────────────────
st.markdown("""
<div style="
  background:#0d1628;
  border:1px solid rgba(255,255,255,0.07);
  border-radius:20px;
  padding:48px 52px;
  margin-bottom:36px;
  border-left:3px solid #00d4a0;
">
  <div style="font-size:11px;font-weight:700;color:#00d4a0;letter-spacing:0.1em;
    text-transform:uppercase;font-family:'Inter',sans-serif;margin-bottom:14px;">How to Use</div>
  <div style="font-size:38px;font-weight:900;color:#ffffff;letter-spacing:-0.04em;
    line-height:1.1;font-family:'Inter',sans-serif;margin-bottom:16px;">
    From documents to workpaper<br>in four steps.
  </div>
  <div style="font-size:15px;color:#5a7394;line-height:1.8;max-width:520px;
    font-family:'Inter',sans-serif;">
    A complete walkthrough from document collection through to finished
    workpaper-ready Excel report.
  </div>
</div>
""", unsafe_allow_html=True)

# ── FOUR STEPS OVERVIEW ───────────────────────────────────────────────────────
steps_overview = [
    ("01", "Collect documents",  "Request from client before fieldwork", "#4d9fff"),
    ("02", "Upload to 80",       "Single upload zone — all files at once", "#4d9fff"),
    ("03", "Set scope & run",    "Confirm population, set dates, click GO", "#00d4a0"),
    ("04", "Review & download",  "Findings on screen, workpaper in one click", "#00d4a0"),
]
cols = st.columns(4, gap="small")
for col, (num, title, sub, color) in zip(cols, steps_overview):
    with col:
        st.markdown(f"""
<div style="background:#0d1628;border:1px solid rgba(255,255,255,0.07);
  border-radius:14px;padding:24px 20px;text-align:center;
  border-top:2px solid {color};">
  <div style="font-size:32px;font-weight:900;color:{color};
    letter-spacing:-0.04em;font-family:'Inter',sans-serif;line-height:1;
    margin-bottom:12px;opacity:0.6;">{num}</div>
  <div style="font-size:13px;font-weight:700;color:#ffffff;
    font-family:'Inter',sans-serif;margin-bottom:8px;">{title}</div>
  <div style="font-size:11px;color:#5a7394;font-family:'Inter',sans-serif;
    line-height:1.6;">{sub}</div>
</div>""", unsafe_allow_html=True)

# ── STEP 1 ────────────────────────────────────────────────────────────────────
st.markdown(section_header("Step 1 — Collect your documents",
    "Request these from the client before fieldwork begins. 80 detects document type from the filename automatically."),
    unsafe_allow_html=True)

col1, col2 = st.columns(2, gap="medium")
with col1:
    st.markdown("""
<div style="background:#0d1628;border:1px solid rgba(255,77,94,0.2);
  border-radius:14px;padding:28px;border-top:2px solid #ff4d5e;margin-bottom:12px;">
  <div style="font-size:11px;font-weight:700;color:#ff4d5e;letter-spacing:0.08em;
    text-transform:uppercase;font-family:'Inter',sans-serif;margin-bottom:16px;">Required</div>
""", unsafe_allow_html=True)
    req_files = [
        ("HR_Master.xlsx", "All employees: Email, FullName, Department, EmploymentStatus, ContractType, TerminationDate"),
        ("System_Access.xlsx", "All accounts: Email, AccessLevel, LastLoginDate, PasswordLastSet, MFA, AccountCreatedDate"),
    ]
    for fname, desc in req_files:
        st.markdown(f"""
<div style="padding:12px 0;border-bottom:1px solid rgba(255,255,255,0.04);">
  <div style="font-size:12px;font-weight:700;color:#ffffff;
    font-family:'JetBrains Mono',monospace;margin-bottom:5px;">{fname}</div>
  <div style="font-size:12px;color:#5a7394;font-family:'Inter',sans-serif;
    line-height:1.5;">{desc}</div>
</div>""", unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)
    st.error("Request HR extract directly from HR — not from IT. Request the system access extract from IT with written instruction: full unfiltered export, do not exclude service accounts, disabled accounts or contractor accounts.")

with col2:
    st.markdown("""
<div style="background:#0d1628;border:1px solid rgba(0,212,160,0.2);
  border-radius:14px;padding:28px;border-top:2px solid #00d4a0;margin-bottom:12px;">
  <div style="font-size:11px;font-weight:700;color:#00d4a0;letter-spacing:0.08em;
    text-transform:uppercase;font-family:'Inter',sans-serif;margin-bottom:16px;">Recommended</div>
""", unsafe_allow_html=True)
    rec_files = [
        ("SOA_ISO27001.xlsx",    "Extracts SoD rules — findings cite client's own policy"),
        ("RBAC_Matrix.xlsx",     "Enables RBAC check — compares access against role entitlements"),
        ("Privileged_Registry.xlsx", "Enables unauthorised admin check"),
        ("Access_Control_Policy.pdf", "Cited in framework references on every finding"),
        ("JML_Procedure.pdf",    "Cited when terminated accounts are found active"),
    ]
    for fname, desc in rec_files:
        st.markdown(f"""
<div style="padding:12px 0;border-bottom:1px solid rgba(255,255,255,0.04);">
  <div style="font-size:12px;font-weight:700;color:#ffffff;
    font-family:'JetBrains Mono',monospace;margin-bottom:5px;">{fname}</div>
  <div style="font-size:12px;color:#5a7394;font-family:'Inter',sans-serif;
    line-height:1.5;">{desc}</div>
</div>""", unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)

# ── STEP 2 ────────────────────────────────────────────────────────────────────
st.markdown(section_header("Step 2 — Upload your files",
    "All files go into the single document zone on the Tool page. 80 classifies each one automatically."),
    unsafe_allow_html=True)

st.markdown("""
<div style="background:#0d1628;border:1px solid rgba(255,255,255,0.07);
  border-radius:14px;padding:28px 32px;margin-bottom:8px;">
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;">
    <div>
      <div style="font-size:13px;font-weight:700;color:#4d9fff;
        font-family:'Inter',sans-serif;margin-bottom:10px;">What 80 detects automatically</div>
      <div style="font-size:13px;color:#5a7394;font-family:'Inter',sans-serif;line-height:1.8;">
        HR Master → keywords: HR, employee, staff, personnel<br>
        System Access → keywords: UAL, access, AD, system<br>
        SOA / Controls → keywords: SOA, ISO27001, annex<br>
        RBAC Matrix → keywords: RBAC, role, matrix<br>
        Registry → keywords: privileged, registry, admin<br>
        Policy docs → any PDF with policy keywords
      </div>
    </div>
    <div>
      <div style="font-size:13px;font-weight:700;color:#4d9fff;
        font-family:'Inter',sans-serif;margin-bottom:10px;">Accepted formats</div>
      <div style="font-size:13px;color:#5a7394;font-family:'Inter',sans-serif;line-height:1.8;">
        .xlsx — Excel workbooks<br>
        .xls — Legacy Excel<br>
        .csv — Comma-separated<br>
        .pdf — PDF documents<br>
        .png / .jpg — Screenshots for OCR<br>
        .docx — Word documents
      </div>
    </div>
  </div>
</div>
""", unsafe_allow_html=True)

# ── STEP 3 ────────────────────────────────────────────────────────────────────
st.markdown(section_header("Step 3 — Set scope and run",
    "Two mandatory gates protect the integrity of every audit before the scan runs."),
    unsafe_allow_html=True)

gates = [
    ("Population completeness gate",
     "Before the scan runs, 80 asks you to confirm that the HR Master represents the complete employee population for the audit scope — not a filtered subset. This confirmation is preserved in the workpaper.",
     "#ffb347"),
    ("Scope lock gate",
     "You set the audit period — start and end date. Once you click GO the scope is locked for that run. The scope is recorded in the workpaper header and all date-sensitive checks (dormant accounts, password expiry) use the scope end date, not today's date.",
     "#ffb347"),
]
for title, body, color in gates:
    st.markdown(f"""
<div style="background:#0d1628;border:1px solid rgba(255,179,71,0.18);
  border-radius:14px;padding:24px 28px;margin-bottom:10px;
  border-left:2px solid {color};">
  <div style="font-size:14px;font-weight:700;color:#ffffff;
    font-family:'Inter',sans-serif;margin-bottom:10px;">{title}</div>
  <div style="font-size:13px;color:#5a7394;font-family:'Inter',sans-serif;
    line-height:1.75;">{body}</div>
</div>""", unsafe_allow_html=True)

# ── STEP 4 ────────────────────────────────────────────────────────────────────
st.markdown(section_header("Step 4 — Review findings and download",
    "Results appear immediately. One consolidated finding per account — all issues listed together."),
    unsafe_allow_html=True)

outputs = [
    ("On-screen findings",   "All findings displayed with severity, account detail, and policy references. Filter by severity, check type or search by email.", "#4d9fff"),
    ("Workpaper Excel",      "9-sheet Excel: Engagement Cover, Audit Opinion, Executive Summary, All Findings, Remediation Playbook, Audit Sample, one sheet per issue type, and raw data files.", "#4d9fff"),
    ("AI audit opinion",     "A professional audit memo with assurance level (Adverse / Qualified / Emphasis / Unqualified), executive summary, and key findings narrative. Review and sign.", "#00d4a0"),
    ("Evidence sampler",     "25-item prioritised sample: Critical first, then High, then random Medium. Each row includes the specific test instruction and evidence required.", "#00d4a0"),
]
col1, col2 = st.columns(2, gap="medium")
for i, (title, body, color) in enumerate(outputs):
    with (col1 if i % 2 == 0 else col2):
        st.markdown(f"""
<div style="background:#0d1628;border:1px solid rgba(255,255,255,0.07);
  border-radius:14px;padding:24px 26px;margin-bottom:10px;
  border-left:2px solid {color};">
  <div style="font-size:14px;font-weight:700;color:#ffffff;
    font-family:'Inter',sans-serif;margin-bottom:10px;">{title}</div>
  <div style="font-size:13px;color:#5a7394;font-family:'Inter',sans-serif;
    line-height:1.75;">{body}</div>
</div>""", unsafe_allow_html=True)

# ── COLUMN REFERENCE ──────────────────────────────────────────────────────────
st.markdown(section_header("Required column names",
    "Column names are matched case-insensitively. Alternatives are detected automatically."),
    unsafe_allow_html=True)

col1, col2 = st.columns(2, gap="medium")
with col1:
    st.markdown("""
<div style="background:#0d1628;border:1px solid rgba(255,255,255,0.07);border-radius:14px;padding:24px 28px;">
  <div style="font-size:12px;font-weight:700;color:#4d9fff;letter-spacing:0.08em;
    text-transform:uppercase;font-family:'Inter',sans-serif;margin-bottom:16px;">HR Master</div>
""", unsafe_allow_html=True)
    hr_cols = [
        ("Email",             "Primary matching key", True),
        ("FullName",          "Employee full name", True),
        ("Department",        "Dept for SoD and RBAC checks", True),
        ("EmploymentStatus",  "Active / Terminated / On Leave", True),
        ("ContractType",      "Permanent / Contractor etc.", True),
        ("TerminationDate",   "Used for post-term login check", False),
        ("JoinDate",          "Used for contractor expiry check", False),
        ("JobTitle",          "Used for RBAC Matrix check", False),
    ]
    for col, desc, req in hr_cols:
        req_text = f'<span style="color:#ff4d5e;font-size:10px;font-weight:700;">required</span>' if req else f'<span style="color:#5a7394;font-size:10px;">optional</span>'
        st.markdown(f"""
<div style="display:flex;align-items:center;justify-content:space-between;
  padding:8px 0;border-bottom:1px solid rgba(255,255,255,0.04);">
  <div>
    <span style="font-size:12px;font-weight:600;color:#c8d8ef;
      font-family:'JetBrains Mono',monospace;">{col}</span>
    <span style="font-size:11px;color:#5a7394;font-family:'Inter',sans-serif;
      margin-left:8px;">{desc}</span>
  </div>
  {req_text}
</div>""", unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)

with col2:
    st.markdown("""
<div style="background:#0d1628;border:1px solid rgba(255,255,255,0.07);border-radius:14px;padding:24px 28px;">
  <div style="font-size:12px;font-weight:700;color:#00d4a0;letter-spacing:0.08em;
    text-transform:uppercase;font-family:'Inter',sans-serif;margin-bottom:16px;">System Access (UAL)</div>
""", unsafe_allow_html=True)
    ual_cols = [
        ("Email",            "Matched against HR Master", True),
        ("AccessLevel",      "Role or access tier", True),
        ("LastLoginDate",    "Used for dormant check", True),
        ("PasswordLastSet",  "Used for password expiry check", True),
        ("MFA",              "Enabled / Disabled / Not Enrolled", True),
        ("SystemName",       "Source system name", False),
        ("AccountStatus",    "Enabled / Disabled", False),
        ("AccountCreatedDate","Used in scope filtering", False),
    ]
    for col, desc, req in ual_cols:
        req_text = f'<span style="color:#ff4d5e;font-size:10px;font-weight:700;">required</span>' if req else f'<span style="color:#5a7394;font-size:10px;">optional</span>'
        st.markdown(f"""
<div style="display:flex;align-items:center;justify-content:space-between;
  padding:8px 0;border-bottom:1px solid rgba(255,255,255,0.04);">
  <div>
    <span style="font-size:12px;font-weight:600;color:#c8d8ef;
      font-family:'JetBrains Mono',monospace;">{col}</span>
    <span style="font-size:11px;color:#5a7394;font-family:'Inter',sans-serif;
      margin-left:8px;">{desc}</span>
  </div>
  {req_text}
</div>""", unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)

