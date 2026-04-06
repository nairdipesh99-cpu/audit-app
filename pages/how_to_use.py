"""80 — IAM Audit Tool | How to Use page"""

import streamlit as st
from components import render_header, render_sidebar_brand

with st.sidebar:
    render_sidebar_brand()

render_header()

st.markdown("## How to use 80")
st.caption("A complete walkthrough from document collection to finished workpaper.")

st.divider()

# ── Overview ──────────────────────────────────────────────────────────────────
c1, c2, c3, c4 = st.columns(4)
c1.info("**Step 1**\n\nCollect your documents before fieldwork begins")
c2.info("**Step 2**\n\nUpload all files to the single document zone")
c3.info("**Step 3**\n\nConfirm population, set scope, click GO")
c4.info("**Step 4**\n\nReview findings and download your workpaper")

st.divider()

# ── Step 1: Documents ─────────────────────────────────────────────────────────
st.markdown("### Step 1 — Collect your documents")
st.markdown("Request these from the client before fieldwork begins. Name your files clearly — 80 detects document type from the filename automatically.")

col1, col2 = st.columns(2)
with col1:
    st.markdown("**Required — tool will not run without these**")
    st.markdown("""
| File | What it must contain |
|---|---|
| `HR_Master_2025.xlsx` | All employees: Email, FullName, Department, EmploymentStatus, ContractType, TerminationDate |
| `System_Access_2025.xlsx` | All accounts: Email, AccessLevel, LastLoginDate, PasswordLastSet, MFA, AccountCreatedDate |
    """)
    st.error("Request the HR extract directly from HR, not from IT. Request the system access extract directly from IT with written instruction: full unfiltered export — do not exclude service accounts, disabled accounts or contractor accounts.")

with col2:
    st.markdown("**Recommended — improves finding quality significantly**")
    st.markdown("""
| File | How 80 uses it |
|---|---|
| `SOA_ISO27001.xlsx` | Extracts SoD rules — findings cite client's own policy |
| `Access_Control_Policy.pdf` | Cited in framework references on every finding |
| `JML_Procedure.pdf` | Cited when terminated accounts are found active |
| `SoD_Matrix.xlsx` | Overrides hardcoded SoD rules with client's own matrix |
| `Risk_Register.xlsx` | Context for known vs newly identified risks |
    """)

st.divider()

# ── Step 2: Upload ────────────────────────────────────────────────────────────
st.markdown("### Step 2 — Upload all documents")
st.markdown("""
Go to the **Use the Tool** page. You will see a single upload zone at the top.

Drop all your files in at once — HR Master, System Access, SOA, policies, procedures, everything together.
80 reads the filename of each file and assigns it automatically:

- File containing `HR_Master` → assigned as HR Master
- File containing `System_Access` → assigned as System Access  
- File containing `SOA` or `ISO27001` → parsed for SoD rules and control references
- File containing `Access_Control` or `Policy` → parsed and cited in framework tab
- File containing `JML` or `Procedure` → parsed and cited in offboarding findings
- Anything else → available in document intelligence panel

If 80 cannot detect the file type from the filename, a manual selector appears so you can assign it yourself.
""")

with st.expander("Using a legacy system that only produces screenshots or PDFs?"):
    st.markdown("""
Expand the **Legacy system upload** section below the main upload zone.
Upload your screenshot or PDF. Click **Extract data from image**.

Claude Vision reads the image and extracts account data — usernames, access levels, login dates — 
and structures it into the correct format. Download it as an Excel file, then upload it as your 
System Access file to run the full 15 checks.

This works on green-screen terminals, printed PDF reports, scanned documents — any image where 
account data is visible.
    """)

st.divider()

# ── Step 3: Scope and run ─────────────────────────────────────────────────────
st.markdown("### Step 3 — Set scope and run")

st.markdown("""
**Fill in engagement details (sidebar)**

Before running, fill in the sidebar:
- Client name and engagement reference — these print on every sheet of the output report
- Your name as lead auditor
- Audit standard (ISO 27001:2022, SOX ITGC, PCI-DSS etc.)
- Tick the compliance frameworks you want cited on findings

**Select department scope (optional)**

If you are auditing specific departments only (e.g. Finance and IT), select them from the 
department filter. Leave empty to scan all departments.

**Confirm population completeness**

Before the scan runs, 80 shows you the row counts for both files and asks you to confirm 
the data is complete and unfiltered. This confirmation is mandatory — it becomes part of 
your workpaper evidence and protects you if the client later disputes a finding.

**Set audit year and click GO**

Use the year dropdown — it defaults to the previous year (which is where your data will be).
Click **Full Year** to set January to December automatically.
Click **▶ GO — Run Audit** to lock the scope and run the scan.
""")

st.warning("If you see 0 accounts scanned after clicking GO — your scope year does not match your data year. Change the year selector to match your data and click Full Year then GO again.")

st.divider()

# ── Step 4: Results ───────────────────────────────────────────────────────────
st.markdown("### Step 4 — Review findings and download")

tabs_info = [
    ("🔎 Findings",    "The complete findings table. Filter by issue type and severity. Every row shows the account email, name, department, access level, days inactive and the detail of what was found. Sort by severity to see Critical findings first."),
    ("🛠️ Remediation", "4-step action plan, named owner and SLA for every finding. Expand each row to see the full remediation instructions. Filter by severity to focus on Critical first. This is what you share with the IT Manager as their action list."),
    ("⚖️ Frameworks",  "SOX, ISO 27001, GDPR and PCI-DSS reference per finding. The exact control clause is cited — not just the framework name. Use this tab when the client asks which control was breached."),
    ("📈 Analysis",    "Breakdown by severity, issue type and department. Bar chart showing dormant account inactivity distribution. Use this for the management presentation."),
    ("✍️ Opinion",     "Toggle between Claude AI opinion (recommended) and rule-based. Click Generate to have Claude write a professional 3-section audit memo. Always review and edit before using. The responsible auditor must approve this opinion."),
    ("🎯 Audit Sample","Set your sample size (default 25). 80 selects Critical findings first, then High, then random Medium to fill the target. Each row has a specific test instruction. Download and hand to the external audit team."),
]

for tab_name, tab_desc in tabs_info:
    with st.expander(tab_name):
        st.markdown(tab_desc)

st.divider()

# ── Download ──────────────────────────────────────────────────────────────────
st.markdown("### The workpaper Excel report")
st.markdown("Click **Download Workpaper-Ready Audit Report** at the bottom of the tool page. The file contains:")

sheets = [
    ("Engagement Cover",        "Client, reference, auditor, standard, scope dates, population counts and total findings. First page of your workpaper file."),
    ("Audit Opinion",           "The full opinion text saved in the workpaper. Must be reviewed and signed by the responsible auditor."),
    ("Executive Summary",       "Finding counts per check type. Copy into your management report as headline numbers."),
    ("All Findings",            "Complete findings schedule with severity, detail, days inactive and post-termination days. Attach as appendix to the report."),
    ("Remediation Playbook",    "4-step action plan, owner, SLA and framework references per finding. Give this to the client as their action list."),
    ("Audit_Sample_Request",    "25-item prioritised sample with test instructions and evidence requirements. Hand to external audit team."),
    ("Per issue-type sheets",   "One tab per finding type — Orphaned, SoD, Dormant etc. Use these in the walkthrough with the IT Manager."),
    ("HR Master (Raw)",         "Exact HR file you uploaded. Workpaper evidence of the population audited."),
    ("System Access (Raw)",     "Exact System Access file you uploaded. Workpaper evidence of the population audited."),
]

for sheet, desc in sheets:
    st.markdown(f"**{sheet}** — {desc}")

st.divider()

# ── After the scan ────────────────────────────────────────────────────────────
st.markdown("### After the scan — what to do with the findings")

st.markdown("""
**Critical findings go to the CISO or IT Manager immediately — not in the report, in person.**
Post-termination logins, SoD violations, orphaned accounts with recent login activity. Do not wait 
for the report to be written before escalating.

**Verify near-match findings with HR before including them.**
Near-match email findings need manual confirmation — some are legitimate aliases or name changes. 
A wrong near-match finding damages your credibility more than missing one.

**Check the exception register before finalising any finding.**
Ask the client for their exception register. An admin account outside IT that was formally approved 
by the CISO and documented in the register is not a finding — it is a managed exception. Note it as 
an observation instead.

**Every finding needs three things in the report:**
1. The fact — what 80 found
2. The policy — what the access control policy or JML procedure says should have happened
3. The risk — what could go wrong because it did not happen

80 gives you all three automatically. Your job is to verify the fact is accurate, confirm the right 
policy is cited, and make the risk statement specific to this client.
""")

st.divider()

# ── Column reference ──────────────────────────────────────────────────────────
st.markdown("### Column name reference")
st.markdown("Column names must match exactly — including capitalisation.")

r1, r2 = st.columns(2)
with r1:
    st.markdown("**HR Master**")
    st.markdown("""
| Column | Required |
|---|---|
| `Email` | ✅ Yes |
| `FullName` | ✅ Yes |
| `Department` | ✅ Yes |
| `EmploymentStatus` | Recommended |
| `ContractType` | Recommended |
| `TerminationDate` | Recommended |
| `JobTitle` | Optional |
    """)
with r2:
    st.markdown("**System Access**")
    st.markdown("""
| Column | Required |
|---|---|
| `Email` | ✅ Yes |
| `AccessLevel` | ✅ Yes |
| `FullName` | Recommended |
| `LastLoginDate` | Recommended |
| `PasswordLastSet` | Recommended |
| `AccountCreatedDate` | Recommended |
| `MFA` | Recommended |
| `SystemName` | Optional |
    """)

st.divider()

if st.button("🛡️  Go to the Tool", type="primary", use_container_width=True):
    st.switch_page("pages/tool.py")

