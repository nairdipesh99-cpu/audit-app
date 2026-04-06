"""80 — IAM Audit Tool | About 80 page"""

import streamlit as st
from components import render_header, render_sidebar_brand

with st.sidebar:
    render_sidebar_brand()

render_header()

st.markdown("## About 80")
st.caption("Everything you need to know about what this tool does, why it was built, and how it works.")

st.divider()

# ── The 80% story ─────────────────────────────────────────────────────────────
st.markdown("### Why 80?")
st.markdown("""
The name comes from a simple observation made talking to IT auditors across multiple organisations.

When you break down what an IAM audit actually involves, roughly 80% of the time is spent on work 
that does not require professional judgement — it requires data processing. Cross-referencing HR records 
against system accounts. Checking whether terminated employees still have active access. Verifying MFA 
status across hundreds of accounts. Mapping each finding to the correct ISO 27001 control. Formatting 
workpapers. Writing the executive summary.

The remaining 20% — the part that actually requires an experienced auditor — is judgement. 
Deciding whether a finding is a material weakness or an observation. Having the conversation with 
the CISO. Assessing the client's compensating controls. Drafting the formal opinion.

**80 automates the 80%. It gives the remaining 20% back to the auditor.**

This is not about replacing auditors. It is about removing the parts of the job that a machine can 
do more accurately, more consistently and in a fraction of the time — so the auditor can focus on 
the parts where their expertise actually matters.
""")

st.divider()

# ── 15 checks ─────────────────────────────────────────────────────────────────
st.markdown("### 15 automated checks — run simultaneously on every account")

critical_checks = [
    ("Orphaned account",                     "An email exists in the system with no matching record in the HR Master. Covers leavers, ex-contractors, ghost accounts and any account provisioned without HR backing. Every orphaned account is a credential with no owner and no one monitoring it.", "SOX AC-1 · ISO A.5.18 · GDPR Art.32 · PCI 8.3.4"),
    ("Terminated employee with active access","HR status shows Resigned, Terminated, Redundant or Inactive but the system account is still enabled. A clear offboarding control failure — the JML process did not work.", "SOX AC-1 · ISO A.5.18 · GDPR Art.32 · PCI 8.3.4"),
    ("Post-termination login",               "The account's last login date is after the recorded termination date in HR. This is the most serious finding — an ex-employee accessed systems after leaving. Triggers GDPR Article 33 breach notification assessment.", "SOX AC-1 · ISO A.8.16 · GDPR Art.33 · PCI 10.2"),
    ("SoD violation — toxic access",         "A user holds an access level that is forbidden for their department under the Segregation of Duties policy. For example, a Finance user with Admin rights, or a Sales user with Payroll access. This user can both initiate and approve transactions — fraud can go completely undetected.", "SOX AC-3 · ISO A.5.3 · GDPR Art.32 · PCI 7.1"),
]

high_checks = [
    ("Dormant account",               "No login recorded in the last 90 days (threshold adjustable). Idle accounts are the most common attacker entry point — no one monitors anomalies on them. Attackers specifically target dormant accounts because alerts are rarely configured for them.", "SOX AC-2 · ISO A.5.18 · PCI 8.3.4"),
    ("Privilege creep",               "The user holds 4 or more distinct roles — the result of access never being revoked when they changed departments or projects. Violates the least-privilege principle. The audit trail becomes unreliable because you cannot determine which role was used for any given action.", "SOX AC-2 · ISO A.5.18 · PCI 7.2"),
    ("Shared / generic account",      "The email or name matches patterns like admin@, test@, helpdesk@, generic@. No individual owner. Actions cannot be attributed to a specific person. The audit trail is completely broken — this is a fundamental identity management failure.", "SOX AC-4 · ISO A.5.16 · PCI 8.2.1"),
    ("Super-user outside IT",         "Admin, DBAdmin, SysAdmin or FullControl rights held by someone outside IT or Security. Requires written CISO justification. Without it, a business user with admin rights is a critical risk — one compromised account equals full system access.", "SOX AC-3 · ISO A.8.2 · PCI 7.2.4"),
    ("MFA not enabled",               "MFA column is blank, disabled, No or not enrolled. A single compromised password gives full account access with no second barrier. Both ISO 27001 A.8.5 and PCI-DSS v4.0 Req 8.4 mandate MFA.", "SOX AC-5 · ISO A.8.5 · PCI 8.4"),
    ("Contractor without expiry date","ContractType is Contractor but no TerminationDate is recorded in HR. Access has no end-date and will persist indefinitely after the engagement ends — one of the most common audit gaps in practice.", "SOX AC-2 · ISO A.5.19 · PCI 8.6"),
]

medium_checks = [
    ("Service account without owner", "Email or name matches patterns like svc_, batch_, system_, backup_, noreply_. Non-human accounts with no named human owner or documented expiry. These accumulate silently and are rarely reviewed.", "SOX AC-4 · ISO A.5.17 · PCI 8.6"),
    ("Password never expired",        "PasswordLastSet date is older than the policy threshold (default 90 days). Stale credentials are the primary vector in credential-stuffing attacks. The account may have been compromised months ago with no one aware.", "SOX AC-5 · ISO A.5.17 · PCI 8.3.9"),
    ("Duplicate system account",      "The same email address appears more than once in the system access file — one person with multiple active account IDs. Multiplies attack surface and makes the audit trail unreliable.", "SOX AC-4 · ISO A.5.16 · PCI 8.2.1"),
    ("Excessive multi-system access", "User appears in more systems than the configurable threshold (default 3). Almost always indicates legacy access from previous projects or roles that was never cleaned up.", "SOX AC-2 · ISO A.5.18 · PCI 7.2"),
    ("Near-match email",              "System email is similar but not identical to an HR email — caught by fuzzy matching (configurable sensitivity). Covers typos, aliases, name changes and potential impersonation attempts. Must be manually verified before raising as a formal finding.", "SOX AC-1 · ISO A.5.16 · PCI 8.2"),
]

with st.expander("🔴 Critical findings — disable or escalate within 24 hours", expanded=True):
    for name, desc, fw in critical_checks:
        st.markdown(f"**{name}**")
        st.markdown(f"{desc}")
        st.caption(f"Framework references: {fw}")
        st.divider()

with st.expander("🟠 High findings — resolve within 5 business days", expanded=False):
    for name, desc, fw in high_checks:
        st.markdown(f"**{name}**")
        st.markdown(f"{desc}")
        st.caption(f"Framework references: {fw}")
        st.divider()

with st.expander("🟡 Medium findings — resolve within 10 business days", expanded=False):
    for name, desc, fw in medium_checks:
        st.markdown(f"**{name}**")
        st.markdown(f"{desc}")
        st.caption(f"Framework references: {fw}")
        st.divider()

st.divider()

# ── Services / features ───────────────────────────────────────────────────────
st.markdown("### What 80 provides")

s1, s2 = st.columns(2)
with s1:
    st.markdown("**Full population testing**")
    st.markdown("Every account is tested against all 15 checks simultaneously. No sampling. No cherry-picking. When 80 says the population is clean, it means every single account was examined.")
    st.markdown("")

    st.markdown("**Compliance framework mapping**")
    st.markdown("Every finding is automatically mapped to SOX ITGC, ISO 27001:2022, GDPR and PCI-DSS v4.0. The exact control clause is cited — not just the framework name. Auditors stop spending time looking up references manually.")
    st.markdown("")

    st.markdown("**Dynamic SoD rules**")
    st.markdown("Upload your organisation's own SoD Matrix or SOA document. 80 reads the rules from it and applies them to the audit instead of generic defaults. Findings cite the client's own policy.")
    st.markdown("")

    st.markdown("**Legacy system OCR**")
    st.markdown("Old systems that only produce screenshots or PDFs are no longer a blocker. Upload the image to 80 and Claude Vision extracts the account data, structures it into the correct format, and makes it available for the full 15-check audit.")

with s2:
    st.markdown("**AI audit opinion**")
    st.markdown("80 uses the Claude API to write a professional 3-section audit memo — Executive Summary with error rate, Key Findings breakdown with ISO references, and a Formal Audit Opinion with the correct level (Adverse / Qualified / Emphasis / Unqualified). The auditor reviews and signs it.")
    st.markdown("")

    st.markdown("**Evidence sampler**")
    st.markdown("External auditors always request a manual sample. 80 generates a prioritised 25-item sample automatically — Critical findings first, then High, then random Medium to fill. Each row includes the specific test instruction and evidence required. Hand it to the external team in one click.")
    st.markdown("")

    st.markdown("**Workpaper-ready Excel report**")
    st.markdown("The download includes 9+ sheets: Engagement Cover, Audit Opinion, Executive Summary, All Findings, Remediation Playbook with 4-step action plans, Audit Sample, one sheet per issue type, and the raw data files. Everything needed to close the workpaper file.")
    st.markdown("")

    st.markdown("**Audit workflow gates**")
    st.markdown("Two mandatory gates protect the integrity of every audit. The population completeness gate requires the auditor to confirm the data is complete before the scan runs. The scope lock gate prevents the audit period from being changed mid-engagement. Both confirmations are preserved in the workpaper.")

st.divider()

# ── Compliance standards ──────────────────────────────────────────────────────
st.markdown("### Compliance standards supported")
f1, f2, f3, f4 = st.columns(4)
with f1:
    st.markdown("**SOX ITGC**")
    st.markdown("Sarbanes-Oxley IT General Controls. Access control checks AC-1 through AC-5 covering logical access, periodic review, SoD, individual accountability and authentication controls.")
with f2:
    st.markdown("**ISO 27001:2022**")
    st.markdown("Annex A controls from A.5.3 (SoD) through A.8.16 (Monitoring). Every finding cites the specific clause number from the standard.")
with f3:
    st.markdown("**GDPR**")
    st.markdown("Articles 5, 25, 28, 32 and 33. Post-termination login findings automatically flag the Article 33 breach notification window.")
with f4:
    st.markdown("**PCI-DSS v4.0**")
    st.markdown("Requirements 7.1 through 10.2 covering access control, account management, authentication and audit logging.")

