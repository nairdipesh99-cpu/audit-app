"""80 — IAM Audit Tool | About"""

import streamlit as st
from components import inject_css, render_header, render_sidebar_brand, section_header

with st.sidebar:
    render_sidebar_brand()

render_header(active="About")


# ── PAGE HERO ─────────────────────────────────────────────────────────────────
st.markdown("""
<div style="
  background:#0d1628;
  border:1px solid rgba(255,255,255,0.07);
  border-radius:20px;
  padding:48px 52px;
  margin-bottom:36px;
  border-left:3px solid #4d9fff;
">
  <div style="font-size:11px;font-weight:700;color:#4d9fff;letter-spacing:0.1em;
    text-transform:uppercase;font-family:'Inter',sans-serif;margin-bottom:14px;">About 80</div>
  <div style="font-size:38px;font-weight:900;color:#ffffff;letter-spacing:-0.04em;
    line-height:1.1;font-family:'Inter',sans-serif;margin-bottom:16px;">
    Built for auditors.<br>Not for dashboards.
  </div>
  <div style="font-size:15px;color:#5a7394;line-height:1.8;max-width:560px;
    font-family:'Inter',sans-serif;">
    80 automates the mechanical 80% of an IAM audit — the part that requires
    processing, not judgement. The part that used to take days now takes minutes.
  </div>
</div>
""", unsafe_allow_html=True)

# ── WHY 80 ────────────────────────────────────────────────────────────────────
st.markdown(section_header("Why 80?"), unsafe_allow_html=True)

st.markdown("""
<div style="background:#0d1628;border:1px solid rgba(255,255,255,0.07);
  border-radius:16px;padding:36px 40px;margin-bottom:8px;">
  <p style="font-size:15px;color:#c8d8ef;line-height:1.85;margin:0 0 18px;
    font-family:'Inter',sans-serif;">
    When you break down what an IAM audit actually involves, roughly
    <strong style="color:#4d9fff;">80%</strong> of the time is spent on work that
    does not require professional judgement — it requires data processing.
    Cross-referencing HR records against system accounts. Checking whether terminated
    employees still have active access. Verifying MFA status across hundreds of accounts.
    Mapping each finding to the correct ISO 27001 control. Formatting workpapers.
  </p>
  <p style="font-size:15px;color:#c8d8ef;line-height:1.85;margin:0 0 18px;
    font-family:'Inter',sans-serif;">
    The remaining <strong style="color:#ffffff;">20%</strong> — the part that
    requires an experienced auditor — is judgement. Deciding whether a finding is a
    material weakness or an observation. Having the conversation with the CISO.
    Assessing compensating controls. Drafting the formal opinion.
  </p>
  <p style="font-size:15px;color:#4d9fff;line-height:1.85;margin:0;
    font-family:'Inter',sans-serif;font-weight:600;">
    80 automates the 80%. It gives the remaining 20% back to the auditor.
  </p>
</div>
""", unsafe_allow_html=True)

# ── 18 CHECKS ─────────────────────────────────────────────────────────────────
st.markdown(section_header("18 automated checks",
    "Every check runs simultaneously across every account in the population."),
    unsafe_allow_html=True)

critical = [
    ("Orphaned account",
     "An email exists in the system with no matching HR record. Covers leavers, ex-contractors, ghost accounts and any account provisioned without HR backing. Every orphaned account is a credential with no owner and no one monitoring it.",
     "SOX AC-1 · ISO A.5.18 · GDPR Art.32 · PCI 8.3.4"),
    ("Terminated with active account",
     "HR status shows Resigned, Terminated, Redundant or Inactive but the system account is still enabled. A clear offboarding control failure.",
     "SOX AC-1 · ISO A.5.18 · GDPR Art.32 · PCI 8.3.4"),
    ("Post-termination login",
     "Last login date is after the recorded termination date. An ex-employee accessed systems after leaving. Triggers GDPR Article 33 breach notification assessment.",
     "SOX AC-1 · ISO A.8.16 · GDPR Art.33 · PCI 10.2"),
    ("SoD violation",
     "A user holds access forbidden for their department under the Segregation of Duties policy. They can both initiate and approve transactions — fraud goes undetected.",
     "SOX AC-3 · ISO A.5.3 · GDPR Art.32 · PCI 7.1"),
    ("RBAC violation",
     "Actual access exceeds what the RBAC Matrix permits for that job title. Access that was never formally authorised by the documented role entitlement.",
     "SOX AC-2 · ISO A.5.15 · GDPR Art.25 · PCI 7.2"),
]

high = [
    ("Dormant account",
     "No login in the last 90 days (adjustable). Idle accounts are the most common attacker entry point — anomalies go unmonitored.",
     "SOX AC-2 · ISO A.5.18 · PCI 8.3.4"),
    ("Privilege creep",
     "User holds 4 or more distinct roles — access accumulated across role changes and never revoked. Violates least-privilege.",
     "SOX AC-2 · ISO A.5.18 · PCI 7.2"),
    ("Generic / shared account",
     "Email matches patterns like admin@, test@, helpdesk@. No individual owner. Actions cannot be attributed. Audit trail is broken.",
     "SOX AC-4 · ISO A.5.16 · PCI 8.2.1"),
    ("Super-user outside IT",
     "Admin or privileged rights held by someone outside IT or Security. A compromised account gives full system access.",
     "SOX AC-3 · ISO A.8.2 · PCI 7.2.4"),
    ("MFA not enabled",
     "MFA is blank, disabled or not enrolled. A single compromised password gives full account access with no second barrier.",
     "SOX AC-5 · ISO A.8.5 · PCI 8.4"),
    ("Contractor without expiry",
     "ContractType is Contractor but no TerminationDate recorded. Access has no end-date and persists indefinitely after the engagement ends.",
     "SOX AC-2 · ISO A.5.19 · PCI 8.6"),
    ("Unauthorised privileged account",
     "Admin rights but no entry in the Privileged User Registry. No documented approval, no named owner, no justification on record.",
     "SOX AC-3 · ISO A.8.2 · GDPR Art.32 · PCI 7.2.4"),
    ("Privileged registry review overdue",
     "In the registry but last review date is over 12 months ago. Privileged access must be formally reconfirmed annually.",
     "SOX AC-2 · ISO A.8.2 · GDPR Art.32 · PCI 7.2.4"),
]

medium = [
    ("Service / system account",
     "Email matches svc_, batch_, system_, backup_, noreply_. Non-human accounts with no named owner or documented expiry.",
     "SOX AC-4 · ISO A.5.17 · PCI 8.6"),
    ("Password never expired",
     "PasswordLastSet is older than the policy threshold (default 90 days). Stale credentials are the primary vector in credential-stuffing attacks.",
     "SOX AC-5 · ISO A.5.17 · PCI 8.3.9"),
    ("Duplicate system account",
     "Same email appears more than once in the same system. Multiple active account IDs — multiplies attack surface.",
     "SOX AC-4 · ISO A.5.16 · PCI 8.2.1"),
    ("Excessive multi-system access",
     "User appears in more systems than the threshold (default 3). Almost always legacy access from previous roles never cleaned up.",
     "SOX AC-2 · ISO A.5.18 · PCI 7.2"),
    ("Near-match email",
     "System email is similar but not identical to an HR email. Covers typos, aliases, name changes and potential impersonation. Requires manual verification.",
     "SOX AC-1 · ISO A.5.16 · PCI 8.2"),
]

def check_section(checks, sev_label, fc, bg, border):
    for name, desc, fw in checks:
        st.markdown(f"""
<div style="background:{bg};border:1px solid {border};border-radius:12px;
  padding:22px 26px;margin-bottom:10px;">
  <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:16px;margin-bottom:10px;">
    <div style="font-size:14px;font-weight:700;color:#ffffff;
      font-family:'Inter',sans-serif;">{name}</div>
    <span style="background:{border};color:{fc};border:1px solid {border};
      padding:3px 10px;border-radius:20px;font-size:10px;font-weight:700;
      letter-spacing:0.06em;font-family:'Inter',sans-serif;
      white-space:nowrap;flex-shrink:0;">{sev_label}</span>
  </div>
  <div style="font-size:13px;color:#7a8fa6;line-height:1.7;
    font-family:'Inter',sans-serif;margin-bottom:10px;">{desc}</div>
  <div style="font-size:11px;color:{fc};font-family:'Inter',sans-serif;
    font-weight:600;opacity:0.8;">{fw}</div>
</div>""", unsafe_allow_html=True)

with st.expander("🔴  Critical — disable or escalate within 24 hours", expanded=True):
    check_section(critical, "CRITICAL", "#ff4d5e", "rgba(255,77,94,0.06)", "rgba(255,77,94,0.2)")

with st.expander("🟠  High — resolve within 5 business days", expanded=False):
    check_section(high, "HIGH", "#ffb347", "rgba(255,179,71,0.06)", "rgba(255,179,71,0.2)")

with st.expander("🟡  Medium — resolve within 10 business days", expanded=False):
    check_section(medium, "MEDIUM", "#4d9fff", "rgba(77,159,255,0.06)", "rgba(77,159,255,0.2)")

# ── WHAT 80 PROVIDES ──────────────────────────────────────────────────────────
st.markdown(section_header("What 80 provides"), unsafe_allow_html=True)

features = [
    ("Full population testing",
     "Every account tested across all 18 checks simultaneously. No sampling. No cherry-picking. When 80 says the population is clean, every single account was examined.",
     "#4d9fff"),
    ("Framework mapping",
     "Every finding automatically mapped to SOX ITGC, ISO 27001:2022, GDPR and PCI-DSS v4.0. The exact control clause is cited — not just the framework name.",
     "#4d9fff"),
    ("AI audit opinion",
     "A professional 3-section audit memo — Executive Summary, Key Findings, and Formal Opinion with the correct assurance level. The auditor reviews and signs.",
     "#4d9fff"),
    ("Workpaper-ready Excel",
     "9 sheets: Engagement Cover, Audit Opinion, Executive Summary, All Findings, Remediation Playbook, Audit Sample, one sheet per issue type, and raw data.",
     "#00d4a0"),
    ("Evidence sampler",
     "External auditors always request a sample. 80 generates a prioritised 25-item sample automatically — Critical first, then High, then random Medium. One click.",
     "#00d4a0"),
    ("Legacy system OCR",
     "Old systems that only produce screenshots or PDFs are no longer a blocker. Upload the image — AI extracts account data and structures it for the full audit.",
     "#00d4a0"),
]

col1, col2 = st.columns(2, gap="medium")
for i, (title, body, color) in enumerate(features):
    with (col1 if i % 2 == 0 else col2):
        st.markdown(f"""
<div style="background:#0d1628;border:1px solid rgba(255,255,255,0.07);
  border-radius:14px;padding:26px 28px;margin-bottom:12px;
  border-left:2px solid {color};">
  <div style="font-size:14px;font-weight:700;color:#ffffff;
    font-family:'Inter',sans-serif;margin-bottom:10px;">{title}</div>
  <div style="font-size:13px;color:#5a7394;font-family:'Inter',sans-serif;
    line-height:1.75;">{body}</div>
</div>""", unsafe_allow_html=True)

# ── COMPLIANCE ────────────────────────────────────────────────────────────────
st.markdown(section_header("Compliance frameworks"), unsafe_allow_html=True)

frameworks = [
    ("SOX ITGC", "Sarbanes-Oxley IT General Controls. Access control checks AC-1 through AC-5 covering logical access, periodic review, SoD, individual accountability and authentication.", "#ff4d5e"),
    ("ISO 27001:2022", "Annex A controls from A.5.3 through A.8.16. Every finding cites the specific clause number from the 2022 revision of the standard.", "#ffb347"),
    ("GDPR", "Articles 5, 25, 28, 32 and 33. Post-termination login findings automatically flag the Article 33 breach notification window.", "#4d9fff"),
    ("PCI-DSS v4.0", "Requirements 7.1 through 10.2 covering access control, account management, authentication and audit logging for cardholder data environments.", "#00d4a0"),
]

f1, f2, f3, f4 = st.columns(4, gap="small")
for col, (name, desc, color) in zip([f1, f2, f3, f4], frameworks):
    with col:
        st.markdown(f"""
<div style="background:#0d1628;border:1px solid rgba(255,255,255,0.07);
  border-radius:14px;padding:22px 20px;
  border-top:2px solid {color};text-align:center;">
  <div style="font-size:14px;font-weight:800;color:#ffffff;
    font-family:'Inter',sans-serif;margin-bottom:12px;">{name}</div>
  <div style="font-size:12px;color:#5a7394;font-family:'Inter',sans-serif;
    line-height:1.7;">{desc}</div>
</div>""", unsafe_allow_html=True)

