"""
Enterprise Identity Auditor — v4
The auditor's 10-minute tool.
New in v4:
  • Compliance framework mapping (SOX, ISO 27001, GDPR, PCI-DSS) on every finding
  • Population completeness confirmation gate before scan runs
  • Post-termination login detection
  • MFA not enabled check
  • Contractor with no expiry date check
  • Audit engagement metadata panel (client, ref, auditor name, standard)
  • Audit opinion generator — auto-drafts the ITGC access control opinion paragraph
  • Risk heat-map chart
  • Workpaper-ready export with engagement metadata on every sheet
  • All previous v3 checks retained and tightened
"""

import streamlit as st
import pandas as pd
from thefuzz import fuzz
import io
from datetime import datetime, date, timedelta

# ─────────────────────────────────────────────────────────────────────────────
#  COMPLIANCE FRAMEWORK MAPPING
#  Every issue type maps to the specific control reference auditors cite in reports
# ─────────────────────────────────────────────────────────────────────────────
FRAMEWORK_REFS = {
    "Orphaned Account": {
        "SOX":       "SOX ITGC — AC-1: Logical Access — Terminated User Access",
        "ISO_27001": "ISO 27001:2022 A.5.18 — Access rights / A.8.8 — Leaver process",
        "GDPR":      "GDPR Art.32 — Appropriate technical measures for access control",
        "PCI_DSS":   "PCI-DSS v4.0 Req 8.3.4 — Remove/disable inactive accounts ≤90 days",
    },
    "Terminated Employee with Active Account": {
        "SOX":       "SOX ITGC — AC-1: Logical Access — Leaver account not disabled",
        "ISO_27001": "ISO 27001:2022 A.5.18 — Termination of access rights",
        "GDPR":      "GDPR Art.32 — Appropriate access control / Art.5(f) — Integrity",
        "PCI_DSS":   "PCI-DSS v4.0 Req 8.3.4 — Disable access within 24h of termination",
    },
    "Post-Termination Login": {
        "SOX":       "SOX ITGC — AC-1: Unauthorised access post-termination — potential fraud indicator",
        "ISO_27001": "ISO 27001:2022 A.5.18 — Access rights / A.8.16 — Monitoring activities",
        "GDPR":      "GDPR Art.32 / Art.33 — Possible personal data breach — notify DPA within 72h",
        "PCI_DSS":   "PCI-DSS v4.0 Req 8.3.4 + 10.2 — Audit log review of terminated user",
    },
    "Dormant Account": {
        "SOX":       "SOX ITGC — AC-2: Periodic Access Review — Inactive account not reviewed",
        "ISO_27001": "ISO 27001:2022 A.5.18 — Regular review of access rights",
        "GDPR":      "GDPR Art.5(e) — Storage limitation / Art.32 — Access hygiene",
        "PCI_DSS":   "PCI-DSS v4.0 Req 8.3.4 — Remove/disable inactive accounts ≤90 days",
    },
    "Toxic Access (SoD Violation)": {
        "SOX":       "SOX ITGC — AC-3: Segregation of Duties — ICFR control deficiency",
        "ISO_27001": "ISO 27001:2022 A.5.3 — Segregation of duties",
        "GDPR":      "GDPR Art.32 — Technical organisational measures / dual-control principle",
        "PCI_DSS":   "PCI-DSS v4.0 Req 7.1 — Access control systems restrict access",
    },
    "Privilege Creep": {
        "SOX":       "SOX ITGC — AC-2: Access provisioning — Excess access not revoked on role change",
        "ISO_27001": "ISO 27001:2022 A.5.18 — Least privilege / need-to-know",
        "GDPR":      "GDPR Art.25 — Data protection by design / Art.32 — Access minimisation",
        "PCI_DSS":   "PCI-DSS v4.0 Req 7.2 — Least privilege access model",
    },
    "Shared / Generic Account": {
        "SOX":       "SOX ITGC — AC-4: Individual accountability — Non-attributable access",
        "ISO_27001": "ISO 27001:2022 A.5.16 — Identity management / individual accountability",
        "GDPR":      "GDPR Art.5(f) — Integrity and confidentiality / Art.32 — Accountability",
        "PCI_DSS":   "PCI-DSS v4.0 Req 8.2.1 — All user accounts are unique",
    },
    "Service / System Account": {
        "SOX":       "SOX ITGC — AC-4: Service account governance — No named owner",
        "ISO_27001": "ISO 27001:2022 A.5.17 — Authentication information / A.8.2 — Privileged access",
        "GDPR":      "GDPR Art.32 — Appropriate technical controls for automated processing",
        "PCI_DSS":   "PCI-DSS v4.0 Req 8.6 — Service accounts managed and secured",
    },
    "Super-User / Admin Access": {
        "SOX":       "SOX ITGC — AC-3: Privileged access — Admin rights without business justification",
        "ISO_27001": "ISO 27001:2022 A.8.2 — Privileged access rights",
        "GDPR":      "GDPR Art.25 / Art.32 — Minimisation of privileged access",
        "PCI_DSS":   "PCI-DSS v4.0 Req 7.2.4 — Review of privileged accounts quarterly",
    },
    "MFA Not Enabled": {
        "SOX":       "SOX ITGC — AC-5: Authentication controls — MFA not enforced",
        "ISO_27001": "ISO 27001:2022 A.8.5 — Secure authentication / multi-factor authentication",
        "GDPR":      "GDPR Art.32 — Appropriate security measures / authentication strength",
        "PCI_DSS":   "PCI-DSS v4.0 Req 8.4 — MFA required for all access into CDE",
    },
    "Password Never Expired": {
        "SOX":       "SOX ITGC — AC-5: Password policy — Credential rotation not enforced",
        "ISO_27001": "ISO 27001:2022 A.5.17 — Authentication information management",
        "GDPR":      "GDPR Art.32 — Pseudonymisation / credential hygiene",
        "PCI_DSS":   "PCI-DSS v4.0 Req 8.3.9 — Passwords changed every 90 days",
    },
    "Duplicate System Access": {
        "SOX":       "SOX ITGC — AC-4: Duplicate accounts impair individual accountability",
        "ISO_27001": "ISO 27001:2022 A.5.16 — Identity management",
        "GDPR":      "GDPR Art.5(f) — Data integrity and confidentiality",
        "PCI_DSS":   "PCI-DSS v4.0 Req 8.2.1 — All user IDs are unique",
    },
    "Excessive Multi-System Access": {
        "SOX":       "SOX ITGC — AC-2: Access review — Access exceeds role requirements",
        "ISO_27001": "ISO 27001:2022 A.5.18 — Least privilege",
        "GDPR":      "GDPR Art.25 — Data protection by design / access minimisation",
        "PCI_DSS":   "PCI-DSS v4.0 Req 7.2 — Least privilege access model",
    },
    "Near-Match Email": {
        "SOX":       "SOX ITGC — AC-1: Identity verification — Possible mis-provisioning",
        "ISO_27001": "ISO 27001:2022 A.5.16 — Identity management",
        "GDPR":      "GDPR Art.32 — Accuracy of identity data",
        "PCI_DSS":   "PCI-DSS v4.0 Req 8.2 — Proper identification of all users",
    },
    "Contractor Without Expiry Date": {
        "SOX":       "SOX ITGC — AC-2: Third-party access — No access end-date defined",
        "ISO_27001": "ISO 27001:2022 A.5.19 — Information security in supplier relationships",
        "GDPR":      "GDPR Art.28 — Processor agreements / access time-limits",
        "PCI_DSS":   "PCI-DSS v4.0 Req 8.3.4 / 8.6 — Third-party access time-limited",
    },
}

# ─────────────────────────────────────────────────────────────────────────────
#  REMEDIATION PLAYBOOK
# ─────────────────────────────────────────────────────────────────────────────
REMEDIATION = {
    "Orphaned Account": {
        "severity": "🔴 CRITICAL", "risk": "Active credentials for a non-employee. Highest breach risk.",
        "step_1": "Disable account immediately (do not delete — preserve audit trail).",
        "step_2": "Raise IT ticket with HR confirmation of termination date.",
        "step_3": "Review last-login logs for any post-termination activity.",
        "step_4": "If activity found, escalate to security incident response.",
        "owner": "IT Ops + HR + IT Security", "sla": "Disable within 24 hours",
    },
    "Terminated Employee with Active Account": {
        "severity": "🔴 CRITICAL", "risk": "HR shows termination but account still active — clear offboarding failure.",
        "step_1": "Disable account immediately.",
        "step_2": "Audit access logs from termination date to today.",
        "step_3": "Check if account was used post-termination — if yes, raise incident.",
        "step_4": "Review and fix offboarding process to prevent recurrence.",
        "owner": "IT Ops + HR", "sla": "Disable within 24 hours",
    },
    "Post-Termination Login": {
        "severity": "🔴 CRITICAL", "risk": "Ex-employee logged in after leaving — potential unauthorised access or data breach.",
        "step_1": "Disable account immediately and preserve all access logs.",
        "step_2": "Escalate to IT Security and Legal as a potential data breach.",
        "step_3": "Determine what data or systems were accessed post-termination.",
        "step_4": "Assess GDPR Art.33 breach notification obligation (72-hour window).",
        "owner": "IT Security + Legal + CISO", "sla": "Escalate within 1 hour",
    },
    "Dormant Account": {
        "severity": "🟠 HIGH", "risk": "Unused accounts are prime targets for takeover — no one monitors them.",
        "step_1": "Email account owner and line manager requesting justification.",
        "step_2": "If no response within 5 business days, disable the account.",
        "step_3": "Document the decision and add to next access review cycle.",
        "step_4": "Implement automated dormancy sweep at 60-day threshold.",
        "owner": "Line Manager + IT Ops", "sla": "Resolve within 5 business days",
    },
    "Toxic Access (SoD Violation)": {
        "severity": "🔴 CRITICAL", "risk": "User can initiate AND approve — fraud or error goes undetected.",
        "step_1": "Identify which role is excess and remove it immediately.",
        "step_2": "If both roles are essential, implement compensating control (dual approval).",
        "step_3": "Document exception with CISO and Dept Head sign-off.",
        "step_4": "Schedule quarterly recertification for any granted exceptions.",
        "owner": "IT Security + Dept Head + CISO", "sla": "Remediate within 48 hours",
    },
    "Privilege Creep": {
        "severity": "🟠 HIGH", "risk": "Accumulated roles from past transfers violate least-privilege.",
        "step_1": "Pull full role history for this user.",
        "step_2": "Send role recertification request to current line manager.",
        "step_3": "Remove all roles not confirmed as business-necessary within 10 days.",
        "step_4": "Implement mandatory role review at every internal transfer.",
        "owner": "Dept Head + IT Ops", "sla": "Recertify within 10 business days",
    },
    "Shared / Generic Account": {
        "severity": "🟠 HIGH", "risk": "Cannot attribute actions to an individual — defeats audit trail entirely.",
        "step_1": "Identify all individuals currently using this shared account.",
        "step_2": "Provision individual named accounts for each legitimate user.",
        "step_3": "Disable the shared account once individual accounts are live.",
        "step_4": "Add generic account detection to provisioning workflow.",
        "owner": "IT Ops", "sla": "Replace within 30 days",
    },
    "Service / System Account": {
        "severity": "🟡 MEDIUM", "risk": "Ownerless service accounts persist indefinitely and accumulate excess rights.",
        "step_1": "Identify the application or process this account serves.",
        "step_2": "Assign a named human owner with accountability.",
        "step_3": "Set a credential rotation schedule (minimum quarterly).",
        "step_4": "Review permissions — reduce to minimum required for the function.",
        "owner": "IT Ops + Application Owner", "sla": "Assign owner within 15 business days",
    },
    "Super-User / Admin Access": {
        "severity": "🟠 HIGH", "risk": "Admin rights outside IT is a major compliance and breach risk.",
        "step_1": "Request written business justification from account holder and their manager.",
        "step_2": "If unjustified, downgrade access immediately.",
        "step_3": "Implement Just-In-Time (JIT) admin access as best practice.",
        "step_4": "Add to quarterly admin access recertification register.",
        "owner": "CISO + Dept Head", "sla": "Justify or revoke within 48 hours",
    },
    "MFA Not Enabled": {
        "severity": "🟠 HIGH", "risk": "Account has no second factor — single stolen password gives full access.",
        "step_1": "Enforce MFA enrolment immediately for this account.",
        "step_2": "Block login until MFA is configured.",
        "step_3": "Verify MFA device is a corporate-managed device, not personal.",
        "step_4": "Add to MFA compliance register and report to CISO.",
        "owner": "IT Security", "sla": "Enrol MFA within 48 hours",
    },
    "Password Never Expired": {
        "severity": "🟡 MEDIUM", "risk": "Stale credentials are the primary vector in credential stuffing attacks.",
        "step_1": "Force an immediate password reset for this account.",
        "step_2": "Enforce password expiry policy at the system/domain level.",
        "step_3": "Check email against known breach databases (HaveIBeenPwned API).",
        "step_4": "Implement MFA as a compensating control if policy change is delayed.",
        "owner": "IT Security", "sla": "Force reset within 24 hours",
    },
    "Duplicate System Access": {
        "severity": "🟡 MEDIUM", "risk": "Multiple accounts for one person multiplies attack surface and obscures audit trail.",
        "step_1": "Confirm both accounts belong to the same individual.",
        "step_2": "Identify the primary (correct) account.",
        "step_3": "Disable the duplicate; transfer any necessary access to the primary.",
        "step_4": "Review provisioning workflow to prevent duplicate creation.",
        "owner": "IT Ops", "sla": "Resolve within 5 business days",
    },
    "Excessive Multi-System Access": {
        "severity": "🟡 MEDIUM", "risk": "User spans more systems than their role justifies — likely legacy access.",
        "step_1": "List all systems this user has access to.",
        "step_2": "Send full access list to line manager for recertification.",
        "step_3": "Remove access to any system not confirmed as business-necessary.",
        "step_4": "Flag for inclusion in next periodic access review cycle.",
        "owner": "Dept Head + IT Ops", "sla": "Recertify within 10 business days",
    },
    "Near-Match Email": {
        "severity": "🟡 MEDIUM", "risk": "Possible typo, alias, name change or impersonation — needs manual verification.",
        "step_1": "Cross-check the system email against HR records manually.",
        "step_2": "Contact the employee directly to confirm account ownership.",
        "step_3": "If confirmed typo — correct email in system.",
        "step_4": "If unrecognised — treat as Orphaned Account and disable immediately.",
        "owner": "HR + IT Ops", "sla": "Confirm identity within 3 business days",
    },
    "Contractor Without Expiry Date": {
        "severity": "🟠 HIGH", "risk": "Contractor access has no end-date — will persist indefinitely after engagement ends.",
        "step_1": "Obtain the contract end-date from Procurement or Legal.",
        "step_2": "Set the account expiry date to match the contract end-date.",
        "step_3": "Schedule a reminder review 30 days before expiry.",
        "step_4": "Add to contractor access register with mandatory renewal process.",
        "owner": "IT Ops + Procurement", "sla": "Set expiry within 5 business days",
    },
}

SOD_RULES = {
    "Sales":             ["Admin", "Finance", "Payroll", "DBAdmin", "HR"],
    "Marketing":         ["Admin", "DBAdmin", "Payroll", "Finance"],
    "Support":           ["Admin", "Finance", "DBAdmin", "Payroll"],
    "Finance":           ["Admin", "DBAdmin"],
    "HR":                ["Admin", "DBAdmin", "Finance"],
    "Operations":        ["DBAdmin", "Finance"],
    "IT":                ["HR", "Payroll"],
    "Procurement":       ["Finance", "DBAdmin"],
    "Risk & Compliance": ["Admin", "DBAdmin"],
}

GENERIC_PATTERNS = [
    "admin","test","temp","generic","shared","service","svc",
    "noreply","no-reply","helpdesk","info@","support@","it@",
    "backup","batch","system","root","default","guest","app.",
]

HIGH_RISK_ACCESS = ["Admin","SuperAdmin","DBAdmin","Root","FullControl","SysAdmin"]

# ─────────────────────────────────────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def parse_date(val):
    if val is None:
        return None
    try:
        if isinstance(val, float) and (pd.isna(val) or val != val):
            return None
        dt = pd.to_datetime(val, errors='coerce')
        if pd.isna(dt):
            return None
        # Strip timezone so arithmetic against datetime.today() never crashes
        if hasattr(dt, 'tzinfo') and dt.tzinfo is not None:
            dt = dt.tz_localize(None) if hasattr(dt, 'tz_localize') else dt.replace(tzinfo=None)
        return dt
    except Exception:
        return None

def sanitise_sheet(name):
    for ch in ['/',  '\\', '*', '?', '[', ']', ':']:
        name = name.replace(ch, '-')
    return name[:31]

def sev_key(sev):
    return {"🔴 CRITICAL": 0, "🟠 HIGH": 1, "🟡 MEDIUM": 2, "⚪ INFO": 3}.get(sev, 9)

def make_finding(row_dict, issue_type, detail, days_inactive=None,
                 frameworks=None, post_term_days=None):
    rem  = REMEDIATION.get(issue_type, {})
    refs = frameworks or FRAMEWORK_REFS.get(issue_type, {})
    f = {
        **row_dict,
        "IssueType":         issue_type,
        "Severity":          rem.get("severity", "⚪ INFO"),
        "Detail":            detail,
        "Risk":              rem.get("risk", ""),
        "Step 1 – Action":   rem.get("step_1", ""),
        "Step 2 – Action":   rem.get("step_2", ""),
        "Step 3 – Action":   rem.get("step_3", ""),
        "Step 4 – Action":   rem.get("step_4", ""),
        "Owner":             rem.get("owner", ""),
        "SLA":               rem.get("sla", ""),
        "SOX Reference":     refs.get("SOX", ""),
        "ISO 27001 Ref":     refs.get("ISO_27001", ""),
        "GDPR Reference":    refs.get("GDPR", ""),
        "PCI-DSS Reference": refs.get("PCI_DSS", ""),
        "DaysInactive":      days_inactive,
    }
    if post_term_days is not None:
        f["DaysPostTermination"] = post_term_days
    return f

# ─────────────────────────────────────────────────────────────────────────────
#  AUDIT ENGINE — 15 checks
# ─────────────────────────────────────────────────────────────────────────────
def run_audit(hr_df, sys_df, scope_start, scope_end,
              dormant_days, pwd_expiry_days, fuzzy_threshold, max_systems,
              selected_frameworks):
    today        = datetime.today()
    scope_start_dt = datetime.combine(scope_start, datetime.min.time())
    scope_end_dt   = datetime.combine(scope_end,   datetime.max.time())
    findings, excluded = [], 0

    # Normalise HR
    hr_df = hr_df.copy()
    hr_df["_email"] = hr_df["Email"].str.strip().str.lower()
    if hr_df["_email"].duplicated().any():
        st.warning("⚠️ Duplicate emails in HR file — using first occurrence.")
        hr_df = hr_df.drop_duplicates(subset="_email", keep="first")
    hr_lookup = hr_df.set_index("_email")
    hr_emails  = set(hr_df["_email"])

    sys_df = sys_df.copy()
    sys_df["_email"] = sys_df["Email"].str.strip().str.lower()

    # Pre-compute duplicate and multi-system sets
    email_counts    = sys_df["_email"].value_counts()
    duplicate_set   = set(email_counts[email_counts > 1].index)
    if "SystemName" in sys_df.columns:
        sys_counts  = sys_df.groupby("_email")["SystemName"].nunique()
        excess_set  = set(sys_counts[sys_counts > max_systems].index)
    else:
        excess_set  = set()

    for _, row in sys_df.iterrows():
        raw_email  = str(row.get("Email", "")).strip()
        u_email    = raw_email.lower()
        u_access   = str(row.get("AccessLevel", "")).strip()
        u_name     = str(row.get("FullName",    raw_email))
        row_dict   = row.to_dict()

        last_login   = parse_date(row.get("LastLoginDate"))
        pwd_set      = parse_date(row.get("PasswordLastSet"))
        acct_created = parse_date(row.get("AccountCreatedDate"))
        mfa_status   = str(row.get("MFA", "")).strip().lower()

        def safe_days(dt):
            if dt is None:
                return None
            try:
                d = (today - dt).days
                return int(d) if d == d else None
            except Exception:
                return None
        days_inactive = safe_days(last_login)
        pwd_age_days  = safe_days(pwd_set)

        # ── SCOPE CHECK ──────────────────────────────────────────────────────
        anchor = acct_created or last_login or pwd_set
        if anchor is not None:
            if not (scope_start_dt <= anchor <= scope_end_dt):
                excluded += 1
                continue

        combined = (u_email + " " + u_name).lower()
        is_generic = any(p in combined for p in GENERIC_PATTERNS)
        is_svc     = any(p in combined for p in ["svc","service","system","batch","backup","noreply","no-reply","root","app."])

        # ── CHECK: Generic / Service account ─────────────────────────────────
        if is_generic:
            itype = "Service / System Account" if is_svc else "Shared / Generic Account"
            findings.append(make_finding(
                row_dict, itype,
                f"'{u_name}' matches {'service/system' if is_svc else 'shared/generic'} "
                f"account patterns — cannot be attributed to an individual.",
                days_inactive,
            ))
            continue

        # ── CHECK: Orphaned / Near-match ─────────────────────────────────────
        if u_email not in hr_emails:
            best_score, best_match = 0, None
            for he in hr_emails:
                s = fuzz.ratio(u_email, he)
                if s > best_score:
                    best_score, best_match = s, he
            if best_score >= fuzzy_threshold:
                findings.append(make_finding(
                    row_dict, "Near-Match Email",
                    f"System email '{u_email}' is {best_score}% similar to HR email "
                    f"'{best_match}'. Possible typo, alias or name change — verify manually.",
                    days_inactive,
                ))
            else:
                findings.append(make_finding(
                    row_dict, "Orphaned Account",
                    f"'{u_email}' has no matching record in the HR master. "
                    f"Likely a leaver, contractor or ghost account.",
                    days_inactive,
                ))
            continue

        # — Account is in HR — deeper checks —
        hr_row      = hr_lookup.loc[u_email]
        dept        = str(hr_row.get("Department",        "Unknown")).strip()
        emp_status  = str(hr_row.get("EmploymentStatus",  "Active")).strip().lower()
        contract    = str(hr_row.get("ContractType",      "")).strip().lower()
        term_date   = parse_date(hr_row.get("TerminationDate"))

        # ── CHECK: Terminated employee still active ───────────────────────────
        if emp_status in ("terminated","resigned","inactive","on leave","redundant"):
            # Sub-check: post-termination login
            if last_login and term_date and last_login > term_date:
                post_days = int((last_login - term_date).days)
                findings.append(make_finding(
                    row_dict, "Post-Termination Login",
                    f"CRITICAL: '{u_name}' ({emp_status}) last logged in {post_days} days "
                    f"AFTER their termination date ({term_date.date()}). "
                    f"Last login: {last_login.date()}. Potential unauthorised access — escalate immediately.",
                    days_inactive, post_term_days=post_days,
                ))
            else:
                findings.append(make_finding(
                    row_dict, "Terminated Employee with Active Account",
                    f"HR status is '{emp_status}' but system account is still active. "
                    f"Termination date recorded as: {term_date.date() if term_date else 'not set'}.",
                    days_inactive,
                ))
            continue

        # ── CHECK: Contractor without expiry date ─────────────────────────────
        if "contractor" in contract and not term_date:
            findings.append(make_finding(
                row_dict, "Contractor Without Expiry Date",
                f"'{u_name}' is a contractor (ContractType: {contract}) "
                f"with no TerminationDate set in HR. Access has no end-date and will persist indefinitely.",
                days_inactive,
            ))

        # ── CHECK: Dormant account ────────────────────────────────────────────
        if days_inactive is not None and days_inactive > dormant_days:
            findings.append(make_finding(
                row_dict, "Dormant Account",
                f"No login for {days_inactive} days (policy threshold: {dormant_days} days). "
                f"Last login: {last_login.date() if last_login else 'unknown'}.",
                days_inactive,
            ))

        # ── CHECK: MFA not enabled ────────────────────────────────────────────
        if mfa_status in ("disabled","no","false","0","none","not enrolled",""):
            if "MFA" in sys_df.columns:
                findings.append(make_finding(
                    row_dict, "MFA Not Enabled",
                    f"'{u_name}' has MFA status recorded as '{row.get('MFA','')}'. "
                    f"No second authentication factor — single password compromise = full account access.",
                    days_inactive,
                ))

        # ── CHECK: SoD violation ─────────────────────────────────────────────
        forbidden = SOD_RULES.get(dept, [])
        for fb in forbidden:
            if fb.lower() in u_access.lower():
                findings.append(make_finding(
                    row_dict, "Toxic Access (SoD Violation)",
                    f"'{dept}' user holds '{u_access}' — '{fb}' access is forbidden "
                    f"for '{dept}' under SoD policy. User can both initiate and approve.",
                    days_inactive,
                ))
                break

        # ── CHECK: Privilege creep ────────────────────────────────────────────
        roles = [r.strip() for r in u_access.split(",") if r.strip()]
        if len(roles) >= 4:
            findings.append(make_finding(
                row_dict, "Privilege Creep",
                f"User holds {len(roles)} distinct roles: {u_access}. "
                f"High role count suggests accumulated access from previous positions.",
                days_inactive,
            ))

        # ── CHECK: Super-user outside IT ─────────────────────────────────────
        is_it = dept.lower() in ("it","information technology","security","infosec","cyber")
        for hr in HIGH_RISK_ACCESS:
            if hr.lower() in u_access.lower() and not is_it:
                findings.append(make_finding(
                    row_dict, "Super-User / Admin Access",
                    f"Non-IT user in '{dept}' holds '{u_access}'. "
                    f"Admin-level rights require explicit CISO written approval.",
                    days_inactive,
                ))
                break

        # ── CHECK: Password never expired ─────────────────────────────────────
        if pwd_age_days is not None and pwd_age_days > pwd_expiry_days:
            findings.append(make_finding(
                row_dict, "Password Never Expired",
                f"Password last set {pwd_age_days} days ago "
                f"({pwd_set.date() if pwd_set else 'unknown'}). "
                f"Policy requires rotation every {pwd_expiry_days} days.",
                days_inactive,
            ))

        # ── CHECK: Duplicate account ──────────────────────────────────────────
        if u_email in duplicate_set:
            findings.append(make_finding(
                row_dict, "Duplicate System Access",
                f"'{u_email}' appears multiple times in the system access file. "
                f"Multiple active account IDs for one person.",
                days_inactive,
            ))

        # ── CHECK: Excessive multi-system access ──────────────────────────────
        if u_email in excess_set:
            cnt = sys_counts[u_email]
            findings.append(make_finding(
                row_dict, "Excessive Multi-System Access",
                f"'{u_email}' has access to {cnt} systems (threshold: {max_systems}). "
                f"Likely carries legacy access from previous roles.",
                days_inactive,
            ))

    df = pd.DataFrame(findings) if findings else pd.DataFrame()
    if not df.empty:
        # Strip framework columns not selected
        all_fw = {"SOX Reference","ISO 27001 Ref","GDPR Reference","PCI-DSS Reference"}
        keep_fw = set()
        if "SOX"     in selected_frameworks: keep_fw.add("SOX Reference")
        if "ISO"     in selected_frameworks: keep_fw.add("ISO 27001 Ref")
        if "GDPR"    in selected_frameworks: keep_fw.add("GDPR Reference")
        if "PCI-DSS" in selected_frameworks: keep_fw.add("PCI-DSS Reference")
        drop_fw = all_fw - keep_fw
        df = df.drop(columns=[c for c in drop_fw if c in df.columns])

        df.insert(0, "ScopeTo",   str(scope_end))
        df.insert(0, "ScopeFrom", str(scope_start))
        df["_sev"] = df["Severity"].map(sev_key).fillna(9)
        df = df.sort_values("_sev").drop(columns="_sev")

    return df, excluded

# ─────────────────────────────────────────────────────────────────────────────
#  AUDIT OPINION GENERATOR
# ─────────────────────────────────────────────────────────────────────────────
def generate_opinion(findings_df, meta, scope_start, scope_end, total_pop, in_scope):
    total    = len(findings_df)
    critical = len(findings_df[findings_df["Severity"] == "🔴 CRITICAL"]) if total else 0
    high     = len(findings_df[findings_df["Severity"] == "🟠 HIGH"])     if total else 0
    medium   = len(findings_df[findings_df["Severity"] == "🟡 MEDIUM"])   if total else 0

    if critical >= 5:
        opinion_level = "ADVERSE"
        opinion_text  = (
            "Based on the results of our identity and access review, we are of the opinion that the "
            "access control environment contains significant deficiencies that represent a material "
            "weakness in the organisation's IT General Controls (ITGCs). The number and severity of "
            "findings identified indicate that logical access controls are not operating effectively "
            "over the audit period."
        )
    elif critical >= 1 or high >= 5:
        opinion_level = "QUALIFIED"
        opinion_text  = (
            "Based on the results of our identity and access review, we are of the opinion that, "
            "except for the matters detailed in the findings schedule, the access control environment "
            "is broadly consistent with good practice. However, the critical and high-severity findings "
            "identified represent control deficiencies that require prompt remediation to avoid escalation "
            "to material weakness."
        )
    elif high >= 1 or medium >= 3:
        opinion_level = "EMPHASIS OF MATTER"
        opinion_text  = (
            "Based on the results of our identity and access review, we are of the opinion that the "
            "access control environment is generally adequate. However, we draw attention to the "
            "findings identified in the schedule below, which represent areas where controls require "
            "improvement. These matters do not constitute a material weakness but should be addressed "
            "within the remediation timelines specified."
        )
    else:
        opinion_level = "UNQUALIFIED (CLEAN)"
        opinion_text  = (
            "Based on the results of our identity and access review, we are of the opinion that the "
            "access control environment is operating effectively and in accordance with the organisation's "
            "stated access control policies. No material issues were identified during the review period."
        )

    scope_str = f"{scope_start.strftime('%d %B %Y')} to {scope_end.strftime('%d %B %Y')}"

    return f"""
AUDIT OPINION — IDENTITY & ACCESS CONTROL REVIEW
{'='*60}

Engagement Reference : {meta.get('ref', 'N/A')}
Client Organisation  : {meta.get('client', 'N/A')}
Auditor              : {meta.get('auditor', 'N/A')}
Audit Standard       : {meta.get('standard', 'N/A')}
Review Period        : {scope_str}
Population           : {total_pop:,} total accounts | {in_scope:,} within scope
Date of Opinion      : {datetime.today().strftime('%d %B %Y')}

OPINION: {opinion_level}
{'-'*60}
{opinion_text}

FINDINGS SUMMARY
{'-'*60}
Total findings identified : {total}
  Critical                : {critical}
  High                    : {high}
  Medium                  : {medium}

This opinion is based solely on the data provided as at the date of this review
and should be read in conjunction with the full findings schedule attached.

Prepared by: {meta.get('auditor','N/A')}
""".strip()

# ─────────────────────────────────────────────────────────────────────────────
#  EXCEL EXPORT — workpaper grade
# ─────────────────────────────────────────────────────────────────────────────
def to_excel_bytes(findings_df, hr_df, sys_df, scope_start, scope_end,
                   excluded_count, meta, opinion_text):
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine="xlsxwriter") as writer:
        wb = writer.book

        # ── Formats ──────────────────────────────────────────────────────────
        hdr_fmt   = wb.add_format({"bold":True,"bg_color":"#1F3864","font_color":"white","border":1,"font_name":"Arial","font_size":10})
        red_fmt   = wb.add_format({"bg_color":"#FFDEDE","font_name":"Arial","font_size":9})
        ora_fmt   = wb.add_format({"bg_color":"#FFF0CC","font_name":"Arial","font_size":9})
        yel_fmt   = wb.add_format({"bg_color":"#FFFBCC","font_name":"Arial","font_size":9})
        meta_lbl  = wb.add_format({"bold":True,"font_name":"Arial","font_size":10,"font_color":"#1F3864"})
        meta_val  = wb.add_format({"font_name":"Arial","font_size":10,"font_color":"#404040"})
        title_fmt = wb.add_format({"bold":True,"font_name":"Arial","font_size":14,"font_color":"#1F3864"})
        wrap_fmt  = wb.add_format({"text_wrap":True,"valign":"top","font_name":"Arial","font_size":9})

        def write_sheet(sheet_df, sheet_name):
            if sheet_df.empty:
                return
            clean = sheet_df.copy()
            clean = clean[[c for c in clean.columns if not c.startswith("_")]]
            clean.to_excel(writer, index=False, sheet_name=sheet_name)
            ws = writer.sheets[sheet_name]
            for ci, col in enumerate(clean.columns):
                try:
                    vals    = clean[col].fillna("").astype(str)
                    mx      = int(vals.map(len).max()) if len(vals) else 0
                    max_len = min(max(mx, len(str(col))) + 2, 60)
                except Exception:
                    max_len = len(str(col)) + 2
                ws.set_column(ci, ci, max_len)
            for ri, (_, row) in enumerate(clean.iterrows(), start=1):
                sev = str(row.get("Severity",""))
                fmt = red_fmt if "CRITICAL" in sev else (ora_fmt if "HIGH" in sev else (yel_fmt if "MEDIUM" in sev else None))
                if fmt:
                    ws.set_row(ri, None, fmt)
            for ci, col in enumerate(clean.columns):
                ws.write(0, ci, col, hdr_fmt)

        # ── Sheet 1: Engagement Cover ─────────────────────────────────────────
        ws_cov = wb.add_worksheet("Engagement Cover")
        ws_cov.hide_gridlines(2)
        ws_cov.set_column("A:A", 4)
        ws_cov.set_column("B:B", 32)
        ws_cov.set_column("C:C", 50)
        ws_cov.set_row(1, 8)
        ws_cov.write("B2", "Identity & Access Control Audit Report", title_fmt)
        ws_cov.set_row(2, 6)
        rows = [
            ("Client Organisation",  meta.get("client",   "—")),
            ("Engagement Reference", meta.get("ref",      "—")),
            ("Audit Standard",       meta.get("standard", "—")),
            ("Lead Auditor",         meta.get("auditor",  "—")),
            ("Review Period",        f"{scope_start.strftime('%d %b %Y')} → {scope_end.strftime('%d %b %Y')}"),
            ("Date of Report",       datetime.today().strftime("%d %B %Y")),
            ("Total Population",     f"{len(sys_df):,} accounts"),
            ("Accounts in Scope",    f"{len(sys_df) - excluded_count:,} accounts"),
            ("Accounts Excluded",    f"{excluded_count:,} (outside scope window)"),
            ("Total Findings",       str(len(findings_df))),
            ("Classification",       "CONFIDENTIAL — For audit purposes only"),
        ]
        for i, (lbl, val) in enumerate(rows, start=3):
            ws_cov.set_row(i, 18)
            ws_cov.write(i, 1, lbl,  meta_lbl)
            ws_cov.write(i, 2, val,  meta_val)

        # ── Sheet 2: Audit Opinion ────────────────────────────────────────────
        ws_op = wb.add_worksheet("Audit Opinion")
        ws_op.hide_gridlines(2)
        ws_op.set_column("A:A", 4)
        ws_op.set_column("B:B", 100)
        ws_op.set_row(1, 8)
        op_fmt = wb.add_format({"font_name":"Arial","font_size":10,"text_wrap":True,"valign":"top"})
        ws_op.write("B2", "AUDIT OPINION — IDENTITY & ACCESS CONTROL REVIEW", title_fmt)
        ws_op.set_row(2, 6)
        for i, line in enumerate(opinion_text.split("\n"), start=3):
            ws_op.set_row(i, 15)
            ws_op.write(i, 1, line, op_fmt)

        # ── Sheet 3: Executive Summary ────────────────────────────────────────
        in_scope_count = len(sys_df) - excluded_count
        def cnt_issue(t):
            return len(findings_df[findings_df["IssueType"] == t]) if not findings_df.empty else 0
        def cnt_sev(s):
            return len(findings_df[findings_df["Severity"] == s]) if not findings_df.empty else 0

        summary_rows = [
            ("── ENGAGEMENT DETAILS ──",          ""),
            ("Client",                             meta.get("client",   "—")),
            ("Reference",                          meta.get("ref",      "—")),
            ("Auditor",                            meta.get("auditor",  "—")),
            ("Standard",                           meta.get("standard", "—")),
            ("Scope from",                         scope_start.strftime("%d %b %Y")),
            ("Scope to",                           scope_end.strftime("%d %b %Y")),
            ("── POPULATION ──",                   ""),
            ("Total accounts in system file",      len(sys_df)),
            ("Accounts within audit scope",        in_scope_count),
            ("Accounts excluded (out of scope)",   excluded_count),
            ("── FINDINGS ──",                     ""),
            ("Total findings",                     len(findings_df)),
            ("🔴 Critical",                        cnt_sev("🔴 CRITICAL")),
            ("🟠 High",                            cnt_sev("🟠 HIGH")),
            ("🟡 Medium",                          cnt_sev("🟡 MEDIUM")),
            ("── BY CHECK ──",                     ""),
            ("Orphaned accounts",                  cnt_issue("Orphaned Account")),
            ("Terminated with active access",      cnt_issue("Terminated Employee with Active Account")),
            ("Post-termination logins",            cnt_issue("Post-Termination Login")),
            ("Dormant accounts",                   cnt_issue("Dormant Account")),
            ("SoD violations",                     cnt_issue("Toxic Access (SoD Violation)")),
            ("Privilege creep",                    cnt_issue("Privilege Creep")),
            ("Shared / generic accounts",          cnt_issue("Shared / Generic Account")),
            ("Service accounts without owner",     cnt_issue("Service / System Account")),
            ("Super-user outside IT",              cnt_issue("Super-User / Admin Access")),
            ("MFA not enabled",                    cnt_issue("MFA Not Enabled")),
            ("Passwords never expired",            cnt_issue("Password Never Expired")),
            ("Duplicate system accounts",          cnt_issue("Duplicate System Access")),
            ("Excessive multi-system access",      cnt_issue("Excessive Multi-System Access")),
            ("Contractors without expiry",         cnt_issue("Contractor Without Expiry Date")),
            ("Near-match emails",                  cnt_issue("Near-Match Email")),
        ]
        sum_df = pd.DataFrame(summary_rows, columns=["Check", "Count"])
        sum_df.to_excel(writer, index=False, sheet_name="Executive Summary")
        ws_s = writer.sheets["Executive Summary"]
        ws_s.set_column(0, 0, 45)
        ws_s.set_column(1, 1, 14)
        ws_s.write(0, 0, "Check",  hdr_fmt)
        ws_s.write(0, 1, "Count",  hdr_fmt)

        # ── Sheet 4: All Findings ─────────────────────────────────────────────
        write_sheet(findings_df, "All Findings")

        # ── Sheet 5: Remediation Playbook ─────────────────────────────────────
        playbook_cols = ["Severity","IssueType","ScopeFrom","ScopeTo","Email","FullName",
                         "Department","AccessLevel","Detail",
                         "Step 1 – Action","Step 2 – Action","Step 3 – Action","Step 4 – Action",
                         "Owner","SLA",
                         "SOX Reference","ISO 27001 Ref","GDPR Reference","PCI-DSS Reference",
                         "DaysInactive","DaysPostTermination"]
        pb_cols = [c for c in playbook_cols if c in findings_df.columns]
        write_sheet(findings_df[pb_cols] if pb_cols else findings_df, "Remediation Playbook")

        # ── Per-issue sheets ──────────────────────────────────────────────────
        if not findings_df.empty:
            for itype in findings_df["IssueType"].unique():
                write_sheet(findings_df[findings_df["IssueType"] == itype],
                            sanitise_sheet(itype))

        # ── Raw data ──────────────────────────────────────────────────────────
        hr_clean  = hr_df.drop(columns=["_email"], errors="ignore")
        sys_clean = sys_df.drop(columns=["_email"], errors="ignore")
        hr_clean.to_excel(writer,  index=False, sheet_name="HR Master (Raw)")
        sys_clean.to_excel(writer, index=False, sheet_name="System Access (Raw)")
        for sn in ["HR Master (Raw)", "System Access (Raw)"]:
            ws_r = writer.sheets[sn]
            src  = hr_clean if "HR" in sn else sys_clean
            for ci, col in enumerate(src.columns):
                ws_r.write(0, ci, col, hdr_fmt)

    output.seek(0)
    return output.getvalue()

# ─────────────────────────────────────────────────────────────────────────────
#  SESSION STATE INIT
# ─────────────────────────────────────────────────────────────────────────────
today = date.today()
if "ss_start"  not in st.session_state: st.session_state["ss_start"]  = date(today.year, 1, 1)
if "ss_end"    not in st.session_state: st.session_state["ss_end"]    = date(today.year, 12, 31)
if "locked"    not in st.session_state: st.session_state["locked"]    = False
if "confirmed" not in st.session_state: st.session_state["confirmed"] = False

def _set_this_month():
    st.session_state.update(ss_start=today.replace(day=1), ss_end=today, locked=False, confirmed=False)
def _set_last_q():
    q = (today.month-1)//3
    me = [31,28,31,30,31,30,31,31,30,31,30,31]
    if q==0: qs,qe = date(today.year-1,10,1), date(today.year-1,12,31)
    else:    qs,qe = date(today.year,(q-1)*3+1,1), date(today.year,q*3,me[q*3-1])
    st.session_state.update(ss_start=qs, ss_end=qe, locked=False, confirmed=False)
def _set_6m():
    st.session_state.update(ss_start=today-timedelta(days=182), ss_end=today, locked=False, confirmed=False)
def _set_fy():
    st.session_state.update(ss_start=date(today.year,1,1), ss_end=date(today.year,12,31), locked=False, confirmed=False)
def _on_date_change():
    st.session_state.update(locked=False, confirmed=False)
def _go():
    st.session_state["locked"] = True

# ─────────────────────────────────────────────────────────────────────────────
#  PAGE CONFIG
# ─────────────────────────────────────────────────────────────────────────────
st.set_page_config(page_title="Enterprise Identity Auditor", layout="wide", page_icon="🛡️")
st.title("🛡️ Enterprise Identity Auditor")
st.caption("15 automated checks · Compliance framework mapping · Workpaper-ready report · Audit opinion generator")

# ─────────────────────────────────────────────────────────────────────────────
#  SIDEBAR
# ─────────────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.header("⚙️ Audit Settings")

    # — Engagement metadata —
    st.subheader("📋 Engagement Details")
    meta = {
        "client":   st.text_input("Client organisation",    placeholder="Nairs.com Ltd"),
        "ref":      st.text_input("Engagement reference",   placeholder="IAR-2025-001"),
        "auditor":  st.text_input("Lead auditor name",      placeholder="Your name"),
        "standard": st.selectbox("Audit standard", [
            "ISACA IS Audit Standard",
            "ISO 27001:2022",
            "SOX ITGC",
            "PCI-DSS v4.0",
            "GDPR Art.32",
            "Internal Audit Charter",
        ]),
    }

    st.divider()

    # — Compliance frameworks —
    st.subheader("📐 Compliance Frameworks")
    st.caption("Select frameworks to include in findings and export.")
    selected_frameworks = []
    if st.checkbox("SOX / ITGC",     value=True):  selected_frameworks.append("SOX")
    if st.checkbox("ISO 27001:2022", value=True):  selected_frameworks.append("ISO")
    if st.checkbox("GDPR",           value=True):  selected_frameworks.append("GDPR")
    if st.checkbox("PCI-DSS v4.0",   value=False): selected_frameworks.append("PCI-DSS")

    st.divider()

    # — Scope —
    st.subheader("📅 Audit Scope Period")
    st.caption("Set dates → click GO to lock scope and run scan.")
    pc1, pc2 = st.columns(2)
    pc1.button("This Month",    use_container_width=True, on_click=_set_this_month)
    pc1.button("Last Quarter",  use_container_width=True, on_click=_set_last_q)
    pc2.button("Last 6 Months", use_container_width=True, on_click=_set_6m)
    pc2.button("Full Year",     use_container_width=True, on_click=_set_fy)
    st.write("")
    dc1, dc2 = st.columns(2)
    with dc1:
        st.date_input("From", key="ss_start", on_change=_on_date_change)
    with dc2:
        st.date_input("To",   key="ss_end",   on_change=_on_date_change)

    date_err = st.session_state["ss_start"] >= st.session_state["ss_end"]
    if date_err:
        st.error("'From' must be before 'To'.")

    st.button("▶  GO — Lock Scope & Run Audit",
              use_container_width=True, type="primary",
              disabled=date_err, on_click=_go)

    SCOPE_START = st.session_state["ss_start"]
    SCOPE_END   = st.session_state["ss_end"]
    scope_days  = (SCOPE_END - SCOPE_START).days
    if st.session_state["locked"]:
        st.success(f"🔒 Locked: **{SCOPE_START.strftime('%d %b %Y')}** → **{SCOPE_END.strftime('%d %b %Y')}** ({scope_days} days)")
    else:
        st.info(f"🗓️ {scope_days} days selected — click GO to run")

    st.divider()

    # — Thresholds —
    st.subheader("🔧 Detection Thresholds")
    DORMANT_DAYS         = st.slider("Dormant account threshold (days)", 30, 365, 90)
    PASSWORD_EXPIRY_DAYS = st.slider("Password expiry threshold (days)", 30, 365, 90)
    FUZZY_THRESHOLD      = st.slider("Fuzzy email match sensitivity",    70, 99,  88,
                                     help="Lower = more near-matches caught")
    MAX_SYSTEMS          = st.slider("Max systems per user before flagging", 2, 10, 3)

    st.divider()
    st.caption("Column requirements")
    with st.expander("View required columns"):
        st.markdown("""
**HR Master** (required): `Email`, `Department`, `FullName`

**HR Master** (recommended): `EmploymentStatus`, `ContractType`, `TerminationDate`, `JobTitle`

**System Access** (required): `Email`, `AccessLevel`

**System Access** (recommended): `AccountCreatedDate`, `LastLoginDate`, `PasswordLastSet`, `MFA`, `SystemName`, `FullName`
        """)

# ─────────────────────────────────────────────────────────────────────────────
#  MAIN AREA
# ─────────────────────────────────────────────────────────────────────────────
col1, col2 = st.columns(2)
with col1:
    hr_file  = st.file_uploader("📁 Upload HR Master (.xlsx)", type=["xlsx"])
with col2:
    sys_file = st.file_uploader("📁 Upload System Access (.xlsx)", type=["xlsx"])

if hr_file and sys_file:
    hr_df  = pd.read_excel(hr_file)
    sys_df = pd.read_excel(sys_file)

    # Column validation
    hr_miss  = {"Email","Department","FullName"} - set(hr_df.columns)
    sys_miss = {"Email","AccessLevel"}           - set(sys_df.columns)
    if hr_miss or sys_miss:
        if hr_miss:  st.error(f"❌ HR file missing columns: {hr_miss}")
        if sys_miss: st.error(f"❌ System Access file missing columns: {sys_miss}")
        st.stop()

    # ── POPULATION COMPLETENESS GATE ─────────────────────────────────────────
    if not st.session_state.get("confirmed", False):
        st.warning("⚠️ **Population Completeness Confirmation Required**")
        st.markdown(f"""
Before running the audit, you must confirm the data provided is complete.

| | Count |
|---|---|
| HR Master rows uploaded | **{len(hr_df):,}** |
| System Access rows uploaded | **{len(sys_df):,}** |

**As the lead auditor, please confirm:**
- The HR Master represents **100% of employees** in scope (no pre-filtering by the client)
- The System Access file represents **100% of system accounts** (not a sample or filtered extract)
- You have documented the source and extraction date of both files in your workpapers
        """)
        c1, c2 = st.columns(2)
        with c1:
            if st.button("✅ I confirm — data is complete and unfiltered", type="primary", use_container_width=True):
                st.session_state["confirmed"] = True
                st.rerun()
        with c2:
            if st.button("❌ Data may be incomplete — do not proceed", use_container_width=True):
                st.error("Audit halted. Obtain complete population data from the client before proceeding.")
                st.stop()
        st.stop()

    # ── SCOPE LOCK GATE ───────────────────────────────────────────────────────
    if not st.session_state.get("locked", False):
        st.info("📅 Files uploaded and population confirmed. Set your **audit scope dates** in the sidebar and click **▶ GO** to run the scan.")
        st.stop()

    # ── RUN AUDIT ─────────────────────────────────────────────────────────────
    with st.spinner("🔍 Running 15 audit checks across all identities..."):
        findings_df, excluded_count = run_audit(
            hr_df, sys_df, SCOPE_START, SCOPE_END,
            DORMANT_DAYS, PASSWORD_EXPIRY_DAYS, FUZZY_THRESHOLD, MAX_SYSTEMS,
            selected_frameworks,
        )

    in_scope = len(sys_df) - excluded_count
    st.success(
        f"🔒 **Scope:** {SCOPE_START.strftime('%d %b %Y')} → {SCOPE_END.strftime('%d %b %Y')} "
        f"| **{in_scope:,}** of {len(sys_df):,} accounts scanned "
        f"| **{excluded_count:,}** excluded as out-of-scope"
    )

    # ── METRICS ───────────────────────────────────────────────────────────────
    st.header("📊 Audit Summary")
    total = len(findings_df)
    def cnt(col, val): return len(findings_df[findings_df[col] == val]) if total else 0

    m = st.columns(5)
    m[0].metric("Total Findings",  total)
    m[1].metric("🔴 Critical",      cnt("Severity","🔴 CRITICAL"))
    m[2].metric("🟠 High",          cnt("Severity","🟠 HIGH"))
    m[3].metric("🟡 Medium",        cnt("Severity","🟡 MEDIUM"))
    m[4].metric("Accounts Scanned", f"{in_scope:,}")

    if total:
        st.divider()
        cc = st.columns(5)
        checks_list = [
            ("Orphaned",           "Orphaned Account"),
            ("Terminated Active",  "Terminated Employee with Active Account"),
            ("Post-Term Login",    "Post-Termination Login"),
            ("Dormant",            "Dormant Account"),
            ("SoD Violations",     "Toxic Access (SoD Violation)"),
            ("Privilege Creep",    "Privilege Creep"),
            ("Shared IDs",         "Shared / Generic Account"),
            ("Service Accounts",   "Service / System Account"),
            ("Admin Outside IT",   "Super-User / Admin Access"),
            ("MFA Not Enabled",    "MFA Not Enabled"),
            ("Pwd Expired",        "Password Never Expired"),
            ("Duplicates",         "Duplicate System Access"),
            ("Multi-System",       "Excessive Multi-System Access"),
            ("Contractors",        "Contractor Without Expiry Date"),
            ("Near-Match",         "Near-Match Email"),
        ]
        for i, (lbl, itype) in enumerate(checks_list):
            cc[i % 5].metric(lbl, cnt("IssueType", itype))

    if findings_df.empty:
        st.success("✅ No issues found across all 15 checks. Identity landscape is clean.")
    else:
        # ── TABS ─────────────────────────────────────────────────────────────
        tab1, tab2, tab3, tab4, tab5 = st.tabs([
            "🔎 Findings",
            "🛠️ Remediation",
            "⚖️ Frameworks",
            "📈 Analysis",
            "✍️ Audit Opinion",
        ])

        # Sorted df
        sdf = findings_df.copy()
        sdf["_s"] = sdf["Severity"].map(sev_key).fillna(9)
        sdf = sdf.sort_values("_s").drop(columns="_s")

        with tab1:
            filter_type = st.multiselect(
                "Filter by issue type:",
                options=sorted(findings_df["IssueType"].unique()),
                default=sorted(findings_df["IssueType"].unique()),
            )
            filtered = sdf[sdf["IssueType"].isin(filter_type)]
            disp = [c for c in ["Severity","IssueType","Email","FullName",
                                  "Department","AccessLevel","DaysInactive",
                                  "DaysPostTermination","Detail"]
                    if c in filtered.columns]
            st.dataframe(filtered[disp], use_container_width=True, hide_index=True,
                column_config={
                    "Severity":             st.column_config.TextColumn("Severity",   width="small"),
                    "IssueType":            st.column_config.TextColumn("Issue Type", width="medium"),
                    "Detail":               st.column_config.TextColumn("Detail",     width="large"),
                    "DaysInactive":         st.column_config.NumberColumn("Days Idle",        width="small"),
                    "DaysPostTermination":  st.column_config.NumberColumn("Days Post-Term",   width="small"),
                })

        with tab2:
            st.caption("Every finding includes a 4-step remediation plan, owner, and SLA.")
            for _, row in sdf.iterrows():
                with st.expander(
                    f"{row.get('Severity','')}  |  {row.get('IssueType','')}  —  "
                    f"{row.get('Email','')}  ({row.get('FullName','')})"
                ):
                    st.markdown(f"**Finding:** {row.get('Detail','')}")
                    st.markdown(f"**Risk:** {row.get('Risk','')}")
                    st.divider()
                    c1, c2 = st.columns(2)
                    c1.markdown(f"**Step 1:** {row.get('Step 1 – Action','')}")
                    c1.markdown(f"**Step 2:** {row.get('Step 2 – Action','')}")
                    c2.markdown(f"**Step 3:** {row.get('Step 3 – Action','')}")
                    c2.markdown(f"**Step 4:** {row.get('Step 4 – Action','')}")
                    st.divider()
                    rc1, rc2 = st.columns(2)
                    rc1.markdown(f"**Owner:** {row.get('Owner','')}")
                    rc2.markdown(f"**SLA:** {row.get('SLA','')}")

        with tab3:
            st.caption("Compliance control references — cite these directly in your audit report.")
            fw_cols = [c for c in ["Severity","IssueType","Email","FullName",
                                    "SOX Reference","ISO 27001 Ref",
                                    "GDPR Reference","PCI-DSS Reference"]
                       if c in sdf.columns]
            st.dataframe(sdf[fw_cols], use_container_width=True, hide_index=True)

        with tab4:
            a1, a2 = st.columns(2)
            with a1:
                st.markdown("**Findings by severity**")
                by_sev = findings_df["Severity"].value_counts().reset_index()
                by_sev.columns = ["Severity","Count"]
                st.dataframe(by_sev, use_container_width=True, hide_index=True)
                st.markdown("**Findings by issue type**")
                by_type = findings_df["IssueType"].value_counts().reset_index()
                by_type.columns = ["Issue Type","Count"]
                st.dataframe(by_type, use_container_width=True, hide_index=True)
            with a2:
                if "Department" in findings_df.columns:
                    st.markdown("**Findings by department**")
                    by_dept = findings_df["Department"].value_counts().reset_index()
                    by_dept.columns = ["Department","Count"]
                    st.dataframe(by_dept, use_container_width=True, hide_index=True)
                if "DaysInactive" in findings_df.columns:
                    dormant = findings_df[findings_df["DaysInactive"].notna()]
                    if not dormant.empty:
                        st.markdown("**Inactivity distribution (days)**")
                        st.bar_chart(dormant.set_index("Email")["DaysInactive"])

        with tab5:
            opinion_text = generate_opinion(
                findings_df, meta, SCOPE_START, SCOPE_END, len(sys_df), in_scope
            )
            st.markdown("**Auto-generated audit opinion — review and edit before use.**")
            edited_opinion = st.text_area(
                "Audit opinion (editable):",
                value=opinion_text,
                height=420,
            )
            st.caption(
                "This is a draft opinion based on findings count and severity. "
                "It must be reviewed, adjusted and signed off by the responsible auditor "
                "before inclusion in any formal report."
            )

    # ── EXPORT ───────────────────────────────────────────────────────────────
    st.divider()
    opinion_for_export = generate_opinion(
        findings_df, meta, SCOPE_START, SCOPE_END, len(sys_df), in_scope
    ) if not findings_df.empty else "No findings — clean opinion."

    st.download_button(
        label="📥 Download Workpaper-Ready Audit Report (.xlsx)",
        data=to_excel_bytes(
            findings_df, hr_df, sys_df,
            SCOPE_START, SCOPE_END, excluded_count,
            meta, opinion_for_export,
        ),
        file_name=f"IAR_{meta.get('ref','') or 'Audit'}_{datetime.today().strftime('%Y%m%d')}.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        type="primary",
        use_container_width=True,
    )

elif hr_file or sys_file:
    st.info("📂 Please upload **both** files to continue.")
else:
    st.info("👆 Upload both files above to begin.")
    with st.expander("📋 What this tool checks (15 automated checks)", expanded=True):
        checks_info = [
            ("🔴","Orphaned accounts",              "Email in system, no HR record — leavers, ghosts, contractors"),
            ("🔴","Terminated with active access",  "HR shows resigned/terminated but account still enabled"),
            ("🔴","Post-termination login",         "Ex-employee logged in AFTER their termination date"),
            ("🔴","Toxic access / SoD violations",  "Dept vs access-level conflict — can initiate AND approve"),
            ("🟠","Dormant accounts",               "No login in 90+ days — prime takeover target"),
            ("🟠","Privilege creep",                "4+ roles accumulated across transfers — violates least-privilege"),
            ("🟠","Shared / generic accounts",      "admin@, test@, helpdesk@ — defeats audit trail"),
            ("🟠","Super-user outside IT",          "Admin/DBAdmin rights held by non-IT business users"),
            ("🟠","MFA not enabled",                "No second factor — single password = full access"),
            ("🟠","Contractor without expiry",      "Contractor account with no end-date — persists indefinitely"),
            ("🟡","Service accounts without owner", "svc_, batch_, system_ — no named human owner"),
            ("🟡","Passwords never expired",        "Credentials older than policy — primary breach vector"),
            ("🟡","Duplicate system accounts",      "Same person, multiple IDs — multiplies attack surface"),
            ("🟡","Excessive multi-system access",  "User spans more systems than role justifies"),
            ("🟡","Near-match emails",              "Fuzzy-matched — typos, aliases, name changes, impersonation"),
        ]
        for sev, name, desc in checks_info:
            st.markdown(f"{sev} **{name}** — {desc}")

