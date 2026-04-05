"""
Nairs.com Enterprise Identity Auditor — v3
Senior IT Audit Edition: 9 automated checks + remediation playbook + audit scope window
"""

import streamlit as st
import pandas as pd
from thefuzz import fuzz
import io
from datetime import datetime

# ─────────────────────────────────────────────────────────────────────────────
#  POLICY CONFIGURATION  ← tune these for your organisation
# ─────────────────────────────────────────────────────────────────────────────
# Audit scope window — only accounts whose relevant date falls within this range are examined.
# These are overridden at runtime by the sidebar date pickers.
from datetime import date, timedelta
SCOPE_START = date.today() - timedelta(days=365)   # default: last 12 months
SCOPE_END   = date.today()

DORMANT_DAYS            = 90    # Flag accounts idle longer than this
PASSWORD_EXPIRY_DAYS    = 90    # Flag passwords older than this
FUZZY_THRESHOLD         = 88    # 0-100; lower = catch more near-matches
MAX_SYSTEMS_PER_USER    = 3     # Flag users appearing in more systems than this

# Segregation-of-Duties: which access levels are FORBIDDEN per department
SOD_RULES = {
    "Sales":      ["Admin", "Finance", "Payroll", "DBAdmin", "HR"],
    "Marketing":  ["Admin", "DBAdmin", "Payroll", "Finance"],
    "Support":    ["Admin", "Finance", "DBAdmin", "Payroll"],
    "Finance":    ["Admin", "DBAdmin"],
    "HR":         ["Admin", "DBAdmin", "Finance"],
    "Operations": ["DBAdmin", "Finance"],
    "IT":         ["HR", "Payroll"],   # IT shouldn't touch HR/Payroll data
}

# Accounts whose name/email pattern suggest they are shared or service accounts
GENERIC_PATTERNS = [
    "admin", "test", "temp", "generic", "shared", "service", "svc",
    "noreply", "no-reply", "helpdesk", "info@", "support@", "it@",
    "backup", "batch", "system", "root", "default", "guest",
]

# High-risk access levels that need extra scrutiny
HIGH_RISK_ACCESS = ["Admin", "SuperAdmin", "DBAdmin", "Root", "FullControl", "SysAdmin"]

# ─────────────────────────────────────────────────────────────────────────────
#  SEVERITY & REMEDIATION PLAYBOOK
# ─────────────────────────────────────────────────────────────────────────────
REMEDIATION = {
    "Orphaned Account": {
        "severity":   "🔴 CRITICAL",
        "risk":       "Active credentials for a non-employee. Highest breach risk.",
        "step_1":     "Disable account immediately (do not delete — preserve audit trail).",
        "step_2":     "Raise IT ticket with HR confirmation of termination date.",
        "step_3":     "Review last-login logs for any post-termination activity.",
        "step_4":     "If activity found, escalate to security incident response.",
        "owner":      "IT Ops + HR + IT Security",
        "sla":        "Disable within 24 hours",
    },
    "Terminated Employee with Active Account": {
        "severity":   "🔴 CRITICAL",
        "risk":       "HR shows termination but account still active — clear control failure.",
        "step_1":     "Disable account immediately.",
        "step_2":     "Audit access logs from termination date to today.",
        "step_3":     "Check if account was used post-termination.",
        "step_4":     "Review offboarding checklist and plug the gap.",
        "owner":      "IT Ops + HR",
        "sla":        "Disable within 24 hours",
    },
    "Dormant Account": {
        "severity":   "🟠 HIGH",
        "risk":       "Unused accounts are prime targets for takeover; no one notices anomalies.",
        "step_1":     "Email the account owner and their line manager requesting justification.",
        "step_2":     "If no response within 5 business days, disable the account.",
        "step_3":     "For confirmed dormant accounts, disable and schedule quarterly review.",
        "step_4":     "Add to automated inactive-account sweep process.",
        "owner":      "Line Manager + IT Ops",
        "sla":        "Resolve within 5 business days",
    },
    "Toxic Access (SoD Violation)": {
        "severity":   "🔴 CRITICAL",
        "risk":       "User can initiate AND approve transactions — fraud or error goes undetected.",
        "step_1":     "Identify which role is the lesser-need role and remove it.",
        "step_2":     "If both roles are needed, implement compensating control (dual approval).",
        "step_3":     "Document justification if exception is granted.",
        "step_4":     "Schedule quarterly recertification for any granted exceptions.",
        "owner":      "IT Security + Dept Head + CISO",
        "sla":        "Remediate within 48 hours",
    },
    "Privilege Creep": {
        "severity":   "🟠 HIGH",
        "risk":       "Accumulated roles from past projects/transfers violate least-privilege.",
        "step_1":     "Pull role history for this user.",
        "step_2":     "Send role recertification request to current line manager.",
        "step_3":     "Remove all roles not confirmed as needed within 10 business days.",
        "step_4":     "Implement role review at every internal transfer.",
        "owner":      "Dept Head + IT Ops",
        "sla":        "Recertify within 10 business days",
    },
    "Shared / Generic Account": {
        "severity":   "🟠 HIGH",
        "risk":       "Cannot attribute actions to an individual — defeats audit trail entirely.",
        "step_1":     "Identify all users of this shared account.",
        "step_2":     "Create individual named accounts for each legitimate user.",
        "step_3":     "Disable the shared account once individual accounts are live.",
        "step_4":     "Add generic pattern detection to new-account provisioning workflow.",
        "owner":      "IT Ops",
        "sla":        "Replace within 30 days",
    },
    "Service / System Account": {
        "severity":   "🟡 MEDIUM",
        "risk":       "Ownerless service accounts can persist forever and accumulate excess rights.",
        "step_1":     "Identify the application/process this account serves.",
        "step_2":     "Assign a named human owner who is accountable.",
        "step_3":     "Set a password/secret rotation schedule.",
        "step_4":     "Review permissions — reduce to minimum required for the function.",
        "owner":      "IT Ops + Application Owner",
        "sla":        "Assign owner within 15 business days",
    },
    "Super-User / Admin Access": {
        "severity":   "🟠 HIGH",
        "risk":       "Admin rights outside IT/Security is a major control and compliance risk.",
        "step_1":     "Confirm business justification for admin rights in writing.",
        "step_2":     "If unjustified, downgrade access immediately.",
        "step_3":     "Implement Just-In-Time (JIT) admin access as best practice.",
        "step_4":     "Schedule quarterly re-approval for all admin accounts.",
        "owner":      "CISO + Dept Head",
        "sla":        "Justify or revoke within 48 hours",
    },
    "Password Never Expired": {
        "severity":   "🟡 MEDIUM",
        "risk":       "Stale credentials are a primary vector in credential stuffing attacks.",
        "step_1":     "Force an immediate password reset for this account.",
        "step_2":     "Enforce password expiry policy at the system level.",
        "step_3":     "Check if this account appears in any known breach databases (HaveIBeenPwned).",
        "step_4":     "Consider implementing MFA as a compensating control.",
        "owner":      "IT Security",
        "sla":        "Force reset within 24 hours",
    },
    "Duplicate System Access": {
        "severity":   "🟡 MEDIUM",
        "risk":       "Multiple accounts for one person multiplies attack surface and obscures audit trail.",
        "step_1":     "Confirm both accounts belong to the same individual.",
        "step_2":     "Identify the primary (correct) account.",
        "step_3":     "Disable the duplicate; merge any necessary access to the primary.",
        "step_4":     "Review provisioning workflow to prevent duplicate creation.",
        "owner":      "IT Ops",
        "sla":        "Resolve within 5 business days",
    },
    "Near-Match Email": {
        "severity":   "🟡 MEDIUM",
        "risk":       "Possible typo or alias — could be a genuine person or an impersonation attempt.",
        "step_1":     "Cross-check the system email against HR records manually.",
        "step_2":     "Contact the employee directly to confirm ownership.",
        "step_3":     "If confirmed typo: correct the email in the system.",
        "step_4":     "If unrecognised: treat as Orphaned Account and disable.",
        "owner":      "HR + IT Ops",
        "sla":        "Confirm within 3 business days",
    },
    "Excessive Multi-System Access": {
        "severity":   "🟡 MEDIUM",
        "risk":       "Users spanning many systems often hold legacy access from previous roles.",
        "step_1":     "List all systems this user has access to.",
        "step_2":     "Send to line manager for full recertification.",
        "step_3":     "Remove access to any system not confirmed as business-necessary.",
        "step_4":     "Flag for inclusion in next access review cycle.",
        "owner":      "Dept Head + IT Ops",
        "sla":        "Recertify within 10 business days",
    },
}


# ─────────────────────────────────────────────────────────────────────────────
#  HELPER UTILITIES
# ─────────────────────────────────────────────────────────────────────────────
def parse_date(val):
    """Safely parse a date from various formats."""
    if pd.isna(val) or val == "" or val is None:
        return None
    try:
        return pd.to_datetime(val)
    except Exception:
        return None


def is_generic(email: str, name: str) -> bool:
    """Return True if the email or name looks like a shared/generic/service account."""
    combined = (email + " " + name).lower()
    return any(pattern in combined for pattern in GENERIC_PATTERNS)


def is_service_account(email: str, name: str) -> bool:
    """Narrower check — explicitly a service/system account."""
    combined = (email + " " + name).lower()
    svc_patterns = ["svc", "service", "system", "batch", "backup", "noreply", "no-reply", "root"]
    return any(p in combined for p in svc_patterns)


def finding(row_dict: dict, issue_type: str, detail: str, days_inactive=None) -> dict:
    """Build a standardised finding record."""
    rem = REMEDIATION.get(issue_type, {})
    return {
        **row_dict,
        "IssueType":        issue_type,
        "Severity":         rem.get("severity", "⚪ INFO"),
        "Detail":           detail,
        "Risk":             rem.get("risk", ""),
        "Step 1 – Action":  rem.get("step_1", ""),
        "Step 2 – Action":  rem.get("step_2", ""),
        "Step 3 – Action":  rem.get("step_3", ""),
        "Step 4 – Action":  rem.get("step_4", ""),
        "Owner":            rem.get("owner", ""),
        "SLA":              rem.get("sla", ""),
        "DaysInactive":     days_inactive,
    }


# ─────────────────────────────────────────────────────────────────────────────
#  AUDIT ENGINE  — 9 checks
# ─────────────────────────────────────────────────────────────────────────────
def run_audit(
    hr_df: pd.DataFrame,
    sys_df: pd.DataFrame,
    scope_start: date = None,
    scope_end: date   = None,
) -> tuple:
    """
    Returns (findings_df, excluded_count) where excluded_count is the number
    of rows that were outside the audit scope window.
    """
    today = datetime.today()
    scope_start = scope_start or SCOPE_START
    scope_end   = scope_end   or SCOPE_END

    # Convert scope dates to datetime for comparison
    scope_start_dt = datetime.combine(scope_start, datetime.min.time())
    scope_end_dt   = datetime.combine(scope_end,   datetime.max.time())

    findings = []
    excluded_count = 0

    # --- Normalise HR ---
    hr_df = hr_df.copy()
    hr_df["_email"] = hr_df["Email"].str.strip().str.lower()
    if hr_df["_email"].duplicated().any():
        dupes = hr_df.loc[hr_df["_email"].duplicated(keep=False), "Email"].tolist()
        st.warning(f"⚠️ Duplicate emails in HR file — using first occurrence: {dupes}")
        hr_df = hr_df.drop_duplicates(subset="_email", keep="first")
    hr_lookup = hr_df.set_index("_email")
    hr_emails = set(hr_df["_email"])

    # --- Normalise System file ---
    sys_df = sys_df.copy()
    sys_df["_email"] = sys_df["Email"].str.strip().str.lower()

    # ── CHECK 8: Duplicate system accounts (same person, multiple IDs) ───────
    email_counts = sys_df["_email"].value_counts()
    duplicate_emails = set(email_counts[email_counts > 1].index)

    # ── CHECK 9: Excessive multi-system access ───────────────────────────────
    if "SystemName" in sys_df.columns:
        system_counts = sys_df.groupby("_email")["SystemName"].nunique()
        excessive_users = set(system_counts[system_counts > MAX_SYSTEMS_PER_USER].index)
    else:
        excessive_users = set()

    # --- Per-row checks with scope filtering ---
    for _, row in sys_df.iterrows():
        raw_email = str(row.get("Email", "")).strip()
        u_email   = raw_email.lower()
        u_access  = str(row.get("AccessLevel", "")).strip()
        u_name    = str(row.get("FullName", raw_email))
        row_dict  = row.to_dict()

        last_login      = parse_date(row.get("LastLoginDate"))
        pwd_last_set    = parse_date(row.get("PasswordLastSet"))
        account_created = parse_date(row.get("AccountCreatedDate"))

        # ── SCOPE CHECK ───────────────────────────────────────────────────────
        # Determine the most relevant date for this account to decide if it
        # falls within the audit window. Priority: AccountCreatedDate →
        # LastLoginDate → PasswordLastSet. If no date exists, include by default
        # (e.g. orphaned accounts with no dates still need to be caught).
        scope_anchor = account_created or last_login or pwd_last_set
        if scope_anchor is not None:
            if not (scope_start_dt <= scope_anchor <= scope_end_dt):
                excluded_count += 1
                continue  # Outside audit scope — skip entirely

        days_inactive   = (today - last_login).days if last_login else None
        pwd_age_days    = (today - pwd_last_set).days if pwd_last_set else None

        # ── CHECK 4: Shared / Generic account ─────────────────────────────
        if is_generic(u_email, u_name):
            if is_service_account(u_email, u_name):
                findings.append(finding(
                    row_dict, "Service / System Account",
                    f"'{u_name}' appears to be a service/system account with no named human owner.",
                    days_inactive,
                ))
            else:
                findings.append(finding(
                    row_dict, "Shared / Generic Account",
                    f"'{u_name}' matches generic account patterns — cannot be attributed to one individual.",
                    days_inactive,
                ))
            continue  # Skip HR-matching checks for generic accounts

        # ── CHECK 1: Orphaned account (no HR record) ───────────────────────
        if u_email not in hr_emails:
            best_score, best_match = 0, None
            for hr_email in hr_emails:
                score = fuzz.ratio(u_email, hr_email)
                if score > best_score:
                    best_score, best_match = score, hr_email

            if best_score >= FUZZY_THRESHOLD:
                findings.append(finding(
                    row_dict, "Near-Match Email",
                    f"System email '{u_email}' closely matches HR email '{best_match}' (similarity {best_score}%). "
                    f"Possible typo, alias or name change — verify manually.",
                    days_inactive,
                ))
            else:
                findings.append(finding(
                    row_dict, "Orphaned Account",
                    f"'{u_email}' has no matching record in the HR master. "
                    f"Likely a leaver, contractor, or ghost account.",
                    days_inactive,
                ))
            continue

        # --- Account IS in HR, run deeper checks ---
        hr_row     = hr_lookup.loc[u_email]
        dept       = str(hr_row.get("Department", "Unknown")).strip()
        emp_status = str(hr_row.get("EmploymentStatus", "Active")).strip().lower()
        job_title  = str(hr_row.get("JobTitle", "")).strip().lower()

        # ── CHECK 1b: Terminated employee still active ─────────────────────
        if emp_status in ("terminated", "resigned", "inactive", "on leave", "redundant"):
            findings.append(finding(
                row_dict, "Terminated Employee with Active Account",
                f"HR status is '{emp_status}' but the system account is still active. "
                f"This is a critical offboarding failure.",
                days_inactive,
            ))
            continue

        # ── CHECK 2: Dormant account ───────────────────────────────────────
        if days_inactive is not None and days_inactive > DORMANT_DAYS:
            findings.append(finding(
                row_dict, "Dormant Account",
                f"No login for {days_inactive} days (policy: {DORMANT_DAYS} days). "
                f"Last login: {last_login.date() if last_login else 'unknown'}.",
                days_inactive,
            ))
            # Don't skip — also check access issues for dormant accounts

        # ── CHECK 3: Toxic access / SoD violation ─────────────────────────
        forbidden_levels = SOD_RULES.get(dept, [])
        for forbidden in forbidden_levels:
            if forbidden.lower() in u_access.lower():
                findings.append(finding(
                    row_dict, "Toxic Access (SoD Violation)",
                    f"'{dept}' department user holds '{u_access}' access. "
                    f"'{forbidden}' is forbidden for '{dept}' under SoD policy — "
                    f"creates opportunity for fraud or undetected error.",
                    days_inactive,
                ))
                break

        # ── CHECK 5: Privilege creep (multi-role accumulation) ─────────────
        roles = [r.strip() for r in u_access.split(",") if r.strip()]
        if len(roles) >= 4:
            findings.append(finding(
                row_dict, "Privilege Creep",
                f"User holds {len(roles)} distinct roles: {u_access}. "
                f"High role count suggests accumulated access from previous positions — "
                f"violates least-privilege principle.",
                days_inactive,
            ))

        # ── CHECK 6: Super-user / Admin access outside IT ─────────────────
        is_it_staff = dept.lower() in ("it", "information technology", "security", "infosec")
        for high_risk in HIGH_RISK_ACCESS:
            if high_risk.lower() in u_access.lower() and not is_it_staff:
                findings.append(finding(
                    row_dict, "Super-User / Admin Access",
                    f"Non-IT user in '{dept}' holds '{u_access}' — "
                    f"admin-level access for a business user requires explicit CISO approval.",
                    days_inactive,
                ))
                break

        # ── CHECK 7: Password never expired ───────────────────────────────
        if pwd_age_days is not None and pwd_age_days > PASSWORD_EXPIRY_DAYS:
            findings.append(finding(
                row_dict, "Password Never Expired",
                f"Password last set {pwd_age_days} days ago "
                f"({pwd_last_set.date() if pwd_last_set else 'unknown'}). "
                f"Policy requires reset every {PASSWORD_EXPIRY_DAYS} days.",
                days_inactive,
            ))

        # ── CHECK 8: Duplicate system account ─────────────────────────────
        if u_email in duplicate_emails:
            findings.append(finding(
                row_dict, "Duplicate System Access",
                f"'{u_email}' appears multiple times in the system access file — "
                f"this user has more than one active account ID.",
                days_inactive,
            ))

        # ── CHECK 9: Excessive multi-system access ─────────────────────────
        if u_email in excessive_users:
            count = system_counts[u_email]
            findings.append(finding(
                row_dict, "Excessive Multi-System Access",
                f"'{u_email}' has access to {count} different systems "
                f"(threshold: {MAX_SYSTEMS_PER_USER}). "
                f"Likely carries legacy access from previous roles.",
                days_inactive,
            ))

    return (pd.DataFrame(findings) if findings else pd.DataFrame()), excluded_count


# ─────────────────────────────────────────────────────────────────────────────
#  EXCEL EXPORT  — multi-sheet with remediation
# ─────────────────────────────────────────────────────────────────────────────
def sanitise_sheet_name(name: str) -> str:
    """Strip characters Excel forbids in sheet names and enforce 31-char limit."""
    for ch in ['/', '\\', '*', '?', '[', ']', ':']:
        name = name.replace(ch, '-')
    return name[:31]


def to_excel_bytes(
    df: pd.DataFrame,
    hr_df: pd.DataFrame,
    sys_df: pd.DataFrame,
    scope_start: date = None,
    scope_end: date   = None,
    excluded_count: int = 0,
) -> bytes:
    output = io.BytesIO()

    sev_order = {"🔴 CRITICAL": 0, "🟠 HIGH": 1, "🟡 MEDIUM": 2, "⚪ INFO": 3}
    df = df.copy()
    df["_s"] = df["Severity"].map(sev_order).fillna(9)
    df = df.sort_values("_s").drop(columns="_s")

    with pd.ExcelWriter(output, engine="xlsxwriter") as writer:
        wb = writer.book

        # Formats
        hdr_fmt   = wb.add_format({"bold": True, "bg_color": "#1F3864", "font_color": "white", "border": 1})
        red_fmt   = wb.add_format({"bg_color": "#FFDEDE"})
        orange_fmt= wb.add_format({"bg_color": "#FFF0CC"})
        yellow_fmt= wb.add_format({"bg_color": "#FFFBCC"})
        wrap_fmt  = wb.add_format({"text_wrap": True, "valign": "top"})

        def write_sheet(sheet_df, sheet_name):
            sheet_df.to_excel(writer, index=False, sheet_name=sheet_name)
            ws = writer.sheets[sheet_name]
            for col_num, col in enumerate(sheet_df.columns):
                try:
                    col_values = sheet_df[col].fillna('').astype(str)
                    data_max   = col_values.map(len).max() if len(col_values) > 0 else 0
                    max_len    = min(max(int(data_max), len(str(col))) + 2, 60)
                except Exception:
                    max_len = len(str(col)) + 2
                ws.set_column(col_num, col_num, max_len)
            # Colour rows by severity
            for row_num, (_, row) in enumerate(sheet_df.iterrows(), start=1):
                sev = str(row.get("Severity", ""))
                fmt = red_fmt if "CRITICAL" in sev else (orange_fmt if "HIGH" in sev else (yellow_fmt if "MEDIUM" in sev else None))
                if fmt:
                    ws.set_row(row_num, None, fmt)
            # Header
            for col_num, col in enumerate(sheet_df.columns):
                ws.write(0, col_num, col, hdr_fmt)

        # Sheet 1: Executive Summary
        scope_s = scope_start.strftime("%d %b %Y") if scope_start else "N/A"
        scope_e = scope_end.strftime("%d %b %Y")   if scope_end   else "N/A"
        summary_data = {
            "Check": [
                "── AUDIT SCOPE ──",
                "Scope period (from)",
                "Scope period (to)",
                "Total accounts in system file",
                "Accounts within audit scope",
                "Accounts excluded (out of scope)",
                "── FINDINGS ──",
                "Total findings",
                "🔴 Critical findings",
                "🟠 High findings",
                "🟡 Medium findings",
                "Orphaned accounts",
                "Terminated with active access",
                "Dormant accounts",
                "Toxic / SoD violations",
                "Privilege creep",
                "Shared / generic accounts",
                "Service accounts without owner",
                "Super-user outside IT",
                "Passwords never expired",
                "Duplicate system accounts",
                "Excessive multi-system access",
                "Near-match emails (for review)",
            ],
            "Count": [
                "",
                scope_s,
                scope_e,
                len(sys_df),
                len(sys_df) - excluded_count,
                excluded_count,
                "",
                len(df),
                len(df[df["Severity"] == "🔴 CRITICAL"]) if len(df) else 0,
                len(df[df["Severity"] == "🟠 HIGH"])     if len(df) else 0,
                len(df[df["Severity"] == "🟡 MEDIUM"])   if len(df) else 0,
                len(df[df["IssueType"] == "Orphaned Account"])                        if len(df) else 0,
                len(df[df["IssueType"] == "Terminated Employee with Active Account"]) if len(df) else 0,
                len(df[df["IssueType"] == "Dormant Account"])                         if len(df) else 0,
                len(df[df["IssueType"] == "Toxic Access (SoD Violation)"])            if len(df) else 0,
                len(df[df["IssueType"] == "Privilege Creep"])                         if len(df) else 0,
                len(df[df["IssueType"] == "Shared / Generic Account"])               if len(df) else 0,
                len(df[df["IssueType"] == "Service / System Account"])               if len(df) else 0,
                len(df[df["IssueType"] == "Super-User / Admin Access"])              if len(df) else 0,
                len(df[df["IssueType"] == "Password Never Expired"])                 if len(df) else 0,
                len(df[df["IssueType"] == "Duplicate System Access"])                if len(df) else 0,
                len(df[df["IssueType"] == "Excessive Multi-System Access"])          if len(df) else 0,
                len(df[df["IssueType"] == "Near-Match Email"])                       if len(df) else 0,
            ]
        }
        summary_df = pd.DataFrame(summary_data)
        summary_df.to_excel(writer, index=False, sheet_name="Executive Summary")
        ws = writer.sheets["Executive Summary"]
        ws.set_column(0, 0, 45)
        ws.set_column(1, 1, 12)
        for col_num, col in enumerate(summary_df.columns):
            ws.write(0, col_num, col, hdr_fmt)

        # Sheet 2: All findings (sorted by severity)
        write_sheet(df, "All Findings")

        # Sheet 3: Remediation playbook
        playbook_cols = ["Severity", "IssueType", "Email", "FullName", "Detail",
                         "Step 1 – Action", "Step 2 – Action", "Step 3 – Action",
                         "Step 4 – Action", "Owner", "SLA"]
        playbook_cols = [c for c in playbook_cols if c in df.columns]
        write_sheet(df[playbook_cols], "Remediation Playbook")

        # Sheets per issue type
        for issue_type in df["IssueType"].unique():
            subset = df[df["IssueType"] == issue_type]
            sheet_name = sanitise_sheet_name(issue_type)
            write_sheet(subset, sheet_name)

        # Raw data sheets for reference
        hr_df.drop(columns=["_email"], errors="ignore").to_excel(writer, index=False, sheet_name="HR Master (Raw)")
        sys_df.drop(columns=["_email"], errors="ignore").to_excel(writer, index=False, sheet_name="System Access (Raw)")

    output.seek(0)
    return output.getvalue()


# ─────────────────────────────────────────────────────────────────────────────
#  PAGE CONFIG & UI
# ─────────────────────────────────────────────────────────────────────────────
st.set_page_config(page_title="Nairs Identity Auditor", layout="wide", page_icon="🛡️")
st.title("🛡️ Nairs.com Enterprise Identity Auditor")
st.caption("Automated identity audit — 9 checks a human would miss with random sampling")

# ── Sidebar: config ──────────────────────────────────────────────────────────
with st.sidebar:
    st.header("⚙️ Audit Policy Settings")

    # ── AUDIT SCOPE ───────────────────────────────────────────────────────────
    st.subheader("📅 Audit Scope Period")
    st.caption(
        "Only accounts whose creation date, last login, or password-set date "
        "falls within this window will be examined. Accounts with no date at all "
        "are always included (they could be ghost accounts)."
    )
    scope_col1, scope_col2 = st.columns(2)
    with scope_col1:
        SCOPE_START = st.date_input(
            "From",
            value=date.today() - timedelta(days=365),
            max_value=date.today(),
            help="Start of audit scope — no findings will be raised for activity before this date",
        )
    with scope_col2:
        SCOPE_END = st.date_input(
            "To",
            value=date.today(),
            min_value=SCOPE_START,
            max_value=date.today(),
            help="End of audit scope — typically today or the last day of the review period",
        )

    if SCOPE_START >= SCOPE_END:
        st.error("⚠️ 'From' date must be before 'To' date.")

    scope_days = (SCOPE_END - SCOPE_START).days
    st.info(f"🗓️ Scope window: **{scope_days} days**  ({SCOPE_START.strftime('%d %b %Y')} → {SCOPE_END.strftime('%d %b %Y')})")
    st.divider()

    # ── THRESHOLDS ────────────────────────────────────────────────────────────
    st.subheader("🔧 Detection Thresholds")
    DORMANT_DAYS         = st.slider("Dormant account threshold (days)", 30, 365, DORMANT_DAYS)
    PASSWORD_EXPIRY_DAYS = st.slider("Password expiry threshold (days)", 30, 365, PASSWORD_EXPIRY_DAYS)
    FUZZY_THRESHOLD      = st.slider("Fuzzy email match sensitivity", 70, 99, FUZZY_THRESHOLD,
                                      help="Lower = catch more near-matches; higher = stricter")
    MAX_SYSTEMS_PER_USER = st.slider("Max systems per user before flagging", 2, 10, MAX_SYSTEMS_PER_USER)
    st.divider()
    st.markdown("**Column requirements**")
    st.markdown("""
**HR Master** (required):
- `Email`, `Department`, `FullName`

**HR Master** (optional but recommended):
- `EmploymentStatus`
- `JobTitle`

**System Access** (required):
- `Email`, `AccessLevel`

**System Access** (optional but strongly recommended):
- `AccountCreatedDate` ← primary scope anchor
- `LastLoginDate`
- `PasswordLastSet`
- `FullName`
- `SystemName`

> **Scope logic:** The tool checks `AccountCreatedDate` first, then `LastLoginDate`, then `PasswordLastSet` to decide if a record falls within your audit window. Accounts with **no date at all** are always included — they are the most suspicious.
    """)

# ── File upload ──────────────────────────────────────────────────────────────
col1, col2 = st.columns(2)
with col1:
    hr_file  = st.file_uploader("📁 HR Master (.xlsx)", type=["xlsx"])
with col2:
    sys_file = st.file_uploader("📁 System Access (.xlsx)", type=["xlsx"])

if hr_file and sys_file:
    hr_df  = pd.read_excel(hr_file)
    sys_df = pd.read_excel(sys_file)

    # Column validation
    hr_required  = {"Email", "Department", "FullName"}
    sys_required = {"Email", "AccessLevel"}
    hr_missing   = hr_required  - set(hr_df.columns)
    sys_missing  = sys_required - set(sys_df.columns)
    if hr_missing or sys_missing:
        if hr_missing:
            st.error(f"❌ HR file is missing required columns: **{hr_missing}**")
        if sys_missing:
            st.error(f"❌ System Access file is missing required columns: **{sys_missing}**")
        st.stop()

    with st.spinner("🔍 Running all 9 audit checks..."):
        findings_df, excluded_count = run_audit(hr_df, sys_df, SCOPE_START, SCOPE_END)

    # ── SCOPE BANNER ─────────────────────────────────────────────────────────
    in_scope_count = len(sys_df) - excluded_count
    st.info(
        f"📅 **Audit scope:** {SCOPE_START.strftime('%d %b %Y')} → {SCOPE_END.strftime('%d %b %Y')}  "
        f"| **{in_scope_count}** of {len(sys_df)} accounts examined  "
        f"| **{excluded_count}** excluded as out-of-scope"
    )

    # ── METRICS ──────────────────────────────────────────────────────────────
    st.header("📊 Audit Summary")
    total = len(findings_df)

    def count(col, val): 
        return len(findings_df[findings_df[col] == val]) if total else 0

    m = st.columns(4)
    m[0].metric("Total Findings",   total)
    m[1].metric("🔴 Critical",       count("Severity", "🔴 CRITICAL"))
    m[2].metric("🟠 High",           count("Severity", "🟠 HIGH"))
    m[3].metric("🟡 Medium",         count("Severity", "🟡 MEDIUM"))

    if not findings_df.empty:
        st.divider()
        check_cols = st.columns(4)
        checks = [
            ("Orphaned Accounts",           "Orphaned Account"),
            ("Terminated Still Active",     "Terminated Employee with Active Account"),
            ("Dormant Accounts",            "Dormant Account"),
            ("SoD Violations",              "Toxic Access (SoD Violation)"),
            ("Privilege Creep",             "Privilege Creep"),
            ("Shared / Generic IDs",        "Shared / Generic Account"),
            ("Service Accounts",            "Service / System Account"),
            ("Admin Outside IT",            "Super-User / Admin Access"),
            ("Password Expired",            "Password Never Expired"),
            ("Duplicate IDs",               "Duplicate System Access"),
            ("Multi-System Excess",         "Excessive Multi-System Access"),
            ("Near-Match Emails",           "Near-Match Email"),
        ]
        for i, (label, issue_type) in enumerate(checks):
            check_cols[i % 4].metric(label, count("IssueType", issue_type))

    if findings_df.empty:
        st.success("✅ No issues found across all 9 checks. Identity landscape is clean.")
        st.stop()

    # ── TABS ─────────────────────────────────────────────────────────────────
    tab1, tab2, tab3 = st.tabs(["🔎 All Findings", "🛠️ Remediation Playbook", "📈 Analysis"])

    sev_order   = {"🔴 CRITICAL": 0, "🟠 HIGH": 1, "🟡 MEDIUM": 2, "⚪ INFO": 3}
    sorted_df   = findings_df.copy()
    sorted_df["_s"] = sorted_df["Severity"].map(sev_order).fillna(9)
    sorted_df   = sorted_df.sort_values("_s").drop(columns="_s")

    with tab1:
        filter_type = st.multiselect(
            "Filter by issue type:",
            options=sorted(findings_df["IssueType"].unique().tolist()),
            default=sorted(findings_df["IssueType"].unique().tolist()),
        )
        filtered = sorted_df[sorted_df["IssueType"].isin(filter_type)]

        display_cols = [c for c in ["Severity", "IssueType", "Email", "FullName",
                                     "Department", "AccessLevel", "DaysInactive", "Detail"]
                        if c in filtered.columns]
        st.dataframe(
            filtered[display_cols],
            use_container_width=True,
            hide_index=True,
            column_config={
                "Severity":     st.column_config.TextColumn("Severity", width="small"),
                "IssueType":    st.column_config.TextColumn("Issue Type", width="medium"),
                "Detail":       st.column_config.TextColumn("Detail", width="large"),
                "DaysInactive": st.column_config.NumberColumn("Days Inactive", width="small"),
            }
        )

    with tab2:
        st.markdown("Each finding below includes a 4-step remediation plan, owner, and SLA.")
        for _, row in sorted_df.iterrows():
            with st.expander(
                f"{row.get('Severity', '')}  |  {row.get('IssueType', '')}  —  "
                f"{row.get('Email', '')}  ({row.get('FullName', '')})"
            ):
                st.markdown(f"**Detail:** {row.get('Detail', '')}")
                st.markdown(f"**Risk:** {row.get('Risk', '')}")
                st.divider()
                c1, c2 = st.columns(2)
                c1.markdown(f"**Step 1:** {row.get('Step 1 – Action', '')}")
                c1.markdown(f"**Step 2:** {row.get('Step 2 – Action', '')}")
                c2.markdown(f"**Step 3:** {row.get('Step 3 – Action', '')}")
                c2.markdown(f"**Step 4:** {row.get('Step 4 – Action', '')}")
                st.divider()
                rc1, rc2 = st.columns(2)
                rc1.markdown(f"**Owner:** {row.get('Owner', '')}")
                rc2.markdown(f"**SLA:** {row.get('SLA', '')}")

    with tab3:
        a1, a2 = st.columns(2)
        with a1:
            st.markdown("**Findings by issue type**")
            by_type = findings_df["IssueType"].value_counts().reset_index()
            by_type.columns = ["Issue Type", "Count"]
            st.dataframe(by_type, use_container_width=True, hide_index=True)
        with a2:
            st.markdown("**Findings by severity**")
            by_sev = findings_df["Severity"].value_counts().reset_index()
            by_sev.columns = ["Severity", "Count"]
            st.dataframe(by_sev, use_container_width=True, hide_index=True)

        if "Department" in findings_df.columns:
            st.markdown("**Findings by department**")
            by_dept = findings_df["Department"].value_counts().reset_index()
            by_dept.columns = ["Department", "Count"]
            st.dataframe(by_dept, use_container_width=True, hide_index=True)

        if "DaysInactive" in findings_df.columns:
            dormant_data = findings_df[findings_df["DaysInactive"].notna()]
            if not dormant_data.empty:
                st.markdown("**Inactivity distribution (days)**")
                st.bar_chart(dormant_data.set_index("Email")["DaysInactive"])

    # ── EXPORT ───────────────────────────────────────────────────────────────
    st.divider()
    st.download_button(
        label="📥 Download Full Audit Report (.xlsx) — includes remediation playbook",
        data=to_excel_bytes(findings_df, hr_df, sys_df, SCOPE_START, SCOPE_END, excluded_count),
        file_name=f"Identity_Audit_{datetime.today().strftime('%Y%m%d')}.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        type="primary",
    )

elif hr_file or sys_file:
    st.info("📂 Please upload **both** files to run the audit.")
else:
    # Landing state — show what the tool checks
    st.info("👆 Upload both files above to begin the audit.")
    with st.expander("📋 What this tool checks (9 automated checks)", expanded=True):
        checks_info = [
            ("🔴", "Orphaned accounts",               "Accounts in system with no HR record — leavers, ghosts, contractors"),
            ("🔴", "Terminated with active access",   "HR shows resigned/terminated but account is still live"),
            ("🔴", "Toxic access / SoD violations",   "Dept vs access-level conflict (e.g. Sales with Finance access)"),
            ("🟠", "Dormant accounts",                "No login in 90+ days — high takeover risk"),
            ("🟠", "Privilege creep",                 "4+ roles accumulated over time — violates least-privilege"),
            ("🟠", "Shared / generic accounts",       "admin@, test@, helpdesk@ — defeats audit trail entirely"),
            ("🟠", "Super-user outside IT",           "Admin/DBAdmin rights granted to non-IT business users"),
            ("🟡", "Service accounts without owner",  "svc_, system_, batch_ accounts with no named human owner"),
            ("🟡", "Passwords never expired",         "Credentials older than policy limit — breach risk"),
            ("🟡", "Duplicate system accounts",       "Same person with multiple IDs — multiplies attack surface"),
            ("🟡", "Excessive multi-system access",   "Users spanning more systems than their role justifies"),
            ("🟡", "Near-match emails",               "Fuzzy-matched emails — possible typos, aliases or impersonation"),
        ]
        for sev, name, desc in checks_info:
            st.markdown(f"{sev} **{name}** — {desc}")

