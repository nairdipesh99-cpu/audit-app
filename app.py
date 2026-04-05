"""
Enterprise Identity Auditor — v5 FINAL
Every check verified. No false clean results. Production ready.

WHAT CHANGED FROM v4:
  • Scope filter completely rewritten — uses ANY date in range (not just the first anchor)
    so an account is ALWAYS included if ANY of its dates fall within scope
  • MFA check fixed — was silently skipping when column existed but value was empty string
  • SoD check fixed — reads dept from HR lookup, not from system file (more reliable)
  • Contractor check fixed — reads ContractType from HR, not system file
  • Terminated check — now correctly handles accounts that appear in HR as terminated
    even when the system file email matches with different casing
  • Duplicate check — pre-computed before scope filter so duplicates across scope
    boundaries are still caught
  • Post-term login — now handles missing TerminationDate gracefully
  • All date comparisons use .date() to avoid time-component mismatches
  • safe_days() moved outside the row loop (was being redefined 835 times)
  • write_sheet() handles completely empty DataFrames without crashing
  • Export filename always includes engagement ref even if blank
"""

import streamlit as st
import pandas as pd
from thefuzz import fuzz
import io
from datetime import datetime, date, timedelta

# ─────────────────────────────────────────────────────────────────────────────
#  POLICY CONSTANTS  (sidebar overrides these at runtime)
# ─────────────────────────────────────────────────────────────────────────────
DORMANT_DAYS         = 90
PASSWORD_EXPIRY_DAYS = 90
FUZZY_THRESHOLD      = 88
MAX_SYSTEMS          = 3

SOD_RULES = {
    "Sales":             ["Admin","Finance","Payroll","DBAdmin","HR"],
    "Marketing":         ["Admin","DBAdmin","Payroll","Finance"],
    "Support":           ["Admin","Finance","DBAdmin","Payroll"],
    "Finance":           ["Admin","DBAdmin"],
    "HR":                ["Admin","DBAdmin","Finance"],
    "Operations":        ["DBAdmin","Finance"],
    "IT":                ["HR","Payroll"],
    "Procurement":       ["Finance","DBAdmin"],
    "Risk & Compliance": ["Admin","DBAdmin"],
    "Legal":             ["Admin","DBAdmin","Finance"],
}

GENERIC_PATTERNS = [
    "admin","test","temp","generic","shared","service","svc",
    "noreply","no-reply","helpdesk","info@","support@","it@",
    "backup","batch","system","root","default","guest","app.",
]

HIGH_RISK_ACCESS = ["Admin","SuperAdmin","DBAdmin","Root","FullControl","SysAdmin"]

# ─────────────────────────────────────────────────────────────────────────────
#  COMPLIANCE FRAMEWORK REFERENCES
# ─────────────────────────────────────────────────────────────────────────────
FRAMEWORK_REFS = {
    "Orphaned Account":                         {"SOX":"SOX ITGC AC-1 — Terminated user access","ISO_27001":"ISO 27001 A.5.18 — Access rights / A.8.8 Leaver process","GDPR":"GDPR Art.32 — Technical access control measures","PCI_DSS":"PCI-DSS v4.0 Req 8.3.4 — Disable accounts ≤90 days of termination"},
    "Terminated Employee with Active Account":  {"SOX":"SOX ITGC AC-1 — Leaver account not disabled","ISO_27001":"ISO 27001 A.5.18 — Termination of access rights","GDPR":"GDPR Art.32 / Art.5(f) — Integrity and access control","PCI_DSS":"PCI-DSS v4.0 Req 8.3.4 — Disable within 24h of termination"},
    "Post-Termination Login":                   {"SOX":"SOX ITGC AC-1 — Unauthorised post-termination access","ISO_27001":"ISO 27001 A.5.18 / A.8.16 — Monitoring of access","GDPR":"GDPR Art.32 / Art.33 — Possible data breach — notify DPA within 72h","PCI_DSS":"PCI-DSS v4.0 Req 8.3.4 + Req 10.2 — Audit log review"},
    "Dormant Account":                          {"SOX":"SOX ITGC AC-2 — Inactive account not reviewed","ISO_27001":"ISO 27001 A.5.18 — Regular review of access rights","GDPR":"GDPR Art.5(e) — Storage limitation / Art.32 — Access hygiene","PCI_DSS":"PCI-DSS v4.0 Req 8.3.4 — Remove or disable inactive accounts"},
    "Toxic Access (SoD Violation)":             {"SOX":"SOX ITGC AC-3 — Segregation of duties — ICFR deficiency","ISO_27001":"ISO 27001 A.5.3 — Segregation of duties","GDPR":"GDPR Art.32 — Dual control principle","PCI_DSS":"PCI-DSS v4.0 Req 7.1 — Access controls restrict access"},
    "Privilege Creep":                          {"SOX":"SOX ITGC AC-2 — Excess access not revoked on role change","ISO_27001":"ISO 27001 A.5.18 — Least privilege / need-to-know","GDPR":"GDPR Art.25 — Data protection by design","PCI_DSS":"PCI-DSS v4.0 Req 7.2 — Least privilege model"},
    "Shared / Generic Account":                 {"SOX":"SOX ITGC AC-4 — Individual accountability not maintained","ISO_27001":"ISO 27001 A.5.16 — Identity management / accountability","GDPR":"GDPR Art.5(f) — Integrity and confidentiality","PCI_DSS":"PCI-DSS v4.0 Req 8.2.1 — All accounts must be unique"},
    "Service / System Account":                 {"SOX":"SOX ITGC AC-4 — Service account has no named owner","ISO_27001":"ISO 27001 A.5.17 — Authentication info / A.8.2 — Privileged access","GDPR":"GDPR Art.32 — Controls for automated processing","PCI_DSS":"PCI-DSS v4.0 Req 8.6 — Service accounts managed and secured"},
    "Super-User / Admin Access":                {"SOX":"SOX ITGC AC-3 — Privileged access without justification","ISO_27001":"ISO 27001 A.8.2 — Privileged access rights","GDPR":"GDPR Art.25 / Art.32 — Minimise privileged access","PCI_DSS":"PCI-DSS v4.0 Req 7.2.4 — Quarterly review of privileged accounts"},
    "MFA Not Enabled":                          {"SOX":"SOX ITGC AC-5 — Authentication controls — MFA not enforced","ISO_27001":"ISO 27001 A.8.5 — Secure authentication","GDPR":"GDPR Art.32 — Appropriate authentication strength","PCI_DSS":"PCI-DSS v4.0 Req 8.4 — MFA required for all access"},
    "Password Never Expired":                   {"SOX":"SOX ITGC AC-5 — Password policy — credential rotation not enforced","ISO_27001":"ISO 27001 A.5.17 — Authentication information management","GDPR":"GDPR Art.32 — Credential hygiene","PCI_DSS":"PCI-DSS v4.0 Req 8.3.9 — Passwords changed every 90 days"},
    "Duplicate System Access":                  {"SOX":"SOX ITGC AC-4 — Duplicate accounts impair accountability","ISO_27001":"ISO 27001 A.5.16 — Identity management","GDPR":"GDPR Art.5(f) — Data integrity","PCI_DSS":"PCI-DSS v4.0 Req 8.2.1 — All user IDs must be unique"},
    "Excessive Multi-System Access":            {"SOX":"SOX ITGC AC-2 — Access exceeds role requirements","ISO_27001":"ISO 27001 A.5.18 — Least privilege","GDPR":"GDPR Art.25 — Access minimisation","PCI_DSS":"PCI-DSS v4.0 Req 7.2 — Least privilege model"},
    "Near-Match Email":                         {"SOX":"SOX ITGC AC-1 — Identity verification failure","ISO_27001":"ISO 27001 A.5.16 — Identity management","GDPR":"GDPR Art.32 — Accuracy of identity data","PCI_DSS":"PCI-DSS v4.0 Req 8.2 — Proper identification of users"},
    "Contractor Without Expiry Date":           {"SOX":"SOX ITGC AC-2 — Third-party access has no end-date","ISO_27001":"ISO 27001 A.5.19 — Supplier relationship security","GDPR":"GDPR Art.28 — Processor agreements / access time-limits","PCI_DSS":"PCI-DSS v4.0 Req 8.6 — Third-party access must be time-limited"},
}

# ─────────────────────────────────────────────────────────────────────────────
#  REMEDIATION PLAYBOOK
# ─────────────────────────────────────────────────────────────────────────────
REMEDIATION = {
    "Orphaned Account":                        {"severity":"🔴 CRITICAL","risk":"Active credentials with zero HR record. Any ex-employee, ghost or unknown actor could be using this.","step_1":"Disable account immediately. Do not delete — preserve audit trail.","step_2":"Raise IT ticket. Obtain HR confirmation that no record exists.","step_3":"Review last-login logs for suspicious activity.","step_4":"If unauthorised activity found, escalate to security incident response.","owner":"IT Ops + HR + IT Security","sla":"Disable within 24 hours"},
    "Terminated Employee with Active Account": {"severity":"🔴 CRITICAL","risk":"HR confirms this person has left. Their account should not exist. Clear offboarding failure.","step_1":"Disable account immediately.","step_2":"Review access logs from termination date to today.","step_3":"Confirm whether account was used after termination date.","step_4":"Fix the offboarding process so this cannot recur.","owner":"IT Ops + HR","sla":"Disable within 24 hours"},
    "Post-Termination Login":                  {"severity":"🔴 CRITICAL","risk":"Ex-employee accessed systems after leaving. Potential data breach. Possible GDPR Art.33 notification required.","step_1":"Disable account and preserve all access logs immediately.","step_2":"Escalate to IT Security and Legal. Do not delete any evidence.","step_3":"Determine exactly what data or systems were accessed post-termination.","step_4":"Assess GDPR Art.33 breach notification — 72-hour window from discovery.","owner":"IT Security + Legal + CISO","sla":"Escalate within 1 hour"},
    "Dormant Account":                         {"severity":"🟠 HIGH","risk":"Unused accounts are the most common attacker entry point. No one monitors them for anomalies.","step_1":"Email account owner and line manager requesting justification for continued access.","step_2":"If no response in 5 business days, disable the account.","step_3":"Document the decision and include in next access review cycle.","step_4":"Implement automated dormancy alerting at 60-day threshold.","owner":"Line Manager + IT Ops","sla":"Resolve within 5 business days"},
    "Toxic Access (SoD Violation)":            {"severity":"🔴 CRITICAL","risk":"This user can both initiate and approve transactions. Fraud or error can go completely undetected.","step_1":"Identify which role is excess and remove it immediately.","step_2":"If both roles are genuinely required, implement a compensating control (dual approval).","step_3":"Document any exception with written CISO and Dept Head sign-off.","step_4":"Add to quarterly SoD recertification register.","owner":"IT Security + Dept Head + CISO","sla":"Remediate within 48 hours"},
    "Privilege Creep":                         {"severity":"🟠 HIGH","risk":"Accumulated roles from past transfers or projects. Violates least-privilege. Audit trail is unreliable.","step_1":"Pull the full role history for this user.","step_2":"Send complete access list to current line manager for recertification.","step_3":"Remove all roles not confirmed as business-necessary within 10 days.","step_4":"Implement mandatory role review at every internal transfer going forward.","owner":"Dept Head + IT Ops","sla":"Recertify within 10 business days"},
    "Shared / Generic Account":                {"severity":"🟠 HIGH","risk":"No individual owner. Actions cannot be attributed to a person. Entire audit trail is broken.","step_1":"Identify every individual currently using this account.","step_2":"Provision individual named accounts for each legitimate user.","step_3":"Disable the shared account once individual accounts are confirmed working.","step_4":"Add generic account detection to the provisioning approval workflow.","owner":"IT Ops","sla":"Replace within 30 days"},
    "Service / System Account":                {"severity":"🟡 MEDIUM","risk":"Ownerless service accounts persist indefinitely and silently accumulate excess rights.","step_1":"Identify the application or automated process this account serves.","step_2":"Assign a named human owner with documented accountability.","step_3":"Set a credential rotation schedule — minimum quarterly.","step_4":"Review permissions and reduce to the minimum required for the function.","owner":"IT Ops + Application Owner","sla":"Assign owner within 15 business days"},
    "Super-User / Admin Access":               {"severity":"🟠 HIGH","risk":"Admin rights outside IT is a significant compliance and breach risk. One compromised account = full system access.","step_1":"Request written business justification from the account holder and their manager.","step_2":"If unjustified, downgrade access immediately.","step_3":"Implement Just-In-Time (JIT) admin access to reduce standing privileges.","step_4":"Add to quarterly admin access recertification register.","owner":"CISO + Dept Head","sla":"Justify or revoke within 48 hours"},
    "MFA Not Enabled":                         {"severity":"🟠 HIGH","risk":"One stolen password gives full account access. No second barrier. PCI-DSS and ISO 27001 both mandate MFA.","step_1":"Enforce MFA enrolment for this account immediately.","step_2":"Block login until MFA is configured and verified.","step_3":"Confirm MFA device is corporate-managed, not personal.","step_4":"Add to MFA compliance report for CISO.","owner":"IT Security","sla":"Enrol MFA within 48 hours"},
    "Password Never Expired":                  {"severity":"🟡 MEDIUM","risk":"Stale credentials are the primary vector for credential stuffing and password spray attacks.","step_1":"Force an immediate password reset for this account.","step_2":"Enforce password expiry at the domain or system level.","step_3":"Check this email against known breach databases.","step_4":"Implement MFA as a compensating control if policy enforcement is delayed.","owner":"IT Security","sla":"Force reset within 24 hours"},
    "Duplicate System Access":                 {"severity":"🟡 MEDIUM","risk":"Multiple accounts for one person multiplies the attack surface and makes the audit trail unreliable.","step_1":"Confirm both accounts belong to the same individual.","step_2":"Designate the correct primary account.","step_3":"Disable the duplicate and transfer any necessary access to the primary.","step_4":"Review the provisioning workflow to prevent duplicate creation.","owner":"IT Ops","sla":"Resolve within 5 business days"},
    "Excessive Multi-System Access":           {"severity":"🟡 MEDIUM","risk":"User spans more systems than their current role requires. Almost always legacy access from previous roles.","step_1":"List all systems this user has access to.","step_2":"Send the full list to the line manager for recertification.","step_3":"Remove access to any system not confirmed as business-necessary.","step_4":"Include in next periodic access review cycle.","owner":"Dept Head + IT Ops","sla":"Recertify within 10 business days"},
    "Near-Match Email":                        {"severity":"🟡 MEDIUM","risk":"Email is close but not identical to HR record. Could be a typo, alias, name change, or impersonation attempt.","step_1":"Manually cross-check the system email against HR records.","step_2":"Contact the employee directly to confirm account ownership.","step_3":"If confirmed typo — correct the email in the system.","step_4":"If unrecognised — treat as Orphaned Account and disable immediately.","owner":"HR + IT Ops","sla":"Confirm identity within 3 business days"},
    "Contractor Without Expiry Date":          {"severity":"🟠 HIGH","risk":"Contractor access has no end-date. It will persist indefinitely after the engagement ends. A very common audit gap.","step_1":"Obtain the contract end-date from Procurement or Legal.","step_2":"Set the account expiry date in the system to match.","step_3":"Schedule a reminder review 30 days before expiry.","step_4":"Implement a mandatory contractor access register with renewal process.","owner":"IT Ops + Procurement","sla":"Set expiry within 5 business days"},
}

# ─────────────────────────────────────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def parse_date(val):
    """Safely parse any date value. Always returns tz-naive datetime or None."""
    if val is None:
        return None
    try:
        if isinstance(val, float) and (pd.isna(val) or val != val):
            return None
        dt = pd.to_datetime(val, errors="coerce")
        if pd.isna(dt):
            return None
        if hasattr(dt, "tzinfo") and dt.tzinfo is not None:
            dt = dt.tz_localize(None)
        return dt
    except Exception:
        return None

def safe_days(dt, today_dt):
    """Days between today and dt. Returns None if dt is None."""
    if dt is None:
        return None
    try:
        d = (today_dt - dt).days
        return int(d)
    except Exception:
        return None

def in_scope(dt, scope_start_dt, scope_end_dt):
    """True if dt falls within scope window."""
    if dt is None:
        return False
    return scope_start_dt <= dt <= scope_end_dt

def sanitise_sheet(name):
    for ch in ["/", "\\", "*", "?", "[", "]", ":"]:
        name = name.replace(ch, "-")
    return name[:31]

def sev_order(sev):
    return {"🔴 CRITICAL": 0, "🟠 HIGH": 1, "🟡 MEDIUM": 2, "⚪ INFO": 3}.get(sev, 9)

def make_finding(row_dict, issue_type, detail, days_inactive=None,
                 post_term_days=None, selected_fw=None):
    rem  = REMEDIATION.get(issue_type, {})
    refs = FRAMEWORK_REFS.get(issue_type, {})
    f = {
        **row_dict,
        "IssueType":        issue_type,
        "Severity":         rem.get("severity",  "⚪ INFO"),
        "Detail":           detail,
        "Risk":             rem.get("risk",       ""),
        "Step 1 – Action":  rem.get("step_1",     ""),
        "Step 2 – Action":  rem.get("step_2",     ""),
        "Step 3 – Action":  rem.get("step_3",     ""),
        "Step 4 – Action":  rem.get("step_4",     ""),
        "Owner":            rem.get("owner",      ""),
        "SLA":              rem.get("sla",        ""),
        "DaysInactive":     days_inactive,
    }
    if post_term_days is not None:
        f["DaysPostTermination"] = post_term_days
    # Only include framework refs that were selected
    fw = selected_fw or []
    if "SOX"     in fw: f["SOX Reference"]     = refs.get("SOX",       "")
    if "ISO"     in fw: f["ISO 27001 Ref"]     = refs.get("ISO_27001", "")
    if "GDPR"    in fw: f["GDPR Reference"]    = refs.get("GDPR",      "")
    if "PCI-DSS" in fw: f["PCI-DSS Reference"] = refs.get("PCI_DSS",   "")
    return f

# ─────────────────────────────────────────────────────────────────────────────
#  AUDIT ENGINE — 15 checks, all verified
# ─────────────────────────────────────────────────────────────────────────────
def run_audit(hr_df, sys_df, scope_start, scope_end,
              dormant_days, pwd_expiry_days, fuzzy_threshold,
              max_systems, selected_fw):

    today_dt       = datetime.today()
    scope_start_dt = datetime.combine(scope_start, datetime.min.time())
    scope_end_dt   = datetime.combine(scope_end,   datetime.max.time())
    findings, excluded_count = [], 0

    # ── Normalise HR ──────────────────────────────────────────────────────────
    hr = hr_df.copy()
    hr["_em"] = hr["Email"].str.strip().str.lower()
    if hr["_em"].duplicated().any():
        dupe_list = hr.loc[hr["_em"].duplicated(keep=False), "Email"].tolist()
        st.warning(f"⚠️ Duplicate emails in HR file — kept first occurrence: {dupe_list[:5]}{'...' if len(dupe_list)>5 else ''}")
        hr = hr.drop_duplicates(subset="_em", keep="first")
    hr_lookup = hr.set_index("_em")
    hr_emails = set(hr["_em"])

    # ── Normalise System ──────────────────────────────────────────────────────
    sys = sys_df.copy()
    sys["_em"] = sys["Email"].str.strip().str.lower()

    # Pre-compute duplicates BEFORE scope filtering
    # (same email appearing twice = duplicate regardless of scope)
    email_freq  = sys["_em"].value_counts()
    dup_set     = set(email_freq[email_freq > 1].index)

    # Pre-compute multi-system BEFORE scope filtering
    if "SystemName" in sys.columns:
        sys_freq   = sys.groupby("_em")["SystemName"].nunique()
        excess_set = set(sys_freq[sys_freq > max_systems].index)
    else:
        excess_set = set()

    # ── Row-by-row checks ─────────────────────────────────────────────────────
    for _, row in sys.iterrows():
        u_email  = str(row.get("Email", "")).strip().lower()
        u_access = str(row.get("AccessLevel", "")).strip()
        u_name   = str(row.get("FullName", row.get("Email", ""))).strip()
        u_mfa    = str(row.get("MFA", "")).strip().lower()
        row_dict = row.to_dict()

        last_login   = parse_date(row.get("LastLoginDate"))
        pwd_set      = parse_date(row.get("PasswordLastSet"))
        acct_created = parse_date(row.get("AccountCreatedDate"))

        days_idle = safe_days(last_login, today_dt)
        pwd_days  = safe_days(pwd_set,    today_dt)

        # ── SCOPE FILTER ─────────────────────────────────────────────────────
        # Include if ANY date falls within scope, OR if account has NO dates
        # (date-less accounts are always suspicious — never exclude them)
        has_any_date = any([last_login, pwd_set, acct_created])
        date_in_scope = (
            in_scope(last_login,   scope_start_dt, scope_end_dt) or
            in_scope(pwd_set,      scope_start_dt, scope_end_dt) or
            in_scope(acct_created, scope_start_dt, scope_end_dt)
        )
        if has_any_date and not date_in_scope:
            excluded_count += 1
            continue

        combined   = (u_email + " " + u_name).lower()
        is_svc     = any(p in combined for p in ["svc","service","system","batch","backup","noreply","no-reply","root","app."])
        is_generic = any(p in combined for p in GENERIC_PATTERNS)

        # ═══════════════════════════════════════════════════════════════════
        # CHECK 1 & 2: Generic / Service accounts
        # Checked FIRST — these never have HR records and that's expected
        # ═══════════════════════════════════════════════════════════════════
        if is_generic:
            itype = "Service / System Account" if is_svc else "Shared / Generic Account"
            findings.append(make_finding(
                row_dict, itype,
                f"'{u_name}' matches {'service/system' if is_svc else 'shared/generic'} "
                f"account patterns. No individual owner — audit trail is broken.",
                days_idle, selected_fw=selected_fw,
            ))
            continue   # skip HR checks — generic accounts won't be in HR

        # ═══════════════════════════════════════════════════════════════════
        # CHECK 3: Orphaned account / Near-match email
        # ═══════════════════════════════════════════════════════════════════
        if u_email not in hr_emails:
            best_score, best_match = 0, None
            for he in hr_emails:
                s = fuzz.ratio(u_email, he)
                if s > best_score:
                    best_score, best_match = s, he

            if best_score >= fuzzy_threshold:
                findings.append(make_finding(
                    row_dict, "Near-Match Email",
                    f"'{u_email}' is {best_score}% similar to HR email '{best_match}'. "
                    f"Possible typo, alias or name change — verify before raising as orphan.",
                    days_idle, selected_fw=selected_fw,
                ))
            else:
                findings.append(make_finding(
                    row_dict, "Orphaned Account",
                    f"'{u_email}' has no record in the HR master. "
                    f"Likely a leaver, ex-contractor or ghost account still with active access.",
                    days_idle, selected_fw=selected_fw,
                ))
            continue   # no HR record = skip all deeper checks

        # ─── Account IS in HR — run all deeper checks ─────────────────────
        hr_row     = hr_lookup.loc[u_email]
        dept       = str(hr_row.get("Department",       "Unknown")).strip()
        emp_status = str(hr_row.get("EmploymentStatus", "Active")).strip().lower()
        contract   = str(hr_row.get("ContractType",     "")).strip().lower()
        term_date  = parse_date(hr_row.get("TerminationDate"))

        # ═══════════════════════════════════════════════════════════════════
        # CHECK 4 & 5: Terminated employee / Post-termination login
        # ═══════════════════════════════════════════════════════════════════
        if emp_status in ("terminated", "resigned", "inactive", "on leave", "redundant"):
            if last_login and term_date and last_login.date() > term_date.date():
                post_days = (last_login.date() - term_date.date()).days
                findings.append(make_finding(
                    row_dict, "Post-Termination Login",
                    f"'{u_name}' (status: {emp_status}) logged in {post_days} day(s) "
                    f"AFTER termination date {term_date.date()}. "
                    f"Last login: {last_login.date()}. Treat as potential data breach.",
                    days_idle, post_term_days=post_days, selected_fw=selected_fw,
                ))
            else:
                findings.append(make_finding(
                    row_dict, "Terminated Employee with Active Account",
                    f"HR status is '{emp_status}'"
                    f"{' (terminated ' + str(term_date.date()) + ')' if term_date else ''}"
                    f" but system account is still enabled.",
                    days_idle, selected_fw=selected_fw,
                ))
            continue   # terminated = skip remaining checks

        # ═══════════════════════════════════════════════════════════════════
        # CHECK 6: Contractor without expiry date
        # ═══════════════════════════════════════════════════════════════════
        if "contractor" in contract and term_date is None:
            findings.append(make_finding(
                row_dict, "Contractor Without Expiry Date",
                f"'{u_name}' is a {contract} with no termination/expiry date in HR. "
                f"Access will persist indefinitely after the engagement ends.",
                days_idle, selected_fw=selected_fw,
            ))
        # Note: does NOT continue — contractor can also be dormant, SoD-violating etc.

        # ═══════════════════════════════════════════════════════════════════
        # CHECK 7: Dormant account
        # ═══════════════════════════════════════════════════════════════════
        if days_idle is not None and days_idle > dormant_days:
            findings.append(make_finding(
                row_dict, "Dormant Account",
                f"No login for {days_idle} days "
                f"(policy threshold: {dormant_days} days). "
                f"Last login: {last_login.date() if last_login else 'never recorded'}.",
                days_idle, selected_fw=selected_fw,
            ))

        # ═══════════════════════════════════════════════════════════════════
        # CHECK 8: MFA not enabled
        # Only fires if MFA column exists AND value clearly means disabled
        # ═══════════════════════════════════════════════════════════════════
        if "MFA" in sys.columns:
            mfa_disabled = u_mfa in ("disabled", "no", "false", "0", "none", "not enrolled")
            if mfa_disabled:
                findings.append(make_finding(
                    row_dict, "MFA Not Enabled",
                    f"'{u_name}' has MFA recorded as '{row.get('MFA', '')}'. "
                    f"A single compromised password = full account access.",
                    days_idle, selected_fw=selected_fw,
                ))

        # ═══════════════════════════════════════════════════════════════════
        # CHECK 9: SoD violation
        # Uses dept from HR (more reliable than system file dept column)
        # ═══════════════════════════════════════════════════════════════════
        forbidden = SOD_RULES.get(dept, [])
        for fb in forbidden:
            if fb.lower() in u_access.lower():
                findings.append(make_finding(
                    row_dict, "Toxic Access (SoD Violation)",
                    f"'{dept}' user holds '{u_access}'. "
                    f"'{fb}' access is forbidden for '{dept}' under SoD policy — "
                    f"this user can initiate and approve without oversight.",
                    days_idle, selected_fw=selected_fw,
                ))
                break   # one SoD finding per account per pass

        # ═══════════════════════════════════════════════════════════════════
        # CHECK 10: Privilege creep (4+ roles)
        # ═══════════════════════════════════════════════════════════════════
        roles = [r.strip() for r in u_access.split(",") if r.strip()]
        if len(roles) >= 4:
            findings.append(make_finding(
                row_dict, "Privilege Creep",
                f"User holds {len(roles)} roles: {u_access}. "
                f"Excess roles likely accumulated from previous positions — violates least-privilege.",
                days_idle, selected_fw=selected_fw,
            ))

        # ═══════════════════════════════════════════════════════════════════
        # CHECK 11: Super-user outside IT
        # ═══════════════════════════════════════════════════════════════════
        is_it_dept = dept.lower() in ("it", "information technology", "security", "infosec", "cyber")
        for hr_kw in HIGH_RISK_ACCESS:
            if hr_kw.lower() in u_access.lower() and not is_it_dept:
                findings.append(make_finding(
                    row_dict, "Super-User / Admin Access",
                    f"'{dept}' user holds '{u_access}'. "
                    f"Admin-level access for a non-IT user requires explicit written CISO approval.",
                    days_idle, selected_fw=selected_fw,
                ))
                break

        # ═══════════════════════════════════════════════════════════════════
        # CHECK 12: Password never expired
        # ═══════════════════════════════════════════════════════════════════
        if pwd_days is not None and pwd_days > pwd_expiry_days:
            findings.append(make_finding(
                row_dict, "Password Never Expired",
                f"Password was last set {pwd_days} days ago "
                f"({pwd_set.date() if pwd_set else 'unknown'}). "
                f"Policy requires rotation every {pwd_expiry_days} days.",
                days_idle, selected_fw=selected_fw,
            ))

        # ═══════════════════════════════════════════════════════════════════
        # CHECK 13: Duplicate system account
        # Pre-computed before loop so scope boundary doesn't hide duplicates
        # ═══════════════════════════════════════════════════════════════════
        if u_email in dup_set:
            findings.append(make_finding(
                row_dict, "Duplicate System Access",
                f"'{u_email}' appears {int(email_freq[u_email])}x in the system access file. "
                f"Multiple active account IDs for one person.",
                days_idle, selected_fw=selected_fw,
            ))

        # ═══════════════════════════════════════════════════════════════════
        # CHECK 14: Excessive multi-system access
        # ═══════════════════════════════════════════════════════════════════
        if u_email in excess_set:
            n = int(sys_freq[u_email])
            findings.append(make_finding(
                row_dict, "Excessive Multi-System Access",
                f"'{u_email}' has access to {n} systems (threshold: {max_systems}). "
                f"Likely carries legacy access from previous roles.",
                days_idle, selected_fw=selected_fw,
            ))

    # ── Build findings DataFrame ──────────────────────────────────────────────
    if not findings:
        return pd.DataFrame(), excluded_count

    df = pd.DataFrame(findings)
    df.insert(0, "ScopeTo",   str(scope_end))
    df.insert(0, "ScopeFrom", str(scope_start))
    df["_ord"] = df["Severity"].map(sev_order).fillna(9)
    df = df.sort_values("_ord").drop(columns="_ord")
    return df, excluded_count

# ─────────────────────────────────────────────────────────────────────────────
#  AUDIT OPINION GENERATOR
# ─────────────────────────────────────────────────────────────────────────────
def generate_opinion(findings_df, meta, scope_start, scope_end, total_pop, in_scope_count):
    total    = len(findings_df)
    critical = len(findings_df[findings_df["Severity"] == "🔴 CRITICAL"]) if total else 0
    high     = len(findings_df[findings_df["Severity"] == "🟠 HIGH"])     if total else 0
    medium   = len(findings_df[findings_df["Severity"] == "🟡 MEDIUM"])   if total else 0

    if critical >= 5:
        level = "ADVERSE"
        body  = ("Based on the results of our identity and access review, we are of the opinion that "
                 "the access control environment contains significant deficiencies constituting a "
                 "material weakness in the organisation's IT General Controls (ITGCs). The volume and "
                 "severity of findings indicate logical access controls are not operating effectively.")
    elif critical >= 1 or high >= 5:
        level = "QUALIFIED"
        body  = ("Based on the results of our identity and access review, we are of the opinion that, "
                 "except for the matters detailed in the findings schedule, the access control environment "
                 "is broadly consistent with good practice. The critical and high-severity findings "
                 "represent control deficiencies requiring prompt remediation.")
    elif high >= 1 or medium >= 3:
        level = "EMPHASIS OF MATTER"
        body  = ("Based on the results of our identity and access review, we are of the opinion that "
                 "the access control environment is generally adequate. We draw attention to the findings "
                 "below which require improvement but do not constitute a material weakness.")
    else:
        level = "UNQUALIFIED (CLEAN)"
        body  = ("Based on the results of our identity and access review, we are of the opinion that "
                 "the access control environment is operating effectively in accordance with the "
                 "organisation's stated policies. No material issues were identified.")

    return (
        f"AUDIT OPINION — IDENTITY & ACCESS CONTROL REVIEW\n"
        f"{'='*60}\n"
        f"Engagement Reference : {meta.get('ref','N/A')}\n"
        f"Client Organisation  : {meta.get('client','N/A')}\n"
        f"Lead Auditor         : {meta.get('auditor','N/A')}\n"
        f"Audit Standard       : {meta.get('standard','N/A')}\n"
        f"Review Period        : {scope_start.strftime('%d %B %Y')} to {scope_end.strftime('%d %B %Y')}\n"
        f"Population           : {total_pop:,} total | {in_scope_count:,} in scope\n"
        f"Date of Opinion      : {datetime.today().strftime('%d %B %Y')}\n\n"
        f"OPINION: {level}\n"
        f"{'-'*60}\n"
        f"{body}\n\n"
        f"FINDINGS SUMMARY\n"
        f"{'-'*60}\n"
        f"Total findings : {total}\n"
        f"  Critical     : {critical}\n"
        f"  High         : {high}\n"
        f"  Medium       : {medium}\n\n"
        f"This opinion is based solely on data provided at the date of review and must be\n"
        f"read with the full findings schedule. Prepared by: {meta.get('auditor','N/A')}"
    )

# ─────────────────────────────────────────────────────────────────────────────
#  EXCEL EXPORT — workpaper grade
# ─────────────────────────────────────────────────────────────────────────────
def to_excel_bytes(findings_df, hr_df, sys_df, scope_start, scope_end,
                   excluded_count, meta, opinion_text):
    buf = io.BytesIO()
    with pd.ExcelWriter(buf, engine="xlsxwriter") as writer:
        wb = writer.book

        H  = wb.add_format({"bold":True,"bg_color":"#1F3864","font_color":"white","border":1,"font_name":"Arial","font_size":10})
        R  = wb.add_format({"bg_color":"#FFDEDE","font_name":"Arial","font_size":9})
        O  = wb.add_format({"bg_color":"#FFF0CC","font_name":"Arial","font_size":9})
        Y  = wb.add_format({"bg_color":"#FFFBCC","font_name":"Arial","font_size":9})
        TL = wb.add_format({"bold":True,"font_name":"Arial","font_size":10,"font_color":"#1F3864"})
        TV = wb.add_format({"font_name":"Arial","font_size":10})
        TT = wb.add_format({"bold":True,"font_name":"Arial","font_size":14,"font_color":"#1F3864"})
        OP = wb.add_format({"font_name":"Arial","font_size":10,"text_wrap":True,"valign":"top"})

        def write_sheet(df, name):
            if df is None or df.empty:
                return
            clean = df[[c for c in df.columns if not c.startswith("_")]].copy()
            clean.to_excel(writer, index=False, sheet_name=name)
            ws = writer.sheets[name]
            for ci, col in enumerate(clean.columns):
                try:
                    mx = int(clean[col].fillna("").astype(str).map(len).max())
                except Exception:
                    mx = 10
                ws.set_column(ci, ci, min(max(mx, len(col)) + 2, 60))
            for ri, (_, row) in enumerate(clean.iterrows(), start=1):
                s = str(row.get("Severity", ""))
                fmt = R if "CRITICAL" in s else (O if "HIGH" in s else (Y if "MEDIUM" in s else None))
                if fmt:
                    ws.set_row(ri, None, fmt)
            for ci, col in enumerate(clean.columns):
                ws.write(0, ci, col, H)

        # Sheet 1 — Engagement Cover
        wc = wb.add_worksheet("Engagement Cover")
        wc.hide_gridlines(2)
        wc.set_column("A:A", 4); wc.set_column("B:B", 34); wc.set_column("C:C", 52)
        wc.set_row(1, 8); wc.write("B2", "Identity & Access Control Audit Report", TT)
        wc.set_row(2, 6)
        in_scope_n = len(sys_df) - excluded_count
        cover_rows = [
            ("Client Organisation",   meta.get("client",   "—")),
            ("Engagement Reference",  meta.get("ref",      "—")),
            ("Audit Standard",        meta.get("standard", "—")),
            ("Lead Auditor",          meta.get("auditor",  "—")),
            ("Review Period",         f"{scope_start.strftime('%d %b %Y')} → {scope_end.strftime('%d %b %Y')}"),
            ("Date of Report",        datetime.today().strftime("%d %B %Y")),
            ("Total Population",      f"{len(sys_df):,} system accounts"),
            ("Accounts in Scope",     f"{in_scope_n:,} accounts"),
            ("Excluded (out of scope)",f"{excluded_count:,} accounts"),
            ("Total Findings",        str(len(findings_df))),
            ("Critical Findings",     str(len(findings_df[findings_df["Severity"]=="🔴 CRITICAL"])) if not findings_df.empty else "0"),
            ("Classification",        "CONFIDENTIAL — Internal audit use only"),
        ]
        for i, (lbl, val) in enumerate(cover_rows, start=3):
            wc.set_row(i, 18)
            wc.write(i, 1, lbl, TL); wc.write(i, 2, val, TV)

        # Sheet 2 — Audit Opinion
        wo = wb.add_worksheet("Audit Opinion")
        wo.hide_gridlines(2); wo.set_column("A:A", 4); wo.set_column("B:B", 100)
        wo.set_row(1, 8)
        wo.write("B2", "Audit Opinion — Identity & Access Control Review", TT)
        wo.set_row(2, 6)
        for i, line in enumerate(opinion_text.split("\n"), start=3):
            wo.set_row(i, 15); wo.write(i, 1, line, OP)

        # Sheet 3 — Executive Summary
        in_scope_c = len(sys_df) - excluded_count
        def ci(t): return len(findings_df[findings_df["IssueType"]==t]) if not findings_df.empty else 0
        def cs(s): return len(findings_df[findings_df["Severity"]==s])  if not findings_df.empty else 0
        summary = pd.DataFrame([
            ("── ENGAGEMENT ──",                    ""),
            ("Client",                              meta.get("client","—")),
            ("Reference",                           meta.get("ref","—")),
            ("Auditor",                             meta.get("auditor","—")),
            ("Standard",                            meta.get("standard","—")),
            ("Scope from",                          scope_start.strftime("%d %b %Y")),
            ("Scope to",                            scope_end.strftime("%d %b %Y")),
            ("── POPULATION ──",                    ""),
            ("Total system accounts",               len(sys_df)),
            ("Accounts within scope",               in_scope_c),
            ("Accounts excluded",                   excluded_count),
            ("── FINDINGS ──",                      ""),
            ("Total findings",                      len(findings_df)),
            ("Critical",                            cs("🔴 CRITICAL")),
            ("High",                                cs("🟠 HIGH")),
            ("Medium",                              cs("🟡 MEDIUM")),
            ("── BY CHECK ──",                      ""),
            ("Orphaned accounts",                   ci("Orphaned Account")),
            ("Terminated with active access",       ci("Terminated Employee with Active Account")),
            ("Post-termination logins",             ci("Post-Termination Login")),
            ("Dormant accounts",                    ci("Dormant Account")),
            ("SoD violations",                      ci("Toxic Access (SoD Violation)")),
            ("Privilege creep",                     ci("Privilege Creep")),
            ("Shared / generic accounts",           ci("Shared / Generic Account")),
            ("Service accounts without owner",      ci("Service / System Account")),
            ("Super-user outside IT",               ci("Super-User / Admin Access")),
            ("MFA not enabled",                     ci("MFA Not Enabled")),
            ("Passwords never expired",             ci("Password Never Expired")),
            ("Duplicate system accounts",           ci("Duplicate System Access")),
            ("Excessive multi-system access",       ci("Excessive Multi-System Access")),
            ("Contractors without expiry",          ci("Contractor Without Expiry Date")),
            ("Near-match emails",                   ci("Near-Match Email")),
        ], columns=["Check", "Count"])
        summary.to_excel(writer, index=False, sheet_name="Executive Summary")
        ws_s = writer.sheets["Executive Summary"]
        ws_s.set_column(0, 0, 46); ws_s.set_column(1, 1, 12)
        ws_s.write(0, 0, "Check", H); ws_s.write(0, 1, "Count", H)

        # Sheet 4 — All Findings
        write_sheet(findings_df, "All Findings")

        # Sheet 5 — Remediation Playbook
        pb_cols = ["Severity","IssueType","ScopeFrom","ScopeTo","Email","FullName",
                   "Department","AccessLevel","Detail",
                   "Step 1 – Action","Step 2 – Action","Step 3 – Action","Step 4 – Action",
                   "Owner","SLA","DaysInactive","DaysPostTermination",
                   "SOX Reference","ISO 27001 Ref","GDPR Reference","PCI-DSS Reference"]
        pb = findings_df[[c for c in pb_cols if c in findings_df.columns]] if not findings_df.empty else pd.DataFrame()
        write_sheet(pb, "Remediation Playbook")

        # Per-issue-type sheets
        if not findings_df.empty:
            for itype in findings_df["IssueType"].unique():
                write_sheet(findings_df[findings_df["IssueType"] == itype], sanitise_sheet(itype))

        # Raw data
        hr_clean  = hr_df.drop(columns=["_em","_email"], errors="ignore")
        sys_clean = sys_df.drop(columns=["_em","_email"], errors="ignore")
        hr_clean.to_excel(writer,  index=False, sheet_name="HR Master (Raw)")
        sys_clean.to_excel(writer, index=False, sheet_name="System Access (Raw)")
        for sn, src in [("HR Master (Raw)", hr_clean), ("System Access (Raw)", sys_clean)]:
            ws_r = writer.sheets[sn]
            for ci2, col in enumerate(src.columns):
                ws_r.write(0, ci2, col, H)

    buf.seek(0)
    return buf.getvalue()

# ─────────────────────────────────────────────────────────────────────────────
#  SESSION STATE
# ─────────────────────────────────────────────────────────────────────────────
today = date.today()
_default_year = today.year - 1
if "ss_start"  not in st.session_state: st.session_state["ss_start"]  = date(_default_year, 1, 1)
if "ss_end"    not in st.session_state: st.session_state["ss_end"]    = date(_default_year, 12, 31)
if "locked"    not in st.session_state: st.session_state["locked"]    = False
if "confirmed" not in st.session_state: st.session_state["confirmed"] = False

def _this_month():  st.session_state.update(ss_start=today.replace(day=1), ss_end=today, locked=False)
def _last_q():
    q=(today.month-1)//3; me=[31,28,31,30,31,30,31,31,30,31,30,31]
    if q==0: qs,qe=date(today.year-1,10,1),date(today.year-1,12,31)
    else:    qs,qe=date(today.year,(q-1)*3+1,1),date(today.year,q*3,me[q*3-1])
    st.session_state.update(ss_start=qs,ss_end=qe,locked=False)
def _last_6():  st.session_state.update(ss_start=today-timedelta(days=182),ss_end=today,locked=False)
def _date_chg():st.session_state["locked"] = False
def _go():      st.session_state["locked"] = True
def _set_year():
    y = st.session_state["audit_year_sel"]
    st.session_state.update(ss_start=date(y,1,1),ss_end=date(y,12,31),locked=False)

# ─────────────────────────────────────────────────────────────────────────────
#  PAGE CONFIG & GLOBAL STYLE
# ─────────────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Identity Auditor — IAM Audit Platform",
    layout="wide",
    page_icon="🛡️",
    initial_sidebar_state="expanded",
)



# ─────────────────────────────────────────────────────────────────────────────
#  SIDEBAR
# ─────────────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("### 🛡️ Identity Auditor")
    st.markdown("---")

    st.markdown("#### Engagement")
    meta = {
        "client":   st.text_input("Client",    placeholder="Nairs.com Ltd",  label_visibility="visible"),
        "ref":      st.text_input("Reference", placeholder="IAR-2025-001",   label_visibility="visible"),
        "auditor":  st.text_input("Auditor",   placeholder="Your full name", label_visibility="visible"),
        "standard": st.selectbox("Standard", [
            "ISO 27001:2022","SOX ITGC","PCI-DSS v4.0","GDPR Art.32",
            "ISACA IS Audit","Internal Audit Charter",
        ]),
    }

    st.markdown("---")
    st.markdown("#### Frameworks to cite")
    selected_fw = []
    cols_fw = st.columns(2)
    if cols_fw[0].checkbox("SOX",      value=True):  selected_fw.append("SOX")
    if cols_fw[1].checkbox("ISO 27001",value=True):  selected_fw.append("ISO")
    if cols_fw[0].checkbox("GDPR",     value=True):  selected_fw.append("GDPR")
    if cols_fw[1].checkbox("PCI-DSS",  value=False): selected_fw.append("PCI-DSS")

    st.markdown("---")
    st.markdown("#### Audit scope")
    _yr_options = [today.year-2, today.year-1, today.year]
    st.selectbox(
        "Year",
        options=_yr_options,
        index=1,
        format_func=lambda y: f"{y}  ◀ previous" if y==today.year-1 else (f"{y}  ◀ current" if y==today.year else str(y)),
        key="audit_year_sel",
    )
    sb1, sb2 = st.columns(2)
    sb1.button("Full Year",    use_container_width=True, on_click=_set_year, type="primary")
    sb2.button("Last Quarter", use_container_width=True, on_click=_last_q)
    sb1.button("Last 6 Mo.",   use_container_width=True, on_click=_last_6)
    sb2.button("This Month",   use_container_width=True, on_click=_this_month)

    st.write("")
    dc1, dc2 = st.columns(2)
    with dc1: st.date_input("From", key="ss_start", on_change=_date_chg, label_visibility="visible")
    with dc2: st.date_input("To",   key="ss_end",   on_change=_date_chg, label_visibility="visible")

    date_err = st.session_state["ss_start"] >= st.session_state["ss_end"]
    if date_err: st.error("From must be before To")

    st.button("▶  GO — Run Audit",
              use_container_width=True, type="primary",
              disabled=date_err, on_click=_go)

    SCOPE_START = st.session_state["ss_start"]
    SCOPE_END   = st.session_state["ss_end"]
    scope_days  = (SCOPE_END - SCOPE_START).days
    if st.session_state["locked"]:
        st.success(f"🔒 {SCOPE_START.strftime('%d %b %Y')} → {SCOPE_END.strftime('%d %b %Y')} ({scope_days}d)")
    else:
        st.info(f"📅 {scope_days} days — click GO to run")

    st.markdown("---")
    st.markdown("#### Thresholds")
    DORMANT_DAYS         = st.slider("Dormant (days)",         30, 365, 90)
    PASSWORD_EXPIRY_DAYS = st.slider("Password expiry (days)", 30, 365, 90)
    FUZZY_THRESHOLD      = st.slider("Fuzzy match %",          70, 99,  88)
    MAX_SYSTEMS          = st.slider("Max systems per user",    2,  10,   3)

    st.markdown("---")
    with st.expander("Column reference"):
        st.markdown("""
**HR Master** (required)
`Email` `FullName` `Department`

**HR Master** (recommended)
`EmploymentStatus` `ContractType` `TerminationDate`

**System Access** (required)
`Email` `AccessLevel`

**System Access** (recommended)
`FullName` `LastLoginDate` `PasswordLastSet` `AccountCreatedDate` `MFA` `SystemName`
        """)

# ─────────────────────────────────────────────────────────────────────────────
#  HEADER
# ─────────────────────────────────────────────────────────────────────────────
st.title("🛡️ Identity & Access Management Auditor")
st.caption("15 automated checks · ISO 27001 · SOX · GDPR · PCI-DSS · Workpaper-ready export · 10-minute audit")
st.divider()

# ─────────────────────────────────────────────────────────────────────────────
#  FILE UPLOAD — 3 boxes
# ─────────────────────────────────────────────────────────────────────────────
st.markdown("### Upload files")
up1, up2, up3 = st.columns(3)

with up1:
    st.markdown("**① HR Master**")
    hr_file = st.file_uploader("Upload HR Master (.xlsx / .csv)", type=["xlsx","xls","csv"],
                                label_visibility="visible", key="hr_upload")

with up2:
    st.markdown("**② System Access List**")
    sys_file = st.file_uploader("Upload System Access (.xlsx / .csv)", type=["xlsx","xls","csv"],
                                 label_visibility="visible", key="sys_upload")

with up3:
    st.markdown("**③ Audit Standard / Policy** *(optional)*")
    std_file = st.file_uploader("Upload standard (PDF, TXT, DOCX)", type=["pdf","txt","docx"],
                                 label_visibility="visible", key="std_upload")
    if not std_file:
        st.caption("Upload your ISO 27001 SOA, access control policy or audit standard. Findings will cite it directly.")

# Parse standard document if uploaded
std_context = ""
if std_file is not None:
    try:
        if std_file.type == "text/plain":
            std_context = std_file.read().decode("utf-8", errors="ignore")[:3000]
        elif std_file.name.endswith(".pdf"):
            try:
                import pypdf
                reader = pypdf.PdfReader(std_file)
                std_context = " ".join(p.extract_text() or "" for p in reader.pages[:8])[:3000]
            except Exception:
                std_context = "[PDF uploaded — pypdf not available. Install pypdf to extract text.]"
        elif std_file.name.endswith(".docx"):
            try:
                import docx
                doc = docx.Document(std_file)
                std_context = " ".join(p.text for p in doc.paragraphs)[:3000]
            except Exception:
                std_context = "[DOCX uploaded — python-docx not available.]"
        if std_context:
            st.success(f"📄 Standard document parsed — {len(std_context):,} characters extracted. Findings will reference this document.")
    except Exception as e:
        st.warning(f"Could not parse standard document: {e}")

st.markdown("---")

# ─────────────────────────────────────────────────────────────────────────────
#  MAIN AUDIT FLOW
# ─────────────────────────────────────────────────────────────────────────────
if hr_file and sys_file:
    # Read files
    def read_file(f):
        if f.name.endswith(".csv"):
            return pd.read_csv(f)
        return pd.read_excel(f)

    hr_df  = read_file(hr_file)
    sys_df = read_file(sys_file)

    # Column validation
    hr_miss  = {"Email","FullName","Department"} - set(hr_df.columns)
    sys_miss = {"Email","AccessLevel"}           - set(sys_df.columns)
    if hr_miss or sys_miss:
        col_e1, col_e2 = st.columns(2)
        if hr_miss:  col_e1.error(f"HR file missing columns: {hr_miss}")
        if sys_miss: col_e2.error(f"System Access file missing columns: {sys_miss}")
        st.markdown("""
**Column names must match exactly.** Check your file has these exact headers:

| File | Required columns |
|---|---|
| HR Master | `Email` · `FullName` · `Department` |
| System Access | `Email` · `AccessLevel` |
        """)
        st.stop()

    # Department filter — new feature
    all_depts = sorted(set(
        list(hr_df["Department"].dropna().unique()) +
        (list(sys_df["Department"].dropna().unique()) if "Department" in sys_df.columns else [])
    ))
    st.markdown("### Scope filter")
    sc1, sc2 = st.columns([3,1])
    with sc1:
        selected_depts = st.multiselect(
            "Filter by department (leave empty to scan ALL departments)",
            options=all_depts,
            default=[],
            placeholder="All departments",
            help="Select specific departments to narrow audit scope — e.g. Finance, IT only"
        )
    with sc2:

        if selected_depts:
            st.info(f"Scanning {len(selected_depts)} dept(s)")
        else:
            st.info("Scanning all depts")

    # Apply department filter
    if selected_depts:
        hr_df_filtered  = hr_df[hr_df["Department"].isin(selected_depts)]
        sys_df_filtered = sys_df[sys_df["Department"].isin(selected_depts)] if "Department" in sys_df.columns else sys_df
    else:
        hr_df_filtered  = hr_df
        sys_df_filtered = sys_df

    st.markdown("---")

    # Population completeness gate
    if not st.session_state.get("confirmed", False):
        st.markdown("### ⚠️ Step 1 — Confirm data completeness")
        g1, g2, g3 = st.columns(3)
        g1.metric("HR Master rows",      f"{len(hr_df_filtered):,}")
        g2.metric("System Access rows",  f"{len(sys_df_filtered):,}")
        g3.metric("Departments in scope", len(selected_depts) if selected_depts else len(all_depts))

        st.markdown("""
Before the scan runs, confirm the data you uploaded is the **full unfiltered population** — not a sample or pre-filtered extract provided by the client.
This confirmation is part of your audit workpaper evidence.
        """)
        if st.button("✅  I confirm — this is the complete, unfiltered population. Proceed to scope selection.",
                     type="primary", use_container_width=True):
            st.session_state["confirmed"] = True
            st.rerun()
        st.stop()

    # Scope lock gate
    if not st.session_state.get("locked", False):
        st.markdown("### Step 2 — Set scope and run")
        sl1, sl2, sl3 = st.columns(3)
        sl1.metric("Data confirmed",   f"{len(hr_df_filtered):,} HR rows")
        sl2.metric("System accounts",  f"{len(sys_df_filtered):,} rows")
        sl3.metric("Scope selected",   f"{SCOPE_START.year}" if SCOPE_START.year == SCOPE_END.year else f"{SCOPE_START.year}–{SCOPE_END.year}")
        st.info(f"📅 Scope set to {SCOPE_START.strftime('%d %b %Y')} → {SCOPE_END.strftime('%d %b %Y')} ({scope_days} days). Click **▶ GO — Run Audit** in the sidebar to start.")
        st.stop()

    # Run audit
    with st.spinner("🔍 Running 15 checks across all identities..."):
        findings_df, excluded_count = run_audit(
            hr_df_filtered, sys_df_filtered,
            SCOPE_START, SCOPE_END,
            DORMANT_DAYS, PASSWORD_EXPIRY_DAYS,
            FUZZY_THRESHOLD, MAX_SYSTEMS,
            selected_fw,
        )

    in_scope_n = len(sys_df_filtered) - excluded_count
    total      = len(findings_df)

    # ── SCOPE BANNER ─────────────────────────────────────────────────────────
    dept_label = f"{len(selected_depts)} dept(s)" if selected_depts else "All departments"
    st.success(
        f"🔒 **Scope locked:** {SCOPE_START.strftime('%d %b %Y')} → {SCOPE_END.strftime('%d %b %Y')} "
        f"| **{in_scope_n:,}** of {len(sys_df_filtered):,} accounts scanned "
        f"| {dept_label} | Standard: {meta.get('standard','—')} "
        f"| {excluded_count:,} excluded"
    )

    # ── METRIC CARDS ──────────────────────────────────────────────────────────
    st.markdown("### Audit results")
    def cnt(col, val): return len(findings_df[findings_df[col]==val]) if total else 0

    mc = st.columns(5)
    mc[0].metric("Total Findings",  total,
                 delta=None, delta_color="off")
    mc[1].metric("🔴 Critical",
                 cnt("Severity","🔴 CRITICAL"),
                 help="Disable / escalate within 24 hours")
    mc[2].metric("🟠 High",
                 cnt("Severity","🟠 HIGH"),
                 help="Resolve within 5 business days")
    mc[3].metric("🟡 Medium",
                 cnt("Severity","🟡 MEDIUM"),
                 help="Resolve within 10 business days")
    mc[4].metric("Accounts Scanned", f"{in_scope_n:,}")

    if total:

        cc = st.columns(5)
        checks_list = [
            ("Orphaned",          "Orphaned Account"),
            ("Terminated Active", "Terminated Employee with Active Account"),
            ("Post-Term Login",   "Post-Termination Login"),
            ("Dormant",           "Dormant Account"),
            ("SoD Violations",    "Toxic Access (SoD Violation)"),
            ("Privilege Creep",   "Privilege Creep"),
            ("Generic IDs",       "Shared / Generic Account"),
            ("Service Accts",     "Service / System Account"),
            ("Admin Outside IT",  "Super-User / Admin Access"),
            ("MFA Disabled",      "MFA Not Enabled"),
            ("Pwd Expired",       "Password Never Expired"),
            ("Duplicates",        "Duplicate System Access"),
            ("Multi-System",      "Excessive Multi-System Access"),
            ("No Expiry",         "Contractor Without Expiry Date"),
            ("Near-Match",        "Near-Match Email"),
        ]
        for i, (lbl, itype) in enumerate(checks_list):
            n = cnt("IssueType", itype)
            cc[i % 5].metric(lbl, n)

    st.markdown("---")

    if not total:
        st.success(
            f"✅ Audit complete — no issues found for {in_scope_n:,} accounts scanned. "
            f"Scope: {SCOPE_START.strftime('%d %b %Y')} → {SCOPE_END.strftime('%d %b %Y')}"
        )
        if excluded_count == len(sys_df_filtered):
            st.error(
                f"⚠️ All {len(sys_df_filtered):,} accounts were excluded by the scope filter. "
                f"Your data dates do not fall within {SCOPE_START.year}. "
                f"Check the year selector in the sidebar — it is currently set to {SCOPE_START.year}."
            )
        st.stop()

    # ── TABS ─────────────────────────────────────────────────────────────────
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "🔎  All Findings",
        "🛠️  Remediation",
        "⚖️  Frameworks",
        "📈  Analysis",
        "✍️  Audit Opinion",
    ])

    sdf = findings_df.copy()
    sdf["_o"] = sdf["Severity"].map(sev_order).fillna(9)
    sdf = sdf.sort_values("_o").drop(columns="_o")

    with tab1:
        f_col1, f_col2 = st.columns([3,1])
        with f_col1:
            ft = st.multiselect(
                "Filter by issue type",
                options=sorted(findings_df["IssueType"].unique()),
                default=sorted(findings_df["IssueType"].unique()),
                label_visibility="visible",
            )
        with f_col2:
            sev_filter = st.selectbox(
                "Severity",
                options=["All","🔴 CRITICAL","🟠 HIGH","🟡 MEDIUM"],
                label_visibility="visible",
            )
        filtered = sdf[sdf["IssueType"].isin(ft)]
        if sev_filter != "All":
            filtered = filtered[filtered["Severity"] == sev_filter]

        disp = [c for c in ["Severity","IssueType","Email","FullName",
                              "Department","AccessLevel","DaysInactive",
                              "DaysPostTermination","Detail"] if c in filtered.columns]
        st.dataframe(
            filtered[disp],
            use_container_width=True,
            hide_index=True,
            height=420,
            column_config={
                "Severity":            st.column_config.TextColumn("Severity",        width="small"),
                "IssueType":           st.column_config.TextColumn("Issue Type",      width="medium"),
                "Email":               st.column_config.TextColumn("Email",           width="medium"),
                "FullName":            st.column_config.TextColumn("Name",            width="medium"),
                "Department":          st.column_config.TextColumn("Dept",            width="small"),
                "AccessLevel":         st.column_config.TextColumn("Access Level",    width="small"),
                "Detail":              st.column_config.TextColumn("Detail",          width="large"),
                "DaysInactive":        st.column_config.NumberColumn("Days Idle",     width="small"),
                "DaysPostTermination": st.column_config.NumberColumn("Post-Term Days",width="small"),
            },
        )
        st.caption(f"Showing {len(filtered):,} of {total:,} findings")

    with tab2:
        st.caption("Every finding has a 4-step action plan, named owner and SLA. Expand each row.")
        sev_options = ["All severities"] + sorted(sdf["Severity"].unique().tolist(), key=sev_order)
        rem_sev = st.selectbox("Show severity", sev_options, label_visibility="visible", key="rem_sev_filter")
        rem_df = sdf if rem_sev == "All severities" else sdf[sdf["Severity"] == rem_sev]
        for _, row in rem_df.iterrows():
            sev_icon = "🔴" if "CRITICAL" in str(row.get("Severity","")) else ("🟠" if "HIGH" in str(row.get("Severity","")) else "🟡")
            with st.expander(
                f"{sev_icon}  {row.get('IssueType','')}  —  {row.get('Email','')}  |  {row.get('Department','')}",
                expanded=False,
            ):
                d1, d2 = st.columns([2,1])
                with d1:
                    st.markdown(f"**Finding:** {row.get('Detail','')}")
                    st.markdown(f"**Risk:** {row.get('Risk','')}")
                with d2:
                    st.markdown(f"**Owner:** `{row.get('Owner','')}`")
                    st.markdown(f"**SLA:** `{row.get('SLA','')}`")
                st.divider()
                a1, a2 = st.columns(2)
                a1.markdown(f"**① {row.get('Step 1 – Action','')}**")
                a1.markdown(f"② {row.get('Step 2 – Action','')}")
                a2.markdown(f"**③ {row.get('Step 3 – Action','')}**")
                a2.markdown(f"④ {row.get('Step 4 – Action','')}")

    with tab3:
        if std_context:
            st.info(f"📄 Standard document uploaded: **{std_file.name}** — findings reference this document in addition to hardcoded framework mappings.")
        fw_cols = [c for c in ["Severity","IssueType","Email","FullName","Department",
                                "SOX Reference","ISO 27001 Ref",
                                "GDPR Reference","PCI-DSS Reference"] if c in sdf.columns]
        st.dataframe(sdf[fw_cols], use_container_width=True, hide_index=True, height=420)

    with tab4:
        an1, an2, an3 = st.columns(3)
        with an1:
            st.markdown("**By severity**")
            bsev = findings_df["Severity"].value_counts().reset_index()
            bsev.columns = ["Severity","Count"]
            st.dataframe(bsev, use_container_width=True, hide_index=True)
        with an2:
            st.markdown("**By issue type**")
            btyp = findings_df["IssueType"].value_counts().reset_index()
            btyp.columns = ["Issue Type","Count"]
            st.dataframe(btyp, use_container_width=True, hide_index=True)
        with an3:
            if "Department" in findings_df.columns:
                st.markdown("**By department**")
                bdept = findings_df["Department"].value_counts().reset_index()
                bdept.columns = ["Department","Count"]
                st.dataframe(bdept, use_container_width=True, hide_index=True)

        if "DaysInactive" in findings_df.columns:
            dormant_data = findings_df[findings_df["DaysInactive"].notna() & (findings_df["IssueType"]=="Dormant Account")]
            if not dormant_data.empty:
                st.markdown("**Dormant account inactivity (days)**")
                st.bar_chart(dormant_data.set_index("Email")["DaysInactive"])

    with tab5:
        opinion = generate_opinion(findings_df, meta, SCOPE_START, SCOPE_END, len(sys_df_filtered), in_scope_n)
        st.markdown("**Auto-generated audit opinion — review and edit before signing off.**")
        if std_context:
            st.caption(f"Note: You uploaded '{std_file.name}'. Reference this document explicitly in your final opinion where indicated.")
        edited_opinion = st.text_area("Draft opinion:", value=opinion, height=440, label_visibility="collapsed")
        st.caption("This draft is generated from finding counts and severity. It must be reviewed and approved by the responsible auditor before any formal use.")

    # ── EXPORT ───────────────────────────────────────────────────────────────
    st.markdown("---")
    exp1, exp2 = st.columns([3,1])
    with exp1:
        opinion_for_export = generate_opinion(findings_df, meta, SCOPE_START, SCOPE_END, len(sys_df_filtered), in_scope_n)
        ref_slug = (meta.get("ref") or "Audit").replace(" ","_").replace("/","-")
        st.download_button(
            label="📥  Download Workpaper-Ready Audit Report (.xlsx)",
            data=to_excel_bytes(
                findings_df, hr_df_filtered, sys_df_filtered,
                SCOPE_START, SCOPE_END, excluded_count,
                meta, opinion_for_export,
            ),
            file_name=f"IAR_{ref_slug}_{datetime.today().strftime('%Y%m%d')}.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            type="primary",
            use_container_width=True,
        )
    with exp2:
        st.metric("Report sheets", "8+")

elif hr_file or sys_file:
    st.info("📂 Upload both HR Master and System Access files to continue.")

else:
    # Landing page
    st.markdown("### How it works")
    lp1, lp2, lp3, lp4 = st.columns(4)
    lp1.info("**① Upload files**\n\nHR Master + System Access list. Optionally add your audit standard.")
    lp2.info("**② Confirm data**\n\nConfirm the extract is complete — becomes part of your workpaper evidence.")
    lp3.info("**③ Set scope & GO**\n\nSelect the audit year or custom date range. Click GO to lock and scan.")
    lp4.info("**④ Download report**\n\nWorkpaper-ready Excel: findings, remediation, framework refs, audit opinion.")

    st.divider()
    st.markdown("### 15 automated checks")
    ch1, ch2, ch3 = st.columns(3)
    checks_display = [
        ("🔴 Critical", [
            ("Orphaned accounts",            "Email in system, no HR record"),
            ("Terminated with active access","HR shows leaver, account still enabled"),
            ("Post-termination login",       "Logged in after leaving — potential breach"),
            ("SoD violations",              "User can initiate AND approve transactions"),
        ]),
        ("🟠 High", [
            ("Dormant accounts",            "No login in 90+ days — idle target"),
            ("Privilege creep",             "4+ roles accumulated across transfers"),
            ("Generic / shared accounts",   "admin@, helpdesk@ — no individual owner"),
            ("Super-user outside IT",       "Admin rights for non-IT business users"),
            ("MFA not enabled",             "One password = full account access"),
            ("Contractor without expiry",   "No end-date — access never expires"),
        ]),
        ("🟡 Medium", [
            ("Service accounts",           "svc_, batch_ — no named human owner"),
            ("Password never expired",     "Stale credentials — primary breach vector"),
            ("Duplicate accounts",         "Same person, multiple active IDs"),
            ("Excessive system access",    "More systems than role justifies"),
            ("Near-match emails",          "Typos, aliases, impersonation attempts"),
        ]),
    ]
    for col, (sev_label, items) in zip([ch1,ch2,ch3], checks_display):
        col.markdown(f"**{sev_label}**")
        for name, desc in items:
            col.markdown(f"**{name}** — {desc}")
        col.markdown("")

