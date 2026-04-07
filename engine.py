"""80 — IAM Audit Tool engine. All audit logic lives here. Pages import from this file."""

import pandas as pd
from thefuzz import fuzz
import io, json, base64, re, random
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
    "RBAC Violation":                           {"SOX":"SOX ITGC AC-2 — Access provisioned beyond role entitlement","ISO_27001":"ISO 27001 A.5.15 — Access control / A.5.18 — Role-based access rights","GDPR":"GDPR Art.25 — Data protection by design / least privilege","PCI_DSS":"PCI-DSS v4.0 Req 7.2 — Least privilege access model"},
    "Unauthorised Privileged Account":          {"SOX":"SOX ITGC AC-3 — Privileged access without approval or documentation","ISO_27001":"ISO 27001 A.8.2 — Privileged access rights management","GDPR":"GDPR Art.32 — Appropriate technical controls for privileged access","PCI_DSS":"PCI-DSS v4.0 Req 7.2.4 — Quarterly review of privileged accounts"},
    "Privileged Account Review Overdue":        {"SOX":"SOX ITGC AC-2 — Periodic access review not completed","ISO_27001":"ISO 27001 A.8.2 — Privileged access rights / periodic review","GDPR":"GDPR Art.32 — Ongoing security measures","PCI_DSS":"PCI-DSS v4.0 Req 7.2.4 — Review privileged access quarterly"},
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
              max_systems, selected_fw, sod_override=None,
              rbac_matrix=None, registry_df=None):

    today_dt       = datetime.today()
    scope_start_dt = datetime.combine(scope_start, datetime.min.time())
    scope_end_dt   = datetime.combine(scope_end,   datetime.max.time())
    findings, excluded_count = [], 0

    # Apply SoD rules from uploaded SOA/policy document if provided
    # This means findings cite the CLIENT'S own policy, not hardcoded defaults
    active_sod = {**SOD_RULES}
    if sod_override:
        for dept, rules in sod_override.items():
            if dept in active_sod:
                active_sod[dept] = list(set(active_sod[dept] + rules))
            else:
                active_sod[dept] = rules

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
        # Logic:
        #   - No dates at all        → always include (suspicious)
        #   - Any date IN scope      → include
        #   - Account CREATED before scope but logged in DURING scope → include
        #   - Account created before scope, no login in scope → include if
        #     AccountCreatedDate predates scope (could be dormant — important finding)
        #   - All dates AFTER scope end → exclude (future data, wrong file)
        # This ensures forensic/historical audits catch all relevant accounts.
        has_any_date = any([last_login, pwd_set, acct_created])

        # Include if any date falls within scope
        date_in_scope = (
            in_scope(last_login,   scope_start_dt, scope_end_dt) or
            in_scope(pwd_set,      scope_start_dt, scope_end_dt) or
            in_scope(acct_created, scope_start_dt, scope_end_dt)
        )

        # Also include if account was CREATED before scope end
        # (active accounts that predate the audit period are valid subjects)
        account_predates_scope_end = (
            acct_created is not None and acct_created <= scope_end_dt
        )

        # Also include if last login was before scope end
        # (account was active up to or during the audit period)
        active_before_scope_end = (
            last_login is not None and last_login <= scope_end_dt
        )

        should_include = (
            not has_any_date or          # no dates = always include
            date_in_scope or             # any date in scope window
            account_predates_scope_end or # account existed before scope end
            active_before_scope_end       # account was used before scope end
        )

        # Exclude only if ALL dates are clearly AFTER the scope end
        # (this catches wrong-year data uploads)
        all_dates_after_scope = has_any_date and all([
            (last_login   is None or last_login   > scope_end_dt),
            (pwd_set      is None or pwd_set      > scope_end_dt),
            (acct_created is None or acct_created > scope_end_dt),
        ])

        if all_dates_after_scope:
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
        forbidden = active_sod.get(dept, [])
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

    # ── RBAC Matrix checks ───────────────────────────────────────────────────
    if rbac_matrix:
        rbac_findings = run_rbac_checks(sys_df, hr_df, rbac_matrix, selected_fw, today_dt)
        findings.extend(rbac_findings)

    # ── Privileged User Registry checks ──────────────────────────────────────
    if registry_df is not None:
        reg_findings = run_registry_checks(sys_df, hr_df, registry_df, selected_fw, today_dt)
        findings.extend(reg_findings)

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

        # Audit Sample sheet
        sample_export = generate_audit_sample(findings_df, 25)
        add_sample_sheet(writer, sample_export, wb, H, R, O, Y)

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
#  FEATURE 1: CLAUDE VISION OCR — extract system access data from images/PDFs
# ─────────────────────────────────────────────────────────────────────────────
def ocr_via_ai(uploaded_file):
    """
    Send an image or PDF screenshot to the AI for data extraction.
    Returns a DataFrame matching the system access schema, or None on failure.
    """
    import requests
    try:
        file_bytes = uploaded_file.read()
        b64        = base64.b64encode(file_bytes).decode("utf-8")
        fname      = uploaded_file.name.lower()
        media_type = "application/pdf" if fname.endswith(".pdf") else "image/png" if fname.endswith(".png") else "image/jpeg"

        prompt = """You are an IT audit assistant. The image shows a legacy system access report 
(could be a green-screen terminal, a PDF printout, or a screenshot).

Extract ALL user account rows you can see and return them as a JSON array.
Each object must have these exact keys (use null if not visible):
  Email, FullName, Department, AccessLevel, LastLoginDate, PasswordLastSet,
  AccountCreatedDate, MFA, SystemName, AccountStatus

Rules:
- Email: if no email shown, construct one from username as username@unknown.local
- AccessLevel: map role names to: Admin, DBAdmin, Finance, HR, CRM, Payroll, ReadOnly, Support
- Dates: format as YYYY-MM-DD
- MFA: Enabled or Disabled
- AccountStatus: Enabled or Disabled

Return ONLY the JSON array, no other text, no markdown fences."""

        response = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={"Content-Type": "application/json"},
            json={
                "model": "claude-sonnet-4-20250514",
                "max_tokens": 2000,
                "messages": [{
                    "role": "user",
                    "content": [
                        {"type": "image", "source": {"type": "base64", "media_type": media_type, "data": b64}},
                        {"type": "text",  "text": prompt}
                    ]
                }]
            }
        )
        if response.status_code != 200:
            return None, f"API error {response.status_code}: {response.text[:200]}"

        text = response.json()["content"][0]["text"].strip()
        text = re.sub(r"^```json|^```|```$", "", text.strip(), flags=re.MULTILINE).strip()
        rows = json.loads(text)
        df   = pd.DataFrame(rows)
        return df, None

    except json.JSONDecodeError as e:
        return None, f"Could not parse AI response as JSON: {e}"
    except Exception as e:
        return None, f"OCR failed: {e}"


# ─────────────────────────────────────────────────────────────────────────────
#  FEATURE 2: DYNAMIC SoD MATRIX — read from uploaded Excel
# ─────────────────────────────────────────────────────────────────────────────
def load_sod_matrix(uploaded_file):
    """
    Read a standalone SoD Matrix Excel file.
    Expects columns: Department, ForbiddenAccessLevels (comma-separated)
    Also accepts our SOA format which has a 'SoD Rules' sheet.
    Returns dict {dept: [forbidden_levels]} or empty dict.
    """
    try:
        uploaded_file.seek(0)
        xl = pd.ExcelFile(uploaded_file)
        sheet = None

        # Try to find the right sheet
        for name in xl.sheet_names:
            if any(k in name.lower() for k in ["sod", "segregation", "matrix", "rules"]):
                sheet = name
                break
        if sheet is None and xl.sheet_names:
            sheet = xl.sheet_names[0]

        df = pd.read_excel(uploaded_file, sheet_name=sheet)
        df.columns = df.columns.str.strip()

        # Try common column name patterns
        dept_col    = next((c for c in df.columns if "dept" in c.lower() or "department" in c.lower()), None)
        access_col  = next((c for c in df.columns if "forbidden" in c.lower() or "access" in c.lower() or "level" in c.lower()), None)

        if not dept_col or not access_col:
            return {}, f"Could not find Department and Forbidden columns. Found: {list(df.columns)}"

        rules = {}
        for _, row in df.iterrows():
            dept    = str(row[dept_col]).strip()
            raw     = str(row[access_col]).strip()
            if dept and dept.lower() not in ("nan","none",""):
                levels = [x.strip() for x in re.split(r"[,;/]", raw) if x.strip() and x.strip().lower() not in ("nan","none","")]
                if levels:
                    rules[dept] = levels
        return rules, None

    except Exception as e:
        return {}, str(e)


# ─────────────────────────────────────────────────────────────────────────────
#  FEATURE 3+5: CLAUDE API — professional audit memo + executive summary
# ─────────────────────────────────────────────────────────────────────────────
def generate_ai_opinion(findings_df, meta, scope_start, scope_end, total_pop, in_scope_count):
    """
    Use AI to write a professional audit memo.
    Falls back to the rule-based opinion if the API call fails.
    """
    import requests

    total    = len(findings_df)
    critical = len(findings_df[findings_df["Severity"] == "🔴 CRITICAL"]) if total else 0
    high     = len(findings_df[findings_df["Severity"] == "🟠 HIGH"])     if total else 0
    medium   = len(findings_df[findings_df["Severity"] == "🟡 MEDIUM"])   if total else 0
    error_rate = round((total / in_scope_count * 100), 1) if in_scope_count > 0 else 0

    # Top 3 most frequent issue types
    if total > 0:
        top3 = findings_df["IssueType"].value_counts().head(3).to_dict()
        top3_str = ", ".join(f"{k} ({v} findings)" for k,v in top3.items())
    else:
        top3_str = "No findings"

    # Department breakdown
    if total > 0 and "Department" in findings_df.columns:
        dept_breakdown = findings_df["Department"].value_counts().head(5).to_dict()
        dept_str = ", ".join(f"{k}: {v}" for k,v in dept_breakdown.items())
    else:
        dept_str = "Not available"

    prompt = f"""You are a Senior IT Auditor writing a professional audit memo for a board-level audience.

ENGAGEMENT DATA:
- Client: {meta.get('client', 'Nairs.com Ltd')}
- Engagement Reference: {meta.get('ref', 'N/A')}
- Lead Auditor: {meta.get('auditor', 'N/A')}
- Audit Standard: {meta.get('standard', 'ISO 27001:2022')}
- Review Period: {scope_start.strftime('%d %B %Y')} to {scope_end.strftime('%d %B %Y')}
- Total population tested: {in_scope_count:,} system accounts
- Total findings: {total}
- Critical findings: {critical}
- High findings: {high}
- Medium findings: {medium}
- Overall error rate: {error_rate}%
- Top 3 issue types: {top3_str}
- Findings by department: {dept_str}

Write a professional audit memo with exactly these three sections:

**SECTION 1 — EXECUTIVE SUMMARY** (2 paragraphs)
Describe the overall risk posture. Mention the error rate. Reference the most impactful finding types. 
Use language appropriate for a board-level or CISO audience.

**SECTION 2 — KEY FINDINGS BREAKDOWN** (bullet points)
Cover the top 3 most frequent finding types. For each one, state what was found, what the risk is, 
and what ISO 27001:2022 control applies. Keep each bullet to 2-3 sentences.

**SECTION 3 — FORMAL AUDIT OPINION**
Issue one of: "Adverse" (5+ Criticals), "Qualified" (any Critical or 5+ High), 
"Emphasis of Matter" (any High), or "Unqualified" (no Criticals or Highs).
Write a formal opinion paragraph in standard audit language. 
State the opinion clearly and explain what it means for the organisation.

Format your response in clean markdown that will render well in Streamlit.
Do not include any preamble — start directly with the first section heading.
Today's date: {datetime.today().strftime('%d %B %Y')}"""

    try:
        response = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={"Content-Type": "application/json"},
            json={
                "model": "claude-sonnet-4-20250514",
                "max_tokens": 1500,
                "messages": [{"role": "user", "content": prompt}]
            }
        )
        if response.status_code == 200:
            return response.json()["content"][0]["text"], True
        else:
            return None, False
    except Exception:
        return None, False


# ─────────────────────────────────────────────────────────────────────────────
#  FEATURE 4: EVIDENCE SAMPLER — 25-item audit sample for external auditors
# ─────────────────────────────────────────────────────────────────────────────
def generate_audit_sample(findings_df, sample_size=25):
    """
    Produces a prioritised sample of findings for external auditor review.
    Priority: Critical first → High → random Medium to fill to sample_size.
    Returns a DataFrame of sample_size rows (or fewer if not enough findings).
    """
    if findings_df.empty:
        return pd.DataFrame()

    critical = findings_df[findings_df["Severity"] == "🔴 CRITICAL"].copy()
    high     = findings_df[findings_df["Severity"] == "🟠 HIGH"].copy()
    medium   = findings_df[findings_df["Severity"] == "🟡 MEDIUM"].copy()

    sample = pd.DataFrame()

    # Take all Criticals first (up to sample_size)
    take_crit = min(len(critical), sample_size)
    if take_crit > 0:
        sample = pd.concat([sample, critical.head(take_crit)])

    # Fill with Highs
    remaining = sample_size - len(sample)
    if remaining > 0 and len(high) > 0:
        take_high = min(len(high), remaining)
        sample = pd.concat([sample, high.head(take_high)])

    # Fill remainder with random Mediums
    remaining = sample_size - len(sample)
    if remaining > 0 and len(medium) > 0:
        take_med = min(len(medium), remaining)
        sample = pd.concat([sample, medium.sample(take_med, random_state=42)])

    # Add sample metadata columns
    sample = sample.reset_index(drop=True)
    sample.insert(0, "Sample#",       range(1, len(sample)+1))
    sample.insert(1, "TestInstruction", sample["IssueType"].map({
        "Orphaned Account":                        "Verify email does not exist in current HR system. Confirm account is disabled or deleted.",
        "Terminated Employee with Active Account": "Confirm termination date in HR. Verify account was disabled within 24h per JML procedure.",
        "Post-Termination Login":                  "Pull AD login audit log. Confirm login timestamp vs termination date. Escalate to Legal.",
        "Toxic Access (SoD Violation)":            "Confirm current role from HR. Verify access level in live system. Request written CISO approval or escalate.",
        "Dormant Account":                         "Confirm last login date from system extract. Check with line manager if access is still required.",
        "MFA Not Enabled":                         "Log into identity portal. Confirm MFA status. Verify against MFA rollout register.",
        "Password Never Expired":                  "Confirm PasswordLastSet from AD. Verify against password policy requirement.",
        "Duplicate System Access":                 "Confirm both account IDs exist in live system. Identify primary account and request disable of duplicate.",
        "Contractor Without Expiry Date":          "Obtain contract from Procurement. Confirm end date. Set account expiry in system.",
        "Privilege Creep":                         "Pull full role history from IT. Confirm which roles are still needed with line manager.",
        "Shared / Generic Account":                "Identify all individuals using this account. Provision named accounts. Disable shared account.",
        "Service / System Account":                "Identify system/application using this account. Confirm named owner. Review permissions.",
        "Super-User / Admin Access":               "Request written CISO justification. Confirm in exception register. Downgrade if unjustified.",
        "Excessive Multi-System Access":           "List all systems. Send to line manager for recertification. Remove unconfirmed access.",
        "Near-Match Email":                        "Cross-check with HR. Contact employee directly. Confirm ownership or treat as orphaned.",
    }).fillna("Verify finding against source data and policy. Document evidence of testing."))
    sample.insert(2, "EvidenceRequired", "Screenshot of live system + HR record extract + written confirmation from system owner")
    sample.insert(3, "TestedBy",         "")
    sample.insert(4, "TestDate",         "")
    sample.insert(5, "TestResult",       "")
    sample.insert(6, "AuditorNote",      "")

    return sample


# ─────────────────────────────────────────────────────────────────────────────
#  FEATURE 4: Add Audit_Sample sheet to Excel export (helper)
# ─────────────────────────────────────────────────────────────────────────────
def add_sample_sheet(writer, sample_df, wb, H, R, O, Y):
    """Write the Audit_Sample_Request sheet into an open ExcelWriter."""
    if sample_df is None or sample_df.empty:
        return
    clean = sample_df[[c for c in sample_df.columns if not c.startswith("_")]].copy()
    clean.to_excel(writer, index=False, sheet_name="Audit_Sample_Request")
    ws = writer.sheets["Audit_Sample_Request"]

    # Column widths
    widths = {"Sample#":8,"TestInstruction":55,"EvidenceRequired":40,"TestedBy":18,
              "TestDate":14,"TestResult":16,"AuditorNote":36,
              "Severity":14,"IssueType":28,"Email":36,"FullName":24,"Department":18}
    for ci, col in enumerate(clean.columns):
        ws.set_column(ci, ci, widths.get(col, 16))

    # Header row
    for ci, col in enumerate(clean.columns):
        ws.write(0, ci, col, H)

    # Row colours by severity
    for ri, (_, row) in enumerate(clean.iterrows(), start=1):
        s = str(row.get("Severity",""))
        fmt = R if "CRITICAL" in s else (O if "HIGH" in s else (Y if "MEDIUM" in s else None))
        if fmt:
            ws.set_row(ri, None, fmt)



# ─────────────────────────────────────────────────────────────────────────────
#  RBAC MATRIX PARSER
# ─────────────────────────────────────────────────────────────────────────────
def load_rbac_matrix(uploaded_file):
    """
    Read an RBAC Matrix Excel file.
    Expected columns: JobTitle, System (optional), PermittedAccess
    Returns dict: {job_title: [permitted_access_levels]}
    Also accepts: {job_title: {system: permitted_access}}

    Example file:
      JobTitle          | System           | PermittedAccess
      Finance Manager   | SAP Finance      | Full Access
      Finance Manager   | Active Directory | Read Only
      Sales Executive   | CRM              | Full Access
    """
    try:
        uploaded_file.seek(0)
        df = pd.read_excel(uploaded_file)
        df.columns = df.columns.str.strip()

        # Flexible column detection
        title_col  = next((c for c in df.columns if any(k in c.lower() for k in
                           ["job","title","role","position","designation"])), None)
        access_col = next((c for c in df.columns if any(k in c.lower() for k in
                           ["permitted","access","level","entitlement","right"])), None)
        system_col = next((c for c in df.columns if any(k in c.lower() for k in
                           ["system","application","app","platform"])), None)

        if not title_col or not access_col:
            return {}, f"Could not detect JobTitle and PermittedAccess columns. Found: {list(df.columns)}"

        matrix = {}
        for _, row in df.iterrows():
            job   = str(row[title_col]).strip()
            perms = str(row[access_col]).strip()
            if job.lower() in ("nan","none","") or perms.lower() in ("nan","none",""):
                continue
            # Parse comma-separated permitted levels
            levels = [p.strip() for p in perms.split(",") if p.strip()]
            if job not in matrix:
                matrix[job] = []
            matrix[job].extend(levels)
            # Deduplicate
            matrix[job] = list(set(matrix[job]))

        return matrix, None

    except Exception as e:
        return {}, str(e)


# ─────────────────────────────────────────────────────────────────────────────
#  PRIVILEGED USER REGISTRY LOADER
# ─────────────────────────────────────────────────────────────────────────────
def load_privileged_registry(uploaded_file):
    """
    Read a Privileged User Registry Excel file.
    Expected columns: Email, AccessLevel, Owner, Justification,
                      ApprovedBy, LastReviewDate
    Returns a DataFrame of registered privileged accounts.

    Example file:
      Email                  | AccessLevel | Owner       | LastReviewDate
      john.smith@nairs.com   | Admin       | John Smith  | 2025-01-15
      svc.backup@nairs.com   | DBAdmin     | IT Manager  | 2024-06-01
    """
    try:
        uploaded_file.seek(0)
        df = pd.read_excel(uploaded_file)
        df.columns = df.columns.str.strip()

        # Flexible column detection
        email_col  = next((c for c in df.columns if "email" in c.lower() or
                           "account" in c.lower()), None)
        access_col = next((c for c in df.columns if any(k in c.lower() for k in
                           ["access","level","role","privilege"])), None)
        review_col = next((c for c in df.columns if any(k in c.lower() for k in
                           ["review","last","date","renewed"])), None)

        if not email_col:
            return None, f"Could not detect Email/Account column. Found: {list(df.columns)}"

        # Normalise email column
        df["_email_norm"] = df[email_col].str.strip().str.lower()

        # Parse review date if present
        if review_col:
            df["_review_date"] = pd.to_datetime(df[review_col], errors="coerce")
        else:
            df["_review_date"] = None

        return df, None

    except Exception as e:
        return None, str(e)


# ─────────────────────────────────────────────────────────────────────────────
#  RBAC CHECK — run against full system df
# ─────────────────────────────────────────────────────────────────────────────
def run_rbac_checks(sys_df, hr_df, rbac_matrix, selected_fw, today_dt):
    """
    Compare each account's actual access against what their job title
    permits in the RBAC Matrix. Returns list of finding dicts.
    """
    findings = []
    if not rbac_matrix or sys_df.empty or hr_df.empty:
        return findings

    hr = hr_df.copy()
    hr["_em"] = hr["Email"].str.strip().str.lower()
    hr = hr.drop_duplicates(subset="_em", keep="first")
    hr_lkp = hr.set_index("_em")

    sys = sys_df.copy()
    sys["_em"] = sys["Email"].str.strip().str.lower()

    for _, row in sys.iterrows():
        u_email  = str(row.get("Email","")).strip().lower()
        u_access = str(row.get("AccessLevel","")).strip()
        row_dict = row.to_dict()

        # Only check accounts that exist in HR
        if u_email not in set(hr["_em"]):
            continue

        hr_row   = hr_lkp.loc[u_email]
        job      = str(hr_row.get("JobTitle","")).strip()
        emp_stat = str(hr_row.get("EmploymentStatus","Active")).strip().lower()

        # Skip terminated employees — handled by other checks
        if emp_stat in ("terminated","resigned","inactive"):
            continue

        if not job or job.lower() in ("nan","none","unknown",""):
            continue

        # Find permitted access for this job title
        permitted = rbac_matrix.get(job, [])
        if not permitted:
            continue  # Job not in matrix — cannot assess

        # Parse actual access levels (comma-separated)
        actual_levels = [a.strip() for a in u_access.split(",") if a.strip()]

        # Check each actual level against permitted list
        violations = []
        for level in actual_levels:
            # Check if this level is permitted (case-insensitive partial match)
            is_permitted = any(
                level.lower() in p.lower() or p.lower() in level.lower()
                for p in permitted
            )
            if not is_permitted:
                violations.append(level)

        if violations:
            findings.append(make_finding(
                row_dict,
                "RBAC Violation",
                f"'{job}' is permitted {permitted} per RBAC Matrix but holds "
                f"'{', '.join(violations)}' — access exceeds role entitlement. "
                f"Actual access: '{u_access}'.",
                selected_fw=selected_fw,
            ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
#  PRIVILEGED USER REGISTRY CHECK
# ─────────────────────────────────────────────────────────────────────────────
def run_registry_checks(sys_df, hr_df, registry_df, selected_fw, today_dt):
    """
    Cross-reference every privileged account found in the system
    against the Privileged User Registry.
    Flags:
      - Privileged accounts NOT in the registry (unauthorised)
      - Registry entries whose review date is > 12 months ago (overdue)
    """
    findings = []
    if registry_df is None or sys_df.empty:
        return findings

    from datetime import timedelta
    REVIEW_THRESHOLD_DAYS = 365

    reg_emails  = set(registry_df["_email_norm"].dropna())
    sys = sys_df.copy()
    sys["_em"] = sys["Email"].str.strip().str.lower()

    # Build HR lookup for employment status
    hr = hr_df.copy()
    hr["_em"] = hr["Email"].str.strip().str.lower()
    hr = hr.drop_duplicates(subset="_em", keep="first")
    hr_em_set = set(hr["_em"])
    hr_lkp = hr.set_index("_em")

    checked_for_overdue = set()  # avoid duplicate overdue findings

    for _, row in sys.iterrows():
        u_email  = str(row.get("Email","")).strip().lower()
        u_access = str(row.get("AccessLevel","")).strip()
        u_name   = str(row.get("FullName", u_email)).strip()
        row_dict = row.to_dict()

        # Only check privileged accounts
        is_privileged = any(
            hr_kw.lower() in u_access.lower()
            for hr_kw in HIGH_RISK_ACCESS
        )
        if not is_privileged:
            continue

        # Skip terminated employees
        if u_email in hr_em_set:
            hr_row   = hr_lkp.loc[u_email]
            emp_stat = str(hr_row.get("EmploymentStatus","Active")).strip().lower()
            if emp_stat in ("terminated","resigned","inactive"):
                continue

        # Check 1: Is this account in the registry?
        if u_email not in reg_emails:
            findings.append(make_finding(
                row_dict,
                "Unauthorised Privileged Account",
                f"'{u_name}' holds privileged access '{u_access}' but does NOT appear "
                f"in the Privileged User Registry. No documented approval, justification "
                f"or named owner on record.",
                selected_fw=selected_fw,
            ))
        else:
            # Check 2: Is the review date current?
            reg_row = registry_df[registry_df["_email_norm"] == u_email].iloc[0]
            review_date = reg_row.get("_review_date")

            if u_email not in checked_for_overdue:
                checked_for_overdue.add(u_email)
                if review_date is not None and not pd.isna(review_date):
                    days_since = (today_dt - review_date).days
                    if days_since > REVIEW_THRESHOLD_DAYS:
                        findings.append(make_finding(
                            row_dict,
                            "Privileged Account Review Overdue",
                            f"'{u_name}' holds privileged access '{u_access}'. "
                            f"Last registry review was {days_since} days ago "
                            f"({review_date.strftime('%d %b %Y')}). "
                            f"Policy requires review every 12 months.",
                            selected_fw=selected_fw,
                        ))
                elif review_date is None or pd.isna(review_date):
                    findings.append(make_finding(
                        row_dict,
                        "Privileged Account Review Overdue",
                        f"'{u_name}' holds privileged access '{u_access}'. "
                        f"Privileged User Registry entry has no LastReviewDate recorded. "
                        f"Cannot confirm this account has ever been formally reviewed.",
                        selected_fw=selected_fw,
                    ))

    return findings

# ── Document parsing helpers ──────────────────────────────────────────────────

def extract_text(uploaded_file, max_chars=5000):
    """Extract text from PDF, DOCX, TXT or XLSX. Returns empty string on failure."""
    if uploaded_file is None:
        return ""
    name = uploaded_file.name.lower()
    try:
        if name.endswith(".txt"):
            return uploaded_file.read().decode("utf-8", errors="ignore")[:max_chars]
        elif name.endswith(".pdf"):
            try:
                import pypdf
                reader = pypdf.PdfReader(uploaded_file)
                text = " ".join(p.extract_text() or "" for p in reader.pages[:10])
                return text[:max_chars]
            except Exception:
                return "[PDF uploaded — install pypdf to extract content]"
        elif name.endswith(".docx"):
            try:
                import docx
                doc = docx.Document(uploaded_file)
                return " ".join(p.text for p in doc.paragraphs)[:max_chars]
            except Exception:
                return "[DOCX uploaded — install python-docx to extract content]"
        elif name.endswith((".xlsx",".xls")):
            df = pd.read_excel(uploaded_file, sheet_name=None)
            text_parts = []
            for sheet_name, sheet_df in df.items():
                text_parts.append(f"[Sheet: {sheet_name}]")
                text_parts.append(sheet_df.to_string(index=False))
            return " ".join(text_parts)[:max_chars]
        elif name.endswith(".csv"):
            df = pd.read_csv(uploaded_file)
            return df.to_string(index=False)[:max_chars]
    except Exception as e:
        return f"[Could not parse {uploaded_file.name}: {e}]"
    return ""

def detect_doc_type(f):
    """
    Auto-detect document type from filename.
    Returns one of: hr_master | system_access | soa | access_policy |
                    jml_procedure | risk_register | other
    """
    if f is None:
        return "other"
    name = f.name.lower()
    if any(k in name for k in ["hr_master","hr master","hrmaster","employee","staff_list","staff list","personnel"]):
        return "hr_master"
    if any(k in name for k in ["system_access","system access","access_list","access list","user_access","useraccess","sysaccess"]):
        return "system_access"
    if any(k in name for k in ["soa","statement_of_applicability","statement of applicability","annex_a","annex a"]):
        return "soa"
    if any(k in name for k in ["access_policy","access policy","access_control","access control policy"]):
        return "access_policy"
    if any(k in name for k in ["jml","joiner","mover","leaver","onboard","offboard","joinermover"]):
        return "jml_procedure"
    if any(k in name for k in ["risk_register","risk register","riskregister"]):
        return "risk_register"
    if any(k in name for k in ["iso","standard","policy","procedure","framework","gdpr","sox","pci"]):
        return "standard"
    return "other"

def parse_soa_sod_rules(soa_text):
    """
    Try to extract SoD rules from uploaded SOA/policy text.
    Returns a dict of {dept: [forbidden_access_levels]} or empty dict.
    """
    import re
    rules = {}
    # Look for patterns like "Finance: Admin, DBAdmin" or "Sales staff: Finance, Payroll"
    dept_keywords = ["Finance","IT","HR","Sales","Marketing","Operations","Procurement","Legal","Risk","Support"]
    access_keywords = ["Admin","Finance","Payroll","DBAdmin","HR","SysAdmin","FullControl","SuperAdmin","Root"]
    for dept in dept_keywords:
        pattern = rf"{dept}[^.\n]{{0,60}}({"|".join(access_keywords)})"
        matches = re.findall(pattern, soa_text, re.IGNORECASE)
        if matches:
            rules[dept] = list(set(matches))
    return rules

