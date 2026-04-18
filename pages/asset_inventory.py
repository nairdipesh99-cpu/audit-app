"""
asset_inventory.py — Asset Inventory & Access Map
Standalone page. No changes required to engine.py or tool.py.

Upload: Asset_Inventory.xlsx  (or .csv)

Required columns:
    AssetName, AssetType, AssetCriticality, AssetOwner,
    Email, FullName, Department, AccessLevel, EmploymentStatus,
    ContractType, LastReviewed, JMLEvent

Optional columns (exception tracking):
    ExceptionFlag, ExceptionReason, ExceptionApprovedBy, ExceptionReviewDate

AssetType values  : Server | Application | Legacy System | Database |
                    Cloud Service | Network Device
AssetCriticality  : CRITICAL | HIGH | MEDIUM | LOW
EmploymentStatus  : Active | Terminated | On Leave | Transferred
JMLEvent          : Joiner | Mover | Leaver | None
ExceptionFlag     : Yes | No | Pending
"""

import streamlit as st
import pandas as pd
import io
from datetime import date, datetime

try:
    from components import inject_css, render_header, render_sidebar_brand
    inject_css()
    render_header()
except Exception:
    pass

# ─────────────────────────────────────────────────────────────────────────────
#  CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

ASSET_CRITICALITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

ASSET_TYPE_CRITICALITY = {
    "Server":         "CRITICAL",
    "Database":       "CRITICAL",
    "Network Device": "HIGH",
    "Application":    "HIGH",
    "Legacy System":  "HIGH",
    "Cloud Service":  "MEDIUM",
}

SEVERITY_ICON = {
    "🔴 CRITICAL": 0,
    "🟠 HIGH":     1,
    "🟡 MEDIUM":   2,
}

TODAY = date.today()


# ─────────────────────────────────────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _parse_date(val):
    if val is None or (isinstance(val, float) and pd.isna(val)):
        return None
    try:
        return pd.to_datetime(str(val)).date()
    except Exception:
        return None


def _days_since(val):
    d = _parse_date(val)
    if d is None:
        return None
    return (TODAY - d).days


def _norm(val, default=""):
    if val is None or (isinstance(val, float) and pd.isna(val)):
        return default
    return str(val).strip()


def _criticality_color(crit):
    return {
        "CRITICAL": "🔴",
        "HIGH":     "🟠",
        "MEDIUM":   "🟡",
        "LOW":      "🟢",
    }.get(str(crit).upper(), "⚪")


def _exception_valid(row):
    """Return True if this row has a valid, unexpired approved exception."""
    flag     = _norm(row.get("ExceptionFlag", "")).upper()
    approved = _norm(row.get("ExceptionApprovedBy", ""))
    exp_date = _parse_date(row.get("ExceptionReviewDate"))
    if flag != "YES":
        return False
    if not approved or approved.lower() in ("nan", "none", ""):
        return False
    if exp_date is not None and exp_date < TODAY:
        return False   # expired
    return True


def _exception_expired(row):
    flag     = _norm(row.get("ExceptionFlag", "")).upper()
    exp_date = _parse_date(row.get("ExceptionReviewDate"))
    if flag != "YES":
        return False
    if exp_date is not None and exp_date < TODAY:
        return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
#  CORE AUDIT LOGIC
# ─────────────────────────────────────────────────────────────────────────────

def run_asset_audit(df: pd.DataFrame, dormant_days: int = 90) -> tuple:
    """
    Run all asset access checks.
    Returns (violations_df, exceptions_df, clean_df)
    """
    violations  = []
    exceptions  = []
    clean_rows  = []

    for _, row in df.iterrows():
        asset       = _norm(row.get("AssetName",        "Unknown Asset"))
        asset_type  = _norm(row.get("AssetType",        "Application"))
        criticality = _norm(row.get("AssetCriticality", "")).upper()
        if not criticality or criticality not in ("CRITICAL","HIGH","MEDIUM","LOW"):
            criticality = ASSET_TYPE_CRITICALITY.get(asset_type, "MEDIUM")

        asset_owner   = _norm(row.get("AssetOwner",        ""))
        email         = _norm(row.get("Email",             "")).lower()
        full_name     = _norm(row.get("FullName",          email))
        department    = _norm(row.get("Department",        "Unknown"))
        access_level  = _norm(row.get("AccessLevel",       "ReadOnly"))
        emp_status    = _norm(row.get("EmploymentStatus",  "Active")).lower()
        contract_type = _norm(row.get("ContractType",      "")).lower()
        jml_event     = _norm(row.get("JMLEvent",          "None"))
        last_reviewed = row.get("LastReviewed")
        exc_flag      = _norm(row.get("ExceptionFlag",     "No"))
        exc_reason    = _norm(row.get("ExceptionReason",   ""))
        exc_approved  = _norm(row.get("ExceptionApprovedBy",""))
        exc_rev_date  = row.get("ExceptionReviewDate")

        days_since_review = _days_since(last_reviewed)
        exc_exp_date_str  = str(_parse_date(exc_rev_date)) if _parse_date(exc_rev_date) else "No expiry set"

        issues = []   # list of (severity, check_name, detail, why_column)

        # ── CHECK 1: Terminated — access not removed ───────────────────────
        if emp_status in ("terminated","resigned","left","inactive","deprovisioned"):
            term_d = _parse_date(row.get("TerminationDate"))
            days_str = f" ({(TODAY - term_d).days} days ago)" if term_d else ""
            issues.append((
                "🔴 CRITICAL",
                "Access Not Removed — Leaver",
                f"{full_name} ({email}) left the organisation{days_str} but still has {access_level} access to {asset} [{asset_type} — {criticality}]. Offboarding failed.",
                "Access should have been revoked on the termination date as part of the JML offboarding procedure."
            ))

        # ── CHECK 2: Mover — access from old role not removed ─────────────
        if jml_event.lower() == "mover":
            issues.append((
                "🔴 CRITICAL",
                "Access Not Removed — Mover",
                f"{full_name} ({email}) has moved roles/departments but retains {access_level} access to {asset} [{asset_type} — {criticality}] from their previous position.",
                "On role change (Mover event), access from the previous role must be revoked within 5 business days per JML procedure."
            ))

        # ── CHECK 3: No access review in threshold days ───────────────────
        if days_since_review is not None and days_since_review > dormant_days:
            sev = "🔴 CRITICAL" if criticality == "CRITICAL" else "🟠 HIGH"
            issues.append((
                sev,
                "Access Review Overdue",
                f"Last review of {full_name}'s access to {asset} was {days_since_review} days ago (threshold: {dormant_days} days). Asset criticality: {criticality}.",
                "Periodic access reviews are required under ISO 27001 A.5.18 and PCI-DSS 7.2.4. Review frequency should match asset criticality."
            ))
        elif days_since_review is None:
            sev = "🔴 CRITICAL" if criticality == "CRITICAL" else "🟠 HIGH"
            issues.append((
                sev,
                "No Access Review on Record",
                f"No LastReviewed date recorded for {full_name}'s access to {asset} [{asset_type} — {criticality}].",
                "Access to this asset has never been formally reviewed. This is a control gap regardless of asset criticality."
            ))

        # ── CHECK 4: Critical asset — no named owner ──────────────────────
        if criticality == "CRITICAL" and (not asset_owner or asset_owner.lower() in ("nan","none","")):
            issues.append((
                "🔴 CRITICAL",
                "Critical Asset — No Named Owner",
                f"{asset} is classified CRITICAL but has no named AssetOwner. Accountability is broken.",
                "Every CRITICAL asset must have a named owner responsible for access approvals and periodic reviews."
            ))

        # ── CHECK 5: Contractor on CRITICAL asset — no exception review date
        if ("contractor" in contract_type or "vendor" in contract_type or "temp" in contract_type):
            if criticality == "CRITICAL":
                exp_d = _parse_date(exc_rev_date)
                if exp_d is None:
                    issues.append((
                        "🟠 HIGH",
                        "Contractor on Critical Asset — No Review Date",
                        f"{full_name} ({email}) is a contractor/vendor with {access_level} access to {asset} [CRITICAL]. No exception review date is set.",
                        "Third-party access to CRITICAL assets must be time-limited with a documented review date. ISO 27001 A.5.19 / PCI-DSS Req 8.6."
                    ))

        # ── CHECK 6: Exception flag YES but no approver ───────────────────
        if exc_flag.upper() == "YES" and (not exc_approved or exc_approved.lower() in ("nan","none","")):
            issues.append((
                "🟠 HIGH",
                "Exception Not Approved",
                f"{full_name}'s access to {asset} is marked as an exception but has no documented approver.",
                "All access exceptions must be formally approved by the CISO or Asset Owner with a written reason and review date."
            ))

        # ── CHECK 7: Exception expired ────────────────────────────────────
        if _exception_expired(row):
            issues.append((
                "🟠 HIGH",
                "Exception Expired — Access Requires Re-approval",
                f"The exception for {full_name}'s access to {asset} expired on {exc_exp_date_str}. Access is now unapproved.",
                "Expired exceptions must be re-evaluated. Either re-approve with a new review date or revoke access immediately."
            ))

        # ── CHECK 8: Joiner — access to CRITICAL asset on day one ─────────
        if jml_event.lower() == "joiner" and criticality == "CRITICAL":
            issues.append((
                "🟡 MEDIUM",
                "Joiner with Critical Asset Access",
                f"{full_name} ({email}) is a new joiner (Joiner event) with {access_level} access to {asset} [CRITICAL]. Confirm this is intentional.",
                "New joiners should not have access to CRITICAL assets without formal approval. Verify against their job role and provisioning request."
            ))

        # ── BUILD FINDING OR CLEAN ROW ─────────────────────────────────────
        if not issues:
            clean_rows.append(row.to_dict())
            continue

        for severity, check_name, detail, why in issues:
            base = {
                "Severity":           severity,
                "Check":              check_name,
                "AssetName":          asset,
                "AssetType":          asset_type,
                "AssetCriticality":   criticality,
                "AssetOwner":         asset_owner,
                "Email":              email,
                "FullName":           full_name,
                "Department":         department,
                "AccessLevel":        access_level,
                "EmploymentStatus":   _norm(row.get("EmploymentStatus","")).title(),
                "ContractType":       _norm(row.get("ContractType","")).title(),
                "JMLEvent":           jml_event,
                "LastReviewed":       str(_parse_date(last_reviewed)) if _parse_date(last_reviewed) else "Never",
                "DaysSinceReview":    days_since_review if days_since_review else "N/A",
                "Detail":             detail,
                "WHY":                why,
                "ExceptionFlag":      exc_flag.title(),
                "ExceptionReason":    exc_reason,
                "ExceptionApprovedBy":exc_approved,
                "ExceptionReviewDate":exc_exp_date_str,
                "ExceptionStatus":    (
                    "✅ Valid Exception"    if _exception_valid(row) else
                    "❌ Expired Exception"  if _exception_expired(row) else
                    "⚠️ Pending Approval"  if exc_flag.upper() == "PENDING" else
                    "No Exception"
                ),
            }

            if _exception_valid(row):
                exceptions.append(base)
            else:
                violations.append(base)

    violations_df = pd.DataFrame(violations) if violations else pd.DataFrame()
    exceptions_df = pd.DataFrame(exceptions) if exceptions else pd.DataFrame()
    clean_df      = pd.DataFrame(clean_rows)  if clean_rows  else pd.DataFrame()

    # Sort violations by severity
    if not violations_df.empty and "Severity" in violations_df.columns:
        violations_df["_sev_order"] = violations_df["Severity"].map(SEVERITY_ICON).fillna(9)
        violations_df = violations_df.sort_values("_sev_order").drop(columns="_sev_order")

    return violations_df, exceptions_df, clean_df


# ─────────────────────────────────────────────────────────────────────────────
#  CRITICAL USER MAP  (JML cross-system view)
# ─────────────────────────────────────────────────────────────────────────────

def build_critical_user_map(df: pd.DataFrame) -> pd.DataFrame:
    """
    One row per person. Shows every asset they have access to,
    how many CRITICAL assets, total systems, JML event, and
    WHY + Exception summary for flagged access.
    """
    if df.empty:
        return pd.DataFrame()

    records = []
    for email, grp in df.groupby(df["Email"].str.strip().str.lower()):
        full_name   = _norm(grp["FullName"].iloc[0])
        department  = _norm(grp["Department"].iloc[0])
        emp_status  = _norm(grp["EmploymentStatus"].iloc[0])
        contract    = _norm(grp["ContractType"].iloc[0])
        jml_event   = _norm(grp["JMLEvent"].iloc[0]) if "JMLEvent" in grp.columns else "None"

        assets_list     = grp["AssetName"].tolist()
        types_list      = grp["AssetType"].tolist() if "AssetType" in grp.columns else []
        crits_list      = grp["AssetCriticality"].tolist() if "AssetCriticality" in grp.columns else []
        access_list     = grp["AccessLevel"].tolist() if "AccessLevel" in grp.columns else []

        n_critical  = sum(1 for c in crits_list if str(c).upper() == "CRITICAL")
        n_high      = sum(1 for c in crits_list if str(c).upper() == "HIGH")
        n_total     = len(assets_list)

        # Exception summary
        exc_reasons = []
        for _, r in grp.iterrows():
            ef = _norm(r.get("ExceptionFlag","")).upper()
            er = _norm(r.get("ExceptionReason",""))
            ea = _norm(r.get("ExceptionApprovedBy",""))
            if ef == "YES" and er:
                exc_reasons.append(f"{_norm(r.get('AssetName','?'))}: {er} (approved by {ea})")

        # Risk flag
        is_leaver     = emp_status.lower() in ("terminated","resigned","left","inactive")
        is_mover      = jml_event.lower() == "mover"
        is_contractor = "contractor" in contract.lower() or "vendor" in contract.lower()

        risk_flag = (
            "🔴 LEAVER WITH ACCESS"       if is_leaver else
            "🔴 MOVER — STALE ACCESS"     if is_mover else
            "🟠 CONTRACTOR — MULTI-SYSTEM" if (is_contractor and n_total >= 3) else
            "🟠 HIGH EXPOSURE"            if n_critical >= 3 else
            "🟡 REVIEW REQUIRED"          if n_critical >= 1 else
            "🟢 STANDARD"
        )

        records.append({
            "Email":             email,
            "FullName":          full_name,
            "Department":        department,
            "EmploymentStatus":  emp_status.title(),
            "ContractType":      contract.title(),
            "JMLEvent":          jml_event,
            "TotalSystems":      n_total,
            "CriticalAssets":    n_critical,
            "HighAssets":        n_high,
            "AssetsAccess":      " | ".join(assets_list),
            "AssetTypes":        " | ".join(dict.fromkeys(types_list)),
            "AccessLevels":      " | ".join(dict.fromkeys(access_list)),
            "RiskFlag":          risk_flag,
            "WHY_Exception":     "; ".join(exc_reasons) if exc_reasons else "No exceptions on record",
        })

    result = pd.DataFrame(records)
    sev_order = {
        "🔴 LEAVER WITH ACCESS":       0,
        "🔴 MOVER — STALE ACCESS":     1,
        "🟠 CONTRACTOR — MULTI-SYSTEM":2,
        "🟠 HIGH EXPOSURE":            3,
        "🟡 REVIEW REQUIRED":          4,
        "🟢 STANDARD":                 5,
    }
    result["_ord"] = result["RiskFlag"].map(sev_order).fillna(9)
    result = result.sort_values(["_ord","CriticalAssets"], ascending=[True, False])
    return result.drop(columns="_ord")


# ─────────────────────────────────────────────────────────────────────────────
#  EXPORT
# ─────────────────────────────────────────────────────────────────────────────

def to_excel_export(df_raw, violations_df, exceptions_df, user_map_df):
    buf = io.BytesIO()
    with pd.ExcelWriter(buf, engine="xlsxwriter") as writer:
        wb = writer.book
        H  = wb.add_format({"bold":True,"bg_color":"#1F3864","font_color":"white",
                             "border":1,"font_name":"Arial","font_size":10})
        R  = wb.add_format({"bg_color":"#FFDEDE","font_name":"Arial","font_size":9})
        O  = wb.add_format({"bg_color":"#FFF0CC","font_name":"Arial","font_size":9})
        Y  = wb.add_format({"bg_color":"#FFFBCC","font_name":"Arial","font_size":9})
        G  = wb.add_format({"bg_color":"#E2EFDA","font_name":"Arial","font_size":9})
        N  = wb.add_format({"font_name":"Arial","font_size":9})

        def write_sheet(df, name):
            if df is None or df.empty:
                return
            df.to_excel(writer, index=False, sheet_name=name[:31])
            ws = writer.sheets[name[:31]]
            for ci, col in enumerate(df.columns):
                ws.write(0, ci, col, H)
                ws.set_column(ci, ci, max(14, len(str(col)) + 4))
            for ri, (_, row) in enumerate(df.iterrows(), start=1):
                sev = str(row.get("Severity",""))
                fmt = R if "CRITICAL" in sev else O if "HIGH" in sev else Y if "MEDIUM" in sev else N
                for ci, col in enumerate(df.columns):
                    try:
                        ws.write(ri, ci, str(row[col]) if not pd.isna(row[col]) else "", fmt)
                    except Exception:
                        ws.write(ri, ci, str(row.get(col, "")), fmt)

        write_sheet(violations_df, "Violations")
        write_sheet(exceptions_df, "Approved Exceptions")
        write_sheet(user_map_df,   "Critical User Map (JML)")
        write_sheet(df_raw,        "Raw Asset Inventory")

        # Asset summary per asset
        if not df_raw.empty and "AssetName" in df_raw.columns:
            summary = (
                df_raw.groupby(["AssetName","AssetType","AssetCriticality"])
                .agg(UserCount=("Email","nunique"))
                .reset_index()
                .sort_values("AssetCriticality", key=lambda s: s.map(ASSET_CRITICALITY_ORDER).fillna(9))
            )
            write_sheet(summary, "Asset Summary")

    buf.seek(0)
    return buf.getvalue()


# ─────────────────────────────────────────────────────────────────────────────
#  SAMPLE TEMPLATE
# ─────────────────────────────────────────────────────────────────────────────

def generate_sample_template():
    sample = pd.DataFrame([
        {
            "AssetName": "PayrollDB-PROD",      "AssetType": "Database",
            "AssetCriticality": "CRITICAL",     "AssetOwner": "john.ciso@acme.com",
            "Email": "alice.johnson@acme.com",  "FullName": "Alice Johnson",
            "Department": "Finance",            "AccessLevel": "Admin",
            "EmploymentStatus": "Active",       "ContractType": "Permanent",
            "JMLEvent": "None",                 "LastReviewed": "2024-06-01",
            "TerminationDate": "",
            "ExceptionFlag": "No",              "ExceptionReason": "",
            "ExceptionApprovedBy": "",          "ExceptionReviewDate": "",
        },
        {
            "AssetName": "CoreBanking-APP",     "AssetType": "Application",
            "AssetCriticality": "CRITICAL",     "AssetOwner": "john.ciso@acme.com",
            "Email": "mark.harris@acme.com",    "FullName": "Mark Harris",
            "Department": "Sales",              "AccessLevel": "ReadOnly",
            "EmploymentStatus": "Terminated",   "ContractType": "Permanent",
            "JMLEvent": "Leaver",               "LastReviewed": "2024-01-10",
            "TerminationDate": "2024-11-01",
            "ExceptionFlag": "No",              "ExceptionReason": "",
            "ExceptionApprovedBy": "",          "ExceptionReviewDate": "",
        },
        {
            "AssetName": "AD-Server-01",        "AssetType": "Server",
            "AssetCriticality": "CRITICAL",     "AssetOwner": "it.ops@acme.com",
            "Email": "kate.thomas@acme.com",    "FullName": "Kate Thomas",
            "Department": "IT",                 "AccessLevel": "Admin",
            "EmploymentStatus": "Active",       "ContractType": "Contractor",
            "JMLEvent": "None",                 "LastReviewed": "2024-03-15",
            "TerminationDate": "",
            "ExceptionFlag": "Yes",
            "ExceptionReason": "Business continuity — DevOps migration project requires continued access until Q2 completion.",
            "ExceptionApprovedBy": "CISO — J. Smith",
            "ExceptionReviewDate": "2025-06-30",
        },
        {
            "AssetName": "Salesforce-CRM",      "AssetType": "Application",
            "AssetCriticality": "HIGH",         "AssetOwner": "sales.ops@acme.com",
            "Email": "emily.davis@acme.com",    "FullName": "Emily Davis",
            "Department": "Finance",            "AccessLevel": "Finance",
            "EmploymentStatus": "Active",       "ContractType": "Permanent",
            "JMLEvent": "Mover",                "LastReviewed": "2024-09-01",
            "TerminationDate": "",
            "ExceptionFlag": "Pending",         "ExceptionReason": "Awaiting IT to remove old role",
            "ExceptionApprovedBy": "",          "ExceptionReviewDate": "",
        },
        {
            "AssetName": "LegacyERP-v2",        "AssetType": "Legacy System",
            "AssetCriticality": "HIGH",         "AssetOwner": "",
            "Email": "svc_batch@acme.com",      "FullName": "Batch Service Account",
            "Department": "IT",                 "AccessLevel": "Admin",
            "EmploymentStatus": "Active",       "ContractType": "Service Account",
            "JMLEvent": "None",                 "LastReviewed": "",
            "TerminationDate": "",
            "ExceptionFlag": "No",              "ExceptionReason": "",
            "ExceptionApprovedBy": "",          "ExceptionReviewDate": "",
        },
    ])
    buf = io.BytesIO()
    sample.to_excel(buf, index=False)
    buf.seek(0)
    return buf.getvalue()


# ─────────────────────────────────────────────────────────────────────────────
#  PAGE UI
# ─────────────────────────────────────────────────────────────────────────────

st.markdown("## 🗄️ Asset Inventory & Access Map")
st.caption(
    "Upload your Asset Inventory file to see who has access to what servers, applications, "
    "legacy systems, and databases — flagged by severity, JML event, and exception status."
)

# ── Sidebar ────────────────────────────────────────────────────────────────
with st.sidebar:
    try:
        render_sidebar_brand()
    except Exception:
        st.markdown("### 🛡️ IAM Audit Tool")
    st.divider()
    st.markdown("#### Asset Inventory Settings")
    review_threshold = st.slider("Access review threshold (days)", 30, 365, 90, 10,
                                 help="Flag access not reviewed within this many days.")
    min_systems = st.slider("Multi-system threshold", 2, 10, 3, 1,
                            help="Flag users with access to this many or more systems.")
    st.divider()
    st.markdown("#### Filter")
    filter_criticality = st.multiselect(
        "Asset Criticality",
        options=["CRITICAL","HIGH","MEDIUM","LOW"],
        default=["CRITICAL","HIGH","MEDIUM","LOW"],
    )
    filter_jml = st.multiselect(
        "JML Event",
        options=["Joiner","Mover","Leaver","None"],
        default=["Joiner","Mover","Leaver","None"],
    )

# ── Template download ──────────────────────────────────────────────────────
with st.expander("📥 Download sample Asset_Inventory template", expanded=False):
    st.caption(
        "Not sure of the format? Download the template, fill it in with your assets and "
        "user access data, then upload it below."
    )
    st.download_button(
        label="📥 Download Asset_Inventory_Template.xlsx",
        data=generate_sample_template(),
        file_name="Asset_Inventory_Template.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )

st.divider()

# ── Upload ─────────────────────────────────────────────────────────────────
uploaded = st.file_uploader(
    "Upload Asset_Inventory file",
    type=["xlsx","xls","csv"],
    label_visibility="collapsed",
    key="asset_upload",
)

if not uploaded:
    st.info(
        "📂 Upload your Asset Inventory file above to begin. "
        "Download the template above if you need the column format."
    )
    st.stop()

# ── Read file ──────────────────────────────────────────────────────────────
@st.cache_data(show_spinner="Reading asset inventory…")
def load_file(file_bytes, fname):
    import io as _io
    buf = _io.BytesIO(file_bytes)
    if fname.endswith(".csv"):
        return pd.read_csv(buf)
    return pd.read_excel(buf)

raw_df = load_file(uploaded.read(), uploaded.name)

# Required column check
required = {"AssetName","Email","AccessLevel"}
missing  = required - set(raw_df.columns)
if missing:
    st.error(f"Missing required columns: {missing}. Minimum required: AssetName, Email, AccessLevel.")
    st.stop()

# Fill optional columns with defaults
for col, default in [
    ("AssetType","Application"),("AssetCriticality","MEDIUM"),("AssetOwner",""),
    ("FullName",""),("Department","Unknown"),("EmploymentStatus","Active"),
    ("ContractType",""),("JMLEvent","None"),("LastReviewed",""),
    ("ExceptionFlag","No"),("ExceptionReason",""),
    ("ExceptionApprovedBy",""),("ExceptionReviewDate",""),
    ("TerminationDate",""),
]:
    if col not in raw_df.columns:
        raw_df[col] = default

# Apply sidebar filters
df = raw_df.copy()
if filter_criticality:
    df = df[df["AssetCriticality"].str.upper().isin([c.upper() for c in filter_criticality])]
if filter_jml:
    df = df[df["JMLEvent"].isin(filter_jml)]

# ── Run audit ──────────────────────────────────────────────────────────────
with st.spinner("Running asset access checks…"):
    violations_df, exceptions_df, clean_df = run_asset_audit(df, review_threshold)
    user_map_df = build_critical_user_map(df)

total_v   = len(violations_df)
total_exc = len(exceptions_df)
total_c   = len(clean_df)

crit_v = len(violations_df[violations_df["Severity"]=="🔴 CRITICAL"]) if not violations_df.empty else 0
high_v = len(violations_df[violations_df["Severity"]=="🟠 HIGH"])     if not violations_df.empty else 0
med_v  = len(violations_df[violations_df["Severity"]=="🟡 MEDIUM"])   if not violations_df.empty else 0

# ── Top metrics ────────────────────────────────────────────────────────────
st.divider()
st.markdown("### 📊 Asset Access Summary")

m1,m2,m3,m4,m5,m6 = st.columns(6)
m1.metric("Total records",      f"{len(df):,}")
m2.metric("🔴 Critical",         crit_v)
m3.metric("🟠 High",             high_v)
m4.metric("🟡 Medium",           med_v)
m5.metric("✅ Approved exceptions", total_exc)
m6.metric("✅ Clean records",    total_c)

# Asset criticality breakdown
if "AssetCriticality" in df.columns:
    st.divider()
    ac1, ac2, ac3, ac4 = st.columns(4)
    for col_m, crit_label in zip([ac1,ac2,ac3,ac4], ["CRITICAL","HIGH","MEDIUM","LOW"]):
        n = len(df[df["AssetCriticality"].str.upper() == crit_label]["AssetName"].unique())
        col_m.metric(f"{_criticality_color(crit_label)} {crit_label} assets", n)

st.divider()

# ── TABS ───────────────────────────────────────────────────────────────────
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "🚨  Violations",
    "🗺️  Asset Access Map",
    "👤  Critical User Map (JML)",
    "✅  Exceptions Register",
    "📥  Export",
])

# ── Tab 1: Violations ──────────────────────────────────────────────────────
with tab1:
    st.markdown("#### Access Control Violations")
    st.caption("All flagged records ordered by severity. Approved exceptions are excluded from this view.")

    if violations_df.empty:
        st.success("✅ No violations found across all assets.")
    else:
        # Filters
        f1, f2, f3 = st.columns([2,2,2])
        with f1:
            chk_filter = st.multiselect(
                "Check type", options=sorted(violations_df["Check"].unique()),
                default=sorted(violations_df["Check"].unique()), key="v_check"
            )
        with f2:
            sev_filter = st.selectbox("Severity", ["All","🔴 CRITICAL","🟠 HIGH","🟡 MEDIUM"], key="v_sev")
        with f3:
            asset_filter = st.selectbox(
                "Asset", ["All"] + sorted(violations_df["AssetName"].unique().tolist()), key="v_asset"
            )

        vdf = violations_df[violations_df["Check"].isin(chk_filter)]
        if sev_filter != "All":
            vdf = vdf[vdf["Severity"] == sev_filter]
        if asset_filter != "All":
            vdf = vdf[vdf["AssetName"] == asset_filter]

        st.caption(f"Showing {len(vdf):,} of {total_v:,} violations")

        disp_cols = [c for c in [
            "Severity","Check","AssetName","AssetType","AssetCriticality",
            "Email","FullName","Department","AccessLevel","EmploymentStatus",
            "JMLEvent","LastReviewed","ExceptionStatus"
        ] if c in vdf.columns]

        st.dataframe(
            vdf[disp_cols].reset_index(drop=True),
            use_container_width=True, hide_index=True,
            height=min(420, 45 + len(vdf) * 35),
            column_config={
                "Severity":         st.column_config.TextColumn("Severity",    width="small"),
                "Check":            st.column_config.TextColumn("Check",       width="medium"),
                "AssetName":        st.column_config.TextColumn("Asset",       width="medium"),
                "AssetType":        st.column_config.TextColumn("Type",        width="small"),
                "AssetCriticality": st.column_config.TextColumn("Criticality", width="small"),
                "Email":            st.column_config.TextColumn("Email",       width="medium"),
                "FullName":         st.column_config.TextColumn("Name",        width="small"),
                "Department":       st.column_config.TextColumn("Dept",        width="small"),
                "AccessLevel":      st.column_config.TextColumn("Access",      width="small"),
                "EmploymentStatus": st.column_config.TextColumn("HR Status",   width="small"),
                "JMLEvent":         st.column_config.TextColumn("JML",         width="small"),
                "LastReviewed":     st.column_config.TextColumn("Last Review", width="small"),
                "ExceptionStatus":  st.column_config.TextColumn("Exception",   width="medium"),
            }
        )

        st.markdown("#### Violation Details")
        st.caption("Expand each row to see the full detail, the WHY, and exception information.")

        for _, row in vdf.head(150).iterrows():
            ico   = "🔴" if "CRITICAL" in str(row.get("Severity","")) else ("🟠" if "HIGH" in str(row.get("Severity","")) else "🟡")
            label = f"{ico} {row.get('Check','')} — {row.get('Email','')} | {row.get('AssetName','')} [{row.get('AssetCriticality','')}]"
            with st.expander(label, expanded=False):
                c1, c2 = st.columns([2,1])
                with c1:
                    st.markdown(f"**Finding:** {row.get('Detail','')}")
                    st.markdown(f"**WHY this is flagged:** {row.get('WHY','')}")
                with c2:
                    st.markdown(f"**Asset type:** `{row.get('AssetType','')}`")
                    st.markdown(f"**Access level:** `{row.get('AccessLevel','')}`")
                    st.markdown(f"**JML Event:** `{row.get('JMLEvent','')}`")
                    st.markdown(f"**Last reviewed:** `{row.get('LastReviewed','')}`")
                st.divider()
                e1, e2, e3, e4 = st.columns(4)
                e1.markdown(f"**Exception Flag:** `{row.get('ExceptionFlag','')}`")
                e2.markdown(f"**Reason:** {row.get('ExceptionReason','—') or '—'}")
                e3.markdown(f"**Approved by:** {row.get('ExceptionApprovedBy','—') or '—'}")
                e4.markdown(f"**Review date:** `{row.get('ExceptionReviewDate','—')}`")

# ── Tab 2: Asset Access Map ────────────────────────────────────────────────
with tab2:
    st.markdown("#### Asset Access Map — Who Has Access to What")
    st.caption("Complete view of every person's access to every asset, sorted by asset criticality.")

    if df.empty:
        st.info("No data to display.")
    else:
        # Per-asset summary
        st.markdown("**Asset overview — user count and violation count per asset**")
        asset_summary = []
        for asset_name, grp in df.groupby("AssetName"):
            crit  = _norm(grp["AssetCriticality"].iloc[0]).upper()
            atype = _norm(grp["AssetType"].iloc[0])
            owner = _norm(grp["AssetOwner"].iloc[0]) if "AssetOwner" in grp.columns else ""
            n_users = grp["Email"].nunique()

            v_count = 0
            if not violations_df.empty and "AssetName" in violations_df.columns:
                v_count = len(violations_df[violations_df["AssetName"] == asset_name])

            asset_summary.append({
                "Criticality":  f"{_criticality_color(crit)} {crit}",
                "AssetName":    asset_name,
                "AssetType":    atype,
                "AssetOwner":   owner,
                "Users":        n_users,
                "Violations":   v_count,
                "RiskRating":   (
                    "🔴 High Risk"  if v_count >= 3 or (crit == "CRITICAL" and v_count >= 1) else
                    "🟠 Elevated"   if v_count >= 1 else
                    "🟢 Clean"
                ),
            })

        asset_sum_df = pd.DataFrame(asset_summary)
        asset_sum_df["_crit_order"] = asset_sum_df["Criticality"].apply(
            lambda x: ASSET_CRITICALITY_ORDER.get(x.split(" ")[-1], 9)
        )
        asset_sum_df = asset_sum_df.sort_values(["_crit_order","Violations"], ascending=[True,False])
        asset_sum_df = asset_sum_df.drop(columns="_crit_order")

        st.dataframe(
            asset_sum_df, use_container_width=True, hide_index=True,
            height=min(420, 45 + len(asset_sum_df) * 35),
            column_config={
                "Criticality": st.column_config.TextColumn("Criticality", width="small"),
                "AssetName":   st.column_config.TextColumn("Asset",       width="medium"),
                "AssetType":   st.column_config.TextColumn("Type",        width="small"),
                "AssetOwner":  st.column_config.TextColumn("Owner",       width="medium"),
                "Users":       st.column_config.NumberColumn("Users",     width="small"),
                "Violations":  st.column_config.NumberColumn("Violations",width="small"),
                "RiskRating":  st.column_config.TextColumn("Risk",        width="small"),
            }
        )

        st.divider()
        st.markdown("**Full access map — every user × every asset**")

        map_asset = st.selectbox(
            "Filter by asset (leave on All to see everything)",
            ["All"] + sorted(df["AssetName"].unique().tolist()),
            key="map_asset_filter"
        )

        map_df = df.copy() if map_asset == "All" else df[df["AssetName"] == map_asset]

        map_cols = [c for c in [
            "AssetName","AssetType","AssetCriticality","AssetOwner",
            "Email","FullName","Department","AccessLevel",
            "EmploymentStatus","JMLEvent","LastReviewed","ExceptionFlag"
        ] if c in map_df.columns]

        st.dataframe(
            map_df[map_cols].reset_index(drop=True),
            use_container_width=True, hide_index=True,
            height=min(480, 45 + len(map_df) * 35),
        )

# ── Tab 3: Critical User Map (JML) ────────────────────────────────────────
with tab3:
    st.markdown("#### Critical User Map — JML Cross-System View")
    st.caption(
        "One row per person. Shows every system they have access to, their JML status, "
        "how many critical assets they can reach, and the WHY & Exception column for flagged access."
    )

    if user_map_df.empty:
        st.info("No data to display.")
    else:
        # Filter controls
        uf1, uf2, uf3 = st.columns(3)
        with uf1:
            u_jml = st.multiselect(
                "JML Event", options=["Joiner","Mover","Leaver","None"],
                default=["Joiner","Mover","Leaver","None"], key="u_jml"
            )
        with uf2:
            u_risk = st.multiselect(
                "Risk Flag",
                options=sorted(user_map_df["RiskFlag"].unique().tolist()),
                default=sorted(user_map_df["RiskFlag"].unique().tolist()),
                key="u_risk"
            )
        with uf3:
            u_min_crit = st.number_input(
                "Min critical assets", min_value=0, max_value=20, value=0, step=1, key="u_min_crit"
            )

        udf = user_map_df[
            user_map_df["JMLEvent"].isin(u_jml) &
            user_map_df["RiskFlag"].isin(u_risk) &
            (user_map_df["CriticalAssets"] >= u_min_crit)
        ]

        # Summary metrics
        um1, um2, um3, um4 = st.columns(4)
        um1.metric("Total identities",       len(udf))
        um2.metric("🔴 Leavers with access", len(udf[udf["RiskFlag"].str.contains("LEAVER")]))
        um3.metric("🔴 Movers — stale access",len(udf[udf["RiskFlag"].str.contains("MOVER")]))
        um4.metric("🟠 High exposure",       len(udf[udf["CriticalAssets"] >= 3]))

        st.dataframe(
            udf.reset_index(drop=True),
            use_container_width=True, hide_index=True,
            height=min(480, 45 + len(udf) * 35),
            column_config={
                "Email":            st.column_config.TextColumn("Email",           width="medium"),
                "FullName":         st.column_config.TextColumn("Name",            width="small"),
                "Department":       st.column_config.TextColumn("Department",      width="small"),
                "EmploymentStatus": st.column_config.TextColumn("HR Status",       width="small"),
                "ContractType":     st.column_config.TextColumn("Contract",        width="small"),
                "JMLEvent":         st.column_config.TextColumn("JML",             width="small"),
                "TotalSystems":     st.column_config.NumberColumn("Total Systems", width="small"),
                "CriticalAssets":   st.column_config.NumberColumn("🔴 Critical",  width="small"),
                "HighAssets":       st.column_config.NumberColumn("🟠 High",      width="small"),
                "AssetsAccess":     st.column_config.TextColumn("Assets",          width="large"),
                "AssetTypes":       st.column_config.TextColumn("Types",           width="medium"),
                "AccessLevels":     st.column_config.TextColumn("Access Levels",   width="medium"),
                "RiskFlag":         st.column_config.TextColumn("Risk Flag",       width="medium"),
                "WHY_Exception":    st.column_config.TextColumn("WHY / Exception", width="large"),
            }
        )

        st.divider()
        st.markdown("#### Individual deep-dive")
        st.caption("Select a person to see their full asset footprint.")

        selected_email = st.selectbox(
            "Select identity",
            options=["— select —"] + udf["Email"].tolist(),
            key="u_deepdive"
        )

        if selected_email != "— select —":
            person_rows = df[df["Email"].str.strip().str.lower() == selected_email.lower()]
            if not person_rows.empty:
                pr = person_rows.iloc[0]
                d1, d2, d3 = st.columns(3)
                d1.markdown(f"**Name:** {_norm(pr.get('FullName',''))}")
                d1.markdown(f"**Department:** {_norm(pr.get('Department',''))}")
                d2.markdown(f"**HR Status:** {_norm(pr.get('EmploymentStatus',''))}")
                d2.markdown(f"**JML Event:** {_norm(pr.get('JMLEvent',''))}")
                d3.markdown(f"**Contract:** {_norm(pr.get('ContractType',''))}")
                d3.markdown(f"**Total systems:** {len(person_rows)}")

                st.markdown("**All assets this person has access to:**")
                person_cols = [c for c in [
                    "AssetName","AssetType","AssetCriticality","AccessLevel",
                    "LastReviewed","ExceptionFlag","ExceptionReason","ExceptionApprovedBy","ExceptionReviewDate"
                ] if c in person_rows.columns]
                st.dataframe(
                    person_rows[person_cols].reset_index(drop=True),
                    use_container_width=True, hide_index=True,
                )

# ── Tab 4: Exceptions Register ─────────────────────────────────────────────
with tab4:
    st.markdown("#### Exceptions Register — Approved & Pending")
    st.caption(
        "Access that has been formally approved as an exception. "
        "Valid exceptions are suppressed from the Violations tab. "
        "Expired exceptions are re-surfaced as violations automatically."
    )

    # Also show pending exceptions from raw data
    pending_df = df[
        df["ExceptionFlag"].str.strip().str.upper() == "PENDING"
    ].copy() if "ExceptionFlag" in df.columns else pd.DataFrame()

    e1, e2, e3 = st.columns(3)
    e1.metric("✅ Approved exceptions",  total_exc)
    e2.metric("⏳ Pending approval",     len(pending_df))
    e3.metric("❌ Expired exceptions",
              len(violations_df[violations_df["ExceptionStatus"] == "❌ Expired Exception"])
              if not violations_df.empty and "ExceptionStatus" in violations_df.columns else 0)

    if not exceptions_df.empty:
        st.markdown("**Approved exceptions — valid and unexpired**")
        exc_cols = [c for c in [
            "AssetName","AssetType","AssetCriticality","Email","FullName",
            "Department","AccessLevel","JMLEvent","Check",
            "ExceptionReason","ExceptionApprovedBy","ExceptionReviewDate","ExceptionStatus"
        ] if c in exceptions_df.columns]
        st.dataframe(
            exceptions_df[exc_cols].reset_index(drop=True),
            use_container_width=True, hide_index=True,
            height=min(380, 45 + len(exceptions_df) * 35),
            column_config={
                "ExceptionReason":    st.column_config.TextColumn("Reason",       width="large"),
                "ExceptionApprovedBy":st.column_config.TextColumn("Approved By",  width="medium"),
                "ExceptionReviewDate":st.column_config.TextColumn("Review Date",  width="small"),
                "ExceptionStatus":    st.column_config.TextColumn("Status",       width="medium"),
            }
        )
    else:
        st.info("No approved exceptions on record.")

    if not pending_df.empty:
        st.divider()
        st.markdown("**⏳ Pending exceptions — awaiting approval**")
        pend_cols = [c for c in [
            "AssetName","AssetType","AssetCriticality","Email","FullName",
            "Department","AccessLevel","ExceptionReason","ExceptionApprovedBy"
        ] if c in pending_df.columns]
        st.dataframe(
            pending_df[pend_cols].reset_index(drop=True),
            use_container_width=True, hide_index=True,
        )

# ── Tab 5: Export ──────────────────────────────────────────────────────────
with tab5:
    st.markdown("#### Export Asset Inventory Report")
    st.caption(
        "Exports 5 sheets: Violations, Approved Exceptions, Critical User Map (JML), "
        "Asset Summary, and Raw Asset Inventory."
    )

    export_data = to_excel_export(raw_df, violations_df, exceptions_df, user_map_df)
    st.download_button(
        label="📥 Download Asset Inventory Report (.xlsx)",
        data=export_data,
        file_name=f"Asset_Inventory_Report_{datetime.today().strftime('%Y%m%d')}.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        type="primary",
        use_container_width=True,
    )

    st.divider()
    st.markdown("**What each sheet contains:**")
    sheets = [
        ("Violations",             "All flagged access records sorted by severity with WHY column and exception status"),
        ("Approved Exceptions",    "All access records with a valid, unexpired approved exception"),
        ("Critical User Map (JML)","One row per person — all assets, JML event, risk flag, WHY & Exception column"),
        ("Asset Summary",          "One row per asset — user count, violation count, criticality"),
        ("Raw Asset Inventory",    "The original uploaded data unmodified"),
    ]
    for sheet, desc in sheets:
        st.markdown(f"**{sheet}** — {desc}")
