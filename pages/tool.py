"""80 — IAM Audit Tool | Use the Tool page"""

import streamlit as st
import pandas as pd
import io
from datetime import datetime, date, timedelta
from engine import (
    run_audit, generate_opinion, generate_ai_opinion,
    to_excel_bytes, generate_audit_sample, add_sample_sheet,
    ocr_via_ai, load_sod_matrix,
    extract_text, detect_doc_type, parse_soa_sod_rules,
    load_rbac_matrix, load_privileged_registry,
    run_rbac_checks, run_registry_checks,
    sev_order, SOD_RULES,
)
from components import inject_css, render_header, render_sidebar_brand, led_status_bar, led_dot
from irs import compute_irs, build_risk_register, irs_summary_stats

# ─────────────────────────────────────────────────────────────────────────────
#  SESSION STATE
# ─────────────────────────────────────────────────────────────────────────────
today = date.today()
_default_year = today.year - 1
if "ss_start"  not in st.session_state: st.session_state["ss_start"]  = date(_default_year, 1, 1)
if "ss_end"    not in st.session_state: st.session_state["ss_end"]    = date(_default_year, 12, 31)
if "locked"    not in st.session_state: st.session_state["locked"]    = False
if "confirmed" not in st.session_state: st.session_state["confirmed"] = False

# Module-level defaults — prevent NameError if referenced before sidebar renders
SCOPE_START          = st.session_state["ss_start"]
SCOPE_END            = st.session_state["ss_end"]
DORMANT_DAYS         = 90
PASSWORD_EXPIRY_DAYS = 90
FUZZY_THRESHOLD      = 88
MAX_SYSTEMS          = 3
selected_fw          = ["SOX", "ISO", "GDPR"]

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
#  DOCUMENT PARSER
# ─────────────────────────────────────────────────────────────────────────────
def extract_text(uploaded_file, max_chars=5000):
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
    if any(k in name for k in ["rbac","role_matrix","role matrix","access_matrix","access matrix","entitlement","permission_matrix"]):
        return "rbac_matrix"
    if any(k in name for k in ["privileged","priv_register","priv register","admin_register","privileged_user","privileged user registry"]):
        return "privileged_registry"
    if any(k in name for k in ["ual","active_directory","active directory","ad_export","user_access_list","useraccesslist"]):
        return "system_access"
    if any(k in name for k in ["iso","standard","policy","procedure","framework","gdpr","sox","pci"]):
        return "standard"
    return "other"

def parse_soa_sod_rules(soa_text):
    import re
    rules = {}
    dept_keywords   = ["Finance","IT","HR","Sales","Marketing","Operations","Procurement","Legal","Risk","Support"]
    access_keywords = ["Admin","Finance","Payroll","DBAdmin","HR","SysAdmin","FullControl","SuperAdmin","Root"]
    for dept in dept_keywords:
        pattern = rf"{dept}[^.\n]{{0,60}}({'|'.join(access_keywords)})"
        matches = re.findall(pattern, soa_text, re.IGNORECASE)
        if matches:
            rules[dept] = list(set(matches))
    return rules


# ─────────────────────────────────────────────────────────────────────────────
#  SIDEBAR
# ─────────────────────────────────────────────────────────────────────────────
with st.sidebar:
    render_sidebar_brand()
    st.divider()

    st.markdown("#### Engagement details")
    _client  = st.text_input("Client",    placeholder="Nairs.com Ltd",  key="meta_client")
    _ref     = st.text_input("Reference", placeholder="IAR-2025-001",  key="meta_ref")
    _auditor = st.text_input("Auditor",   placeholder="Your full name", key="meta_auditor")
    _std     = st.selectbox("Audit standard", [
        "ISO 27001:2022","SOX ITGC","PCI-DSS v4.0","GDPR Art.32",
        "ISACA IS Audit","Internal Audit Charter",
    ], key="meta_standard")
    meta = {
        "client":   _client   or "Not specified",
        "ref":      _ref      or "Not specified",
        "auditor":  _auditor  or "Not specified",
        "standard": _std,
    }

    st.divider()
    st.markdown("#### Compliance frameworks")
    selected_fw = []
    c1,c2 = st.columns(2)
    if c1.checkbox("SOX",       value=True):  selected_fw.append("SOX")
    if c2.checkbox("ISO 27001", value=True):  selected_fw.append("ISO")
    if c1.checkbox("GDPR",      value=True):  selected_fw.append("GDPR")
    if c2.checkbox("PCI-DSS",   value=False): selected_fw.append("PCI-DSS")

    st.divider()
    st.markdown("#### Audit parameters")
    DORMANT_DAYS         = st.slider("Dormant threshold (days)",    30, 365, 90, 10)
    PASSWORD_EXPIRY_DAYS = st.slider("Password expiry (days)",      30, 365, 90, 10)
    FUZZY_THRESHOLD      = st.slider("Fuzzy match threshold",       70, 100, 88,  1)
    MAX_SYSTEMS          = st.slider("Max systems per user",         1,  10,  3,  1)

    st.divider()
    st.markdown("#### Audit scope")
    year_opts = list(range(today.year, today.year - 6, -1))
    st.selectbox("Quick year", year_opts, key="audit_year_sel", on_change=_set_year, index=1)
    bc1,bc2,bc3 = st.columns(3)
    bc1.button("This month", on_click=_this_month, use_container_width=True)
    bc2.button("Last Q",     on_click=_last_q,     use_container_width=True)
    bc3.button("Last 6m",    on_click=_last_6,     use_container_width=True)
    SCOPE_START = st.date_input("From", value=st.session_state["ss_start"],
                                key="di_start", on_change=_date_chg)
    SCOPE_END   = st.date_input("To",   value=st.session_state["ss_end"],
                                key="di_end",   on_change=_date_chg)
    st.button("▶  GO", on_click=_go, type="primary", use_container_width=True)
    if st.session_state.get("locked"):
        st.success(f"Locked: {SCOPE_START.strftime('%d %b %Y')} → {SCOPE_END.strftime('%d %b %Y')}")


# ─────────────────────────────────────────────────────────────────────────────
#  PAGE HEADER
# ─────────────────────────────────────────────────────────────────────────────
inject_css()
render_header()
led_status_bar()

st.markdown("## 🔍 IAM Audit Tool")
st.caption("Upload HR Master + System Access files to run a full Identity & Access audit.")

# ─────────────────────────────────────────────────────────────────────────────
#  FILE UPLOAD
# ─────────────────────────────────────────────────────────────────────────────
uploaded_files = st.file_uploader(
    "Upload files — HR Master, System Access, SOA, RBAC Matrix, Privileged Registry, policy documents",
    type=["xlsx","xls","csv","pdf","docx","txt"],
    accept_multiple_files=True,
    key="main_uploader",
)

hr_file  = None
sys_file = None
doc_files = []
rbac_file = None
registry_file = None

if uploaded_files:
    auto_hr  = next((f for f in uploaded_files if detect_doc_type(f) == "hr_master"),     None)
    auto_sys = next((f for f in uploaded_files if detect_doc_type(f) == "system_access"),  None)

    remaining = [f for f in uploaded_files if f not in [auto_hr, auto_sys]]

    uc1, uc2 = st.columns(2)
    with uc1:
        hr_opts  = ["— auto-detected —"] + [f.name for f in uploaded_files]
        hr_sel   = st.selectbox("HR Master file",     hr_opts,
                                index=hr_opts.index(auto_hr.name)  if auto_hr  else 0,
                                key="hr_sel")
        hr_file  = next((f for f in uploaded_files if f.name == hr_sel),  auto_hr)
    with uc2:
        sys_opts = ["— auto-detected —"] + [f.name for f in uploaded_files]
        sys_sel  = st.selectbox("System Access file", sys_opts,
                                index=sys_opts.index(auto_sys.name) if auto_sys else 0,
                                key="sys_sel")
        sys_file = next((f for f in uploaded_files if f.name == sys_sel), auto_sys)

    # OCR fallback for images / scanned PDFs
    ocr_files = [f for f in uploaded_files if f.name.lower().endswith((".png",".jpg",".jpeg"))]
    if ocr_files and not sys_file:
        st.info(f"🖼️ Image file detected: {ocr_files[0].name}. Attempting OCR extraction…")
        ocr_df, ocr_err = ocr_via_ai(ocr_files[0])
        if ocr_df is not None:
            st.success(f"OCR extracted {len(ocr_df)} rows from {ocr_files[0].name}")
            sys_file_ocr = io.BytesIO()
            ocr_df.to_csv(sys_file_ocr, index=False)
            sys_file_ocr.name = "ocr_system_access.csv"
            sys_file_ocr.seek(0)
            sys_file = sys_file_ocr
        else:
            st.warning(f"OCR failed: {ocr_err}")

    doc_files     = [(f, detect_doc_type(f)) for f in uploaded_files
                     if f not in [hr_file, sys_file] and detect_doc_type(f) not in ("hr_master","system_access")]
    rbac_file     = next((f for f,t in doc_files if t == "rbac_matrix"),        None)
    registry_file = next((f for f,t in doc_files if t == "privileged_registry"),None)

    if doc_files:
        st.caption(f"📄 Additional documents detected: {', '.join(f.name for f,_ in doc_files)}")

soa_sod_extra = {}
rbac_matrix   = None
registry_df   = None

if doc_files:
    for f, dtype in doc_files:
        f.seek(0)
        if dtype == "rbac_matrix" and rbac_file:
            rbac_file.seek(0)
            rbac_matrix = load_rbac_matrix(rbac_file)
            if rbac_matrix:
                st.caption(f"✅ RBAC Matrix loaded — {len(rbac_matrix)} role definitions.")
        elif dtype == "privileged_registry" and registry_file:
            registry_file.seek(0)
            registry_df = load_privileged_registry(registry_file)
            if registry_df is not None:
                st.caption(f"✅ Privileged Registry loaded — {len(registry_df)} entries.")
        else:
            text = extract_text(f)
            if text:
                matrix_rules = load_sod_matrix(f) if dtype in ("soa","rbac_matrix") else {}
                if matrix_rules:
                    soa_sod_extra.update(matrix_rules)
                    extra = parse_soa_sod_rules(text)
                    if extra:
                        st.caption(f"Extracted {len(extra)} SoD rules from document text.")
                        soa_sod_extra.update(extra)
            else:
                st.caption(text or "No text extracted.")
            st.divider()

# ─────────────────────────────────────────────────────────────────────────────
#  MAIN AUDIT FLOW
# ─────────────────────────────────────────────────────────────────────────────
if hr_file and sys_file:
    def read_file(f):
        f.seek(0)
        if f.name.endswith(".csv"): return pd.read_csv(f)
        return pd.read_excel(f)

    hr_df  = read_file(hr_file)
    sys_df = read_file(sys_file)

    if "findings_cache" in st.session_state:
        del st.session_state["findings_cache"]
        del st.session_state["excluded_cache"]
        if "_last_cache_key" in st.session_state:
            del st.session_state["_last_cache_key"]

    hr_miss  = {"Email","FullName","Department"} - set(hr_df.columns)
    sys_miss = {"Email","AccessLevel"}           - set(sys_df.columns)
    if hr_miss or sys_miss:
        e1,e2 = st.columns(2)
        if hr_miss:  e1.error(f"HR Master missing columns: {hr_miss}")
        if sys_miss: e2.error(f"System Access missing columns: {sys_miss}")
        st.info("Required columns — HR Master: Email, FullName, Department | System Access: Email, AccessLevel")
        st.stop()

    all_depts = sorted(set(
        list(hr_df["Department"].dropna().unique()) +
        (list(sys_df["Department"].dropna().unique()) if "Department" in sys_df.columns else [])
    ))
    st.markdown("### Department scope")
    df1,df2 = st.columns([3,1])
    with df1:
        selected_depts = st.multiselect(
            "Filter by department — leave empty to scan ALL",
            options=all_depts, default=[],
            placeholder="All departments — no filter applied",
        )
    with df2:
        st.markdown("<br>", unsafe_allow_html=True)
        st.info(f"{'Selected: '+', '.join(selected_depts) if selected_depts else 'All departments'}")

    hr_df_f  = hr_df[hr_df["Department"].isin(selected_depts)] if selected_depts else hr_df
    sys_df_f = sys_df[sys_df["Department"].isin(selected_depts)] if (selected_depts and "Department" in sys_df.columns) else sys_df

    st.divider()

    if not st.session_state.get("confirmed", False):
        st.markdown("### ⚠️ Confirm data completeness")
        g1,g2,g3 = st.columns(3)
        g1.metric("HR Master rows",       f"{len(hr_df_f):,}")
        g2.metric("System Access rows",   f"{len(sys_df_f):,}")
        g3.metric("Policy docs uploaded", len(doc_files))
        st.markdown("""
Before the scan runs, confirm that the data you uploaded is the **complete, unfiltered population** —
not a sample or extract pre-filtered by the client.
        """)
        if st.button("✅  I confirm — this is the complete population. Proceed to scope & run.",
                     type="primary", use_container_width=True):
            st.session_state["confirmed"] = True
            st.rerun()
        st.stop()

    _cache_key = (
        getattr(hr_file,  "name","") + str(len(hr_df_f)) +
        getattr(sys_file, "name","") + str(len(sys_df_f)) +
        str(SCOPE_START) + str(SCOPE_END) +
        str(DORMANT_DAYS) + str(PASSWORD_EXPIRY_DAYS) +
        str(FUZZY_THRESHOLD) + str(MAX_SYSTEMS) + str(selected_fw)
    )

    if (st.session_state.get("findings_cache") is None or
            st.session_state.get("_last_cache_key") != _cache_key):
        with st.spinner("Running audit checks…"):
            findings_df, excluded_count, missing_warnings = run_audit(
                hr_df_f, sys_df_f,
                SCOPE_START, SCOPE_END,
                DORMANT_DAYS, PASSWORD_EXPIRY_DAYS,
                FUZZY_THRESHOLD, MAX_SYSTEMS,
                selected_fw,
                sod_override=soa_sod_extra or None,
                rbac_matrix=rbac_matrix,
                registry_df=registry_df,
            )
            if rbac_matrix and not findings_df.empty:
                rbac_findings = run_rbac_checks(sys_df_f, rbac_matrix, selected_fw)
                if not rbac_findings.empty:
                    findings_df = pd.concat([findings_df, rbac_findings], ignore_index=True)
            if registry_df is not None and not findings_df.empty:
                reg_findings = run_registry_checks(sys_df_f, registry_df, selected_fw)
                if not reg_findings.empty:
                    findings_df = pd.concat([findings_df, reg_findings], ignore_index=True)

        st.session_state["findings_cache"]  = findings_df
        st.session_state["excluded_cache"]  = excluded_count
        st.session_state["_last_cache_key"] = _cache_key
    else:
        findings_df    = st.session_state["findings_cache"]
        excluded_count = st.session_state["excluded_cache"]
        missing_warnings = []

    for w in missing_warnings:
        st.warning(w)

    # IRS
    risk_register = None
    irs_stats     = {}
    try:
        if not findings_df.empty:
            risk_register = build_risk_register(findings_df, SCOPE_END)
            irs_stats     = irs_summary_stats(risk_register)
            findings_df   = compute_irs(findings_df, SCOPE_END)
    except Exception:
        pass

    total      = len(findings_df)
    in_scope_n = max(len(sys_df_f) - excluded_count, 0)

    if excluded_count == len(sys_df_f) and len(sys_df_f) > 0:
        st.error(
            f"⚠️ All {len(sys_df_f):,} accounts were excluded by the scope filter. "
            f"The dates in your System Access file do not fall within "
            f"**{SCOPE_START.strftime('%d %b %Y')} → {SCOPE_END.strftime('%d %b %Y')}**."
        )
        st.markdown("""
**How to fix this:**
1. Check what year your data is from — look at the LastLoginDate or AccountCreatedDate columns
2. Use the **year selector** in the sidebar to match that year
3. Click **Full Year** then **GO** again
        """)
        st.stop()

    # ── RESULTS ──────────────────────────────────────────────────────────────
    st.divider()
    st.markdown("### 📊 Audit results")
    def cnt(col,val): return len(findings_df[findings_df[col]==val]) if total else 0

    # ── Row 1: core metrics ───────────────────────────────────────────────────
    m = st.columns(5)
    m[0].metric("Total findings",  total)
    m[1].metric("🔴 Critical",      cnt("Severity","🔴 CRITICAL"))
    m[2].metric("🟠 High",          cnt("Severity","🟠 HIGH"))
    m[3].metric("🟡 Medium",        cnt("Severity","🟡 MEDIUM"))
    m[4].metric("Accounts scanned", f"{in_scope_n:,}")

    # ── Row 2: IRS summary metrics ────────────────────────────────────────────
    if irs_stats:
        st.divider()
        st.markdown("#### 🎯 Identity Risk Score — population summary")
        i1,i2,i3,i4,i5,i6 = st.columns(6)
        i1.metric("Mean IRS",          f"{irs_stats.get('mean_score', 0)}")
        i2.metric("Median IRS",        f"{irs_stats.get('median_score', 0)}")
        i3.metric("Highest IRS",       f"{irs_stats.get('max_score', 0)}")
        i4.metric("🔴 Critical band",  irs_stats.get("critical_count", 0),
                  help="Identities scoring 75–100")
        i5.metric("🟠 High band",      irs_stats.get("high_count", 0),
                  help="Identities scoring 50–74")
        i6.metric("% Critical band",   f"{irs_stats.get('pct_critical', 0)}%")

    if total:
        st.divider()
        cc = st.columns(5)
        for i,(lbl,itype) in enumerate([
            ("Orphaned",         "Orphaned Account"),
            ("Terminated Active","Terminated Employee with Active Account"),
            ("Post-Term Login",  "Post-Termination Login"),
            ("Dormant",          "Dormant Account"),
            ("SoD Violations",   "Toxic Access (SoD Violation)"),
            ("Privilege Creep",  "Privilege Creep"),
            ("Generic IDs",      "Shared / Generic Account"),
            ("Service Accts",    "Service / System Account"),
            ("Admin Outside IT", "Super-User / Admin Access"),
            ("MFA Disabled",     "MFA Not Enabled"),
            ("Pwd Expired",      "Password Never Expired"),
            ("Duplicates",       "Duplicate System Access"),
            ("Multi-System",     "Excessive Multi-System Access"),
            ("No Expiry",        "Contractor Without Expiry Date"),
            ("Near-Match",       "Near-Match Email"),
            ("RBAC Violations",  "RBAC Violation"),
            ("Unauth Priv",      "Unauthorised Privileged Account"),
            ("Reg. Overdue",     "Privileged Account Review Overdue"),
        ]):
            cc[i%5].metric(lbl, cnt("IssueType",itype))

    if not total:
        st.success(
            f"✅ Audit complete — no issues found for {in_scope_n:,} accounts. "
            f"Scope: {SCOPE_START.strftime('%d %b %Y')} → {SCOPE_END.strftime('%d %b %Y')}"
        )
        st.stop()

    st.divider()

    # ── TABS ─────────────────────────────────────────────────────────────────
    tab1,tab2,tab3,tab4,tab5,tab6,tab7,tab8 = st.tabs([
        "🔎  Findings","🛠️  Remediation","⚖️  Frameworks",
        "📈  Analysis","🛡️  MFA Heatmap","🎯  Risk Register",
        "✍️  Opinion","🎲  Audit Sample",
    ])

    sdf = findings_df.copy()
    sdf["_o"] = sdf["Severity"].map(sev_order).fillna(9)
    sdf = sdf.sort_values("_o").drop(columns="_o")

    # ── Tab 1: Findings ───────────────────────────────────────────────────────
    with tab1:
        t1a, t1b, t1c = st.columns([3, 1, 1])
        with t1a:
            ft = st.multiselect(
                "Issue type",
                options=sorted(findings_df["IssueType"].unique()),
                default=sorted(findings_df["IssueType"].unique()),
                key="ft_filter",
            )
        with t1b:
            sf = st.selectbox("Severity", ["All","🔴 CRITICAL","🟠 HIGH","🟡 MEDIUM"], key="sev_filter")
        with t1c:
            dept_opts = ["All"] + sorted(findings_df["Department"].dropna().unique().tolist())
            df_filter = st.selectbox("Department", dept_opts, key="dept_filter")

        filtered = sdf[sdf["IssueType"].isin(ft)]
        if sf != "All":
            filtered = filtered[filtered["Severity"] == sf]
        if df_filter != "All":
            filtered = filtered[filtered["Department"] == df_filter]

        st.caption(f"Showing {len(filtered):,} of {total:,} findings — click any row to expand details")

        # ── Summary table — includes IRS columns if present ───────────────────
        base_cols = ["Severity","IssueType","Email","FullName","Department","AccessLevel"]
        irs_display_cols = ["identity_risk_score","risk_band"]
        summary_cols = [c for c in base_cols + irs_display_cols if c in filtered.columns]

        col_cfg = {
            "Severity":             st.column_config.TextColumn("Severity",    width="small"),
            "IssueType":            st.column_config.TextColumn("Issue",       width="medium"),
            "Email":                st.column_config.TextColumn("Email",       width="medium"),
            "FullName":             st.column_config.TextColumn("Name",        width="small"),
            "Department":           st.column_config.TextColumn("Department",  width="small"),
            "AccessLevel":          st.column_config.TextColumn("Access",      width="small"),
            "identity_risk_score":  st.column_config.NumberColumn("IRS",       width="small",
                                        help="Identity Risk Score 0–100"),
            "risk_band":            st.column_config.TextColumn("Risk Band",   width="small"),
        }

        try:
            st.dataframe(
                filtered[summary_cols].reset_index(drop=True),
                use_container_width=True,
                hide_index=True,
                height=min(400, 45 + len(filtered) * 35),
                column_config=col_cfg,
            )
        except Exception:
            st.dataframe(
                filtered[summary_cols].reset_index(drop=True),
                use_container_width=True,
                hide_index=True,
            )

        # ── Expandable detail ─────────────────────────────────────────────────
        st.markdown("#### Finding details")
        st.caption("Expand any finding to see the full detail, risk statement and remediation steps.")

        MAX_EXPAND = 100
        show_df = filtered.head(MAX_EXPAND)
        if len(filtered) > MAX_EXPAND:
            st.warning(f"Showing first {MAX_EXPAND} of {len(filtered):,} findings. Use the filters above to narrow down.")

        for _, row in show_df.iterrows():
            sev   = str(row.get("Severity",""))
            itype = str(row.get("IssueType",""))
            email = str(row.get("Email",""))
            dept  = str(row.get("Department",""))
            irs_v = row.get("identity_risk_score")
            band  = row.get("risk_band","")
            ico   = "🔴" if "CRITICAL" in sev else ("🟠" if "HIGH" in sev else "🟡")
            irs_tag = f" | IRS {irs_v} ({band})" if irs_v is not None else ""
            label = f"{ico} {itype} — {email} | {dept}{irs_tag}"
            with st.expander(label, expanded=False):
                d1, d2 = st.columns([2, 1])
                with d1:
                    st.markdown(f"**Finding:** {row.get('Detail','')}")
                    if row.get('Risk'):
                        st.markdown(f"**Risk:** {row.get('Risk','')}")
                with d2:
                    st.markdown(f"**Access level:** `{row.get('AccessLevel','')}`")
                    if row.get('JobTitle'):
                        st.markdown(f"**Job title:** `{row.get('JobTitle','')}`")
                    if irs_v is not None:
                        st.markdown(f"**Identity Risk Score:** `{irs_v}` — `{band}`")
                    _di = row.get('DaysInactive')
                    try:
                        if _di is not None and str(_di).lower() not in ('nan','none','') and float(_di) > 0:
                            st.markdown(f"**Days inactive:** `{int(float(_di))}`")
                    except (ValueError, TypeError):
                        pass
                    _dp = row.get('DaysPostTermination')
                    try:
                        if _dp is not None and str(_dp).lower() not in ('nan','none','') and float(_dp) > 0:
                            st.markdown(f"**Days post-term:** `{int(float(_dp))}`")
                    except (ValueError, TypeError):
                        pass
                fw_refs = []
                for fw_col in ["SOX Reference","ISO 27001 Ref","GDPR Reference","PCI-DSS Reference"]:
                    if row.get(fw_col):
                        fw_refs.append(f"`{row.get(fw_col)}`")
                if fw_refs:
                    st.markdown("**Framework refs:** " + " · ".join(fw_refs))

    # ── Tab 2: Remediation ────────────────────────────────────────────────────
    with tab2:
        sev_opts = ["All severities"]+sorted(sdf["Severity"].unique(), key=sev_order)
        rem_sev  = st.selectbox("Filter", sev_opts, key="rem_filter")
        rem_df   = sdf if rem_sev=="All severities" else sdf[sdf["Severity"]==rem_sev]
        for _,row in rem_df.iterrows():
            ico = "🔴" if "CRITICAL" in str(row.get("Severity","")) else ("🟠" if "HIGH" in str(row.get("Severity","")) else "🟡")
            with st.expander(f"{ico}  {row.get('IssueType','')}  —  {row.get('Email','')}  |  {row.get('Department','')}"):
                d1,d2 = st.columns([2,1])
                d1.markdown(f"**Finding:** {row.get('Detail','')}")
                d1.markdown(f"**Risk:** {row.get('Risk','')}")
                d2.markdown(f"**Owner:** `{row.get('Owner','')}`")
                d2.markdown(f"**SLA:** `{row.get('SLA','')}`")
                st.divider()
                a1,a2 = st.columns(2)
                a1.markdown(f"**① {row.get('Step 1 – Action','')}**")
                a1.markdown(f"② {row.get('Step 2 – Action','')}")
                a2.markdown(f"**③ {row.get('Step 3 – Action','')}**")
                a2.markdown(f"④ {row.get('Step 4 – Action','')}")

    # ── Tab 3: Frameworks ─────────────────────────────────────────────────────
    with tab3:
        if doc_files:
            uploaded_doc_names = ", ".join(f.name for f,_ in doc_files)
            st.info(f"📄 Documents parsed: **{uploaded_doc_names}**")
        fw_cols = [c for c in ["Severity","IssueType","Email","FullName","Department",
                                "SOX Reference","ISO 27001 Ref","GDPR Reference","PCI-DSS Reference"]
                   if c in sdf.columns]
        st.dataframe(sdf[fw_cols], use_container_width=True, hide_index=True, height=420)

    # ── Tab 4: Analysis ───────────────────────────────────────────────────────
    with tab4:
        st.markdown("### Risk analysis")

        pc1, pc2, pc3 = st.columns([2, 1, 1])

        with pc1:
            st.markdown("**Overall risk gap — severity distribution**")
            sev_map = {"🔴 CRITICAL": 0, "🟠 HIGH": 0, "🟡 MEDIUM": 0}
            for sev in findings_df["Severity"]:
                if sev in sev_map:
                    sev_map[sev] += 1
            sev_labels = [s.split(" ", 1)[1] for s in sev_map.keys()]
            sev_vals   = list(sev_map.values())
            sev_colors = ["#E24B4A","#EF9F27","#F9CB42"]
            try:
                import plotly.graph_objects as go
                fig = go.Figure(data=[go.Pie(
                    labels=sev_labels, values=sev_vals, hole=0.45,
                    marker=dict(colors=sev_colors, line=dict(color="#ffffff", width=2)),
                    textinfo="label+percent", textfont=dict(size=13),
                    hovertemplate="%{label}<br>%{value} findings<br>%{percent}<extra></extra>",
                )])
                fig.update_layout(
                    margin=dict(t=20,b=20,l=20,r=20), height=280,
                    showlegend=False, paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)", font=dict(family="Arial",color="#404040"),
                    annotations=[dict(text=f"<b>{total}</b><br>findings",
                                      x=0.5, y=0.5, font_size=14, showarrow=False,
                                      font_color="#1F3864")]
                )
                st.plotly_chart(fig, use_container_width=True)
            except ImportError:
                sev_df = pd.DataFrame({"Severity": sev_labels, "Count": sev_vals})
                st.bar_chart(sev_df.set_index("Severity"))

        with pc2:
            st.markdown("**By severity**")
            bsev = findings_df["Severity"].value_counts().reset_index()
            bsev.columns = ["Severity","Count"]
            bsev["% of total"] = (bsev["Count"] / total * 100).round(1).astype(str) + "%"
            st.dataframe(bsev, use_container_width=True, hide_index=True, height=260)

        with pc3:
            st.markdown("**Error rate**")
            error_rate = round(total / in_scope_n * 100, 1) if in_scope_n > 0 else 0
            crit_rate  = round(cnt("Severity","🔴 CRITICAL") / in_scope_n * 100, 1) if in_scope_n > 0 else 0
            st.metric("Overall error rate",  f"{error_rate}%")
            st.metric("Critical error rate", f"{crit_rate}%")
            st.metric("Accounts clean",      f"{in_scope_n - total:,}")
            st.metric("Accounts with issues",f"{min(total, in_scope_n):,}")

        st.divider()

        if "Department" in findings_df.columns:
            st.markdown("**Department risk breakdown**")
            dept_crit  = findings_df[findings_df["Severity"]=="🔴 CRITICAL"]["Department"].value_counts()
            dept_high  = findings_df[findings_df["Severity"]=="🟠 HIGH"]["Department"].value_counts()
            dept_med   = findings_df[findings_df["Severity"]=="🟡 MEDIUM"]["Department"].value_counts()
            all_depts_f= sorted(findings_df["Department"].dropna().unique())

            dept_heat = pd.DataFrame({
                "Department":  all_depts_f,
                "🔴 Critical": [dept_crit.get(d, 0) for d in all_depts_f],
                "🟠 High":     [dept_high.get(d, 0) for d in all_depts_f],
                "🟡 Medium":   [dept_med.get(d, 0)  for d in all_depts_f],
            })
            dept_heat["Total"] = dept_heat["🔴 Critical"] + dept_heat["🟠 High"] + dept_heat["🟡 Medium"]
            dept_heat = dept_heat.sort_values("Total", ascending=False)

            def risk_rating(row):
                if row["🔴 Critical"] >= 5:  return "🔴 High Risk"
                if row["🔴 Critical"] >= 1:  return "🟠 Elevated"
                if row["🟠 High"] >= 5:      return "🟠 Elevated"
                if row["🟠 High"] >= 1:      return "🟡 Moderate"
                return "🟢 Low Risk"
            dept_heat["Risk Rating"] = dept_heat.apply(risk_rating, axis=1)

            st.dataframe(
                dept_heat, use_container_width=True, hide_index=True,
                height=min(50 + len(dept_heat) * 35, 480),
                column_config={
                    "Department":  st.column_config.TextColumn("Department",  width="medium"),
                    "🔴 Critical": st.column_config.NumberColumn("🔴 Critical",width="small"),
                    "🟠 High":     st.column_config.NumberColumn("🟠 High",    width="small"),
                    "🟡 Medium":   st.column_config.NumberColumn("🟡 Medium",  width="small"),
                    "Total":       st.column_config.NumberColumn("Total",      width="small"),
                    "Risk Rating": st.column_config.TextColumn("Risk Rating",  width="medium"),
                }
            )

            st.markdown("**Top 8 departments by total findings**")
            top8 = dept_heat.head(8)
            try:
                import plotly.graph_objects as go
                fig2 = go.Figure(data=[go.Bar(
                    x=top8["Department"].tolist(), y=top8["🔴 Critical"].tolist(),
                    name="Critical", marker_color="#E24B4A",
                )])
                fig2.add_trace(go.Bar(
                    x=top8["Department"].tolist(), y=top8["🟠 High"].tolist(),
                    name="High", marker_color="#EF9F27",
                ))
                fig2.add_trace(go.Bar(
                    x=top8["Department"].tolist(), y=top8["🟡 Medium"].tolist(),
                    name="Medium", marker_color="#F9CB42",
                ))
                fig2.update_layout(
                    barmode="stack", height=320,
                    margin=dict(t=20,b=60,l=40,r=20),
                    paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                    font=dict(family="Arial",color="#404040"),
                    legend=dict(orientation="h",yanchor="bottom",y=1.02,xanchor="right",x=1),
                    xaxis=dict(tickangle=-30,gridcolor="rgba(0,0,0,0.05)"),
                    yaxis=dict(gridcolor="rgba(0,0,0,0.05)",title="Findings"),
                )
                st.plotly_chart(fig2, use_container_width=True)
            except ImportError:
                st.bar_chart(top8.set_index("Department")[["🔴 Critical","🟠 High","🟡 Medium"]])

        st.divider()

        r3a, r3b = st.columns(2)
        with r3a:
            st.markdown("**By issue type**")
            btyp = findings_df["IssueType"].value_counts().reset_index()
            btyp.columns = ["Issue Type","Count"]
            btyp["% of total"] = (btyp["Count"] / total * 100).round(1).astype(str) + "%"
            st.dataframe(btyp, use_container_width=True, hide_index=True, height=360)

        with r3b:
            st.markdown("**Top 10 highest-risk individuals**")
            if "identity_risk_score" in findings_df.columns:
                top_ids = (
                    findings_df.groupby("Email")
                    .agg(IRS=("identity_risk_score","max"),
                         Findings=("IssueType","count"),
                         Department=("Department","first"),
                         FullName=("FullName","first"))
                    .reset_index()
                    .sort_values("IRS", ascending=False)
                    .head(10)
                )
                st.dataframe(top_ids, use_container_width=True, hide_index=True, height=360)
            else:
                top_ids = (
                    findings_df.groupby("Email")
                    .agg(Findings=("IssueType","count"),
                         Department=("Department","first"),
                         FullName=("FullName","first"))
                    .reset_index()
                    .sort_values("Findings", ascending=False)
                    .head(10)
                )
                st.dataframe(top_ids, use_container_width=True, hide_index=True, height=360)

    # ── Tab 5: MFA Heatmap ────────────────────────────────────────────────────
    with tab5:
        st.markdown("### 🛡️ MFA Coverage & Enforcement Gap Analysis")
        st.caption(
            "Identity is the new perimeter. Every account with MFA disabled is an open door. "
            "This heatmap shows exactly where the perimeter is broken — by department and by system."
        )

        # ── Build MFA population from sys_df_f ───────────────────────────────
        if "MFA" not in sys_df_f.columns:
            st.warning("⚠️ MFA column not found in System Access file. Upload a file that includes an MFA column (values: Enabled / Disabled).")
        else:
            _mfa = sys_df_f.copy()
            _mfa["_mfa_lower"] = _mfa["MFA"].astype(str).str.strip().str.lower()
            _mfa["MFA_Status"] = _mfa["_mfa_lower"].apply(
                lambda v: "Enabled" if v in ("enabled","yes","true","1","enrolled","active")
                          else ("Disabled" if v in ("disabled","no","false","0","none","not enrolled","not_enrolled","")
                          else "Unknown")
            )

            # Join Department from HR if not present in sys_df_f
            if "Department" not in _mfa.columns or _mfa["Department"].isna().all():
                _hr_dept = hr_df_f[["Email","Department"]].copy()
                _hr_dept["Email"] = _hr_dept["Email"].str.strip().str.lower()
                _mfa["_em_lower"] = _mfa["Email"].str.strip().str.lower()
                _mfa = _mfa.merge(_hr_dept.rename(columns={"Email":"_em_lower","Department":"_dept_hr"}),
                                  on="_em_lower", how="left")
                _mfa["Department"] = _mfa.get("_dept_hr", "Unknown").fillna("Unknown")
            else:
                _mfa["Department"] = _mfa["Department"].fillna("Unknown")

            _system_col = "SystemName" if "SystemName" in _mfa.columns else None

            total_accounts  = len(_mfa)
            mfa_enabled_n   = len(_mfa[_mfa["MFA_Status"] == "Enabled"])
            mfa_disabled_n  = len(_mfa[_mfa["MFA_Status"] == "Disabled"])
            mfa_unknown_n   = len(_mfa[_mfa["MFA_Status"] == "Unknown"])
            coverage_pct    = round(mfa_enabled_n / total_accounts * 100, 1) if total_accounts else 0
            gap_pct         = round(mfa_disabled_n / total_accounts * 100, 1) if total_accounts else 0

            # ── Top-level MFA metrics ─────────────────────────────────────────
            hm1, hm2, hm3, hm4, hm5 = st.columns(5)
            hm1.metric("Total accounts",     f"{total_accounts:,}")
            hm2.metric("✅ MFA Enabled",      f"{mfa_enabled_n:,}",  delta=f"{coverage_pct}%")
            hm3.metric("🚨 MFA Disabled",     f"{mfa_disabled_n:,}", delta=f"-{gap_pct}%", delta_color="inverse")
            hm4.metric("❓ MFA Unknown",      f"{mfa_unknown_n:,}")
            hm5.metric("Coverage",           f"{coverage_pct}%",
                       delta="Target: 100%", delta_color="off")

            st.divider()

            # ── Heatmap: Department × System ─────────────────────────────────
            st.markdown("#### MFA Gap Heatmap — Department × System")
            st.caption("Each cell shows the number of accounts with MFA **disabled**. Red = most exposed.")

            _disabled = _mfa[_mfa["MFA_Status"] == "Disabled"].copy()

            if _disabled.empty:
                st.success("✅ No MFA gaps found — full MFA coverage across all departments and systems.")
            else:
                if _system_col:
                    pivot = (
                        _disabled.groupby(["Department", _system_col])
                        .size()
                        .reset_index(name="MFA_Disabled_Count")
                        .pivot(index="Department", columns=_system_col, values="MFA_Disabled_Count")
                        .fillna(0)
                        .astype(int)
                    )
                    pivot["TOTAL"] = pivot.sum(axis=1)
                    pivot = pivot.sort_values("TOTAL", ascending=False)
                    systems = [c for c in pivot.columns if c != "TOTAL"]

                    try:
                        import plotly.graph_objects as go
                        import numpy as np

                        z_vals      = pivot[systems].values
                        dept_labels = pivot.index.tolist()
                        sys_labels  = systems

                        # Custom red-scale: 0 = white, max = deep red
                        colorscale = [
                            [0.0,  "#ffffff"],
                            [0.01, "#fff0f0"],
                            [0.3,  "#ffaaaa"],
                            [0.6,  "#ef4444"],
                            [1.0,  "#7f1d1d"],
                        ]

                        fig_hm = go.Figure(data=go.Heatmap(
                            z=z_vals,
                            x=sys_labels,
                            y=dept_labels,
                            colorscale=colorscale,
                            text=z_vals,
                            texttemplate="%{text}",
                            textfont={"size": 13, "color": "black"},
                            hovertemplate="Dept: %{y}<br>System: %{x}<br>MFA Disabled: %{z}<extra></extra>",
                            showscale=True,
                            colorbar=dict(title="Accounts<br>w/ MFA off", thickness=14, len=0.8),
                        ))
                        fig_hm.update_layout(
                            height=max(300, len(dept_labels) * 44 + 80),
                            margin=dict(t=30, b=60, l=160, r=40),
                            paper_bgcolor="rgba(0,0,0,0)",
                            plot_bgcolor="rgba(0,0,0,0)",
                            font=dict(family="Arial", color="#1F3864", size=12),
                            xaxis=dict(tickangle=-30, side="bottom"),
                            yaxis=dict(autorange="reversed"),
                        )
                        st.plotly_chart(fig_hm, use_container_width=True)

                    except ImportError:
                        st.dataframe(pivot, use_container_width=True)

                    # ── Department totals bar chart ───────────────────────────
                    st.markdown("#### MFA disabled count by department")
                    dept_totals = pivot["TOTAL"].reset_index()
                    dept_totals.columns = ["Department","MFA Disabled"]
                    dept_totals = dept_totals.sort_values("MFA Disabled", ascending=False)

                    try:
                        fig_bar = go.Figure(data=[go.Bar(
                            x=dept_totals["Department"].tolist(),
                            y=dept_totals["MFA Disabled"].tolist(),
                            marker_color=[
                                "#7f1d1d" if v >= 10 else
                                "#ef4444" if v >= 5 else
                                "#fca5a5" if v >= 1 else "#d1fae5"
                                for v in dept_totals["MFA Disabled"].tolist()
                            ],
                            text=dept_totals["MFA Disabled"].tolist(),
                            textposition="outside",
                        )])
                        fig_bar.update_layout(
                            height=320,
                            margin=dict(t=20, b=80, l=40, r=20),
                            paper_bgcolor="rgba(0,0,0,0)",
                            plot_bgcolor="rgba(0,0,0,0)",
                            font=dict(family="Arial", color="#1F3864"),
                            xaxis=dict(tickangle=-30),
                            yaxis=dict(title="Accounts with MFA disabled"),
                            showlegend=False,
                        )
                        st.plotly_chart(fig_bar, use_container_width=True)
                    except ImportError:
                        st.bar_chart(dept_totals.set_index("Department"))

                else:
                    # No SystemName column — show department-only breakdown
                    dept_gap = (
                        _disabled.groupby("Department")
                        .size()
                        .reset_index(name="MFA Disabled")
                        .sort_values("MFA Disabled", ascending=False)
                    )
                    st.dataframe(dept_gap, use_container_width=True, hide_index=True)

            st.divider()

            # ── Coverage % by department table ────────────────────────────────
            st.markdown("#### MFA coverage by department")
            dept_total_counts   = _mfa.groupby("Department").size().rename("Total")
            dept_enabled_counts = _mfa[_mfa["MFA_Status"]=="Enabled"].groupby("Department").size().rename("Enabled")
            dept_disabled_counts= _mfa[_mfa["MFA_Status"]=="Disabled"].groupby("Department").size().rename("Disabled")
            dept_coverage = pd.concat([dept_total_counts, dept_enabled_counts, dept_disabled_counts], axis=1).fillna(0).astype(int)
            dept_coverage["Coverage %"] = (dept_coverage["Enabled"] / dept_coverage["Total"] * 100).round(1)
            dept_coverage["Gap %"]      = (dept_coverage["Disabled"] / dept_coverage["Total"] * 100).round(1)
            dept_coverage["Status"] = dept_coverage["Coverage %"].apply(
                lambda p: "🔴 Critical" if p < 50 else
                          "🟠 At Risk"  if p < 80 else
                          "🟡 Partial"  if p < 100 else
                          "✅ Full"
            )
            dept_coverage = dept_coverage.reset_index().sort_values("Coverage %")
            st.dataframe(
                dept_coverage,
                use_container_width=True,
                hide_index=True,
                height=min(60 + len(dept_coverage) * 35, 460),
                column_config={
                    "Department":  st.column_config.TextColumn("Department",  width="medium"),
                    "Total":       st.column_config.NumberColumn("Total",     width="small"),
                    "Enabled":     st.column_config.NumberColumn("✅ Enabled", width="small"),
                    "Disabled":    st.column_config.NumberColumn("🚨 Disabled",width="small"),
                    "Coverage %":  st.column_config.ProgressColumn("Coverage %", min_value=0, max_value=100, format="%.1f%%"),
                    "Gap %":       st.column_config.NumberColumn("Gap %",     width="small"),
                    "Status":      st.column_config.TextColumn("Status",      width="small"),
                }
            )

            st.divider()

            # ── Kill List: Enrol These Users Now ─────────────────────────────
            st.markdown("#### 🎯 Enrolment Kill List — users to enrol in MFA immediately")
            st.caption(
                "Prioritised by access level: Admin and privileged accounts first, then by department risk. "
                "Hand this list to your IT Security team with a 48-hour SLA."
            )

            _kill_list = _mfa[_mfa["MFA_Status"] == "Disabled"].copy()

            # Merge HR data for enrichment
            _hr_enrich = hr_df_f[["Email","FullName","Department","EmploymentStatus","ContractType"]].copy()
            _hr_enrich["Email"] = _hr_enrich["Email"].str.strip().str.lower()
            _kill_list["_em_kl"] = _kill_list["Email"].str.strip().str.lower()
            _kill_list = _kill_list.merge(
                _hr_enrich.rename(columns={
                    "Email":"_em_kl","FullName":"_FullName_hr",
                    "Department":"_Dept_hr","EmploymentStatus":"_EmpStatus",
                    "ContractType":"_ContractType"
                }),
                on="_em_kl", how="left"
            )

            # Priority score: Admin/DBAdmin = 3, Payroll/Finance = 2, others = 1
            def _access_priority(access_str):
                a = str(access_str).lower()
                if any(x in a for x in ("admin","root","superadmin","sysadmin","dbadmin")): return 3
                if any(x in a for x in ("payroll","finance","hr")): return 2
                return 1

            _kill_list["_priority"] = _kill_list["AccessLevel"].apply(_access_priority) if "AccessLevel" in _kill_list.columns else 1
            _kill_list = _kill_list.sort_values("_priority", ascending=False)

            # Build display columns
            kl_display_cols = []
            for col in ["Email","FullName","_FullName_hr","Department","_Dept_hr","AccessLevel",
                        "_EmpStatus","_ContractType","SystemName","LastLoginDate"]:
                if col in _kill_list.columns:
                    kl_display_cols.append(col)

            _kill_list["Priority"] = _kill_list["_priority"].map({3:"🔴 Urgent",2:"🟠 High",1:"🟡 Standard"})
            _kill_list["Action"]   = "Enrol MFA within 48h — block login until enrolled"

            kl_final_cols = ["Priority","Email"]
            for c in ["FullName","_FullName_hr"]:
                if c in _kill_list.columns and _kill_list[c].notna().any():
                    kl_final_cols.append(c); break
            for c in ["Department","_Dept_hr"]:
                if c in _kill_list.columns and _kill_list[c].notna().any():
                    kl_final_cols.append(c); break
            for c in ["AccessLevel","SystemName","LastLoginDate","_EmpStatus","Action"]:
                if c in _kill_list.columns:
                    kl_final_cols.append(c)

            kl_final_cols = list(dict.fromkeys(kl_final_cols))  # dedup preserving order
            kl_show = _kill_list[kl_final_cols].rename(columns={
                "_FullName_hr": "FullName",
                "_Dept_hr":     "Department",
                "_EmpStatus":   "Status",
            }).reset_index(drop=True)

            kl1, kl2, kl3 = st.columns(3)
            kl1.metric("Users to enrol",   len(kl_show))
            kl2.metric("🔴 Urgent (Admin)", int((_kill_list["_priority"] == 3).sum()))
            kl3.metric("🟠 High (Finance/Payroll/HR)", int((_kill_list["_priority"] == 2).sum()))

            st.dataframe(
                kl_show, use_container_width=True, hide_index=True,
                height=min(60 + len(kl_show) * 35, 500),
                column_config={
                    "Priority":      st.column_config.TextColumn("Priority",     width="small"),
                    "Email":         st.column_config.TextColumn("Email",        width="medium"),
                    "FullName":      st.column_config.TextColumn("Name",         width="small"),
                    "Department":    st.column_config.TextColumn("Department",   width="small"),
                    "AccessLevel":   st.column_config.TextColumn("Access Level", width="small"),
                    "SystemName":    st.column_config.TextColumn("System",       width="small"),
                    "LastLoginDate": st.column_config.TextColumn("Last Login",   width="small"),
                    "Status":        st.column_config.TextColumn("HR Status",    width="small"),
                    "Action":        st.column_config.TextColumn("Action",       width="large"),
                }
            )

            # ── One-click export ──────────────────────────────────────────────
            if not kl_show.empty:
                kl_buf = io.BytesIO()
                with pd.ExcelWriter(kl_buf, engine="xlsxwriter") as kl_writer:
                    kl_wb  = kl_writer.book
                    kl_hdr = kl_wb.add_format({
                        "bold": True, "bg_color": "#1F3864", "font_color": "white",
                        "border": 1, "font_name": "Arial", "font_size": 10,
                    })
                    kl_red = kl_wb.add_format({"bg_color": "#FFDEDE", "font_name": "Arial", "font_size": 9})
                    kl_org = kl_wb.add_format({"bg_color": "#FFF0CC", "font_name": "Arial", "font_size": 9})
                    kl_std = kl_wb.add_format({"font_name": "Arial", "font_size": 9})

                    kl_show.to_excel(kl_writer, index=False, sheet_name="MFA_Enrolment_KillList")
                    ws_kl = kl_writer.sheets["MFA_Enrolment_KillList"]

                    for ci, col in enumerate(kl_show.columns):
                        ws_kl.write(0, ci, col, kl_hdr)
                        ws_kl.set_column(ci, ci, max(18, len(str(col)) + 4))

                    for ri, (_, row) in enumerate(_kill_list.iterrows(), start=1):
                        fmt = kl_red if row.get("_priority") == 3 else (kl_org if row.get("_priority") == 2 else kl_std)
                        for ci, col in enumerate(kl_show.columns):
                            ws_kl.write(ri, ci, str(kl_show.iloc[ri-1][col] if ri-1 < len(kl_show) else ""), fmt)

                    # Summary sheet
                    ws_sum = kl_wb.add_worksheet("MFA_Coverage_Summary")
                    ws_sum.write(0, 0, "MFA Gap Analysis — generated by IAM Audit Tool", kl_hdr)
                    ws_sum.write(1, 0, f"Generated: {datetime.today().strftime('%d %B %Y')}")
                    ws_sum.write(2, 0, f"Total accounts scanned: {total_accounts}")
                    ws_sum.write(3, 0, f"MFA Enabled: {mfa_enabled_n} ({coverage_pct}%)")
                    ws_sum.write(4, 0, f"MFA Disabled: {mfa_disabled_n} ({gap_pct}%)")
                    ws_sum.write(5, 0, f"Accounts requiring immediate enrolment: {len(kl_show)}")
                    ws_sum.set_column(0, 0, 50)

                    dept_coverage.to_excel(kl_writer, index=False, sheet_name="Dept_MFA_Coverage")

                kl_buf.seek(0)
                ref_slug_mfa = (meta.get("ref") or "Audit").replace(" ","_").replace("/","-")
                st.download_button(
                    label="📥  Download MFA Enrolment Kill List (.xlsx)",
                    data=kl_buf.getvalue(),
                    file_name=f"MFA_Gap_{ref_slug_mfa}_{datetime.today().strftime('%Y%m%d')}.xlsx",
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    type="primary",
                    use_container_width=True,
                )
                st.caption(
                    "Hand this to IT Security with instruction: "
                    "**Enforce MFA enrolment within 48 hours — block login for 🔴 Urgent accounts until enrolled.**"
                )

    # ── Tab 6: Risk Register ──────────────────────────────────────────────────
    with tab6:
        st.markdown("#### 🎯 Identity Risk Register")
        if risk_register is not None and not risk_register.empty:
            comp_cols = [c for c in ["IRS_Severity","IRS_Critical_Flag","IRS_Dormancy",
                                     "IRS_Privilege","IRS_Contractor"] if c in risk_register.columns]

            rr1, rr2, rr3 = st.columns(3)
            with rr1:
                st.markdown("**Risk band distribution**")
                if "risk_band" in risk_register.columns:
                    band_counts = risk_register["risk_band"].value_counts().reset_index()
                    band_counts.columns = ["Band","Count"]
                    st.dataframe(band_counts, use_container_width=True, hide_index=True, height=200)
            with rr2:
                st.markdown("**Top 10 highest-risk identities**")
                if "identity_risk_score" in risk_register.columns:
                    top10 = risk_register.nlargest(10, "identity_risk_score")[
                        [c for c in ["Email","FullName","identity_risk_score","risk_band","Department"]
                         if c in risk_register.columns]
                    ]
                    st.dataframe(top10, use_container_width=True, hide_index=True, height=380)
            with rr3:
                st.markdown("**IRS score histogram**")
                if "identity_risk_score" in risk_register.columns:
                    try:
                        import plotly.graph_objects as go
                        hist_vals = risk_register["identity_risk_score"].dropna().tolist()
                        fig_irs = go.Figure(data=[go.Histogram(
                            x=hist_vals, nbinsx=20,
                            marker_color="#4F81BD",
                            marker_line=dict(color="white", width=0.5),
                        )])
                        fig_irs.update_layout(
                            height=300,
                            margin=dict(t=20,b=40,l=40,r=20),
                            paper_bgcolor="rgba(0,0,0,0)",
                            plot_bgcolor="rgba(0,0,0,0)",
                            font=dict(family="Arial",color="#404040"),
                            xaxis=dict(title="IRS Score",gridcolor="rgba(0,0,0,0.05)"),
                            yaxis=dict(title="Count",gridcolor="rgba(0,0,0,0.05)"),
                            bargap=0.05,
                        )
                        st.plotly_chart(fig_irs, use_container_width=True)
                    except ImportError:
                        st.bar_chart(risk_register["identity_risk_score"].value_counts().sort_index())

            st.divider()
            st.markdown("**Full risk register**")
            display_cols = [c for c in
                ["Email","FullName","Department","identity_risk_score","risk_band"] + comp_cols
                if c in risk_register.columns]
            st.dataframe(
                risk_register[display_cols].sort_values("identity_risk_score", ascending=False)
                if "identity_risk_score" in risk_register.columns else risk_register[display_cols],
                use_container_width=True, hide_index=True, height=420,
                column_config={
                    "identity_risk_score": st.column_config.NumberColumn("IRS Score", width="small"),
                    "risk_band":           st.column_config.TextColumn("Band",        width="small"),
                }
            )

            if comp_cols:
                st.divider()
                st.markdown("**Component score breakdown — population averages**")
                comp_means = risk_register[comp_cols].mean().round(3)
                comp_labels = {
                    "IRS_Severity":     "Severity weight (40%)",
                    "IRS_Critical_Flag":"Critical flag (25%)",
                    "IRS_Dormancy":     "Dormancy (15%)",
                    "IRS_Privilege":    "Privilege breadth (12%)",
                    "IRS_Contractor":   "Contractor risk (8%)",
                }
                comp_df = pd.DataFrame({
                    "Component": [comp_labels.get(c,c) for c in comp_cols],
                    "Avg raw score (0–1)": [comp_means[c] for c in comp_cols],
                })
                st.dataframe(comp_df, use_container_width=True, hide_index=True, height=220)

            # ── Export risk register ──────────────────────────────────────────
            st.divider()
            rr_buf = io.BytesIO()
            risk_register.to_excel(rr_buf, index=False)
            rr_buf.seek(0)
            ref_slug = (meta.get("ref") or "Audit").replace(" ","_").replace("/","-")
            st.download_button(
                label="📥 Download Identity Risk Register (.xlsx)",
                data=rr_buf.getvalue(),
                file_name=f"IRS_Register_{ref_slug}_{datetime.today().strftime('%Y%m%d')}.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                type="primary",
            )
        else:
            st.info("No risk register data. Run the audit to generate IRS scores.")

    # ── Tab 7: Opinion ────────────────────────────────────────────────────────
    with tab7:
        st.markdown("#### Audit opinion")
        oc1, oc2 = st.columns([2,1])
        with oc2:
            use_ai = st.checkbox("Use AI to generate opinion", value=True)
        with oc1:
            if use_ai:
                st.caption("AI will write a professional audit memo with Executive Summary, Key Findings, and Formal Opinion.")
            else:
                st.caption("Rule-based opinion generated from finding counts and severity levels.")

        if use_ai:
            if st.button("✍️ Generate Audit Opinion", type="primary", use_container_width=True):
                with st.spinner("Generating your audit memo..."):
                    ai_opinion, success = generate_ai_opinion(
                        findings_df, meta, SCOPE_START, SCOPE_END, len(sys_df_f), in_scope_n
                    )
                if success and ai_opinion:
                    st.session_state["ai_opinion"] = ai_opinion
                else:
                    st.warning("AI opinion unavailable — showing rule-based opinion instead.")
                    st.session_state["ai_opinion"] = generate_opinion(
                        findings_df, meta, SCOPE_START, SCOPE_END, len(sys_df_f), in_scope_n
                    )
            if "ai_opinion" in st.session_state:
                st.markdown("---")
                st.markdown(st.session_state["ai_opinion"])
                st.markdown("---")
                st.caption("⚠️ AI-generated content. Review and edit before any formal use.")
        else:
            opinion = generate_opinion(findings_df, meta, SCOPE_START, SCOPE_END, len(sys_df_f), in_scope_n)
            st.text_area("Draft opinion (edit before use):", value=opinion, height=440)
            st.caption("This draft is generated from finding counts and severity. Must be reviewed before formal use.")
        if doc_files:
            st.caption(f"Documents uploaded: {', '.join(f.name for f,_ in doc_files)}.")

    # ── Tab 8: Audit Sample ───────────────────────────────────────────────────
    with tab8:
        st.markdown("#### Audit sample — 25 items for external auditors")
        st.caption(
            "External auditors always request a manual sample even after a full population test. "
            "This generates a prioritised 25-item sample: Critical first, then High, then random Medium."
        )
        ss1, ss2 = st.columns([1,3])
        with ss1:
            sample_size = st.number_input("Sample size", min_value=5, max_value=100, value=25, step=5)
        with ss2:
            st.markdown("<br>", unsafe_allow_html=True)
            st.info(f"Will select up to {sample_size} findings — Critical priority first, then High, then random Medium.")

        sample_df = generate_audit_sample(findings_df, sample_size)
        if not sample_df.empty:
            crit_in = len(sample_df[sample_df["Severity"]=="🔴 CRITICAL"])
            high_in = len(sample_df[sample_df["Severity"]=="🟠 HIGH"])
            med_in  = len(sample_df[sample_df["Severity"]=="🟡 MEDIUM"])
            sc1,sc2,sc3,sc4 = st.columns(4)
            sc1.metric("Total in sample", len(sample_df))
            sc2.metric("Critical",  crit_in)
            sc3.metric("High",      high_in)
            sc4.metric("Medium",    med_in)

            disp_cols = [c for c in ["Sample#","Severity","IssueType","Email","FullName",
                                      "Department","TestInstruction"] if c in sample_df.columns]
            st.dataframe(sample_df[disp_cols], use_container_width=True, hide_index=True, height=380,
                column_config={
                    "Sample#":        st.column_config.NumberColumn("No.", width="small"),
                    "Severity":       st.column_config.TextColumn("Severity", width="small"),
                    "TestInstruction":st.column_config.TextColumn("Test instruction", width="large"),
                })

            buf_s = io.BytesIO()
            with pd.ExcelWriter(buf_s, engine="xlsxwriter") as wr:
                wb_s = wr.book
                H_s = wb_s.add_format({"bold":True,"bg_color":"#1F3864","font_color":"white","border":1,"font_name":"Arial","font_size":10})
                R_s = wb_s.add_format({"bg_color":"#FFDEDE","font_name":"Arial","font_size":9})
                O_s = wb_s.add_format({"bg_color":"#FFF0CC","font_name":"Arial","font_size":9})
                Y_s = wb_s.add_format({"bg_color":"#FFFBCC","font_name":"Arial","font_size":9})
                add_sample_sheet(wr, sample_df, wb_s, H_s, R_s, O_s, Y_s)
            buf_s.seek(0)
            ref_s = (meta.get("ref") or "Audit").replace(" ","_")
            st.download_button(
                label="📥 Download Audit_Sample_Request.xlsx",
                data=buf_s.getvalue(),
                file_name=f"Audit_Sample_{ref_s}_{datetime.today().strftime('%Y%m%d')}.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                type="primary", use_container_width=True,
            )
            st.caption("Hand this file to the external audit team.")
        else:
            st.info("No findings to sample.")

    # ── EXPORT ────────────────────────────────────────────────────────────────
    st.divider()
    ex1,ex2 = st.columns([3,1])
    with ex1:
        op_export = generate_opinion(findings_df, meta, SCOPE_START, SCOPE_END, len(sys_df_f), in_scope_n)
        ref_slug  = (meta.get("ref") or "Audit").replace(" ","_").replace("/","-")
        st.download_button(
            label="📥  Download Workpaper-Ready Audit Report (.xlsx)",
            data=to_excel_bytes(findings_df, hr_df_f, sys_df_f, SCOPE_START, SCOPE_END,
                                excluded_count, meta, op_export),
            file_name=f"IAR_{ref_slug}_{datetime.today().strftime('%Y%m%d')}.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            type="primary", use_container_width=True,
        )
    with ex2:
        st.metric("Report sheets", "9+")

elif uploaded_files and (not hr_file or not sys_file):
    if not hr_file:
        st.warning("⚠️ HR Master not identified. Rename your file to include `HR_Master` or use the manual selector above.")
    if not sys_file:
        st.warning("⚠️ System Access file not identified. Rename your file to include `System_Access` or use the manual selector above.")

else:
    st.info(
        "📂 Upload your HR Master and System Access files above to begin the audit. "
        "You can also add your SOA, RBAC Matrix, Privileged User Registry and policy documents "
        "to the same upload zone — the tool detects each one automatically."
    )
    st.caption(
        "New here? Visit the **How to Use** page in the sidebar for a full step-by-step walkthrough, "
        "column reference and document naming guide."
    )
