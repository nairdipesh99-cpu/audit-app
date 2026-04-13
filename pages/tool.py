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
from components import inject_css, render_header, render_sidebar_brand

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
#  DOCUMENT PARSER
#  Reads any uploaded file and returns its text content
# ─────────────────────────────────────────────────────────────────────────────
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


# ─────────────────────────────────────────────────────────────────────────────
#  PAGE CONFIG
# ─────────────────────────────────────────────────────────────────────────────


# ─────────────────────────────────────────────────────────────────────────────
#  SIDEBAR
# ─────────────────────────────────────────────────────────────────────────────

    st.markdown("#### Engagement details")
    meta = {
        "client":   st.text_input("Client",    placeholder="Nairs.com Ltd"),
        "ref":      st.text_input("Reference", placeholder="IAR-2025-001"),
        "auditor":  st.text_input("Auditor",   placeholder="Your full name"),
        "standard": st.selectbox("Audit standard", [
            "ISO 27001:2022","SOX ITGC","PCI-DSS v4.0","GDPR Art.32",
            "ISACA IS Audit","Internal Audit Charter",
        ]),
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
    st.markdown("#### Audit scope")
    # Year range: current year back to 15 years ago
    # Supports forensic audits and fraud investigations
    _yr_opts = list(range(today.year, today.year - 16, -1))

    def _fmt_year(y):
        if y == today.year:     return f"{y}  — current year"
        if y == today.year - 1: return f"{y}  — previous year"
        if y == today.year - 2: return f"{y}  — 2 years ago"
        return f"{y}  — {today.year - y} years ago"

    st.selectbox(
        "Audit year",
        options=_yr_opts,
        index=1,
        format_func=_fmt_year,
        key="audit_year_sel",
        help="Select any year from the last 15 years. For fraud investigations or historical audits, go as far back as needed."
    )
    sb1, sb2 = st.columns(2)
    sb1.button("Full Year",    use_container_width=True, on_click=_set_year, type="primary")
    sb2.button("Last Quarter", use_container_width=True, on_click=_last_q)
    sb1.button("Last 6 Mo.",   use_container_width=True, on_click=_last_6)
    sb2.button("This Month",   use_container_width=True, on_click=_this_month)

    st.caption("Or set a custom date range below for multi-year or specific period audits.")
    dc1, dc2 = st.columns(2)
    with dc1:
        st.date_input(
            "From",
            key="ss_start",
            on_change=_date_chg,
            min_value=date(today.year - 15, 1, 1),
            max_value=today,
            help="Start of audit scope. Can go back up to 15 years for forensic reviews."
        )
    with dc2:
        st.date_input(
            "To",
            key="ss_end",
            on_change=_date_chg,
            min_value=date(today.year - 15, 1, 2),
            max_value=today,
            help="End of audit scope."
        )

    date_err = st.session_state["ss_start"] >= st.session_state["ss_end"]
    if date_err: st.error("From must be before To.")
    st.button("▶  GO — Run Audit", use_container_width=True, type="primary",
              disabled=date_err, on_click=_go)

    SCOPE_START = st.session_state["ss_start"]
    SCOPE_END   = st.session_state["ss_end"]
    scope_days  = (SCOPE_END - SCOPE_START).days
    if st.session_state["locked"]:
        st.success(f"🔒 {SCOPE_START.strftime('%d %b %Y')} → {SCOPE_END.strftime('%d %b %Y')} ({scope_days}d)")
    else:
        st.info(f"📅 {scope_days} days — click GO to run")

    st.divider()
    st.markdown("#### Detection thresholds")
    DORMANT_DAYS         = st.slider("Dormant (days)",         30, 365, 90)
    PASSWORD_EXPIRY_DAYS = st.slider("Password expiry (days)", 30, 365, 90)
    FUZZY_THRESHOLD      = st.slider("Fuzzy match %",          70,  99, 88)
    MAX_SYSTEMS          = st.slider("Max systems per user",    2,   10,  3)




# ─────────────────────────────────────────────────────────────────────────────
#  HEADER + DOCUMENT UPLOAD ZONE
# ─────────────────────────────────────────────────────────────────────────────
render_header()
with st.sidebar:
    render_sidebar_brand()
    st.divider()

st.markdown("### 📂 Upload audit documents")
st.caption(
    "Upload all documents in one place. The tool auto-detects each file by filename. "
    "Name files clearly: `HR_Master_2025.xlsx` · `System_Access_2025.xlsx` · `SOA_ISO27001.xlsx` · "
    "`SoD_Matrix.xlsx` · `Access_Control_Policy.pdf` · `JML_Procedure.pdf`"
)

uploaded_files = st.file_uploader(
    "Drop all your audit documents here",
    type=["xlsx","xls","csv","pdf","txt","docx"],
    accept_multiple_files=True,
    label_visibility="collapsed",
    key="multi_upload",
)

# ── Auto-classify uploaded files ─────────────────────────────────────────────
hr_file   = None
sys_file  = None
doc_files = []   # policies, SOA, standards, etc.

if uploaded_files:
    classified = {f.name: detect_doc_type(f) for f in uploaded_files}

    # Show what was detected
    st.markdown("**Files detected:**")
    det_cols = st.columns(min(len(uploaded_files), 4))
    for i, f in enumerate(uploaded_files):
        dtype = classified[f.name]
        icon = {"hr_master":"👥","system_access":"💻","soa":"📋",
                "access_policy":"🔒","jml_procedure":"🔄","risk_register":"⚠️",
                "rbac_matrix":"🔑","privileged_registry":"🛡️",
                "standard":"📄","other":"📎"}.get(dtype,"📎")
        label = {"hr_master":"HR Master","system_access":"System Access / UAL",
                 "soa":"SOA / Standard","access_policy":"Access Policy",
                 "jml_procedure":"JML Procedure","risk_register":"Risk Register",
                 "rbac_matrix":"RBAC Matrix","privileged_registry":"Privileged User Registry",
                 "standard":"Standard / Policy","other":"Other document"}.get(dtype,"Document")
        det_cols[i % 4].success(f"{icon} {f.name} — {label}")

    # Assign files
    for f in uploaded_files:
        dtype = classified[f.name]
        if dtype == "hr_master" and hr_file is None:
            hr_file = f
        elif dtype == "system_access" and sys_file is None:
            sys_file = f
        else:
            doc_files.append((f, dtype))

    # If no auto-detected HR/system files, let user manually assign
    if not hr_file or not sys_file:
        st.warning("⚠️ Could not auto-detect all required files. Please assign them manually:")
        other_files = [f for f in uploaded_files]
        file_names  = [f.name for f in other_files]
        ma1, ma2 = st.columns(2)
        with ma1:
            hr_sel = st.selectbox(
                "Which file is the HR Master?",
                options=["— not uploaded —"] + file_names,
                key="hr_manual_sel",
            )
            if hr_sel != "— not uploaded —":
                hr_file = next(f for f in uploaded_files if f.name == hr_sel)
        with ma2:
            sys_sel = st.selectbox(
                "Which file is the System Access list?",
                options=["— not uploaded —"] + file_names,
                key="sys_manual_sel",
            )
            if sys_sel != "— not uploaded —":
                sys_file = next(f for f in uploaded_files if f.name == sys_sel)


# ── Feature 1: Legacy system / OCR upload ────────────────────────────────────
with st.expander("📸 Legacy system upload — screenshot or PDF (AI-powered extraction)", expanded=False):
    st.caption(
        "For old systems that only produce screenshots or PDFs. "
        "Upload an image or PDF — AI extracts the account data and converts it to the right format automatically."
    )
    ocr_file = st.file_uploader(
        "Upload screenshot or PDF of legacy system report",
        type=["png","jpg","jpeg","pdf"],
        key="ocr_upload",
        label_visibility="collapsed",
    )
    if ocr_file:
        if st.button("🔍 Extract data from image", type="primary"):
            with st.spinner("Extracting account data from image..."):
                ocr_df, ocr_err = ocr_via_ai(ocr_file)
            if ocr_err:
                st.error(f"Extraction failed: {ocr_err}")
            elif ocr_df is not None and not ocr_df.empty:
                st.success(f"Extracted {len(ocr_df)} account rows from the image.")
                st.dataframe(ocr_df, use_container_width=True, hide_index=True)
                # Allow download as xlsx for uploading as system access file
                buf = io.BytesIO()
                ocr_df.to_excel(buf, index=False)
                buf.seek(0)
                st.download_button(
                    "📥 Download extracted data as System_Access.xlsx",
                    data=buf.getvalue(),
                    file_name="System_Access_OCR_Extracted.xlsx",
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                )
                st.caption("Download this file, then upload it as your System Access file above to run the full audit.")
            else:
                st.warning("No account rows could be extracted. Try a clearer image.")

st.divider()

# ─────────────────────────────────────────────────────────────────────────────
#  DOCUMENT INTELLIGENCE PANEL
#  Show what the tool extracted from each non-data document
# ─────────────────────────────────────────────────────────────────────────────
doc_context   = {}   # {dtype: text}
soa_sod_extra   = {}   # SoD rules extracted from uploaded SOA/policy
rbac_matrix_data = {}   # RBAC Matrix: {JobTitle: [PermittedAccessLevels]}
registry_df_data = None  # Privileged User Registry DataFrame

if doc_files:
    with st.expander(f"📄 Document intelligence — {len(doc_files)} policy/standard document(s) parsed", expanded=False):
        for f, dtype in doc_files:
            text = extract_text(f)
            doc_context[dtype] = text
            label = {"soa":"SOA — ISO 27001 Annex A","access_policy":"Access Control Policy",
                     "jml_procedure":"JML Procedure","risk_register":"Risk Register",
                     "standard":"Audit Standard / Policy","other":"Supporting document"}.get(dtype, dtype)
            st.markdown(f"**{f.name}** — detected as: *{label}*")
            if text and not text.startswith("["):
                st.caption(f"Extracted {len(text):,} characters. Findings will reference this document.")
                # Load RBAC Matrix
                if dtype == "rbac_matrix":
                    f.seek(0)
                    rbac_rules, rbac_err = load_rbac_matrix(f)
                    if rbac_rules:
                        rbac_matrix_data.update(rbac_rules)
                        st.caption(f"RBAC Matrix loaded — {len(rbac_rules)} job role entitlements. Accounts will be checked against permitted access levels.")
                    elif rbac_err:
                        st.warning(f"Could not read RBAC Matrix: {rbac_err}")

                # Load Privileged User Registry
                elif dtype == "privileged_registry":
                    f.seek(0)
                    reg_df, reg_err = load_privileged_registry(f)
                    if reg_df is not None:
                        registry_df_data = reg_df
                        st.caption(f"Privileged User Registry loaded — {len(reg_df)} entries. All Admin/privileged accounts will be cross-referenced.")
                    elif reg_err:
                        st.warning(f"Could not read Privileged User Registry: {reg_err}")

                # Try to extract SoD rules from SOA or dedicated SoD matrix
                elif dtype in ("soa","access_policy","sod_matrix","other"):
                    # First try structured Excel SoD matrix parse
                    if f.name.lower().endswith((".xlsx",".xls")):
                        f.seek(0)
                        matrix_rules, matrix_err = load_sod_matrix(f)
                        if matrix_rules:
                            st.caption(f"Loaded {len(matrix_rules)} SoD rules from Excel matrix — overrides hardcoded defaults.")
                            soa_sod_extra.update(matrix_rules)
                        elif not matrix_err:
                            pass
                    # Also try text-based extraction from SOA
                    extra = parse_soa_sod_rules(text)
                    if extra:
                        st.caption(f"Extracted {len(extra)} SoD rules from document text — applied to audit.")
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

    # Clear findings cache when new files are uploaded
    if "findings_cache" in st.session_state:
        del st.session_state["findings_cache"]
        del st.session_state["excluded_cache"]
        if "_last_cache_key" in st.session_state:
            del st.session_state["_last_cache_key"]

    # Column validation
    hr_miss  = {"Email","FullName","Department"} - set(hr_df.columns)
    sys_miss = {"Email","AccessLevel"}           - set(sys_df.columns)
    if hr_miss or sys_miss:
        e1,e2 = st.columns(2)
        if hr_miss:  e1.error(f"HR Master missing columns: {hr_miss}")
        if sys_miss: e2.error(f"System Access missing columns: {sys_miss}")
        st.info("Required columns — HR Master: Email, FullName, Department | System Access: Email, AccessLevel")
        st.stop()

    # Department filter
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

    # Population completeness gate
    if not st.session_state.get("confirmed", False):
        st.markdown("### ⚠️ Confirm data completeness")
        g1,g2,g3 = st.columns(3)
        g1.metric("HR Master rows",       f"{len(hr_df_f):,}")
        g2.metric("System Access rows",   f"{len(sys_df_f):,}")
        g3.metric("Policy docs uploaded", len(doc_files))
        st.markdown("""
Before the scan runs, confirm that the data you uploaded is the **complete, unfiltered population** —
not a sample or extract pre-filtered by the client. This confirmation forms part of your audit workpaper evidence.
        """)
        if st.button("✅  I confirm — this is the complete population. Proceed to scope & run.",
                     type="primary", use_container_width=True):
            st.session_state["confirmed"] = True
            st.rerun()
        st.stop()

    # Scope lock gate
    if not st.session_state.get("locked", False):
        s1,s2,s3 = st.columns(3)
        s1.metric("Population confirmed", f"{len(hr_df_f):,} HR | {len(sys_df_f):,} system")
        s2.metric("Year selector",        str(st.session_state.get("audit_year_sel", _default_year)))
        s3.metric("Policy docs parsed",   len(doc_files))
        st.info(
            f"📅 Set to **{SCOPE_START.strftime('%d %b %Y')} → {SCOPE_END.strftime('%d %b %Y')}**. "
            f"Click **▶ GO — Run Audit** in the sidebar to lock and scan."
        )
        st.stop()

    # Run audit — with session state caching so tabs don't re-run the engine
    _cache_key = (
        len(hr_df_f), len(sys_df_f),
        str(SCOPE_START), str(SCOPE_END),
        DORMANT_DAYS, PASSWORD_EXPIRY_DAYS,
        FUZZY_THRESHOLD, MAX_SYSTEMS,
        tuple(sorted(selected_fw)),
        len(soa_sod_extra),
        len(rbac_matrix_data) if rbac_matrix_data else 0,
        len(registry_df_data) if registry_df_data is not None else 0,
    )

    if (st.session_state.get("_last_cache_key") != _cache_key or
            "findings_cache" not in st.session_state):
        with st.spinner("🔍 Running 18 checks across all identities — this may take a moment for large files..."):
            findings_df, excluded_count, col_warnings = run_audit(
                hr_df_f, sys_df_f,
                SCOPE_START, SCOPE_END,
                DORMANT_DAYS, PASSWORD_EXPIRY_DAYS,
                FUZZY_THRESHOLD, MAX_SYSTEMS,
                selected_fw,
                sod_override=soa_sod_extra if soa_sod_extra else None,
                rbac_matrix=rbac_matrix_data if rbac_matrix_data else None,
                registry_df=registry_df_data,
            )
        st.session_state["findings_cache"]  = findings_df
        st.session_state["excluded_cache"]  = excluded_count
        st.session_state["_last_cache_key"] = _cache_key
    else:
        findings_df    = st.session_state["findings_cache"]
        excluded_count = st.session_state["excluded_cache"]
        col_warnings   = st.session_state.get("col_warnings", [])

    in_scope_n = len(sys_df_f) - excluded_count
    total = len(findings_df)

    # Show missing column warnings prominently
    if col_warnings:
        for w in col_warnings:
            st.warning(w)

    # Scope & doc banner
    doc_names = ", ".join(f.name for f,_ in doc_files) if doc_files else "None uploaded"
    dept_label = f"{len(selected_depts)} dept(s): {', '.join(selected_depts)}" if selected_depts else "All departments"

    b1,b2,b3,b4 = st.columns(4)
    b1.success(f"🔒 Scope: {SCOPE_START.strftime('%d %b %Y')} → {SCOPE_END.strftime('%d %b %Y')}")
    b2.success(f"👥 Scanned: {in_scope_n:,} of {len(sys_df_f):,} accounts")
    b3.info(f"🏢 Departments: {dept_label}")
    b4.info(f"📄 Docs: {len(doc_files)} policy/standard file(s)")

    # Scope exclusion warning
    if excluded_count == len(sys_df_f) and len(sys_df_f) > 0:
            st.error(
                f"⚠️ All {len(sys_df_f):,} accounts were excluded by the scope filter. "
                f"The dates in your System Access file do not fall within "
                f"**{SCOPE_START.strftime('%d %b %Y')} → {SCOPE_END.strftime('%d %b %Y')}**."
            )
            st.markdown("""
**How to fix this:**
1. Check what year your data is from — look at the LastLoginDate or AccountCreatedDate columns in your System Access file
2. Use the **year selector** in the sidebar to match that year
3. Click **Full Year** then **GO** again

For forensic or historical audits going back several years, select the exact year your data covers.
The tool supports up to 15 years back.
            """)
            st.stop()

    # ── RESULTS ──────────────────────────────────────────────────────────────
    st.divider()
    st.markdown("### 📊 Audit results")
    def cnt(col,val): return len(findings_df[findings_df[col]==val]) if total else 0

    m = st.columns(5)
    m[0].metric("Total findings",   total)
    m[1].metric("🔴 Critical",       cnt("Severity","🔴 CRITICAL"))
    m[2].metric("🟠 High",           cnt("Severity","🟠 HIGH"))
    m[3].metric("🟡 Medium",         cnt("Severity","🟡 MEDIUM"))
    m[4].metric("Accounts scanned",  f"{in_scope_n:,}")

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
    tab1,tab2,tab3,tab4,tab5,tab6 = st.tabs([
        "🔎  Findings","🛠️  Remediation","⚖️  Frameworks","📈  Analysis","✍️  Opinion","🎯  Audit Sample"
    ])

    sdf = findings_df.copy()
    sdf["_o"] = sdf["Severity"].map(sev_order).fillna(9)
    sdf = sdf.sort_values("_o").drop(columns="_o")

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

        # ── Collapsed summary table — fast to render ──────────────────────────
        # Show only key columns — no heavy text columns
        summary_cols = [c for c in ["Severity","IssueType","Email","FullName","Department","AccessLevel"]
                        if c in filtered.columns]
        st.dataframe(
            filtered[summary_cols].reset_index(drop=True),
            use_container_width=True,
            hide_index=True,
            height=min(400, 45 + len(filtered) * 35),
            column_config={
                "Severity":   st.column_config.TextColumn("Severity",    width="small"),
                "IssueType":  st.column_config.TextColumn("Issue",       width="medium"),
                "Email":      st.column_config.TextColumn("Email",       width="medium"),
                "FullName":   st.column_config.TextColumn("Name",        width="small"),
                "Department": st.column_config.TextColumn("Department",  width="small"),
                "AccessLevel":st.column_config.TextColumn("Access",      width="small"),
            }
        )

        # ── Expandable detail per finding ─────────────────────────────────────
        st.markdown("#### Finding details")
        st.caption("Expand any finding to see the full detail, risk statement and remediation steps.")

        # Show max 100 at a time to prevent crashes
        MAX_EXPAND = 100
        show_df = filtered.head(MAX_EXPAND)
        if len(filtered) > MAX_EXPAND:
            st.warning(f"Showing first {MAX_EXPAND} of {len(filtered):,} findings. Use the filters above to narrow down.")

        for _, row in show_df.iterrows():
            sev   = str(row.get("Severity",""))
            itype = str(row.get("IssueType",""))
            email = str(row.get("Email",""))
            dept  = str(row.get("Department",""))
            ico   = "🔴" if "CRITICAL" in sev else ("🟠" if "HIGH" in sev else "🟡")
            label = f"{ico} {itype} — {email} | {dept}"
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

    with tab3:
        if doc_files:
            uploaded_doc_names = ", ".join(f.name for f,_ in doc_files)
            st.info(f"📄 Documents parsed: **{uploaded_doc_names}** — findings are referenced against these documents and hardcoded framework mappings.")
        fw_cols = [c for c in ["Severity","IssueType","Email","FullName","Department",
                                "SOX Reference","ISO 27001 Ref","GDPR Reference","PCI-DSS Reference"]
                   if c in sdf.columns]
        st.dataframe(sdf[fw_cols], use_container_width=True, hide_index=True, height=420)

    with tab4:
        st.markdown("### Risk analysis")

        # ── Row 1: Pie chart + severity table + issue type table ─────────────
        pc1, pc2, pc3 = st.columns([2, 1, 1])

        with pc1:
            st.markdown("**Overall risk gap — severity distribution**")
            # Build severity counts
            sev_map = {"🔴 CRITICAL": 0, "🟠 HIGH": 0, "🟡 MEDIUM": 0}
            for sev in findings_df["Severity"]:
                if sev in sev_map:
                    sev_map[sev] += 1
            sev_labels = [s.split(" ", 1)[1] for s in sev_map.keys()]
            sev_vals   = list(sev_map.values())
            sev_colors = ["#E24B4A","#EF9F27","#F9CB42"]

            # Build pie chart using plotly if available, else native bar
            try:
                import plotly.graph_objects as go
                fig = go.Figure(data=[go.Pie(
                    labels=sev_labels,
                    values=sev_vals,
                    hole=0.45,
                    marker=dict(colors=sev_colors,
                                line=dict(color="#ffffff", width=2)),
                    textinfo="label+percent",
                    textfont=dict(size=13),
                    hovertemplate="%{label}<br>%{value} findings<br>%{percent}<extra></extra>",
                )])
                fig.update_layout(
                    margin=dict(t=20, b=20, l=20, r=20),
                    height=280,
                    showlegend=False,
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)",
                    font=dict(family="Arial", color="#404040"),
                    annotations=[dict(
                        text=f"<b>{total}</b><br>findings",
                        x=0.5, y=0.5, font_size=14,
                        showarrow=False, font_color="#1F3864"
                    )]
                )
                st.plotly_chart(fig, use_container_width=True)
            except ImportError:
                # Fallback: simple bar chart
                sev_df = pd.DataFrame({"Severity": sev_labels, "Count": sev_vals})
                st.bar_chart(sev_df.set_index("Severity"))

        with pc2:
            st.markdown("**By severity**")
            bsev = findings_df["Severity"].value_counts().reset_index()
            bsev.columns = ["Severity","Count"]
            # Add percentage column
            bsev["% of total"] = (bsev["Count"] / total * 100).round(1).astype(str) + "%"
            st.dataframe(bsev, use_container_width=True, hide_index=True, height=260)

        with pc3:
            st.markdown("**Error rate**")
            error_rate = round(total / in_scope_n * 100, 1) if in_scope_n > 0 else 0
            crit_rate  = round(cnt("Severity","🔴 CRITICAL") / in_scope_n * 100, 1) if in_scope_n > 0 else 0
            st.metric("Overall error rate",  f"{error_rate}%", help="Findings as % of accounts scanned")
            st.metric("Critical error rate", f"{crit_rate}%",  help="Critical findings as % of accounts scanned")
            st.metric("Accounts clean",
                f"{in_scope_n - total:,}",
                help="Accounts with no findings")
            st.metric("Accounts with issues",
                f"{min(total, in_scope_n):,}",
                help="Note: one account can have multiple findings")

        st.divider()

        # ── Row 2: Department risk heatmap ────────────────────────────────────
        if "Department" in findings_df.columns:
            st.markdown("**Department risk breakdown**")
            st.caption("Shows which departments have the most findings by severity — use this to prioritise your fieldwork.")

            dept_crit  = findings_df[findings_df["Severity"]=="🔴 CRITICAL"]["Department"].value_counts()
            dept_high  = findings_df[findings_df["Severity"]=="🟠 HIGH"]["Department"].value_counts()
            dept_med   = findings_df[findings_df["Severity"]=="🟡 MEDIUM"]["Department"].value_counts()
            all_depts_f= sorted(findings_df["Department"].dropna().unique())

            dept_heat = pd.DataFrame({
                "Department": all_depts_f,
                "🔴 Critical": [dept_crit.get(d, 0) for d in all_depts_f],
                "🟠 High":     [dept_high.get(d, 0) for d in all_depts_f],
                "🟡 Medium":   [dept_med.get(d, 0)  for d in all_depts_f],
            })
            dept_heat["Total"] = dept_heat["🔴 Critical"] + dept_heat["🟠 High"] + dept_heat["🟡 Medium"]
            dept_heat = dept_heat.sort_values("Total", ascending=False)

            # Risk rating
            def risk_rating(row):
                if row["🔴 Critical"] >= 5:  return "🔴 High Risk"
                if row["🔴 Critical"] >= 1:  return "🟠 Elevated"
                if row["🟠 High"] >= 5:      return "🟠 Elevated"
                if row["🟠 High"] >= 1:      return "🟡 Moderate"
                return "🟢 Low Risk"
            dept_heat["Risk Rating"] = dept_heat.apply(risk_rating, axis=1)

            st.dataframe(
                dept_heat,
                use_container_width=True,
                hide_index=True,
                height=min(50 + len(dept_heat) * 35, 480),
                column_config={
                    "Department":   st.column_config.TextColumn("Department",   width="medium"),
                    "🔴 Critical":  st.column_config.NumberColumn("🔴 Critical", width="small"),
                    "🟠 High":      st.column_config.NumberColumn("🟠 High",     width="small"),
                    "🟡 Medium":    st.column_config.NumberColumn("🟡 Medium",   width="small"),
                    "Total":        st.column_config.NumberColumn("Total",       width="small"),
                    "Risk Rating":  st.column_config.TextColumn("Risk Rating",   width="medium"),
                }
            )

            # Department risk pie chart
            st.markdown("**Top 8 departments by total findings**")
            top8 = dept_heat.head(8)
            try:
                import plotly.graph_objects as go
                fig2 = go.Figure(data=[go.Bar(
                    x=top8["Department"].tolist(),
                    y=top8["🔴 Critical"].tolist(),
                    name="Critical",
                    marker_color="#E24B4A",
                )])
                fig2.add_trace(go.Bar(
                    x=top8["Department"].tolist(),
                    y=top8["🟠 High"].tolist(),
                    name="High",
                    marker_color="#EF9F27",
                ))
                fig2.add_trace(go.Bar(
                    x=top8["Department"].tolist(),
                    y=top8["🟡 Medium"].tolist(),
                    name="Medium",
                    marker_color="#F9CB42",
                ))
                fig2.update_layout(
                    barmode="stack",
                    height=320,
                    margin=dict(t=20, b=60, l=40, r=20),
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)",
                    font=dict(family="Arial", color="#404040"),
                    legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
                    xaxis=dict(tickangle=-30, gridcolor="rgba(0,0,0,0.05)"),
                    yaxis=dict(gridcolor="rgba(0,0,0,0.05)", title="Findings"),
                )
                st.plotly_chart(fig2, use_container_width=True)
            except ImportError:
                st.bar_chart(top8.set_index("Department")[["🔴 Critical","🟠 High","🟡 Medium"]])

        st.divider()

        # ── Row 3: Issue type breakdown + dormant chart ────────────────────────
        r3a, r3b = st.columns(2)
        with r3a:
            st.markdown("**By issue type**")
            btyp = findings_df["IssueType"].value_counts().reset_index()
            btyp.columns = ["Issue Type","Count"]
            btyp["% of total"] = (btyp["Count"] / total * 100).round(1).astype(str) + "%"
            st.dataframe(btyp, use_container_width=True, hide_index=True, height=360)

        with r3b:
            if "DaysInactive" in findings_df.columns:
                dom = findings_df[
                    findings_df["DaysInactive"].notna() &
                    (findings_df["IssueType"] == "Dormant Account")
                ].copy()
                if not dom.empty:
                    st.markdown("**Dormant account inactivity distribution**")
                    # Bucket into ranges
                    def bucket(d):
                        if d <= 180:  return "91–180 days"
                        if d <= 365:  return "181–365 days"
                        if d <= 730:  return "1–2 years"
                        return "2+ years"
                    dom["Range"] = dom["DaysInactive"].apply(bucket)
                    buckets = dom["Range"].value_counts().reindex(
                        ["91–180 days","181–365 days","1–2 years","2+ years"], fill_value=0
                    ).reset_index()
                    buckets.columns = ["Inactivity range","Count"]
                    try:
                        import plotly.graph_objects as go
                        fig3 = go.Figure(data=[go.Bar(
                            x=buckets["Inactivity range"].tolist(),
                            y=buckets["Count"].tolist(),
                            marker_color=["#F9CB42","#EF9F27","#E24B4A","#A32D2D"],
                            text=buckets["Count"].tolist(),
                            textposition="outside",
                        )])
                        fig3.update_layout(
                            height=300, margin=dict(t=30,b=40,l=40,r=20),
                            paper_bgcolor="rgba(0,0,0,0)",
                            plot_bgcolor="rgba(0,0,0,0)",
                            font=dict(family="Arial",color="#404040"),
                            yaxis=dict(gridcolor="rgba(0,0,0,0.05)"),
                            showlegend=False,
                        )
                        st.plotly_chart(fig3, use_container_width=True)
                    except ImportError:
                        st.bar_chart(buckets.set_index("Inactivity range"))

    with tab5:
        st.markdown("#### Audit opinion")
        oc1, oc2 = st.columns([2,1])
        with oc2:
            use_ai = st.checkbox(
                "Use AI to generate opinion",
                value=True,
                help="Uses AI to write a professional 3-section audit memo. Falls back to rule-based if unavailable."
            )
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
                    st.session_state["ai_opinion"] = generate_opinion(findings_df, meta, SCOPE_START, SCOPE_END, len(sys_df_f), in_scope_n)

            if "ai_opinion" in st.session_state:
                st.markdown("---")
                st.markdown(st.session_state["ai_opinion"])
                st.markdown("---")
                st.caption("⚠️ AI-generated content. Review and edit before any formal use. The responsible auditor must approve this opinion.")
        else:
            opinion = generate_opinion(findings_df, meta, SCOPE_START, SCOPE_END, len(sys_df_f), in_scope_n)
            edited_opinion = st.text_area("Draft opinion (edit before use):",
                                          value=opinion, height=440, label_visibility="visible")
            st.caption("This draft is generated from finding counts and severity. It must be reviewed and approved before formal use.")
        if doc_files:
            st.caption(f"Documents uploaded: {', '.join(f.name for f,_ in doc_files)}. Reference these in your final opinion.")

    with tab6:
        st.markdown("#### Audit sample — 25 items for external auditors")
        st.caption(
            "External auditors always request a manual sample even after a full population test. "
            "This generates a prioritised 25-item sample: Critical first, then High, then random Medium. "
            "Each row includes a test instruction and evidence checklist for the external team."
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

            # Export sample to Excel
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
            st.caption("Hand this file to the external audit team. Each row has a test instruction, evidence requirement, and columns for their testing notes.")
        else:
            st.info("No findings to sample.")

    # ── EXPORT ───────────────────────────────────────────────────────────────
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
        st.metric("Report sheets", "8+")

elif uploaded_files and (not hr_file or not sys_file):
    if not hr_file:
        st.warning("⚠️ HR Master not identified. Rename your file to include `HR_Master` or use the manual selector above.")
    if not sys_file:
        st.warning("⚠️ System Access file not identified. Rename your file to include `System_Access` or use the manual selector above.")

else:
    # ── UPLOAD PROMPT ─────────────────────────────────────────────────────────
    st.info(
        "📂 Upload your HR Master and System Access files above to begin the audit. "
        "You can also add your SOA, RBAC Matrix, Privileged User Registry and policy documents "
        "to the same upload zone — the tool detects each one automatically."
    )
    st.caption(
        "New here? Visit the **How to Use** page in the sidebar for a full step-by-step walkthrough, "
        "column reference and document naming guide."
    )

