"""80 — IAM Audit Tool | Use the Tool page"""

import streamlit as st
import pandas as pd
import io
from datetime import datetime, date, timedelta
from engine import (
    run_audit, generate_opinion, generate_claude_opinion,
    to_excel_bytes, generate_audit_sample, add_sample_sheet,
    ocr_via_claude, load_sod_matrix,
    extract_text, detect_doc_type, parse_soa_sod_rules,
    sev_order, SOD_RULES,
)
from components import render_header, render_sidebar_brand

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
with st.sidebar:
    render_sidebar_brand()
    st.divider()

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
    _yr_opts = [today.year-2, today.year-1, today.year]
    st.selectbox(
        "Audit year",
        options=_yr_opts, index=1,
        format_func=lambda y: f"{y}  ← previous" if y==today.year-1 else (f"{y}  ← current" if y==today.year else str(y)),
        key="audit_year_sel",
    )
    sb1,sb2 = st.columns(2)
    sb1.button("Full Year",    use_container_width=True, on_click=_set_year, type="primary")
    sb2.button("Last Quarter", use_container_width=True, on_click=_last_q)
    sb1.button("Last 6 Mo.",   use_container_width=True, on_click=_last_6)
    sb2.button("This Month",   use_container_width=True, on_click=_this_month)
    dc1,dc2 = st.columns(2)
    with dc1: st.date_input("From", key="ss_start", on_change=_date_chg)
    with dc2: st.date_input("To",   key="ss_end",   on_change=_date_chg)

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

    st.divider()
    with st.expander("Column reference"):
        st.markdown("""
**HR Master** *(required)*
`Email` `FullName` `Department`

**HR Master** *(recommended)*
`EmploymentStatus` `ContractType` `TerminationDate`

**System Access** *(required)*
`Email` `AccessLevel`

**System Access** *(recommended)*
`LastLoginDate` `PasswordLastSet` `AccountCreatedDate` `MFA` `SystemName`
        """)


# ─────────────────────────────────────────────────────────────────────────────
#  DOCUMENT UPLOAD ZONE — single intelligent zone for all documents
# ─────────────────────────────────────────────────────────────────────────────
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
                "standard":"📄","other":"📎"}.get(dtype,"📎")
        label = {"hr_master":"HR Master","system_access":"System Access",
                 "soa":"SOA / Standard","access_policy":"Access Policy",
                 "jml_procedure":"JML Procedure","risk_register":"Risk Register",
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
with st.expander("📸 Legacy system upload — screenshot or PDF (OCR via Claude Vision)", expanded=False):
    st.caption(
        "For old systems that only produce screenshots or PDFs. "
        "Upload an image or PDF — Claude Vision extracts the account data and converts it to the right format automatically."
    )
    ocr_file = st.file_uploader(
        "Upload screenshot or PDF of legacy system report",
        type=["png","jpg","jpeg","pdf"],
        key="ocr_upload",
        label_visibility="collapsed",
    )
    if ocr_file:
        if st.button("🔍 Extract data from image", type="primary"):
            with st.spinner("Sending to Claude Vision — extracting account data..."):
                ocr_df, ocr_err = ocr_via_claude(ocr_file)
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
soa_sod_extra = {}   # SoD rules extracted from uploaded SOA/policy

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
                # Try to extract SoD rules from SOA or dedicated SoD matrix
                if dtype in ("soa","access_policy","sod_matrix","other"):
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

    # Run audit
    with st.spinner("🔍 Running 15 checks across all identities..."):
        findings_df, excluded_count = run_audit(
            hr_df_f, sys_df_f,
            SCOPE_START, SCOPE_END,
            DORMANT_DAYS, PASSWORD_EXPIRY_DAYS,
            FUZZY_THRESHOLD, MAX_SYSTEMS,
            selected_fw,
            sod_override=soa_sod_extra if soa_sod_extra else None,
        )

    in_scope_n = len(sys_df_f) - excluded_count
    total = len(findings_df)

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
            f"Your data dates do not fall within **{SCOPE_START.year}**. "
            f"Use the year selector in the sidebar — try **{today.year - 1}** for last year's data."
        )
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
        t1a,t1b = st.columns([3,1])
        with t1a:
            ft = st.multiselect("Issue type", options=sorted(findings_df["IssueType"].unique()),
                                default=sorted(findings_df["IssueType"].unique()))
        with t1b:
            sf = st.selectbox("Severity", ["All","🔴 CRITICAL","🟠 HIGH","🟡 MEDIUM"])
        filtered = sdf[sdf["IssueType"].isin(ft)]
        if sf != "All": filtered = filtered[filtered["Severity"]==sf]
        disp = [c for c in ["Severity","IssueType","Email","FullName","Department",
                             "AccessLevel","DaysInactive","DaysPostTermination","Detail"]
                if c in filtered.columns]
        st.dataframe(filtered[disp], use_container_width=True, hide_index=True, height=420,
            column_config={
                "Severity":            st.column_config.TextColumn("Severity",       width="small"),
                "IssueType":           st.column_config.TextColumn("Issue Type",     width="medium"),
                "Detail":              st.column_config.TextColumn("Detail",         width="large"),
                "DaysInactive":        st.column_config.NumberColumn("Days Idle",    width="small"),
                "DaysPostTermination": st.column_config.NumberColumn("Post-Term",    width="small"),
            })
        st.caption(f"Showing {len(filtered):,} of {total:,} findings")

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
        an1,an2,an3 = st.columns(3)
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
            dom = findings_df[findings_df["DaysInactive"].notna() & (findings_df["IssueType"]=="Dormant Account")]
            if not dom.empty:
                st.markdown("**Dormant account inactivity (days)**")
                st.bar_chart(dom.set_index("Email")["DaysInactive"])

    with tab5:
        st.markdown("#### Audit opinion")
        oc1, oc2 = st.columns([2,1])
        with oc2:
            use_claude = st.checkbox(
                "Use Claude AI to write opinion",
                value=True,
                help="Uses the Claude API to write a professional 3-section audit memo. Falls back to rule-based if unavailable."
            )
        with oc1:
            if use_claude:
                st.caption("Claude will write a professional audit memo with Executive Summary, Key Findings, and Formal Opinion.")
            else:
                st.caption("Rule-based opinion generated from finding counts and severity levels.")

        if use_claude:
            if st.button("✍️ Generate AI Audit Opinion", type="primary", use_container_width=True):
                with st.spinner("Claude is writing your audit memo..."):
                    claude_opinion, success = generate_claude_opinion(
                        findings_df, meta, SCOPE_START, SCOPE_END, len(sys_df_f), in_scope_n
                    )
                if success and claude_opinion:
                    st.session_state["claude_opinion"] = claude_opinion
                else:
                    st.warning("Claude API unavailable — showing rule-based opinion instead.")
                    st.session_state["claude_opinion"] = generate_opinion(findings_df, meta, SCOPE_START, SCOPE_END, len(sys_df_f), in_scope_n)

            if "claude_opinion" in st.session_state:
                st.markdown("---")
                st.markdown(st.session_state["claude_opinion"])
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
    # ── LANDING PAGE ─────────────────────────────────────────────────────────
    st.markdown("### How to use this tool")
    l1,l2,l3,l4 = st.columns(4)
    l1.info("**① Upload documents**\n\nDrop all your audit files into the single upload zone — HR Master, System Access list, SOA, policies, procedures. The tool auto-detects each one.")
    l2.info("**② Confirm population**\n\nConfirm the HR and system extracts are complete and unfiltered. This becomes part of your workpaper evidence.")
    l3.info("**③ Set scope & run**\n\nSelect the audit year (default: previous year). Pick specific departments if needed. Click GO to lock and scan.")
    l4.info("**④ Download report**\n\nGet a workpaper-ready Excel: engagement cover, audit opinion, all findings with 4-step remediation, compliance framework references.")

    st.divider()
    st.markdown("### Documents the tool uses")
    d1,d2 = st.columns(2)
    with d1:
        st.markdown("**Required for audit checks to run:**")
        st.markdown("- `HR_Master_2025.xlsx` — employee list with EmploymentStatus, ContractType, TerminationDate")
        st.markdown("- `System_Access_2025.xlsx` — system accounts with AccessLevel, LastLoginDate, MFA, PasswordLastSet")
    with d2:
        st.markdown("**Optional — enriches the findings:**")
        st.markdown("- `SOA_ISO27001.xlsx` — Statement of Applicability, SoD rules extracted automatically")
        st.markdown("- `Access_Control_Policy.pdf` — cited in framework references tab")
        st.markdown("- `JML_Procedure.pdf` — cited in terminated/orphaned findings")
        st.markdown("- `Risk_Register.xlsx` — gives context on known vs new risks")

    st.divider()
    st.markdown("### 15 automated checks")
    ch1,ch2,ch3 = st.columns(3)
    for i,(sev,name,desc) in enumerate([
        ("🔴 Critical","Orphaned accounts",            "Email in system, no HR record"),
        ("🔴 Critical","Terminated with active access","HR shows leaver, account still enabled"),
        ("🔴 Critical","Post-termination login",       "Logged in after leaving — potential breach"),
        ("🔴 Critical","SoD violations",              "Can initiate AND approve — fraud risk"),
        ("🟠 High",    "Dormant accounts",            "No login in 90+ days"),
        ("🟠 High",    "Privilege creep",             "4+ roles from multiple transfers"),
        ("🟠 High",    "Generic / shared accounts",   "admin@, helpdesk@ — no audit trail"),
        ("🟠 High",    "Super-user outside IT",       "Admin rights for non-IT users"),
        ("🟠 High",    "MFA not enabled",             "Single password = full access"),
        ("🟠 High",    "Contractor without expiry",   "No end-date — access never expires"),
        ("🟡 Medium",  "Service accounts",            "svc_, batch_ — no named owner"),
        ("🟡 Medium",  "Password never expired",      "Stale credentials — breach vector"),
        ("🟡 Medium",  "Duplicate accounts",          "Same person, multiple IDs"),
        ("🟡 Medium",  "Excessive system access",     "More systems than role justifies"),
        ("🟡 Medium",  "Near-match emails",           "Typos, aliases, impersonation"),
    ]):
        [ch1,ch2,ch3][i%3].markdown(f"**{sev}** — **{name}:** {desc}")

