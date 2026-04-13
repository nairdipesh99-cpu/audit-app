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
from irs import compute_irs
from components import inject_css, render_header, render_sidebar_brand, led_status_bar, led_dot

# ─────────────────────────────────────────────────────────────────────────────
#  SESSION STATE
# ─────────────────────────────────────────────────────────────────────────────
today = date.today()
_default_year = today.year - 1
if "ss_start"  not in st.session_state: st.session_state["ss_start"]  = date(_default_year, 1, 1)
if "ss_end"    not in st.session_state: st.session_state["ss_end"]    = date(_default_year, 12, 31)
if "locked"    not in st.session_state: st.session_state["locked"]    = False
if "confirmed" not in st.session_state: st.session_state["confirmed"] = False

# Module-level defaults
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
    if uploaded_file is None: return ""
    name = uploaded_file.name.lower()
    try:
        if name.endswith(".txt"): return uploaded_file.read().decode("utf-8", errors="ignore")[:max_chars]
        elif name.endswith(".pdf"):
            import pypdf
            reader = pypdf.PdfReader(uploaded_file)
            return " ".join(p.extract_text() or "" for p in reader.pages[:10])[:max_chars]
        elif name.endswith(".docx"):
            import docx
            doc = docx.Document(uploaded_file)
            return " ".join(p.text for p in doc.paragraphs)[:max_chars]
        elif name.endswith((".xlsx",".xls")):
            df = pd.read_excel(uploaded_file, sheet_name=None)
            return " ".join(sheet_df.to_string(index=False) for sheet_df in df.values())[:max_chars]
        elif name.endswith(".csv"):
            return pd.read_csv(uploaded_file).to_string(index=False)[:max_chars]
    except Exception as e: return f"[Could not parse {uploaded_file.name}: {e}]"
    return ""

def detect_doc_type(f):
    if f is None: return "other"
    name = f.name.lower()
    if any(k in name for k in ["hr_master","employee","staff_list"]): return "hr_master"
    if any(k in name for k in ["system_access","user_access","ual"]): return "system_access"
    if any(k in name for k in ["soa","annex_a"]): return "soa"
    if any(k in name for k in ["access_policy","access_control"]): return "access_policy"
    if any(k in name for k in ["jml","joiner","mover","leaver"]): return "jml_procedure"
    if any(k in name for k in ["rbac","role_matrix"]): return "rbac_matrix"
    if any(k in name for k in ["privileged","priv_register"]): return "privileged_registry"
    return "other"

def parse_soa_sod_rules(soa_text):
    import re
    rules = {}
    dept_keywords = ["Finance","IT","HR","Sales","Operations"]
    access_keywords = ["Admin","Finance","Payroll","DBAdmin"]
    for dept in dept_keywords:
        pattern = rf"{dept}[^.\n]{{0,60}}({"|".join(access_keywords)})"
        matches = re.findall(pattern, soa_text, re.IGNORECASE)
        if matches: rules[dept] = list(set(matches))
    return rules

# ─────────────────────────────────────────────────────────────────────────────
#  SIDEBAR
# ─────────────────────────────────────────────────────────────────────────────
with st.sidebar:
    render_sidebar_brand()
    st.divider()
    st.markdown("#### Engagement details")
    _client  = st.text_input("Client", placeholder="Nairs.com Ltd", key="meta_client")
    _ref     = st.text_input("Reference", placeholder="IAR-2025-001", key="meta_ref")
    _auditor = st.text_input("Auditor", placeholder="Your full name", key="meta_auditor")
    _std     = st.selectbox("Audit standard", ["ISO 27001:2022","SOX ITGC","PCI-DSS v4.0","GDPR Art.32"], key="meta_standard")

    st.divider()
    st.markdown("#### Audit scope")
    _yr_opts = list(range(today.year, today.year - 16, -1))
    st.selectbox("Audit year", options=_yr_opts, index=1, key="audit_year_sel")
    sb1, sb2 = st.columns(2)
    sb1.button("Full Year", use_container_width=True, on_click=_set_year, type="primary")
    sb2.button("Last Quarter", use_container_width=True, on_click=_last_q)
    dc1, dc2 = st.columns(2)
    dc1.date_input("From", key="ss_start", on_change=_date_chg)
    dc2.date_input("To", key="ss_end", on_change=_date_chg)
    
    date_err = st.session_state["ss_start"] >= st.session_state["ss_end"]
    st.button("▶  GO — Run Audit", use_container_width=True, type="primary", disabled=date_err, on_click=_go)

    st.divider()
    DORMANT_DAYS         = st.slider("Dormant (days)", 30, 365, 90)
    PASSWORD_EXPIRY_DAYS = st.slider("Password expiry (days)", 30, 365, 90)
    FUZZY_THRESHOLD      = st.slider("Fuzzy match %", 70, 99, 88)
    MAX_SYSTEMS          = st.slider("Max systems per user", 2, 10, 3)

# ─────────────────────────────────────────────────────────────────────────────
#  HEADER + DOCUMENT UPLOAD
# ─────────────────────────────────────────────────────────────────────────────
render_header()
st.markdown("### 📂 Upload audit documents")
uploaded_files = st.file_uploader("Drop documents here", type=["xlsx","xls","csv","pdf","txt","docx"], accept_multiple_files=True, label_visibility="collapsed", key="multi_upload")

hr_file = None
sys_file = None
doc_files = []

if uploaded_files:
    classified = {f.name: detect_doc_type(f) for f in uploaded_files}
    for f in uploaded_files:
        dtype = classified[f.name]
        if dtype == "hr_master" and hr_file is None: hr_file = f
        elif dtype == "system_access" and sys_file is None: sys_file = f
        else: doc_files.append((f, dtype))

with st.expander("📸 Legacy system upload — AI-powered extraction", expanded=False):
    ocr_file = st.file_uploader("Upload screenshot", type=["png","jpg","jpeg","pdf"], key="ocr_upload")
    if ocr_file and st.button("🔍 Extract data from image", type="primary"):
        ocr_df, ocr_err = ocr_via_ai(ocr_file)
        if ocr_df is not None: st.dataframe(ocr_df, use_container_width=True, hide_index=True)

st.divider()

# ─────────────────────────────────────────────────────────────────────────────
#  DOCUMENT INTELLIGENCE
# ─────────────────────────────────────────────────────────────────────────────
doc_context = {}
soa_sod_extra = {}
rbac_matrix_data = {}
registry_df_data = None

if doc_files:
    with st.expander(f"📄 Document intelligence — {len(doc_files)} parsed", expanded=False):
        for f, dtype in doc_files:
            text = extract_text(f)
            doc_context[dtype] = text
            if dtype == "rbac_matrix":
                f.seek(0)
                rules, _ = load_rbac_matrix(f)
                if rules: rbac_matrix_data.update(rules)
            elif dtype == "privileged_registry":
                f.seek(0)
                reg_df, _ = load_privileged_registry(f)
                if reg_df is not None: registry_df_data = reg_df
            elif dtype in ("soa","access_policy","sod_matrix"):
                if f.name.lower().endswith((".xlsx",".xls")):
                    f.seek(0)
                    m_rules, _ = load_sod_matrix(f)
                    if m_rules: soa_sod_extra.update(m_rules)
                extra = parse_soa_sod_rules(text)
                if extra: soa_sod_extra.update(extra)

# ─────────────────────────────────────────────────────────────────────────────
#  MAIN AUDIT FLOW
# ─────────────────────────────────────────────────────────────────────────────
if hr_file and sys_file:
    def read_file(f):
        f.seek(0)
        return pd.read_csv(f) if f.name.endswith(".csv") else pd.read_excel(f)

    hr_df = read_file(hr_file)
    sys_df = read_file(sys_file)

    if not st.session_state.get("confirmed", False):
        st.markdown("### ⚠️ Confirm data completeness")
        if st.button("✅ I confirm — complete population", type="primary", use_container_width=True):
            st.session_state["confirmed"] = True
            st.rerun()
        st.stop()

    if not st.session_state.get("locked", False):
        st.info(f"📅 Scope: {st.session_state['ss_start']} → {st.session_state['ss_end']}. Click GO in sidebar.")
        st.stop()

    _cache_key = (len(hr_df), len(sys_df), str(st.session_state["ss_start"]), str(st.session_state["ss_end"]), DORMANT_DAYS)

    if st.session_state.get("_last_cache_key") != _cache_key:
        with st.spinner("🔍 Running Audit..."):
            findings_df, excluded_count, _ = run_audit(
                hr_df, sys_df, st.session_state["ss_start"], st.session_state["ss_end"],
                DORMANT_DAYS, PASSWORD_EXPIRY_DAYS, FUZZY_THRESHOLD, MAX_SYSTEMS, selected_fw,
                sod_override=soa_sod_extra, rbac_matrix=rbac_matrix_data, registry_df=registry_df_data
            )
            # Add IRS score calculation
            findings_df = compute_irs(findings_df, st.session_state["ss_end"])
            
        st.session_state["findings_cache"] = findings_df
        st.session_state["excluded_cache"] = excluded_count
        st.session_state["_last_cache_key"] = _cache_key
    else:
        findings_df = st.session_state["findings_cache"]
        excluded_count = st.session_state["excluded_cache"]

    st.markdown("### 📊 Audit results")
    m = st.columns(4)
    m[0].metric("Total findings", len(findings_df))
    m[1].metric("Critical", len(findings_df[findings_df["Severity"]=="🔴 CRITICAL"]))
    m[2].metric("High", len(findings_df[findings_df["Severity"]=="🟠 HIGH"]))
    m[3].metric("Avg Risk Score", int(findings_df["identity_risk_score"].mean()) if not findings_df.empty else 0)

    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs(["🔎 Findings","🛠️ Remediation","⚖️ Frameworks","📈 Analysis","✍️ Opinion","🎯 Audit Sample"])

    with tab1:
        # Restore original summary columns + IRS
        summary_cols = ["identity_risk_score", "risk_band", "Severity", "IssueType", "Email", "FullName", "Department"]
        summary_cols = [c for c in summary_cols if c in findings_df.columns]
        
        st.dataframe(
            findings_df[summary_cols].sort_values("identity_risk_score", ascending=False),
            use_container_width=True,
            hide_index=True
        )

        st.markdown("#### Finding details")
        for _, row in findings_df.head(100).iterrows():
            with st.expander(f"{row.get('Severity','')} {row.get('IssueType','')} — {row.get('Email','')}"):
                st.markdown(f"**Finding:** {row.get('Detail','')}")
                st.markdown(f"**Risk Score:** {row.get('identity_risk_score','')} ({row.get('risk_band','')})")
                st.markdown(f"**Remediation:** {row.get('Remediation','')}")
