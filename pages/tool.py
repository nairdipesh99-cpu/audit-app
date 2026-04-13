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
# NEW: Import Identity Risk Score engine
import irs 
from components import inject_css, render_header, render_sidebar_brand, led_status_bar, led_dot, stat_card

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
#  SIDEBAR
# ─────────────────────────────────────────────────────────────────────────────
with st.sidebar:
    render_sidebar_brand()
    st.divider()

    st.markdown("#### Engagement details")
    _client  = st.text_input("Client",    placeholder="Waitrose & Partners",  key="meta_client")
    _ref     = st.text_input("Reference", placeholder="IAR-2026-RET",  key="meta_ref")
    _auditor = st.text_input("Auditor",   placeholder="Your Name", key="meta_auditor")
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
    st.markdown("#### Audit scope")
    _yr_opts = list(range(today.year, today.year - 16, -1))
    
    st.selectbox("Audit year", options=_yr_opts, index=0, key="audit_year_sel")
    sb1, sb2 = st.columns(2)
    sb1.button("Full Year",    use_container_width=True, on_click=_set_year, type="primary")
    sb2.button("Last Quarter", use_container_width=True, on_click=_last_q)
    
    dc1, dc2 = st.columns(2)
    with dc1: st.date_input("From", key="ss_start", on_change=_date_chg)
    with dc2: st.date_input("To", key="ss_end", on_change=_date_chg)

    date_err = st.session_state["ss_start"] >= st.session_state["ss_end"]
    if date_err: st.error("From must be before To.")
    st.button("▶  GO — Run Audit", use_container_width=True, type="primary",
              disabled=date_err, on_click=_go)

    SCOPE_START = st.session_state["ss_start"]
    SCOPE_END   = st.session_state["ss_end"]

    st.divider()
    st.markdown("#### Detection thresholds")
    DORMANT_DAYS         = st.slider("Dormant (days)",         30, 365, 90)
    PASSWORD_EXPIRY_DAYS = st.slider("Password expiry (days)", 30, 365, 90)
    FUZZY_THRESHOLD      = st.slider("Fuzzy match %",          70,  99, 88)
    MAX_SYSTEMS          = st.slider("Max systems per user",    2,   10,  3)

# ─────────────────────────────────────────────────────────────────────────────
#  HEADER + UPLOAD
# ─────────────────────────────────────────────────────────────────────────────
render_header()

st.markdown("### 📂 Upload audit documents")
uploaded_files = st.file_uploader("Drop documents here", type=["xlsx","xls","csv","pdf","txt","docx"], accept_multiple_files=True, label_visibility="collapsed")

hr_file  = None
sys_file = None
doc_files = []
soa_sod_extra = {}
rbac_matrix_data = {}
registry_df_data = None

if uploaded_files:
    classified = {f.name: detect_doc_type(f) for f in uploaded_files}
    for f in uploaded_files:
        dtype = classified[f.name]
        if dtype == "hr_master": hr_file = f
        elif dtype == "system_access": sys_file = f
        else: doc_files.append((f, dtype))

# ─────────────────────────────────────────────────────────────────────────────
#  AUDIT EXECUTION
# ─────────────────────────────────────────────────────────────────────────────
if hr_file and sys_file:
    hr_df  = pd.read_excel(hr_file) if not hr_file.name.endswith(".csv") else pd.read_csv(hr_file)
    sys_df = pd.read_excel(sys_file) if not sys_file.name.endswith(".csv") else pd.read_csv(sys_file)

    if not st.session_state.get("locked", False):
        st.info("Files loaded. Click GO in the sidebar to run audit.")
        st.stop()

    # Engine Execution
    with st.spinner("🔍 Scanning identities..."):
        findings_df, excluded_count, _col_warnings = run_audit(
            hr_df, sys_df, SCOPE_START, SCOPE_END,
            DORMANT_DAYS, PASSWORD_EXPIRY_DAYS, FUZZY_THRESHOLD, MAX_SYSTEMS, selected_fw
        )
        
        # NEW: Compute Identity Risk Scores (Phase 1)
        findings_df = irs.compute_irs(findings_df, SCOPE_END)
        risk_register = irs.build_risk_register(findings_df)
        irs_stats = irs.irs_summary_stats(risk_register)

    # ── RESULTS DASHBOARD ─────────────────────────────────────────────────────
    st.markdown("### 📊 Audit intelligence")
    
    # Row 1: High Level Counts
    m = st.columns(5)
    m[0].metric("Total findings", len(findings_df))
    m[1].metric("🔴 Critical", len(findings_df[findings_df["Severity"].str.contains("CRITICAL", na=False)]))
    m[2].metric("Avg Risk Score", f"{irs_stats.get('mean_score', 0)}")
    m[3].metric("Risk Band", irs_stats.get("max_score", 0), delta="Max Score", delta_color="inverse")
    m[4].metric("High Risk Users", irs_stats.get("critical_count", 0))

    st.divider()

    # ── TABS ─────────────────────────────────────────────────────────────────
    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
        "🔎 Findings", "🛡️ Risk Register", "⚖️ Frameworks", "📈 Analysis", "✍️ Opinion", "🎯 Audit Sample"
    ])

    with tab1:
        st.dataframe(findings_df[["Severity", "IssueType", "Email", "Department", "identity_risk_score"]], use_container_width=True)

    with tab2:
        st.markdown("### 🛡️ Identity Risk Register")
        st.caption("This register ranks every identity found in the audit by their composite risk score (0-100).")
        
        # Display Risk Register with Color Coding
        st.dataframe(
            risk_register.style.background_gradient(subset=["Risk_Score"], cmap="YlOrRd"),
            use_container_width=True,
            hide_index=True
        )
        
        # Download specialized Risk Register
        csv = risk_register.to_csv(index=False).encode('utf-8')
        st.download_button("📥 Download Risk Register (CSV)", data=csv, file_name="Identity_Risk_Register.csv", mime="text/csv")

    with tab5:
        st.markdown("### ✍️ AI Audit Opinion")
        if st.button("Generate AI Opinion"):
            opinion = generate_ai_opinion(findings_df, meta)
            st.write(opinion)
            st.session_state["opinion_cache"] = opinion

    # ── FINAL EXPORT ──────────────────────────────────────────────────────────
    st.divider()
    if st.button("📦 Generate Final Audit Workpaper (9+ Sheets)"):
        opinion = st.session_state.get("opinion_cache", "AI Opinion not generated.")
        
        # The to_excel_bytes in engine.py should be updated to handle the extra sheet
        xlsx_data = to_excel_bytes(
            findings_df, hr_df, sys_df, 
            SCOPE_START, SCOPE_END, excluded_count, 
            meta, opinion
        )
        
        st.download_button(
            label="📥 Download Workpaper-Ready Excel",
            data=xlsx_data,
            file_name=f"Audit_Report_{meta['client']}_{SCOPE_END.year}.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )

else:
    st.info("Please upload your HR Master and System Access files to begin.")
