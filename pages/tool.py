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
import identity_risk 
from components import inject_css, render_header, render_sidebar_brand, led_status_bar, led_dot, stat_card

# ─────────────────────────────────────────────────────────────────────────────
# SESSION STATE
# ─────────────────────────────────────────────────────────────────────────────
today = date.today()
_default_year = today.year - 1
if "ss_start"  not in st.session_state: st.session_state["ss_start"]  = date(_default_year, 1, 1)
if "ss_end"    not in st.session_state: st.session_state["ss_end"]    = date(_default_year, 12, 31)
if "locked"    not in st.session_state: st.session_state["locked"]    = False

SCOPE_START = st.session_state["ss_start"]
SCOPE_END   = st.session_state["ss_end"]

def _set_year():
    y = st.session_state["audit_year_sel"]
    st.session_state.update(ss_start=date(y,1,1), ss_end=date(y,12,31), locked=False)

def _last_q():
    q=(today.month-1)//3; me=[31,28,31,30,31,30,31,31,30,31,30,31]
    if q==0: qs,qe=date(today.year-1,10,1),date(today.year-1,12,31)
    else: qs,qe=date(today.year,(q-1)*3+1,1),date(today.year,q*3,me[q*3-1])
    st.session_state.update(ss_start=qs,ss_end=qe,locked=False)

def _date_chg(): st.session_state["locked"] = False
def _go(): st.session_state["locked"] = True

# ─────────────────────────────────────────────────────────────────────────────
# SIDEBAR
# ─────────────────────────────────────────────────────────────────────────────
with st.sidebar:
    render_sidebar_brand()
    st.divider()
    st.markdown("#### Engagement details")
    _client  = st.text_input("Client", placeholder="Waitrose & Partners", key="meta_client")
    _ref     = st.text_input("Reference", placeholder="IAR-2026-RET", key="meta_ref")
    _auditor = st.text_input("Auditor", placeholder="Your Name", key="meta_auditor")
    _std     = st.selectbox("Audit standard", ["ISO 27001:2022","SOX ITGC","PCI-DSS v4.0","GDPR Art.32"], key="meta_standard")
    
    meta = {
        "client": _client or "Not specified", 
        "ref": _ref or "Not specified", 
        "auditor": _auditor or "Not specified", 
        "standard": _std
    }

    st.divider()
    st.markdown("#### Audit scope")
    _yr_opts = list(range(today.year, today.year - 16, -1))
    st.selectbox("Audit year", options=_yr_opts, index=0, key="audit_year_sel")
    sb1, sb2 = st.columns(2)
    sb1.button("Full Year", use_container_width=True, on_click=_set_year, type="primary")
    sb2.button("Last Quarter", use_container_width=True, on_click=_last_q)
    
    dc1, dc2 = st.columns(2)
    with dc1: st.date_input("From", key="ss_start", on_change=_date_chg)
    with dc2: st.date_input("To", key="ss_end", on_change=_date_chg)

    st.button("▶  GO — Run Audit", use_container_width=True, type="primary", on_click=_go)

    DORMANT_DAYS         = st.slider("Dormant (days)", 30, 365, 90)
    PASSWORD_EXPIRY_DAYS = st.slider("Password expiry (days)", 30, 365, 90)
    FUZZY_THRESHOLD      = st.slider("Fuzzy match %", 70, 99, 88)
    MAX_SYSTEMS          = st.slider("Max systems per user", 2, 10, 3)

# ─────────────────────────────────────────────────────────────────────────────
# MAIN UI
# ─────────────────────────────────────────────────────────────────────────────
render_header()
st.markdown("### 📂 Upload audit documents")
uploaded_files = st.file_uploader("Drop files", accept_multiple_files=True, label_visibility="collapsed")

hr_file, sys_file = None, None
if uploaded_files:
    for f in uploaded_files:
        dtype = detect_doc_type(f)
        if dtype == "hr_master": hr_file = f
        elif dtype == "system_access": sys_file = f

if hr_file and sys_file:
    hr_df = pd.read_excel(hr_file) if not hr_file.name.endswith(".csv") else pd.read_csv(hr_file)
    sys_df = pd.read_excel(sys_file) if not sys_file.name.endswith(".csv") else pd.read_csv(sys_file)

    if st.session_state.get("locked"):
        with st.spinner("🔍 Auditing..."):
            findings_df, excluded_count, _ = run_audit(
                hr_df, sys_df, SCOPE_START, SCOPE_END, 
                DORMANT_DAYS, PASSWORD_EXPIRY_DAYS, FUZZY_THRESHOLD, MAX_SYSTEMS, []
            )
            
            # IDENTITY RISK CALCULATIONS
            findings_df = identity_risk.compute_irs(findings_df, SCOPE_END)
            risk_register = identity_risk.build_risk_register(findings_df)
            irs_stats = identity_risk.irs_summary_stats(risk_register)

        # DASHBOARD
        st.markdown("### 📊 Audit intelligence")
        m = st.columns(5)
        m[0].metric("Total findings", len(findings_df))
        m[2].metric("Avg Risk Score", f"{irs_stats.get('mean_score', 0)}")
        m[4].metric("High Risk Users", irs_stats.get('critical_count', 0))

        tab1, tab2, tab5 = st.tabs(["🔎 Findings", "🛡️ Risk Register", "✍️ Opinion"])

        with tab1:
            # Display findings with the computed score column
            st.dataframe(findings_df, use_container_width=True)

        with tab2:
            st.markdown("### 🛡️ Identity Risk Register")
            if not risk_register.empty:
                # Synchronizing column names: We use 'Risk_Score' in the styling
                # Ensuring the code is resilient with a simple check
                target_col = "Risk_Score" if "Risk_Score" in risk_register.columns else risk_register.columns[-1]
                
                st.dataframe(
                    risk_register.style.background_gradient(subset=[target_col], cmap="YlOrRd"),
                    use_container_width=True, hide_index=True
                )

        with tab5:
            if st.button("Generate AI Opinion"):
                st.write(generate_ai_opinion(findings_df, meta))

        if st.button("📦 Export Workpaper"):
            xlsx = to_excel_bytes(findings_df, hr_df, sys_df, SCOPE_START, SCOPE_END, 0, meta, "")
            st.download_button("📥 Download", data=xlsx, file_name="Audit_Report.xlsx")
else:
    st.info("Upload files to begin.")
