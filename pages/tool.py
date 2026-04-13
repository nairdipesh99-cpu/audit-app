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
from irs import compute_irs  #
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

# ─────────────────────────────────────────────────────────────────────────────
#  HEADER + UPLOAD
# ─────────────────────────────────────────────────────────────────────────────
render_header()
uploaded_files = st.file_uploader("Upload documents", type=["xlsx","xls","csv","pdf","txt","docx"], accept_multiple_files=True)

# (Simplified detection logic for brevity)
hr_file = None
sys_file = None
doc_files = []
if uploaded_files:
    for f in uploaded_files:
        if "hr" in f.name.lower(): hr_file = f
        elif "sys" in f.name.lower() or "access" in f.name.lower(): sys_file = f
        else: doc_files.append((f, "other"))

# ─────────────────────────────────────────────────────────────────────────────
#  MAIN AUDIT FLOW
# ─────────────────────────────────────────────────────────────────────────────
if hr_file and sys_file:
    hr_df = pd.read_excel(hr_file) if hr_file.name.endswith('.xlsx') else pd.read_csv(hr_file)
    sys_df = pd.read_excel(sys_file) if sys_file.name.endswith('.xlsx') else pd.read_csv(sys_file)

    if st.session_state.get("locked", False):
        # 1. Run Core Audit
        findings_df, excluded_count, _ = run_audit(
            hr_df, sys_df, 
            st.session_state["ss_start"], st.session_state["ss_end"],
            DORMANT_DAYS, PASSWORD_EXPIRY_DAYS, FUZZY_THRESHOLD, MAX_SYSTEMS, selected_fw
        )

        # 2. Run IRS Scoring
        findings_df = compute_irs(findings_df, st.session_state["ss_end"])

        # 3. Results Dashboard
        st.divider()
        avg_risk = int(findings_df["identity_risk_score"].mean()) if not findings_df.empty else 0
        m = st.columns(4)
        m[0].metric("Total Findings", len(findings_df))
        m[1].metric("Avg Risk Score", f"{avg_risk}/100")
        m[2].metric("Critical Band", len(findings_df[findings_df["risk_band"] == "CRITICAL"]) if not findings_df.empty else 0)
        m[3].metric("Accounts Scanned", len(sys_df) - excluded_count)

        # 4. Tabs
        tab1, tab2, tab3 = st.tabs(["🔎 Findings", "📈 Analysis", "✍️ Opinion"])

        with tab1:
            if not findings_df.empty:
                st.markdown("#### 🏆 Identity Risk Leaderboard")
                # Identity Resolution
                id_col = next((c for c in ["Email", "Username", "User"] if c in findings_df.columns), "Email")
                leaderboard = findings_df[[id_col, "identity_risk_score", "risk_band"]].drop_duplicates().sort_values("identity_risk_score", ascending=False).head(5)
                st.table(leaderboard)

                st.divider()
                # Table with Progress Bar for Risk
                st.dataframe(
                    findings_df.reset_index(drop=True),
                    column_config={
                        "identity_risk_score": st.column_config.ProgressColumn("Risk Score", min_value=0, max_value=100),
                        "risk_band": "Risk Band"
                    }
                )
