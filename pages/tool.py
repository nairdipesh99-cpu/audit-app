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
#  HEADER + UPLOAD
# ─────────────────────────────────────────────────────────────────────────────
render_header()
st.markdown("### 📂 Upload audit documents")
uploaded_files = st.file_uploader("Drop documents here", type=["xlsx","xls","csv","pdf","txt","docx"], accept_multiple_files=True, label_visibility="collapsed")

hr_file, sys_file, doc_files = None, None, []
if uploaded_files:
    for f in uploaded_files:
        dtype = detect_doc_type(f)
        if dtype == "hr_master": hr_file = f
        elif dtype == "system_access": sys_file = f
        else: doc_files.append((f, dtype))

# ─────────────────────────────────────────────────────────────────────────────
#  MAIN AUDIT FLOW
# ─────────────────────────────────────────────────────────────────────────────
if hr_file and sys_file:
    hr_df = pd.read_excel(hr_file) if not hr_file.name.endswith('.csv') else pd.read_csv(hr_file)
    sys_df = pd.read_excel(sys_file) if not sys_file.name.endswith('.csv') else pd.read_csv(sys_file)

    if not st.session_state.get("confirmed", False):
        if st.button("✅ I confirm — complete population", type="primary", use_container_width=True):
            st.session_state["confirmed"] = True
            st.rerun()
        st.stop()

    if st.session_state.get("locked", False):
        # 1. RUN ENGINE
        findings_df, excluded_count, _ = run_audit(
            hr_
