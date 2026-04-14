import streamlit as st
import pandas as pd
import io
from datetime import datetime, date, timedelta
from engine import (
    run_audit, generate_opinion, generate_ai_opinion,
    to_excel_bytes, detect_doc_type
)
import identity_risk 

# SESSION STATE
today = date.today()
if "ss_start" not in st.session_state: st.session_state["ss_start"] = date(today.year-1, 1, 1)
if "ss_end"   not in st.session_state: st.session_state["ss_end"]   = date(today.year-1, 12, 31)
if "locked"   not in st.session_state: st.session_state["locked"]   = False

# SIDEBAR
with st.sidebar:
    st.title("Audit Settings")
    _client = st.text_input("Client", "Waitrose")
    st.date_input("From", key="ss_start")
    st.date_input("To", key="ss_end")
    if st.button("▶ RUN AUDIT", use_container_width=True, type="primary"):
        st.session_state["locked"] = True

# MAIN UI
st.title("📂 Audit Documents")
uploaded_files = st.file_uploader("Upload HR and System Files", accept_multiple_files=True)

hr_file, sys_file = None, None
if uploaded_files:
    for f in uploaded_files:
        dtype = detect_doc_type(f)
        if dtype == "hr_master": hr_file = f
        elif dtype == "system_access": sys_file = f

if hr_file and sys_file and st.session_state["locked"]:
    hr_df = pd.read_excel(hr_file) if not hr_file.name.endswith(".csv") else pd.read_csv(hr_file)
    sys_df = pd.read_excel(sys_file) if not sys_file.name.endswith(".csv") else pd.read_csv(sys_file)

    with st.spinner("Analyzing..."):
        findings_df, _, _ = run_audit(hr_df, sys_df, st.session_state["ss_start"], st.session_state["ss_end"], 90, 90, 88, 3, [])
        
        # Risk Calculations
        findings_df = identity_risk.compute_irs(findings_df, st.session_state["ss_end"])
        risk_register = identity_risk.build_risk_register(findings_df)
        irs_stats = identity_risk.irs_summary_stats(risk_register)

    # Dashboard
    st.markdown("### 📊 Results")
    m1, m2, m3 = st.columns(3)
    m1.metric("Findings", len(findings_df))
    m2.metric("Avg Risk Score", irs_stats.get("mean_score", 0))
    m3.metric("Critical Users", irs_stats.get("critical_count", 0))

    t1, t2 = st.tabs(["Findings", "Risk Register"])
    with t1: st.dataframe(findings_df, use_container_width=True)
    with t2: st.dataframe(risk_register.style.background_gradient(subset=["Risk_Score"], cmap="YlOrRd"), use_container_width=True)

    if st.button("📦 Export Excel"):
        xlsx = to_excel_bytes(findings_df, hr_df, sys_df, st.session_state["ss_start"], st.session_state["ss_end"], 0, {"client":_client}, "")
        st.download_button("Download Report", xlsx, "Audit_Report.xlsx")
elif not st.session_state["locked"]:
    st.info("Upload files and click RUN AUDIT in the sidebar.")
