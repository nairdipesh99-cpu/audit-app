import streamlit as st
import pandas as pd
import io
from datetime import datetime, date
from engine import run_audit, to_excel_bytes, detect_doc_type, generate_ai_opinion
import identity_risk 

# SESSION STATE
today = date.today()
if "locked" not in st.session_state: st.session_state["locked"] = False

# SIDEBAR
with st.sidebar:
    st.title("Settings")
    client = st.text_input("Client", "Client Name")
    start = st.date_input("Start Date", date(today.year-1, 1, 1))
    end = st.date_input("End Date", date(today.year-1, 12, 31))
    dormant = st.slider("Dormant Days", 30, 180, 90)
    if st.button("▶ RUN AUDIT", use_container_width=True, type="primary"):
        st.session_state["locked"] = True

# MAIN UI
st.title("80 — IAM Audit Tool")
uploaded_files = st.file_uploader("Upload HR Master & System Access Files", accept_multiple_files=True)

hr_file, sys_file = None, None
if uploaded_files:
    for f in uploaded_files:
        dtype = detect_doc_type(f)
        if dtype == "hr_master": hr_file = f
        elif dtype == "system_access": sys_file = f

if hr_file and sys_file and st.session_state["locked"]:
    hr_df = pd.read_excel(hr_file) if not hr_file.name.endswith(".csv") else pd.read_csv(hr_file)
    sys_df = pd.read_excel(sys_file) if not sys_file.name.endswith(".csv") else pd.read_csv(sys_file)

    with st.spinner("Processing Data..."):
        # Run Restored Audit Logic
        findings_df, _, _ = run_audit(hr_df, sys_df, start, end, dormant, 90, 88, 3, [])
        
        # Identity Risk Analysis
        findings_df = identity_risk.compute_irs(findings_df, end)
        risk_register = identity_risk.build_risk_register(findings_df)
        stats = identity_risk.irs_summary_stats(risk_register)

    # Dashboard
    st.markdown("### 📊 Metrics")
    c1, c2, c3 = st.columns(3)
    c1.metric("Findings", len(findings_df))
    c2.metric("Avg Risk Score", stats.get("mean_score", 0))
    c3.metric("Critical Users", stats.get("critical_count", 0))

    tab1, tab2 = st.tabs(["🔎 Findings", "🛡️ Risk Register"])
    with tab1:
        st.dataframe(findings_df, use_container_width=True)
    with tab2:
        if not risk_register.empty:
            st.dataframe(risk_register.style.background_gradient(subset=["Risk_Score"], cmap="YlOrRd"), use_container_width=True)

    if st.button("📦 Export Report"):
        xlsx = to_excel_bytes(findings_df, hr_df, sys_df, start, end, 0, {"client": client}, "")
        st.download_button("Download Excel", xlsx, f"Audit_{client}.xlsx")
else:
    st.info("Upload your files and click 'RUN AUDIT' in the sidebar.")
