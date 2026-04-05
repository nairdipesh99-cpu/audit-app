import streamlit as st
import pandas as pd
from thefuzz import fuzz
import io

st.set_page_config(page_title="Nairs Identity Auditor", layout="wide")
st.title("🛡️ Nairs.com Enterprise Identity Auditor")

# --- FILE UPLOADS ---
col1, col2 = st.columns(2)
with col1:
    hr_file = st.file_uploader("Upload HR Master", type=["xlsx"])
with col2:
    sys_file = st.file_uploader("Upload System Access", type=["xlsx"])

if hr_file and sys_file:
    hr_df = pd.read_excel(hr_file)
    sys_df = pd.read_excel(sys_file)
    
    # Pre-process for speed
    hr_emails = hr_df['Email'].str.lower().tolist()
    hr_lookup = hr_df.set_index(hr_df['Email'].str.lower())[['Department', 'FullName']]
    
    zombies = []
    toxic_access = []

    # --- THE AUDIT BRAIN ---
    with st.spinner("Analyzing 1,000+ identities for Nairs.com..."):
        for _, row in sys_df.iterrows():
            u_email = str(row['Email']).lower()
            u_access = str(row['AccessLevel'])
            
            # 1. CHECK FOR ZOMBIES (Leavers)
            if u_email not in hr_emails:
                row['Issue'] = "CRITICAL: Terminated User / Orphaned Account"
                zombies.append(row)
            else:
                # 2. CHECK FOR TOXIC ACCESS (Mover Risk)
                user_dept = hr_lookup.loc[u_email, 'Department']
                if user_dept == "Sales" and "Admin" in u_access:
                    row['Issue'] = f"RISK: {user_dept} user has {u_access} access"
                    toxic_access.append(row)

    # --- DISPLAY FINDINGS ---
    st.header("📋 Audit Findings Summary")
    c1, c2 = st.columns(2)
    c1.metric("Orphaned Accounts (Zombies)", len(zombies))
    c2.metric("Toxic Access (SOD Risks)", len(toxic_access))

    if zombies:
        st.error("### 🚩 Orphaned Account List")
        st.dataframe(pd.DataFrame(zombies), use_container_width=True)
        
    if toxic_access:
        st.warning("### ⚠️ Toxic Access / Privilege Creep")
        st.dataframe(pd.DataFrame(toxic_access), use_container_width=True)

    # Export Findings
    final_report = pd.concat([pd.DataFrame(zombies), pd.DataFrame(toxic_access)])
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        final_report.to_excel(writer, index=False, sheet_name='Findings')
    
    st.download_button("📥 Download Full Audit Report", output.getvalue(), "Audit_Report_Nairs.xlsx")
