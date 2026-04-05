import streamlit as st
import pandas as pd
from thefuzz import fuzz
import io

st.set_page_config(page_title="JML Ghost Hunter Pro", layout="wide")

st.title("👻 JML Ghost Hunter: Enterprise Identity Auditor")
st.markdown("""
This tool performs **100% Population Testing** by reconciling HR records against System Access. 
It uses **Fuzzy Matching** to detect nicknames and typos that standard Excel VLOOKUPs miss.
""")

# --- 1. UPLOADS ---
col1, col2 = st.columns(2)
with col1:
    hr_file = st.file_uploader("📂 Upload HR Master (Active Employees)", type=["xlsx"])
with col2:
    sys_file = st.file_uploader("🔑 Upload System Access Export", type=["xlsx"])

if hr_file and sys_file:
    hr_df = pd.read_excel(hr_file)
    sys_df = pd.read_excel(sys_file)

    st.divider()
    
    # --- 2. MATCHING LOGIC ---
    zombies = []
    matches = []
    
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    # Create a list of HR emails for fast checking
    hr_emails = hr_df['Email'].str.lower().tolist()
    hr_names = hr_df['Full Name'].tolist()

    total_accounts = len(sys_df)
    
    for index, row in sys_df.iterrows():
        sys_email = str(row['Email']).lower()
        sys_name = str(row['Account Name'])
        
        # Level 1: Exact Email Match
        if sys_email in hr_emails:
            matches.append(row)
        else:
            # Level 2: Fuzzy Name Match (The "Rare" Audit Logic)
            best_score = 0
            best_match_name = ""
            
            for hr_name in hr_names:
                score = fuzz.token_sort_ratio(sys_name, hr_name)
                if score > best_score:
                    best_score = score
                    best_match_name = hr_name
            
            if best_score > 80: # If it's a likely match (e.g., Chris vs Christopher)
                row['Audit_Note'] = f"Likely Match: {best_match_name} ({best_score}%)"
                matches.append(row)
            else:
                # Level 3: It's a Zombie!
                row['Audit_Note'] = "CRITICAL: No matching HR record found."
                zombies.append(row)
        
        # Update progress
        progress_bar.progress((index + 1) / total_accounts)
        status_text.text(f"Auditing account {index + 1} of {total_accounts}...")

    # --- 3. RESULTS DASHBOARD ---
    zombie_df = pd.DataFrame(zombies)
    
    st.subheader("📊 Audit Summary")
    s1, s2, s3 = st.columns(3)
    s1.metric("Total Accounts Checked", total_accounts)
    s2.metric("Matched Identities", len(matches), delta="Safe", delta_color="normal")
    s3.metric("Ghost Accounts Found", len(zombies), delta="Unsafe", delta_color="inverse")

    if not zombie_df.empty:
        st.error("### 🚩 High Risk: Orphaned Accounts Detected")
        st.dataframe(zombie_df, use_container_width=True)
        
        # --- 4. EXPORT FOR REPORTING ---
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
            zombie_df.to_excel(writer, index=False, sheet_name='Audit_Findings')
        
        st.download_button(
            label="📥 Download Audit Findings for Report",
            data=output.getvalue(),
            file_name="JML_Audit_Findings.xlsx",
            mime="application/vnd.ms-excel"
        )
    else:
        st.balloons()
        st.success("Audit Clean! 100% of accounts mapped to active employees.")
