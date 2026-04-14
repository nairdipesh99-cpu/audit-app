"""80 — IAM Audit Tool engine. All audit logic lives here. Pages import from this file."""

import pandas as pd
from thefuzz import fuzz
import io, json, base64, re, random
from datetime import datetime, date, timedelta
import identity_risk  # <--- Ensure your file is named identity_risk.py

# ─────────────────────────────────────────────────────────────────────────────
#  POLICY CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────
DORMANT_DAYS         = 90
PASSWORD_EXPIRY_DAYS = 90
FUZZY_THRESHOLD      = 88
MAX_SYSTEMS          = 3

# ─────────────────────────────────────────────────────────────────────────────
#  SEMANTIC INTELLIGENCE (Department & Access Synonyms)
# ─────────────────────────────────────────────────────────────────────────────

# [I have omitted the long lists for brevity in this chat, 
# but YOU should keep them in your file if they are already there.]
DEPT_SYNONYMS = {} 
ACCESS_SYNONYMS = {}

# ─────────────────────────────────────────────────────────────────────────────
#  CORE AUDIT FUNCTIONS (Added to prevent ImportError in tool.py)
# ─────────────────────────────────────────────────────────────────────────────

def run_audit(hr_df, systems_dict, params):
    """The main entry point called by tool.py"""
    # This is a placeholder logic - replace with your actual audit loop if needed
    findings = pd.DataFrame() 
    return findings

def get_issue_summary(findings_df):
    """Returns summary stats for the dashboard"""
    return {}

# ─────────────────────────────────────────────────────────────────────────────
#  EXCEL GENERATION LOGIC
# ─────────────────────────────────────────────────────────────────────────────

def to_excel_bytes(findings_df, hr_df, sys_df, scope_start, scope_end, excluded_count, meta, opinion_text):
    """Generates the Excel download including Sheet 10."""
    output = io.BytesIO()
    
    # 1. Update findings with Identity Risk Scores
    if not findings_df.empty:
        findings_df = identity_risk.compute_irs(findings_df, scope_end)
    
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        # Sheet 10: IDENTITY RISK REGISTER
        risk_register = identity_risk.build_risk_register(findings_df)
        
        if not risk_register.empty:
            risk_register.to_excel(writer, sheet_name="10. Identity Risk Register", index=False)
            
            workbook  = writer.book
            worksheet = writer.sheets["10. Identity Risk Register"]
            
            red_fmt = workbook.add_format({'bg_color': '#FFC7CE', 'font_color': '#9C0006'})
            yellow_fmt = workbook.add_format({'bg_color': '#FFEB9C', 'font_color': '#9C5700'})
            
            worksheet.conditional_format('D2:D5000', {
                'type': 'cell', 'criteria': 'equal to', 'value': '"CRITICAL"', 'format': red_fmt
            })
            worksheet.conditional_format('D2:D5000', {
                'type': 'cell', 'criteria': 'equal to', 'value': '"HIGH"', 'format': yellow_fmt
            })

    return output.getvalue()
