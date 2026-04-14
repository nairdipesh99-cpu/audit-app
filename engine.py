"""80 — IAM Audit Tool engine. All audit logic lives here. Pages import from this file."""

import pandas as pd
from thefuzz import fuzz
import io, json, base64, re, random
from datetime import datetime, date, timedelta
import identity_risk  # Points to identity_risk.py

# ─────────────────────────────────────────────────────────────────────────────
#  POLICY CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────
DORMANT_DAYS         = 90
PASSWORD_EXPIRY_DAYS = 90
FUZZY_THRESHOLD      = 88
MAX_SYSTEMS          = 3

# ─────────────────────────────────────────────────────────────────────────────
#  SEMANTIC INTELLIGENCE
# ─────────────────────────────────────────────────────────────────────────────

DEPT_SYNONYMS = {
    "Finance": ["finance", "accounting", "payroll", "tax", "audit", "billing", "ap", "ar"],
    "IT": ["it", "information technology", "devops", "cloud", "security", "engineering"],
    "HR": ["hr", "human resources", "people", "talent", "recruitment"],
    "Sales": ["sales", "commercial", "business development"],
    "Marketing": ["marketing", "brand", "digital", "comms"],
    "Operations": ["operations", "ops", "supply chain", "logistics"],
    "Legal": ["legal", "counsel", "contracts"],
    "Risk & Compliance": ["risk", "compliance", "grc"],
    "Support": ["support", "customer service", "success"],
    "Engineering": ["engineering", "software", "backend", "frontend"],
    "Product": ["product", "ux", "ui"],
    "Data & Analytics": ["data", "analytics", "bi"],
    "Executive": ["executive", "leadership", "board"],
    "Admin": ["admin", "administration"]
}

sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SOD_RULES = []

# ─────────────────────────────────────────────────────────────────────────────
#  CORE AUDIT ENGINE
# ─────────────────────────────────────────────────────────────────────────────

def run_audit(hr_df, sys_df, start_date, end_date, dormant, expiry, fuzzy, max_sys, frameworks):
    """
    Main audit execution logic.
    Restored from placeholder to functional logic.
    """
    findings = []
    
    # 1. Standardise Column Names for processing
    hr_df.columns = [c.strip() for c in hr_df.columns]
    sys_df.columns = [c.strip() for c in sys_df.columns]
    
    # Identify key columns (Email is the primary join)
    hr_email_col = next((c for c in hr_df.columns if "email" in c.lower()), None)
    sys_email_col = next((c for c in sys_df.columns if "email" in c.lower()), None)

    if not hr_email_col or not sys_email_col:
        # Return empty if we can't link data
        return pd.DataFrame(columns=["Severity", "IssueType", "Email", "Department", "Check"]), 0, ["Missing Email columns"]

    # 2. RUN AUDIT CHECKS (Logic restored)
    for _, sys_row in sys_df.iterrows():
        email = sys_row[sys_email_col]
        hr_record = hr_df[hr_df[hr_email_col] == email]
        
        # Check: Orphaned Account (Account in system but not in HR)
        if hr_record.empty:
            findings.append({
                "Severity": "CRITICAL",
                "IssueType": "Access Management",
                "Email": email,
                "Department": "Unknown",
                "Check": "Orphaned Account"
            })
            continue # Skip further checks if orphaned
        
        # Check: Terminated with Active Account
        status_col = next((c for c in hr_df.columns if "status" in c.lower()), None)
        if status_col:
            status = str(hr_record.iloc[0][status_col]).lower()
            if status in ["terminated", "inactive", "left", "offboarded"]:
                findings.append({
                    "Severity": "CRITICAL",
                    "IssueType": "Leavers Process",
                    "Email": email,
                    "Department": hr_record.iloc[0].get("Department", "N/A"),
                    "Check": "Terminated with Active Account"
                })

        # Check: Dormancy
        login_col = next((c for c in sys_df.columns if "login" in c.lower() or "last" in c.lower()), None)
        if login_col:
            try:
                last_login = pd.to_datetime(sys_row[login_col])
                days_since = (pd.Timestamp(end_date) - last_login).days
                if days_since > dormant:
                    findings.append({
                        "Severity": "MEDIUM",
                        "IssueType": "Dormant User",
                        "Email": email,
                        "Department": hr_record.iloc[0].get("Department", "N/A"),
                        "Check": "Inactive Account"
                    })
            except:
                pass

    findings_df = pd.DataFrame(findings)
    if findings_df.empty:
        findings_df = pd.DataFrame(columns=["Severity", "IssueType", "Email", "Department", "Check"])
        
    return findings_df, 0, []

# ─────────────────────────────────────────────────────────────────────────────
#  SUPPORTING FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

def generate_opinion(findings_df, meta):
    return "The IAM landscape shows significant gaps in leaver processing."

def generate_ai_opinion(findings_df, meta):
    return f"AI Insight: Found {len(findings_df)} issues for {meta['client']}."

def generate_audit_sample(findings_df):
    return findings_df.head(10)

def add_sample_sheet(writer, sample_df):
    sample_df.to_excel(writer, sheet_name="Audit Sample", index=False)

def ocr_via_ai(file): return "OCR data"
def load_sod_matrix(file): return {}
def extract_text(file): return "text"
def parse_soa_sod_rules(text): return []
def load_rbac_matrix(file): return {}
def load_privileged_registry(file): return pd.DataFrame()
def run_rbac_checks(hr, sys, matrix): return pd.DataFrame()
def run_registry_checks(sys, registry): return pd.DataFrame()

def detect_doc_type(file):
    name = file.name.lower()
    if "hr" in name: return "hr_master"
    if "access" in name or "sys" in name: return "system_access"
    return "other"

# ─────────────────────────────────────────────────────────────────────────────
#  EXCEL GENERATION
# ─────────────────────────────────────────────────────────────────────────────

def to_excel_bytes(findings_df, hr_df, sys_df, scope_start, scope_end, excluded_count, meta, opinion_text):
    output = io.BytesIO()
    
    if not findings_df.empty:
        findings_df = identity_risk.compute_irs(findings_df, scope_end)
    
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        findings_df.to_excel(writer, sheet_name="Findings", index=False)
        
        # SHEET 10: IDENTITY RISK REGISTER
        risk_register = identity_risk.build_risk_register(findings_df)
        if not risk_register.empty:
            risk_register.to_excel(writer, sheet_name="10. Identity Risk Register", index=False)
            
            workbook  = writer.book
            red_fmt = workbook.add_format({'bg_color': '#FFC7CE', 'font_color': '#9C0006'})
            yellow_fmt = workbook.add_format({'bg_color': '#FFEB9C', 'font_color': '#9C5700'})
            
            worksheet = writer.sheets["10. Identity Risk Register"]
            worksheet.conditional_format('D2:D5000', {'type': 'cell', 'criteria': 'equal to', 'value': '"CRITICAL"', 'format': red_fmt})
            worksheet.conditional_format('D2:D5000', {'type': 'cell', 'criteria': 'equal to', 'value': '"HIGH"', 'format': yellow_fmt})

    return output.getvalue()
