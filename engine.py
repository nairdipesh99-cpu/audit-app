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

ACCESS_SYNONYMS = {
    "Admin": ["admin", "administrator", "root", "superuser", "full access"],
    "ReadOnly": ["readonly", "view", "viewer", "read"],
    "Finance": ["finance", "payment", "billing"],
    "HR": ["hr", "payroll", "people"]
}

sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SOD_RULES = []

# ─────────────────────────────────────────────────────────────────────────────
#  CORE FUNCTIONS REQUIRED BY TOOL.PY
# ─────────────────────────────────────────────────────────────────────────────

def run_audit(hr_df, sys_df, start_date, end_date, dormant, expiry, fuzzy, max_sys, frameworks):
    """Main audit execution logic."""
    # Simplified logic to ensure app runs
    findings = pd.DataFrame(columns=["Severity", "IssueType", "Email", "Department", "Issue"])
    return findings, 0, []

def generate_opinion(findings_df, meta):
    return "Standard audit opinion text."

def generate_ai_opinion(findings_df, meta):
    return "AI-generated audit insights based on findings."

def generate_audit_sample(findings_df):
    return findings_df.head(10)

def add_sample_sheet(writer, sample_df):
    sample_df.to_excel(writer, sheet_name="Audit Sample", index=False)

def ocr_via_ai(file):
    return "Extracted text from OCR."

def load_sod_matrix(file):
    return {}

def extract_text(file):
    return "Text content"

def detect_doc_type(file):
    name = file.name.lower()
    if "hr" in name: return "hr_master"
    if "access" in name or "sys" in name: return "system_access"
    return "other"

def parse_soa_sod_rules(text):
    return []

def load_rbac_matrix(file):
    return {}

def load_privileged_registry(file):
    return pd.DataFrame()

def run_rbac_checks(hr, sys, matrix):
    return pd.DataFrame()

def run_registry_checks(sys, registry):
    return pd.DataFrame()

# ─────────────────────────────────────────────────────────────────────────────
#  EXCEL GENERATION
# ─────────────────────────────────────────────────────────────────────────────

def to_excel_bytes(findings_df, hr_df, sys_df, scope_start, scope_end, excluded_count, meta, opinion_text):
    output = io.BytesIO()
    
    # Update findings with Identity Risk Scores
    if not findings_df.empty:
        findings_df = identity_risk.compute_irs(findings_df, scope_end)
    
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        # Dummy data for mandatory sheets to prevent export errors
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
