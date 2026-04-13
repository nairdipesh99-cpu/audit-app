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
#  DOCUMENT PARSER
# ─────────────────────────────────────────────────────────────────────────────
def extract_text(uploaded_file, max_chars=5000):
    if uploaded_file is None: return ""
    name = uploaded_file.name.lower()
    try:
        if name.endswith(".txt"):
            return uploaded_file.read().decode("utf-8", errors="ignore")[:max_chars]
        elif name.endswith(".pdf"):
            import pypdf
            reader = pypdf.PdfReader(uploaded_file)
            return " ".join(p.extract_text() or "" for p in reader.pages[:10])[:max_chars]
        elif name.endswith(".docx"):
            import docx
            doc = docx.Document(uploaded_file)
            return " ".join(p.text for p in doc.paragraphs)[:max_chars]
        elif name.endswith((".xlsx",".xls")):
            df = pd.read_excel(uploaded_file, sheet_name=None)
            text_parts = []
            for sheet_name, sheet_df in df.items():
                text_parts.append(f"[Sheet: {sheet_name}]")
                text_parts.append(sheet_df.to_string(index=False))
            return " ".join(text_parts)[:max_chars]
        elif name.endswith(".csv"):
            return pd.read_csv(uploaded_file).to_string(index=False)[:max_chars]
    except Exception as e:
        return f"[Could not parse {uploaded_file.name}: {e}]"
    return ""

def detect_doc_type(f):
    if f is None: return "other"
    name = f.name.lower()
    if any(k in name for k in ["hr_master","hr master","hrmaster","employee","staff_list","personnel"]): return "hr_master"
    if any(k in name for k in ["system_access","user_access","ual"]): return "system_access"
    if any(k in name for k in ["soa","annex_a","policy"]): return "soa"
    if any(k in name for k in ["rbac","role_matrix"]): return "rbac_matrix"
    if any(k in name for k in ["privileged","priv_register"]): return "privileged_registry"
    return "other"

def parse_soa_sod_rules(soa_text):
    import re
    rules = {}
    dept_keywords = ["Finance","IT","HR","Sales","Operations"]
    access_keywords = ["Admin","Finance","Payroll","DBAdmin"]
    for dept in dept_keywords:
        pattern = rf"{dept}[^.\n]{{0,60}}({"|".join(access_keywords)})"
        matches = re.findall(pattern, soa_text, re.IGNORECASE)
        if matches:
            rules[dept] = list(set(matches))
    return rules

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
    dc2.date_
