import streamlit as st
import json
import os
import re
import sys
import textwrap
import pathlib
from dataclasses import dataclass, field, asdict
from typing import Optional
from pypdf import PdfReader
import docx

# 1. DATA MODELS
@dataclass
class ControlRequirement:
    control_id: str
    control_name: str
    key_requirements: list[str]

@dataclass
class GapFinding:
    control_id: str
    control_name: str
    status: str
    matched_items: list[str] = field(default_factory=list)
    missing_items: list[str] = field(default_factory=list)
    remediation: str = ""
    evidence_snippets: list[str] = field(default_factory=list)

# 2. WEB-FRIENDLY TEXT EXTRACTION
def extract_text(uploaded_file):
    """Reads text from an uploaded Streamlit file object."""
    filename = uploaded_file.name.lower()
    
    if filename.endswith(".pdf"):
        reader = PdfReader(uploaded_file)
        return "\n".join([page.extract_text() or "" for page in reader.pages])
    
    elif filename.endswith(".docx"):
        doc = docx.Document(uploaded_file)
        return "\n".join([p.text for p in doc.paragraphs if p.text.strip()])
    
    else:
        return str(uploaded_file.read(), "utf-8", errors="replace")

# 3. CONTROLS LIBRARY (Your ISO 27002 Content)
ACCESS_CONTROL_CONTROLS = [
    ControlRequirement("5.15", "Access control", ["least privilege principle", "need-to-know", "access control rules"]),
    ControlRequirement("5.16", "Identity management", ["unique identity", "identity lifecycle", "audit log"]),
    ControlRequirement("8.2", "Privileged access rights", ["MFA for privileged access", "separate accounts", "logging"]),
]

# 4. KEYWORD MATCHING ENGINE
REQUIREMENT_KEYWORDS = {
    "least privilege principle": ["least privilege", "minimum access"],
    "need-to-know": ["need to know", "need-to-know"],
    "unique identity": ["unique id", "individual account"],
    "MFA for privileged access": ["mfa", "multi-factor", "2fa"],
    "access control rules": ["access rule", "control rules"]
}

def find_evidence(text, keywords):
    norm = text.lower()
    snippets = []
    for kw in keywords:
        if kw in norm:
            start = max(0, norm.find(kw) - 50)
            end = min(len(text), norm.find(kw) + 100)
            snippets.append(f"...{text[start:end]}...")
    return snippets[:2]

# 5. ANALYSIS LOGIC
def analyse_control(policy_text, control):
    matched, missing, evidence = [], [], []
    for req in control.key_requirements:
        keywords = REQUIREMENT_KEYWORDS.get(req, [req])
        snips = find_evidence(policy_text, keywords)
        if snips:
            matched.append(req)
            evidence.extend(snips)
        else:
            missing.append(req)
    
    status = "Full Match" if not missing else ("Gap" if not matched else "Partial Match")
    return GapFinding(control.control_id, control.control_name, status, matched, missing, "Update policy.", evidence)

# 6. THE STREAMLIT INTERFACE
def main():
    st.set_page_config(page_title="AI Audit Tool", layout="wide")
    st.title("🛡️ ISO/IEC 27002:2022 Gap Analysis")
    
    col1, col2 = st.columns(2)
    with col1:
        std_file = st.file_uploader("Upload ISO Standard", type=["pdf", "docx"])
    with col2:
        pol_file = st.file_uploader("Upload Company Policy", type=["pdf", "docx"])

    if std_file and pol_file:
        with st.spinner("Analyzing Gap..."):
            policy_text = extract_text(pol_file)
            
            findings = []
            for ctrl in ACCESS_CONTROL_CONTROLS:
                findings.append(analyse_control(policy_text, ctrl))
            
            # Display Results
            for f in findings:
                with st.expander(f"{f.control_id} - {f.control_name} ({f.status})"):
                    st.write(f"**Status:** {f.status}")
                    if f.matched_items:
                        st.success(f"Matches: {', '.join(f.matched_items)}")
                    if f.missing_items:
                        st.error(f"Missing: {', '.join(f.missing_items)}")
                    if f.evidence_snippets:
                        st.info(f"Evidence: {f.evidence_snippets[0]}")

if __name__ == "__main__":
    main()
