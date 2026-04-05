import streamlit as st
import anthropic
from pypdf import PdfReader
import docx

# 1. SETUP & BRAIN (CLAUDE AI)
def get_claude_response(standard_text, policy_text):
    client = anthropic.Anthropic(api_key=st.secrets["ANTHROPIC_API_KEY"])
    
    prompt = f"""
    You are a Senior IT Auditor. I will provide you with an Audit Standard and a Company Policy.
    
    STANDARD:
    {standard_text[:4000]} 
    
    POLICY:
    {policy_text[:4000]}
    
    TASK:
    1. Identify the key controls required by the Standard.
    2. Check if the Policy meets these controls.
    3. For every Gap, provide a 'Remediation Action'.
    
    Format your response as a professional table with: Control ID, Status (Compliant/Gap), and Auditor's Comments.
    """
    
    message = client.messages.create(
        model="claude-3-haiku-20240307",
        max_tokens=2000,
        messages=[{"role": "user", "content": prompt}]
    )
    return message.content[0].text

# 2. TEXT EXTRACTION (WORKS FOR ANY DOC)
def extract_text(file):
    if file.name.lower().endswith(".pdf"):
        return "\n".join([p.extract_text() for p in PdfReader(file).pages])
    elif file.name.lower().endswith(".docx"):
        return "\n".join([p.text for p in docx.Document(file).paragraphs])
    return str(file.read(), "utf-8")

# 3. THE INTERFACE
st.set_page_config(page_title="Ultimate AI Auditor", layout="wide")
st.title("🤖 Ultimate AI Audit Assistant")
st.markdown("Upload **ANY** Standard and **ANY** Policy for a full Gap Analysis.")

with st.sidebar:
    st.header("Upload Center")
    std_file = st.file_uploader("📁 Upload Audit Standard", type=["pdf", "docx", "txt"])
    pol_file = st.file_uploader("📄 Upload Company Policy", type=["pdf", "docx", "txt"])
    analyze_button = st.button("🚀 Run Full AI Audit")

if analyze_button:
    if std_file and pol_file:
        with st.spinner("Claude is reading your documents... this takes about 30 seconds."):
            try:
                std_txt = extract_text(std_file)
                pol_txt = extract_text(pol_file)
                
                report = get_claude_response(std_txt, pol_txt)
                
                st.subheader("📋 AI Gap Analysis Report")
                st.markdown(report)
                st.success("Audit Complete!")
            except Exception as e:
                st.error(f"Make sure your API Key is in 'Advanced Settings'. Error: {e}")
    else:
        st.warning("Please upload both files first!")
