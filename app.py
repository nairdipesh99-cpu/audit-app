"""
80 — IAM Audit Tool
Multi-page entry point. All audit logic is in engine.py.
"""

import streamlit as st

st.set_page_config(
    page_title="80 — IAM Audit Tool",
    layout="wide",
    page_icon="🛡️",
    initial_sidebar_state="expanded",
)

home     = st.Page("pages/home.py",        title="Home",         icon="🏠", default=True)
about    = st.Page("pages/about.py",       title="About 80",     icon="📋")
tool     = st.Page("pages/tool.py",        title="Use the Tool", icon="🛡️")
how_to   = st.Page("pages/how_to_use.py",  title="How to Use",   icon="📖")

pg = st.navigation([home, about, tool, how_to])
pg.run()

