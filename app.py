"""
80 — IAM Audit Tool
Multi-page entry point.
"""

import streamlit as st

st.set_page_config(
    page_title="80 — IAM Audit Tool",
    layout="wide",
    page_icon="🛡️",
    initial_sidebar_state="collapsed",
)

home   = st.Page("pages/home.py",       title="Home",       icon="🏠", default=True)
tool   = st.Page("pages/tool.py",       title="Tool",       icon="🛡️")
about  = st.Page("pages/about.py",      title="About",      icon="📋")
howto  = st.Page("pages/how_to_use.py", title="How to Use", icon="📖")

pg = st.navigation([home, tool, about, howto], position="hidden")
pg.run()

