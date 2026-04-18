"""80 — IAM Audit Tool"""

import streamlit as st

st.set_page_config(
    page_title="80 — IAM Audit Tool",
    layout="wide",
    page_icon="🛡️",
    initial_sidebar_state="expanded",
)

home   = st.Page("pages/home.py",            title="Home",            icon="🏠", default=True)
tool   = st.Page("pages/tool.py",            title="Tool",            icon="🛡️")
asset  = st.Page("pages/asset_inventory.py", title="Asset Inventory", icon="🗄️")
about  = st.Page("pages/about.py",           title="About",           icon="📋")
howto  = st.Page("pages/how_to_use.py",      title="How to Use",      icon="📖")

pg = st.navigation([home, tool, asset, about, howto])
pg.run()
