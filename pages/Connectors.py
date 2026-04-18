"""
pages/Connectors.py — Live Connector Hub
"""

import streamlit as st
import pandas as pd
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from connectors import (
    OktaConnector, EntraConnector, GoogleWorkspaceConnector,
    BambooHRConnector, WorkdayConnector, GitHubConnector,
    AWSIAMConnector, SalesforceConnector,
)

try:
    from components import inject_css, render_header, render_sidebar_brand
    inject_css()
    render_header()
except Exception:
    pass

MOCK_BASE = "http://localhost:5000"

CONNECTORS = {
    "Okta": {
        "icon": "🔐", "category": "IAM / Identity Provider",
        "description": "Pull users, groups, MFA status, and last login from Okta.",
        "produces": ["sys_df", "hr_df"],
        "fields": [
            {"key": "domain",    "label": "Okta Domain URL",  "placeholder": "https://yourorg.okta.com", "secret": False},
            {"key": "api_token", "label": "API Token (SSWS)", "placeholder": "SSWS 00abc...",            "secret": True},
        ],
        "mock_values": {
            "domain":    "http://localhost:5000/okta",
            "api_token": "mock_ssws_token_acmecorp",
        },
    },
    "Microsoft Entra ID": {
        "icon": "🪟", "category": "IAM / Identity Provider",
        "description": "Pull users, groups, MFA, and last sign-in from Azure AD via Microsoft Graph API.",
        "produces": ["sys_df", "hr_df"],
        "fields": [
            {"key": "tenant_id",     "label": "Tenant ID",     "placeholder": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", "secret": False},
            {"key": "client_id",     "label": "Client ID",     "placeholder": "App registration client ID",            "secret": False},
            {"key": "client_secret", "label": "Client Secret", "placeholder": "App registration client secret",        "secret": True},
        ],
        "mock_values": {
            "tenant_id":     "mock-tenant-acmecorp",
            "client_id":     "mock-client-id",
            "client_secret": "mock-client-secret",
        },
    },
    "Google Workspace": {
        "icon": "🔵", "category": "IAM / Identity Provider",
        "description": "Pull users, org units, 2FA status, and last login from Google Admin SDK.",
        "produces": ["sys_df", "hr_df"],
        "fields": [
            {"key": "domain",      "label": "Primary Domain", "placeholder": "yourorg.com",        "secret": False},
            {"key": "admin_email", "label": "Admin Email",    "placeholder": "admin@yourorg.com",  "secret": False},
            {"key": "mock_token",  "label": "Service Account Token",
             "placeholder": "mock_google_access_token_...", "secret": True},
        ],
        "mock_values": {
            "domain":      "acmecorp.com",
            "admin_email": "admin@acmecorp.com",
            "mock_token":  "mock_google_access_token_acmecorp",
        },
    },
    "BambooHR": {
        "icon": "🌿", "category": "HR System",
        "description": "Pull employee records, terminations, and departments from BambooHR.",
        "produces": ["hr_df"],
        "fields": [
            {"key": "subdomain", "label": "BambooHR Subdomain", "placeholder": "yourorg",              "secret": False},
            {"key": "api_key",   "label": "API Key",            "placeholder": "Your BambooHR API key", "secret": True},
        ],
        "mock_values": {
            "subdomain": "acmecorp",
            "api_key":   "mock_bamboohr_key",
        },
    },
    "Workday": {
        "icon": "📋", "category": "HR System",
        "description": "Pull workers, hires, terminations, and role changes from Workday.",
        "produces": ["hr_df"],
        "fields": [
            {"key": "tenant",   "label": "Workday Tenant",   "placeholder": "yourorg",             "secret": False},
            {"key": "username", "label": "Integration User", "placeholder": "isusername",           "secret": False},
            {"key": "password", "label": "Password",         "placeholder": "integration password", "secret": True},
        ],
        "mock_values": {
            "tenant":   "acmecorp",
            "username": "mock_workday_user",
            "password": "mock_workday_pass",
        },
    },
    "GitHub": {
        "icon": "🐙", "category": "Developer Tools",
        "description": "Pull org members, teams, and access levels from GitHub.",
        "produces": ["sys_df"],
        "fields": [
            {"key": "org",   "label": "Organisation Name",   "placeholder": "your-github-org", "secret": False},
            {"key": "token", "label": "Personal Access Token","placeholder": "ghp_...",         "secret": True},
        ],
        "mock_values": {
            "org":   "acmecorp",
            "token": "mock_github_pat",
        },
    },
    "AWS IAM": {
        "icon": "☁️", "category": "Cloud Platform",
        "description": "Pull IAM users, groups, MFA status, and last activity from AWS.",
        "produces": ["sys_df"],
        "fields": [
            {"key": "access_key", "label": "Access Key ID",     "placeholder": "AKIAIOSFODNN7EXAMPLE", "secret": False},
            {"key": "secret_key", "label": "Secret Access Key", "placeholder": "Your AWS secret key",   "secret": True},
        ],
        "mock_values": {
            "access_key": "MOCKAWSACCESSKEY123",
            "secret_key": "mockAWSsecretKey456",
        },
    },
    "Salesforce": {
        "icon": "☁️", "category": "CRM",
        "description": "Pull Salesforce users, profiles, and last login.",
        "produces": ["sys_df"],
        "fields": [
            {"key": "instance_url", "label": "Instance URL",  "placeholder": "https://yourorg.my.salesforce.com", "secret": False},
            {"key": "access_token", "label": "Access Token",  "placeholder": "Your Salesforce access token",      "secret": True},
        ],
        "mock_values": {
            "instance_url": "http://localhost:5000/salesforce",
            "access_token": "mock_sf_token",
        },
    },
}


def build_connector(name, creds):
    if name == "Okta":
        return OktaConnector(domain=creds["domain"], api_token=creds["api_token"], fetch_mfa=True)

    if name == "Microsoft Entra ID":
        is_mock  = "mock" in creds.get("tenant_id","") or "localhost" in creds.get("tenant_id","")
        token_ep = f"{MOCK_BASE}/entra/token" if is_mock else None
        c = EntraConnector(
            tenant_id=creds["tenant_id"], client_id=creds["client_id"],
            client_secret=creds["client_secret"], token_endpoint=token_ep,
        )
        if is_mock:
            c.graph_base = f"{MOCK_BASE}/entra/v1.0"
        return c

    if name == "Google Workspace":
        is_mock  = "mock" in creds.get("mock_token","")
        token_ep = f"{MOCK_BASE}/google/token" if is_mock else None
        base_url = f"{MOCK_BASE}/google" if is_mock else "https://admin.googleapis.com"
        c = GoogleWorkspaceConnector(
            domain=creds["domain"], admin_email=creds["admin_email"],
            token_endpoint=token_ep, mock_token=creds.get("mock_token"),
        )
        c.base_url = base_url
        return c

    if name == "BambooHR":
        is_mock  = "mock" in creds.get("api_key","")
        base_url = f"{MOCK_BASE}/bamboohr/api/gateway.php/{creds['subdomain']}/v1" if is_mock else None
        return BambooHRConnector(subdomain=creds["subdomain"], api_key=creds["api_key"],
                                 base_url_override=base_url)

    if name == "Workday":
        is_mock  = "mock" in creds.get("username","")
        base_url = f"{MOCK_BASE}/workday/ccx/service/{creds['tenant']}" if is_mock else None
        return WorkdayConnector(tenant=creds["tenant"], username=creds["username"],
                                password=creds["password"], base_url_override=base_url)

    if name == "GitHub":
        is_mock  = "mock" in creds.get("token","")
        base_url = f"{MOCK_BASE}/github" if is_mock else None
        return GitHubConnector(org=creds["org"], token=creds["token"],
                               base_url_override=base_url)

    if name == "AWS IAM":
        is_mock  = "MOCK" in creds.get("access_key","")
        base_url = f"{MOCK_BASE}/aws" if is_mock else None
        return AWSIAMConnector(access_key=creds["access_key"], secret_key=creds["secret_key"],
                               base_url_override=base_url)

    if name == "Salesforce":
        return SalesforceConnector(instance_url=creds["instance_url"],
                                   access_token=creds["access_token"])

    raise ValueError(f"Unknown connector: {name}")


# ─────────────────────────────────────────────────────────────────────────────
#  SESSION STATE INIT
# ─────────────────────────────────────────────────────────────────────────────

if "connector_results"  not in st.session_state:
    st.session_state["connector_results"] = {}
if "combined_hr"        not in st.session_state:
    st.session_state["combined_hr"]  = pd.DataFrame()
if "combined_sys"       not in st.session_state:
    st.session_state["combined_sys"] = pd.DataFrame()
if "mock_fill"          not in st.session_state:
    st.session_state["mock_fill"] = {}

# ── Pre-fill mock values BEFORE widgets render ────────────────────────────
# When a mock button is clicked we store which connector needs filling.
# On the next rerun we set the session state keys before widgets are created.
for conn_name, cfg in CONNECTORS.items():
    if st.session_state["mock_fill"].get(conn_name):
        for field in cfg["fields"]:
            key = f"conn_{conn_name}_{field['key']}"
            if key not in st.session_state:
                st.session_state[key] = cfg["mock_values"].get(field["key"], "")
            else:
                st.session_state[key] = cfg["mock_values"].get(field["key"], "")
        st.session_state["mock_fill"][conn_name] = False


# ─────────────────────────────────────────────────────────────────────────────
#  PAGE
# ─────────────────────────────────────────────────────────────────────────────

st.markdown("## 🔌 Live Connector Hub")
st.caption(
    "Connect to your organisation's identity providers and HR systems. "
    "Live data is fetched in real time — no CSV exports, no stale data. "
    "CSV upload remains available as a fallback on the Tool page."
)

with st.expander("🧪 Testing with Mock Server?", expanded=False):
    st.info(
        "**Run the mock server first in a separate terminal:**\n\n"
        "```\npip install flask\npython mock_identity_server.py\n```\n\n"
        "Then click **Use Mock Values** on any connector below. "
        "All credentials will be pre-filled for the fake Acme Corp organisation."
    )
    st.caption("Mock server health check: `http://localhost:5000/health`")

st.divider()

# ─────────────────────────────────────────────────────────────────────────────
#  CONNECTOR CARDS
# ─────────────────────────────────────────────────────────────────────────────

categories = {}
for name, cfg in CONNECTORS.items():
    categories.setdefault(cfg["category"], []).append(name)

for category, connector_names in categories.items():
    st.markdown(f"### {category}")
    cols = st.columns(min(len(connector_names), 2))

    for ci, conn_name in enumerate(connector_names):
        cfg = CONNECTORS[conn_name]
        col = cols[ci % 2]

        with col:
            with st.container(border=True):
                st.markdown(f"**{cfg['icon']} {conn_name}**")
                st.caption(cfg["description"])

                produces = cfg["produces"]
                tags = []
                if "hr_df"  in produces: tags.append("✅ HR data")
                if "sys_df" in produces: tags.append("✅ System Access data")
                st.caption(" · ".join(tags))

                # ── Render input fields ───────────────────────────────────
                creds = {}
                for field in cfg["fields"]:
                    skey = f"conn_{conn_name}_{field['key']}"
                    # Initialise key if not present
                    if skey not in st.session_state:
                        st.session_state[skey] = ""
                    val = st.text_input(
                        field["label"],
                        placeholder=field["placeholder"],
                        key=skey,
                        type="password" if field["secret"] else "default",
                    )
                    creds[field["key"]] = val

                # ── Action buttons ────────────────────────────────────────
                b1, b2, b3 = st.columns(3)

                # Use Mock Values — sets flag, triggers rerun BEFORE widgets
                if b1.button("🧪 Mock Values", key=f"mock_{conn_name}",
                             use_container_width=True):
                    st.session_state["mock_fill"][conn_name] = True
                    st.rerun()

                # Test Connection
                if b2.button("🔗 Test", key=f"test_{conn_name}",
                             use_container_width=True):
                    filled = {f["key"]: st.session_state.get(f"conn_{conn_name}_{f['key']}","")
                              for f in cfg["fields"]}
                    if not all(filled.values()):
                        st.warning("Fill in all fields first.")
                    else:
                        with st.spinner("Testing…"):
                            try:
                                connector   = build_connector(conn_name, filled)
                                ok, msg     = connector.test_connection()
                                if ok:
                                    st.success(f"✅ {msg}")
                                else:
                                    st.error(f"❌ {msg}")
                            except Exception as e:
                                st.error(f"❌ {str(e)}")

                # Pull Data
                if b3.button("⬇️ Pull", key=f"pull_{conn_name}",
                             use_container_width=True, type="primary"):
                    filled = {f["key"]: st.session_state.get(f"conn_{conn_name}_{f['key']}","")
                              for f in cfg["fields"]}
                    if not all(filled.values()):
                        st.warning("Fill in all fields first.")
                    else:
                        with st.spinner(f"Fetching from {conn_name}…"):
                            try:
                                connector = build_connector(conn_name, filled)
                                result    = connector.fetch()
                                st.session_state["connector_results"][conn_name] = result
                                if result.success:
                                    st.success(
                                        f"✅ {result.user_count} records pulled from {conn_name}"
                                    )
                                    if not result.hr_df.empty:
                                        st.caption(f"HR: {len(result.hr_df)} records")
                                    if not result.sys_df.empty:
                                        st.caption(f"System Access: {len(result.sys_df)} records")
                                else:
                                    st.error(f"❌ {'; '.join(result.errors)}")
                            except Exception as e:
                                st.error(f"❌ {str(e)}")

                # Show last result status
                if conn_name in st.session_state["connector_results"]:
                    r = st.session_state["connector_results"][conn_name]
                    if r.success:
                        st.caption(f"Last pull: {r.user_count} records · {r.source}")

    st.divider()


# ─────────────────────────────────────────────────────────────────────────────
#  MERGE AND SEND TO AUDIT ENGINE
# ─────────────────────────────────────────────────────────────────────────────

st.markdown("### 🚀 Send to Audit Engine")

pulled = {k: v for k, v in st.session_state["connector_results"].items() if v.success}

if not pulled:
    st.info(
        "Pull data from at least one connector above, "
        "then click Send to Audit Engine."
    )
else:
    st.markdown(f"**{len(pulled)} connector(s) ready:**")
    for name, r in pulled.items():
        cfg  = CONNECTORS[name]
        mode = (
            "HR + System Access" if not r.hr_df.empty and not r.sys_df.empty else
            "HR only"            if not r.hr_df.empty else
            "System Access only"
        )
        st.markdown(f"- {cfg['icon']} **{name}** — {r.user_count} records ({mode})")

    if st.button("🚀 Merge All & Send to Audit Engine",
                 type="primary", use_container_width=True):

        all_hr  = [r.hr_df  for r in pulled.values() if not r.hr_df.empty]
        all_sys = [r.sys_df for r in pulled.values() if not r.sys_df.empty]

        combined_hr  = (
            pd.concat(all_hr, ignore_index=True)
            .drop_duplicates(subset="Email", keep="first")
            if all_hr else pd.DataFrame()
        )
        combined_sys = (
            pd.concat(all_sys, ignore_index=True)
            if all_sys else pd.DataFrame()
        )

        st.session_state["combined_hr"]      = combined_hr
        st.session_state["combined_sys"]     = combined_sys
        st.session_state["live_data_ready"]  = True

        st.success(
            f"✅ Data merged — {len(combined_hr)} HR records · "
            f"{len(combined_sys)} system access records. "
            f"Go to the **Tool** page — the audit will use this live data automatically."
        )

        if not combined_hr.empty:
            st.markdown("**HR data preview:**")
            st.dataframe(combined_hr.head(5), use_container_width=True, hide_index=True)
        if not combined_sys.empty:
            st.markdown("**System access preview:**")
            st.dataframe(combined_sys.head(5), use_container_width=True, hide_index=True)

    if st.button("🗑️ Clear all connector data", use_container_width=True):
        st.session_state["connector_results"] = {}
        st.session_state["combined_hr"]       = pd.DataFrame()
        st.session_state["combined_sys"]      = pd.DataFrame()
        st.session_state["live_data_ready"]   = False
        st.rerun()
