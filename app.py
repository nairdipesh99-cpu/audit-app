"""
okta_connector.py — Standalone Okta Users API connector for the IAM Audit Tool.

Fetches all users from the Okta /api/v1/users endpoint with full pagination
support and returns a Pandas DataFrame with the exact columns expected by
engine.py's run_audit() function.

Output columns:
    Email         → maps to engine.py "Email"          (sys_df)
    FullName      → maps to engine.py "FullName"        (sys_df)
    AccountStatus → maps to engine.py "AccountStatus"   (sys_df)  Enabled | Disabled
    MFA_Enabled   → maps to engine.py "MFA"             (sys_df)  Enabled | Disabled
    LastLogin     → maps to engine.py "LastLoginDate"   (sys_df)  YYYY-MM-DD

Usage:
    from okta_connector import fetch_okta_users

    df = fetch_okta_users(
        api_token="YOUR_OKTA_API_TOKEN",
        org_url="https://your-domain.okta.com"
    )
"""

import re
import requests
import pandas as pd
from datetime import datetime
from typing import Optional


# ─────────────────────────────────────────────────────────────────────────────
#  CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

DEFAULT_PAGE_SIZE = 200   # Okta maximum per-page limit

# Okta account status → engine.py AccountStatus canonical values
OKTA_STATUS_TO_ACCOUNT_STATUS: dict[str, str] = {
    "ACTIVE":           "Enabled",
    "STAGED":           "Enabled",
    "PROVISIONED":      "Enabled",
    "RECOVERY":         "Enabled",
    "PASSWORD_EXPIRED": "Enabled",
    "LOCKED_OUT":       "Disabled",
    "SUSPENDED":        "Disabled",
    "DEPROVISIONED":    "Disabled",
}

# Regex to extract the next-page URL from Okta's Link response header
_NEXT_URL_RE = re.compile(r'<([^>]+)>;\s*rel="next"')


# ─────────────────────────────────────────────────────────────────────────────
#  INTERNAL HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _build_headers(api_token: str) -> dict[str, str]:
    return {
        "Accept":        "application/json",
        "Content-Type":  "application/json",
        "Authorization": f"SSWS {api_token}",
    }


def _fmt_date(okta_ts: Optional[str]) -> Optional[str]:
    """Convert an Okta ISO-8601 timestamp to a YYYY-MM-DD string, or None."""
    if not okta_ts:
        return None
    try:
        dt = datetime.fromisoformat(okta_ts.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d")
    except (ValueError, AttributeError):
        return None


def _extract_next_url(link_header: str) -> Optional[str]:
    """
    Parse Okta's Link header and return the next-page URL, or None.

    Okta paginates via:
        Link: <https://org.okta.com/api/v1/users?after=...>; rel="next"
    """
    if not link_header:
        return None
    match = _NEXT_URL_RE.search(link_header)
    return match.group(1) if match else None


def _paginate_users(
    org_url: str,
    headers: dict[str, str],
    page_size: int,
) -> list[dict]:
    """
    Walk all pages of /api/v1/users and return a flat list of raw user dicts.
    Follows Okta Link-header cursor pagination until no `rel="next"` link remains.
    """
    url    = f"{org_url.rstrip('/')}/api/v1/users"
    params = {"limit": page_size}
    users  = []

    while url:
        response = requests.get(url, headers=headers, params=params, timeout=30)
        response.raise_for_status()
        page   = response.json()
        if not isinstance(page, list):
            raise ValueError(f"Unexpected Okta response type: {type(page)}")
        users.extend(page)
        url    = _extract_next_url(response.headers.get("Link", ""))
        params = None   # cursor is already embedded in the next URL

    return users


def _get_mfa_status(
    user_id: str,
    org_url: str,
    headers: dict[str, str],
) -> str:
    """
    Query /api/v1/users/{id}/factors and return 'Enabled' if the user has at
    least one ACTIVE factor enrolled, otherwise 'Disabled'.
    Returns 'Disabled' on any API error rather than raising.
    """
    try:
        url      = f"{org_url.rstrip('/')}/api/v1/users/{user_id}/factors"
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code != 200:
            return "Disabled"
        factors  = response.json()
        active   = [f for f in factors if isinstance(f, dict) and f.get("status") == "ACTIVE"]
        return "Enabled" if active else "Disabled"
    except Exception:
        return "Disabled"


# ─────────────────────────────────────────────────────────────────────────────
#  PUBLIC API
# ─────────────────────────────────────────────────────────────────────────────

def fetch_okta_users(
    api_token: str,
    org_url: str,
    fetch_mfa: bool = True,
    page_size: int = DEFAULT_PAGE_SIZE,
) -> pd.DataFrame:
    """
    Fetch all users from the Okta Users API and return a DataFrame with the
    exact columns consumed by engine.py's run_audit().

    Args:
        api_token:  Okta API token (SSWS type).
                    Generate via: Admin → Security → API → Tokens.
        org_url:    Your Okta organisation base URL.
                    Example: "https://acme.okta.com"
        fetch_mfa:  If True (default), calls /api/v1/users/{id}/factors for
                    each user to retrieve authoritative MFA status.
                    Set to False to skip MFA calls and default all to "Disabled"
                    (significantly faster for large populations — use when MFA
                    data will be supplied separately or is not required).
        page_size:  Records per API page. Okta maximum is 200.

    Returns:
        pd.DataFrame with columns:
            Email           str            user principal / login email
            FullName        str            first + last name
            AccountStatus   str            "Enabled" | "Disabled"
            MFA_Enabled     str            "Enabled" | "Disabled"
            LastLogin       str|None       YYYY-MM-DD or None

    Raises:
        requests.HTTPError   on non-2xx API responses
        ValueError           if the API returns unexpected data
    """
    headers    = _build_headers(api_token)
    raw_users  = _paginate_users(org_url, headers, page_size)

    rows: list[dict] = []

    for user in raw_users:
        if not isinstance(user, dict):
            continue

        profile    = user.get("profile") or {}
        uid        = user.get("id", "")
        okta_status = user.get("status", "ACTIVE")

        # ── Email ────────────────────────────────────────────────────────────
        email = (
            profile.get("email")
            or profile.get("login")
            or ""
        ).strip().lower()

        # ── Full name ────────────────────────────────────────────────────────
        first     = (profile.get("firstName") or "").strip()
        last      = (profile.get("lastName")  or "").strip()
        full_name = f"{first} {last}".strip() or email

        # ── Account status ───────────────────────────────────────────────────
        account_status = OKTA_STATUS_TO_ACCOUNT_STATUS.get(okta_status, "Disabled")

        # ── Last login ───────────────────────────────────────────────────────
        last_login = _fmt_date(user.get("lastLogin"))

        # ── MFA status ───────────────────────────────────────────────────────
        if fetch_mfa and uid:
            mfa_enabled = _get_mfa_status(uid, org_url, headers)
        else:
            mfa_enabled = "Disabled"

        rows.append({
            "Email":         email,
            "FullName":      full_name,
            "AccountStatus": account_status,
            "MFA_Enabled":   mfa_enabled,
            "LastLogin":     last_login,
        })

    df = pd.DataFrame(rows, columns=["Email", "FullName", "AccountStatus", "MFA_Enabled", "LastLogin"])
    df = df.drop_duplicates(subset="Email", keep="first").reset_index(drop=True)
    return df


def fetch_okta_users_to_engine_schema(
    api_token: str,
    org_url: str,
    fetch_mfa: bool = True,
    system_name: str = "Okta",
    page_size: int = DEFAULT_PAGE_SIZE,
) -> pd.DataFrame:
    """
    Wrapper around fetch_okta_users() that renames columns to match the exact
    engine.py run_audit() sys_df schema so the DataFrame can be passed directly
    to run_audit() without any further transformation.

    Column mapping applied:
        Email         → Email            (unchanged)
        FullName      → FullName         (unchanged)
        AccountStatus → AccountStatus    (unchanged)
        MFA_Enabled   → MFA
        LastLogin     → LastLoginDate

    Additional columns added with None values to satisfy engine column checks:
        PasswordLastSet, AccountCreatedDate, AccessLevel, SystemName

    Args:
        api_token:    Okta API token (SSWS).
        org_url:      Okta organisation base URL.
        fetch_mfa:    Fetch per-user MFA status via /factors endpoint.
        system_name:  Value to populate the SystemName column (default "Okta").
        page_size:    Okta API page size (max 200).

    Returns:
        pd.DataFrame ready for engine.run_audit(hr_df, sys_df, ...)
    """
    df = fetch_okta_users(
        api_token=api_token,
        org_url=org_url,
        fetch_mfa=fetch_mfa,
        page_size=page_size,
    )

    df = df.rename(columns={
        "MFA_Enabled": "MFA",
        "LastLogin":   "LastLoginDate",
    })

    df["PasswordLastSet"]    = None
    df["AccountCreatedDate"] = None
    df["AccessLevel"]        = "ReadOnly"
    df["SystemName"]         = system_name

    return df[
        [
            "Email",
            "FullName",
            "AccessLevel",
            "LastLoginDate",
            "PasswordLastSet",
            "MFA",
            "AccountCreatedDate",
            "AccountStatus",
            "SystemName",
        ]
    ]


# ─────────────────────────────────────────────────────────────────────────────
#  CLI — quick smoke-test
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import os
    import sys

    token   = os.getenv("OKTA_API_TOKEN", "YOUR_OKTA_API_TOKEN")
    org     = os.getenv("OKTA_ORG_URL",   "https://your-domain.okta.com")

    if "YOUR_OKTA" in token or "YOUR_OKTA" in org:
        print("Set OKTA_API_TOKEN and OKTA_ORG_URL environment variables before running.")
        sys.exit(1)

    print(f"Connecting to {org} …")
    df = fetch_okta_users(api_token=token, org_url=org, fetch_mfa=True)
    print(f"Fetched {len(df):,} users.\n")
    print(df.head(10).to_string(index=False))

    out = "okta_users_export.csv"
    df.to_csv(out, index=False)
    print(f"\nSaved → {out}")
