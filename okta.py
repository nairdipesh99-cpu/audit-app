
"""
okta_connector.py — Okta API connector for the IAM Audit Tool.
Fetches Users and Groups from Okta and formats the data to match
the exact HR Master and System Access (UAL) column schemas expected
by engine.py's run_audit() function.
"""

import requests
import pandas as pd
from datetime import datetime, timezone

# ─────────────────────────────────────────────────────────────────────────────
#  CONFIGURATION — replace with real values or inject via environment variables
# ─────────────────────────────────────────────────────────────────────────────
OKTA_DOMAIN    = "https://your-domain.okta.com"   # e.g. https://acme.okta.com
OKTA_API_TOKEN = "YOUR_OKTA_API_TOKEN"             # Okta API token (SSWS)

HEADERS = {
    "Accept":        "application/json",
    "Content-Type":  "application/json",
    "Authorization": f"SSWS {OKTA_API_TOKEN}",
}

# Maps Okta status values → engine.py EmploymentStatus canonical values
OKTA_STATUS_MAP = {
    "ACTIVE":              "Active",
    "DEPROVISIONED":       "Terminated",
    "SUSPENDED":           "Suspended",
    "LOCKED_OUT":          "Suspended",
    "PASSWORD_EXPIRED":    "Active",
    "RECOVERY":            "Active",
    "STAGED":              "Active",
}

# Maps Okta group names → AccessLevel values recognised by engine.py
# Extend this map to match your organisation's Okta group naming conventions
ACCESS_LEVEL_MAP = {
    "admins":             "Admin",
    "administrators":     "Admin",
    "db_admins":          "DBAdmin",
    "database_admins":    "DBAdmin",
    "finance":            "Finance",
    "finance_team":       "Finance",
    "hr":                 "HR",
    "hr_team":            "HR",
    "crm":                "CRM",
    "crm_users":          "CRM",
    "payroll":            "Payroll",
    "payroll_team":       "Payroll",
    "readonly":           "ReadOnly",
    "read_only":          "ReadOnly",
    "support":            "Support",
    "helpdesk":           "Support",
}


class OktaConnector:
    """
    Fetches Users and Groups from the Okta API and formats the data
    for ingestion by the IAM Audit Tool engine (engine.py).
    """

    def __init__(self, domain: str = OKTA_DOMAIN, api_token: str = OKTA_API_TOKEN):
        self.domain    = domain.rstrip("/")
        self.api_token = api_token
        self.headers   = {
            "Accept":        "application/json",
            "Content-Type":  "application/json",
            "Authorization": f"SSWS {api_token}",
        }

    # ─────────────────────────────────────────────────────────────────────────
    #  PRIVATE HELPERS
    # ─────────────────────────────────────────────────────────────────────────

    def _paginate(self, url: str, params: dict = None) -> list:
        """Follow Okta's Link-header pagination and return all records."""
        results = []
        while url:
            resp = requests.get(url, headers=self.headers, params=params)
            resp.raise_for_status()
            results.extend(resp.json())
            # Okta signals next page via the Link header
            link_header = resp.headers.get("Link", "")
            next_url    = None
            for part in link_header.split(","):
                part = part.strip()
                if 'rel="next"' in part:
                    next_url = part.split(";")[0].strip().strip("<>")
                    break
            url    = next_url
            params = None   # params only sent on first request
        return results

    @staticmethod
    def _fmt_date(okta_ts: str | None) -> str | None:
        """Convert Okta ISO-8601 timestamp to YYYY-MM-DD string."""
        if not okta_ts:
            return None
        try:
            dt = datetime.fromisoformat(okta_ts.replace("Z", "+00:00"))
            return dt.strftime("%Y-%m-%d")
        except (ValueError, AttributeError):
            return None

    # ─────────────────────────────────────────────────────────────────────────
    #  PUBLIC FETCH METHODS
    # ─────────────────────────────────────────────────────────────────────────

    def fetch_users(self) -> list[dict]:
        """
        Fetch ALL users from Okta (all statuses).
        Returns a list of raw Okta user objects.
        """
        url = f"{self.domain}/api/v1/users"
        return self._paginate(url, params={"limit": 200})

    def fetch_groups(self) -> list[dict]:
        """
        Fetch ALL groups from Okta.
        Returns a list of raw Okta group objects.
        """
        url = f"{self.domain}/api/v1/groups"
        return self._paginate(url, params={"limit": 200})

    def fetch_group_members(self, group_id: str) -> list[dict]:
        """
        Fetch all members of a specific Okta group by group ID.
        Returns a list of raw Okta user objects.
        """
        url = f"{self.domain}/api/v1/groups/{group_id}/users"
        return self._paginate(url, params={"limit": 200})

    def build_user_group_map(self) -> dict[str, list[str]]:
        """
        Build a mapping of { user_id: [group_name, ...] } for all users.
        Used to derive AccessLevel from group membership.
        """
        groups          = self.fetch_groups()
        user_group_map  = {}   # {okta_user_id: [group_name, ...]}

        for group in groups:
            g_name    = group.get("profile", {}).get("name", "")
            g_id      = group.get("id", "")
            if not g_id:
                continue
            members = self.fetch_group_members(g_id)
            for member in members:
                uid = member.get("id", "")
                if uid:
                    user_group_map.setdefault(uid, []).append(g_name)

        return user_group_map

    # ─────────────────────────────────────────────────────────────────────────
    #  FORMAT FOR AUDIT
    # ─────────────────────────────────────────────────────────────────────────

    def format_for_audit(self) -> dict[str, pd.DataFrame]:
        """
        Fetch Okta users and groups, then return two DataFrames:

          hr_df  — matches the HR Master schema expected by engine.run_audit()
                   Columns: Email, FullName, Department, EmploymentStatus,
                            ContractType, TerminationDate, JoinDate, JobTitle

          sys_df — matches the System Access (UAL) schema expected by engine.run_audit()
                   Columns: Email, FullName, AccessLevel, LastLoginDate,
                            PasswordLastSet, MFA, AccountCreatedDate,
                            AccountStatus, SystemName

        Returns:
            {"hr": hr_df, "system": sys_df}
        """
        raw_users      = self.fetch_users()
        user_group_map = self.build_user_group_map()

        hr_rows  = []
        sys_rows = []

        for user in raw_users:
            profile = user.get("profile", {})
            uid     = user.get("id", "")

            # ── Core identity ────────────────────────────────────────────────
            email      = (profile.get("email") or profile.get("login") or "").strip().lower()
            first      = profile.get("firstName", "") or ""
            last       = profile.get("lastName",  "") or ""
            full_name  = f"{first} {last}".strip() or email

            # ── Dates ────────────────────────────────────────────────────────
            created         = self._fmt_date(user.get("created"))
            last_login      = self._fmt_date(user.get("lastLogin"))
            pwd_changed     = self._fmt_date(user.get("passwordChanged"))
            status_changed  = self._fmt_date(user.get("statusChanged"))

            # ── Status mapping ───────────────────────────────────────────────
            okta_status  = user.get("status", "ACTIVE")
            emp_status   = OKTA_STATUS_MAP.get(okta_status, "Active")
            term_date    = status_changed if emp_status == "Terminated" else None
            acct_status  = "Enabled" if okta_status == "ACTIVE" else "Disabled"

            # ── Department / job title ───────────────────────────────────────
            department = (profile.get("department") or
                          profile.get("organization") or
                          "Unknown").strip()
            job_title  = (profile.get("title") or
                          profile.get("userType") or "").strip()

            # ── Contract type (heuristic from userType / employee type) ──────
            raw_type     = (profile.get("employeeType") or
                            profile.get("userType") or "").strip().lower()
            contract_map = {
                "contractor": "Contractor",
                "contract":   "Contractor",
                "temp":       "Contractor",
                "temporary":  "Contractor",
                "vendor":     "Contractor",
                "employee":   "Permanent",
                "full-time":  "Permanent",
                "full time":  "Permanent",
                "permanent":  "Permanent",
                "part-time":  "Permanent",
            }
            contract_type = contract_map.get(raw_type, "Permanent")

            # ── Access level from group membership ───────────────────────────
            groups_for_user  = user_group_map.get(uid, [])
            access_levels    = []
            for g in groups_for_user:
                mapped = ACCESS_LEVEL_MAP.get(g.strip().lower())
                if mapped and mapped not in access_levels:
                    access_levels.append(mapped)
            access_level = ", ".join(access_levels) if access_levels else "ReadOnly"

            # ── MFA status — Okta stores this at the factor level ────────────
            # Heuristic: if the user has logged in recently via Okta, MFA is
            # likely enrolled. Fetch /users/{id}/factors for authoritative data.
            mfa_status = "Enabled"   # default; override via fetch_user_mfa() below

            # ── Build HR row ─────────────────────────────────────────────────
            hr_rows.append({
                "Email":            email,
                "FullName":         full_name,
                "Department":       department,
                "EmploymentStatus": emp_status,
                "ContractType":     contract_type,
                "TerminationDate":  term_date,
                "JoinDate":         created,
                "JobTitle":         job_title,
            })

            # ── Build System Access row ──────────────────────────────────────
            sys_rows.append({
                "Email":              email,
                "FullName":           full_name,
                "AccessLevel":        access_level,
                "LastLoginDate":      last_login,
                "PasswordLastSet":    pwd_changed,
                "MFA":                mfa_status,
                "AccountCreatedDate": created,
                "AccountStatus":      acct_status,
                "SystemName":         "Okta",
            })

        hr_df  = pd.DataFrame(hr_rows)
        sys_df = pd.DataFrame(sys_rows)

        # Deduplicate on Email (keep first occurrence) — mirrors engine.py behaviour
        hr_df  = hr_df.drop_duplicates(subset="Email", keep="first").reset_index(drop=True)
        sys_df = sys_df.reset_index(drop=True)

        return {"hr": hr_df, "system": sys_df}

    def fetch_user_mfa(self, user_id: str) -> str:
        """
        Return 'Enabled' or 'Disabled' for a specific Okta user's MFA status
        by querying their enrolled factors.
        """
        url  = f"{self.domain}/api/v1/users/{user_id}/factors"
        resp = requests.get(url, headers=self.headers)
        if resp.status_code != 200:
            return "Disabled"
        factors = resp.json()
        active  = [f for f in factors if f.get("status") == "ACTIVE"]
        return "Enabled" if active else "Disabled"

    def format_for_audit_with_mfa(self) -> dict[str, pd.DataFrame]:
        """
        Extended version of format_for_audit() that fetches authoritative
        MFA status for every user via the /factors endpoint.
        NOTE: Makes one additional API call per user — use on smaller populations.
        """
        result  = self.format_for_audit()
        raw_users = self.fetch_users()

        uid_email_map = {}
        for user in raw_users:
            uid   = user.get("id", "")
            email = (user.get("profile", {}).get("email") or
                     user.get("profile", {}).get("login") or "").strip().lower()
            if uid and email:
                uid_email_map[email] = uid

        for idx, row in result["system"].iterrows():
            email = row["Email"]
            uid   = uid_email_map.get(email)
            if uid:
                result["system"].at[idx, "MFA"] = self.fetch_user_mfa(uid)

        return result


# ─────────────────────────────────────────────────────────────────────────────
#  CONVENIENCE FUNCTION — drop-in replacement for loading CSV/Excel files
# ─────────────────────────────────────────────────────────────────────────────

def load_okta_data(domain: str = OKTA_DOMAIN,
                   api_token: str = OKTA_API_TOKEN,
                   fetch_mfa: bool = False) -> dict[str, pd.DataFrame]:
    """
    Top-level convenience function. Returns {"hr": hr_df, "system": sys_df}
    ready for direct use in engine.run_audit().

    Args:
        domain:     Okta domain URL, e.g. https://acme.okta.com
        api_token:  Okta API token (SSWS type)
        fetch_mfa:  If True, fetches authoritative MFA status per user
                    (slower — one extra API call per user)

    Example:
        from okta_connector import load_okta_data
        from engine import run_audit

        data    = load_okta_data()
        results = run_audit(data["hr"], data["system"], ...)
    """
    connector = OktaConnector(domain=domain, api_token=api_token)
    if fetch_mfa:
        return connector.format_for_audit_with_mfa()
    return connector.format_for_audit()
