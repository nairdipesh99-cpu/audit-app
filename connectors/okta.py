"""
connectors/okta.py — Okta connector.
Wraps existing okta.py logic into the BaseConnector interface.
"""

import requests
import pandas as pd
from .base import BaseConnector, ConnectorResult

OKTA_STATUS_MAP = {
    "ACTIVE":           "Active",
    "DEPROVISIONED":    "Terminated",
    "SUSPENDED":        "Suspended",
    "LOCKED_OUT":       "Suspended",
    "PASSWORD_EXPIRED": "Active",
    "RECOVERY":         "Active",
    "STAGED":           "Active",
}

ACCESS_LEVEL_MAP = {
    "admins": "Admin", "administrators": "Admin",
    "db_admins": "DBAdmin", "database_admins": "DBAdmin",
    "finance": "Finance", "finance_team": "Finance",
    "hr": "HR", "hr_team": "HR",
    "crm": "CRM", "crm_users": "CRM",
    "payroll": "Payroll", "payroll_team": "Payroll",
    "readonly": "ReadOnly", "read_only": "ReadOnly",
    "support": "Support", "helpdesk": "Support",
}


class OktaConnector(BaseConnector):
    SOURCE_NAME = "Okta"

    def __init__(self, domain: str, api_token: str, fetch_mfa: bool = True):
        self.domain    = domain.rstrip("/")
        self.api_token = api_token
        self.fetch_mfa = fetch_mfa
        self.headers   = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"SSWS {api_token}",
        }

    def _get(self, url, params=None):
        resp = requests.get(url, headers=self.headers, params=params, timeout=30)
        resp.raise_for_status()
        return resp

    def _paginate(self, url, params=None):
        results = []
        while url:
            resp    = self._get(url, params)
            results.extend(resp.json())
            url     = self._paginate_link_header(resp.headers)
            params  = None
        return results

    def _fetch_groups(self):
        url = f"{self.domain}/api/v1/groups"
        return self._paginate(url, {"limit": 200})

    def _build_group_map(self):
        groups       = self._fetch_groups()
        user_grp_map = {}
        for g in groups:
            gname = g.get("profile", {}).get("name", "")
            gid   = g.get("id", "")
            if not gid:
                continue
            members = self._paginate(f"{self.domain}/api/v1/groups/{gid}/users", {"limit": 200})
            for m in members:
                uid = m.get("id", "")
                if uid:
                    user_grp_map.setdefault(uid, []).append(gname)
        return user_grp_map

    def _get_mfa(self, user_id):
        try:
            resp    = self._get(f"{self.domain}/api/v1/users/{user_id}/factors")
            factors = resp.json()
            return "Enabled" if any(f.get("status") == "ACTIVE" for f in factors) else "Disabled"
        except Exception:
            return "Disabled"

    def test_connection(self):
        try:
            resp = requests.get(
                f"{self.domain}/api/v1/users",
                headers=self.headers, params={"limit": 1}, timeout=10
            )
            if resp.status_code == 200:
                return True, "Okta connection successful"
            return False, f"HTTP {resp.status_code}: {resp.text[:200]}"
        except Exception as e:
            return False, str(e)

    def fetch(self) -> ConnectorResult:
        errors, warnings = [], []
        try:
            raw_users  = self._paginate(f"{self.domain}/api/v1/users", {"limit": 200})
            grp_map    = self._build_group_map()
        except Exception as e:
            return ConnectorResult(errors=[str(e)], source=self.SOURCE_NAME)

        hr_rows, sys_rows = [], []

        for user in raw_users:
            profile     = user.get("profile", {})
            uid         = user.get("id", "")
            email       = self._norm(profile.get("email") or profile.get("login")).lower()
            full_name   = f"{self._norm(profile.get('firstName'))} {self._norm(profile.get('lastName'))}".strip() or email
            department  = self._norm(profile.get("department") or profile.get("organization"), "Unknown")
            job_title   = self._norm(profile.get("title") or profile.get("userType"))
            raw_type    = self._norm(profile.get("employeeType") or profile.get("userType")).lower()
            contract    = {"contractor":"Contractor","contract":"Contractor","temp":"Contractor",
                           "temporary":"Contractor","vendor":"Contractor"}.get(raw_type, "Permanent")
            okta_status = user.get("status", "ACTIVE")
            emp_status  = OKTA_STATUS_MAP.get(okta_status, "Active")
            term_date   = self._fmt_date(user.get("statusChanged")) if emp_status == "Terminated" else None
            acct_status = "Enabled" if okta_status == "ACTIVE" else "Disabled"
            created     = self._fmt_date(user.get("created"))
            last_login  = self._fmt_date(user.get("lastLogin"))
            pwd_changed = self._fmt_date(user.get("passwordChanged"))

            grps        = grp_map.get(uid, [])
            access_lvls = list(dict.fromkeys(filter(None, [ACCESS_LEVEL_MAP.get(g.strip().lower()) for g in grps])))
            access_level= ", ".join(access_lvls) if access_lvls else "ReadOnly"
            mfa         = self._get_mfa(uid) if self.fetch_mfa and uid else "Disabled"

            hr_rows.append({
                "Email": email, "FullName": full_name, "Department": department,
                "EmploymentStatus": emp_status, "ContractType": contract,
                "TerminationDate": term_date, "JoinDate": created, "JobTitle": job_title,
            })
            sys_rows.append({
                "Email": email, "FullName": full_name, "AccessLevel": access_level,
                "LastLoginDate": last_login, "PasswordLastSet": pwd_changed, "MFA": mfa,
                "AccountCreatedDate": created, "AccountStatus": acct_status, "SystemName": "Okta",
            })

        hr_df  = pd.DataFrame(hr_rows).drop_duplicates(subset="Email", keep="first")
        sys_df = pd.DataFrame(sys_rows)

        return ConnectorResult(
            hr_df=hr_df, sys_df=sys_df,
            source=self.SOURCE_NAME, user_count=len(hr_df),
            errors=errors, warnings=warnings,
        )
