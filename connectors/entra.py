"""connectors/entra.py — Microsoft Entra ID (Azure AD) connector."""

import requests
import pandas as pd
from .base import BaseConnector, ConnectorResult

ACCESS_LEVEL_MAP = {
    "admins": "Admin", "administrators": "Admin",
    "finance": "Finance", "finance_team": "Finance",
    "hr": "HR", "hr_team": "HR",
    "crm": "CRM", "payroll": "Payroll",
    "readonly": "ReadOnly", "support": "Support",
}


class EntraConnector(BaseConnector):
    SOURCE_NAME = "Microsoft Entra ID"

    def __init__(self, tenant_id: str, client_id: str, client_secret: str,
                 token_endpoint: str = None):
        self.tenant_id     = tenant_id
        self.client_id     = client_id
        self.client_secret = client_secret
        # Allow override for mock server testing
        self.token_endpoint = token_endpoint or \
            f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
        self.graph_base    = "https://graph.microsoft.com/v1.0"
        self._token        = None

    def _get_token(self):
        if self._token:
            return self._token
        resp = requests.post(self.token_endpoint, data={
            "grant_type":    "client_credentials",
            "client_id":     self.client_id,
            "client_secret": self.client_secret,
            "scope":         "https://graph.microsoft.com/.default",
        }, timeout=15)
        resp.raise_for_status()
        self._token = resp.json()["access_token"]
        return self._token

    def _get(self, url, params=None):
        headers = {"Authorization": f"Bearer {self._get_token()}",
                   "Content-Type": "application/json"}
        resp    = requests.get(url, headers=headers, params=params, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def _paginate(self, url, params=None):
        results = []
        data    = self._get(url, params)
        results.extend(data.get("value", []))
        while "@odata.nextLink" in data:
            data = self._get(data["@odata.nextLink"])
            results.extend(data.get("value", []))
        return results

    def _build_group_map(self):
        groups    = self._paginate(f"{self.graph_base}/groups")
        grp_map   = {}
        for g in groups:
            gid   = g.get("id","")
            gname = g.get("displayName","").lower().replace(" ","_")
            members = self._paginate(f"{self.graph_base}/groups/{gid}/members")
            for m in members:
                uid = m.get("id","")
                if uid:
                    grp_map.setdefault(uid, []).append(gname)
        return grp_map

    def _get_mfa_map(self):
        try:
            data = self._get(
                f"{self.graph_base}/reports/authenticationMethods/userRegistrationDetails"
            )
            return {
                r["userPrincipalName"].lower(): "Enabled" if r.get("isMfaRegistered") else "Disabled"
                for r in data.get("value", [])
            }
        except Exception:
            return {}

    def test_connection(self):
        try:
            self._get_token()
            return True, "Entra ID connection successful"
        except Exception as e:
            return False, str(e)

    def fetch(self) -> ConnectorResult:
        try:
            users   = self._paginate(f"{self.graph_base}/users",
                                     {"$select": "id,displayName,givenName,surname,mail,"
                                                 "userPrincipalName,department,jobTitle,"
                                                 "accountEnabled,createdDateTime,"
                                                 "signInActivity,employeeType,"
                                                 "onPremisesExtensionAttributes"})
            grp_map = self._build_group_map()
            mfa_map = self._get_mfa_map()
        except Exception as e:
            return ConnectorResult(errors=[str(e)], source=self.SOURCE_NAME)

        hr_rows, sys_rows = [], []

        for u in users:
            uid        = u.get("id","")
            email      = self._norm(u.get("mail") or u.get("userPrincipalName")).lower()
            full_name  = self._norm(u.get("displayName") or
                                    f"{u.get('givenName','')} {u.get('surname','')}".strip())
            department = self._norm(u.get("department","Unknown"))
            job_title  = self._norm(u.get("jobTitle",""))
            emp_type   = self._norm(u.get("employeeType",""))
            contract   = "Contractor" if "contractor" in emp_type.lower() or "vendor" in emp_type.lower() else "Permanent"

            ext        = u.get("onPremisesExtensionAttributes") or {}
            emp_status = self._norm(ext.get("extensionAttribute1","Active")) or "Active"
            term_date  = self._fmt_date(ext.get("extensionAttribute2",""))

            enabled    = u.get("accountEnabled", True)
            acct_status= "Enabled" if enabled else "Disabled"
            created    = self._fmt_date(u.get("createdDateTime"))

            sign_in    = u.get("signInActivity") or {}
            last_login = self._fmt_date(sign_in.get("lastSignInDateTime"))
            pwd_ts     = u.get("passwordProfile") or {}
            pwd_changed= self._fmt_date(pwd_ts.get("lastPasswordChangeDateTime"))

            grps       = grp_map.get(uid, [])
            access_lvls= list(dict.fromkeys(filter(None, [ACCESS_LEVEL_MAP.get(g) for g in grps])))
            access_level= ", ".join(access_lvls) if access_lvls else "ReadOnly"
            mfa        = mfa_map.get(email, "Disabled")

            hr_rows.append({
                "Email": email, "FullName": full_name, "Department": department,
                "EmploymentStatus": emp_status, "ContractType": contract,
                "TerminationDate": term_date, "JoinDate": created, "JobTitle": job_title,
            })
            sys_rows.append({
                "Email": email, "FullName": full_name, "AccessLevel": access_level,
                "LastLoginDate": last_login, "PasswordLastSet": pwd_changed, "MFA": mfa,
                "AccountCreatedDate": created, "AccountStatus": acct_status,
                "SystemName": "Microsoft Entra ID",
            })

        hr_df  = pd.DataFrame(hr_rows).drop_duplicates(subset="Email", keep="first")
        sys_df = pd.DataFrame(sys_rows)
        return ConnectorResult(hr_df=hr_df, sys_df=sys_df,
                               source=self.SOURCE_NAME, user_count=len(hr_df))
