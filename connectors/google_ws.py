"""connectors/google_ws.py — Google Workspace connector."""

import requests
import pandas as pd
from .base import BaseConnector, ConnectorResult


class GoogleWorkspaceConnector(BaseConnector):
    SOURCE_NAME = "Google Workspace"

    def __init__(self, domain: str, admin_email: str, service_account_key: dict = None,
                 token_endpoint: str = None, mock_token: str = None):
        self.domain           = domain
        self.admin_email      = admin_email
        self.service_account  = service_account_key
        self.token_endpoint   = token_endpoint
        self.mock_token       = mock_token
        self._token           = mock_token
        self.base_url         = "https://admin.googleapis.com"

    def _get_token(self):
        if self._token:
            return self._token
        if self.token_endpoint:
            resp = requests.post(self.token_endpoint, data={
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion":  "mock_jwt",
            }, timeout=15)
            resp.raise_for_status()
            self._token = resp.json().get("access_token")
            return self._token
        raise ValueError("No token endpoint or mock token configured")

    def _get(self, url, params=None):
        headers = {"Authorization": f"Bearer {self._get_token()}"}
        resp    = requests.get(url, headers=headers, params=params, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def _paginate_users(self, base_url):
        results    = []
        page_token = None
        while True:
            params = {"domain": self.domain, "maxResults": 500}
            if page_token:
                params["pageToken"] = page_token
            data       = self._get(base_url, params)
            results.extend(data.get("users", []))
            page_token = data.get("nextPageToken")
            if not page_token:
                break
        return results

    def test_connection(self):
        try:
            self._get_token()
            return True, "Google Workspace connection successful"
        except Exception as e:
            return False, str(e)

    def fetch(self) -> ConnectorResult:
        try:
            users = self._paginate_users(f"{self.base_url}/admin/directory/v1/users")
        except Exception as e:
            return ConnectorResult(errors=[str(e)], source=self.SOURCE_NAME)

        hr_rows, sys_rows = [], []

        for u in users:
            email      = self._norm(u.get("primaryEmail","")).lower()
            name       = u.get("name", {})
            full_name  = self._norm(name.get("fullName") or
                                    f"{name.get('givenName','')} {name.get('familyName','')}".strip())
            org_path   = self._norm(u.get("orgUnitPath","/")).strip("/")
            department = self._norm(u.get("department") or (org_path.split("/")[-1] if org_path else "Unknown"), "Unknown")
            job_title  = self._norm(u.get("title",""))

            custom     = u.get("customSchemas",{}).get("Employment",{})
            emp_type   = self._norm(custom.get("employeeType","employee"))
            contract   = "Contractor" if "contractor" in emp_type.lower() else "Permanent"
            term_date  = self._fmt_date(custom.get("terminationDate",""))
            emp_status = "Terminated" if term_date else ("Active" if not u.get("suspended") else "Suspended")

            created    = self._fmt_date(u.get("creationTime"))
            last_login = self._fmt_date(u.get("lastLoginTime"))
            suspended  = u.get("suspended", False)
            is_admin   = u.get("isAdmin", False)
            mfa        = "Enabled" if u.get("isEnrolledIn2Sv") else "Disabled"
            access     = "Admin" if is_admin else "ReadOnly"

            hr_rows.append({
                "Email": email, "FullName": full_name, "Department": department,
                "EmploymentStatus": emp_status, "ContractType": contract,
                "TerminationDate": term_date, "JoinDate": created, "JobTitle": job_title,
            })
            sys_rows.append({
                "Email": email, "FullName": full_name, "AccessLevel": access,
                "LastLoginDate": last_login, "PasswordLastSet": None, "MFA": mfa,
                "AccountCreatedDate": created, "AccountStatus": "Disabled" if suspended else "Enabled",
                "SystemName": "Google Workspace",
            })

        hr_df  = pd.DataFrame(hr_rows).drop_duplicates(subset="Email", keep="first")
        sys_df = pd.DataFrame(sys_rows)
        return ConnectorResult(hr_df=hr_df, sys_df=sys_df,
                               source=self.SOURCE_NAME, user_count=len(hr_df))
