"""connectors/salesforce.py — Salesforce connector."""

import requests
import pandas as pd
from .base import BaseConnector, ConnectorResult

ACCESS_MAP = {
    "System Administrator": "Admin",
    "Finance User":         "Finance",
    "Sales User":           "CRM",
    "Standard User":        "ReadOnly",
    "Marketing User":       "CRM",
    "Contract Manager":     "ReadOnly",
    "Read Only":            "ReadOnly",
}


class SalesforceConnector(BaseConnector):
    SOURCE_NAME = "Salesforce"

    def __init__(self, instance_url: str, access_token: str,
                 token_endpoint: str = None, client_id: str = None,
                 client_secret: str = None, username: str = None,
                 password: str = None):
        self.instance_url   = instance_url.rstrip("/")
        self.access_token   = access_token
        self.token_endpoint = token_endpoint
        self.headers        = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type":  "application/json",
        }

    def _soql(self, query: str):
        resp = requests.get(
            f"{self.instance_url}/services/data/v58.0/query",
            headers=self.headers,
            params={"q": query},
            timeout=30,
        )
        resp.raise_for_status()
        data    = resp.json()
        records = data.get("records", [])
        while not data.get("done") and data.get("nextRecordsUrl"):
            resp    = requests.get(
                f"{self.instance_url}{data['nextRecordsUrl']}",
                headers=self.headers, timeout=30,
            )
            resp.raise_for_status()
            data    = resp.json()
            records.extend(data.get("records", []))
        return records

    def test_connection(self):
        try:
            self._soql("SELECT Id FROM User LIMIT 1")
            return True, "Salesforce connection successful"
        except Exception as e:
            return False, str(e)

    def fetch(self) -> ConnectorResult:
        try:
            records = self._soql(
                "SELECT Id, Username, Email, FirstName, LastName, IsActive, "
                "Profile.Name, UserRole.Name, Department, Title, "
                "LastLoginDate, CreatedDate, UserType "
                "FROM User"
            )
        except Exception as e:
            return ConnectorResult(errors=[str(e)], source=self.SOURCE_NAME)

        sys_rows = []
        for r in records:
            email      = self._norm(r.get("Email","") or r.get("Username","")).lower()
            full_name  = self._norm(f"{r.get('FirstName','')} {r.get('LastName','')}".strip())
            profile    = (r.get("Profile") or {}).get("Name","Standard User")
            access     = ACCESS_MAP.get(profile, "ReadOnly")
            is_active  = r.get("IsActive", True)
            last_login = self._fmt_date(r.get("LastLoginDate"))
            created    = self._fmt_date(r.get("CreatedDate"))

            sys_rows.append({
                "Email": email, "FullName": full_name, "AccessLevel": access,
                "LastLoginDate": last_login, "PasswordLastSet": None,
                "MFA": "Unknown",
                "AccountCreatedDate": created,
                "AccountStatus": "Enabled" if is_active else "Disabled",
                "SystemName": "Salesforce",
            })

        sys_df = pd.DataFrame(sys_rows)
        return ConnectorResult(
            hr_df=self._make_empty_hr(), sys_df=sys_df,
            source=self.SOURCE_NAME, user_count=len(sys_df),
        )
