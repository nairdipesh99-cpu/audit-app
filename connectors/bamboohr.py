"""connectors/bamboohr.py — BambooHR connector (HR Master source)."""

import requests
import pandas as pd
from .base import BaseConnector, ConnectorResult


class BambooHRConnector(BaseConnector):
    SOURCE_NAME = "BambooHR"

    def __init__(self, subdomain: str, api_key: str, base_url_override: str = None):
        self.subdomain = subdomain
        self.api_key   = api_key
        self.base_url  = base_url_override or f"https://api.bamboohr.com/api/gateway.php/{subdomain}/v1"

    def _get(self, path, params=None):
        resp = requests.get(
            f"{self.base_url}{path}",
            auth=(self.api_key, "x"),
            headers={"Accept": "application/json"},
            params=params, timeout=30,
        )
        resp.raise_for_status()
        return resp.json()

    def test_connection(self):
        try:
            self._get("/employees/directory")
            return True, "BambooHR connection successful"
        except Exception as e:
            return False, str(e)

    def fetch(self) -> ConnectorResult:
        try:
            data      = self._get("/employees/directory")
            employees = data.get("employees", [])
        except Exception as e:
            return ConnectorResult(errors=[str(e)], source=self.SOURCE_NAME)

        hr_rows = []
        for e in employees:
            email      = self._norm(e.get("workEmail","")).lower()
            if not email:
                continue
            full_name  = self._norm(e.get("displayName",""))
            department = self._norm(e.get("department","Unknown"))
            job_title  = self._norm(e.get("jobTitle",""))
            status     = self._norm(e.get("employmentHistoryStatus","Active"))
            emp_type   = self._norm(e.get("employeeType","Employee")).title()
            contract   = "Contractor" if "contractor" in emp_type.lower() or "vendor" in emp_type.lower() else "Permanent"
            term_date  = self._fmt_date(e.get("terminationDate",""))
            emp_status = "Terminated" if term_date else status

            hr_rows.append({
                "Email": email, "FullName": full_name, "Department": department,
                "EmploymentStatus": emp_status, "ContractType": contract,
                "TerminationDate": term_date,
                "JoinDate": self._fmt_date(e.get("hireDate","")),
                "JobTitle": job_title,
            })

        hr_df = pd.DataFrame(hr_rows).drop_duplicates(subset="Email", keep="first")
        return ConnectorResult(
            hr_df=hr_df, sys_df=self._make_empty_sys(),
            source=self.SOURCE_NAME, user_count=len(hr_df),
        )
