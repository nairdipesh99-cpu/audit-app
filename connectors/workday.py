"""connectors/workday.py — Workday connector (HR Master source)."""

import requests
import pandas as pd
from .base import BaseConnector, ConnectorResult


class WorkdayConnector(BaseConnector):
    SOURCE_NAME = "Workday"

    def __init__(self, tenant: str, username: str, password: str,
                 base_url_override: str = None):
        self.tenant   = tenant
        self.username = username
        self.password = password
        self.base_url = base_url_override or \
            f"https://{tenant}.workday.com/ccx/service/{tenant}"

    def _get(self, path, params=None):
        resp = requests.get(
            f"{self.base_url}{path}",
            auth=(self.username, self.password),
            headers={"Accept": "application/json"},
            params=params, timeout=30,
        )
        resp.raise_for_status()
        return resp.json()

    def test_connection(self):
        try:
            self._get("/Human_Resources/v40.1/workers")
            return True, "Workday connection successful"
        except Exception as e:
            return False, str(e)

    def fetch(self) -> ConnectorResult:
        try:
            data    = self._get("/Human_Resources/v40.1/workers")
            workers = data.get("Report_Entry", [])
        except Exception as e:
            return ConnectorResult(errors=[str(e)], source=self.SOURCE_NAME)

        hr_rows = []
        for w in workers:
            personal  = w.get("Personal_Data", {})
            name_data = personal.get("Name_Data", {}).get("Legal_Name_Data", {}).get("Name_Detail_Data", {})
            contact   = personal.get("Contact_Data", {}).get("Email_Address_Data", [{}])
            email     = self._norm(contact[0].get("Email_Address","") if contact else "").lower()
            if not email:
                continue

            first     = self._norm(name_data.get("First_Name",""))
            last      = self._norm(name_data.get("Last_Name",""))
            full_name = f"{first} {last}".strip()

            emp_data  = w.get("Employment_Data", {})
            status_d  = emp_data.get("Worker_Status_Data", {})
            pos_data  = emp_data.get("Position_Data", {})

            department = self._norm(pos_data.get("Department_Reference", {}).get("Descriptor","Unknown"))
            job_title  = self._norm(pos_data.get("Job_Profile_Name",""))
            emp_type   = self._norm(pos_data.get("Worker_Type","Employee"))
            contract   = "Contractor" if "contractor" in emp_type.lower() else "Permanent"
            term_date  = self._fmt_date(status_d.get("Termination_Date",""))
            hire_date  = self._fmt_date(status_d.get("Hire_Date",""))
            emp_status = "Terminated" if term_date else self._norm(status_d.get("Employment_Status","Active"))

            hr_rows.append({
                "Email": email, "FullName": full_name, "Department": department,
                "EmploymentStatus": emp_status, "ContractType": contract,
                "TerminationDate": term_date, "JoinDate": hire_date, "JobTitle": job_title,
            })

        hr_df = pd.DataFrame(hr_rows).drop_duplicates(subset="Email", keep="first")
        return ConnectorResult(
            hr_df=hr_df, sys_df=self._make_empty_sys(),
            source=self.SOURCE_NAME, user_count=len(hr_df),
        )
