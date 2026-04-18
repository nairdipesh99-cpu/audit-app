"""connectors/github_conn.py — GitHub connector."""

import requests
import pandas as pd
from .base import BaseConnector, ConnectorResult


class GitHubConnector(BaseConnector):
    SOURCE_NAME = "GitHub"

    def __init__(self, org: str, token: str, base_url_override: str = None):
        self.org      = org
        self.token    = token
        self.base_url = base_url_override or "https://api.github.com"
        self.headers  = {
            "Authorization": f"token {token}",
            "Accept":        "application/vnd.github.v3+json",
        }

    def _paginate(self, url, params=None):
        results = []
        while url:
            resp = requests.get(url, headers=self.headers, params=params, timeout=30)
            resp.raise_for_status()
            results.extend(resp.json())
            url    = self._paginate_link_header(resp.headers)
            params = None
        return results

    def test_connection(self):
        try:
            resp = requests.get(f"{self.base_url}/orgs/{self.org}",
                                headers=self.headers, timeout=10)
            if resp.status_code == 200:
                return True, f"GitHub org '{self.org}' connected"
            return False, f"HTTP {resp.status_code}"
        except Exception as e:
            return False, str(e)

    def fetch(self) -> ConnectorResult:
        try:
            members = self._paginate(f"{self.base_url}/orgs/{self.org}/members",
                                     {"per_page": 100})
            teams   = self._paginate(f"{self.base_url}/orgs/{self.org}/teams",
                                     {"per_page": 100})
        except Exception as e:
            return ConnectorResult(errors=[str(e)], source=self.SOURCE_NAME)

        user_teams = {}
        for team in teams:
            slug       = team.get("slug","")
            t_members  = self._paginate(
                f"{self.base_url}/orgs/{self.org}/teams/{slug}/members",
                {"per_page": 100}
            )
            for m in t_members:
                login = m.get("login","")
                user_teams.setdefault(login, []).append(slug)

        sys_rows = []
        for m in members:
            login      = self._norm(m.get("login",""))
            email      = self._norm(m.get("email","") or f"{login}@github-{self.org}.local").lower()
            name       = self._norm(m.get("name","") or login)
            role       = m.get("role","member")
            access     = "Admin" if role == "admin" else "ReadOnly"
            created    = self._fmt_date(m.get("created_at"))
            last_login = self._fmt_date(m.get("updated_at"))

            sys_rows.append({
                "Email": email, "FullName": name, "AccessLevel": access,
                "LastLoginDate": last_login, "PasswordLastSet": None, "MFA": "Unknown",
                "AccountCreatedDate": created, "AccountStatus": "Enabled",
                "SystemName": f"GitHub / {self.org}",
            })

        sys_df = pd.DataFrame(sys_rows)
        return ConnectorResult(
            hr_df=self._make_empty_hr(), sys_df=sys_df,
            source=self.SOURCE_NAME, user_count=len(sys_df),
        )
