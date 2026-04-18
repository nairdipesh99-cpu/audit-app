"""connectors/aws_iam.py — AWS IAM connector."""

import requests
import pandas as pd
from .base import BaseConnector, ConnectorResult


class AWSIAMConnector(BaseConnector):
    SOURCE_NAME = "AWS IAM"

    def __init__(self, access_key: str, secret_key: str,
                 base_url_override: str = None):
        self.access_key  = access_key
        self.secret_key  = secret_key
        self.base_url    = base_url_override
        self._use_mock   = bool(base_url_override)

    def _mock_get(self, path):
        resp = requests.get(
            f"{self.base_url}{path}",
            headers={"Authorization": f"AWS {self.access_key}:{self.secret_key}"},
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()

    def _real_get(self, action):
        try:
            import boto3
            iam = boto3.client("iam",
                               aws_access_key_id=self.access_key,
                               aws_secret_access_key=self.secret_key)
            return iam
        except ImportError:
            raise ImportError("boto3 not installed. Run: pip install boto3")

    def test_connection(self):
        try:
            if self._use_mock:
                self._mock_get("/iam/users")
            else:
                iam = self._real_get("ListUsers")
                iam.list_users(MaxItems=1)
            return True, "AWS IAM connection successful"
        except Exception as e:
            return False, str(e)

    def fetch(self) -> ConnectorResult:
        try:
            if self._use_mock:
                data  = self._mock_get("/iam/users")
                users = data.get("Users", [])
            else:
                iam    = self._real_get("ListUsers")
                paginator = iam.get_paginator("list_users")
                users  = []
                for page in paginator.paginate():
                    users.extend(page.get("Users", []))
        except Exception as e:
            return ConnectorResult(errors=[str(e)], source=self.SOURCE_NAME)

        sys_rows = []
        for u in users:
            username   = self._norm(u.get("UserName",""))
            tags       = {t["Key"]: t["Value"] for t in u.get("Tags", [])}
            email      = self._norm(tags.get("Email","") or f"{username}@aws-iam.local").lower()
            full_name  = self._norm(tags.get("FullName","") or username)
            department = self._norm(tags.get("Department","IT"))
            policies   = u.get("AttachedPolicies", [])
            is_admin   = any("Administrator" in p.get("PolicyName","") for p in policies)
            access     = "Admin" if is_admin else "ReadOnly"
            mfa        = "Enabled" if u.get("MFAEnabled", False) else "Disabled"
            last_login = self._fmt_date(u.get("PasswordLastUsed"))
            created    = self._fmt_date(u.get("CreateDate"))

            sys_rows.append({
                "Email": email, "FullName": full_name, "AccessLevel": access,
                "LastLoginDate": last_login, "PasswordLastSet": None, "MFA": mfa,
                "AccountCreatedDate": created, "AccountStatus": "Enabled",
                "SystemName": "AWS IAM",
            })

        sys_df = pd.DataFrame(sys_rows)
        return ConnectorResult(
            hr_df=self._make_empty_hr(), sys_df=sys_df,
            source=self.SOURCE_NAME, user_count=len(sys_df),
        )
