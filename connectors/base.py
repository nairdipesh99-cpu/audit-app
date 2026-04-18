"""
base.py — Shared interface all connectors implement.
Every connector returns the same two DataFrames regardless of source.
The engine never changes.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
import pandas as pd


@dataclass
class ConnectorResult:
    """
    Standardised output from every connector.
    hr_df  → HR Master schema  (Email, FullName, Department, EmploymentStatus,
                                ContractType, TerminationDate, JoinDate, JobTitle)
    sys_df → System Access UAL (Email, FullName, AccessLevel, LastLoginDate,
                                PasswordLastSet, MFA, AccountCreatedDate,
                                AccountStatus, SystemName)
    """
    hr_df:       pd.DataFrame = field(default_factory=pd.DataFrame)
    sys_df:      pd.DataFrame = field(default_factory=pd.DataFrame)
    source:      str          = ""
    user_count:  int          = 0
    errors:      list         = field(default_factory=list)
    warnings:    list         = field(default_factory=list)
    raw:         dict         = field(default_factory=dict)

    @property
    def success(self) -> bool:
        return not self.errors and not self.hr_df.empty

    def merge_with(self, other: "ConnectorResult") -> "ConnectorResult":
        """Merge two results — used when combining HR + IAM connectors."""
        merged_hr  = pd.concat([self.hr_df,  other.hr_df],  ignore_index=True).drop_duplicates(subset="Email", keep="first")
        merged_sys = pd.concat([self.sys_df, other.sys_df], ignore_index=True)
        return ConnectorResult(
            hr_df      = merged_hr,
            sys_df     = merged_sys,
            source     = f"{self.source} + {other.source}",
            user_count = len(merged_hr),
            errors     = self.errors + other.errors,
            warnings   = self.warnings + other.warnings,
        )


class BaseConnector(ABC):
    """
    Abstract base class all connectors inherit from.
    Enforces the contract: every connector must implement fetch().
    """

    SOURCE_NAME: str = "Unknown"

    # ── Schema definitions ────────────────────────────────────────────────
    HR_COLUMNS = [
        "Email", "FullName", "Department", "EmploymentStatus",
        "ContractType", "TerminationDate", "JoinDate", "JobTitle",
    ]

    SYS_COLUMNS = [
        "Email", "FullName", "AccessLevel", "LastLoginDate",
        "PasswordLastSet", "MFA", "AccountCreatedDate",
        "AccountStatus", "SystemName",
    ]

    @abstractmethod
    def fetch(self) -> ConnectorResult:
        """
        Fetch data from the source and return a ConnectorResult.
        Must populate either hr_df, sys_df, or both.
        """
        ...

    def test_connection(self) -> tuple[bool, str]:
        """
        Test credentials without pulling all data.
        Returns (success: bool, message: str).
        Override in subclasses for faster connection testing.
        """
        try:
            result = self.fetch()
            if result.success:
                return True, f"Connected — {result.user_count} records found"
            return False, "; ".join(result.errors) or "No records returned"
        except Exception as e:
            return False, str(e)

    # ── Shared helpers ────────────────────────────────────────────────────
    @staticmethod
    def _fmt_date(val) -> str | None:
        if not val:
            return None
        try:
            import pandas as pd
            return pd.to_datetime(str(val)).strftime("%Y-%m-%d")
        except Exception:
            return None

    @staticmethod
    def _norm(val, default="") -> str:
        if val is None:
            return default
        import pandas as pd
        if isinstance(val, float) and pd.isna(val):
            return default
        return str(val).strip()

    @staticmethod
    def _paginate_link_header(headers: dict) -> str | None:
        """Parse Link header for next page URL (Okta / GitHub style)."""
        import re
        link = headers.get("Link", "")
        match = re.search(r'<([^>]+)>;\s*rel="next"', link)
        return match.group(1) if match else None

    def _make_empty_hr(self) -> pd.DataFrame:
        return pd.DataFrame(columns=self.HR_COLUMNS)

    def _make_empty_sys(self) -> pd.DataFrame:
        return pd.DataFrame(columns=self.SYS_COLUMNS)
