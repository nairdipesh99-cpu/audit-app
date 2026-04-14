"""
irs.py — Identity Risk Score (IRS) Engine
Project 80 | Phase 1
Computes a 0–100 composite risk score per identity from run_audit() findings_df.
No additional data inputs required.
"""

from __future__ import annotations

import math
import numpy as np
import pandas as pd
from datetime import date, datetime
from typing import Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Component weights (must sum to 1.0)
W_SEVERITY   = 0.40
W_CRITICAL   = 0.25
W_DORMANCY   = 0.15
W_PRIVILEGE  = 0.12
W_CONTRACTOR = 0.08

# Severity point values
# Engine emits "🔴 CRITICAL" — strip emoji prefix before lookup (handled in _score_severity)
SEV_POINTS = {
    "CRITICAL": 20,
    "HIGH":     10,
    "MEDIUM":    5,
    "LOW":       2,
}

# Critical-flag checks — matched against findings_df["IssueType"] (engine output column)
CRITICAL_FLAG_CHECKS = {
    "Orphaned Account",
    "Terminated with Active Account",
    "Terminated Employee with Active Account",
    "Post-Termination Login",
    "Toxic Access (SoD Violation)",
    "SoD Violation",
}

# Dormancy gradient window (days)
DORMANCY_WINDOW = 180

# Privilege breadth caps (used for normalisation)
MAX_ROLES_CAP   = 10   # 10+ roles → full score on that sub-component
MAX_SYSTEMS_CAP =  5   #  5+ systems → full score on that sub-component

# Risk band thresholds
BAND_THRESHOLDS = [
    (75, "CRITICAL"),
    (50, "HIGH"),
    (25, "MEDIUM"),
    ( 0, "LOW"),
]

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _parse_date(val) -> Optional[date]:
    """Coerce varied date representations to a Python date, or None."""
    if val is None or (isinstance(val, float) and math.isnan(val)):
        return None
    if isinstance(val, date) and not isinstance(val, datetime):
        return val
    if isinstance(val, datetime):
        return val.date()
    if isinstance(val, pd.Timestamp):
        return val.date() if not pd.isnull(val) else None
    try:
        return pd.to_datetime(str(val)).date()
    except Exception:
        return None


def _strip_sev(s: str) -> str:
    """
    Normalise engine severity strings to bare keyword.
    "🔴 CRITICAL" → "CRITICAL", "🟠 HIGH" → "HIGH", etc.
    Strips leading emoji + space if present.
    """
    s = s.upper().strip()
    for kw in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if kw in s:
            return kw
    return s


def _score_severity(row_checks: list[str], row_severities: list[str]) -> float:
    """
    Component A — Severity-weighted finding count (0–1).
    Sum severity points, cap at 100 raw, normalise to 0–1.
    Max realistic raw = 4 CRITICAL (80) + 4 HIGH (40) = 120 → cap at 100.
    Engine emits emoji-prefixed strings — _strip_sev normalises before lookup.
    """
    raw = sum(SEV_POINTS.get(_strip_sev(s), 0) for s in row_severities)
    return min(raw, 100) / 100.0


def _score_critical_flag(row_checks: list[str]) -> float:
    """
    Component B — Critical check presence (0–1).
    One or more critical-flag checks → 1.0.
    Partial credit: 0.5 per critical check, capped at 1.0.
    """
    hits = sum(1 for c in row_checks if c in CRITICAL_FLAG_CHECKS)
    return min(hits * 0.5, 1.0)


def _score_dormancy(last_login_val, scope_end: date) -> float:
    """
    Component C — Dormancy linear gradient (0–1).
    0 days dormant → 0.0; >= DORMANCY_WINDOW days → 1.0; None → 1.0 (never logged in).
    """
    if last_login_val is None:
        return 1.0
    ll = _parse_date(last_login_val)
    if ll is None:
        return 1.0
    delta = (scope_end - ll).days
    if delta <= 0:
        return 0.0
    return min(delta / DORMANCY_WINDOW, 1.0)


def _score_privilege(role_count_val, system_count_val) -> float:
    """
    Component D — Privilege breadth (0–1).
    Blended: 60% role count normalised, 40% system count normalised.
    """
    try:
        roles = float(role_count_val) if role_count_val is not None else 0.0
    except (TypeError, ValueError):
        roles = 0.0
    try:
        systems = float(system_count_val) if system_count_val is not None else 0.0
    except (TypeError, ValueError):
        systems = 0.0

    role_norm   = min(roles   / MAX_ROLES_CAP,   1.0)
    system_norm = min(systems / MAX_SYSTEMS_CAP, 1.0)
    return 0.6 * role_norm + 0.4 * system_norm


def _score_contractor(employment_type_val, expiry_val) -> float:
    """
    Component E — Contractor risk (0–1).
    Contractor with no/missing expiry → 1.0.
    Non-contractor → 0.0.
    Contractor with expiry → 0.25 (still carries some residual risk).
    """
    if employment_type_val is None:
        return 0.0
    et = str(employment_type_val).strip().lower()
    is_contractor = et in {
        "contractor", "contract", "temp", "temporary",
        "vendor", "third party", "3rd party", "agency",
        "freelance", "interim",
    }
    if not is_contractor:
        return 0.0
    expiry = _parse_date(expiry_val)
    return 0.25 if expiry is not None else 1.0


def _band(score: int) -> str:
    for threshold, label in BAND_THRESHOLDS:
        if score >= threshold:
            return label
    return "LOW"


# ---------------------------------------------------------------------------
# Per-identity aggregation helpers
# ---------------------------------------------------------------------------

def _aggregate_identity_rows(group: pd.DataFrame, scope_end: date) -> dict:
    """
    Given all finding rows for one identity, compute all five component scores
    and return a dict with the composite IRS and band.

    Columns consumed — mapped to actual engine findings_df output names:
      IssueType       (critical flag check)
      Severity        (emoji-prefixed: "🔴 CRITICAL")
      LastLoginDate   (dormancy)
      RoleCount       (privilege breadth — optional)
      SystemCount     (privilege breadth — optional)
      EmploymentType  (contractor risk — optional)
      ContractExpiry  (contractor risk — optional)
    """
    # IssueType is the engine column — used for both severity lookup and critical flag
    issue_types = group["IssueType"].dropna().tolist() if "IssueType" in group.columns else []
    severities  = group["Severity"].dropna().tolist()  if "Severity"  in group.columns else []

    # Last login — engine column is LastLoginDate
    last_login = None
    for col in ("LastLoginDate", "Last_Login", "LastLogin"):
        if col in group.columns:
            ll_series = group[col].dropna()
            if not ll_series.empty:
                parsed = [_parse_date(v) for v in ll_series]
                valid  = [d for d in parsed if d is not None]
                last_login = max(valid) if valid else None
            break

    # Role / system count — try both naming conventions
    role_count   = 0
    system_count = 0
    for col in ("RoleCount", "Role_Count"):
        if col in group.columns:
            try:
                role_count = pd.to_numeric(group[col], errors="coerce").max()
                role_count = 0 if pd.isna(role_count) else role_count
            except Exception:
                pass
            break
    for col in ("SystemCount", "System_Count"):
        if col in group.columns:
            try:
                system_count = pd.to_numeric(group[col], errors="coerce").max()
                system_count = 0 if pd.isna(system_count) else system_count
            except Exception:
                pass
            break

    # Employment / expiry — try both naming conventions
    emp_type = None
    exp_date = None
    for col in ("EmploymentType", "Employment_Type", "ContractType"):
        if col in group.columns:
            vals = group[col].dropna()
            emp_type = vals.iloc[0] if not vals.empty else None
            break
    for col in ("ContractExpiry", "Contract_Expiry", "ContractEndDate"):
        if col in group.columns:
            vals = group[col].dropna()
            exp_date = vals.iloc[0] if not vals.empty else None
            break

    # Component scores
    c_sev        = _score_severity(issue_types, severities)
    c_critical   = _score_critical_flag(issue_types)
    c_dormancy   = _score_dormancy(last_login, scope_end)
    c_privilege  = _score_privilege(role_count, system_count)
    c_contractor = _score_contractor(emp_type, exp_date)

    # Composite
    composite = (
        W_SEVERITY   * c_sev        +
        W_CRITICAL   * c_critical   +
        W_DORMANCY   * c_dormancy   +
        W_PRIVILEGE  * c_privilege  +
        W_CONTRACTOR * c_contractor
    )
    score = min(int(round(composite * 100)), 100)

    return {
        "identity_risk_score":    score,
        "risk_band":              _band(score),
        "irs_c_severity":         round(c_sev,        4),
        "irs_c_critical_flag":    round(c_critical,   4),
        "irs_c_dormancy":         round(c_dormancy,   4),
        "irs_c_privilege":        round(c_privilege,  4),
        "irs_c_contractor":       round(c_contractor, 4),
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def compute_irs(
    findings_df: pd.DataFrame,
    scope_end:   date,
) -> pd.DataFrame:
    """
    Attach identity_risk_score (0–100) and risk_band to findings_df.

    Parameters
    ----------
    findings_df : pd.DataFrame
        Output of run_audit(). Must contain at minimum an identity column.
        Recognised identity columns (checked in order):
          "Username", "User", "Account", "Email", "Identity"
    scope_end : date
        Audit period end date (Python date object).

    Returns
    -------
    pd.DataFrame
        findings_df with additional columns:
          identity_risk_score, risk_band,
          irs_c_severity, irs_c_critical_flag, irs_c_dormancy,
          irs_c_privilege, irs_c_contractor
    """
    if findings_df is None or findings_df.empty:
        findings_df["identity_risk_score"] = pd.Series(dtype=int)
        findings_df["risk_band"]           = pd.Series(dtype=str)
        return findings_df

    # Resolve identity column
    identity_col = None
    for candidate in ("Username", "User", "Account", "Email", "Identity"):
        if candidate in findings_df.columns:
            identity_col = candidate
            break
    if identity_col is None:
        # Fallback — use index; score everything as a single group
        findings_df["identity_risk_score"] = 0
        findings_df["risk_band"]           = "LOW"
        return findings_df

    # Compute scores per identity
    score_map = {}
    for identity, group in findings_df.groupby(identity_col, sort=False):
        score_map[identity] = _aggregate_identity_rows(group, scope_end)

    # Expand score_map back to findings_df rows
    score_df = pd.DataFrame.from_dict(score_map, orient="index")
    score_df.index.name = identity_col
    score_df = score_df.reset_index()

    findings_df = findings_df.merge(score_df, on=identity_col, how="left")

    # Ensure int dtype for score column
    findings_df["identity_risk_score"] = (
        pd.to_numeric(findings_df["identity_risk_score"], errors="coerce")
        .fillna(0)
        .astype(int)
    )

    return findings_df


def build_risk_register(findings_df: pd.DataFrame) -> pd.DataFrame:
    """
    Produce the Identity Risk Register — one row per identity, ranked by score.
    Used for Excel Sheet 10.

    Returns
    -------
    pd.DataFrame with columns:
      Rank, Identity, Risk_Score, Risk_Band, Finding_Count,
      Critical_Findings, High_Findings, Medium_Findings,
      Checks_Triggered, IRS_Severity, IRS_Critical_Flag,
      IRS_Dormancy, IRS_Privilege, IRS_Contractor
    """
    if findings_df is None or findings_df.empty:
        return pd.DataFrame()

    identity_col = None
    for candidate in ("Username", "User", "Account", "Email", "Identity"):
        if candidate in findings_df.columns:
            identity_col = candidate
            break
    if identity_col is None:
        return pd.DataFrame()

    required_irs_cols = ["identity_risk_score", "risk_band"]
    for col in required_irs_cols:
        if col not in findings_df.columns:
            return pd.DataFrame()

    rows = []
    for identity, group in findings_df.groupby(identity_col, sort=False):
        score = group["identity_risk_score"].iloc[0]
        band  = group["risk_band"].iloc[0]

        sev_counts = group["Severity"].str.upper().value_counts() if "Severity" in group.columns else pd.Series(dtype=int)
        checks_triggered = ", ".join(sorted(group["Check"].dropna().unique())) if "Check" in group.columns else ""

        rows.append({
            "Identity":          identity,
            "Risk_Score":        score,
            "Risk_Band":         band,
            "Finding_Count":     len(group),
            "Critical_Findings": sev_counts.get("CRITICAL", 0),
            "High_Findings":     sev_counts.get("HIGH",     0),
            "Medium_Findings":   sev_counts.get("MEDIUM",   0),
            "Checks_Triggered":  checks_triggered,
            "IRS_Severity":      group["irs_c_severity"].iloc[0]       if "irs_c_severity"      in group.columns else None,
            "IRS_Critical_Flag": group["irs_c_critical_flag"].iloc[0]  if "irs_c_critical_flag" in group.columns else None,
            "IRS_Dormancy":      group["irs_c_dormancy"].iloc[0]       if "irs_c_dormancy"      in group.columns else None,
            "IRS_Privilege":     group["irs_c_privilege"].iloc[0]      if "irs_c_privilege"     in group.columns else None,
            "IRS_Contractor":    group["irs_c_contractor"].iloc[0]     if "irs_c_contractor"    in group.columns else None,
        })

    register = (
        pd.DataFrame(rows)
        .sort_values("Risk_Score", ascending=False)
        .reset_index(drop=True)
    )
    register.insert(0, "Rank", register.index + 1)
    return register


def irs_summary_stats(register_df: pd.DataFrame) -> dict:
    """
    Aggregate statistics for the Engagement Cover / Executive Summary sheet.

    Returns
    -------
    dict with keys:
      mean_score, median_score, max_score,
      critical_count, high_count, medium_count, low_count,
      pct_critical, pct_high
    """
    if register_df is None or register_df.empty or "Risk_Score" not in register_df.columns:
        return {}

    scores = register_df["Risk_Score"]
    bands  = register_df["Risk_Band"] if "Risk_Band" in register_df.columns else pd.Series(dtype=str)
    n      = len(register_df)

    band_counts = bands.value_counts()

    return {
        "mean_score":     round(float(scores.mean()), 1),
        "median_score":   round(float(scores.median()), 1),
        "max_score":      int(scores.max()),
        "critical_count": int(band_counts.get("CRITICAL", 0)),
        "high_count":     int(band_counts.get("HIGH",     0)),
        "medium_count":   int(band_counts.get("MEDIUM",   0)),
        "low_count":      int(band_counts.get("LOW",      0)),
        "pct_critical":   round(band_counts.get("CRITICAL", 0) / n * 100, 1) if n else 0.0,
        "pct_high":       round(band_counts.get("HIGH",     0) / n * 100, 1) if n else 0.0,
    }

