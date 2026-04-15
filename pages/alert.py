"""
alerts.py — Post-Termination Login Slack & Email Alert System
Plugs directly into engine.py findings_df output.
Call send_post_termination_alerts(findings_df, config) after run_audit().
"""

import requests
import smtplib
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
import pandas as pd


# ─────────────────────────────────────────────────────────────────────────────
#  ALERT CONFIG SCHEMA
#  Pass this dict from tool.py sidebar inputs
# ─────────────────────────────────────────────────────────────────────────────
# config = {
#     "slack_webhook_url":  "https://hooks.slack.com/services/XXX/YYY/ZZZ",
#     "email_enabled":      True,
#     "smtp_host":          "smtp.gmail.com",
#     "smtp_port":          587,
#     "smtp_user":          "alerts@yourcompany.com",
#     "smtp_password":      "your-app-password",
#     "alert_recipients":   ["ciso@yourcompany.com", "it-security@yourcompany.com"],
#     "client_name":        "Acme Corp",
#     "audit_ref":          "IAR-2025-001",
# }


# ─────────────────────────────────────────────────────────────────────────────
#  CORE: EXTRACT POST-TERMINATION FINDINGS
# ─────────────────────────────────────────────────────────────────────────────

def get_post_termination_findings(findings_df: pd.DataFrame) -> pd.DataFrame:
    """Filter findings_df for Post-Termination Login entries only."""
    if findings_df is None or findings_df.empty:
        return pd.DataFrame()
    mask = findings_df["IssueType"] == "Post-Termination Login"
    return findings_df[mask].copy()


# ─────────────────────────────────────────────────────────────────────────────
#  SLACK ALERT
# ─────────────────────────────────────────────────────────────────────────────

def _build_slack_payload(pt_findings: pd.DataFrame, config: dict) -> dict:
    """Build Slack Block Kit message payload from post-termination findings."""
    client    = config.get("client_name", "Unknown Client")
    ref       = config.get("audit_ref",   "N/A")
    count     = len(pt_findings)
    timestamp = datetime.now().strftime("%d %b %Y %H:%M UTC")

    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"🚨 CRITICAL ALERT — Post-Termination Login Detected",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Client:*\n{client}"},
                {"type": "mrkdwn", "text": f"*Audit Ref:*\n{ref}"},
                {"type": "mrkdwn", "text": f"*Accounts Flagged:*\n{count}"},
                {"type": "mrkdwn", "text": f"*Detected At:*\n{timestamp}"},
            ],
        },
        {"type": "divider"},
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    "*Required Actions:*\n"
                    "1. Disable account immediately\n"
                    "2. Preserve all access logs — do not delete evidence\n"
                    "3. Escalate to IT Security + Legal\n"
                    "4. Assess GDPR Art.33 breach notification (72-hour window)"
                ),
            },
        },
        {"type": "divider"},
    ]

    for _, row in pt_findings.iterrows():
        email      = str(row.get("Email",              "Unknown"))
        name       = str(row.get("FullName",           "Unknown"))
        dept       = str(row.get("Department",         "Unknown"))
        access     = str(row.get("AccessLevel",        "Unknown"))
        detail     = str(row.get("Detail",             ""))
        post_days  = row.get("DaysPostTermination",    "")
        system     = str(row.get("SystemName",         "Unknown"))
        last_login = str(row.get("LastLoginDate",      "Unknown"))

        post_days_str = f"{int(float(post_days))} days after termination" if post_days and str(post_days).lower() not in ("nan","none","") else "timing unclear"

        blocks.append({
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Account:*\n`{email}`"},
                {"type": "mrkdwn", "text": f"*Name:*\n{name}"},
                {"type": "mrkdwn", "text": f"*Department:*\n{dept}"},
                {"type": "mrkdwn", "text": f"*Access Level:*\n`{access}`"},
                {"type": "mrkdwn", "text": f"*System:*\n{system}"},
                {"type": "mrkdwn", "text": f"*Last Login:*\n{last_login}"},
                {"type": "mrkdwn", "text": f"*Post-Term Gap:*\n{post_days_str}"},
                {"type": "mrkdwn", "text": f"*Finding:*\n{detail[:200]}"},
            ],
        })
        blocks.append({"type": "divider"})

    blocks.append({
        "type": "context",
        "elements": [
            {
                "type": "mrkdwn",
                "text": "Sent by *IAM Audit Tool — 80* | This alert requires immediate action by IT Security and Legal.",
            }
        ],
    })

    return {"blocks": blocks}


def send_slack_alert(pt_findings: pd.DataFrame, config: dict) -> tuple[bool, str]:
    """
    POST a Slack Block Kit alert to the configured webhook URL.
    Returns (success: bool, message: str).
    """
    webhook_url = config.get("slack_webhook_url", "").strip()
    if not webhook_url:
        return False, "No Slack webhook URL configured."
    if pt_findings.empty:
        return True, "No post-termination findings — no alert sent."

    payload = _build_slack_payload(pt_findings, config)

    try:
        response = requests.post(
            webhook_url,
            data=json.dumps(payload),
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        if response.status_code == 200 and response.text == "ok":
            return True, f"Slack alert sent — {len(pt_findings)} finding(s) reported."
        else:
            return False, f"Slack returned {response.status_code}: {response.text[:200]}"
    except requests.exceptions.Timeout:
        return False, "Slack alert timed out — check webhook URL and network."
    except requests.exceptions.RequestException as e:
        return False, f"Slack alert failed: {str(e)}"


# ─────────────────────────────────────────────────────────────────────────────
#  EMAIL ALERT
# ─────────────────────────────────────────────────────────────────────────────

def _build_email_html(pt_findings: pd.DataFrame, config: dict) -> str:
    """Build HTML email body for post-termination alert."""
    client    = config.get("client_name", "Unknown Client")
    ref       = config.get("audit_ref",   "N/A")
    timestamp = datetime.now().strftime("%d %B %Y %H:%M UTC")
    count     = len(pt_findings)

    rows_html = ""
    for _, row in pt_findings.iterrows():
        email     = str(row.get("Email",           "Unknown"))
        name      = str(row.get("FullName",        "Unknown"))
        dept      = str(row.get("Department",      "Unknown"))
        access    = str(row.get("AccessLevel",     "Unknown"))
        detail    = str(row.get("Detail",          ""))
        post_days = row.get("DaysPostTermination", "")
        system    = str(row.get("SystemName",      "Unknown"))
        last_login= str(row.get("LastLoginDate",   "Unknown"))

        post_days_str = (
            f"{int(float(post_days))} days after termination"
            if post_days and str(post_days).lower() not in ("nan","none","")
            else "timing unclear"
        )

        rows_html += f"""
        <tr style="border-bottom:1px solid #e5e7eb;">
            <td style="padding:12px 8px;font-weight:600;color:#dc2626;">{email}</td>
            <td style="padding:12px 8px;">{name}</td>
            <td style="padding:12px 8px;">{dept}</td>
            <td style="padding:12px 8px;font-family:monospace;font-size:12px;">{access}</td>
            <td style="padding:12px 8px;">{system}</td>
            <td style="padding:12px 8px;color:#dc2626;font-weight:600;">{post_days_str}</td>
            <td style="padding:12px 8px;">{last_login}</td>
            <td style="padding:12px 8px;font-size:12px;color:#6b7280;">{detail[:150]}{'...' if len(detail) > 150 else ''}</td>
        </tr>"""

    return f"""
    <!DOCTYPE html>
    <html>
    <head><meta charset="utf-8"></head>
    <body style="font-family:Arial,sans-serif;background:#f9fafb;margin:0;padding:20px;">
        <div style="max-width:960px;margin:0 auto;background:#ffffff;border-radius:8px;
                    border:1px solid #e5e7eb;overflow:hidden;">

            <!-- Header -->
            <div style="background:#dc2626;padding:24px 32px;">
                <h1 style="color:#ffffff;margin:0;font-size:22px;">
                    🚨 CRITICAL — Post-Termination Login Detected
                </h1>
                <p style="color:#fecaca;margin:8px 0 0;font-size:14px;">
                    Immediate action required by IT Security and Legal
                </p>
            </div>

            <!-- Meta -->
            <div style="padding:24px 32px;background:#fef2f2;border-bottom:1px solid #fecaca;">
                <table style="width:100%;border-collapse:collapse;">
                    <tr>
                        <td style="padding:4px 16px 4px 0;font-size:13px;color:#6b7280;">Client</td>
                        <td style="padding:4px 0;font-size:13px;font-weight:600;">{client}</td>
                        <td style="padding:4px 16px 4px 32px;font-size:13px;color:#6b7280;">Audit Reference</td>
                        <td style="padding:4px 0;font-size:13px;font-weight:600;">{ref}</td>
                    </tr>
                    <tr>
                        <td style="padding:4px 16px 4px 0;font-size:13px;color:#6b7280;">Accounts Flagged</td>
                        <td style="padding:4px 0;font-size:13px;font-weight:600;color:#dc2626;">{count}</td>
                        <td style="padding:4px 16px 4px 32px;font-size:13px;color:#6b7280;">Alert Generated</td>
                        <td style="padding:4px 0;font-size:13px;font-weight:600;">{timestamp}</td>
                    </tr>
                </table>
            </div>

            <!-- Findings table -->
            <div style="padding:24px 32px;">
                <h2 style="font-size:16px;color:#111827;margin:0 0 16px;">Flagged Accounts</h2>
                <div style="overflow-x:auto;">
                    <table style="width:100%;border-collapse:collapse;font-size:13px;">
                        <thead>
                            <tr style="background:#f3f4f6;text-align:left;">
                                <th style="padding:10px 8px;font-weight:600;color:#374151;">Email</th>
                                <th style="padding:10px 8px;font-weight:600;color:#374151;">Name</th>
                                <th style="padding:10px 8px;font-weight:600;color:#374151;">Department</th>
                                <th style="padding:10px 8px;font-weight:600;color:#374151;">Access</th>
                                <th style="padding:10px 8px;font-weight:600;color:#374151;">System</th>
                                <th style="padding:10px 8px;font-weight:600;color:#374151;">Post-Term Gap</th>
                                <th style="padding:10px 8px;font-weight:600;color:#374151;">Last Login</th>
                                <th style="padding:10px 8px;font-weight:600;color:#374151;">Detail</th>
                            </tr>
                        </thead>
                        <tbody>{rows_html}</tbody>
                    </table>
                </div>
            </div>

            <!-- Required actions -->
            <div style="padding:0 32px 24px;">
                <div style="background:#fef2f2;border:1px solid #fecaca;border-radius:6px;padding:20px;">
                    <h3 style="margin:0 0 12px;font-size:14px;color:#dc2626;">Required Actions</h3>
                    <ol style="margin:0;padding-left:20px;font-size:13px;color:#374151;line-height:2;">
                        <li><strong>Disable account immediately</strong> and preserve all access logs</li>
                        <li><strong>Escalate to IT Security + Legal</strong> — do not delete any evidence</li>
                        <li><strong>Determine what data or systems were accessed</strong> post-termination</li>
                        <li><strong>Assess GDPR Art.33</strong> breach notification requirement (72-hour window from discovery)</li>
                    </ol>
                </div>
            </div>

            <!-- Footer -->
            <div style="padding:16px 32px;background:#f9fafb;border-top:1px solid #e5e7eb;">
                <p style="margin:0;font-size:12px;color:#9ca3af;">
                    Sent by IAM Audit Tool — 80 &nbsp;|&nbsp;
                    This alert was generated automatically. Review and act immediately.
                </p>
            </div>
        </div>
    </body>
    </html>
    """


def send_email_alert(pt_findings: pd.DataFrame, config: dict) -> tuple[bool, str]:
    """
    Send an HTML email alert via SMTP for post-termination findings.
    Returns (success: bool, message: str).
    """
    recipients = config.get("alert_recipients", [])
    if not recipients:
        return False, "No email recipients configured."
    if not config.get("email_enabled", False):
        return False, "Email alerts are disabled in config."
    if pt_findings.empty:
        return True, "No post-termination findings — no email sent."

    smtp_host = config.get("smtp_host", "smtp.gmail.com")
    smtp_port = int(config.get("smtp_port", 587))
    smtp_user = config.get("smtp_user", "")
    smtp_pass = config.get("smtp_password", "")
    client    = config.get("client_name", "Unknown Client")
    count     = len(pt_findings)

    if not smtp_user or not smtp_pass:
        return False, "SMTP credentials not configured."

    subject = (
        f"🚨 CRITICAL ALERT — {count} Post-Termination Login(s) Detected | {client}"
    )
    html_body = _build_email_html(pt_findings, config)

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = smtp_user
    msg["To"]      = ", ".join(recipients)
    msg.attach(MIMEText(html_body, "html"))

    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as server:
            server.ehlo()
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_user, recipients, msg.as_string())
        return True, f"Email alert sent to {len(recipients)} recipient(s) — {count} finding(s) reported."
    except smtplib.SMTPAuthenticationError:
        return False, "SMTP authentication failed — check username and app password."
    except smtplib.SMTPException as e:
        return False, f"SMTP error: {str(e)}"
    except Exception as e:
        return False, f"Email alert failed: {str(e)}"


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN ENTRY POINT — call this from tool.py after run_audit()
# ─────────────────────────────────────────────────────────────────────────────

def send_post_termination_alerts(
    findings_df: pd.DataFrame,
    config: dict,
) -> list[dict]:
    """
    Check findings_df for Post-Termination Login entries and fire
    Slack and/or email alerts as configured.

    Args:
        findings_df:  DataFrame returned by engine.run_audit()
        config:       Alert configuration dict (see schema at top of file)

    Returns:
        List of result dicts: [{"channel": "slack"|"email", "success": bool, "message": str}]

    Usage in tool.py:
        from alerts import send_post_termination_alerts
        results = send_post_termination_alerts(findings_df, alert_config)
        for r in results:
            if r["success"]:
                st.success(r["message"])
            else:
                st.warning(r["message"])
    """
    pt_findings = get_post_termination_findings(findings_df)
    results     = []

    # Slack
    if config.get("slack_webhook_url", "").strip():
        ok, msg = send_slack_alert(pt_findings, config)
        results.append({"channel": "slack", "success": ok, "message": msg})

    # Email
    if config.get("email_enabled", False) and config.get("alert_recipients"):
        ok, msg = send_email_alert(pt_findings, config)
        results.append({"channel": "email", "success": ok, "message": msg})

    if not results:
        results.append({
            "channel": "none",
            "success": False,
            "message": "No alert channels configured. Add a Slack webhook URL or enable email alerts.",
        })

    return results
