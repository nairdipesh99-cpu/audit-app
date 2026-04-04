#!/usr/bin/env python3
"""
ISO/IEC 27002:2022 Gap Analysis Tool
=====================================
Compares an internal policy document against an ISO/IEC standard
and produces a structured gap analysis report.

Usage:
    python gap_analysis_tool.py --standard <file> --policy <file> [--output <file>] [--controls <ids>]

Supported file types: .pdf, .docx, .txt

Requirements:
    pip install pypdf python-docx pdfminer.six
"""

import argparse
import json
import os
import re
import sys
import textwrap
import pathlib
import urllib.request	
import urllib.error
from dataclasses import dataclass, field, asdict
from typing import Optional


# ─────────────────────────────────────────────
# Data models
# ─────────────────────────────────────────────

@dataclass
class ControlRequirement:
    control_id: str
    control_name: str
    key_requirements: list[str]
    standard_text: str = ""


@dataclass
class GapFinding:
    control_id: str
    control_name: str
    status: str          # "Full Match" | "Partial Match" | "Gap"
    matched_items: list[str] = field(default_factory=list)
    missing_items: list[str] = field(default_factory=list)
    remediation: str = ""
    evidence_snippets: list[str] = field(default_factory=list)


# ─────────────────────────────────────────────
# File extraction
# ─────────────────────────────────────────────

def extract_text_from_pdf(path: str) -> str:
    """Extract text from a PDF using pypdf with pdfminer fallback."""
    text = ""
    try:
        from pypdf import PdfReader
        reader = PdfReader(path)
        pages = [page.extract_text() or "" for page in reader.pages]
        text = "\n".join(pages)
        if len(text.strip()) > 200:
            return text
    except Exception as e:
        print(f"  [pypdf] Warning: {e}", file=sys.stderr)

    # Fallback: pdfminer
    try:
        from pdfminer.high_level import extract_text as pm_extract
        text = pm_extract(path)
        return text
    except Exception as e:
        print(f"  [pdfminer] Warning: {e}", file=sys.stderr)

    return text


def extract_text_from_docx(path: str) -> str:
    """Extract text from a .docx file."""
    try:
        import docx
        doc = docx.Document(path)
        paragraphs = [p.text for p in doc.paragraphs if p.text.strip()]
        return "\n".join(paragraphs)
    except Exception as e:
        raise RuntimeError(f"Failed to read .docx file: {e}")


def extract_text(path: str) -> str:
    """Auto-detect file type and extract text."""
    path = path.strip()
    if not os.path.exists(path):
        raise FileNotFoundError(f"File not found: {path}")

    suffix = pathlib.Path(path).suffix.lower()
    print(f"  Extracting text from: {os.path.basename(path)} ({suffix})")

    if suffix == ".pdf":
        return extract_text_from_pdf(path)
    elif suffix == ".docx":
        return extract_text_from_docx(path)
    elif suffix in (".txt", ".md", ".text"):
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    else:
        raise ValueError(f"Unsupported file type: {suffix}. Supported: .pdf, .docx, .txt")


# ─────────────────────────────────────────────
# ISO 27002:2022 Access Control control library
# ─────────────────────────────────────────────

ACCESS_CONTROL_CONTROLS: list[ControlRequirement] = [
    ControlRequirement(
        control_id="5.15",
        control_name="Access control",
        key_requirements=[
            "access control rules based on business and security requirements",
            "topic-specific access control policy",
            "need-to-know and need-to-use principles",
            "least privilege principle",
            "segregation of access control functions (request, authorise, administer)",
            "linkage to information classification",
            "physical and logical access controls aligned",
            "access control model (MAC/DAC/RBAC/ABAC)",
            "regular review of access control rules",
        ]
    ),
    ControlRequirement(
        control_id="5.16",
        control_name="Identity management",
        key_requirements=[
            "unique identity linked to a single person",
            "identity lifecycle management (create, modify, disable, delete)",
            "shared or generic accounts prohibited or controlled",
            "timely disabling of identities when no longer required",
            "controls for non-human entity identities (service accounts)",
            "audit log of identity events",
            "re-verification process for identity changes",
            "duplicate identities avoided",
        ]
    ),
    ControlRequirement(
        control_id="5.17",
        control_name="Authentication information",
        key_requirements=[
            "password complexity and minimum length requirements",
            "prohibition on sharing authentication information",
            "change of temporary or default credentials immediately",
            "secure transmission of credentials (no clear-text)",
            "password management system requirements",
            "compromised credential handling procedure",
            "password history and reuse controls",
            "user acknowledgement of authentication responsibilities",
        ]
    ),
    ControlRequirement(
        control_id="5.18",
        control_name="Access rights",
        key_requirements=[
            "formal access provisioning process",
            "access rights approved by asset owner or management",
            "central register of access rights maintained",
            "temporary access with defined expiry",
            "access rights removed or adjusted on termination or role change",
            "periodic review of access rights (not only annual)",
            "consideration of risk factors before termination",
            "segregation of request and approval roles",
        ]
    ),
    ControlRequirement(
        control_id="8.2",
        control_name="Privileged access rights",
        key_requirements=[
            "privileged access restricted and controlled",
            "privileged accounts not used for day-to-day tasks",
            "enhanced authentication (MFA) for privileged access",
            "periodic review of privileged users",
            "no generic admin accounts (root/admin)",
            "time-bound or just-in-time privileged access grants",
            "logging of all privileged access",
            "separate privileged and standard user accounts",
        ]
    ),
    ControlRequirement(
        control_id="8.3",
        control_name="Information access restriction",
        key_requirements=[
            "access restricted according to information classification",
            "no anonymous access to sensitive information",
            "access granularity (read, write, delete, execute) defined",
            "isolation of sensitive applications or data",
            "dynamic access management for high-value information",
            "configuration mechanisms to enforce access restrictions",
        ]
    ),
    ControlRequirement(
        control_id="8.5",
        control_name="Secure authentication",
        key_requirements=[
            "multi-factor authentication (MFA) required",
            "account lockout after failed login attempts",
            "session timeout or inactivity lockout",
            "no clear-text password transmission",
            "general warning notice displayed at login",
            "last successful login details displayed",
            "no helpful error messages on login failure",
            "brute-force protection mechanisms",
        ]
    ),
]


# ─────────────────────────────────────────────
# Keyword matching engine
# ─────────────────────────────────────────────

# Maps each requirement to a list of keyword signals to look for in policy text
REQUIREMENT_KEYWORDS: dict[str, list[str]] = {
    # 5.15
    "access control rules based on business and security requirements":
        ["business requirement", "security requirement", "access rule", "rules for access"],
    "topic-specific access control policy":
        ["access control policy", "policy on access", "access policy"],
    "need-to-know and need-to-use principles":
        ["need to know", "need-to-know", "need to use", "need-to-use"],
    "least privilege principle":
        ["least privilege", "minimum necessary", "minimum access", "principle of least"],
    "segregation of access control functions (request, authorise, administer)":
        ["segregation", "segregate", "separation of duties", "separate roles", "request.*approv", "approv.*request"],
    "linkage to information classification":
        ["classification", "classified", "data classification", "information classification"],
    "physical and logical access controls aligned":
        ["physical access", "logical access", "physical and logical"],
    "access control model (MAC/DAC/RBAC/ABAC)":
        ["rbac", "role.based", "role based", "mac", "dac", "abac", "attribute.based", "mandatory access", "discretionary"],
    "regular review of access control rules":
        ["review", "annual", "annually", "periodic", "regular review"],

    # 5.16
    "unique identity linked to a single person":
        ["unique", "unique id", "unique user", "unique identifier", "individual account"],
    "identity lifecycle management (create, modify, disable, delete)":
        ["lifecycle", "life cycle", "provisioning", "de-provisioning", "deprovisioning", "identity management"],
    "shared or generic accounts prohibited or controlled":
        ["shared account", "generic account", "shared id", "group account", "shared credentials"],
    "timely disabling of identities when no longer required":
        ["disable", "deactivate", "revoke", "timely", "immediately", "same day", "prompt"],
    "controls for non-human entity identities (service accounts)":
        ["service account", "system account", "non-human", "machine identity", "application account"],
    "audit log of identity events":
        ["audit", "audit log", "audit trail", "log", "record", "event log"],
    "re-verification process for identity changes":
        ["re-verification", "re.verif", "verify", "verification", "re-authenticate"],
    "duplicate identities avoided":
        ["duplicate", "no duplicate", "single identity", "one account per user"],

    # 5.17
    "password complexity and minimum length requirements":
        ["password complexity", "complex password", "minimum length", "length requirement",
         "uppercase", "lowercase", "special character", "alphanumeric", "character requirement"],
    "prohibition on sharing authentication information":
        ["not share", "do not share", "sharing.*password", "password.*sharing", "confidential",
         "not.*disclose", "prohibited.*share"],
    "change of temporary or default credentials immediately":
        ["default password", "temporary password", "initial password", "change.*first",
         "first login", "first use", "change immediately"],
    "secure transmission of credentials (no clear-text)":
        ["secure transmission", "encrypted", "no clear text", "not clear text",
         "tls", "ssl", "https", "protected channel"],
    "password management system requirements":
        ["password manager", "password vault", "password management system", "password tool"],
    "compromised credential handling procedure":
        ["compromised", "breach", "leaked", "stolen", "credential.*incident", "reset.*compromised"],
    "password history and reuse controls":
        ["password history", "reuse", "re-use", "previous password", "cannot reuse"],
    "user acknowledgement of authentication responsibilities":
        ["acknowledge", "responsibility", "terms", "agree", "training", "awareness"],

    # 5.18
    "formal access provisioning process":
        ["provisioning", "provision", "access request", "request.*access", "grant access", "formal process"],
    "access rights approved by asset owner or management":
        ["approved", "authorised", "authorized", "manager.*approv", "owner.*approv",
         "management.*approv", "approval.*access"],
    "central register of access rights maintained":
        ["register", "inventory", "central record", "access register", "record.*access",
         "maintain.*list", "access log"],
    "temporary access with defined expiry":
        ["temporary", "time.limited", "time limited", "expiry", "expiration", "expire", "temporary access"],
    "access rights removed or adjusted on termination or role change":
        ["terminat", "revoke", "role change", "leaver", "joiner", "mover",
         "immediately.*terminat", "terminat.*immediately", "removed.*access", "access.*removed"],
    "periodic review of access rights (not only annual)":
        ["review", "recertif", "periodic", "quarterly", "annually", "annual review", "access review"],
    "consideration of risk factors before termination":
        ["risk", "risk factor", "risk assess", "consider.*terminat", "terminat.*consider"],
    "segregation of request and approval roles":
        ["segregat", "separation", "separate role", "request.*approv", "approv.*request",
         "different person", "independent"],

    # 8.2
    "privileged access restricted and controlled":
        ["privileged", "admin", "administrator", "administrative", "elevated", "restricted"],
    "privileged accounts not used for day-to-day tasks":
        ["day.to.day", "daily task", "general use", "separate account", "standard account",
         "not.*general", "not.*everyday"],
    "enhanced authentication (MFA) for privileged access":
        ["mfa", "multi.factor", "multifactor", "two.factor", "2fa", "strong authentication",
         "additional factor"],
    "periodic review of privileged users":
        ["review.*privileged", "privileged.*review", "admin.*review", "review.*admin"],
    "no generic admin accounts (root/admin)":
        ["generic", "root", "shared admin", "no generic", "named account", "individual admin"],
    "time-bound or just-in-time privileged access grants":
        ["time.bound", "just.in.time", "temporary.*privileged", "privileged.*temporary",
         "limited time", "break.glass", "on.demand"],
    "logging of all privileged access":
        ["log", "audit", "monitor", "record", "privileged.*log", "admin.*log",
         "administrative.*log", "all.*action"],
    "separate privileged and standard user accounts":
        ["separate account", "two accounts", "standard account", "privileged account",
         "different account", "dedicated.*admin"],

    # 8.3
    "access restricted according to information classification":
        ["classification", "classified", "sensitive", "confidential",
         "classification.*access", "access.*classification"],
    "no anonymous access to sensitive information":
        ["anonymous", "no anonymous", "public access", "unauthenticated",
         "prohibit.*anonymous", "anonymous.*prohibit"],
    "access granularity (read, write, delete, execute) defined":
        ["read", "write", "delete", "execute", "permission", "granular", "privilege level",
         "read.*write", "access level"],
    "isolation of sensitive applications or data":
        ["isolat", "segregat", "separate.*sensitive", "sensitive.*separate",
         "network segmentation", "network segment"],
    "dynamic access management for high-value information":
        ["dynamic", "real.time", "context.aware", "adaptive", "dynamic access"],
    "configuration mechanisms to enforce access restrictions":
        ["configuration", "technical control", "enforce", "system.*control", "automated"],

    # 8.5
    "multi-factor authentication (MFA) required":
        ["mfa", "multi.factor", "multifactor", "two.factor", "2fa", "multiple factor",
         "second factor"],
    "account lockout after failed login attempts":
        ["lockout", "lock out", "lock account", "failed.*attempt", "attempt.*failed",
         "maximum.*attempt", "failed.*login"],
    "session timeout or inactivity lockout":
        ["timeout", "time.out", "inactivity", "session.*expire", "idle", "auto.*logout",
         "automatic.*logout"],
    "no clear-text password transmission":
        ["clear.text", "cleartext", "plain.text", "plaintext", "unencrypted.*password",
         "password.*unencrypted", "encrypt.*transmit"],
    "general warning notice displayed at login":
        ["warning", "notice", "banner", "unauthorized.*access", "authorised.*only",
         "authorized.*only", "login.*notice"],
    "last successful login details displayed":
        ["last.*login", "previous.*login", "last.*logon", "last.*access", "login.*history"],
    "no helpful error messages on login failure":
        ["error message", "generic error", "no.*hint", "not.*indicate", "vague error",
         "not.*disclose.*error"],
    "brute-force protection mechanisms":
        ["brute.force", "rate.limit", "throttl", "captcha", "lockout", "failed.*attempt"],
}


def normalise(text: str) -> str:
    """Lowercase and collapse whitespace for matching."""
    return re.sub(r"\s+", " ", text.lower())


def find_evidence(text: str, keywords: list[str], window: int = 120) -> list[str]:
    """Return short text snippets around keyword matches."""
    norm = normalise(text)
    snippets = []
    seen_positions = set()
    for kw in keywords:
        pattern = re.compile(kw, re.IGNORECASE)
        for m in pattern.finditer(norm):
            pos = m.start()
            # Avoid near-duplicate snippets
            if any(abs(pos - p) < 80 for p in seen_positions):
                continue
            seen_positions.add(pos)
            start = max(0, pos - 60)
            end = min(len(text), pos + window)
            snippet = text[start:end].replace("\n", " ").strip()
            snippet = re.sub(r"\s+", " ", snippet)
            snippets.append(f"…{snippet}…")
            if len(snippets) >= 2:
                return snippets
    return snippets


def check_requirement(policy_text: str, requirement: str) -> tuple[bool, list[str]]:
    """Check if a requirement is addressed in the policy text.
    Returns (is_met, evidence_snippets)."""
    keywords = REQUIREMENT_KEYWORDS.get(requirement, [requirement.split()[:3]])
    evidence = find_evidence(policy_text, keywords)
    return len(evidence) > 0, evidence


def analyse_control(policy_text: str, control: ControlRequirement) -> GapFinding:
    """Run gap analysis for a single control."""
    matched = []
    missing = []
    all_evidence = []

    for req in control.key_requirements:
        is_met, evidence = check_requirement(policy_text, req)
        if is_met:
            matched.append(req)
            all_evidence.extend(evidence)
        else:
            missing.append(req)

    total = len(control.key_requirements)
    match_ratio = len(matched) / total if total > 0 else 0

    if match_ratio >= 0.85:
        status = "Full Match"
    elif match_ratio >= 0.35:
        status = "Partial Match"
    else:
        status = "Gap"

    remediation = generate_remediation(control.control_id, missing)

    return GapFinding(
        control_id=control.control_id,
        control_name=control.control_name,
        status=status,
        matched_items=matched,
        missing_items=missing,
        remediation=remediation,
        evidence_snippets=all_evidence[:3],
    )


def generate_remediation(control_id: str, missing: list[str]) -> str:
    """Generate a remediation suggestion based on missing items."""
    if not missing:
        return "No remediation required."

    remediation_map = {
        "5.15": "Define a formal access control model (RBAC/ABAC), document need-to-know and least-privilege principles, and align the policy with the information classification scheme.",
        "5.16": "Introduce identity lifecycle procedures covering provisioning, modification, disabling and deletion. Add controls for service accounts and require audit logging of all identity events.",
        "5.17": "Create a dedicated authentication standard covering password complexity, length, history, and reuse rules. Mandate secure credential transmission and define a process for handling compromised credentials.",
        "5.18": "Document a formal joiner/mover/leaver procedure. Establish a central access register, define temporary access expiry controls, and implement trigger-based reviews on role changes.",
        "8.2": "Mandate separate privileged and standard accounts per user, require MFA for all privileged sessions, prohibit generic admin accounts, and implement time-limited privileged grants with quarterly reviews.",
        "8.3": "Add a data access restriction section that maps access permissions to the information classification scheme. Define read/write/delete/execute granularity and prohibit anonymous access to sensitive resources.",
        "8.5": "Define explicit secure log-on requirements: MFA for remote and privileged access, account lockout thresholds (≤10 attempts), session inactivity timeout (≤15 minutes), and prohibition on clear-text credential transmission.",
    }
    return remediation_map.get(control_id, f"Address the {len(missing)} missing requirement(s) identified above.")


# ─────────────────────────────────────────────
# Report generation
# ─────────────────────────────────────────────

SEPARATOR = "=" * 72
THIN_SEP  = "-" * 72
STATUS_ICONS = {
    "Full Match":    "✅ Full Match",
    "Partial Match": "⚠️  Partial Match",
    "Gap":           "❌ Gap",
}


def wrap(text: str, indent: int = 4, width: int = 68) -> str:
    return textwrap.fill(text, width=width, initial_indent=" " * indent,
                         subsequent_indent=" " * indent)


def print_report(findings: list[GapFinding], policy_file: str, standard_file: str) -> None:
    """Print a formatted console report."""
    print()
    print(SEPARATOR)
    print("  ISO/IEC 27002:2022 — ACCESS CONTROL GAP ANALYSIS REPORT")
    print(SEPARATOR)
    print(f"  Standard : {os.path.basename(standard_file)}")
    print(f"  Policy   : {os.path.basename(policy_file)}")
    print()

    # Summary table
    counts = {"Full Match": 0, "Partial Match": 0, "Gap": 0}
    for f in findings:
        counts[f.status] += 1

    total = len(findings)
    print("  EXECUTIVE SUMMARY")
    print(THIN_SEP)
    print(f"  Controls analysed  : {total}")
    print(f"  Full Match         : {counts['Full Match']}  ({counts['Full Match']/total*100:.0f}%)")
    print(f"  Partial Match      : {counts['Partial Match']}  ({counts['Partial Match']/total*100:.0f}%)")
    print(f"  Gap                : {counts['Gap']}  ({counts['Gap']/total*100:.0f}%)")

    compliant = counts["Full Match"] + (counts["Partial Match"] * 0.5)
    maturity_pct = compliant / total * 100 if total else 0
    print(f"  Estimated maturity : {maturity_pct:.0f}%")
    print()

    # Detailed findings
    for finding in findings:
        print(SEPARATOR)
        icon = STATUS_ICONS.get(finding.status, finding.status)
        print(f"  Control {finding.control_id} — {finding.control_name}")
        print(f"  Status  : {icon}")
        print()

        if finding.matched_items:
            print("  REQUIREMENTS MET:")
            for item in finding.matched_items:
                print(wrap(f"• {item}", indent=4))

        if finding.missing_items:
            print()
            print("  REQUIREMENTS NOT MET (GAPS):")
            for item in finding.missing_items:
                print(wrap(f"• {item}", indent=4))

        if finding.evidence_snippets:
            print()
            print("  EVIDENCE FOUND IN POLICY:")
            for snip in finding.evidence_snippets:
                print(wrap(snip, indent=4))

        if finding.missing_items:
            print()
            print("  REMEDIATION:")
            print(wrap(finding.remediation, indent=4))

        print()

    print(SEPARATOR)
    print("  END OF REPORT")
    print(SEPARATOR)
    print()


def save_json_report(findings: list[GapFinding], output_path: str,
                     policy_file: str, standard_file: str) -> None:
    """Save findings to a JSON file."""
    report = {
        "standard": os.path.basename(standard_file),
        "policy": os.path.basename(policy_file),
        "summary": {
            "total_controls": len(findings),
            "full_match": sum(1 for f in findings if f.status == "Full Match"),
            "partial_match": sum(1 for f in findings if f.status == "Partial Match"),
            "gap": sum(1 for f in findings if f.status == "Gap"),
        },
        "findings": [asdict(f) for f in findings],
    }
    with open(output_path, "w", encoding="utf-8") as fp:
        json.dump(report, fp, indent=2, ensure_ascii=False)
    print(f"  JSON report saved to: {output_path}")


def save_txt_report(findings: list[GapFinding], output_path: str,
                    policy_file: str, standard_file: str) -> None:
    """Save a plain-text version of the report."""
    import io
    old_stdout = sys.stdout
    sys.stdout = buf = io.StringIO()
    print_report(findings, policy_file, standard_file)
    sys.stdout = old_stdout
    content = buf.getvalue()
    with open(output_path, "w", encoding="utf-8") as fp:
        fp.write(content)
    print(f"  Text report saved to: {output_path}")


# ─────────────────────────────────────────────
# CLI entry point
# ─────────────────────────────────────────────

def parse_args():
    st.title("🛡️ ISO/IEC 27002:2022 Gap Analysis Tool")
    st.markdown("Upload your documents below to start the AI-powered audit.")

    # These replace the command-line arguments with actual buttons
    standard_file = st.file_uploader("Upload ISO/IEC 27002 Standard", type=["pdf", "docx", "txt"])
    policy_file = st.file_uploader("Upload Internal Policy Document", type=["pdf", "docx", "txt"])
    
    # Optional settings
    controls_input = st.text_input("Specific Control IDs (optional)", placeholder="e.g. 5.15 5.16 8.2")
    
    # Create an "args" object that your existing code can understand
    class Args:
        def __init__(self, standard, policy, controls):
            self.standard = standard
            self.policy = policy
            self.controls = controls.split() if controls else None
            self.output = None

    if standard_file and policy_file:
        return Args(standard_file, policy_file, controls_input)
    else:
        st.info("Waiting for both documents to be uploaded...")
        st.stop()


def main():
    args = parse_args()

    print()
    print(SEPARATOR)
    print("  ISO/IEC 27002:2022 Gap Analysis Tool  —  Starting")
    print(SEPARATOR)

    # ── Load documents ──
    print("\n[1/3] Loading documents...")
    try:
        standard_text = extract_text(args.standard)
        policy_text   = extract_text(args.policy)
    except (FileNotFoundError, ValueError, RuntimeError) as e:
        print(f"\n  ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    if len(standard_text.strip()) < 100:
        print("  WARNING: Standard document appears to be empty or unreadable.", file=sys.stderr)
    if len(policy_text.strip()) < 50:
        print("  WARNING: Policy document appears to be empty or unreadable.", file=sys.stderr)

    print(f"  Standard : {len(standard_text):,} characters extracted")
    print(f"  Policy   : {len(policy_text):,} characters extracted")

    # ── Select controls ──
    controls_to_run = ACCESS_CONTROL_CONTROLS
    if args.controls:
        requested = set(args.controls)
        controls_to_run = [c for c in ACCESS_CONTROL_CONTROLS if c.control_id in requested]
        if not controls_to_run:
            print(f"\n  ERROR: No matching controls found for: {args.controls}", file=sys.stderr)
            print(f"  Available IDs: {[c.control_id for c in ACCESS_CONTROL_CONTROLS]}", file=sys.stderr)
            sys.exit(1)
        print(f"\n  Analysing {len(controls_to_run)} selected control(s): {[c.control_id for c in controls_to_run]}")
    else:
        print(f"\n  Analysing all {len(controls_to_run)} access control controls.")

    # ── Run analysis ──
    print("\n[2/3] Running gap analysis...")
    findings: list[GapFinding] = []
    for ctrl in controls_to_run:
        print(f"  Checking {ctrl.control_id} — {ctrl.control_name}...")
        finding = analyse_control(policy_text, ctrl)
        findings.append(finding)
        icon = {"Full Match": "✅", "Partial Match": "⚠️", "Gap": "❌"}.get(finding.status, "?")
        matched_count = len(finding.matched_items)
        total_req     = len(ctrl.key_requirements)
        print(f"    {icon} {finding.status}  ({matched_count}/{total_req} requirements met)")

    # ── Output ──
    print("\n[3/3] Generating report...")
    print_report(findings, args.policy, args.standard)

    if args.output:
        out = args.output.strip()
        if out.endswith(".json"):
            save_json_report(findings, out, args.policy, args.standard)
        else:
            save_txt_report(findings, out, args.policy, args.standard)

    print("\n  Done.\n")


if __name__ == "__main__":
    main()

