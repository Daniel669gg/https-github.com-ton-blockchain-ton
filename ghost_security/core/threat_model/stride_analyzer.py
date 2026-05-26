"""
SentinelOps — STRIDE Threat Modeling Analyzer
Maps security findings to STRIDE categories and generates a structured threat model report.

STRIDE: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class STRIDECategory(str, Enum):
    SPOOFING             = "Spoofing"
    TAMPERING            = "Tampering"
    REPUDIATION          = "Repudiation"
    INFORMATION_DISC     = "Information Disclosure"
    DENIAL_OF_SERVICE    = "Denial of Service"
    ELEVATION_OF_PRIV    = "Elevation of Privilege"


# CWE → STRIDE mapping (primary threat category)
_CWE_STRIDE: Dict[str, STRIDECategory] = {
    # Spoofing
    "CWE-287": STRIDECategory.SPOOFING,   # Improper Authentication
    "CWE-290": STRIDECategory.SPOOFING,   # Authentication Bypass by Spoofing
    "CWE-293": STRIDECategory.SPOOFING,   # Using Referer Field for Authentication
    "CWE-295": STRIDECategory.SPOOFING,   # Improper Certificate Validation
    "CWE-297": STRIDECategory.SPOOFING,   # Improper Validation of Certificate with Host Mismatch
    "CWE-306": STRIDECategory.SPOOFING,   # Missing Authentication for Critical Function
    "CWE-384": STRIDECategory.SPOOFING,   # Session Fixation
    # Tampering
    "CWE-20":  STRIDECategory.TAMPERING,  # Improper Input Validation
    "CWE-77":  STRIDECategory.TAMPERING,  # Command Injection
    "CWE-78":  STRIDECategory.TAMPERING,  # OS Command Injection
    "CWE-89":  STRIDECategory.TAMPERING,  # SQL Injection
    "CWE-94":  STRIDECategory.TAMPERING,  # Code Injection
    "CWE-116": STRIDECategory.TAMPERING,  # Improper Encoding or Escaping
    "CWE-345": STRIDECategory.TAMPERING,  # Insufficient Verification of Data Authenticity
    "CWE-494": STRIDECategory.TAMPERING,  # Download Without Integrity Check
    "CWE-829": STRIDECategory.TAMPERING,  # Inclusion of Functionality from Untrusted Control Sphere
    # Repudiation
    "CWE-223": STRIDECategory.REPUDIATION, # Omission of Security-relevant Information
    "CWE-778": STRIDECategory.REPUDIATION, # Insufficient Logging
    "CWE-779": STRIDECategory.REPUDIATION, # Logging of Excessive Data
    # Information Disclosure
    "CWE-200": STRIDECategory.INFORMATION_DISC,  # Exposure of Sensitive Information
    "CWE-201": STRIDECategory.INFORMATION_DISC,  # Insertion of Sensitive Information Into Sent Data
    "CWE-209": STRIDECategory.INFORMATION_DISC,  # Generation of Error Message Containing Sensitive Information
    "CWE-312": STRIDECategory.INFORMATION_DISC,  # Cleartext Storage of Sensitive Information
    "CWE-319": STRIDECategory.INFORMATION_DISC,  # Cleartext Transmission of Sensitive Information
    "CWE-359": STRIDECategory.INFORMATION_DISC,  # Exposure of Private Personal Information
    "CWE-532": STRIDECategory.INFORMATION_DISC,  # Insertion of Sensitive Information into Log File
    "CWE-798": STRIDECategory.INFORMATION_DISC,  # Use of Hard-coded Credentials
    # Denial of Service
    "CWE-400": STRIDECategory.DENIAL_OF_SERVICE, # Uncontrolled Resource Consumption
    "CWE-404": STRIDECategory.DENIAL_OF_SERVICE, # Improper Resource Shutdown
    "CWE-770": STRIDECategory.DENIAL_OF_SERVICE, # Allocation of Resources Without Limits
    "CWE-834": STRIDECategory.DENIAL_OF_SERVICE, # Excessive Iteration
    # Elevation of Privilege
    "CWE-250": STRIDECategory.ELEVATION_OF_PRIV, # Execution with Unnecessary Privileges
    "CWE-264": STRIDECategory.ELEVATION_OF_PRIV, # Permissions / Privileges
    "CWE-269": STRIDECategory.ELEVATION_OF_PRIV, # Improper Privilege Management
    "CWE-284": STRIDECategory.ELEVATION_OF_PRIV, # Improper Access Control
    "CWE-285": STRIDECategory.ELEVATION_OF_PRIV, # Improper Authorization
    "CWE-732": STRIDECategory.ELEVATION_OF_PRIV, # Incorrect Permission Assignment for Critical Resource
    "CWE-862": STRIDECategory.ELEVATION_OF_PRIV, # Missing Authorization
    "CWE-863": STRIDECategory.ELEVATION_OF_PRIV, # Incorrect Authorization
}

# Keyword → STRIDE heuristic fallback
_KEYWORD_STRIDE: List[tuple[list[str], STRIDECategory]] = [
    (["auth", "spoof", "impersonat", "session", "csrf", "token_theft"], STRIDECategory.SPOOFING),
    (["inject", "tamper", "xss", "xxe", "ssti", "rce", "sqli", "command"], STRIDECategory.TAMPERING),
    (["log", "audit", "trail", "repudiat"], STRIDECategory.REPUDIATION),
    (["secret", "leak", "disclosure", "exposure", "cleartext", "hardcod", "key", "password", "credential"], STRIDECategory.INFORMATION_DISC),
    (["dos", "ddos", "resource", "exhaustion", "loop", "recursion", "oom", "gas"], STRIDECategory.DENIAL_OF_SERVICE),
    (["privilege", "escalat", "access_control", "authz", "permission", "role", "sudo", "admin"], STRIDECategory.ELEVATION_OF_PRIV),
]

# STRIDE threat descriptions for report generation
_STRIDE_DESCRIPTIONS: Dict[STRIDECategory, str] = {
    STRIDECategory.SPOOFING:          "Attacker can impersonate a legitimate entity to bypass trust boundaries.",
    STRIDECategory.TAMPERING:         "Attacker can modify data or code in transit or at rest to alter behavior.",
    STRIDECategory.REPUDIATION:       "Insufficient audit trail allows attackers to deny malicious actions.",
    STRIDECategory.INFORMATION_DISC:  "Sensitive data is exposed to unauthorized parties through leaks or misconfiguration.",
    STRIDECategory.DENIAL_OF_SERVICE: "Attacker can exhaust resources or crash the system, denying service to legitimate users.",
    STRIDECategory.ELEVATION_OF_PRIV: "Attacker gains higher privileges than intended, enabling unauthorized actions.",
}

_STRIDE_MITIGATIONS: Dict[STRIDECategory, List[str]] = {
    STRIDECategory.SPOOFING:         ["Implement strong authentication (MFA)", "Validate certificates and TLS", "Use signed tokens with expiration"],
    STRIDECategory.TAMPERING:        ["Validate and sanitize all inputs", "Use parameterized queries", "Enforce content-security policies"],
    STRIDECategory.REPUDIATION:      ["Implement structured audit logging", "Use append-only logs", "Include timestamps and user context in logs"],
    STRIDECategory.INFORMATION_DISC: ["Encrypt secrets at rest and in transit", "Remove debug output in production", "Use secret management vaults"],
    STRIDECategory.DENIAL_OF_SERVICE:["Implement rate limiting and quotas", "Use circuit breakers", "Set resource limits (memory, CPU, gas)"],
    STRIDECategory.ELEVATION_OF_PRIV:["Apply principle of least privilege", "Implement RBAC/ABAC", "Validate authorization on every request"],
}


@dataclass
class STRIDEResult:
    finding_id:  str
    rule_id:     str
    title:       str
    file:        str
    line:        int
    severity:    str
    cwe:         str
    category:    STRIDECategory
    description: str
    mitigations: List[str]
    confidence:  str = "medium"


@dataclass
class STRIDEReport:
    total_findings: int = 0
    by_category: Dict[str, int] = field(default_factory=dict)
    results: List[STRIDEResult] = field(default_factory=list)
    risk_summary: Dict[str, str] = field(default_factory=dict)


class STRIDEAnalyzer:
    """
    Classifies security findings according to the STRIDE threat model.
    Generates structured reports suitable for threat modeling sessions.
    """

    def classify_finding(self, finding: dict) -> STRIDEResult:
        """Map a single finding dict to a STRIDEResult."""
        cwe      = finding.get("cwe", "")
        rule_id  = finding.get("rule_id", "UNKNOWN")
        title    = finding.get("title", finding.get("message", "Unknown Finding"))
        file_    = finding.get("file", "")
        line     = finding.get("line", 0)
        severity = finding.get("severity", "medium")
        confidence = finding.get("confidence", "medium")

        category = self._resolve_category(cwe, rule_id, title)

        return STRIDEResult(
            finding_id  = finding.get("id", f"{rule_id}:{file_}:{line}"),
            rule_id     = rule_id,
            title       = title,
            file        = file_,
            line        = line,
            severity    = severity,
            cwe         = cwe,
            category    = category,
            description = _STRIDE_DESCRIPTIONS[category],
            mitigations = _STRIDE_MITIGATIONS[category],
            confidence  = confidence,
        )

    def _resolve_category(self, cwe: str, rule_id: str, title: str) -> STRIDECategory:
        """Resolve STRIDE category from CWE, then rule_id, then title keywords."""
        if cwe and cwe.upper() in _CWE_STRIDE:
            return _CWE_STRIDE[cwe.upper()]

        combined = (rule_id + " " + title).lower()
        for keywords, cat in _KEYWORD_STRIDE:
            if any(kw in combined for kw in keywords):
                return cat

        return STRIDECategory.TAMPERING  # safe default

    def map_cwe_to_stride(self, cwe: str) -> Optional[STRIDECategory]:
        return _CWE_STRIDE.get(cwe.upper())

    def analyze(self, findings: List[dict]) -> STRIDEReport:
        """Classify a list of findings and produce a STRIDEReport."""
        report = STRIDEReport(total_findings=len(findings))

        for cat in STRIDECategory:
            report.by_category[cat.value] = 0

        for f in findings:
            result = self.classify_finding(f)
            report.results.append(result)
            report.by_category[result.category.value] = report.by_category.get(result.category.value, 0) + 1

        # Build risk summary
        for cat, count in report.by_category.items():
            if count > 0:
                report.risk_summary[cat] = f"{count} finding(s) — {_STRIDE_DESCRIPTIONS.get(STRIDECategory(cat), '')}"

        return report

    def analyze_directory(self, path: str, findings: List[dict]) -> STRIDEReport:
        """Filter findings by path prefix and return a STRIDE report."""
        scoped = [f for f in findings if f.get("file", "").startswith(path)]
        return self.analyze(scoped)

    def generate_report(self, findings: List[dict], fmt: str = "text") -> str:
        """Generate human-readable or JSON STRIDE report."""
        report = self.analyze(findings)

        if fmt == "json":
            return json.dumps({
                "total_findings":  report.total_findings,
                "by_category":     report.by_category,
                "risk_summary":    report.risk_summary,
                "results": [
                    {
                        "finding_id": r.finding_id,
                        "rule_id":    r.rule_id,
                        "title":      r.title,
                        "file":       r.file,
                        "line":       r.line,
                        "severity":   r.severity,
                        "cwe":        r.cwe,
                        "category":   r.category.value,
                        "mitigations": r.mitigations,
                    }
                    for r in report.results
                ],
            }, indent=2)

        lines = [
            "╔══════════════════════════════════════════════════════════════╗",
            "║          STRIDE THREAT MODEL REPORT — SentinelOps           ║",
            "╚══════════════════════════════════════════════════════════════╝",
            f"\nTotal findings analyzed: {report.total_findings}",
            "\n── Findings by STRIDE Category ──",
        ]
        for cat, count in report.by_category.items():
            bar = "█" * min(count, 40)
            lines.append(f"  {cat:<30} {count:>4}  {bar}")

        if report.results:
            lines.append("\n── Detailed Findings ──")
            for r in report.results:
                lines.append(f"\n  [{r.category.value}] {r.rule_id} — {r.title}")
                lines.append(f"    File: {r.file}:{r.line}  Severity: {r.severity}  CWE: {r.cwe}")
                lines.append(f"    Threat: {r.description}")
                for m in r.mitigations:
                    lines.append(f"      ✦ {m}")

        lines.append("\n── Risk Summary ──")
        for cat, summary in report.risk_summary.items():
            lines.append(f"  {cat}: {summary}")

        return "\n".join(lines)
