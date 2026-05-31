"""
TythanAI — Compliance Framework Mapper

Maps Ghost findings (CWE / OWASP) to regulatory frameworks:
  • PCI-DSS 4.0
  • SOC 2 (Trust Service Criteria)
  • HIPAA Security Rule
  • NIST SP 800-53 Rev 5
  • ISO/IEC 27001:2022
  • OWASP ASVS 4.0

Usage:
    from core.compliance.compliance_mapper import ComplianceMapper
    mapper   = ComplianceMapper()
    findings = mapper.enrich(findings)    # adds compliance_tags to each finding
    report   = mapper.compliance_report(findings, frameworks=["PCI-DSS", "SOC2"])
"""
from __future__ import annotations

from typing import Dict, List, Optional, Set


# ── CWE → Framework control mapping ──────────────────────────────────────────
# Format: CWE-ID → { framework: [controls] }

_CWE_MAP: Dict[str, Dict[str, List[str]]] = {
    # Injection (SQL, OS, LDAP, XPath)
    "CWE-89": {
        "PCI-DSS":  ["6.2.4", "6.3.2"],
        "SOC2":     ["CC6.1", "CC7.1"],
        "HIPAA":    ["§164.312(a)(1)"],
        "NIST":     ["SI-10", "SA-15"],
        "ISO27001": ["A.8.25", "A.8.28"],
        "ASVS":     ["5.3.4", "5.3.5"],
    },
    "CWE-78": {
        "PCI-DSS":  ["6.2.4"],
        "SOC2":     ["CC6.1", "CC7.1"],
        "HIPAA":    ["§164.312(a)(1)"],
        "NIST":     ["SI-10", "SA-15"],
        "ISO27001": ["A.8.28"],
        "ASVS":     ["5.2.2", "5.3.8"],
    },
    "CWE-79": {
        "PCI-DSS":  ["6.2.4", "6.3.2"],
        "SOC2":     ["CC6.1"],
        "NIST":     ["SI-10"],
        "ISO27001": ["A.8.28"],
        "ASVS":     ["5.3.3"],
    },
    "CWE-94": {
        "PCI-DSS":  ["6.2.4"],
        "SOC2":     ["CC6.1", "CC7.1"],
        "NIST":     ["SI-10", "SA-15"],
        "ISO27001": ["A.8.28"],
        "ASVS":     ["5.2.4"],
    },
    # Broken Authentication / Credentials
    "CWE-287": {
        "PCI-DSS":  ["8.2.1", "8.3.1", "8.4.2"],
        "SOC2":     ["CC6.1", "CC6.2"],
        "HIPAA":    ["§164.312(d)"],
        "NIST":     ["IA-2", "IA-5", "IA-8"],
        "ISO27001": ["A.5.16", "A.5.17"],
        "ASVS":     ["2.1.1", "2.2.1"],
    },
    "CWE-798": {
        "PCI-DSS":  ["8.3.1", "8.6.2"],
        "SOC2":     ["CC6.1", "CC6.7"],
        "HIPAA":    ["§164.312(d)"],
        "NIST":     ["IA-5", "SC-12"],
        "ISO27001": ["A.5.17", "A.8.13"],
        "ASVS":     ["2.10.4", "6.4.1"],
    },
    "CWE-259": {
        "PCI-DSS":  ["8.3.1", "8.6.2"],
        "SOC2":     ["CC6.1"],
        "HIPAA":    ["§164.312(d)"],
        "NIST":     ["IA-5"],
        "ISO27001": ["A.5.17"],
        "ASVS":     ["2.10.4"],
    },
    # Cryptographic failures
    "CWE-327": {
        "PCI-DSS":  ["4.2.1", "6.2.4"],
        "SOC2":     ["CC6.7"],
        "HIPAA":    ["§164.312(a)(2)(iv)", "§164.312(e)(2)(ii)"],
        "NIST":     ["SC-8", "SC-12", "SC-28"],
        "ISO27001": ["A.8.24"],
        "ASVS":     ["6.2.1", "6.2.2"],
    },
    "CWE-330": {
        "PCI-DSS":  ["6.2.4"],
        "SOC2":     ["CC6.7"],
        "HIPAA":    ["§164.312(a)(2)(iv)"],
        "NIST":     ["SC-12", "IA-5"],
        "ISO27001": ["A.8.24"],
        "ASVS":     ["6.3.1", "6.3.2"],
    },
    "CWE-326": {
        "PCI-DSS":  ["4.2.1"],
        "SOC2":     ["CC6.7"],
        "HIPAA":    ["§164.312(e)(2)(ii)"],
        "NIST":     ["SC-8"],
        "ISO27001": ["A.8.24"],
        "ASVS":     ["6.2.3"],
    },
    # Sensitive data exposure
    "CWE-312": {
        "PCI-DSS":  ["3.3.1", "3.4.1"],
        "SOC2":     ["CC6.7"],
        "HIPAA":    ["§164.312(a)(2)(iv)"],
        "NIST":     ["SC-28", "MP-4"],
        "ISO27001": ["A.5.33", "A.8.10"],
        "ASVS":     ["8.3.4"],
    },
    "CWE-313": {
        "PCI-DSS":  ["3.3.1"],
        "SOC2":     ["CC6.7"],
        "HIPAA":    ["§164.312(a)(2)(iv)"],
        "NIST":     ["SC-28"],
        "ISO27001": ["A.8.10"],
        "ASVS":     ["8.2.1"],
    },
    # Access control
    "CWE-284": {
        "PCI-DSS":  ["7.2.1", "7.3.1"],
        "SOC2":     ["CC6.1", "CC6.3"],
        "HIPAA":    ["§164.312(a)(1)"],
        "NIST":     ["AC-3", "AC-6"],
        "ISO27001": ["A.5.15", "A.8.2"],
        "ASVS":     ["4.1.1", "4.1.2"],
    },
    "CWE-285": {
        "PCI-DSS":  ["7.2.1"],
        "SOC2":     ["CC6.1", "CC6.3"],
        "HIPAA":    ["§164.312(a)(1)"],
        "NIST":     ["AC-3"],
        "ISO27001": ["A.5.15"],
        "ASVS":     ["4.2.1"],
    },
    "CWE-22": {
        "PCI-DSS":  ["6.2.4"],
        "SOC2":     ["CC6.1"],
        "NIST":     ["SI-10", "AC-3"],
        "ISO27001": ["A.8.28"],
        "ASVS":     ["12.3.1"],
    },
    # Security misconfiguration
    "CWE-16": {
        "PCI-DSS":  ["2.2.1", "6.2.4"],
        "SOC2":     ["CC6.1", "CC7.1"],
        "NIST":     ["CM-2", "CM-6"],
        "ISO27001": ["A.8.9"],
        "ASVS":     ["14.1.1"],
    },
    "CWE-732": {
        "PCI-DSS":  ["7.2.1"],
        "SOC2":     ["CC6.1"],
        "NIST":     ["AC-3", "AC-6"],
        "ISO27001": ["A.8.2"],
        "ASVS":     ["1.4.2"],
    },
    # Supply chain / dependencies
    "CWE-1035": {
        "PCI-DSS":  ["6.3.2"],
        "SOC2":     ["CC9.1"],
        "HIPAA":    ["§164.308(a)(1)"],
        "NIST":     ["SA-12", "RA-5"],
        "ISO27001": ["A.5.22", "A.8.8"],
        "ASVS":     ["14.2.1"],
    },
    "CWE-1104": {
        "PCI-DSS":  ["6.3.2"],
        "SOC2":     ["CC9.1"],
        "NIST":     ["SA-12"],
        "ISO27001": ["A.5.22"],
        "ASVS":     ["14.2.2"],
    },
    # Memory safety
    "CWE-120": {
        "PCI-DSS":  ["6.2.4"],
        "SOC2":     ["CC7.1"],
        "NIST":     ["SA-11", "SI-16"],
        "ISO27001": ["A.8.28"],
        "ASVS":     ["1.14.1"],
    },
    "CWE-190": {
        "PCI-DSS":  ["6.2.4"],
        "NIST":     ["SA-11"],
        "ISO27001": ["A.8.28"],
        "ASVS":     ["1.14.1"],
    },
    "CWE-416": {
        "PCI-DSS":  ["6.2.4"],
        "NIST":     ["SA-11"],
        "ISO27001": ["A.8.28"],
        "ASVS":     ["1.14.1"],
    },
    # Logging / monitoring
    "CWE-778": {
        "PCI-DSS":  ["10.2.1", "10.3.1"],
        "SOC2":     ["CC7.2", "CC7.3"],
        "HIPAA":    ["§164.312(b)"],
        "NIST":     ["AU-2", "AU-12"],
        "ISO27001": ["A.8.15", "A.8.16"],
        "ASVS":     ["7.1.1", "7.2.1"],
    },
    "CWE-117": {
        "PCI-DSS":  ["10.3.1"],
        "SOC2":     ["CC7.2"],
        "NIST":     ["AU-3", "AU-9"],
        "ISO27001": ["A.8.15"],
        "ASVS":     ["7.3.1"],
    },
    # DoS / resource exhaustion
    "CWE-400": {
        "PCI-DSS":  ["6.2.4"],
        "SOC2":     ["A1.1", "A1.2"],
        "HIPAA":    ["§164.312(a)(2)(ii)"],
        "NIST":     ["SC-5"],
        "ISO27001": ["A.8.6"],
        "ASVS":     ["13.1.1"],
    },
    # SSRF
    "CWE-918": {
        "PCI-DSS":  ["6.2.4"],
        "SOC2":     ["CC6.1"],
        "NIST":     ["SI-10", "SC-7"],
        "ISO27001": ["A.8.28"],
        "ASVS":     ["10.3.2"],
    },
    # Container / IaC
    "CWE-250": {
        "PCI-DSS":  ["7.2.1", "7.3.1"],
        "SOC2":     ["CC6.3"],
        "NIST":     ["AC-6", "CM-6"],
        "ISO27001": ["A.5.15", "A.8.9"],
        "ASVS":     ["14.1.3"],
    },
    "CWE-311": {
        "PCI-DSS":  ["3.4.1", "3.5.1"],
        "SOC2":     ["CC6.7"],
        "HIPAA":    ["§164.312(a)(2)(iv)"],
        "NIST":     ["SC-28"],
        "ISO27001": ["A.8.24"],
        "ASVS":     ["8.3.3"],
    },
}

# ── Framework display names and URLs ──────────────────────────────────────────

_FRAMEWORKS = {
    "PCI-DSS":  {"name": "PCI-DSS 4.0",          "url": "https://www.pcisecuritystandards.org/"},
    "SOC2":     {"name": "SOC 2 (AICPA)",          "url": "https://www.aicpa.org/soc2"},
    "HIPAA":    {"name": "HIPAA Security Rule",    "url": "https://www.hhs.gov/hipaa/"},
    "NIST":     {"name": "NIST SP 800-53 Rev 5",  "url": "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final"},
    "ISO27001": {"name": "ISO/IEC 27001:2022",     "url": "https://www.iso.org/standard/82875.html"},
    "ASVS":     {"name": "OWASP ASVS 4.0",        "url": "https://owasp.org/www-project-application-security-verification-standard/"},
}


class ComplianceMapper:
    """
    Enriches findings with compliance framework control references.
    Generates compliance gap reports.
    """

    def __init__(self, frameworks: Optional[List[str]] = None) -> None:
        self.frameworks = frameworks or list(_FRAMEWORKS.keys())

    # ── Public API ─────────────────────────────────────────────────────────────

    def enrich(self, findings: List[Dict]) -> List[Dict]:
        """Add compliance_tags to each finding."""
        for f in findings:
            cwe  = f.get("cwe", "")
            tags = self._get_tags(cwe)
            if tags:
                f["compliance_tags"] = tags
                f["compliance_frameworks"] = list(tags.keys())
        return findings

    def compliance_report(
        self,
        findings:   List[Dict],
        frameworks: Optional[List[str]] = None,
    ) -> Dict:
        """
        Generate a compliance gap report showing which controls are violated.
        """
        active_fw = frameworks or self.frameworks
        violations: Dict[str, Dict[str, List[Dict]]] = {fw: {} for fw in active_fw}

        for f in findings:
            tags = f.get("compliance_tags") or self._get_tags(f.get("cwe", ""))
            for fw in active_fw:
                controls = tags.get(fw, [])
                for ctrl in controls:
                    violations[fw].setdefault(ctrl, [])
                    violations[fw][ctrl].append({
                        "id":       f.get("id", ""),
                        "severity": f.get("severity", ""),
                        "file":     f.get("file", ""),
                        "line":     f.get("line", 0),
                        "message":  (f.get("message") or f.get("description") or "")[:100],
                    })

        summary: Dict[str, Dict] = {}
        for fw, ctrls in violations.items():
            fw_info = _FRAMEWORKS.get(fw, {})
            summary[fw] = {
                "framework":        fw_info.get("name", fw),
                "url":              fw_info.get("url", ""),
                "violations":       len(ctrls),
                "affected_controls": list(ctrls.keys()),
                "controls":         ctrls,
                "status":           "FAIL" if ctrls else "PASS",
            }

        total_violations = sum(s["violations"] for s in summary.values())
        return {
            "total_violations": total_violations,
            "frameworks":       summary,
            "overall_status":   "FAIL" if total_violations > 0 else "PASS",
        }

    def markdown_report(
        self,
        findings:   List[Dict],
        frameworks: Optional[List[str]] = None,
    ) -> str:
        """Generate a Markdown compliance report."""
        report = self.compliance_report(findings, frameworks)
        lines  = ["# TythanAI — Compliance Report\n"]

        status_icon = "❌ FAIL" if report["overall_status"] == "FAIL" else "✅ PASS"
        lines.append(f"**Overall Status:** {status_icon}  ")
        lines.append(f"**Total Control Violations:** {report['total_violations']}\n\n---\n")

        for fw, data in report["frameworks"].items():
            icon = "❌" if data["status"] == "FAIL" else "✅"
            lines.append(f"## {icon} {data['framework']}\n")
            if not data["controls"]:
                lines.append("No violations found.\n\n")
                continue
            lines.append(f"**Violated Controls:** {', '.join(data['affected_controls'])}\n\n")
            for ctrl, flist in data["controls"].items():
                lines.append(f"### Control {ctrl}\n")
                for f in flist[:5]:
                    lines.append(
                        f"- `[{f['severity']}]` {f['message']} "
                        f"(`{f['file']}:{f['line']}`)\n"
                    )
                if len(flist) > 5:
                    lines.append(f"- _...and {len(flist)-5} more_\n")
                lines.append("\n")

        return "".join(lines)

    # ── Internal ───────────────────────────────────────────────────────────────

    def _get_tags(self, cwe: str) -> Dict[str, List[str]]:
        if not cwe:
            return {}
        mapping = _CWE_MAP.get(cwe, {})
        return {fw: ctrls for fw, ctrls in mapping.items() if fw in self.frameworks}
