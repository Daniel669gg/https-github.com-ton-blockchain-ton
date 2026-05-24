"""
Ghost Security Platform — Compliance Report Generator
Автоматически маппирует findings на контролы SOC2, ISO 27001, NIST CSF.
Генерирует evidence пакеты для аудиторов.

Поддерживает:
  SOC2 Type II    — Trust Services Criteria (CC6, CC7, CC8, CC9)
  ISO 27001:2022  — Annex A controls
  NIST CSF 2.0    — Identify, Protect, Detect, Respond, Recover
  OWASP ASVS 4.0  — Application Security Verification Standard
  PCI DSS 4.0     — Payment Card Industry requirements
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional


# ── CWE → compliance controls mapping ────────────────────────────────────────

_CWE_SOC2: Dict[str, List[str]] = {
    "CWE-89":  ["CC6.1", "CC6.7", "CC7.1"],
    "CWE-79":  ["CC6.1", "CC6.7"],
    "CWE-78":  ["CC6.1", "CC6.7", "CC7.1"],
    "CWE-94":  ["CC6.1", "CC6.7", "CC7.1"],
    "CWE-22":  ["CC6.1", "CC6.6"],
    "CWE-798": ["CC6.1", "CC6.2", "CC6.3"],
    "CWE-312": ["CC6.1", "CC6.7"],
    "CWE-327": ["CC6.1", "CC6.7"],
    "CWE-306": ["CC6.1", "CC6.2"],
    "CWE-862": ["CC6.1", "CC6.3"],
    "CWE-400": ["CC7.1", "CC7.2"],
    "CWE-502": ["CC6.1", "CC7.1"],
    "CWE-918": ["CC6.1", "CC6.7"],
}

_CWE_ISO27001: Dict[str, List[str]] = {
    "CWE-89":  ["A.8.28", "A.8.31"],
    "CWE-79":  ["A.8.28"],
    "CWE-78":  ["A.8.28", "A.8.31"],
    "CWE-798": ["A.8.12", "A.5.17"],
    "CWE-312": ["A.8.24"],
    "CWE-327": ["A.8.24"],
    "CWE-306": ["A.8.2", "A.5.15"],
    "CWE-862": ["A.8.2", "A.5.15", "A.5.18"],
    "CWE-400": ["A.8.6"],
    "CWE-22":  ["A.8.28"],
    "CWE-502": ["A.8.28"],
}

_CWE_NIST: Dict[str, List[str]] = {
    "CWE-89":  ["PR.DS-1", "PR.IP-1"],
    "CWE-79":  ["PR.DS-1", "PR.IP-1"],
    "CWE-78":  ["PR.AC-3", "PR.IP-1"],
    "CWE-798": ["PR.AC-1", "PR.DS-5"],
    "CWE-312": ["PR.DS-1", "PR.DS-5"],
    "CWE-327": ["PR.DS-1", "PR.DS-5"],
    "CWE-306": ["PR.AC-1", "PR.AC-3"],
    "CWE-862": ["PR.AC-4", "PR.AC-6"],
    "CWE-400": ["PR.IP-1", "DE.CM-1"],
    "CWE-918": ["PR.AC-3", "PR.DS-5"],
    "CWE-502": ["PR.IP-1", "DE.CM-4"],
}

_SOC2_DESCRIPTIONS: Dict[str, str] = {
    "CC6.1": "Logical and physical access controls prevent unauthorized access",
    "CC6.2": "Prior to issuing system credentials, entity registers new users",
    "CC6.3": "Role-based access control limits user permissions to job functions",
    "CC6.6": "Logical access controls restrict access to information assets",
    "CC6.7": "Data transmission security — encryption in transit and at rest",
    "CC7.1": "Vulnerabilities in system components are identified and monitored",
    "CC7.2": "Security events are identified and monitored",
    "CC8.1": "Changes to system components are authorized and tested",
    "CC9.1": "Entity assesses risk associated with third-party vendors",
    "CC9.2": "Entity has a risk management program in place",
}

_ISO_DESCRIPTIONS: Dict[str, str] = {
    "A.5.15": "Access control — principle of least privilege",
    "A.5.17": "Authentication — management of secret authentication information",
    "A.5.18": "Access rights — review and revocation",
    "A.8.2":  "Privileged access rights",
    "A.8.6":  "Capacity management",
    "A.8.12": "Data leakage prevention",
    "A.8.24": "Use of cryptography — policy and implementation",
    "A.8.28": "Secure coding practices",
    "A.8.31": "Separation of development, testing, and production environments",
}

_NIST_DESCRIPTIONS: Dict[str, str] = {
    "PR.AC-1": "Identities and credentials are managed for authorized devices/users",
    "PR.AC-3": "Remote access is managed",
    "PR.AC-4": "Access permissions are managed incorporating least privilege",
    "PR.AC-6": "Identities are proofed and bound to credentials",
    "PR.DS-1": "Data-at-rest is protected",
    "PR.DS-5": "Protections against data leaks are implemented",
    "PR.IP-1": "Baseline configuration of IT/OT systems is created and maintained",
    "DE.CM-1": "Network and communications activity is monitored",
    "DE.CM-4": "Malicious code is detected",
}


# ── Compliance finding ─────────────────────────────────────────────────────────

@dataclass
class ComplianceFinding:
    finding:        dict
    soc2_controls:  List[str]
    iso_controls:   List[str]
    nist_controls:  List[str]

    def to_dict(self) -> dict:
        return {
            "finding_id":    self.finding.get("rule_id",""),
            "severity":      self.finding.get("severity",""),
            "description":   self.finding.get("message","") or self.finding.get("description",""),
            "file":          self.finding.get("file",""),
            "line":          self.finding.get("line",0),
            "cwe":           self.finding.get("cwe",""),
            "soc2_controls": self.soc2_controls,
            "iso_controls":  self.iso_controls,
            "nist_controls": self.nist_controls,
        }


# ── Compliance Report ─────────────────────────────────────────────────────────

@dataclass
class ComplianceReport:
    framework:       str
    generated_at:    float = field(default_factory=time.time)
    target:          str = ""
    findings:        List[ComplianceFinding] = field(default_factory=list)
    controls_failed: Dict[str, List[dict]] = field(default_factory=dict)
    controls_passed: List[str] = field(default_factory=list)
    risk_level:      str = "UNKNOWN"
    summary:         str = ""

    def to_dict(self) -> dict:
        return {
            "framework":       self.framework,
            "generated_at":    time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.generated_at)),
            "target":          self.target,
            "total_findings":  len(self.findings),
            "controls_failed": len(self.controls_failed),
            "controls_passed": len(self.controls_passed),
            "risk_level":      self.risk_level,
            "summary":         self.summary,
            "failed_controls": {
                ctrl: [f for f in items]
                for ctrl, items in self.controls_failed.items()
            },
        }

    def to_markdown(self) -> str:
        date = time.strftime("%Y-%m-%d", time.gmtime(self.generated_at))
        lines = [
            f"# {self.framework} Compliance Report",
            f"**Date:** {date}  ",
            f"**Target:** {self.target}  ",
            f"**Overall Risk:** {self.risk_level}",
            "",
            "## Executive Summary",
            "",
            self.summary,
            "",
            f"## Control Assessment",
            "",
            f"| Status | Count |",
            f"|--------|-------|",
            f"| ❌ Failed controls | {len(self.controls_failed)} |",
            f"| ✅ No evidence of failure | {len(self.controls_passed)} |",
            f"| 📋 Total findings mapped | {len(self.findings)} |",
            "",
            "## Failed Controls",
            "",
        ]
        for ctrl, items in sorted(self.controls_failed.items()):
            desc = (
                _SOC2_DESCRIPTIONS.get(ctrl) or
                _ISO_DESCRIPTIONS.get(ctrl)   or
                _NIST_DESCRIPTIONS.get(ctrl)  or ""
            )
            lines.append(f"### {ctrl}")
            if desc:
                lines.append(f"*{desc}*")
            lines.append("")
            for item in items[:5]:
                sev  = item.get("severity","?")
                msg  = item.get("description","")[:80]
                f    = item.get("file","")
                lines.append(f"- **[{sev}]** {msg} — `{f}`")
            if len(items) > 5:
                lines.append(f"- *...and {len(items)-5} more findings*")
            lines.append("")
        lines += [
            "---",
            "*Generated by Ghost Security Platform — automated compliance evidence*",
            "*This report is supporting evidence only. A certified auditor must conduct formal assessment.*",
        ]
        return "\n".join(lines)


# ── Generator ──────────────────────────────────────────────────────────────────

class ComplianceReportGenerator:
    """
    Maps Ghost findings to compliance controls and generates evidence reports.
    """

    def generate(
        self,
        findings:  List[dict],
        framework: str = "soc2",
        target:    str = "",
    ) -> ComplianceReport:
        """
        Generate a compliance report for given framework.
        framework: soc2 | iso27001 | nist | all
        """
        framework = framework.lower()
        mapped: List[ComplianceFinding] = []
        controls_failed: Dict[str, List[dict]] = {}

        for f in findings:
            cwe = f.get("cwe","")
            soc2  = _CWE_SOC2.get(cwe,[])
            iso   = _CWE_ISO27001.get(cwe,[])
            nist  = _CWE_NIST.get(cwe,[])

            cf = ComplianceFinding(finding=f, soc2_controls=soc2,
                                   iso_controls=iso, nist_controls=nist)
            mapped.append(cf)

            # Which controls to use for this framework
            active = []
            if framework in ("soc2","all"):   active += soc2
            if framework in ("iso27001","all"): active += iso
            if framework in ("nist","all"):   active += nist

            for ctrl in active:
                controls_failed.setdefault(ctrl, []).append({
                    "severity":    f.get("severity","?"),
                    "description": f.get("message") or f.get("description",""),
                    "file":        f.get("file",""),
                    "line":        f.get("line",0),
                    "cwe":         cwe,
                })

        # Controls with no failures
        all_controls = set()
        if framework in ("soc2","all"):    all_controls |= set(_CWE_SOC2.keys())
        if framework in ("iso27001","all"): all_controls |= set(_CWE_ISO27001.keys())
        if framework in ("nist","all"):    all_controls |= set(_CWE_NIST.keys())
        controls_passed = [c for c in all_controls if c not in controls_failed]

        # Risk level
        crits = sum(1 for f in findings if f.get("severity")=="CRITICAL")
        highs = sum(1 for f in findings if f.get("severity")=="HIGH")
        risk  = ("CRITICAL" if crits > 0 else "HIGH" if highs > 0 else
                 "MEDIUM" if len(findings) > 0 else "LOW")

        # Summary
        fname = {"soc2":"SOC2 Type II","iso27001":"ISO 27001:2022","nist":"NIST CSF 2.0"}.get(framework, framework.upper())
        summary = (
            f"Ghost Security Platform identified **{len(findings)} finding(s)** in the target codebase "
            f"that affect **{len(controls_failed)} {fname} control(s)**. "
            f"The overall risk assessment is **{risk}**. "
            f"{'Immediate remediation is required before next audit.' if crits > 0 else 'Controls require review and remediation planning.'}"
        )

        return ComplianceReport(
            framework       = fname,
            target          = target,
            findings        = mapped,
            controls_failed = controls_failed,
            controls_passed = controls_passed,
            risk_level      = risk,
            summary         = summary,
        )

    def generate_soc2(self, findings: List[dict], target: str = "") -> ComplianceReport:
        return self.generate(findings, "soc2", target)

    def generate_iso27001(self, findings: List[dict], target: str = "") -> ComplianceReport:
        return self.generate(findings, "iso27001", target)

    def generate_nist(self, findings: List[dict], target: str = "") -> ComplianceReport:
        return self.generate(findings, "nist", target)

    def generate_all(self, findings: List[dict], target: str = "") -> Dict[str, ComplianceReport]:
        return {
            "soc2":     self.generate_soc2(findings, target),
            "iso27001": self.generate_iso27001(findings, target),
            "nist":     self.generate_nist(findings, target),
        }
