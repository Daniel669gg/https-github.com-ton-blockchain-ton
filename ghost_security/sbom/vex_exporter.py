"""
Ghost Security — CycloneDX VEX Exporter v1.0

Generates Vulnerability Exploitability eXchange (VEX) documents in
CycloneDX 1.4 JSON format.  VEX lets product vendors assert whether
CVEs listed in an SBOM are actually exploitable in their product,
satisfying the EU Cyber Resilience Act (CRA) 2025 requirement for
machine-readable vulnerability disclosure.

VEX statuses:
    affected             — vulnerability is present and exploitable
    not_affected         — vulnerability is present but not exploitable
    fixed                — vulnerability was present but has been remediated
    under_investigation  — triage is in progress

Justification codes (used only with not_affected):
    component_not_present
    vulnerable_code_not_present
    vulnerable_code_cannot_be_controlled_by_adversary
    vulnerable_code_not_in_execute_path
    inline_mitigations_already_exist

Usage:
    from sbom.vex_exporter import VEXExporter
    exporter = VEXExporter("MyProduct", "2.3.1")
    vex      = exporter.from_findings(ghost_findings, sbom=cyclonedx_sbom)
    exporter.write(vex, "vex.json")
"""
from __future__ import annotations

import json
import re
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TOOL_NAME    = "Ghost Security Platform"
TOOL_VERSION = "10.0"
SPEC_VERSION = "1.4"
BOM_FORMAT   = "CycloneDX"

# Ghost severity → CycloneDX severity string (lower-cased)
_SEVERITY_MAP: Dict[str, str] = {
    "CRITICAL": "critical",
    "HIGH":     "high",
    "MEDIUM":   "medium",
    "LOW":      "low",
    "INFO":     "info",
    "NONE":     "none",
}

# VEX states
_STATE_AFFECTED            = "affected"
_STATE_NOT_AFFECTED        = "not_affected"
_STATE_FIXED               = "fixed"
_STATE_UNDER_INVESTIGATION = "under_investigation"

# Default justification for suppressed findings where no reason is given
_DEFAULT_JUSTIFICATION = "vulnerable_code_not_present"

# Reachability → VEX state mapping
_REACHABILITY_STATE: Dict[str, str] = {
    "REACHABLE":     _STATE_AFFECTED,
    "NOT_REACHABLE": _STATE_NOT_AFFECTED,
    "UNKNOWN":       _STATE_UNDER_INVESTIGATION,
}

# Justification keyword mapping — suppression reason strings → CycloneDX codes.
# More specific patterns must appear before broader ones so the first match wins.
_JUSTIFICATION_KEYWORDS: List[tuple] = [
    # "vulnerable code not present" / "code not present" / "no vuln code"
    (re.compile(r"vuln.*code.*not.?present|code.*not.?present|no.?vuln", re.I),
     "vulnerable_code_not_present"),
    # "not in execute path" / "dead code" / "not executed"
    (re.compile(r"not.?in.?execut|dead.?code|not.?executed|execute.?path", re.I),
     "vulnerable_code_not_in_execute_path"),
    # Adversary / attacker control
    (re.compile(r"adversary|attacker|user.?control", re.I),
     "vulnerable_code_cannot_be_controlled_by_adversary"),
    # Inline mitigations
    (re.compile(r"mitigat|waf|firewall|compensat", re.I),
     "inline_mitigations_already_exist"),
    # Generic "component not present" — broad, so last
    (re.compile(r"component.*not.?present|not.?present|absent", re.I),
     "component_not_present"),
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now_iso8601() -> str:
    """Return current UTC time in ISO 8601 format."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _serial_number() -> str:
    """Generate a CycloneDX-compliant serial number (urn:uuid:...)."""
    return f"urn:uuid:{uuid.uuid4()}"


def _extract_cve(finding: Dict) -> Optional[str]:
    """Extract a CVE identifier from a finding if one is present."""
    cve_fields = ("cve", "id", "vulnerability_id")
    for field in cve_fields:
        val = finding.get(field, "")
        if isinstance(val, str) and re.match(r"CVE-\d{4}-\d{4,}", val, re.I):
            return val.upper()
    return None


def _extract_cwe_int(finding: Dict) -> Optional[int]:
    """Return the integer CWE number from a finding's cwe field, or None."""
    raw = finding.get("cwe", "")
    if not raw:
        return None
    m = re.search(r"\d+", str(raw))
    return int(m.group()) if m else None


def _extract_purl(finding: Dict, sbom: Optional[Dict]) -> Optional[str]:
    """
    Attempt to find a purl (package URL) for the affected component.

    Looks up the component name from the finding in the SBOM's component list.
    Falls back to a synthetic purl constructed from the package name/version.
    """
    pkg_name    = finding.get("package") or finding.get("component", "")
    pkg_version = finding.get("installed_version") or finding.get("version", "")

    # Try to match in the provided SBOM
    if sbom and pkg_name:
        for component in sbom.get("components", []):
            comp_name = component.get("name", "")
            if comp_name.lower() == pkg_name.lower():
                purl = component.get("purl")
                if purl:
                    return purl

    # Construct a synthetic purl
    if pkg_name:
        ecosystem = finding.get("ecosystem", "")
        eco_map = {
            "pypi": "pypi", "npm": "npm", "go": "golang",
            "crates.io": "cargo", "cargo": "cargo",
            "rubygems": "gem", "maven": "maven",
        }
        purl_type = eco_map.get(ecosystem.lower(), "generic") if ecosystem else "generic"
        ver_part  = f"@{pkg_version}" if pkg_version else ""
        return f"pkg:{purl_type}/{pkg_name}{ver_part}"

    return None


def _map_justification(suppression_reason: str) -> str:
    """
    Map a free-text suppression reason to a CycloneDX justification code.
    Returns a default code if no keyword matches.
    """
    if not suppression_reason:
        return _DEFAULT_JUSTIFICATION
    for pattern, code in _JUSTIFICATION_KEYWORDS:
        if pattern.search(suppression_reason):
            return code
    return _DEFAULT_JUSTIFICATION


def _determine_state(finding: Dict) -> str:
    """
    Determine the VEX state for a finding based on Ghost metadata.

    Rules (in priority order):
        1. If reachability_status is set, map it.
        2. If suppressed==True or suppression_reason is present → not_affected.
        3. If fixed_in and installed_version suggest the fix is applied → fixed.
        4. CRITICAL/HIGH with no suppression → affected.
        5. Otherwise → under_investigation.
    """
    reachability = finding.get("reachability_status", "").upper()
    if reachability in _REACHABILITY_STATE:
        return _REACHABILITY_STATE[reachability]

    if finding.get("suppressed") or finding.get("suppression_reason"):
        return _STATE_NOT_AFFECTED

    if finding.get("status", "").lower() == "fixed":
        return _STATE_FIXED

    severity = finding.get("severity", "").upper()
    if severity in ("CRITICAL", "HIGH"):
        return _STATE_AFFECTED

    return _STATE_UNDER_INVESTIGATION


# ---------------------------------------------------------------------------
# Main exporter
# ---------------------------------------------------------------------------

class VEXExporter:
    """
    Converts Ghost Security findings to a CycloneDX 1.4 VEX document.

    Args:
        product_name:    Name of the product or service being assessed.
        product_version: Version string of the product (default: "unknown").
    """

    def __init__(self, product_name: str, product_version: str = "unknown") -> None:
        self.product_name    = product_name
        self.product_version = product_version

    # ── Public API ────────────────────────────────────────────────────────────

    def from_findings(
        self,
        findings: List[Dict],
        sbom: Optional[Dict] = None,
    ) -> Dict:
        """
        Convert a list of Ghost findings to a CycloneDX VEX document.

        Args:
            findings: List of Ghost finding dicts (from any scanner).
            sbom:     Optional CycloneDX SBOM dict; used to resolve purls.

        Returns:
            A complete CycloneDX 1.4 VEX document as a Python dict.
        """
        vulnerabilities: List[Dict] = []

        for finding in findings:
            vuln     = self._make_vulnerability(finding, sbom)
            analysis = self._make_analysis(finding)

            vuln["analysis"] = analysis
            vulnerabilities.append(vuln)

        return {
            "bomFormat":    BOM_FORMAT,
            "specVersion":  SPEC_VERSION,
            "serialNumber": _serial_number(),
            "version":      1,
            "metadata":     self._make_metadata(),
            "vulnerabilities": vulnerabilities,
        }

    def write(self, vex: Dict, output_path: str) -> str:
        """
        Serialise a VEX document to a JSON file.

        Args:
            vex:         The VEX dict returned by from_findings().
            output_path: Destination file path (created or overwritten).

        Returns:
            The resolved output path string.
        """
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(vex, indent=2, ensure_ascii=False), encoding="utf-8")
        return str(path.resolve())

    # ── CycloneDX object builders ─────────────────────────────────────────────

    def _make_metadata(self) -> Dict:
        """Build the CycloneDX metadata block."""
        return {
            "timestamp": _now_iso8601(),
            "component": {
                "type":    "application",
                "name":    self.product_name,
                "version": self.product_version,
            },
            "tools": [
                {
                    "name":    TOOL_NAME,
                    "version": TOOL_VERSION,
                }
            ],
        }

    def _make_vulnerability(
        self, finding: Dict, sbom: Optional[Dict] = None
    ) -> Dict:
        """
        Build a CycloneDX vulnerability object from a Ghost finding.

        Returns:
            {
                "id":          CVE id or Ghost finding id,
                "source":      {"name": ..., "url": ...},
                "ratings":     [{"severity": ..., "method": "CVSSv31"}],
                "cwes":        [int],
                "description": str,
                "advisories":  [{"url": ...}],
                "affects":     [{"ref": purl}],
            }
        """
        cve_id  = _extract_cve(finding)
        vuln_id = cve_id or finding.get("id", f"GHOST-{uuid.uuid4().hex[:8].upper()}")

        # Source: NVD for CVEs, otherwise Ghost Security
        if cve_id:
            source = {
                "name": "NVD",
                "url":  f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            }
        else:
            source = {
                "name": TOOL_NAME,
                "url":  "https://ghost.security",
            }

        # Ratings
        severity_raw = finding.get("severity", "MEDIUM")
        severity_cdx = _SEVERITY_MAP.get(severity_raw.upper(), "medium")
        ratings: List[Dict] = [
            {
                "severity": severity_cdx,
                "method":   "CVSSv31",
            }
        ]
        # Include CVSS score if present
        cvss_score = finding.get("cvss_score") or finding.get("cvss")
        if cvss_score is not None:
            try:
                ratings[0]["score"] = float(cvss_score)
            except (TypeError, ValueError):
                pass

        # CWEs
        cwes: List[int] = []
        cwe_int = _extract_cwe_int(finding)
        if cwe_int:
            cwes.append(cwe_int)

        # Description
        description = (
            finding.get("description")
            or finding.get("message")
            or f"{vuln_id} — detected by {TOOL_NAME}"
        )

        # Advisories
        advisories: List[Dict] = []
        if cve_id:
            advisories.append({"url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"})
        for url_field in ("advisory_url", "reference_url", "url"):
            url_val = finding.get(url_field)
            if url_val and isinstance(url_val, str):
                advisories.append({"url": url_val})
                break

        # Affects — component purls
        affects: List[Dict] = []
        purl = _extract_purl(finding, sbom)
        if purl:
            affects.append({"ref": purl})
        else:
            # Use the file path as a fallback ref
            file_ref = finding.get("file", "")
            if file_ref:
                affects.append({"ref": file_ref})

        vuln: Dict[str, Any] = {
            "id":          vuln_id,
            "source":      source,
            "ratings":     ratings,
            "description": description,
            "affects":     affects,
        }
        if cwes:
            vuln["cwes"] = cwes
        if advisories:
            vuln["advisories"] = advisories

        return vuln

    def _make_analysis(self, finding: Dict) -> Dict:
        """
        Build the CycloneDX analysis block for a finding.

        Returns:
            {
                "state":         VEX state string,
                "justification": justification code (only for not_affected),
                "detail":        free-text explanation,
                "responses":     list of response action strings,
            }
        """
        state              = _determine_state(finding)
        suppression_reason = finding.get("suppression_reason", "")
        reachability       = finding.get("reachability_status", "").upper()

        analysis: Dict[str, Any] = {"state": state}

        # Justification is only meaningful for not_affected
        if state == _STATE_NOT_AFFECTED:
            if reachability == "NOT_REACHABLE":
                analysis["justification"] = "vulnerable_code_not_in_execute_path"
            else:
                analysis["justification"] = _map_justification(suppression_reason)

        # Detail text — build from available context
        detail_parts: List[str] = []
        if suppression_reason:
            detail_parts.append(f"Suppression reason: {suppression_reason}")
        if reachability:
            detail_parts.append(f"Reachability analysis: {reachability}")
        remediation = finding.get("remediation") or finding.get("recommendation")
        if remediation:
            detail_parts.append(f"Remediation: {remediation}")
        if detail_parts:
            analysis["detail"] = " | ".join(detail_parts)

        # Responses
        responses: List[str] = []
        if state == _STATE_AFFECTED:
            fixed_in = finding.get("fixed_in") or finding.get("patched_version")
            if fixed_in:
                responses.append(f"update (upgrade to {fixed_in})")
            else:
                responses.append("workaround_available")
        elif state == _STATE_FIXED:
            responses.append("update")
        elif state == _STATE_NOT_AFFECTED:
            responses.append("will_not_fix")
        if responses:
            analysis["responses"] = responses

        return analysis
