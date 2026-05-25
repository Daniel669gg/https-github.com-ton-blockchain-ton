"""
Ghost Security — SARIF 2.1.0 Exporter
=======================================
Converts Ghost Security findings (list of dicts) to valid SARIF JSON consumable
by GitHub Code Scanning, VS Code, Azure DevOps, and any OASIS SARIF 2.1.0 consumer.

Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/
Schema: https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json

Usage::

    from reports.sarif_exporter import SARIFExporter, ghost_findings_to_sarif

    exporter = SARIFExporter()
    sarif_dict = exporter.export(findings)
    output_path = exporter.write(sarif_dict, "/tmp/results.sarif")

    # Convenience one-liner:
    json_str = ghost_findings_to_sarif(findings)

    # Load from a JSON findings file and write SARIF in one call:
    output_path = SARIFExporter.from_file("findings.json", "results.sarif")
"""
from __future__ import annotations

import json
import os
from collections import defaultdict
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)
_SARIF_VERSION = "2.1.0"

_TOOL_NAME = "Ghost Security"
_TOOL_VERSION = "10.0"
_TOOL_URI = "https://ghost.security"

# SARIF level values per severity
_SEVERITY_TO_LEVEL: Dict[str, str] = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "none",
}

# SARIF rank (0–100) per severity — used by some tools for prioritisation
_SEVERITY_TO_RANK: Dict[str, float] = {
    "CRITICAL": 100.0,
    "HIGH": 75.0,
    "MEDIUM": 50.0,
    "LOW": 25.0,
    "INFO": 5.0,
}


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _sarif_level(severity: str) -> str:
    """Map Ghost severity string to a SARIF level token."""
    return _SEVERITY_TO_LEVEL.get(severity.upper(), "none")


def _sarif_rank(severity: str) -> float:
    """Map Ghost severity string to a SARIF rank float."""
    return _SEVERITY_TO_RANK.get(severity.upper(), 5.0)


def _normalise_uri(file_path: str) -> str:
    """Convert a filesystem path to a forward-slash URI fragment."""
    return file_path.replace("\\", "/")


def _safe_line(value: Any, default: int = 1) -> int:
    """Return a positive integer line number, falling back to *default*."""
    try:
        line = int(value)
        return max(line, 1)
    except (TypeError, ValueError):
        return default


def _safe_col(value: Any, default: int = 1) -> int:
    """Return a positive integer column number, falling back to *default*."""
    try:
        col = int(value)
        return max(col, 1)
    except (TypeError, ValueError):
        return default


def _truncate(text: str, limit: int) -> str:
    """Truncate *text* to at most *limit* characters, appending '…' if cut."""
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "…"


# ---------------------------------------------------------------------------
# SARIFExporter
# ---------------------------------------------------------------------------

class SARIFExporter:
    """Convert Ghost Security findings to SARIF 2.1.0 format.

    Parameters
    ----------
    tool_name:
        Override the ``tool.driver.name`` field (default: "Ghost Security").
    tool_version:
        Override the ``tool.driver.version`` field (default: "10.0").
    tool_uri:
        Override the ``tool.driver.informationUri`` field.
    help_base_uri:
        Base URL prepended to rule IDs to form ``helpUri`` links.  Set to
        ``None`` to omit ``helpUri`` from rules.
    """

    def __init__(
        self,
        tool_name: str = _TOOL_NAME,
        tool_version: str = _TOOL_VERSION,
        tool_uri: str = _TOOL_URI,
        help_base_uri: Optional[str] = "https://ghost.security/rules/",
    ) -> None:
        self.tool_name = tool_name
        self.tool_version = tool_version
        self.tool_uri = tool_uri
        self.help_base_uri = help_base_uri

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def export(
        self,
        findings,
        tool_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Convert Ghost findings to a SARIF 2.1.0 document.

        Accepts either:
        - List[Dict] — direct list of findings
        - Dict with a "findings" key — Ghost report envelope (backward compat)
        """
        # Backward compat: accept a report dict with findings key
        if isinstance(findings, dict):
            findings = findings.get("findings", [])

        effective_tool_name = tool_name or self.tool_name

        # Group findings by their scanner/source so each scanner becomes a
        # separate SARIF run.
        by_source: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for finding in findings:
            source = finding.get("scanner") or finding.get("source") or "ghost"
            by_source[source].append(finding)

        runs: List[Dict[str, Any]] = []
        for source, source_findings in by_source.items():
            runs.append(self._build_run(source_findings, effective_tool_name))

        # If there are no findings at all, emit one empty run so the document
        # is still valid SARIF.
        if not runs:
            runs.append(self._build_run([], effective_tool_name))

        return {
            "version": _SARIF_VERSION,
            "$schema": _SARIF_SCHEMA,
            "runs": runs,
        }

    def write(self, sarif: Dict[str, Any], output_path: str) -> str:
        """Serialise a SARIF dict to *output_path* as pretty-printed JSON.

        Parameters
        ----------
        sarif:
            The SARIF document dict returned by :meth:`export`.
        output_path:
            Destination file path.  Parent directories are created if they do
            not already exist.

        Returns
        -------
        str
            The resolved, absolute path of the written file.
        """
        output_path = os.path.abspath(output_path)
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(sarif, fh, indent=2, ensure_ascii=False)
        return output_path

    def export_to_file(self, report_or_findings, path: str) -> str:
        """Backward-compat alias: export then write to path."""
        sarif = self.export(report_or_findings)
        return self.write(sarif, path)

    @classmethod
    def from_file(
        cls,
        findings_path: str,
        output_path: str,
        **kwargs: Any,
    ) -> str:
        """Load findings from a JSON file and write a SARIF file.

        The JSON file may contain either a bare list of findings or a dict
        with a ``"findings"`` key (the Ghost report envelope format).

        Parameters
        ----------
        findings_path:
            Path to a Ghost findings JSON file.
        output_path:
            Destination for the produced SARIF file.
        **kwargs:
            Forwarded to :class:`SARIFExporter.__init__`.

        Returns
        -------
        str
            The absolute path of the written SARIF file.
        """
        with open(findings_path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)

        if isinstance(raw, list):
            findings = raw
        elif isinstance(raw, dict):
            findings = raw.get("findings", [])
        else:
            raise ValueError(
                f"Unexpected top-level type in {findings_path!r}: {type(raw).__name__}"
            )

        exporter = cls(**kwargs)
        sarif = exporter.export(findings)
        return exporter.write(sarif, output_path)

    # ------------------------------------------------------------------
    # Internal — run / rule / result builders
    # ------------------------------------------------------------------

    def _build_run(
        self,
        findings: List[Dict[str, Any]],
        tool_name: str,
    ) -> Dict[str, Any]:
        """Produce a single SARIF ``run`` object."""
        rules = self._build_rules(findings)
        results = [self._finding_to_result(f) for f in findings]
        artifacts = self._build_artifacts(findings)

        driver: Dict[str, Any] = {
            "name": tool_name,
            "version": self.tool_version,
            "informationUri": self.tool_uri,
            "rules": rules,
        }

        run: Dict[str, Any] = {
            "tool": {"driver": driver},
            "results": results,
            "artifacts": artifacts,
        }
        return run

    def _build_rules(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Deduplicate findings into SARIF rule descriptors."""
        seen: set[str] = set()
        rules: List[Dict[str, Any]] = []

        for f in findings:
            rule_id = f.get("id") or f.get("type") or "GHOST-UNKNOWN"
            if rule_id in seen:
                continue
            seen.add(rule_id)

            severity = f.get("severity", "INFO")
            cwe = f.get("cwe", "")
            description = f.get("description", rule_id)
            recommendation = f.get("recommendation", "")
            scanner = f.get("scanner") or f.get("source") or "ghost"

            tags: List[str] = ["security", scanner]
            if cwe:
                tags.append(cwe)
            # Add OWASP/category tag if available
            category = f.get("category", "")
            if category:
                tags.append(category)

            rule: Dict[str, Any] = {
                "id": rule_id,
                "name": _to_pascal(rule_id),
                "shortDescription": {"text": _truncate(description, 150)},
                "fullDescription": {"text": description},
                "defaultConfiguration": {
                    "level": _sarif_level(severity),
                },
                "properties": {
                    "tags": tags,
                    "security-severity": _severity_to_cvss_string(severity),
                },
            }

            # helpUri — link to documentation
            if self.help_base_uri:
                rule["helpUri"] = self.help_base_uri + rule_id
            elif f.get("reference"):
                rule["helpUri"] = f["reference"]

            # help text (recommendation)
            if recommendation:
                rule["help"] = {
                    "text": recommendation,
                    "markdown": recommendation,
                }

            # CWE relationship
            if cwe:
                cwe_id = cwe.upper().replace("CWE-", "")
                rule["relationships"] = [
                    {
                        "target": {
                            "id": cwe,
                            "toolComponent": {
                                "name": "CWE",
                                "guid": "1489b0c4-7d58-4fe0-9886-1ef19dfe135e",
                            },
                        },
                        "kinds": ["superset"],
                    }
                ]

            rules.append(rule)
        return rules

    def _finding_to_result(self, f: Dict[str, Any]) -> Dict[str, Any]:
        """Convert a single Ghost finding dict to a SARIF result object."""
        rule_id = f.get("id") or f.get("type") or "GHOST-UNKNOWN"
        severity = f.get("severity", "INFO")
        file_path = _normalise_uri(f.get("file", ""))
        line = _safe_line(f.get("line", 1))
        col = _safe_col(f.get("column", f.get("col", 1)))
        message = f.get("message") or f.get("description") or rule_id

        result: Dict[str, Any] = {
            "ruleId": rule_id,
            "level": _sarif_level(severity),
            "message": {"text": message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": file_path,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": line,
                            "startColumn": col,
                        },
                    }
                }
            ],
        }

        # Optional snippet / evidence embedded in the region
        evidence = f.get("evidence", "")
        if evidence:
            result["locations"][0]["physicalLocation"]["region"]["snippet"] = {
                "text": _truncate(str(evidence), 200)
            }

        # Properties bag — carry through Ghost-specific fields
        props: Dict[str, Any] = {
            "confidence": f.get("confidence", 75),
        }
        if f.get("cwe"):
            props["cwe"] = f["cwe"]
        if f.get("scanner"):
            props["scanner"] = f["scanner"]
        if f.get("source"):
            props["source"] = f["source"]
        if f.get("epss_score") is not None:
            props["epss_score"] = f["epss_score"]
        if f.get("cvss_score") is not None:
            props["cvss_score"] = f["cvss_score"]
        if f.get("category"):
            props["category"] = f["category"]
        result["properties"] = props

        # Related locations — show evidence as a secondary pointer
        if evidence and file_path:
            result["relatedLocations"] = [
                {
                    "id": 1,
                    "message": {"text": f"Matched evidence: {_truncate(str(evidence), 150)}"},
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": file_path,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {"startLine": line},
                    },
                }
            ]

        # Fix / remediation
        rec = f.get("recommendation") or f.get("code_fix")
        if rec and str(rec).strip() not in ("", "N/A"):
            result["fixes"] = [{"description": {"text": str(rec)}}]

        return result

    def _build_artifacts(
        self, findings: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Collect unique file URIs referenced by findings into artifact entries."""
        seen: set[str] = set()
        artifacts: List[Dict[str, Any]] = []
        for f in findings:
            uri = _normalise_uri(f.get("file", ""))
            if not uri or uri in seen:
                continue
            seen.add(uri)
            artifacts.append(
                {
                    "location": {
                        "uri": uri,
                        "uriBaseId": "%SRCROOT%",
                    },
                    "roles": ["analysisTarget"],
                }
            )
        return artifacts


# ---------------------------------------------------------------------------
# Module-level convenience function
# ---------------------------------------------------------------------------

def ghost_findings_to_sarif(
    findings: List[Dict[str, Any]],
    tool_name: str = _TOOL_NAME,
) -> str:
    """Convert Ghost findings to a SARIF 2.1.0 JSON string.

    Parameters
    ----------
    findings:
        List of Ghost finding dicts.
    tool_name:
        Displayed in ``tool.driver.name``; defaults to "Ghost Security".

    Returns
    -------
    str
        Pretty-printed SARIF 2.1.0 JSON.
    """
    exporter = SARIFExporter(tool_name=tool_name)
    sarif = exporter.export(findings, tool_name=tool_name)
    return json.dumps(sarif, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _to_pascal(rule_id: str) -> str:
    """Turn e.g. 'JAVA-001' or 'sql_injection' into a PascalCase rule name."""
    parts = rule_id.replace("-", "_").split("_")
    return "".join(p.capitalize() for p in parts if p)


def _severity_to_cvss_string(severity: str) -> str:
    """Return a CVSS-like numeric string for the GitHub security-severity tag."""
    mapping = {
        "CRITICAL": "9.5",
        "HIGH": "7.5",
        "MEDIUM": "5.0",
        "LOW": "2.5",
        "INFO": "0.0",
    }
    return mapping.get(severity.upper(), "0.0")
