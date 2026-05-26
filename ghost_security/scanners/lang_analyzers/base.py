"""
Ghost Security — Lang Analyzers Base
=====================================
Shared dataclasses used by all language-specific analyzers.

LangFinding  : a single detected vulnerability with full context.
LangAnalysisResult : aggregate result from one analyzer run, with
                     SARIF 2.1.0 and plain-dict serialization.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# Severity ordering (for sorting / comparison)
# ---------------------------------------------------------------------------

SEVERITY_ORDER: Dict[str, int] = {
    "CRITICAL": 0,
    "HIGH":     1,
    "MEDIUM":   2,
    "LOW":      3,
    "INFO":     4,
}

# SARIF level mapping
_SARIF_LEVEL: Dict[str, str] = {
    "CRITICAL": "error",
    "HIGH":     "error",
    "MEDIUM":   "warning",
    "LOW":      "note",
    "INFO":     "none",
}


# ---------------------------------------------------------------------------
# LangFinding
# ---------------------------------------------------------------------------

@dataclass
class LangFinding:
    """Represents a single security finding from a language analyzer.

    Attributes
    ----------
    filepath      : Path to the file containing the finding.
    line          : 1-based line number.
    column        : 1-based column number (0 if unknown).
    rule_id       : Unique rule identifier, e.g. "SOL-001".
    title         : Short human-readable title.
    description   : Full explanation of the vulnerability.
    severity      : One of CRITICAL / HIGH / MEDIUM / LOW / INFO.
    category      : Vulnerability category, e.g. "reentrancy".
    code_snippet  : Relevant source excerpt (may be multi-line).
    recommendation: Suggested remediation.
    tool          : Tool that produced the finding (slither / native / etc.).
    confidence    : Float in [0.0, 1.0] expressing detection confidence.
    cwe           : Optional CWE identifier, e.g. "CWE-190".
    """

    filepath: str
    line: int
    column: int
    rule_id: str
    title: str
    description: str
    severity: str
    category: str
    code_snippet: str
    recommendation: str
    tool: str
    confidence: float
    cwe: str = ""

    # ------------------------------------------------------------------ helpers

    @property
    def severity_rank(self) -> int:
        """Lower is more severe."""
        return SEVERITY_ORDER.get(self.severity.upper(), 99)

    def to_dict(self) -> Dict:
        return {
            "filepath":       self.filepath,
            "line":           self.line,
            "column":         self.column,
            "rule_id":        self.rule_id,
            "title":          self.title,
            "description":    self.description,
            "severity":       self.severity,
            "category":       self.category,
            "code_snippet":   self.code_snippet,
            "recommendation": self.recommendation,
            "tool":           self.tool,
            "confidence":     round(self.confidence, 3),
            "cwe":            self.cwe,
        }

    def to_sarif_result(self) -> Dict:
        """Return a SARIF 2.1.0 result object for this finding."""
        return {
            "ruleId":  self.rule_id,
            "level":   _SARIF_LEVEL.get(self.severity.upper(), "warning"),
            "message": {"text": self.description},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": self.filepath},
                        "region": {
                            "startLine":   self.line,
                            "startColumn": self.column,
                            "snippet":     {"text": self.code_snippet},
                        },
                    }
                }
            ],
            "properties": {
                "title":          self.title,
                "category":       self.category,
                "recommendation": self.recommendation,
                "tool":           self.tool,
                "confidence":     round(self.confidence, 3),
                "cwe":            self.cwe,
            },
        }

    def __lt__(self, other: "LangFinding") -> bool:
        return self.severity_rank < other.severity_rank


# ---------------------------------------------------------------------------
# LangAnalysisResult
# ---------------------------------------------------------------------------

@dataclass
class LangAnalysisResult:
    """Aggregate result from a single language analyzer run.

    Attributes
    ----------
    language       : Human name of the language/ecosystem, e.g. "Solidity".
    files_analyzed : Number of source files that were processed.
    findings       : List of LangFinding objects, sorted by severity.
    tool_available : True when an external tool (slither/gosec/…) was found.
    scan_time      : Wall-clock seconds taken for the scan.
    summary        : Dict mapping severity label to count, e.g. {"HIGH": 3}.
    errors         : Non-fatal errors/warnings encountered during analysis.
    """

    language: str
    files_analyzed: int
    findings: List[LangFinding]
    tool_available: bool
    scan_time: float
    summary: Dict[str, int] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

    # ------------------------------------------------------------------ factory

    @classmethod
    def build(
        cls,
        language: str,
        findings: List[LangFinding],
        files_analyzed: int,
        tool_available: bool,
        scan_time: float,
        errors: Optional[List[str]] = None,
    ) -> "LangAnalysisResult":
        """Construct a result, computing the summary automatically."""
        summary: Dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
        for f in findings:
            key = f.severity.upper()
            summary[key] = summary.get(key, 0) + 1
        # Remove zero-count entries for cleanliness
        summary = {k: v for k, v in summary.items() if v > 0}
        return cls(
            language=language,
            files_analyzed=files_analyzed,
            findings=sorted(findings),
            tool_available=tool_available,
            scan_time=round(scan_time, 4),
            summary=summary,
            errors=errors or [],
        )

    # ------------------------------------------------------------------ output

    def to_dict(self) -> Dict:
        return {
            "language":       self.language,
            "files_analyzed": self.files_analyzed,
            "tool_available": self.tool_available,
            "scan_time_sec":  self.scan_time,
            "summary":        self.summary,
            "total_findings": len(self.findings),
            "errors":         self.errors,
            "findings":       [f.to_dict() for f in self.findings],
        }

    def to_sarif(self) -> Dict:
        """Return a SARIF 2.1.0 log object."""
        rules: Dict[str, Dict] = {}
        results = []
        for finding in self.findings:
            if finding.rule_id not in rules:
                rules[finding.rule_id] = {
                    "id": finding.rule_id,
                    "name": finding.title,
                    "shortDescription": {"text": finding.title},
                    "fullDescription":  {"text": finding.description},
                    "helpUri": f"https://cwe.mitre.org/data/definitions/"
                               f"{finding.cwe.replace('CWE-', '')}.html"
                               if finding.cwe else "",
                    "properties": {
                        "tags":     [finding.category],
                        "severity": finding.severity,
                    },
                }
            results.append(finding.to_sarif_result())

        return {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name":    f"GhostSecurity/{self.language}Analyzer",
                            "version": "15.0.0",
                            "rules":   list(rules.values()),
                        }
                    },
                    "results":         results,
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "toolExecutionNotifications": [
                                {"message": {"text": e}, "level": "warning"}
                                for e in self.errors
                            ],
                        }
                    ],
                }
            ],
        }

    # ------------------------------------------------------------------ repr

    def __repr__(self) -> str:
        return (
            f"<LangAnalysisResult language={self.language!r} "
            f"files={self.files_analyzed} findings={len(self.findings)} "
            f"summary={self.summary}>"
        )
