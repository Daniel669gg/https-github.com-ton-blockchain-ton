"""
backend/core/engine/finding_normalizer.py — Unified finding normalization layer.

Converts raw findings from any scanner (Semgrep, AST, OSV, OWASP, secrets, etc.)
into NormalizedFinding objects. Handles deduplication and priority sorting.
"""
from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# CWE → OWASP Top 10 (2021) mapping
# ---------------------------------------------------------------------------

_CWE_TO_OWASP: Dict[str, str] = {
    "CWE-89":  "A03:2021 – Injection",
    "CWE-79":  "A03:2021 – Injection",
    "CWE-78":  "A03:2021 – Injection",
    "CWE-22":  "A01:2021 – Broken Access Control",
    "CWE-798": "A07:2021 – Identification and Authentication Failures",
    "CWE-502": "A08:2021 – Software and Data Integrity Failures",
    "CWE-327": "A02:2021 – Cryptographic Failures",
    "CWE-918": "A10:2021 – Server-Side Request Forgery",
    "CWE-94":  "A03:2021 – Injection",
    "CWE-611": "A05:2021 – Security Misconfiguration",
    "CWE-284": "A01:2021 – Broken Access Control",
    "CWE-862": "A01:2021 – Broken Access Control",
    "CWE-352": "A01:2021 – Broken Access Control",
    "CWE-306": "A07:2021 – Identification and Authentication Failures",
    "CWE-434": "A04:2021 – Insecure Design",
    "CWE-200": "A02:2021 – Cryptographic Failures",
    "CWE-312": "A02:2021 – Cryptographic Failures",
    "CWE-476": "A04:2021 – Insecure Design",
    "CWE-190": "A04:2021 – Insecure Design",
    "CWE-400": "A04:2021 – Insecure Design",
}

# ---------------------------------------------------------------------------
# CWE → one-line fix hints
# ---------------------------------------------------------------------------

_CWE_FIX_HINTS: Dict[str, str] = {
    "CWE-89":  "Use parameterized queries or prepared statements instead of string concatenation.",
    "CWE-79":  "HTML-encode user-supplied data with markupsafe.escape() before rendering.",
    "CWE-78":  "Pass arguments as a list to subprocess.run() with shell=False; use shlex.split() if needed.",
    "CWE-22":  "Resolve the real path with os.path.realpath() and verify it starts with the allowed base directory.",
    "CWE-798": "Read credentials from environment variables (os.environ.get) or a secrets manager, never hardcode.",
    "CWE-502": "Replace yaml.load() with yaml.safe_load(); avoid pickle for untrusted data.",
    "CWE-327": "Replace MD5/SHA-1 with SHA-256 or stronger; use bcrypt/argon2 for passwords.",
    "CWE-918": "Validate request URLs against an explicit allowlist and block private/loopback addresses.",
    "CWE-94":  "Avoid eval()/exec() on user input; use ast.literal_eval() or a strict validation whitelist.",
    "CWE-611": "Disable external entity processing in your XML parser (defusedxml or explicit feature flags).",
    "CWE-284": "Enforce authorization checks on every sensitive resource access.",
    "CWE-862": "Add explicit permission checks before exposing sensitive operations or data.",
}

# Severity ordering for deduplication (higher = more severe)
_SEVERITY_RANK: Dict[str, int] = {
    "CRITICAL": 5,
    "HIGH":     4,
    "MEDIUM":   3,
    "LOW":      2,
    "INFO":     1,
}

# Raw scanner severity → canonical severity
_SEVERITY_MAP: Dict[str, str] = {
    "CRITICAL": "CRITICAL",
    "ERROR":    "CRITICAL",
    "HIGH":     "HIGH",
    "WARNING":  "MEDIUM",
    "WARN":     "MEDIUM",
    "MEDIUM":   "MEDIUM",
    "LOW":      "LOW",
    "INFO":     "INFO",
    "NOTE":     "INFO",
    "NONE":     "INFO",
}

_CWE_PATTERN = re.compile(r"CWE-\d+", re.IGNORECASE)


# ---------------------------------------------------------------------------
# NormalizedFinding
# ---------------------------------------------------------------------------

@dataclass
class NormalizedFinding:
    """Canonical vulnerability finding shared across all scanner outputs."""

    finding_id: str
    title: str
    description: str
    severity: str          # CRITICAL / HIGH / MEDIUM / LOW / INFO
    cwe_id: str            # "CWE-89" or ""
    owasp_category: str    # "A03:2021 – Injection" or ""
    file_path: str
    line: int
    column: int = 0
    evidence: str = ""
    recommendation: str = ""
    source_scanner: str = ""
    confidence: float = 0.75
    cvss_score: float = 0.0
    epss_score: float = 0.0
    is_kev: bool = False
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    rule_id: str = ""
    fix_hint: str = ""

    # ------------------------------------------------------------------

    @staticmethod
    def _make_id(file_path: str, line: int, cwe_id: str, vuln_type: str) -> str:
        """SHA-256 of concatenated key fields, first 16 hex chars."""
        raw = f"{file_path}{line}{cwe_id}{vuln_type}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def priority_score(self) -> float:
        """Composite score used for sort ordering (higher = more urgent)."""
        base = {
            "CRITICAL": 100,
            "HIGH":     75,
            "MEDIUM":   50,
            "LOW":      25,
            "INFO":     5,
        }.get(self.severity, 5)
        return (
            base
            + self.cvss_score * 5
            + self.epss_score * 10
            + (20 if self.is_kev else 0)
        )

    def to_dict(self) -> dict:
        return {
            "finding_id":     self.finding_id,
            "title":          self.title,
            "description":    self.description,
            "severity":       self.severity,
            "cwe_id":         self.cwe_id,
            "owasp_category": self.owasp_category,
            "file_path":      self.file_path,
            "line":           self.line,
            "column":         self.column,
            "evidence":       self.evidence,
            "recommendation": self.recommendation,
            "source_scanner": self.source_scanner,
            "confidence":     self.confidence,
            "cvss_score":     self.cvss_score,
            "epss_score":     self.epss_score,
            "is_kev":         self.is_kev,
            "references":     self.references,
            "tags":           self.tags,
            "rule_id":        self.rule_id,
            "fix_hint":       self.fix_hint,
        }


# ---------------------------------------------------------------------------
# FindingNormalizer
# ---------------------------------------------------------------------------

class FindingNormalizer:
    """Normalizes raw scanner dicts into NormalizedFinding objects."""

    def __init__(self) -> None:
        pass

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _pick(raw: dict, *keys: str, default: str = "") -> str:
        """Return the first non-empty value from *keys in *raw*."""
        for k in keys:
            v = raw.get(k)
            if v is not None:
                s = str(v).strip()
                if s:
                    return s
        return default

    @staticmethod
    def _pick_int(raw: dict, *keys: str, default: int = 0) -> int:
        for k in keys:
            v = raw.get(k)
            if v is not None:
                try:
                    return int(v)
                except (TypeError, ValueError):
                    pass
        return default

    @staticmethod
    def _normalize_severity(raw_severity: str) -> str:
        """Map raw scanner severity string to canonical CRITICAL/HIGH/MEDIUM/LOW/INFO."""
        return _SEVERITY_MAP.get(raw_severity.upper().strip(), "MEDIUM")

    @staticmethod
    def _extract_cwe(raw: dict) -> str:
        """Extract the first CWE-NNN token from common CWE-carrying fields."""
        for key in ("cwe", "cwe_id", "cwe_tag", "cwe_ids", "cwes"):
            val = raw.get(key)
            if val is None:
                continue
            # Could be a list or a string
            if isinstance(val, list):
                for item in val:
                    m = _CWE_PATTERN.search(str(item))
                    if m:
                        return m.group(0).upper()
            else:
                m = _CWE_PATTERN.search(str(val))
                if m:
                    return m.group(0).upper()
        # Fallback: scan the whole dict for a CWE pattern in any string value
        for v in raw.values():
            if isinstance(v, str):
                m = _CWE_PATTERN.search(v)
                if m:
                    return m.group(0).upper()
        return ""

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def normalize(self, raw: dict, scanner: str) -> NormalizedFinding:
        """Convert a raw scanner dict into a NormalizedFinding."""
        # Severity
        raw_sev = self._pick(raw, "severity", "level", "priority", default="MEDIUM")
        severity = self._normalize_severity(raw_sev)

        # CWE
        cwe_id = self._extract_cwe(raw)

        # OWASP (may be overridden later by enrich_cwe_data)
        owasp_category = _CWE_TO_OWASP.get(cwe_id, "")

        # File path
        file_path = self._pick(raw, "file", "path", "file_path", "filename", default="")

        # Line / column
        line   = self._pick_int(raw, "line", "start_line", "line_number", "lineno", default=0)
        column = self._pick_int(raw, "column", "col", "start_column", default=0)

        # Description / title
        description = self._pick(raw, "message", "description", "msg", "detail", "info", default="")
        title_raw   = self._pick(raw, "title", "check_id", "rule_id", "rule", "id", default="")
        title = title_raw or description[:80] or f"{scanner} finding"

        # Evidence
        evidence = self._pick(raw, "evidence", "lines", "code", "snippet", "source", default="")

        # Recommendation
        recommendation = self._pick(raw, "recommendation", "fix", "remediation", "fix_text", default="")

        # Confidence
        confidence_raw = raw.get("confidence", raw.get("score", 0.75))
        try:
            confidence = float(confidence_raw)
            if confidence > 1.0:
                confidence = confidence / 100.0
            confidence = max(0.0, min(1.0, confidence))
        except (TypeError, ValueError):
            confidence = 0.75

        # CVSS / EPSS / KEV
        cvss_score = float(raw.get("cvss_score", raw.get("cvss", 0.0)) or 0.0)
        epss_score = float(raw.get("epss_score", raw.get("epss", 0.0)) or 0.0)
        is_kev     = bool(raw.get("is_kev", raw.get("kev", False)))

        # References / tags
        refs = raw.get("references", raw.get("refs", []))
        if not isinstance(refs, list):
            refs = [str(refs)] if refs else []
        tags = raw.get("tags", [])
        if not isinstance(tags, list):
            tags = [str(tags)] if tags else []

        # Rule ID
        rule_id = self._pick(raw, "rule_id", "check_id", "rule", "id", default="")

        # Fix hint from dictionary
        fix_hint = _CWE_FIX_HINTS.get(cwe_id, "")

        # Finding ID: SHA-256(file_path + str(line) + cwe_id + vuln_type)[:16]
        vuln_type = rule_id or title
        finding_id = NormalizedFinding._make_id(file_path, line, cwe_id, vuln_type)

        return NormalizedFinding(
            finding_id=finding_id,
            title=title,
            description=description,
            severity=severity,
            cwe_id=cwe_id,
            owasp_category=owasp_category,
            file_path=file_path,
            line=line,
            column=column,
            evidence=evidence,
            recommendation=recommendation,
            source_scanner=scanner,
            confidence=confidence,
            cvss_score=cvss_score,
            epss_score=epss_score,
            is_kev=is_kev,
            references=refs,
            tags=tags,
            rule_id=rule_id,
            fix_hint=fix_hint,
        )

    def normalize_batch(self, raws: List[dict], scanner: str) -> List[NormalizedFinding]:
        """Normalize a list of raw finding dicts from one scanner."""
        results: List[NormalizedFinding] = []
        for raw in raws:
            try:
                results.append(self.normalize(raw, scanner))
            except Exception as exc:
                logger.warning("Failed to normalize finding from %s: %s", scanner, exc)
        return results

    def deduplicate(self, findings: List[NormalizedFinding]) -> List[NormalizedFinding]:
        """Deduplicate by finding_id, keeping the instance with the highest severity."""
        best: Dict[str, NormalizedFinding] = {}
        for f in findings:
            existing = best.get(f.finding_id)
            if existing is None:
                best[f.finding_id] = f
            else:
                # Keep whichever has higher severity rank
                if _SEVERITY_RANK.get(f.severity, 0) > _SEVERITY_RANK.get(existing.severity, 0):
                    best[f.finding_id] = f
        return list(best.values())

    def sort_by_priority(self, findings: List[NormalizedFinding]) -> List[NormalizedFinding]:
        """Return findings sorted by priority_score descending."""
        return sorted(findings, key=lambda f: f.priority_score(), reverse=True)

    def enrich_cwe_data(self, findings: List[NormalizedFinding]) -> List[NormalizedFinding]:
        """Fill owasp_category and fix_hint from the built-in dictionaries where blank."""
        for f in findings:
            if f.cwe_id:
                if not f.owasp_category:
                    f.owasp_category = _CWE_TO_OWASP.get(f.cwe_id, "")
                if not f.fix_hint:
                    f.fix_hint = _CWE_FIX_HINTS.get(f.cwe_id, "")
        return findings
