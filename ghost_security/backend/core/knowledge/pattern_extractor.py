"""Pattern Extraction Engine — derives normalized patterns from corpus knowledge.

Extracts vulnerability/exploitation/remediation patterns from CWE/CVE/CAPEC/research entries.
Does NOT duplicate patterns.py (static pattern registry); extends it with dynamic extraction.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Pattern types
# ---------------------------------------------------------------------------


class PatternType:
    VULNERABILITY = "vulnerability"    # code pattern indicating vulnerability
    EXPLOITATION = "exploitation"      # how attackers exploit it
    REMEDIATION = "remediation"        # how to fix it
    DETECTION = "detection"            # how to detect it


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class ExtractedPattern:
    """A normalized pattern extracted from corpus knowledge."""
    pattern_id: str
    pattern_type: str          # PatternType constant
    regex: str                 # regex pattern (may be empty for natural language)
    description: str
    confidence: float          # 0.0-1.0
    source_cwe: str = ""
    source_cve: str = ""
    source_capec: str = ""
    language: str = ""         # python/javascript/java/any
    tags: List[str] = field(default_factory=list)
    examples: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    created_at: str = ""

    def __post_init__(self) -> None:
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return {
            "pattern_id": self.pattern_id,
            "pattern_type": self.pattern_type,
            "regex": self.regex,
            "description": self.description,
            "confidence": self.confidence,
            "source_cwe": self.source_cwe,
            "source_cve": self.source_cve,
            "source_capec": self.source_capec,
            "language": self.language,
            "tags": self.tags,
            "examples": self.examples,
        }


@dataclass
class ExtractionResult:
    """Result of a pattern extraction run."""
    patterns_extracted: int = 0
    patterns_by_type: Dict[str, int] = field(default_factory=dict)
    patterns: List[ExtractedPattern] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    elapsed_ms: float = 0.0

    def to_dict(self) -> dict:
        return {
            "patterns_extracted": self.patterns_extracted,
            "patterns_by_type": self.patterns_by_type,
            "errors": self.errors,
            "elapsed_ms": self.elapsed_ms,
        }


# ---------------------------------------------------------------------------
# CWE → pattern mapping (extends patterns.py static registry)
# ---------------------------------------------------------------------------

_CWE_VULN_PATTERNS: Dict[str, List[Tuple[str, str, float]]] = {
    # cwe_id → [(regex, description, confidence), ...]
    "CWE-89": [
        (r'\.execute\s*\(\s*["\'].*\s*\+\s*\w', "String concatenation in SQL execute()", 0.85),
        (r'cursor\.execute\s*\(\s*f"', "f-string in SQL execute()", 0.80),
        (r'%\s*\(.*user|%\s*\(.*request|%\s*\(.*input', "% formatting with user input in SQL", 0.75),
    ],
    "CWE-79": [
        (r'innerHTML\s*[+=]', "innerHTML assignment", 0.90),
        (r'document\.write\s*\(', "document.write() call", 0.85),
        (r'render_template_string\s*\(', "Flask render_template_string()", 0.80),
    ],
    "CWE-78": [
        (r'os\.system\s*\(', "os.system() with potential user input", 0.90),
        (r'subprocess\.[a-z]+\s*\([^,\)]+shell\s*=\s*True', "subprocess shell=True", 0.85),
        (r'Popen\s*\([^,]+shell\s*=\s*True', "Popen shell=True", 0.85),
    ],
    "CWE-22": [
        (r'open\s*\(\s*\w+\s*\+', "open() with string concatenation", 0.80),
        (r'Path\s*\(\s*\w+.*user', "Path() with user-derived argument", 0.75),
        (r'os\.path\.join.*request\|input\|user', "os.path.join with user input", 0.70),
    ],
    "CWE-502": [
        (r'pickle\.load\s*\(', "pickle.load() on untrusted data", 0.95),
        (r'yaml\.load\s*\([^,\)]+\)', "yaml.load() without Loader", 0.85),
        (r'marshal\.loads\s*\(', "marshal.loads() on untrusted data", 0.90),
    ],
    "CWE-798": [
        (r'password\s*=\s*["\'][^"\']{4,}["\']', "Hardcoded password literal", 0.80),
        (r'api_key\s*=\s*["\'][^"\']{8,}["\']', "Hardcoded API key", 0.80),
        (r'secret\s*=\s*["\'][^"\']{4,}["\']', "Hardcoded secret", 0.75),
    ],
    "CWE-327": [
        (r'\bmd5\b', "MD5 usage (broken)", 0.80),
        (r'\bsha1\b|\bsha-1\b', "SHA-1 usage (broken)", 0.80),
        (r'DES\b|RC4\b|RC2\b', "Broken cipher usage", 0.85),
    ],
    "CWE-918": [
        (r'requests\.(get|post|put|delete)\s*\(\s*\w*url\w*\)', "requests with URL variable", 0.70),
        (r'urllib.*urlopen\s*\(\s*\w', "urlopen with variable URL", 0.70),
    ],
    "CWE-94": [
        (r'\beval\s*\(', "eval() call", 0.95),
        (r'\bexec\s*\(', "exec() call", 0.90),
        (r'compile\s*\([^,]+,\s*["\']["\'],', "compile() for code execution", 0.85),
    ],
}

_CWE_REMEDIATION_PATTERNS: Dict[str, List[Tuple[str, str]]] = {
    "CWE-89": [
        ("%s|:param|parameterize|prepared statement", "Use parameterized queries"),
        ("sqlalchemy|django orm|peewee", "Use ORM instead of raw SQL"),
    ],
    "CWE-79": [
        ("escape|markupsafe|html.escape|DOMPurify", "HTML-encode user output"),
        ("textContent|innerText", "Use textContent instead of innerHTML"),
    ],
    "CWE-78": [
        ("shell=False|shlex.quote|shlex.split", "Disable shell interpretation"),
        (r"\[.*\].*Popen|subprocess.run\(\[", "Pass args as list to subprocess"),
    ],
    "CWE-22": [
        ("realpath|resolve()|abspath", "Resolve path before use"),
        ("startswith.*base_dir|os.path.commonprefix", "Validate path prefix"),
    ],
    "CWE-502": [
        ("yaml.safe_load", "Use yaml.safe_load instead of yaml.load"),
        ("json.loads", "Use JSON instead of pickle for untrusted data"),
    ],
    "CWE-798": [
        ("os.environ|os.getenv|getenv", "Read secrets from environment"),
        ("vault|secrets_manager|keyring", "Use secrets manager"),
    ],
}


# ---------------------------------------------------------------------------
# Description keyword → CWE mapping (for CVE extraction)
# ---------------------------------------------------------------------------

_KEYWORD_CWE_MAP: Dict[str, str] = {
    "sql injection": "CWE-89",
    "sqli": "CWE-89",
    "cross-site scripting": "CWE-79",
    "xss": "CWE-79",
    "command injection": "CWE-78",
    "os command": "CWE-78",
    "path traversal": "CWE-22",
    "directory traversal": "CWE-22",
    "deserialization": "CWE-502",
    "pickle": "CWE-502",
    "hardcoded": "CWE-798",
    "hardcoded secret": "CWE-798",
    "weak crypto": "CWE-327",
    "md5": "CWE-327",
    "sha1": "CWE-327",
    "ssrf": "CWE-918",
    "server-side request": "CWE-918",
    "code injection": "CWE-94",
    "eval": "CWE-94",
    "null pointer": "CWE-476",
    "null dereference": "CWE-476",
    "xml external": "CWE-611",
    "xxe": "CWE-611",
    "csrf": "CWE-352",
    "cross-site request forgery": "CWE-352",
    "buffer overflow": "CWE-121",
    "use after free": "CWE-416",
}


# ---------------------------------------------------------------------------
# Pattern Extractor
# ---------------------------------------------------------------------------


class PatternExtractor:
    """Extracts normalized patterns from corpus entries.

    Extends (does not duplicate) the static patterns.py registry.
    """

    def __init__(self) -> None:
        self._extracted: Dict[str, ExtractedPattern] = {}

    def extract_from_cwe(self, cwe_entry: Any) -> List[ExtractedPattern]:
        """Extract patterns from a CWEEntry corpus object."""
        import time as _time
        cwe_id = getattr(cwe_entry, "cwe_id", "") or (cwe_entry.get("cwe_id", "") if isinstance(cwe_entry, dict) else "")
        if not cwe_id:
            return []

        patterns: List[ExtractedPattern] = []

        # 1. Vulnerability patterns from CWE knowledge base
        for regex, desc, confidence in _CWE_VULN_PATTERNS.get(cwe_id, []):
            pat = ExtractedPattern(
                pattern_id=f"vuln::{cwe_id}::{len(patterns)}",
                pattern_type=PatternType.VULNERABILITY,
                regex=regex,
                description=desc,
                confidence=confidence,
                source_cwe=cwe_id,
                language="python",
                tags=["cwe", cwe_id.lower()],
            )
            patterns.append(pat)
            self._extracted[pat.pattern_id] = pat

        # 2. Remediation patterns from CWE knowledge base
        for pattern_hint, desc in _CWE_REMEDIATION_PATTERNS.get(cwe_id, []):
            pat = ExtractedPattern(
                pattern_id=f"remediation::{cwe_id}::{len(patterns)}",
                pattern_type=PatternType.REMEDIATION,
                regex=pattern_hint,
                description=desc,
                confidence=0.80,
                source_cwe=cwe_id,
                tags=["cwe", "remediation", cwe_id.lower()],
            )
            patterns.append(pat)
            self._extracted[pat.pattern_id] = pat

        # 3. From entry's embedded patterns
        entry_patterns = getattr(cwe_entry, "vulnerability_patterns", []) or []
        for i, ep in enumerate(entry_patterns):
            if isinstance(ep, str) and ep not in [p.regex for p in patterns]:
                pat = ExtractedPattern(
                    pattern_id=f"cwe_entry::{cwe_id}::{i}",
                    pattern_type=PatternType.VULNERABILITY,
                    regex=ep,
                    description=f"Pattern from {cwe_id}",
                    confidence=0.70,
                    source_cwe=cwe_id,
                    tags=["cwe", cwe_id.lower()],
                )
                patterns.append(pat)
                self._extracted[pat.pattern_id] = pat

        return patterns

    def extract_from_cve(self, cve_entry: Any) -> List[ExtractedPattern]:
        """Extract patterns from a CVEEntry based on description keywords."""
        cve_id = getattr(cve_entry, "cve_id", "") or ""
        description = (getattr(cve_entry, "description", "") or "").lower()
        cwe_ids = getattr(cve_entry, "cwe_ids", []) or []
        patterns: List[ExtractedPattern] = []

        # Find CWEs from description keywords
        inferred_cwes = set(cwe_ids)
        for keyword, cwe_id in _KEYWORD_CWE_MAP.items():
            if keyword in description:
                inferred_cwes.add(cwe_id)

        # Generate detection patterns for each inferred CWE
        for cwe_id in inferred_cwes:
            for regex, desc, confidence in _CWE_VULN_PATTERNS.get(cwe_id, []):
                pat = ExtractedPattern(
                    pattern_id=f"cve::{cve_id}::{cwe_id}::{len(patterns)}",
                    pattern_type=PatternType.VULNERABILITY,
                    regex=regex,
                    description=f"{desc} (from {cve_id})",
                    confidence=confidence * 0.9,  # slight discount for CVE derivation
                    source_cwe=cwe_id,
                    source_cve=cve_id,
                    tags=["cve", cwe_id.lower()],
                )
                patterns.append(pat)
                self._extracted[pat.pattern_id] = pat

        return patterns

    def extract_from_capec(self, capec_entry: Any) -> List[ExtractedPattern]:
        """Extract exploitation patterns from a CAPECEntry."""
        capec_id = getattr(capec_entry, "capec_id", "") or ""
        name = getattr(capec_entry, "name", "") or ""
        attack_steps = getattr(capec_entry, "attack_steps", []) or []
        related_cwes = getattr(capec_entry, "related_cwes", []) or []
        patterns: List[ExtractedPattern] = []

        # Create exploitation pattern from attack steps
        if attack_steps:
            pat = ExtractedPattern(
                pattern_id=f"capec::{capec_id}::exploit",
                pattern_type=PatternType.EXPLOITATION,
                regex="",  # No regex for exploitation steps
                description=f"Exploitation pattern: {name}. Steps: {'; '.join(attack_steps[:3])}",
                confidence=0.80,
                source_capec=capec_id,
                tags=["capec", "exploitation"] + [c.lower() for c in related_cwes],
            )
            patterns.append(pat)
            self._extracted[pat.pattern_id] = pat

        # Also extract detection patterns for related CWEs
        for cwe_id in related_cwes:
            for regex, desc, confidence in _CWE_VULN_PATTERNS.get(cwe_id, []):
                pat = ExtractedPattern(
                    pattern_id=f"capec::{capec_id}::{cwe_id}::{len(patterns)}",
                    pattern_type=PatternType.DETECTION,
                    regex=regex,
                    description=f"Detects {name} exploitation: {desc}",
                    confidence=confidence * 0.85,
                    source_cwe=cwe_id,
                    source_capec=capec_id,
                    tags=["capec", "detection", cwe_id.lower()],
                )
                patterns.append(pat)
                self._extracted[pat.pattern_id] = pat

        return patterns

    def extract_from_finding(self, finding: Any) -> List[ExtractedPattern]:
        """Extract patterns from a confirmed vulnerability finding."""
        cwe_id = getattr(finding, "cwe_id", "") or (finding.get("cwe_id", "") if isinstance(finding, dict) else "")
        rule_id = getattr(finding, "rule_id", "") or (finding.get("rule_id", "") if isinstance(finding, dict) else "")
        patterns: List[ExtractedPattern] = []

        if not cwe_id:
            return []

        # Get known patterns for this CWE with boosted confidence (confirmed finding)
        for regex, desc, confidence in _CWE_VULN_PATTERNS.get(cwe_id, []):
            boosted = min(confidence + 0.05, 1.0)
            pat = ExtractedPattern(
                pattern_id=f"finding::{rule_id}::{cwe_id}::{len(patterns)}",
                pattern_type=PatternType.VULNERABILITY,
                regex=regex,
                description=f"Confirmed via finding {rule_id}: {desc}",
                confidence=boosted,
                source_cwe=cwe_id,
                tags=["finding", "confirmed", cwe_id.lower(), rule_id],
            )
            patterns.append(pat)
            self._extracted[pat.pattern_id] = pat

        return patterns

    def extract_all(self, corpus: Any) -> ExtractionResult:
        """Extract patterns from all entries in a SecurityCorpus."""
        import time as _time
        from backend.core.knowledge.security_corpus import (
            CorpusEntryType, CWEEntry, CVEEntry, CAPECEntry,
        )
        t = _time.monotonic()
        result = ExtractionResult()
        by_type: Dict[str, int] = {}

        for entry in corpus.all_entries():
            try:
                if isinstance(entry, CWEEntry):
                    pats = self.extract_from_cwe(entry)
                elif isinstance(entry, CVEEntry):
                    pats = self.extract_from_cve(entry)
                elif isinstance(entry, CAPECEntry):
                    pats = self.extract_from_capec(entry)
                else:
                    pats = []

                for p in pats:
                    by_type[p.pattern_type] = by_type.get(p.pattern_type, 0) + 1
                result.patterns.extend(pats)
                result.patterns_extracted += len(pats)
            except Exception as exc:
                result.errors.append(f"{entry.entry_id}: {exc}")

        result.patterns_by_type = by_type
        result.elapsed_ms = round((_time.monotonic() - t) * 1000, 2)
        return result

    def get_all_patterns(self) -> List[ExtractedPattern]:
        return list(self._extracted.values())

    def get_patterns_for_cwe(self, cwe_id: str) -> List[ExtractedPattern]:
        return [p for p in self._extracted.values() if p.source_cwe == cwe_id]

    def get_patterns_by_type(self, pattern_type: str) -> List[ExtractedPattern]:
        return [p for p in self._extracted.values() if p.pattern_type == pattern_type]
