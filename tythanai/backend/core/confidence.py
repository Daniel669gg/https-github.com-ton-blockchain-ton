"""
backend/core/confidence.py — Phase 1 Advanced AppSec Platform
Pydantic v2 Finding model, ConfidenceFilter, ContextVerifier, Deduplicator.
"""
from __future__ import annotations

import hashlib
import re
import logging
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from pydantic import BaseModel, Field, field_validator, model_validator

logger = logging.getLogger("tythanai.confidence")

# ─────────────────────────────────────────────────────────────────────────────
# Data model
# ─────────────────────────────────────────────────────────────────────────────

class Finding(BaseModel):
    model_config = {"extra": "allow"}

    rule_id: str
    file: str
    line: int = 0
    severity: str = "MEDIUM"           # CRITICAL / HIGH / MEDIUM / LOW / INFO
    confidence: float = Field(default=0.8)
    cwe_id: str = ""
    description: str = ""
    recommendation: str = ""
    sources: List[str] = Field(default_factory=list)
    context_lines: List[str] = Field(default_factory=list)
    is_test_file: bool = False
    is_suppressed: bool = False

    @field_validator("severity")
    @classmethod
    def normalize_severity(cls, v: str) -> str:
        return v.upper()

    @field_validator("confidence", mode="before")
    @classmethod
    def clamp_confidence(cls, v: float) -> float:
        return max(0.0, min(1.0, round(float(v), 4)))

    @property
    def dedup_key(self) -> Tuple[str, int, str]:
        return (self.file, self.line, self.rule_id)

    def fingerprint(self) -> str:
        raw = f"{self.file}:{self.line}:{self.rule_id}"
        return hashlib.sha1(raw.encode()).hexdigest()[:16]


# ─────────────────────────────────────────────────────────────────────────────
# Suppression patterns
# ─────────────────────────────────────────────────────────────────────────────

_SUPPRESSION_TOKENS = ("nosec", "noqa", "audit-ignore")

_COMMENT_LINE_RE = re.compile(r"^\s*(#|//|/\*|\*)")

_SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def _is_suppressed_line(line: str) -> bool:
    """Return True if the source line carries a suppression annotation."""
    low = line.lower()
    return any(tok in low for tok in _SUPPRESSION_TOKENS)


def _is_commented_out(line: str) -> bool:
    """Return True if the line is purely a comment (not code that runs)."""
    return bool(_COMMENT_LINE_RE.match(line))


# ─────────────────────────────────────────────────────────────────────────────
# Context verifier
# ─────────────────────────────────────────────────────────────────────────────

_TEST_FILE_PATTERNS = (
    re.compile(r"(^|[/\\])test_", re.IGNORECASE),
    re.compile(r"_test\.(py|go|js|ts)$", re.IGNORECASE),
    re.compile(r"(^|[/\\])conftest\.py$", re.IGNORECASE),
    re.compile(r"(^|[/\\])tests?[/\\]", re.IGNORECASE),
    re.compile(r"(^|[/\\])spec[/\\]", re.IGNORECASE),
)

_TEST_CONTEXT_TOKENS = (
    "fixture",
    "mock",
    "pytest",
    "unittest",
    "describe(",
    "it(",
    "test_",
)

_SEVERITY_DOWNGRADE: Dict[str, str] = {
    "CRITICAL": "HIGH",
    "HIGH": "MEDIUM",
    "MEDIUM": "LOW",
    "LOW": "INFO",
    "INFO": "INFO",
}


class ContextVerifier:
    """
    Examines each Finding for test-file context and suppression markers.

    Rules:
    - Finding in a test file → is_test_file=True, severity downgraded one level
    - Finding has nosec/noqa/audit-ignore on the triggering line → is_suppressed=True
    - Finding line is pure comment → is_suppressed=True
    """

    def verify(self, finding: Finding) -> Finding:
        finding = finding.model_copy(deep=True)

        # ── Test-file detection ──────────────────────────────────────────────
        if self._is_test_file(finding.file):
            finding.is_test_file = True
            logger.debug("test_file %s:%d rule=%s", finding.file, finding.line, finding.rule_id)

        # Also check context lines for test tokens
        ctx_text = " ".join(finding.context_lines).lower()
        if not finding.is_test_file and any(tok in ctx_text for tok in _TEST_CONTEXT_TOKENS):
            finding.is_test_file = True

        # ── Suppression detection ────────────────────────────────────────────
        for ctx_line in finding.context_lines:
            if _is_suppressed_line(ctx_line):
                finding.is_suppressed = True
                break
            if _is_commented_out(ctx_line):
                finding.is_suppressed = True
                break

        # ── Apply severity downgrade for test-file findings ──────────────────
        if finding.is_test_file and not finding.is_suppressed:
            old_sev = finding.severity
            finding.severity = _SEVERITY_DOWNGRADE.get(old_sev, "LOW")
            if old_sev != finding.severity:
                logger.debug(
                    "severity downgraded %s→%s for test file %s",
                    old_sev, finding.severity, finding.file,
                )

        return finding

    @staticmethod
    def _is_test_file(path: str) -> bool:
        return any(p.search(path) for p in _TEST_FILE_PATTERNS)


# ─────────────────────────────────────────────────────────────────────────────
# Confidence filter
# ─────────────────────────────────────────────────────────────────────────────

class ConfidenceFilter:
    """
    Filters findings below a confidence threshold.
    Also removes suppressed findings entirely.
    """

    def __init__(self, threshold: float = 0.7) -> None:
        self.threshold = threshold

    def filter(
        self,
        findings: Sequence[Finding],
        threshold: Optional[float] = None,
    ) -> List[Finding]:
        thr = threshold if threshold is not None else self.threshold
        result: List[Finding] = []
        for f in findings:
            if f.is_suppressed:
                logger.debug("suppressed %s:%d rule=%s", f.file, f.line, f.rule_id)
                continue
            if f.confidence < thr:
                logger.debug(
                    "low-confidence filtered (%.2f < %.2f) %s:%d rule=%s",
                    f.confidence, thr, f.file, f.line, f.rule_id,
                )
                continue
            result.append(f)
        return result


# ─────────────────────────────────────────────────────────────────────────────
# Deduplicator
# ─────────────────────────────────────────────────────────────────────────────

class Deduplicator:
    """
    Merges findings with the same (file, line, rule_id) key.

    Merging strategy:
    - confidence: max of all duplicates
    - sources: union of all sources lists
    - context_lines: union, capped at 10 lines
    - severity: highest among duplicates
    - Other fields: taken from the first occurrence
    """

    def deduplicate(self, findings: Sequence[Finding]) -> List[Finding]:
        groups: Dict[Tuple[str, int, str], List[Finding]] = {}
        for f in findings:
            groups.setdefault(f.dedup_key, []).append(f)

        merged: List[Finding] = []
        for key, group in groups.items():
            if len(group) == 1:
                merged.append(group[0])
                continue

            base = group[0].model_copy(deep=True)
            all_sources: Set[str] = set(base.sources)
            all_ctx: List[str] = list(base.context_lines)
            best_conf = base.confidence
            best_sev_order = _SEVERITY_ORDER.get(base.severity, 0)

            for dup in group[1:]:
                all_sources.update(dup.sources)
                for ln in dup.context_lines:
                    if ln not in all_ctx:
                        all_ctx.append(ln)
                if dup.confidence > best_conf:
                    best_conf = dup.confidence
                sev_ord = _SEVERITY_ORDER.get(dup.severity, 0)
                if sev_ord > best_sev_order:
                    best_sev_order = sev_ord
                    base.severity = dup.severity

            base.confidence = round(best_conf, 4)
            base.sources = sorted(all_sources)
            base.context_lines = all_ctx[:10]

            logger.debug(
                "dedup %s:%d rule=%s — merged %d duplicates",
                key[0], key[1], key[2], len(group),
            )
            merged.append(base)

        return merged


# ─────────────────────────────────────────────────────────────────────────────
# Convenience helpers
# ─────────────────────────────────────────────────────────────────────────────

def findings_from_dicts(raw: List[Dict[str, Any]]) -> List[Finding]:
    """Convert raw scanner output dicts to Finding objects."""
    result = []
    for d in raw:
        try:
            result.append(Finding(**d))
        except Exception as exc:
            logger.warning("Could not parse finding %s: %s", d, exc)
    return result
