"""
Ghost Security Platform v13 — Advanced False-Positive Reducer v2
Heuristic-based FP reduction and composite risk scoring.
No ML model required — pure rule-based signal processing.
"""
from __future__ import annotations

import re
import logging
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Directories that are always suppressed
_SUPPRESSED_DIRS = re.compile(
    r"(^|[\\/])(vendor|node_modules|venv|\.venv|dist|build|__pycache__)[\\/]",
    re.IGNORECASE,
)

# Test-file path patterns
_TEST_PATH_RE = re.compile(
    r"([\\/]|^)(test_|_test\.|\.spec\.|spec_)",
    re.IGNORECASE,
)

# Suppression comment patterns in surrounding code
_SUPPRESS_COMMENT_RE = re.compile(
    r"#\s*(nosec|noqa|ghost:\s*ignore)",
    re.IGNORECASE,
)

# Placeholder / dummy secret values
_PLACEHOLDER_VALUES = frozenset(
    [
        "changeme",
        "example",
        "yoursecrethere",
        "your_secret_here",
        "xxx",
        "zzz",
        "placeholder",
        "secret",
        "password",
        "test",
        "demo",
        "sample",
        "dummy",
        "fake",
        "insert_here",
        "replace_me",
        "your_api_key",
        "your_token",
        "your_key",
    ]
)

# Pattern matching assignment of placeholder test values
_TEST_VALUE_RE = re.compile(
    r'(?:password|secret|token|api_?key|apikey|passwd|pwd)\s*=\s*["\']'
    r"(?:changeme|example|yoursecrethere|your[_-]secret[_-]here"
    r"|xxx+|zzz+|placeholder|test|demo|sample|dummy|fake|insert_here"
    r"|replace_me|your[_-]api[_-]key|your[_-]token|your[_-]key|password|secret)[\"']",
    re.IGNORECASE,
)

# Severity → weight
_SEV_WEIGHT: dict[str, float] = {
    "CRITICAL": 1.0,
    "HIGH": 0.8,
    "MEDIUM": 0.5,
    "LOW": 0.2,
    "INFO": 0.05,
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _file_path(finding: dict) -> str:
    return str(finding.get("file") or finding.get("path") or finding.get("filename") or "")


def _line_number(finding: dict) -> int:
    try:
        return int(finding.get("line") or finding.get("line_number") or 0)
    except (TypeError, ValueError):
        return 0


def _context(finding: dict) -> str:
    """Return any surrounding code context or code snippet."""
    return str(
        finding.get("context")
        or finding.get("code_snippet")
        or finding.get("evidence")
        or finding.get("snippet")
        or ""
    )


def _get_value(finding: dict) -> str:
    """Return the detected value if present (for secret checks)."""
    return str(finding.get("value") or finding.get("match") or finding.get("secret_value") or "")


def _is_auth_bypass_rule(finding: dict) -> bool:
    rule = str(finding.get("rule_id") or finding.get("id") or finding.get("type") or "").lower()
    return any(kw in rule for kw in ("auth_bypass", "authbypass", "authentication_bypass", "bypass_auth"))


# ---------------------------------------------------------------------------
# FP Heuristics
# ---------------------------------------------------------------------------


def _check_test_file_path(finding: dict) -> float:
    """If the finding is in a test file → reduce confidence by 0.3."""
    fp = _file_path(finding)
    if _TEST_PATH_RE.search(fp):
        return 0.3
    return 0.0


def _check_suppression_comment(finding: dict) -> bool:
    """Return True if surrounding code contains a suppression comment."""
    ctx = _context(finding)
    if _SUPPRESS_COMMENT_RE.search(ctx):
        return True
    # Also check a dedicated field some scanners provide
    suppress_field = str(finding.get("suppress") or finding.get("suppressed") or "")
    if suppress_field.lower() in ("true", "1", "yes"):
        return True
    return False


def _check_test_value(finding: dict) -> float:
    """If line contains password = 'test' style assignment → reduce confidence by 0.25."""
    ctx = _context(finding)
    value = _get_value(finding)

    if _TEST_VALUE_RE.search(ctx):
        return 0.25
    # Check if the detected value itself is a placeholder
    if value.lower().strip("\"'") in _PLACEHOLDER_VALUES:
        return 0.3
    return 0.0


def _check_vendored_path(finding: dict) -> bool:
    """Suppress findings in vendor/node_modules/venv/dist directories."""
    return bool(_SUPPRESSED_DIRS.search(_file_path(finding)))


def _check_auth_bypass_test_file(finding: dict) -> bool:
    """Auth bypass rules in test files → suppress."""
    if not _is_auth_bypass_rule(finding):
        return False
    fp = _file_path(finding)
    # Match test_* or *_test.py
    basename = fp.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    if re.match(r"test_.+\.py$", basename, re.IGNORECASE):
        return True
    if re.match(r".+_test\.py$", basename, re.IGNORECASE):
        return True
    return False


def _check_placeholder_secret(finding: dict) -> bool:
    """Hardcoded secrets whose value is a known placeholder → suppress."""
    rule = str(finding.get("rule_id") or finding.get("id") or finding.get("type") or "").lower()
    if not any(kw in rule for kw in ("secret", "hardcoded", "credential", "token", "password", "api_key")):
        return False
    value = _get_value(finding).lower().strip("\"' \t")
    if value in _PLACEHOLDER_VALUES:
        return True
    # Pattern-based check
    ctx = _context(finding)
    # Template placeholders like ${VAR}, <PLACEHOLDER>
    if re.search(r"(\$\{[^}]+\}|<[A-Z_]+>)", ctx):
        return True
    return False


# ---------------------------------------------------------------------------
# FPReducerV2
# ---------------------------------------------------------------------------


class FPReducerV2:
    """
    Advanced false-positive reducer for Ghost Security v13.

    Applies a cascade of heuristics to each finding, adjusting confidence
    and suppressing clear false positives before the results reach users.
    """

    def __init__(self, min_confidence: float = 0.3) -> None:
        """
        Args:
            min_confidence: Findings whose final confidence falls below this
                            threshold are removed from the output. Default 0.3.
        """
        self.min_confidence = min_confidence

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def reduce(self, findings: list) -> list:
        """
        Filter and re-score a list of raw findings.

        Steps:
        1.  Apply per-heuristic suppression / confidence adjustments.
        2.  Deduplicate findings that fire on the same line from multiple
            patterns (same rule + same file + same line).
        3.  Remove findings whose adjusted confidence is below min_confidence.

        Returns a new list; the originals are not mutated.
        """
        if not findings:
            return []

        processed: list[dict] = []

        for raw in findings:
            finding = dict(raw)  # shallow copy; never mutate callers' data

            # ── Hard suppression checks ─────────────────────────────────
            if _check_vendored_path(finding):
                logger.debug("FP suppressed (vendored path): %s", _file_path(finding))
                continue

            if _check_suppression_comment(finding):
                logger.debug("FP suppressed (nosec/noqa/ghost:ignore): %s", _file_path(finding))
                continue

            if _check_auth_bypass_test_file(finding):
                logger.debug("FP suppressed (auth_bypass in test file): %s", _file_path(finding))
                continue

            if _check_placeholder_secret(finding):
                logger.debug("FP suppressed (placeholder secret): %s", _file_path(finding))
                continue

            # ── Confidence adjustments ──────────────────────────────────
            current_confidence: float = float(finding.get("confidence", 0.8))

            test_file_penalty = _check_test_file_path(finding)
            if test_file_penalty > 0:
                current_confidence -= test_file_penalty
                finding["_fp_reason"] = finding.get("_fp_reason", "") + " test_file_path_penalty"

            test_value_penalty = _check_test_value(finding)
            if test_value_penalty > 0:
                current_confidence -= test_value_penalty
                finding["_fp_reason"] = finding.get("_fp_reason", "") + " test_value_penalty"

            # Clamp
            current_confidence = max(0.0, min(1.0, current_confidence))
            finding["confidence"] = round(current_confidence, 4)

            # ── Risk score ──────────────────────────────────────────────
            finding["risk_score"] = self.calculate_risk_score(finding)

            # ── Below threshold → drop ──────────────────────────────────
            if current_confidence < self.min_confidence:
                logger.debug(
                    "FP dropped (low confidence %.3f): %s:%s",
                    current_confidence,
                    _file_path(finding),
                    _line_number(finding),
                )
                continue

            processed.append(finding)

        # ── Intra-pattern deduplication (same rule + file + line) ───────
        deduplicated = self._dedup_same_rule_same_line(processed)

        return deduplicated

    def calculate_risk_score(self, finding: dict) -> float:
        """
        Composite risk score in [0.0, 1.0].

        Formula:  severity_weight × confidence × (1 − fp_probability)

        fp_probability is estimated from the heuristic penalties already
        applied to confidence, mapped back to a [0, 1] probability.
        """
        severity = str(finding.get("severity") or "MEDIUM").upper()
        severity_weight = _SEV_WEIGHT.get(severity, 0.5)

        confidence = float(finding.get("confidence", 0.8))

        # Estimate FP probability from the heuristic penalties
        # If confidence is very high, FP probability is near zero.
        # Use a simple monotone mapping: fp_prob = 1 - confidence
        fp_probability = 1.0 - confidence

        risk = severity_weight * confidence * (1.0 - fp_probability)
        return round(max(0.0, min(1.0, risk)), 4)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _dedup_same_rule_same_line(findings: list) -> list:
        """
        Remove duplicates where the same rule fires on the same file+line
        from multiple independent patterns.  Keep the highest-confidence copy.
        """
        # Group by (rule_id, file, line)
        groups: dict[tuple, list[dict]] = {}
        for f in findings:
            rule = str(f.get("rule_id") or f.get("id") or f.get("type") or "")
            key = (rule, _file_path(f), _line_number(f))
            groups.setdefault(key, []).append(f)

        result: list[dict] = []
        for group in groups.values():
            if len(group) == 1:
                result.append(group[0])
            else:
                # Keep highest confidence
                best = max(group, key=lambda x: float(x.get("confidence", 0.0)))
                result.append(best)

        return result
