"""
Ghost Security Platform v13 — Duplicate Detector
Deduplicates findings across scanner output using file, line, and CWE identity,
plus merges findings where the same rule fires within a 5-line window.
"""
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


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


def _cwe(finding: dict) -> str:
    """Normalise CWE to a string like 'CWE-89'."""
    raw = str(finding.get("cwe") or finding.get("cwe_id") or finding.get("CWE") or "")
    raw = raw.strip().upper()
    if raw and not raw.startswith("CWE-"):
        raw = "CWE-" + raw.lstrip("CWE").lstrip("-")
    return raw


def _rule_id(finding: dict) -> str:
    return str(finding.get("rule_id") or finding.get("id") or finding.get("type") or "")


def _confidence(finding: dict) -> float:
    try:
        return float(finding.get("confidence", 0.0))
    except (TypeError, ValueError):
        return 0.0


# ---------------------------------------------------------------------------
# DuplicateDetector
# ---------------------------------------------------------------------------


class DuplicateDetector:
    """
    Deduplicates security findings using two complementary strategies:

    1.  **Exact deduplication** — two findings are considered duplicates when
        they share the same ``file``, the same ``cwe``, and their line numbers
        differ by at most ``line_tolerance`` (default 2).  Among a group of
        duplicates the finding with the highest confidence is kept.

    2.  **Window merge** — findings from the *same rule* on the *same file*
        whose line numbers lie within ``window`` (default 5) of each other are
        collapsed into a single representative (again, the highest-confidence
        one is retained).
    """

    def __init__(self, line_tolerance: int = 2, window: int = 5) -> None:
        """
        Args:
            line_tolerance: Maximum line-number difference still counted as
                            the same location for CWE-based deduplication.
            window:         Line-number range for same-rule window merging.
        """
        self.line_tolerance = line_tolerance
        self.window = window

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def deduplicate(self, findings: list) -> list:
        """
        Return a deduplicated list of findings.

        The input list is not mutated.  Each returned finding is a shallow
        copy of the original with an optional ``_dedup_count`` field added
        when multiple findings were merged.
        """
        if not findings:
            return []

        # Step 1 – CWE-based deduplication (same file + line ±2 + same CWE)
        after_cwe_dedup = self._dedup_by_cwe(findings)

        # Step 2 – Window merge (same rule + same file, within 5 lines)
        after_window_merge = self._merge_by_rule_window(after_cwe_dedup)

        return after_window_merge

    # ------------------------------------------------------------------
    # Step 1 — CWE deduplication
    # ------------------------------------------------------------------

    def _dedup_by_cwe(self, findings: list) -> list:
        """
        Group findings that share (file, cwe) and whose lines are within
        ``line_tolerance`` of each other.  Keep the highest-confidence member.
        """
        # Build groups using a union-find-like greedy approach:
        # iterate in input order, place each finding into an existing group
        # when it matches, otherwise start a new group.
        groups: list[list[dict]] = []

        for finding in findings:
            fp = _file_path(finding)
            c = _cwe(finding)
            ln = _line_number(finding)
            placed = False

            for group in groups:
                rep = group[0]  # representative (first member)
                if (
                    _file_path(rep) == fp
                    and _cwe(rep) == c
                    and abs(_line_number(rep) - ln) <= self.line_tolerance
                ):
                    group.append(finding)
                    placed = True
                    break

            if not placed:
                groups.append([finding])

        result: list[dict] = []
        for group in groups:
            best = max(group, key=_confidence)
            out = dict(best)
            if len(group) > 1:
                out["_dedup_count"] = len(group)
                logger.debug(
                    "CWE-dedup merged %d findings at %s:%s (CWE=%s)",
                    len(group),
                    _file_path(best),
                    _line_number(best),
                    _cwe(best),
                )
            result.append(out)

        return result

    # ------------------------------------------------------------------
    # Step 2 — Rule window merge
    # ------------------------------------------------------------------

    def _merge_by_rule_window(self, findings: list) -> list:
        """
        For the same rule on the same file, collapse occurrences whose
        line numbers lie within ``window`` lines of each other.
        Keep the highest-confidence representative.
        """
        # Sort by (file, rule, line) for efficient windowing
        sorted_findings = sorted(
            findings,
            key=lambda f: (_file_path(f), _rule_id(f), _line_number(f)),
        )

        groups: list[list[dict]] = []

        for finding in sorted_findings:
            fp = _file_path(finding)
            rule = _rule_id(finding)
            ln = _line_number(finding)
            placed = False

            for group in groups:
                rep = group[0]
                if (
                    _file_path(rep) == fp
                    and _rule_id(rep) == rule
                    # All lines in the group are within window of each other;
                    # compare against the representative (first / lowest line).
                    and abs(_line_number(rep) - ln) <= self.window
                ):
                    group.append(finding)
                    placed = True
                    break

            if not placed:
                groups.append([finding])

        result: list[dict] = []
        for group in groups:
            best = max(group, key=_confidence)
            out = dict(best)
            if len(group) > 1:
                out["_window_merged_count"] = len(group)
                logger.debug(
                    "Window-merged %d rule=%s occurrences in %s",
                    len(group),
                    _rule_id(best),
                    _file_path(best),
                )
            result.append(out)

        return result
