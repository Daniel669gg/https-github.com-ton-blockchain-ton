"""
backend/core/fp_reducer.py
False Positive Reduction Pipeline: multi-pass confidence scoring + exploitability analysis.

Applies a sequence of heuristic passes (TestFilePass, GeneratedFilePass, etc.) to each
Finding, accumulating confidence deltas, then suppresses findings that fall below the
configured minimum confidence threshold.
"""
from __future__ import annotations

import logging
from typing import Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

from backend.core.confidence import Finding

logger = logging.getLogger("tythanai.fp_reducer")

# ---------------------------------------------------------------------------
# Context model
# ---------------------------------------------------------------------------

class FPContext(BaseModel):
    """Contextual metadata about the file/function containing a finding."""

    file_content: str = ""
    is_test_file: bool = False
    is_generated: bool = False       # auto-generated file (migrations, __pycache__)
    is_vendor: bool = False
    framework: str = ""              # django/flask/fastapi/express/rails/...
    has_input_validation: bool = False
    has_auth_check: bool = False
    has_sanitization: bool = False
    call_stack_depth: int = 0
    reachable_from_entrypoint: bool = True
    cve_epss: float = 0.0
    is_kev: bool = False


# ---------------------------------------------------------------------------
# Base pass
# ---------------------------------------------------------------------------

class FPReducerPass:
    """
    Abstract base for a single FP-reduction heuristic pass.

    Subclasses must implement :py:meth:`apply`.  The method may mutate
    *finding* in-place and must return the (possibly mutated) finding together
    with a signed float confidence_delta.
    """

    name: str = "base"

    def apply(self, finding: Finding, ctx: FPContext) -> Tuple[Finding, float]:  # noqa: D102
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Concrete passes
# ---------------------------------------------------------------------------

_TEST_PATH_MARKERS = (
    "/test",
    "/tests/",
    "_test.py",
    "test_",
    "spec.",
    ".spec.",
    "__mocks__",
)


class TestFilePass(FPReducerPass):
    """Reduces confidence for findings in test / spec files."""

    name = "TestFilePass"

    def apply(self, finding: Finding, ctx: FPContext) -> Tuple[Finding, float]:
        is_test = ctx.is_test_file or any(
            marker in finding.file for marker in _TEST_PATH_MARKERS
        )
        if is_test:
            finding.is_test_file = True
            logger.debug(
                "[TestFilePass] test file detected: %s (rule=%s)",
                finding.file,
                finding.rule_id,
            )
            return finding, -0.3
        return finding, 0.0


_GENERATED_PATH_MARKERS = (
    "migrations/",
    "__pycache__",
    ".min.js",
    "vendor/",
    "node_modules/",
    ".pb.go",
    "_generated",
)


class GeneratedFilePass(FPReducerPass):
    """Reduces confidence for findings in auto-generated or vendored files."""

    name = "GeneratedFilePass"

    def apply(self, finding: Finding, ctx: FPContext) -> Tuple[Finding, float]:
        is_generated = ctx.is_generated or ctx.is_vendor or any(
            marker in finding.file for marker in _GENERATED_PATH_MARKERS
        )
        if is_generated:
            logger.debug(
                "[GeneratedFilePass] generated/vendor file: %s (rule=%s)",
                finding.file,
                finding.rule_id,
            )
            return finding, -0.4
        return finding, 0.0


_SANITIZATION_RULE_PREFIXES = ("TAINT", "XSS", "SQLI", "INJECTION")


class SanitizationContextPass(FPReducerPass):
    """
    Reduces confidence when the surrounding code already sanitises input and
    the finding is a taint-style rule.
    """

    name = "SanitizationContextPass"

    def apply(self, finding: Finding, ctx: FPContext) -> Tuple[Finding, float]:
        if ctx.has_sanitization and any(
            finding.rule_id.startswith(prefix) for prefix in _SANITIZATION_RULE_PREFIXES
        ):
            logger.debug(
                "[SanitizationContextPass] sanitization present for rule %s",
                finding.rule_id,
            )
            return finding, -0.2
        return finding, 0.0


_AUTH_CWE_IDS = {"CWE-306", "CWE-862", "CWE-863"}


class AuthContextPass(FPReducerPass):
    """
    Reduces confidence when an auth check is present and the finding is an
    access-control CWE.
    """

    name = "AuthContextPass"

    def apply(self, finding: Finding, ctx: FPContext) -> Tuple[Finding, float]:
        if ctx.has_auth_check and finding.cwe_id in _AUTH_CWE_IDS:
            logger.debug(
                "[AuthContextPass] auth check present for CWE %s in %s",
                finding.cwe_id,
                finding.file,
            )
            return finding, -0.2
        return finding, 0.0


class ExploitabilityPass(FPReducerPass):
    """
    Adjusts confidence based on real-world exploitability signals: KEV membership,
    EPSS score, and code-reachability.
    """

    name = "ExploitabilityPass"

    def apply(self, finding: Finding, ctx: FPContext) -> Tuple[Finding, float]:
        if ctx.is_kev:
            logger.debug(
                "[ExploitabilityPass] KEV finding boosted: %s", finding.rule_id
            )
            return finding, +0.15
        if ctx.cve_epss >= 0.5:
            return finding, +0.10
        if ctx.cve_epss >= 0.1:
            return finding, +0.05
        if not ctx.reachable_from_entrypoint:
            logger.debug(
                "[ExploitabilityPass] non-reachable finding penalised: %s in %s",
                finding.rule_id,
                finding.file,
            )
            return finding, -0.25
        return finding, 0.0


class SeverityConsistencyPass(FPReducerPass):
    """
    Enforces invariants that keep severity and confidence coherent.

    This pass is applied *after* all confidence deltas have been accumulated
    and the final clamped confidence has been written back to the finding.

    - CRITICAL findings: if final confidence < 0.6, bump it to 0.6 and clear
      any suppression flag that the min_confidence check may have set.
    - LOW findings: if final confidence < 0.3, mark ``is_suppressed = True``.

    Because it is applied post-accumulation the ``confidence_delta`` return
    value is always 0.0 (the pass mutates ``finding.confidence`` directly).
    """

    name = "SeverityConsistencyPass"

    def apply(self, finding: Finding, ctx: FPContext) -> Tuple[Finding, float]:
        # Note: this method is called by the pipeline AFTER the delta has been
        # committed to finding.confidence, so finding.confidence reflects the
        # post-delta clamped value.
        if finding.severity == "CRITICAL" and finding.confidence < 0.6:
            logger.debug(
                "[SeverityConsistencyPass] bumping CRITICAL confidence %.3f → 0.6 for %s",
                finding.confidence,
                finding.file,
            )
            finding.confidence = 0.6
            # Un-suppress: CRITICAL findings must not be suppressed by the
            # pipeline's min_confidence check.
            finding.is_suppressed = False
        elif finding.severity == "LOW" and finding.confidence < 0.3:
            logger.debug(
                "[SeverityConsistencyPass] suppressing LOW-confidence finding %s in %s",
                finding.rule_id,
                finding.file,
            )
            finding.is_suppressed = True
        return finding, 0.0


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

class FPReductionPipeline:
    """
    Runs all :py:class:`FPReducerPass` instances in sequence for every
    :py:class:`Finding`, accumulates confidence deltas, and marks findings
    as suppressed when the final confidence falls below *min_confidence*.

    Pipeline execution order:

    1. **Delta passes** — ``TestFilePass``, ``GeneratedFilePass``,
       ``SanitizationContextPass``, ``AuthContextPass``, ``ExploitabilityPass``.
       Each returns a signed ``confidence_delta``; all deltas are summed and
       applied to the finding's original confidence, then clamped to [0, 1].

    2. **min_confidence check** — if the clamped confidence is below
       ``min_confidence``, ``is_suppressed`` is set to ``True``.

    3. **SeverityConsistencyPass** — applied *after* the min_confidence check
       so it can see (and correct) the committed confidence value:
       - CRITICAL findings below 0.6 are bumped to 0.6 and un-suppressed.
       - LOW findings below 0.3 are suppressed.

    Suppressed findings are kept in the returned list so callers can log or
    report them; callers that want only actionable findings should filter on
    ``finding.is_suppressed == False``.
    """

    def __init__(self, min_confidence: float = 0.5) -> None:
        self.min_confidence = min_confidence
        # Ordered delta passes (run first, their deltas accumulate)
        self._delta_passes: List[FPReducerPass] = [
            TestFilePass(),
            GeneratedFilePass(),
            SanitizationContextPass(),
            AuthContextPass(),
            ExploitabilityPass(),
        ]
        # Post-delta enforcement pass (runs after confidence is committed)
        self._consistency_pass = SeverityConsistencyPass()
        # Public attribute that exposes the full ordered list for introspection
        self.passes: List[FPReducerPass] = self._delta_passes + [self._consistency_pass]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def reduce(
        self,
        findings: List[Finding],
        contexts: Dict[str, FPContext],
    ) -> List[Finding]:
        """
        Apply the full pass pipeline to *findings*.

        *contexts* is a mapping from file path to :py:class:`FPContext`.
        Missing entries default to ``FPContext()`` (no special context).

        Findings are mutated in-place; the same list is returned.
        """
        for finding in findings:
            ctx = contexts.get(finding.file, FPContext())
            total_delta = 0.0

            # Phase 1: accumulate confidence deltas
            for fp_pass in self._delta_passes:
                try:
                    finding, delta = fp_pass.apply(finding, ctx)
                    total_delta += delta
                except Exception as exc:  # noqa: BLE001
                    logger.exception(
                        "FPReducerPass %s raised an exception for %s:%d — skipping: %s",
                        fp_pass.name,
                        finding.file,
                        finding.line,
                        exc,
                    )

            # Phase 2: commit the accumulated delta and clamp
            raw_confidence = finding.confidence + total_delta
            final_confidence = max(0.0, min(1.0, raw_confidence))
            finding.confidence = round(final_confidence, 4)

            # Phase 3: min_confidence suppression check
            if finding.confidence < self.min_confidence:
                finding.is_suppressed = True

            # Phase 4: severity-consistency enforcement (post-delta)
            try:
                finding, _ = self._consistency_pass.apply(finding, ctx)
            except Exception as exc:  # noqa: BLE001
                logger.exception(
                    "SeverityConsistencyPass raised for %s:%d — skipping: %s",
                    finding.file,
                    finding.line,
                    exc,
                )

            logger.debug(
                "reduce: %s:%d rule=%s conf=%.4f suppressed=%s",
                finding.file,
                finding.line,
                finding.rule_id,
                finding.confidence,
                finding.is_suppressed,
            )

        return findings

    def get_stats(self, findings: List[Finding]) -> dict:
        """
        Aggregate statistics over *findings*.

        Returns::

            {
                "total": int,
                "suppressed": int,
                "by_severity": {"CRITICAL": n, "HIGH": n, "MEDIUM": n, "LOW": n, "INFO": n},
                "suppression_rate": float,
            }
        """
        severity_order = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        by_severity: Dict[str, int] = {s: 0 for s in severity_order}
        suppressed = 0

        for f in findings:
            if f.is_suppressed:
                suppressed += 1
            sev = f.severity.upper()
            if sev in by_severity:
                by_severity[sev] += 1
            # unknown severity buckets are silently ignored

        total = len(findings)
        suppression_rate = round(suppressed / total, 4) if total > 0 else 0.0

        return {
            "total": total,
            "suppressed": suppressed,
            "by_severity": by_severity,
            "suppression_rate": suppression_rate,
        }


# ---------------------------------------------------------------------------
# Module-level convenience
# ---------------------------------------------------------------------------

def reduce_false_positives(
    findings: List[Finding],
    contexts: Optional[Dict[str, FPContext]] = None,
    min_confidence: float = 0.5,
) -> List[Finding]:
    """
    Convenience wrapper: construct a :py:class:`FPReductionPipeline` and run it.

    Returns the same list of findings (mutated), including suppressed ones.
    """
    pipeline = FPReductionPipeline(min_confidence)
    return pipeline.reduce(findings, contexts or {})
