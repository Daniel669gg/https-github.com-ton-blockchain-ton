"""
TythanAI — Patch Validator
Compares pre-patch and post-patch findings to verify vulnerability closure
and detect regressions. Integrates with taint analyzer for partial patch detection.
"""
from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

from backend.core.confidence import Finding

logger = logging.getLogger("tythanai.patch_validator")


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class FindingKey(BaseModel):
    """Normalized key for deduplication across scans."""

    rule_id: str
    file: str
    line_range: Tuple[int, int]  # (line-3, line+3) for approximate matching


class PatchStatus(str, Enum):
    FIXED = "fixed"
    REMAINING = "remaining"
    REGRESSED = "regressed"   # new HIGH/CRITICAL not in baseline
    PARTIAL = "partial"       # still reachable via different taint path


class FindingDelta(BaseModel):
    finding: Dict[str, Any]          # serialized Finding
    status: PatchStatus
    baseline_line: Optional[int] = None
    current_line: Optional[int] = None
    notes: str = ""


class PatchValidationReport(BaseModel):
    validation_id: str
    validated_at: str
    baseline_path: str
    current_path: str
    fixed: List[FindingDelta] = Field(default_factory=list)
    remaining: List[FindingDelta] = Field(default_factory=list)
    regressed: List[FindingDelta] = Field(default_factory=list)
    partial: List[FindingDelta] = Field(default_factory=list)
    fixed_count: int = 0
    remaining_count: int = 0
    regressed_count: int = 0
    partial_count: int = 0
    patch_effectiveness: float = 0.0   # fixed / (fixed + remaining + partial) * 100
    verdict: str = "PARTIAL"           # "APPROVED" | "REJECTED" | "PARTIAL"

    def to_markdown(self) -> str:
        lines = [
            f"# Patch Validation Report",
            f"",
            f"**Validation ID:** `{self.validation_id}`",
            f"**Validated At:** {self.validated_at}",
            f"**Baseline:** `{self.baseline_path}`",
            f"**Current:** `{self.current_path}`",
            f"",
            f"## Verdict: {self.verdict}",
            f"",
            f"| Status | Count |",
            f"|--------|-------|",
            f"| ✅ Fixed | {self.fixed_count} |",
            f"| ⚠️ Partial | {self.partial_count} |",
            f"| ❌ Remaining | {self.remaining_count} |",
            f"| 🔴 Regressed | {self.regressed_count} |",
            f"",
            f"**Patch Effectiveness:** {self.patch_effectiveness:.1f}%",
            f"",
        ]

        def _render_section(title: str, items: List[FindingDelta]) -> List[str]:
            if not items:
                return []
            section = [f"## {title}", ""]
            for delta in items:
                f = delta.finding
                rid = f.get("rule_id", "unknown")
                fpath = f.get("file", "unknown")
                line = delta.current_line or delta.baseline_line or f.get("line", 0)
                sev = f.get("severity", "UNKNOWN")
                desc = f.get("description", "")[:100]
                section.append(f"- **{rid}** `{fpath}:{line}` [{sev}]  ")
                section.append(f"  {desc}")
                if delta.notes:
                    section.append(f"  _{delta.notes}_")
                section.append("")
            return section

        lines += _render_section("Fixed Findings", self.fixed)
        lines += _render_section("Remaining Findings", self.remaining)
        lines += _render_section("Regressed Findings", self.regressed)
        lines += _render_section("Partially Fixed Findings", self.partial)

        return "\n".join(lines)

    def to_json(self) -> str:
        return self.model_dump_json(indent=2)

    def summary_line(self) -> str:
        return (
            f"✅ fixed {self.fixed_count} / "
            f"⚠️ partial {self.partial_count} / "
            f"❌ remaining {self.remaining_count} / "
            f"🔴 regressed {self.regressed_count}"
        )


# ---------------------------------------------------------------------------
# PatchValidator
# ---------------------------------------------------------------------------


class PatchValidator:
    """
    Compares baseline and post-patch findings to assess patch effectiveness.

    Workflow:
    1. Match baseline → current findings by (rule_id, file, line ± 5).
    2. Unmatched baseline → fixed.  Matched → remaining.
    3. New HIGH/CRITICAL in current without baseline match → regressed.
    4. If project_root given, run interprocedural taint to detect partial fixes.
    5. Compute patch_effectiveness and verdict.
    """

    def __init__(self, slack_notifier: Any = None) -> None:
        self._slack = slack_notifier

    # ── Key/match helpers ────────────────────────────────────────────────────

    @staticmethod
    def _normalize_path(p: str) -> str:
        """Normalize a file path for comparison (resolve symlinks/casing)."""
        try:
            return str(Path(p).resolve())
        except Exception:
            return os.path.normpath(p)

    def _normalize_finding(self, finding: Finding) -> FindingKey:
        line = finding.line
        return FindingKey(
            rule_id=finding.rule_id,
            file=self._normalize_path(finding.file),
            line_range=(max(0, line - 3), line + 3),
        )

    def _findings_match(self, a: Finding, b: Finding) -> bool:
        """Return True if two findings refer to the same vulnerability."""
        if a.rule_id != b.rule_id:
            return False
        if self._normalize_path(a.file) != self._normalize_path(b.file):
            return False
        return abs(a.line - b.line) <= 5

    # ── Core validation ──────────────────────────────────────────────────────

    def validate(
        self,
        baseline: List[Finding],
        current: List[Finding],
        project_root: Optional[Path] = None,
    ) -> PatchValidationReport:
        """
        Compare baseline vs current findings.

        Returns a :class:`PatchValidationReport` describing what was fixed,
        what remains, regressions, and partial fixes.
        """
        validation_id = str(uuid.uuid4())
        validated_at = datetime.now(timezone.utc).isoformat()

        fixed_deltas: List[FindingDelta] = []
        remaining_deltas: List[FindingDelta] = []
        regressed_deltas: List[FindingDelta] = []
        partial_deltas: List[FindingDelta] = []

        # Track which current findings have been matched
        matched_current_indices: set[int] = set()

        # Step 1 — classify each baseline finding (each current finding matched at most once)
        for b_finding in baseline:
            match_idx: Optional[int] = None
            for idx, c_finding in enumerate(current):
                if idx in matched_current_indices:
                    continue
                if self._findings_match(b_finding, c_finding):
                    match_idx = idx
                    matched_current_indices.add(idx)
                    break

            if match_idx is None:
                # Not found in current → fixed (tentatively)
                fixed_deltas.append(FindingDelta(
                    finding=b_finding.model_dump(),
                    status=PatchStatus.FIXED,
                    baseline_line=b_finding.line,
                    current_line=None,
                    notes="Finding absent from post-patch scan.",
                ))
            else:
                c_finding = current[match_idx]
                remaining_deltas.append(FindingDelta(
                    finding=c_finding.model_dump(),
                    status=PatchStatus.REMAINING,
                    baseline_line=b_finding.line,
                    current_line=c_finding.line,
                    notes="Finding still present after patch.",
                ))

        # Step 2 — detect regressions: new HIGH/CRITICAL not in baseline
        for idx, c_finding in enumerate(current):
            if idx in matched_current_indices:
                continue
            if c_finding.severity.upper() in ("HIGH", "CRITICAL"):
                # Check against all baseline findings (not just matched ones)
                in_baseline = any(self._findings_match(c_finding, b) for b in baseline)
                if not in_baseline:
                    regressed_deltas.append(FindingDelta(
                        finding=c_finding.model_dump(),
                        status=PatchStatus.REGRESSED,
                        baseline_line=None,
                        current_line=c_finding.line,
                        notes=f"New {c_finding.severity} finding introduced by patch.",
                    ))

        # Step 3 — partial fix detection via interprocedural taint
        if project_root is not None and fixed_deltas:
            try:
                from backend.analysis.interprocedural import analyze_project_taint  # type: ignore

                taint_findings = analyze_project_taint(str(project_root), max_depth=10)

                # Build a quick lookup: (file_norm, sink_line) → taint finding
                taint_lookup: Dict[Tuple[str, int], Any] = {}
                for tf in taint_findings:
                    key = (self._normalize_path(tf.sink_file), tf.sink_line)
                    taint_lookup[key] = tf

                promoted: List[FindingDelta] = []
                still_fixed: List[FindingDelta] = []

                for delta in fixed_deltas:
                    f = delta.finding
                    f_file = self._normalize_path(f.get("file", ""))
                    f_line = int(f.get("line", 0))

                    # Check if taint reaches the same location (± 5 lines)
                    reachable = False
                    for (tf_file, tf_line), _ in taint_lookup.items():
                        if tf_file == f_file and abs(tf_line - f_line) <= 5:
                            reachable = True
                            break

                    if reachable:
                        promoted.append(FindingDelta(
                            finding=delta.finding,
                            status=PatchStatus.PARTIAL,
                            baseline_line=delta.baseline_line,
                            current_line=delta.current_line,
                            notes=(
                                "Direct finding removed but location still reachable "
                                "via live interprocedural taint path."
                            ),
                        ))
                    else:
                        still_fixed.append(delta)

                fixed_deltas = still_fixed
                partial_deltas.extend(promoted)

            except ImportError:
                logger.debug(
                    "interprocedural module unavailable; skipping partial-fix detection"
                )
            except Exception as exc:
                logger.warning("Taint analysis for partial-fix detection failed: %s", exc)

        # Step 4 — counts and effectiveness
        fixed_count = len(fixed_deltas)
        remaining_count = len(remaining_deltas)
        regressed_count = len(regressed_deltas)
        partial_count = len(partial_deltas)

        denominator = max(1, fixed_count + remaining_count + partial_count)
        patch_effectiveness = fixed_count / denominator * 100.0

        # Step 5 — verdict
        if regressed_count > 0:
            verdict = "REJECTED"
        elif remaining_count == 0 and partial_count == 0:
            verdict = "APPROVED"
        else:
            verdict = "PARTIAL"

        report = PatchValidationReport(
            validation_id=validation_id,
            validated_at=validated_at,
            baseline_path=str(project_root) if project_root else "<in-memory>",
            current_path=str(project_root) if project_root else "<in-memory>",
            fixed=fixed_deltas,
            remaining=remaining_deltas,
            regressed=regressed_deltas,
            partial=partial_deltas,
            fixed_count=fixed_count,
            remaining_count=remaining_count,
            regressed_count=regressed_count,
            partial_count=partial_count,
            patch_effectiveness=round(patch_effectiveness, 2),
            verdict=verdict,
        )

        # Step 6 — Slack notification on regression
        if regressed_count > 0 and self._slack is not None:
            try:
                summary_text = (
                    f"*Patch Validation REJECTED* — {regressed_count} regression(s) detected.\n"
                    f"{report.summary_line()}"
                )
                self._slack.send_alert(
                    title="Patch Regression Detected",
                    message=summary_text,
                    severity="CRITICAL",
                )
            except Exception as exc:
                logger.warning("Slack notification failed: %s", exc)

        return report

    def validate_paths(
        self,
        baseline_findings_json: str,
        current_findings_json: str,
    ) -> PatchValidationReport:
        """Load findings from JSON strings and run validation."""
        try:
            baseline_raw: List[Dict[str, Any]] = json.loads(baseline_findings_json)
            current_raw: List[Dict[str, Any]] = json.loads(current_findings_json)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid findings JSON: {exc}") from exc

        baseline = [Finding(**d) for d in baseline_raw]
        current = [Finding(**d) for d in current_raw]
        return self.validate(baseline, current)

    def save_report(
        self,
        report: PatchValidationReport,
        output_dir: str = "/tmp/reports/patch_validation",
    ) -> Path:
        """Persist both JSON and Markdown versions of the report. Returns the JSON path."""
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        json_path = out / f"{report.validation_id}.json"
        md_path = out / f"{report.validation_id}.md"

        json_path.write_text(report.to_json(), encoding="utf-8")
        md_path.write_text(report.to_markdown(), encoding="utf-8")

        logger.info("Patch validation report saved: %s", json_path)
        return json_path


# ---------------------------------------------------------------------------
# Module-level convenience
# ---------------------------------------------------------------------------


def validate_patch(
    baseline: List[Finding],
    current: List[Finding],
) -> PatchValidationReport:
    """Convenience wrapper: compare baseline vs current findings."""
    return PatchValidator().validate(baseline, current)


# ---------------------------------------------------------------------------
# Self-test (python -m backend.core.patch_validator)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    # Baseline: 5 CRITICAL findings
    _baseline = [
        Finding(rule_id="sqli-001", file="app/views.py", line=10, severity="CRITICAL",
                description="SQL injection via request.GET"),
        Finding(rule_id="sqli-001", file="app/views.py", line=20, severity="CRITICAL",
                description="SQL injection via request.POST"),
        Finding(rule_id="xss-002", file="app/templates.py", line=5, severity="CRITICAL",
                description="Reflected XSS"),
        Finding(rule_id="cmd-003", file="app/utils.py", line=42, severity="CRITICAL",
                description="Command injection"),
        Finding(rule_id="path-004", file="app/files.py", line=99, severity="CRITICAL",
                description="Path traversal"),
    ]

    # Current: only baseline[0] remains, all others fixed
    _current = [
        Finding(rule_id="sqli-001", file="app/views.py", line=10, severity="CRITICAL",
                description="SQL injection via request.GET"),
    ]

    _report = validate_patch(_baseline, _current)
    print(_report.summary_line())
    assert _report.fixed_count == 4, f"Expected 4 fixed, got {_report.fixed_count}"
    assert _report.remaining_count == 1, f"Expected 1 remaining, got {_report.remaining_count}"
    assert _report.regressed_count == 0, f"Expected 0 regressed, got {_report.regressed_count}"
    assert _report.verdict == "PARTIAL", f"Expected PARTIAL, got {_report.verdict}"
    print("All assertions passed.")
    sys.exit(0)
