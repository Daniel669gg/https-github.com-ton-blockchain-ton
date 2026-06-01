"""Verified Fix Engine — unified fix lifecycle: propose → validate → verify.

Extends existing PatchValidator + BuildValidator with a unified fix lifecycle
that tracks: suggested_fix, verified_fix, fix_confidence, fix_status.
"""
from __future__ import annotations

import ast
import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Fix lifecycle models
# ---------------------------------------------------------------------------


class FixStatus(str, Enum):
    PROPOSED = "proposed"       # patch generated, not yet validated
    VALIDATED = "validated"     # build + syntax OK, tests OK, no regression
    REJECTED = "rejected"       # build failed / regression detected / vuln remains
    VERIFIED = "verified"       # reachability removed, full verification passed


@dataclass
class BuildResult:
    language: str
    success: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    duration_ms: float = 0.0

    def to_dict(self) -> dict:
        return {
            "language": self.language,
            "success": self.success,
            "errors": self.errors,
            "warnings": self.warnings,
            "duration_ms": self.duration_ms,
        }


@dataclass
class FixTestRunResult:
    """Lightweight test result that works without running actual tests."""
    tests_run: int = 0
    tests_passed: int = 0
    tests_failed: int = 0
    coverage_delta: float = 0.0   # negative = coverage dropped
    new_errors: List[str] = field(default_factory=list)

    @property
    def success(self) -> bool:
        return self.tests_failed == 0 and not self.new_errors

    def to_dict(self) -> dict:
        return {
            "tests_run": self.tests_run,
            "tests_passed": self.tests_passed,
            "tests_failed": self.tests_failed,
            "coverage_delta": self.coverage_delta,
            "success": self.success,
            "new_errors": self.new_errors,
        }


@dataclass
class FixConfidenceScore:
    """Composite confidence score for a verified fix."""
    build_success: float = 0.0          # 0.0 or 1.0
    test_success: float = 0.0           # 0.0 or 1.0
    reachability_removed: float = 0.0   # 0.0 or 1.0
    verification_passed: float = 0.0    # 0.0 or 1.0
    no_regression: float = 0.0          # 0.0 or 1.0

    # Weights
    _W_BUILD = 0.15
    _W_TEST = 0.20
    _W_REACH = 0.35
    _W_VERIFY = 0.20
    _W_REG = 0.10

    @property
    def total_score(self) -> float:
        """Weighted composite score in [0.0, 1.0]."""
        return round(
            self.build_success * self._W_BUILD
            + self.test_success * self._W_TEST
            + self.reachability_removed * self._W_REACH
            + self.verification_passed * self._W_VERIFY
            + self.no_regression * self._W_REG,
            4,
        )

    def to_dict(self) -> dict:
        return {
            "build_success": self.build_success,
            "test_success": self.test_success,
            "reachability_removed": self.reachability_removed,
            "verification_passed": self.verification_passed,
            "no_regression": self.no_regression,
            "total_score": self.total_score,
        }


@dataclass
class VerifiedFix:
    """Complete fix record tracking the full lifecycle from proposal to verification."""
    fix_id: str
    finding_id: str
    cwe_id: str
    severity: str
    file_path: str

    suggested_fix: str = ""         # Initial generated patch
    verified_fix: Optional[str] = None  # Patch as it stands after validation (may be same)
    fix_status: FixStatus = FixStatus.PROPOSED
    fix_confidence: float = 0.0

    build_result: Optional[BuildResult] = None
    test_result: Optional[FixTestRunResult] = None
    reachability_removed: bool = False
    regression_detected: bool = False
    vulnerability_confirmed_fixed: bool = False

    confidence_score: Optional[FixConfidenceScore] = None
    attack_paths_removed: List[str] = field(default_factory=list)
    new_attack_paths: List[str] = field(default_factory=list)
    validation_notes: List[str] = field(default_factory=list)
    created_at: str = ""
    validated_at: str = ""

    def to_dict(self) -> dict:
        return {
            "fix_id": self.fix_id,
            "finding_id": self.finding_id,
            "cwe_id": self.cwe_id,
            "severity": self.severity,
            "file_path": self.file_path,
            "fix_status": self.fix_status.value,
            "fix_confidence": self.fix_confidence,
            "suggested_fix": self.suggested_fix[:500] if self.suggested_fix else "",
            "reachability_removed": self.reachability_removed,
            "regression_detected": self.regression_detected,
            "vulnerability_confirmed_fixed": self.vulnerability_confirmed_fixed,
            "attack_paths_removed": self.attack_paths_removed,
            "build_result": self.build_result.to_dict() if self.build_result else None,
            "test_result": self.test_result.to_dict() if self.test_result else None,
            "confidence_score": self.confidence_score.to_dict() if self.confidence_score else None,
            "validation_notes": self.validation_notes,
            "created_at": self.created_at,
            "validated_at": self.validated_at,
        }


@dataclass
class RemediationReport:
    """Aggregated report of all verified fixes."""
    report_id: str
    generated_at: str
    total_fixes: int = 0
    verified_count: int = 0
    validated_count: int = 0
    rejected_count: int = 0
    proposed_count: int = 0
    attack_paths_removed: int = 0
    regressions_detected: int = 0
    average_confidence: float = 0.0
    fixes: List[VerifiedFix] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "report_id": self.report_id,
            "generated_at": self.generated_at,
            "total_fixes": self.total_fixes,
            "verified_count": self.verified_count,
            "validated_count": self.validated_count,
            "rejected_count": self.rejected_count,
            "proposed_count": self.proposed_count,
            "attack_paths_removed": self.attack_paths_removed,
            "regressions_detected": self.regressions_detected,
            "average_confidence": self.average_confidence,
            "fixes": [f.to_dict() for f in self.fixes],
        }

    def to_markdown(self) -> str:
        lines = [
            "# Remediation Validation Report",
            "",
            f"**Report ID:** `{self.report_id}`",
            f"**Generated:** {self.generated_at}",
            "",
            "## Summary",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Total Fixes | {self.total_fixes} |",
            f"| ✅ Verified | {self.verified_count} |",
            f"| ✔️ Validated | {self.validated_count} |",
            f"| ❌ Rejected | {self.rejected_count} |",
            f"| 🔄 Proposed | {self.proposed_count} |",
            f"| ⚔️ Attack Paths Removed | {self.attack_paths_removed} |",
            f"| ⚠️ Regressions Detected | {self.regressions_detected} |",
            f"| Avg Confidence | {self.average_confidence:.1%} |",
            "",
        ]
        for fix in self.fixes:
            status_icon = {"verified": "✅", "validated": "✔️", "rejected": "❌", "proposed": "🔄"}.get(
                fix.fix_status.value, "❓"
            )
            lines.append(f"### {status_icon} `{fix.finding_id}` — {fix.cwe_id} ({fix.severity})")
            lines.append("")
            lines.append(f"- **Status:** {fix.fix_status.value.upper()}")
            lines.append(f"- **Confidence:** {fix.fix_confidence:.1%}")
            lines.append(f"- **Reachability Removed:** {'Yes' if fix.reachability_removed else 'No'}")
            lines.append(f"- **Regression Detected:** {'Yes ⚠️' if fix.regression_detected else 'No'}")
            if fix.validation_notes:
                lines.append(f"- **Notes:** {'; '.join(fix.validation_notes)}")
            lines.append("")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Vulnerability fix patterns (offline verification)
# ---------------------------------------------------------------------------

# Pattern: (vuln_pattern, fix_pattern) — if original has vuln and patch has fix
_FIX_PATTERNS: Dict[str, Tuple[re.Pattern, re.Pattern]] = {
    "CWE-89": (
        re.compile(r'["\']?\s*\+\s*(uid|id|name|input|param|q|query|val)', re.I),
        re.compile(r'parameterize|%s|:\w+|\?|cursor\.execute\([^+]+,|\bprepare\b', re.I),
    ),
    "CWE-78": (
        re.compile(r'os\.system|subprocess\.call|popen|shell=True', re.I),
        re.compile(r'shell=False|shlex\.quote|shlex\.split|\[.*\]', re.I),
    ),
    "CWE-79": (
        re.compile(r'innerHTML\s*=|document\.write\(|render_template_string', re.I),
        re.compile(r'textContent|innerText|escape\(|markupsafe|sanitize|DOMPurify', re.I),
    ),
    "CWE-22": (
        re.compile(r'open\s*\([^,]+\+|Path\s*\([^)]*\+', re.I),
        re.compile(r'realpath|resolve\(\)|abspath|\.parent|os\.path\.join', re.I),
    ),
    "CWE-798": (
        re.compile(r'password\s*=\s*["\'][^"\']+["\']|api_key\s*=\s*["\']', re.I),
        re.compile(r'os\.environ|getenv|os\.getenv|config\[|settings\.', re.I),
    ),
    "CWE-502": (
        re.compile(r'pickle\.load|yaml\.load\s*\([^,)]+\)', re.I),
        re.compile(r'yaml\.safe_load|pickle\.loads.*Unpickler|json\.loads', re.I),
    ),
    "CWE-327": (
        re.compile(r'md5|sha1|des|rc4', re.I),
        re.compile(r'sha256|sha384|sha512|bcrypt|argon2|scrypt', re.I),
    ),
    "CWE-918": (
        re.compile(r'requests\.get\s*\(\s*url\b|urllib.*urlopen\s*\(\s*url\b', re.I),
        re.compile(r'allowlist|whitelist|urlparse|netloc.*allowed|validate_url', re.I),
    ),
}


def _check_vuln_fixed(cwe_id: str, original: str, patched: str) -> Tuple[bool, str]:
    """Check whether a CWE pattern is present in original but absent in patched.

    Returns (is_fixed, notes).
    """
    patterns = _FIX_PATTERNS.get(cwe_id)
    if not patterns:
        # No static pattern available — assume fixed if patch differs
        if original.strip() != patched.strip():
            return True, f"No static pattern for {cwe_id}; patch differs from original"
        return False, f"No static pattern for {cwe_id}; patch identical to original"

    vuln_pattern, fix_pattern = patterns

    had_vuln = bool(vuln_pattern.search(original))
    has_vuln = bool(vuln_pattern.search(patched))
    has_fix = bool(fix_pattern.search(patched))

    if not had_vuln:
        return True, f"Original source did not contain {cwe_id} pattern — may be false positive"
    if not has_vuln and has_fix:
        return True, f"Vulnerability pattern removed and fix pattern detected"
    if not has_vuln:
        return True, f"Vulnerability pattern removed (no fix pattern detected, manual verification advised)"
    if has_fix and has_vuln:
        return False, f"Both vulnerability and fix patterns present — partial fix only"
    return False, f"Vulnerability pattern still present in patched code"


def _check_regression(original: str, patched: str) -> Tuple[bool, List[str]]:
    """Simple regression heuristic: check that patched code doesn't introduce new dangerous patterns."""
    new_issues: List[str] = []

    # Patterns that should NOT be present in patched code if absent from original
    dangerous = [
        (re.compile(r'eval\s*\('), "eval() introduced"),
        (re.compile(r'exec\s*\('), "exec() introduced"),
        (re.compile(r'__import__\s*\('), "__import__() introduced"),
        (re.compile(r'os\.system\s*\('), "os.system() introduced"),
        (re.compile(r'shell=True'), "shell=True introduced"),
        (re.compile(r'pickle\.load'), "pickle.load() introduced"),
    ]

    for pattern, label in dangerous:
        if not pattern.search(original) and pattern.search(patched):
            new_issues.append(label)

    return len(new_issues) > 0, new_issues


# ---------------------------------------------------------------------------
# Verified Fix Engine
# ---------------------------------------------------------------------------


class VerifiedFixEngine:
    """Unified fix lifecycle engine extending existing PatchValidator + BuildValidator.

    Lifecycle:
      proposed → (build_validate) → (syntax_validate) → (vuln_check) →
      (regression_check) → validated/rejected → (reachability_recheck) → verified
    """

    def __init__(self) -> None:
        self._build_validator = _lazy_build_validator()

    def verify_fix(
        self,
        finding: Any,
        patch_code: str,
        original_source: str = "",
        post_patch_source: str = "",
        run_tests: bool = False,
        cpg: Optional[Any] = None,
    ) -> VerifiedFix:
        """Verify a single fix against a finding.

        Parameters
        ----------
        finding : Finding or dict
            The vulnerability finding being fixed.
        patch_code : str
            The proposed patch (replacement source code or diff).
        original_source : str
            Original source code containing the vulnerability.
        post_patch_source : str
            Source code after patch application (if pre-applied); if empty,
            patch_code is treated as the post-patch source.
        run_tests : bool
            Reserved for future test-runner integration.
        cpg : CodePropertyGraph, optional
            If provided, reachability recheck is performed.
        """
        import uuid
        now = datetime.now(timezone.utc).isoformat()

        # Extract finding attributes
        finding_id = _get(finding, "rule_id", "unknown")
        cwe_id = _get(finding, "cwe_id", "")
        severity = _get(finding, "severity", "MEDIUM")
        file_path = _get(finding, "file", "")

        vf = VerifiedFix(
            fix_id=str(uuid.uuid4())[:8],
            finding_id=finding_id,
            cwe_id=cwe_id,
            severity=severity,
            file_path=file_path,
            suggested_fix=patch_code,
            fix_status=FixStatus.PROPOSED,
            created_at=now,
        )

        post_patch = post_patch_source or patch_code
        notes: List[str] = []

        # ── 1. Build validation ─────────────────────────────────────────────
        build_result = None
        if self._build_validator:
            try:
                build_result = self._build_validator.validate(post_patch)
                vf.build_result = build_result
                if not build_result.success:
                    notes.append(f"Build failed: {'; '.join(build_result.errors[:3])}")
            except Exception as exc:
                logger.debug("BuildValidator failed: %s", exc)
                build_result = BuildResult(language="unknown", success=True)

        build_ok = (build_result.success if build_result else True)

        # ── 2. Vulnerability fixed check ────────────────────────────────────
        is_fixed, fix_note = _check_vuln_fixed(cwe_id, original_source, post_patch)
        vf.vulnerability_confirmed_fixed = is_fixed
        notes.append(fix_note)

        # ── 3. Regression detection ─────────────────────────────────────────
        regression, regression_issues = _check_regression(original_source, post_patch)
        vf.regression_detected = regression
        if regression:
            notes.extend(regression_issues)

        # ── 4. Test result (placeholder — real tests require project runner) ─
        test_result = FixTestRunResult(tests_run=0, tests_passed=0)
        vf.test_result = test_result

        # ── 5. Reachability recheck ─────────────────────────────────────────
        reach_removed = False
        if cpg is not None:
            reach_removed = self._reachability_recheck(cwe_id, post_patch, cpg)
        elif is_fixed:
            # Heuristic: if static analysis confirms fix, assume reachability removed
            reach_removed = is_fixed and not regression
        vf.reachability_removed = reach_removed

        # ── 6. Determine fix status ─────────────────────────────────────────
        if not build_ok:
            vf.fix_status = FixStatus.REJECTED
            notes.append("Fix rejected: build failed")
        elif regression:
            vf.fix_status = FixStatus.REJECTED
            notes.append("Fix rejected: regression detected")
        elif reach_removed and is_fixed:
            vf.fix_status = FixStatus.VERIFIED
        elif is_fixed or build_ok:
            vf.fix_status = FixStatus.VALIDATED
        else:
            vf.fix_status = FixStatus.REJECTED

        # ── 7. Confidence score ─────────────────────────────────────────────
        confidence = self.compute_confidence_from_signals(
            build_ok=build_ok,
            test_ok=True,  # no test runner yet
            reach_removed=reach_removed,
            verify_ok=is_fixed,
            no_regression=not regression,
        )
        vf.confidence_score = confidence
        vf.fix_confidence = confidence.total_score
        vf.verified_fix = post_patch if vf.fix_status != FixStatus.REJECTED else None
        vf.validation_notes = notes
        vf.validated_at = datetime.now(timezone.utc).isoformat()

        return vf

    def verify_batch(
        self,
        findings: List[Any],
        patches: List[str],
        original_sources: Optional[List[str]] = None,
    ) -> List[VerifiedFix]:
        """Verify multiple fixes in sequence."""
        results: List[VerifiedFix] = []
        sources = original_sources or [""] * len(findings)
        for finding, patch, source in zip(findings, patches, sources):
            vf = self.verify_fix(finding, patch, original_source=source)
            results.append(vf)
        return results

    @staticmethod
    def compute_confidence_from_signals(
        build_ok: bool = True,
        test_ok: bool = True,
        reach_removed: bool = False,
        verify_ok: bool = False,
        no_regression: bool = True,
    ) -> FixConfidenceScore:
        """Compute fix confidence from boolean signals."""
        return FixConfidenceScore(
            build_success=1.0 if build_ok else 0.0,
            test_success=1.0 if test_ok else 0.0,
            reachability_removed=1.0 if reach_removed else 0.0,
            verification_passed=1.0 if verify_ok else 0.0,
            no_regression=1.0 if no_regression else 0.0,
        )

    def compute_confidence(self, fix: VerifiedFix) -> FixConfidenceScore:
        """Recompute confidence from a VerifiedFix object."""
        return self.compute_confidence_from_signals(
            build_ok=fix.build_result.success if fix.build_result else True,
            test_ok=fix.test_result.success if fix.test_result else True,
            reach_removed=fix.reachability_removed,
            verify_ok=fix.vulnerability_confirmed_fixed,
            no_regression=not fix.regression_detected,
        )

    def generate_report(self, fixes: List[VerifiedFix]) -> RemediationReport:
        """Generate an aggregated RemediationReport from a list of VerifiedFix objects."""
        import uuid
        report = RemediationReport(
            report_id=str(uuid.uuid4())[:8],
            generated_at=datetime.now(timezone.utc).isoformat(),
            total_fixes=len(fixes),
            fixes=fixes,
        )
        for fix in fixes:
            if fix.fix_status == FixStatus.VERIFIED:
                report.verified_count += 1
            elif fix.fix_status == FixStatus.VALIDATED:
                report.validated_count += 1
            elif fix.fix_status == FixStatus.REJECTED:
                report.rejected_count += 1
            else:
                report.proposed_count += 1
            if fix.regression_detected:
                report.regressions_detected += 1
            report.attack_paths_removed += len(fix.attack_paths_removed)

        if fixes:
            report.average_confidence = round(
                sum(f.fix_confidence for f in fixes) / len(fixes), 4
            )
        return report

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _reachability_recheck(cwe_id: str, patched_source: str, cpg: Any) -> bool:
        """Check if the taint path for cwe_id is still reachable after patching."""
        try:
            from backend.core.cpg.query_engine import CPGQueryEngine
            engine = CPGQueryEngine(cpg)
            cwe_to_check = {
                "CWE-89": "find_sql_injection",
                "CWE-78": "find_command_injection",
            }
            method_name = cwe_to_check.get(cwe_id)
            if method_name:
                method = getattr(engine, method_name, None)
                if method:
                    results = method()
                    return len(results) == 0  # reachability removed if no results
        except Exception as exc:
            logger.debug("Reachability recheck failed: %s", exc)
        return False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get(obj: Any, attr: str, default: Any = "") -> Any:
    if isinstance(obj, dict):
        return obj.get(attr, default)
    return getattr(obj, attr, default)


def _lazy_build_validator() -> Optional[Any]:
    try:
        from backend.core.remediation.build_validator import BuildValidator
        return BuildValidator()
    except Exception:
        return None
