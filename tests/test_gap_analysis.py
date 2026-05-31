"""
tests/test_gap_analysis.py — Tests for GAPAnalyzer (TythanAI vs competitors).

Covers:
  - ToolProfile dataclass fields
  - GAPAnalysisResult structure
  - GAPAnalyzer.analyze() returns a valid result
  - Competitor profiles have realistic metrics (precision, recall between 0 and 1)
  - Gaps list is non-empty (honest about weaknesses)
  - Strengths list is non-empty
  - format_report() returns non-empty string with competitor names
  - Overall score is in [0, 1]
"""
from __future__ import annotations

import sys
import pathlib

_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import pytest

from backend.core.gap_analysis import (
    GAPAnalyzer,
    GAPAnalysisResult,
    ToolProfile,
)


# ---------------------------------------------------------------------------
# ToolProfile
# ---------------------------------------------------------------------------

class TestToolProfile:

    def test_tool_profile_has_name(self):
        profile = ToolProfile(
            name="TestTool",
            interprocedural_depth=1,
            languages_supported=["python"],
            custom_rules=True,
            kb_rules_count=100,
            sbca_supported=False,
            cloud_native=False,
            price_tier="free",
            avg_precision=0.75,
            avg_recall=0.60,
            avg_f1=0.67,
        )
        assert profile.name == "TestTool"
        assert 0.0 <= profile.avg_precision <= 1.0
        assert 0.0 <= profile.avg_recall <= 1.0
        assert 0.0 <= profile.avg_f1 <= 1.0


# ---------------------------------------------------------------------------
# GAPAnalyzer competitor profiles
# ---------------------------------------------------------------------------

class TestCompetitorProfiles:

    def test_all_four_competitors_present(self):
        """Semgrep, Snyk, CodeQL, and Wiz must all be in TOOL_PROFILES."""
        profiles = GAPAnalyzer.TOOL_PROFILES
        # Keys may have spaces/case e.g. "Semgrep OSS", "Snyk Code"
        names_combined = " ".join(k.lower() for k in profiles)
        for competitor in ("semgrep", "snyk", "codeql", "wiz"):
            assert competitor in names_combined, (
                f"Missing competitor profile: {competitor}"
            )

    def test_competitor_precision_realistic(self):
        """Competitor precision should be between 0.5 and 1.0 (not fake 100%)."""
        for name, profile in GAPAnalyzer.TOOL_PROFILES.items():
            assert 0.5 <= profile.avg_precision <= 1.0, (
                f"{name} precision {profile.avg_precision} is outside realistic range [0.5, 1.0]"
            )
            assert profile.avg_precision < 1.0, (
                f"{name} precision should not be 100% (unrealistic)"
            )

    def test_competitor_recall_realistic(self):
        """Competitor recall should be between 0.4 and 1.0."""
        for name, profile in GAPAnalyzer.TOOL_PROFILES.items():
            assert 0.4 <= profile.avg_recall <= 1.0, (
                f"{name} recall {profile.avg_recall} is outside realistic range"
            )
            assert profile.avg_recall < 1.0, (
                f"{name} recall should not be 100% (unrealistic)"
            )

    def test_semgrep_has_many_rules(self):
        """Semgrep should have many built-in rules (>= 500)."""
        semgrep = next(
            v for k, v in GAPAnalyzer.TOOL_PROFILES.items() if "semgrep" in k.lower()
        )
        assert semgrep.kb_rules_count >= 500, (
            f"Semgrep should have >= 500 rules, got {semgrep.kb_rules_count}"
        )

    def test_wiz_is_cloud_native(self):
        """Wiz should be marked as cloud_native=True."""
        wiz = next(
            v for k, v in GAPAnalyzer.TOOL_PROFILES.items() if "wiz" in k.lower()
        )
        assert wiz.cloud_native is True, "Wiz must be cloud_native=True"

    def test_codeql_is_interprocedural(self):
        """CodeQL should support interprocedural analysis (depth >= 1 or -1 for unlimited)."""
        codeql = next(
            v for k, v in GAPAnalyzer.TOOL_PROFILES.items() if "codeql" in k.lower()
        )
        assert codeql.interprocedural_depth >= 1 or codeql.interprocedural_depth == -1, (
            f"CodeQL must support interprocedural analysis, got depth={codeql.interprocedural_depth}"
        )


# ---------------------------------------------------------------------------
# GAPAnalyzer.analyze()
# ---------------------------------------------------------------------------

class TestGAPAnalyzerAnalyze:

    def test_analyze_returns_result(self):
        analyzer = GAPAnalyzer()
        result = analyzer.analyze()
        assert isinstance(result, GAPAnalysisResult), (
            f"Expected GAPAnalysisResult, got {type(result)}"
        )

    def test_analyze_has_gaps(self):
        """GAPAnalysisResult should honestly report gaps (non-empty list)."""
        analyzer = GAPAnalyzer()
        result = analyzer.analyze()
        assert len(result.gaps) > 0, (
            "Expected gaps to be identified — no tool is perfect"
        )

    def test_analyze_has_strengths(self):
        """GAPAnalysisResult should report TythanAI strengths."""
        analyzer = GAPAnalyzer()
        result = analyzer.analyze()
        assert len(result.strengths) > 0, "Expected strengths to be identified"

    def test_analyze_has_tool_profiles(self):
        """Result should include all competitor tool profiles."""
        analyzer = GAPAnalyzer()
        result = analyzer.analyze()
        assert len(result.tool_profiles) >= 4, (
            f"Expected >= 4 competitor profiles, got {len(result.tool_profiles)}"
        )

    def test_overall_score_in_range(self):
        """Overall score must be in [0, 100] or [0, 1]."""
        analyzer = GAPAnalyzer()
        result = analyzer.analyze()
        score = result.overall_score
        # Accept either percentage (0-100) or fraction (0.0-1.0) scale
        assert 0 <= score <= 100, (
            f"Overall score {score} out of [0, 100] range"
        )

    def test_overall_score_is_realistic(self):
        """Overall score should be honest — not a perfect score."""
        analyzer = GAPAnalyzer()
        result = analyzer.analyze()
        score = result.overall_score
        # Normalize to 0-100 range if it's a fraction
        if score <= 1.0:
            score_pct = score * 100
        else:
            score_pct = score
        assert score_pct < 100.0, (
            f"Overall score of {score_pct}% is unrealistic — must be honest"
        )

    def test_our_metrics_has_precision(self):
        """Result must include our own tool's metrics."""
        analyzer = GAPAnalyzer()
        result = analyzer.analyze()
        assert result.our_metrics is not None
        assert hasattr(result.our_metrics, "avg_precision")
        # Accept either 0-1 fraction or 0-100 percentage scale
        assert 0.0 <= result.our_metrics.avg_precision <= 100.0

    def test_recommendations_non_empty(self):
        """GAPAnalysisResult should include actionable recommendations."""
        analyzer = GAPAnalyzer()
        result = analyzer.analyze()
        assert len(result.recommendations) > 0, (
            "Expected at least one recommendation"
        )

    def test_gaps_mention_known_weaknesses(self):
        """Gaps should mention real TythanAI weaknesses."""
        analyzer = GAPAnalyzer()
        result = analyzer.analyze()
        gaps_text = " ".join(result.gaps).lower()
        # At least one of these known weaknesses should be mentioned
        known_weaknesses = [
            "java", "go", "c++", "sca", "sbom", "cloud", "sarif",
            "interprocedural", "cross-repo", "container", "docker"
        ]
        assert any(w in gaps_text for w in known_weaknesses), (
            f"Expected known weaknesses in gaps, got: {result.gaps}"
        )

    def test_strengths_mention_ton(self):
        """Strengths should mention TON/blockchain support (unique feature)."""
        analyzer = GAPAnalyzer()
        result = analyzer.analyze()
        strengths_text = " ".join(result.strengths).lower()
        ton_keywords = ["ton", "blockchain", "func", "tact", "solidity", "smart contract"]
        assert any(k in strengths_text for k in ton_keywords), (
            f"Expected TON/blockchain strength mentioned, got: {result.strengths}"
        )


# ---------------------------------------------------------------------------
# GAPAnalyzer.format_report()
# ---------------------------------------------------------------------------

class TestFormatReport:

    def test_format_report_returns_string(self):
        analyzer = GAPAnalyzer()
        result = analyzer.analyze()
        report = analyzer.format_report(result)
        assert isinstance(report, str), "format_report() must return a string"

    def test_format_report_is_non_empty(self):
        analyzer = GAPAnalyzer()
        result = analyzer.analyze()
        report = analyzer.format_report(result)
        assert len(report) > 100, "Report should have substantial content"

    def test_format_report_mentions_competitors(self):
        """Report should mention all 4 competitors by name."""
        analyzer = GAPAnalyzer()
        result = analyzer.analyze()
        report = analyzer.format_report(result).lower()
        for competitor in ("semgrep", "snyk", "codeql", "wiz"):
            assert competitor in report, f"Report should mention {competitor}"

    def test_format_report_has_scores(self):
        """Report should include numeric scores/percentages."""
        import re
        analyzer = GAPAnalyzer()
        result = analyzer.analyze()
        report = analyzer.format_report(result)
        # Should contain at least one percentage or decimal score
        has_number = bool(re.search(r'\d+\.?\d*\s*%|\d\.\d+', report))
        assert has_number, "Report should contain numeric scores"

    def test_format_report_with_none_benchmark(self):
        """analyze() with no benchmark report should still produce valid result."""
        analyzer = GAPAnalyzer()
        result = analyzer.analyze(benchmark_report=None)
        assert isinstance(result, GAPAnalysisResult)
        report = analyzer.format_report(result)
        assert len(report) > 50
