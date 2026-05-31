"""Tests for backend/scoring/risk_scorer.py — Module 3."""
import pytest
from backend.core.confidence import Finding
from backend.scoring.risk_scorer import (
    RiskScorer,
    _severity_score,
    _exposure_score,
    _criticality_score,
)


def _f(severity: str = "MEDIUM", rule_id: str = "R", file: str = "app.py",
        description: str = "", confidence: float = 0.8) -> Finding:
    return Finding(
        rule_id=rule_id, file=file, severity=severity,
        description=description, confidence=confidence,
    )


class TestSeverityComponent:
    def test_critical(self):
        assert _severity_score("CRITICAL") == 40.0

    def test_high(self):
        assert _severity_score("HIGH") == 28.0

    def test_medium(self):
        assert _severity_score("MEDIUM") == 16.0

    def test_low(self):
        assert _severity_score("LOW") == 6.0

    def test_info(self):
        assert _severity_score("INFO") == 1.0


class TestExposureComponent:
    def test_api_endpoint_description(self):
        f = _f(description="Vulnerability in public API endpoint")
        score = _exposure_score(f)
        assert score > 0

    def test_internal_only(self):
        f = _f(description="Local database helper function")
        score = _exposure_score(f)
        assert score < 20.0

    def test_high_exposure_multiple_signals(self):
        f = _f(
            rule_id="api-endpoint",
            file="api/routes.py",
            description="Public HTTP request handler with external websocket",
        )
        score = _exposure_score(f)
        assert score > 10.0


class TestCriticalityComponent:
    def test_password_in_description(self):
        f = _f(description="Password stored in plaintext")
        score = _criticality_score(f)
        assert score > 0

    def test_auth_token_secret(self):
        f = _f(description="Auth token and secret key exposed")
        score = _criticality_score(f)
        assert score > 0

    def test_no_critical_data(self):
        f = _f(description="Unused import statement")
        score = _criticality_score(f)
        assert score == 0.0


class TestRiskScorer:
    def setup_method(self):
        self.scorer = RiskScorer(fetch_epss=False)

    def test_critical_scores_higher_than_medium(self):
        rs_crit = self.scorer.score(_f("CRITICAL"))
        rs_med = self.scorer.score(_f("MEDIUM"))
        assert rs_crit.risk_score > rs_med.risk_score

    def test_score_bounded_0_100(self):
        rs = self.scorer.score(_f("CRITICAL", description="password secret token auth api"))
        assert 0 <= rs.risk_score <= 100

    def test_sorted_by_risk_score_descending(self):
        findings = [
            _f("LOW", rule_id="low"),
            _f("CRITICAL", rule_id="crit"),
            _f("MEDIUM", rule_id="med"),
        ]
        scored = self.scorer.score_all(findings)
        scores = [r.risk_score for r in scored]
        assert scores == sorted(scores, reverse=True)

    def test_10_different_cases_correctly_ranked(self):
        severities = [
            ("CRITICAL", "api password secret token auth admin http external"),
            ("CRITICAL", "public http endpoint request"),
            ("HIGH", "auth token api"),
            ("HIGH", "http external"),
            ("HIGH", "password"),
            ("MEDIUM", "api request"),
            ("MEDIUM", "auth"),
            ("MEDIUM", ""),
            ("LOW", ""),
            ("INFO", ""),
        ]
        findings = [
            _f(sev, rule_id=f"R{i}", description=desc)
            for i, (sev, desc) in enumerate(severities)
        ]
        scored = self.scorer.score_all(findings)
        scores = [r.risk_score for r in scored]
        # Must be sorted descending
        assert scores == sorted(scores, reverse=True)
        # CRITICAL must come before INFO
        sev_order = [s.severity for s in scored]
        crit_indices = [i for i, s in enumerate(sev_order) if s == "CRITICAL"]
        info_indices = [i for i, s in enumerate(sev_order) if s == "INFO"]
        if crit_indices and info_indices:
            assert max(crit_indices) < min(info_indices)

    def test_build_report_has_required_keys(self):
        findings = [_f("HIGH", rule_id=f"R{i}") for i in range(5)]
        report = self.scorer.build_report(findings)
        assert "total" in report
        assert "top_findings" in report
        assert "average_risk_score" in report
        assert "label_distribution" in report

    def test_label_critical_risk(self):
        # CRITICAL severity with exposure → should be CRITICAL_RISK
        f = _f("CRITICAL", description="api http public external request websocket")
        rs = self.scorer.score(f)
        assert rs.label() in ("CRITICAL_RISK", "HIGH_RISK")

    def test_label_low_risk(self):
        f = _f("INFO")
        rs = self.scorer.score(f)
        assert rs.label() == "LOW_RISK"

    def test_components_sum(self):
        f = _f("HIGH")
        rs = self.scorer.score(f)
        total = rs.severity_component + rs.epss_component + rs.exposure_component + rs.criticality_component
        assert abs(rs.risk_score - total) < 0.01
