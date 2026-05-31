"""Tests for backend/core/confidence.py — Module 1."""
import pytest
from backend.core.confidence import (
    ConfidenceFilter,
    ContextVerifier,
    Deduplicator,
    Finding,
    findings_from_dicts,
)


# ─────────────────────────────────────────────────────────────────────────────
# Finding model
# ─────────────────────────────────────────────────────────────────────────────

class TestFinding:
    def test_basic_creation(self):
        f = Finding(rule_id="SQL-001", file="app.py", line=42, severity="high")
        assert f.severity == "HIGH"
        assert f.confidence == 0.8

    def test_confidence_clamped(self):
        f = Finding(rule_id="R", file="f.py", confidence=1.5)
        assert f.confidence == 1.0
        f2 = Finding(rule_id="R", file="f.py", confidence=-0.1)
        assert f2.confidence == 0.0

    def test_dedup_key(self):
        f = Finding(rule_id="X", file="a.py", line=10)
        assert f.dedup_key == ("a.py", 10, "X")

    def test_fingerprint_stable(self):
        f1 = Finding(rule_id="X", file="a.py", line=10)
        f2 = Finding(rule_id="X", file="a.py", line=10)
        assert f1.fingerprint() == f2.fingerprint()

    def test_fingerprint_differs(self):
        f1 = Finding(rule_id="X", file="a.py", line=10)
        f2 = Finding(rule_id="X", file="b.py", line=10)
        assert f1.fingerprint() != f2.fingerprint()


# ─────────────────────────────────────────────────────────────────────────────
# ContextVerifier
# ─────────────────────────────────────────────────────────────────────────────

class TestContextVerifier:
    def setup_method(self):
        self.v = ContextVerifier()

    def test_test_file_detected_prefix(self):
        f = Finding(rule_id="R", file="tests/test_auth.py", line=1)
        result = self.v.verify(f)
        assert result.is_test_file is True

    def test_test_file_suffix(self):
        f = Finding(rule_id="R", file="auth_test.py", line=1)
        result = self.v.verify(f)
        assert result.is_test_file is True

    def test_conftest(self):
        f = Finding(rule_id="R", file="conftest.py", line=1)
        result = self.v.verify(f)
        assert result.is_test_file is True

    def test_normal_file_not_test(self):
        f = Finding(rule_id="R", file="app/routes.py", line=5)
        result = self.v.verify(f)
        assert result.is_test_file is False

    def test_severity_downgraded_for_test_file(self):
        f = Finding(rule_id="R", file="tests/test_x.py", line=1, severity="CRITICAL")
        result = self.v.verify(f)
        assert result.severity == "HIGH"

    def test_nosec_suppressed(self):
        f = Finding(rule_id="R", file="app.py", line=1,
                    context_lines=["x = eval(user_input)  # nosec"])
        result = self.v.verify(f)
        assert result.is_suppressed is True

    def test_noqa_suppressed(self):
        f = Finding(rule_id="R", file="app.py", line=1,
                    context_lines=["import os  # noqa"])
        result = self.v.verify(f)
        assert result.is_suppressed is True

    def test_audit_ignore_suppressed(self):
        f = Finding(rule_id="R", file="app.py", line=1,
                    context_lines=["sql = query  # audit-ignore"])
        result = self.v.verify(f)
        assert result.is_suppressed is True

    def test_commented_code_suppressed(self):
        f = Finding(rule_id="R", file="app.py", line=1,
                    context_lines=["# execute(user_input)"])
        result = self.v.verify(f)
        assert result.is_suppressed is True

    def test_fixture_context_marks_test(self):
        f = Finding(rule_id="R", file="conftest.py", line=1,
                    context_lines=["@pytest.fixture", "def client():"])
        result = self.v.verify(f)
        assert result.is_test_file is True

    def test_mock_context_marks_test(self):
        f = Finding(rule_id="R", file="app.py", line=1,
                    context_lines=["with mock.patch('x') as m:"])
        result = self.v.verify(f)
        assert result.is_test_file is True


# ─────────────────────────────────────────────────────────────────────────────
# ConfidenceFilter
# ─────────────────────────────────────────────────────────────────────────────

class TestConfidenceFilter:
    def setup_method(self):
        self.cf = ConfidenceFilter(threshold=0.7)

    def test_passes_high_confidence(self):
        f = Finding(rule_id="R", file="a.py", confidence=0.9)
        result = self.cf.filter([f])
        assert len(result) == 1

    def test_blocks_low_confidence(self):
        f = Finding(rule_id="R", file="a.py", confidence=0.5)
        result = self.cf.filter([f])
        assert len(result) == 0

    def test_threshold_boundary(self):
        f = Finding(rule_id="R", file="a.py", confidence=0.7)
        result = self.cf.filter([f])
        assert len(result) == 1

    def test_suppressed_filtered_out(self):
        f = Finding(rule_id="R", file="a.py", confidence=0.95, is_suppressed=True)
        result = self.cf.filter([f])
        assert len(result) == 0

    def test_custom_threshold(self):
        findings = [
            Finding(rule_id="R", file="a.py", confidence=0.6),
            Finding(rule_id="R", file="b.py", confidence=0.8),
        ]
        result = self.cf.filter(findings, threshold=0.55)
        assert len(result) == 2

    def test_empty_input(self):
        assert self.cf.filter([]) == []


# ─────────────────────────────────────────────────────────────────────────────
# Deduplicator
# ─────────────────────────────────────────────────────────────────────────────

class TestDeduplicator:
    def setup_method(self):
        self.d = Deduplicator()

    def test_no_duplicates(self):
        findings = [
            Finding(rule_id="R1", file="a.py", line=1),
            Finding(rule_id="R2", file="a.py", line=2),
        ]
        result = self.d.deduplicate(findings)
        assert len(result) == 2

    def test_merges_duplicates(self):
        findings = [
            Finding(rule_id="R1", file="a.py", line=1, confidence=0.7, sources=["bandit"]),
            Finding(rule_id="R1", file="a.py", line=1, confidence=0.9, sources=["semgrep"]),
        ]
        result = self.d.deduplicate(findings)
        assert len(result) == 1
        assert result[0].confidence == 0.9
        assert set(result[0].sources) == {"bandit", "semgrep"}

    def test_highest_severity_wins(self):
        findings = [
            Finding(rule_id="R1", file="a.py", line=1, severity="MEDIUM"),
            Finding(rule_id="R1", file="a.py", line=1, severity="HIGH"),
        ]
        result = self.d.deduplicate(findings)
        assert result[0].severity == "HIGH"

    def test_context_lines_merged(self):
        findings = [
            Finding(rule_id="R1", file="a.py", line=1, context_lines=["line A"]),
            Finding(rule_id="R1", file="a.py", line=1, context_lines=["line B"]),
        ]
        result = self.d.deduplicate(findings)
        assert "line A" in result[0].context_lines
        assert "line B" in result[0].context_lines

    def test_context_lines_capped_at_10(self):
        findings = [
            Finding(rule_id="R1", file="a.py", line=1,
                    context_lines=[f"line {i}" for i in range(8)]),
            Finding(rule_id="R1", file="a.py", line=1,
                    context_lines=[f"extra {i}" for i in range(8)]),
        ]
        result = self.d.deduplicate(findings)
        assert len(result[0].context_lines) <= 10

    def test_findings_from_dicts(self):
        raw = [{"rule_id": "X", "file": "f.py", "line": 5}]
        findings = findings_from_dicts(raw)
        assert len(findings) == 1
        assert findings[0].rule_id == "X"
