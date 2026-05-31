"""
Tests for backend.agents.rule_generator

Coverage:
- GeneratedRule model validation
- Pattern builder routing (taint / auth / crypto / generic)
- RuleGenerator.generate() — filtering, grouping, dedup, YAML output
- Rule promotion (draft → stable after 3+ hits)
- promote_stable_rules() file copy
- SQLite persistence (upsert, hit_count increment)
- True-positive / true-negative cases
- Benchmark: 1000 findings processed in < 5 s
"""
from __future__ import annotations

import os
import sys
import tempfile
import time
from pathlib import Path
from typing import List

import pytest

# ---------------------------------------------------------------------------
# Ensure project root is on sys.path
# ---------------------------------------------------------------------------
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from backend.agents.rule_generator import (
    GeneratedRule,
    RuleGenerator,
    _build_pattern,
    _pattern_for_auth,
    _pattern_for_crypto,
    _pattern_for_taint,
)
from backend.core.confidence import Finding


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_finding(
    rule_id:     str  = "taint-sql-injection",
    file:        str  = "app/api.py",
    line:        int  = 10,
    severity:    str  = "HIGH",
    confidence:  float = 0.9,
    cwe_id:      str  = "CWE-89",
    description: str  = "SQL injection via execute()",
    context_lines: List[str] | None = None,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        file=file,
        line=line,
        severity=severity,
        confidence=confidence,
        cwe_id=cwe_id,
        description=description,
        context_lines=context_lines or ["cursor.execute(query, params)"],
    )


@pytest.fixture()
def tmp_db(tmp_path: Path) -> str:
    """Return a path to a temporary SQLite DB."""
    return str(tmp_path / "rules.db")


@pytest.fixture()
def tmp_output(tmp_path: Path) -> str:
    """Return a temporary output directory."""
    d = tmp_path / "rules" / "generated"
    d.mkdir(parents=True)
    return str(d)


@pytest.fixture()
def generator(tmp_db: str) -> RuleGenerator:
    return RuleGenerator(db_path=tmp_db)


# ---------------------------------------------------------------------------
# GeneratedRule model
# ---------------------------------------------------------------------------

class TestGeneratedRuleModel:
    def test_defaults(self) -> None:
        r = GeneratedRule(rule_id="auto_rule_abc", yaml_content="rules: []")
        assert r.hit_count == 1
        assert r.status == "draft"
        assert r.output_path == ""
        assert 0.0 <= r.confidence_avg <= 1.0

    def test_fields_set_correctly(self) -> None:
        r = GeneratedRule(
            rule_id="auto_rule_xyz",
            yaml_content="rules:\n  - id: auto_rule_xyz",
            hit_count=5,
            status="stable",
            confidence_avg=0.92,
            output_path="/some/path.yaml",
        )
        assert r.rule_id == "auto_rule_xyz"
        assert r.hit_count == 5
        assert r.status == "stable"
        assert r.confidence_avg == 0.92

    def test_created_at_auto_set(self) -> None:
        r = GeneratedRule(rule_id="x", yaml_content="y")
        assert r.created_at  # not empty


# ---------------------------------------------------------------------------
# Pattern builders
# ---------------------------------------------------------------------------

class TestPatternBuilders:

    # ---- taint -------------------------------------------------------------

    def test_taint_extracts_sink_from_context(self) -> None:
        f = _make_finding(
            rule_id="taint-sql",
            context_lines=["cursor.execute(user_input)"],
        )
        pattern = _pattern_for_taint(f)
        assert "execute" in pattern or "cursor" in pattern or "(" in pattern

    def test_taint_falls_back_to_rule_id_fragment(self) -> None:
        f = _make_finding(rule_id="taint-subprocess-cmd", context_lines=[])
        pattern = _pattern_for_taint(f)
        assert "(" in pattern  # must look like a call pattern

    def test_taint_generic_fallback(self) -> None:
        f = _make_finding(rule_id="taint", context_lines=[])
        pattern = _pattern_for_taint(f)
        assert pattern.endswith("(...)")

    # ---- auth --------------------------------------------------------------

    def test_auth_extracts_async_def(self) -> None:
        f = _make_finding(
            rule_id="auth-missing-dep",
            context_lines=["async def get_users(db: Session):"],
        )
        pattern = _pattern_for_auth(f)
        assert "async def" in pattern or "$HANDLER" in pattern

    def test_auth_generic_fallback(self) -> None:
        f = _make_finding(rule_id="auth-jwt", context_lines=[])
        pattern = _pattern_for_auth(f)
        assert "$HANDLER" in pattern

    # ---- crypto ------------------------------------------------------------

    def test_crypto_md5_detected_in_description(self) -> None:
        f = _make_finding(
            rule_id="crypto-weak-hash",
            description="MD5 usage detected",
            context_lines=[],
        )
        pattern = _pattern_for_crypto(f)
        assert "md5" in pattern.lower()

    def test_crypto_sha1_detected_in_context(self) -> None:
        f = _make_finding(
            rule_id="crypto-hash",
            context_lines=["digest = hashlib.sha1(data).hexdigest()"],
        )
        pattern = _pattern_for_crypto(f)
        assert "sha1" in pattern.lower() or "hashlib" in pattern.lower()

    def test_crypto_generic_fallback(self) -> None:
        f = _make_finding(rule_id="crypto-cipher", context_lines=[])
        pattern = _pattern_for_crypto(f)
        assert "(" in pattern

    # ---- routing -----------------------------------------------------------

    def test_build_pattern_routes_taint(self) -> None:
        f = _make_finding(rule_id="taint-sqli")
        p = _build_pattern(f)
        assert "(" in p

    def test_build_pattern_routes_auth(self) -> None:
        f = _make_finding(rule_id="auth-missing-depends")
        p = _build_pattern(f)
        assert "def" in p or "HANDLER" in p or "(" in p

    def test_build_pattern_routes_crypto(self) -> None:
        f = _make_finding(rule_id="crypto-weak-md5")
        p = _build_pattern(f)
        assert "(" in p


# ---------------------------------------------------------------------------
# RuleGenerator.generate() — true positives
# ---------------------------------------------------------------------------

class TestRuleGeneratorGenerate:

    def test_generate_produces_rule_for_two_files(
        self, generator: RuleGenerator, tmp_output: str
    ) -> None:
        findings = [
            _make_finding(file="app/route1.py"),
            _make_finding(file="app/route2.py"),
        ]
        rules = generator.generate(findings, output_dir=tmp_output)
        assert len(rules) == 1
        assert rules[0].rule_id.startswith("auto_rule_")

    def test_generate_writes_yaml_file(
        self, generator: RuleGenerator, tmp_output: str
    ) -> None:
        findings = [
            _make_finding(file="app/a.py"),
            _make_finding(file="app/b.py"),
        ]
        rules = generator.generate(findings, output_dir=tmp_output)
        assert rules
        yaml_path = Path(rules[0].output_path)
        assert yaml_path.exists()
        content = yaml_path.read_text()
        assert "rules:" in content
        assert "auto_rule_" in content

    def test_yaml_contains_required_fields(
        self, generator: RuleGenerator, tmp_output: str
    ) -> None:
        import yaml as _yaml
        findings = [
            _make_finding(file="svc/x.py", cwe_id="CWE-89"),
            _make_finding(file="svc/y.py", cwe_id="CWE-89"),
        ]
        rules = generator.generate(findings, output_dir=tmp_output)
        assert rules
        data = _yaml.safe_load(rules[0].yaml_content)
        rule_def = data["rules"][0]
        assert "id" in rule_def
        assert "pattern" in rule_def
        assert "message" in rule_def
        assert "severity" in rule_def
        assert "languages" in rule_def
        meta = rule_def.get("metadata", {})
        assert "created_at" in meta
        assert "confidence" in meta
        assert "hit_count" in meta
        assert "status" in meta
        assert meta.get("auto_generated") is True

    def test_severity_mapping_to_semgrep(
        self, generator: RuleGenerator, tmp_output: str
    ) -> None:
        import yaml as _yaml
        for ghost_sev, expected_semgrep_sev in [
            ("CRITICAL", "ERROR"),
            ("HIGH", "ERROR"),
            ("MEDIUM", "WARNING"),
            ("LOW", "INFO"),
        ]:
            findings = [
                _make_finding(file="a/x.py", severity=ghost_sev),
                _make_finding(file="a/y.py", severity=ghost_sev),
            ]
            rules = generator.generate(findings, output_dir=tmp_output)
            if rules:
                data = _yaml.safe_load(rules[0].yaml_content)
                assert data["rules"][0]["severity"] == expected_semgrep_sev

    def test_hit_count_increments_on_repeat_calls(
        self, generator: RuleGenerator, tmp_output: str
    ) -> None:
        findings = [
            _make_finding(file="a/x.py"),
            _make_finding(file="a/y.py"),
        ]
        rules1 = generator.generate(findings, output_dir=tmp_output)
        rules2 = generator.generate(findings, output_dir=tmp_output)
        assert rules2[0].hit_count == 2

    def test_status_becomes_stable_after_three_hits(
        self, generator: RuleGenerator, tmp_output: str
    ) -> None:
        findings = [
            _make_finding(file="a/x.py"),
            _make_finding(file="a/y.py"),
        ]
        r1 = generator.generate(findings, output_dir=tmp_output)
        assert r1[0].status == "draft"
        r2 = generator.generate(findings, output_dir=tmp_output)
        assert r2[0].status == "draft"
        r3 = generator.generate(findings, output_dir=tmp_output)
        assert r3[0].status == "stable"

    def test_output_dir_created_if_missing(
        self, generator: RuleGenerator, tmp_path: Path
    ) -> None:
        new_dir = str(tmp_path / "deep" / "nested" / "dir")
        findings = [
            _make_finding(file="app/a.py"),
            _make_finding(file="app/b.py"),
        ]
        rules = generator.generate(findings, output_dir=new_dir)
        assert Path(new_dir).exists()
        if rules:
            assert Path(rules[0].output_path).exists()

    def test_multiple_rule_ids_generate_multiple_rules(
        self, generator: RuleGenerator, tmp_output: str
    ) -> None:
        findings = [
            _make_finding(rule_id="taint-sql", file="a/x.py"),
            _make_finding(rule_id="taint-sql", file="a/y.py"),
            _make_finding(rule_id="auth-missing", file="b/x.py"),
            _make_finding(rule_id="auth-missing", file="b/y.py"),
        ]
        rules = generator.generate(findings, output_dir=tmp_output)
        # Both rule_ids appear in 2+ files → should generate 2 rules
        assert len(rules) == 2


# ---------------------------------------------------------------------------
# RuleGenerator.generate() — true negatives
# ---------------------------------------------------------------------------

class TestRuleGeneratorTrueNegatives:

    def test_low_confidence_findings_excluded(
        self, generator: RuleGenerator, tmp_output: str
    ) -> None:
        findings = [
            _make_finding(file="a/x.py", confidence=0.5),
            _make_finding(file="a/y.py", confidence=0.6),
        ]
        rules = generator.generate(findings, output_dir=tmp_output)
        assert rules == []

    def test_single_file_does_not_generate_rule(
        self, generator: RuleGenerator, tmp_output: str
    ) -> None:
        findings = [
            _make_finding(file="app/only.py"),
            _make_finding(file="app/only.py", line=20),
        ]
        rules = generator.generate(findings, output_dir=tmp_output)
        assert rules == []

    def test_empty_findings_returns_empty(
        self, generator: RuleGenerator, tmp_output: str
    ) -> None:
        rules = generator.generate([], output_dir=tmp_output)
        assert rules == []

    def test_exactly_threshold_confidence_included(
        self, generator: RuleGenerator, tmp_output: str
    ) -> None:
        # confidence == 0.8 should be included (>= threshold)
        findings = [
            _make_finding(file="a/x.py", confidence=0.8),
            _make_finding(file="a/y.py", confidence=0.8),
        ]
        rules = generator.generate(findings, output_dir=tmp_output)
        assert len(rules) == 1

    def test_different_severity_groups_separately(
        self, generator: RuleGenerator, tmp_output: str
    ) -> None:
        # Same rule_id but different severity → different groups
        findings = [
            _make_finding(rule_id="taint-xss", file="a/x.py", severity="HIGH"),
            _make_finding(rule_id="taint-xss", file="a/y.py", severity="MEDIUM"),
        ]
        # Each group has only 1 file → neither qualifies
        rules = generator.generate(findings, output_dir=tmp_output)
        assert rules == []


# ---------------------------------------------------------------------------
# promote_stable_rules
# ---------------------------------------------------------------------------

class TestPromoteStableRules:

    def test_promote_copies_stable_rule_to_rules_dir(
        self, generator: RuleGenerator, tmp_output: str, tmp_path: Path
    ) -> None:
        findings = [
            _make_finding(file="a/x.py"),
            _make_finding(file="a/y.py"),
        ]
        # Generate 3 times to reach stable
        for _ in range(3):
            generator.generate(findings, output_dir=tmp_output)

        rules_dir = str(tmp_path / "rules")
        count = generator.promote_stable_rules(rules_dir=rules_dir)
        assert count >= 1
        # The file must exist in rules_dir
        promoted_files = list(Path(rules_dir).glob("auto_*.yaml"))
        assert len(promoted_files) >= 1

    def test_promote_returns_zero_for_draft_rules(
        self, generator: RuleGenerator, tmp_output: str, tmp_path: Path
    ) -> None:
        findings = [
            _make_finding(file="a/x.py"),
            _make_finding(file="a/y.py"),
        ]
        generator.generate(findings, output_dir=tmp_output)  # only 1 hit → draft
        rules_dir = str(tmp_path / "rules")
        count = generator.promote_stable_rules(rules_dir=rules_dir)
        assert count == 0

    def test_promote_does_not_duplicate_already_promoted(
        self, generator: RuleGenerator, tmp_output: str, tmp_path: Path
    ) -> None:
        findings = [
            _make_finding(file="a/x.py"),
            _make_finding(file="a/y.py"),
        ]
        for _ in range(3):
            generator.generate(findings, output_dir=tmp_output)

        rules_dir = str(tmp_path / "rules")
        count1 = generator.promote_stable_rules(rules_dir=rules_dir)
        count2 = generator.promote_stable_rules(rules_dir=rules_dir)
        assert count1 >= 1
        assert count2 == 0  # second call should not copy again


# ---------------------------------------------------------------------------
# Database persistence
# ---------------------------------------------------------------------------

class TestDatabasePersistence:

    def test_rule_persisted_in_db(
        self, generator: RuleGenerator, tmp_output: str
    ) -> None:
        findings = [
            _make_finding(file="a/x.py"),
            _make_finding(file="a/y.py"),
        ]
        rules = generator.generate(findings, output_dir=tmp_output)
        assert rules
        db_row = generator._db.get_generated_rule(rules[0].rule_id)
        assert db_row is not None
        assert db_row["rule_id"] == rules[0].rule_id
        assert db_row["hit_count"] >= 1

    def test_list_generated_rules_by_status(
        self, generator: RuleGenerator, tmp_output: str
    ) -> None:
        findings = [
            _make_finding(file="a/x.py"),
            _make_finding(file="a/y.py"),
        ]
        for _ in range(3):
            generator.generate(findings, output_dir=tmp_output)

        stable = generator._db.list_generated_rules(status="stable")
        assert any(r["status"] == "stable" for r in stable)

    def test_confidence_avg_stored_correctly(
        self, generator: RuleGenerator, tmp_output: str
    ) -> None:
        findings = [
            _make_finding(file="a/x.py", confidence=0.85),
            _make_finding(file="a/y.py", confidence=0.95),
        ]
        rules = generator.generate(findings, output_dir=tmp_output)
        assert rules
        expected_avg = round((0.85 + 0.95) / 2, 4)
        assert abs(rules[0].confidence_avg - expected_avg) < 0.001


# ---------------------------------------------------------------------------
# Benchmark
# ---------------------------------------------------------------------------

class TestBenchmark:

    def test_generate_1000_findings_under_5s(
        self, generator: RuleGenerator, tmp_output: str
    ) -> None:
        """
        Performance smoke test: 1000 findings (50 unique rule_ids × 20 files each)
        must complete in under 5 seconds.
        """
        findings: List[Finding] = []
        for i in range(50):
            for j in range(20):
                findings.append(
                    _make_finding(
                        rule_id=f"taint-rule-{i:03d}",
                        file=f"app/module_{j:03d}.py",
                        confidence=0.9,
                    )
                )

        start = time.perf_counter()
        rules = generator.generate(findings, output_dir=tmp_output)
        elapsed = time.perf_counter() - start

        assert len(rules) == 50, f"Expected 50 rules, got {len(rules)}"
        assert elapsed < 5.0, f"generate() took {elapsed:.2f}s — exceeds 5s budget"
