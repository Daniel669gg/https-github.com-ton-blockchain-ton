"""Tests for CorpusRuleProposer — TythanAI V6.5 Phase 5."""
import sys
import pathlib

_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import pytest

from backend.core.knowledge.rule_proposer import (
    CorpusRuleProposer,
    RuleProposalStatus,
    ProposedRuleFromCorpus,
    ValidationResult,
)
from backend.core.knowledge.pattern_extractor import PatternExtractor, PatternType
from backend.core.knowledge.security_corpus import SecurityCorpus


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_extracted_pattern_for_cwe(cwe_id: str, index: int = 0):
    """Return an ExtractedPattern for the given CWE using PatternExtractor."""
    corpus = SecurityCorpus(load_embedded=True)
    entry = corpus.get(cwe_id)
    assert entry is not None, f"No corpus entry for {cwe_id}"
    extractor = PatternExtractor()
    patterns = extractor.extract_from_cwe(entry)
    assert len(patterns) > index, f"Not enough patterns for {cwe_id}"
    return patterns[index]


# ---------------------------------------------------------------------------
# 1. TestImports
# ---------------------------------------------------------------------------

class TestImports:
    def test_corpus_rule_proposer_importable(self):
        assert CorpusRuleProposer is not None

    def test_rule_proposal_status_importable(self):
        assert RuleProposalStatus is not None

    def test_proposed_rule_from_corpus_importable(self):
        assert ProposedRuleFromCorpus is not None

    def test_validation_result_importable(self):
        assert ValidationResult is not None


# ---------------------------------------------------------------------------
# 2. TestRuleProposalStatus
# ---------------------------------------------------------------------------

class TestRuleProposalStatus:
    def test_has_proposed_value(self):
        assert hasattr(RuleProposalStatus, "PROPOSED")
        assert RuleProposalStatus.PROPOSED.value == "proposed"

    def test_has_validated_value(self):
        assert hasattr(RuleProposalStatus, "VALIDATED")
        assert RuleProposalStatus.VALIDATED.value == "validated"

    def test_has_promoted_value(self):
        assert hasattr(RuleProposalStatus, "PROMOTED")
        assert RuleProposalStatus.PROMOTED.value == "promoted"

    def test_has_rejected_value(self):
        assert hasattr(RuleProposalStatus, "REJECTED")
        assert RuleProposalStatus.REJECTED.value == "rejected"


# ---------------------------------------------------------------------------
# 3. TestProposedRuleFromCorpus
# ---------------------------------------------------------------------------

class TestProposedRuleFromCorpus:
    def _make_rule(self) -> ProposedRuleFromCorpus:
        return ProposedRuleFromCorpus(
            rule_id="test-rule-001",
            cwe_id="CWE-89",
            name="Test SQL Injection Rule",
            description="Detects string concatenation in SQL execute()",
            pattern_regex=r'\.execute\s*\(\s*["\'].*\s*\+\s*\w',
            severity="ERROR",
            languages=["python"],
            confidence=0.85,
        )

    def test_has_rule_id_field(self):
        rule = self._make_rule()
        assert hasattr(rule, "rule_id")
        assert rule.rule_id == "test-rule-001"

    def test_has_cwe_id_field(self):
        rule = self._make_rule()
        assert hasattr(rule, "cwe_id")
        assert rule.cwe_id == "CWE-89"

    def test_has_status_field_of_correct_type(self):
        rule = self._make_rule()
        assert hasattr(rule, "status")
        assert isinstance(rule.status, RuleProposalStatus)
        assert rule.status == RuleProposalStatus.PROPOSED

    def test_to_semgrep_yaml_returns_string_with_rules(self):
        rule = self._make_rule()
        yaml_str = rule.to_semgrep_yaml()
        assert isinstance(yaml_str, str)
        assert "rules:" in yaml_str
        assert "test-rule-001" in yaml_str
        assert "CWE-89" in yaml_str


# ---------------------------------------------------------------------------
# 4. TestCorpusRuleProposer
# ---------------------------------------------------------------------------

class TestCorpusRuleProposer:
    def test_instantiates_without_arguments(self):
        proposer = CorpusRuleProposer()
        assert isinstance(proposer, CorpusRuleProposer)

    def test_propose_from_cwe_89_returns_list_of_rules(self):
        proposer = CorpusRuleProposer()
        rules = proposer.propose_from_cwe("CWE-89")
        assert isinstance(rules, list)
        assert len(rules) > 0
        for rule in rules:
            assert isinstance(rule, ProposedRuleFromCorpus)

    def test_proposed_rule_has_correct_cwe_id(self):
        proposer = CorpusRuleProposer()
        rules = proposer.propose_from_cwe("CWE-89")
        assert len(rules) > 0
        for rule in rules:
            assert rule.cwe_id == "CWE-89"

    def test_propose_from_cwe_78_command_injection(self):
        proposer = CorpusRuleProposer()
        rules = proposer.propose_from_cwe("CWE-78")
        assert isinstance(rules, list)
        assert len(rules) > 0
        for rule in rules:
            assert rule.cwe_id == "CWE-78"
            assert isinstance(rule.pattern_regex, str)
            assert len(rule.pattern_regex) > 0

    def test_validate_all_returns_list(self):
        proposer = CorpusRuleProposer()
        proposer.propose_from_cwe("CWE-89")
        results = proposer.validate_all()
        assert isinstance(results, list)
        for vr in results:
            assert isinstance(vr, ValidationResult)
            assert isinstance(vr.rule_id, str)

    def test_get_proposed_returns_list(self):
        proposer = CorpusRuleProposer()
        proposer.propose_from_cwe("CWE-89")
        proposed = proposer.get_proposed()
        assert isinstance(proposed, list)
        for r in proposed:
            assert isinstance(r, ProposedRuleFromCorpus)
            assert r.status == RuleProposalStatus.PROPOSED

    def test_get_validated_returns_list(self):
        proposer = CorpusRuleProposer()
        proposer.propose_from_cwe("CWE-89")
        proposer.validate_all()
        validated = proposer.get_validated()
        assert isinstance(validated, list)
        for r in validated:
            assert r.status == RuleProposalStatus.VALIDATED

    def test_generate_report_returns_string_with_rule(self):
        proposer = CorpusRuleProposer()
        proposer.propose_from_cwe("CWE-89")
        report = proposer.generate_report()
        assert isinstance(report, str)
        assert len(report) > 0
        # The report contains a "Rule" section when there are rules
        assert "Rule" in report

    def test_propose_from_pattern_with_extracted_pattern(self):
        pattern = _get_extracted_pattern_for_cwe("CWE-89", index=0)
        # Only patterns with non-empty regex are accepted
        assert isinstance(pattern.regex, str)
        assert len(pattern.regex) > 0

        proposer = CorpusRuleProposer()
        rule = proposer.propose_from_pattern(pattern)
        assert rule is not None
        assert isinstance(rule, ProposedRuleFromCorpus)
        assert rule.cwe_id == "CWE-89"
        assert rule.pattern_regex == pattern.regex
        assert isinstance(rule.confidence, float)
        assert 0.0 <= rule.confidence <= 1.0

    def test_propose_from_pattern_semgrep_yaml_valid(self):
        pattern = _get_extracted_pattern_for_cwe("CWE-89", index=0)
        proposer = CorpusRuleProposer()
        rule = proposer.propose_from_pattern(pattern)
        assert rule is not None
        yaml_str = rule.to_semgrep_yaml()
        assert "rules:" in yaml_str
        assert rule.rule_id in yaml_str

    def test_validation_result_fields(self):
        proposer = CorpusRuleProposer()
        proposer.propose_from_cwe("CWE-89")
        results = proposer.validate_all()
        # CWE-89 has benchmark data, so we get real validation results
        assert len(results) > 0
        vr = results[0]
        assert hasattr(vr, "true_positives")
        assert hasattr(vr, "false_positives")
        assert hasattr(vr, "true_negatives")
        assert hasattr(vr, "false_negatives")
        assert isinstance(vr.true_positives, int)
        assert isinstance(vr.false_positives, int)
        assert isinstance(vr.precision, float)
        assert isinstance(vr.recall, float)
        assert 0.0 <= vr.precision <= 1.0
        assert 0.0 <= vr.recall <= 1.0
