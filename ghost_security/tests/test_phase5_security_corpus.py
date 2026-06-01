"""TythanAI V6.5 Phase 5 — Security Research & Knowledge Acquisition Platform.

Tests for SecurityCorpus and related classes.
"""
from __future__ import annotations

import json
import sys
import pathlib

_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import pytest

from backend.core.knowledge.security_corpus import (
    SecurityCorpus,
    CorpusEntryType,
    VerificationStatus,
    KnowledgeConfidenceScore,
    CorpusEntry,
    CVEEntry,
    CWEEntry,
    CAPECEntry,
    AdvisoryEntry,
    ResearchEntry,
    ExploitEntry,
    RemediationPatternEntry,
    GeneratedRuleEntry,
)


# ---------------------------------------------------------------------------
# TestImports
# ---------------------------------------------------------------------------


class TestImports:
    def test_security_corpus_importable(self):
        assert SecurityCorpus is not None

    def test_corpus_entry_type_importable(self):
        assert CorpusEntryType is not None

    def test_verification_status_importable(self):
        assert VerificationStatus is not None

    def test_knowledge_confidence_score_importable(self):
        assert KnowledgeConfidenceScore is not None

    def test_corpus_entry_importable(self):
        assert CorpusEntry is not None


# ---------------------------------------------------------------------------
# TestCorpusEntryType
# ---------------------------------------------------------------------------


class TestCorpusEntryType:
    def test_has_required_members(self):
        required = {"CVE", "CWE", "CAPEC", "OWASP", "ADVISORY", "RESEARCH", "EXPLOIT", "REMEDIATION", "GENERATED_RULE"}
        members = set(CorpusEntryType.__members__.keys())
        assert required.issubset(members), f"Missing members: {required - members}"

    def test_values_are_strings(self):
        for member in CorpusEntryType:
            assert isinstance(member.value, str), f"{member} value is not a string"

    def test_enum_is_str_subclass(self):
        # CorpusEntryType(str, Enum) means each value is a str
        assert issubclass(CorpusEntryType, str)
        assert CorpusEntryType.CVE == "cve"
        assert CorpusEntryType.CWE == "cwe"
        assert CorpusEntryType.CAPEC == "capec"


# ---------------------------------------------------------------------------
# TestKnowledgeConfidenceScore
# ---------------------------------------------------------------------------


class TestKnowledgeConfidenceScore:
    def test_defaults_give_zero_total_score(self):
        score = KnowledgeConfidenceScore()
        assert score.total_score == 0.0

    def test_all_maxed_gives_near_one(self):
        score = KnowledgeConfidenceScore(
            source_score=1.0,
            confirmation_count=5,  # >= 5 gives full confirmation bonus (0.2)
            detection_success=1.0,
            remediation_success=1.0,
        )
        # 1.0*0.4 + 0.2 + 1.0*0.25 + 1.0*0.15 = 1.0
        assert abs(score.total_score - 1.0) < 1e-6

    def test_total_score_in_range(self):
        score = KnowledgeConfidenceScore(
            source_score=0.7,
            confirmation_count=3,
            detection_success=0.6,
            remediation_success=0.5,
        )
        assert 0.0 <= score.total_score <= 1.0

    def test_has_expected_fields(self):
        score = KnowledgeConfidenceScore(
            source_score=0.8,
            confirmation_count=4,
            detection_success=0.5,
            remediation_success=0.3,
        )
        assert score.source_score == 0.8
        assert score.confirmation_count == 4
        assert score.detection_success == 0.5
        assert score.remediation_success == 0.3


# ---------------------------------------------------------------------------
# TestSecurityCorpus
# ---------------------------------------------------------------------------


class TestSecurityCorpus:
    def test_instantiates_without_arguments(self):
        corpus = SecurityCorpus()
        assert corpus is not None

    def test_size_greater_than_zero(self):
        corpus = SecurityCorpus()
        assert corpus.size > 0, "Expected embedded entries to be loaded at init"

    def test_cwe_count_greater_than_zero(self):
        corpus = SecurityCorpus()
        assert corpus.cwe_count > 0, "Expected embedded CWE entries"

    def test_capec_count_greater_than_zero(self):
        corpus = SecurityCorpus()
        assert corpus.capec_count > 0, "Expected embedded CAPEC entries"

    def test_query_by_cwe_89_returns_entries(self):
        corpus = SecurityCorpus()
        results = corpus.query_by_cwe("CWE-89")
        assert len(results) >= 1, "Expected at least one entry related to CWE-89"

    def test_query_by_type_cwe_returns_nonempty(self):
        corpus = SecurityCorpus()
        results = corpus.query_by_type(CorpusEntryType.CWE)
        assert len(results) > 0, "Expected CWE entries in the corpus"

    def test_search_injection_returns_entries(self):
        corpus = SecurityCorpus()
        results = corpus.search("injection")
        assert len(results) >= 1, "Expected at least one entry matching 'injection'"

    def test_get_stats_has_total_entries(self):
        corpus = SecurityCorpus()
        stats = corpus.get_stats()
        assert isinstance(stats, dict)
        assert "total_entries" in stats
        assert stats["total_entries"] == corpus.size

    def test_to_json_is_valid_json_with_entries_key(self):
        corpus = SecurityCorpus()
        json_str = corpus.to_json()
        parsed = json.loads(json_str)
        assert "entries" in parsed, "Expected 'entries' key in to_json() output"
        assert isinstance(parsed["entries"], list)
        assert len(parsed["entries"]) > 0
