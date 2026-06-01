"""Tests for PatternExtractor — TythanAI V6.5 Phase 5."""
import sys
import pathlib

_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import pytest

from backend.core.knowledge.pattern_extractor import (
    PatternExtractor,
    PatternType,
    ExtractedPattern,
    ExtractionResult,
)
from backend.core.knowledge.security_corpus import SecurityCorpus, CorpusEntryType


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_cwe_obj(cwe_id: str):
    """Return a minimal object that PatternExtractor.extract_from_cwe accepts."""
    from backend.core.knowledge.security_corpus import CWEEntry
    corpus = SecurityCorpus(load_embedded=True)
    entry = corpus.get(cwe_id)
    if entry is not None:
        return entry
    # Fall back to a bare dict-like object
    return {"cwe_id": cwe_id}


# ---------------------------------------------------------------------------
# 1. TestImports
# ---------------------------------------------------------------------------

class TestImports:
    def test_pattern_extractor_importable(self):
        assert PatternExtractor is not None

    def test_pattern_type_importable(self):
        assert PatternType is not None

    def test_extracted_pattern_importable(self):
        assert ExtractedPattern is not None

    def test_extraction_result_importable(self):
        assert ExtractionResult is not None


# ---------------------------------------------------------------------------
# 2. TestPatternType
# ---------------------------------------------------------------------------

class TestPatternType:
    def test_has_vulnerability_constant(self):
        assert hasattr(PatternType, "VULNERABILITY")
        assert isinstance(PatternType.VULNERABILITY, str)
        assert PatternType.VULNERABILITY == "vulnerability"

    def test_has_exploitation_constant(self):
        assert hasattr(PatternType, "EXPLOITATION")
        assert isinstance(PatternType.EXPLOITATION, str)
        assert PatternType.EXPLOITATION == "exploitation"

    def test_has_remediation_constant(self):
        assert hasattr(PatternType, "REMEDIATION")
        assert isinstance(PatternType.REMEDIATION, str)
        assert PatternType.REMEDIATION == "remediation"

    def test_has_detection_constant(self):
        assert hasattr(PatternType, "DETECTION")
        assert isinstance(PatternType.DETECTION, str)
        assert PatternType.DETECTION == "detection"


# ---------------------------------------------------------------------------
# 3. TestExtractedPattern
# ---------------------------------------------------------------------------

class TestExtractedPattern:
    def test_create_with_required_fields(self):
        pat = ExtractedPattern(
            pattern_id="test-001",
            pattern_type=PatternType.VULNERABILITY,
            regex=r"\.execute\s*\(",
            description="Test SQL injection pattern",
            confidence=0.85,
        )
        assert pat.pattern_id == "test-001"
        assert pat.pattern_type == PatternType.VULNERABILITY
        assert pat.regex == r"\.execute\s*\("
        assert pat.description == "Test SQL injection pattern"
        assert pat.confidence == 0.85

    def test_confidence_is_float_in_range(self):
        for conf in (0.0, 0.5, 0.75, 1.0):
            pat = ExtractedPattern(
                pattern_id=f"test-conf-{conf}",
                pattern_type=PatternType.VULNERABILITY,
                regex="",
                description="range check",
                confidence=conf,
            )
            assert isinstance(pat.confidence, float)
            assert 0.0 <= pat.confidence <= 1.0

    def test_has_source_cwe_field(self):
        pat = ExtractedPattern(
            pattern_id="test-cwe",
            pattern_type=PatternType.VULNERABILITY,
            regex=r"\.execute\(",
            description="SQL injection",
            confidence=0.80,
            source_cwe="CWE-89",
        )
        assert hasattr(pat, "source_cwe")
        assert pat.source_cwe == "CWE-89"

    def test_has_tags_field_list(self):
        pat = ExtractedPattern(
            pattern_id="test-tags",
            pattern_type=PatternType.VULNERABILITY,
            regex="",
            description="tagged pattern",
            confidence=0.70,
            tags=["cwe", "sqli"],
        )
        assert hasattr(pat, "tags")
        assert isinstance(pat.tags, list)
        assert "cwe" in pat.tags
        assert "sqli" in pat.tags


# ---------------------------------------------------------------------------
# 4. TestPatternExtractor
# ---------------------------------------------------------------------------

class TestPatternExtractor:
    def test_instantiates_without_arguments(self):
        extractor = PatternExtractor()
        assert isinstance(extractor, PatternExtractor)

    def test_extract_from_cwe_89_returns_list(self):
        extractor = PatternExtractor()
        cwe_entry = _make_cwe_obj("CWE-89")
        result = extractor.extract_from_cwe(cwe_entry)
        assert isinstance(result, list)

    def test_extract_from_cwe_89_not_empty(self):
        extractor = PatternExtractor()
        cwe_entry = _make_cwe_obj("CWE-89")
        patterns = extractor.extract_from_cwe(cwe_entry)
        assert len(patterns) > 0
        for pat in patterns:
            assert isinstance(pat, ExtractedPattern)

    def test_extract_from_cwe_78_command_injection(self):
        extractor = PatternExtractor()
        cwe_entry = _make_cwe_obj("CWE-78")
        patterns = extractor.extract_from_cwe(cwe_entry)
        assert isinstance(patterns, list)
        assert len(patterns) > 0
        cwe_ids = {p.source_cwe for p in patterns}
        assert "CWE-78" in cwe_ids

    def test_extract_from_cwe_502_deserialization(self):
        extractor = PatternExtractor()
        cwe_entry = _make_cwe_obj("CWE-502")
        patterns = extractor.extract_from_cwe(cwe_entry)
        assert isinstance(patterns, list)
        assert len(patterns) > 0
        cwe_ids = {p.source_cwe for p in patterns}
        assert "CWE-502" in cwe_ids

    def test_get_all_patterns_returns_list(self):
        extractor = PatternExtractor()
        cwe_entry = _make_cwe_obj("CWE-89")
        extractor.extract_from_cwe(cwe_entry)
        all_pats = extractor.get_all_patterns()
        assert isinstance(all_pats, list)
        assert len(all_pats) > 0

    def test_get_patterns_for_cwe_89_non_empty(self):
        extractor = PatternExtractor()
        cwe_entry = _make_cwe_obj("CWE-89")
        extractor.extract_from_cwe(cwe_entry)
        pats = extractor.get_patterns_for_cwe("CWE-89")
        assert isinstance(pats, list)
        assert len(pats) > 0
        for p in pats:
            assert p.source_cwe == "CWE-89"

    def test_get_patterns_by_type_vulnerability_returns_list(self):
        extractor = PatternExtractor()
        cwe_entry = _make_cwe_obj("CWE-89")
        extractor.extract_from_cwe(cwe_entry)
        vuln_pats = extractor.get_patterns_by_type(PatternType.VULNERABILITY)
        assert isinstance(vuln_pats, list)
        assert len(vuln_pats) > 0
        for p in vuln_pats:
            assert p.pattern_type == PatternType.VULNERABILITY

    def test_extract_all_with_corpus_returns_extraction_result(self):
        extractor = PatternExtractor()
        corpus = SecurityCorpus(load_embedded=True)
        result = extractor.extract_all(corpus)
        assert isinstance(result, ExtractionResult)
        assert isinstance(result.patterns_extracted, int)
        assert result.patterns_extracted >= 0
        assert isinstance(result.patterns, list)
        assert isinstance(result.patterns_by_type, dict)
        assert isinstance(result.errors, list)
        assert isinstance(result.elapsed_ms, float)

    def test_extract_all_populates_patterns(self):
        extractor = PatternExtractor()
        corpus = SecurityCorpus(load_embedded=True)
        result = extractor.extract_all(corpus)
        # Embedded corpus has CWE and CAPEC entries that produce patterns
        assert result.patterns_extracted > 0
        assert len(result.patterns) == result.patterns_extracted

    def test_extract_all_patterns_by_type_consistent(self):
        extractor = PatternExtractor()
        corpus = SecurityCorpus(load_embedded=True)
        result = extractor.extract_all(corpus)
        total_by_type = sum(result.patterns_by_type.values())
        assert total_by_type == result.patterns_extracted
