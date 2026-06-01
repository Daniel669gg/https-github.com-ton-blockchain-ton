"""TythanAI V6.5 Phase 5 — Security Research & Knowledge Acquisition Platform.

Tests for CorpusIngestionPipeline and IngestionResult.
"""
from __future__ import annotations

import sys
import pathlib

_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import pytest

from backend.core.knowledge.security_corpus import SecurityCorpus, CorpusEntryType
from backend.core.knowledge.ingestion_pipeline import CorpusIngestionPipeline, IngestionResult


# ---------------------------------------------------------------------------
# TestImports
# ---------------------------------------------------------------------------


class TestImports:
    def test_ingestion_pipeline_importable(self):
        assert CorpusIngestionPipeline is not None

    def test_ingestion_result_importable(self):
        assert IngestionResult is not None

    def test_pipeline_instantiable(self):
        corpus = SecurityCorpus(load_embedded=False)
        pipeline = CorpusIngestionPipeline(corpus)
        assert pipeline is not None


# ---------------------------------------------------------------------------
# TestIngestionResult
# ---------------------------------------------------------------------------


class TestIngestionResult:
    def test_default_entries_added_is_zero(self):
        result = IngestionResult()
        assert result.entries_added == 0

    def test_default_errors_is_empty(self):
        result = IngestionResult()
        assert result.errors == []

    def test_merge_combines_added_counts(self):
        r1 = IngestionResult(entries_added=3, entries_updated=1, entries_skipped=2, errors=["e1"])
        r2 = IngestionResult(entries_added=5, entries_updated=2, entries_skipped=0, errors=["e2", "e3"])
        merged = r1.merge(r2)
        assert merged.entries_added == 8
        assert merged.entries_updated == 3
        assert merged.entries_skipped == 2
        assert len(merged.errors) == 3

    def test_merge_returns_ingestion_result(self):
        r1 = IngestionResult(entries_added=1)
        r2 = IngestionResult(entries_added=2)
        merged = r1.merge(r2)
        assert isinstance(merged, IngestionResult)


# ---------------------------------------------------------------------------
# TestOfflineIngestion
# ---------------------------------------------------------------------------


class TestOfflineIngestion:
    def _fresh_pipeline(self) -> tuple[SecurityCorpus, CorpusIngestionPipeline]:
        """Return a corpus with NO embedded data so pipeline tests control ingestion."""
        corpus = SecurityCorpus(load_embedded=False)
        pipeline = CorpusIngestionPipeline(corpus)
        return corpus, pipeline

    def test_run_full_ingestion_returns_ingestion_result(self):
        corpus, pipeline = self._fresh_pipeline()
        result = pipeline.run_full_ingestion()
        assert isinstance(result, IngestionResult)

    def test_corpus_size_grows_after_full_ingestion(self):
        corpus, pipeline = self._fresh_pipeline()
        pipeline.run_full_ingestion()
        assert corpus.size > 0

    def test_ingest_cwe_specific_returns_ingestion_result(self):
        corpus, pipeline = self._fresh_pipeline()
        result = pipeline.ingest_cwe("CWE-89")
        assert isinstance(result, IngestionResult)

    def test_ingest_cwe_all_ingests_multiple_entries(self):
        corpus, pipeline = self._fresh_pipeline()
        result = pipeline.ingest_cwe()
        assert result.entries_added > 1, "Expected more than one CWE to be ingested"

    def test_ingest_capec_specific_returns_ingestion_result(self):
        corpus, pipeline = self._fresh_pipeline()
        result = pipeline.ingest_capec("CAPEC-66")
        assert isinstance(result, IngestionResult)

    def test_ingest_owasp_returns_ingestion_result(self):
        corpus, pipeline = self._fresh_pipeline()
        result = pipeline.ingest_owasp()
        assert isinstance(result, IngestionResult)

    def test_double_ingestion_is_idempotent(self):
        corpus, pipeline = self._fresh_pipeline()
        pipeline.run_full_ingestion()
        size_after_first = corpus.size

        pipeline.run_full_ingestion()
        size_after_second = corpus.size

        assert size_after_first == size_after_second, (
            "Double ingestion should not duplicate entries"
        )

    def test_ingested_count_positive_after_full_ingestion(self):
        corpus, pipeline = self._fresh_pipeline()
        result = pipeline.run_full_ingestion()
        assert result.entries_added > 0, "Expected entries_added > 0 after full ingestion"


# ---------------------------------------------------------------------------
# TestCVEIngestion
# ---------------------------------------------------------------------------


class TestCVEIngestion:
    def _fresh_pipeline(self) -> tuple[SecurityCorpus, CorpusIngestionPipeline]:
        corpus = SecurityCorpus(load_embedded=False)
        pipeline = CorpusIngestionPipeline(corpus)
        return corpus, pipeline

    def test_ingest_valid_cve_dict_returns_ingestion_result(self):
        corpus, pipeline = self._fresh_pipeline()
        cve_dict = {
            "cve_id": "CVE-2024-12345",
            "description": "SQL injection in Acme package",
            "cvss_v3": 9.8,
            "severity": "CRITICAL",
            "cwe_ids": ["CWE-89"],
            "epss_score": 0.75,
            "is_kev": False,
            "published": "2024-01-15",
            "affected_packages": ["acme==1.0.0"],
            "source": "NVD",
        }
        result = pipeline.ingest_cve_from_dict(cve_dict)
        assert isinstance(result, IngestionResult)
        assert result.entries_added == 1

    def test_missing_cve_id_causes_error(self):
        corpus, pipeline = self._fresh_pipeline()
        result = pipeline.ingest_cve_from_dict({"description": "no id here"})
        assert len(result.errors) >= 1, "Expected at least one error when cve_id is missing"

    def test_ingested_cve_appears_in_corpus_by_type(self):
        corpus, pipeline = self._fresh_pipeline()
        cve_dict = {
            "cve_id": "CVE-2024-99999",
            "description": "Remote code execution vulnerability",
            "cvss_v3": 8.1,
            "severity": "HIGH",
            "cwe_ids": ["CWE-78"],
            "epss_score": 0.2,
            "is_kev": True,
            "source": "NVD",
        }
        pipeline.ingest_cve_from_dict(cve_dict)
        cve_entries = corpus.query_by_type(CorpusEntryType.CVE)
        assert len(cve_entries) >= 1

    def test_cve_id_preserved_in_corpus_entry(self):
        corpus, pipeline = self._fresh_pipeline()
        cve_dict = {
            "cve_id": "CVE-2024-55555",
            "description": "Authentication bypass",
            "severity": "HIGH",
            "source": "NVD",
        }
        pipeline.ingest_cve_from_dict(cve_dict)
        entry = corpus.get("CVE-2024-55555")
        assert entry is not None
        assert entry.entry_id == "CVE-2024-55555"

    def test_severity_stored_in_corpus_entry(self):
        corpus, pipeline = self._fresh_pipeline()
        cve_dict = {
            "cve_id": "CVE-2024-77777",
            "description": "Denial of service",
            "severity": "MEDIUM",
            "cvss_v3": 5.0,
            "source": "NVD",
        }
        pipeline.ingest_cve_from_dict(cve_dict)
        entry = corpus.get("CVE-2024-77777")
        assert entry is not None
        # CVEEntry stores severity field
        assert hasattr(entry, "severity")
        assert entry.severity == "MEDIUM"
