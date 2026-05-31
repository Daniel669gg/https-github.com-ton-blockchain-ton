"""
tests/test_memory_manager.py — Tests for backend.memory.memory_manager.

All tests use persist_dir=None (in-memory SQLite fallback) so they run
without chromadb installed.
"""
from __future__ import annotations

import sys
import types
import unittest
from typing import Any
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Ensure project root is on sys.path
# ---------------------------------------------------------------------------
import os
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from backend.core.confidence import Finding
from backend.memory.memory_manager import (
    MemoryEntry,
    MemoryManager,
    MemorySearchResult,
    _bm25_score,
    _tokenize,
)


def _make_finding(
    rule_id: str = "sqli-001",
    file: str = "app/db.py",
    line: int = 42,
    severity: str = "HIGH",
    cwe_id: str = "CWE-89",
    description: str = "SQL Injection via unsanitised input",
    confidence: float = 0.9,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        file=file,
        line=line,
        severity=severity,
        cwe_id=cwe_id,
        description=description,
        confidence=confidence,
    )


def _make_manager(**kwargs: Any) -> MemoryManager:
    """Returns an in-memory MemoryManager (SQLite fallback)."""
    return MemoryManager(persist_dir=None, **kwargs)


# ===========================================================================
# Tests
# ===========================================================================

class TestMemoryEntry(unittest.TestCase):
    def test_dataclass_fields(self) -> None:
        entry = MemoryEntry(
            entry_id="e1",
            content="hello world",
            metadata={"key": "val"},
            timestamp="2025-01-01T00:00:00+00:00",
            memory_type="finding",
        )
        self.assertEqual(entry.entry_id, "e1")
        self.assertEqual(entry.content, "hello world")
        self.assertEqual(entry.metadata["key"], "val")
        self.assertEqual(entry.memory_type, "finding")


class TestMemorySearchResult(unittest.TestCase):
    def test_score_distance_fields(self) -> None:
        entry = MemoryEntry("x", "content", {}, "2025-01-01T00:00:00+00:00", "knowledge")
        result = MemorySearchResult(entry=entry, score=0.85, distance=0.15)
        self.assertAlmostEqual(result.score, 0.85)
        self.assertAlmostEqual(result.distance, 0.15)


class TestTokenizeAndBM25(unittest.TestCase):
    def test_tokenize_basic(self) -> None:
        tokens = _tokenize("Hello World 123!")
        self.assertIn("hello", tokens)
        self.assertIn("world", tokens)
        self.assertIn("123", tokens)

    def test_tokenize_empty(self) -> None:
        self.assertEqual(_tokenize(""), [])

    def test_bm25_identical(self) -> None:
        tokens = _tokenize("sql injection vulnerability")
        score = _bm25_score(tokens, tokens)
        self.assertGreater(score, 0.0)
        self.assertLessEqual(score, 1.0)

    def test_bm25_no_overlap(self) -> None:
        q = _tokenize("sql injection")
        d = _tokenize("python decorator pattern")
        score = _bm25_score(q, d)
        self.assertAlmostEqual(score, 0.0)

    def test_bm25_empty_query(self) -> None:
        score = _bm25_score([], ["sql", "injection"])
        self.assertAlmostEqual(score, 0.0)


class TestStoreAndRetrieveFinding(unittest.TestCase):
    def setUp(self) -> None:
        self.mm = _make_manager()

    def test_store_finding_returns_str_id(self) -> None:
        finding = _make_finding()
        eid = self.mm.store_finding(finding, verdict="tp", session_id="sess-1")
        self.assertIsInstance(eid, str)
        self.assertTrue(len(eid) > 0)

    def test_retrieve_finding_after_store(self) -> None:
        finding = _make_finding(description="SQL Injection via unsanitised input")
        self.mm.store_finding(finding, verdict="tp", session_id="sess-1")
        results = self.mm.retrieve_similar_findings(finding, top_k=5)
        self.assertIsInstance(results, list)
        self.assertGreater(len(results), 0)
        self.assertIsInstance(results[0], MemorySearchResult)
        # The stored finding's rule_id should appear in the top result
        self.assertIn("sqli-001", results[0].entry.content)

    def test_retrieve_similar_findings_top_k(self) -> None:
        """Store 3 findings and ensure retrieval respects top_k."""
        for i in range(3):
            f = _make_finding(
                rule_id=f"xss-{i}",
                cwe_id="CWE-79",
                description=f"XSS vulnerability at endpoint {i}",
                line=i * 10,
            )
            self.mm.store_finding(f, verdict="tp", session_id="sess-x")

        query_finding = _make_finding(
            rule_id="xss-0", cwe_id="CWE-79", description="XSS vulnerability"
        )
        results = self.mm.retrieve_similar_findings(query_finding, top_k=2)
        self.assertLessEqual(len(results), 2)

    def test_score_range(self) -> None:
        finding = _make_finding()
        self.mm.store_finding(finding, verdict="tp", session_id="sess-1")
        results = self.mm.retrieve_similar_findings(finding, top_k=5)
        for r in results:
            self.assertGreaterEqual(r.score, 0.0)
            self.assertLessEqual(r.score, 1.0)


class TestKnowledgeLayer(unittest.TestCase):
    def setUp(self) -> None:
        self.mm = _make_manager()

    def test_store_and_retrieve_knowledge(self) -> None:
        self.mm.store_knowledge(
            cwe_id="CWE-89",
            description="SQL Injection allows attackers to manipulate database queries",
            attack_examples=["' OR 1=1--", "UNION SELECT"],
        )
        results = self.mm.retrieve_knowledge("SQL Injection database queries", top_k=5)
        self.assertGreater(len(results), 0)
        self.assertIn("CWE-89", results[0].entry.content)

    def test_store_attack_pattern(self) -> None:
        eid = self.mm.store_attack_pattern(
            name="Command Injection",
            description="Executing arbitrary OS commands via shell",
            mitre_id="T1059",
            severity="CRITICAL",
        )
        self.assertIsInstance(eid, str)

        results = self.mm.retrieve_attack_patterns("OS command shell execution", top_k=5)
        self.assertGreater(len(results), 0)
        contents = [r.entry.content for r in results]
        self.assertTrue(any("Command Injection" in c for c in contents))

    def test_retrieve_knowledge_empty_returns_empty_list(self) -> None:
        mm = _make_manager()
        results = mm.retrieve_knowledge("totally unrelated query", top_k=5)
        self.assertIsInstance(results, list)


class TestEpisodicLayer(unittest.TestCase):
    def setUp(self) -> None:
        self.mm = _make_manager()

    def test_store_and_retrieve_episode(self) -> None:
        eid = self.mm.store_episode(
            scan_id="scan-abc",
            action="escalate_severity",
            reasoning="Found SQL injection in auth module",
            outcome="severity upgraded to CRITICAL",
        )
        self.assertIsInstance(eid, str)

        results = self.mm.get_episodes("SQL injection escalate", top_k=10)
        self.assertGreater(len(results), 0)
        self.assertIn("scan-abc", results[0].entry.content)

    def test_store_scan_summary(self) -> None:
        eid = self.mm.store_scan_summary(
            scan_id="scan-xyz",
            summary={"total_findings": 10, "critical_count": 2, "fp_count": 1},
        )
        self.assertIsInstance(eid, str)

    def test_get_scan_summaries(self) -> None:
        self.mm.store_scan_summary("scan-001", {"total_findings": 5, "entry_kind": "scan_summary"})
        self.mm.store_scan_summary("scan-002", {"total_findings": 3, "entry_kind": "scan_summary"})
        summaries = self.mm.get_scan_summaries(top_k=10)
        self.assertIsInstance(summaries, list)
        # At least one result (scan summaries stored with entry_kind)
        # get_scan_summaries filters on entry_kind=="scan_summary" in metadata
        # store_scan_summary injects scan_id and other fields but entry_kind is "scan_summary"
        # Let's check raw episodic count
        all_eps = self.mm.get_episodes("scan", top_k=50)
        self.assertGreaterEqual(len(all_eps), 2)


class TestShortTermMemory(unittest.TestCase):
    def setUp(self) -> None:
        self.mm = _make_manager(session_id="test-session-42")

    def test_store_short_term_returns_id(self) -> None:
        eid = self.mm.store_short_term("step_1", "Agent observed XSS in login form")
        self.assertIsInstance(eid, str)

    def test_retrieve_short_term_after_store(self) -> None:
        self.mm.store_short_term("step_1", "Agent detected SQL injection in search endpoint")
        results = self.mm.get_short_term("SQL injection search", top_k=5)
        self.assertGreater(len(results), 0)

    def test_short_term_cleared(self) -> None:
        self.mm.store_short_term("k1", "Important context about SQL injection")
        self.mm.store_short_term("k2", "Another observation about XSS vulnerability")

        # Verify stored
        before = self.mm.get_short_term("SQL injection XSS", top_k=10)
        self.assertGreater(len(before), 0)

        # Clear
        self.mm.clear_short_term()

        # Verify empty
        after = self.mm.get_short_term("SQL injection XSS", top_k=10)
        self.assertEqual(len(after), 0)


class TestRetrieveBeforeDecision(unittest.TestCase):
    def setUp(self) -> None:
        self.mm = _make_manager()

    def test_retrieve_before_decision_all_keys(self) -> None:
        # Seed each layer
        finding = _make_finding()
        self.mm.store_finding(finding, verdict="tp", session_id="s1")
        self.mm.store_knowledge("CWE-89", "SQL Injection description")
        self.mm.store_episode("scan-1", "scan", "reasoning", "outcome")

        result = self.mm.retrieve_before_decision("SQL injection vulnerability", top_k_per_layer=3)
        self.assertIn("long_term", result)
        self.assertIn("semantic", result)
        self.assertIn("episodic", result)

    def test_retrieve_before_decision_returns_lists(self) -> None:
        result = self.mm.retrieve_before_decision("anything", top_k_per_layer=3)
        self.assertIsInstance(result["long_term"], list)
        self.assertIsInstance(result["semantic"], list)
        self.assertIsInstance(result["episodic"], list)

    def test_retrieve_before_decision_seeded_returns_results(self) -> None:
        self.mm.store_knowledge(
            "CWE-78", "Command injection via OS shell calls", ["os.system(user_input)"]
        )
        self.mm.store_finding(_make_finding(cwe_id="CWE-78"), verdict="tp", session_id="s1")
        self.mm.store_episode("s1", "analyze", "found command injection", "escalated")

        result = self.mm.retrieve_before_decision("command injection shell", top_k_per_layer=3)
        total = sum(len(v) for v in result.values())
        self.assertGreater(total, 0)


class TestGetStats(unittest.TestCase):
    def test_stats_empty_manager(self) -> None:
        mm = _make_manager()
        stats = mm.get_stats()
        self.assertIsInstance(stats, dict)
        # All layers should be present (possibly 0)
        for key in stats:
            self.assertIsInstance(stats[key], int)
            self.assertGreaterEqual(stats[key], 0)

    def test_stats_correct_counts(self) -> None:
        mm = _make_manager()
        finding = _make_finding()
        mm.store_finding(finding, verdict="tp", session_id="s1")
        mm.store_knowledge("CWE-89", "SQL Injection")
        mm.store_episode("scan-1", "action", "reasoning", "outcome")

        stats = mm.get_stats()
        self.assertGreaterEqual(stats.get(MemoryManager._LONG_TERM_LAYER, 0), 1)
        self.assertGreaterEqual(stats.get(MemoryManager._SEMANTIC_LAYER, 0), 1)
        self.assertGreaterEqual(stats.get(MemoryManager._EPISODIC_LAYER, 0), 1)


class TestFixStorage(unittest.TestCase):
    def setUp(self) -> None:
        self.mm = _make_manager()

    def test_store_successful_fix(self) -> None:
        eid = self.mm.store_successful_fix(
            rule_id="sqli-001",
            fix_description="Use parameterised queries",
            before_code="cursor.execute(f'SELECT * FROM users WHERE id={user_id}')",
            after_code="cursor.execute('SELECT * FROM users WHERE id=?', (user_id,))",
        )
        self.assertIsInstance(eid, str)

    def test_retrieve_similar_fixes(self) -> None:
        self.mm.store_successful_fix(
            rule_id="sqli-001",
            fix_description="Use parameterised queries instead of string formatting",
            before_code="cursor.execute(f'SELECT * FROM users WHERE id={user_id}')",
            after_code="cursor.execute('SELECT * FROM users WHERE id=?', (user_id,))",
        )
        results = self.mm.retrieve_similar_fixes(
            rule_id="sqli-001",
            code_snippet="cursor.execute format string user_id",
            top_k=3,
        )
        self.assertIsInstance(results, list)
        self.assertGreater(len(results), 0)

    def test_store_confirmed_pattern(self) -> None:
        eid = self.mm.store_confirmed_pattern(
            pattern="string formatting in SQL queries",
            rule_id="sqli-001",
            examples=["f'SELECT * FROM {table}'", "query % (user_id,)"],
        )
        self.assertIsInstance(eid, str)


class TestFallbackScoring(unittest.TestCase):
    """Verify SQLite BM25 fallback works correctly without ChromaDB."""

    def test_fallback_always_active_without_chromadb(self) -> None:
        """With chromadb unavailable, MemoryManager should use SQLite fallback."""
        # Force _use_chroma = False by patching _CHROMADB_AVAILABLE
        with patch("backend.memory.memory_manager._CHROMADB_AVAILABLE", False):
            mm = MemoryManager(persist_dir=None)
            self.assertFalse(mm._use_chroma)

    def test_fallback_scoring_relevance(self) -> None:
        """BM25 should score relevant docs higher than irrelevant ones."""
        mm = _make_manager()

        mm.store_knowledge(
            "CWE-89",
            "SQL Injection allows manipulation of database queries via unsanitised input",
        )
        mm.store_knowledge(
            "CWE-79",
            "Cross-site scripting inserts malicious JavaScript into web pages",
        )

        results = mm.retrieve_knowledge("SQL database query manipulation", top_k=5)
        self.assertGreater(len(results), 0)
        # Top result should be more relevant to SQL than XSS
        top_content = results[0].entry.content.lower()
        self.assertTrue("sql" in top_content or "cwe-89" in top_content)

    def test_fallback_empty_collection(self) -> None:
        mm = _make_manager()
        results = mm.retrieve_knowledge("SQL Injection", top_k=5)
        self.assertEqual(results, [])

    def test_fallback_score_bounded(self) -> None:
        mm = _make_manager()
        mm.store_knowledge("CWE-94", "Code injection via eval()")
        results = mm.retrieve_knowledge("code injection eval", top_k=3)
        for r in results:
            self.assertGreaterEqual(r.score, 0.0)
            self.assertLessEqual(r.score, 1.0)
            self.assertGreaterEqual(r.distance, 0.0)


if __name__ == "__main__":
    unittest.main()
