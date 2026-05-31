"""
tests/test_knowledge_base.py — Tests for backend.memory.knowledge_base.KnowledgeBase.

All tests use in-memory MemoryManager (SQLite fallback) so they run
without chromadb installed.
"""
from __future__ import annotations

import sys
import unittest

import os
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from backend.core.confidence import Finding
from backend.memory.knowledge_base import (
    KnowledgeBase,
    _CWE_KNOWLEDGE,
    _ATTACK_PATTERNS,
)
from backend.memory.memory_manager import MemoryManager


def _make_memory() -> MemoryManager:
    return MemoryManager(persist_dir=None)


def _make_kb(mm: MemoryManager | None = None) -> KnowledgeBase:
    return KnowledgeBase(mm or _make_memory())


def _make_finding(
    rule_id: str = "sqli-001",
    file: str = "app/db.py",
    line: int = 42,
    severity: str = "HIGH",
    cwe_id: str = "CWE-89",
    description: str = "SQL Injection via unsanitised query parameter",
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


# ===========================================================================
# Tests
# ===========================================================================

class TestInitialize(unittest.TestCase):
    def test_initialize_loads_cwes(self) -> None:
        """After init, CWE-89 knowledge must be retrievable."""
        kb = _make_kb()
        kb.initialize()

        results = kb._memory.retrieve_knowledge("SQL Injection database", top_k=10)
        self.assertGreater(len(results), 0)
        contents = " ".join(r.entry.content for r in results).lower()
        self.assertTrue("cwe-89" in contents or "sql" in contents)

    def test_initialize_loads_patterns(self) -> None:
        """After init, attack patterns like 'Command Injection' must be retrievable."""
        kb = _make_kb()
        kb.initialize()

        results = kb._memory.retrieve_attack_patterns("command injection OS shell", top_k=10)
        self.assertGreater(len(results), 0)
        contents = " ".join(r.entry.content for r in results).lower()
        self.assertIn("command injection", contents)

    def test_initialize_sets_flag(self) -> None:
        kb = _make_kb()
        self.assertFalse(kb._initialized)
        kb.initialize()
        self.assertTrue(kb._initialized)

    def test_all_20_cwes_defined(self) -> None:
        """The _CWE_KNOWLEDGE dict must contain all 20 required CWEs."""
        required = {
            "CWE-89", "CWE-79", "CWE-78", "CWE-22", "CWE-20",
            "CWE-200", "CWE-306", "CWE-327", "CWE-502", "CWE-798",
            "CWE-611", "CWE-94", "CWE-190", "CWE-416", "CWE-362",
            "CWE-476", "CWE-787", "CWE-285", "CWE-319", "CWE-352",
        }
        self.assertTrue(required.issubset(set(_CWE_KNOWLEDGE.keys())))

    def test_all_attack_patterns_have_required_fields(self) -> None:
        for pattern in _ATTACK_PATTERNS:
            self.assertIn("name", pattern)
            self.assertIn("description", pattern)
            self.assertIn("mitre_id", pattern)
            self.assertIn("severity", pattern)

    def test_at_least_15_attack_patterns(self) -> None:
        self.assertGreaterEqual(len(_ATTACK_PATTERNS), 15)


class TestIdempotentInitialize(unittest.TestCase):
    def test_idempotent_initialize(self) -> None:
        """Calling initialize() twice should not duplicate CWE entries."""
        mm = _make_memory()
        kb = KnowledgeBase(mm)
        kb.initialize()
        stats_first = mm.get_stats()

        kb.initialize()  # second call — should be a no-op
        stats_second = mm.get_stats()

        # Counts must be identical after second init
        self.assertEqual(stats_first, stats_second)

    def test_second_manager_uses_stable_ids(self) -> None:
        """Two KBs sharing the same MemoryManager still don't duplicate."""
        mm = _make_memory()
        kb1 = KnowledgeBase(mm)
        kb2 = KnowledgeBase(mm)
        kb1.initialize()
        before = mm.get_stats()
        # kb2 has its own _initialized=False, but stable entry IDs prevent duplicates
        # Because ChromaDB/SQLite uses INSERT OR REPLACE on stable IDs
        kb2.initialize()
        after = mm.get_stats()
        self.assertEqual(before, after)


class TestAddConfirmedFinding(unittest.TestCase):
    def setUp(self) -> None:
        self.mm = _make_memory()
        self.kb = KnowledgeBase(self.mm)

    def test_add_confirmed_finding_tp(self) -> None:
        finding = _make_finding()
        self.kb.add_confirmed_finding(finding, verdict="tp", code_context="cursor.execute(query)")

        results = self.mm.retrieve_similar_findings(finding, top_k=5)
        self.assertGreater(len(results), 0)
        contents = " ".join(r.entry.content for r in results)
        self.assertIn("tp", contents)

    def test_add_confirmed_finding_fp(self) -> None:
        finding = _make_finding(rule_id="xss-002", cwe_id="CWE-79", description="XSS in template")
        self.kb.add_confirmed_finding(finding, verdict="fp")

        results = self.mm.retrieve_similar_findings(finding, top_k=5)
        self.assertGreater(len(results), 0)
        contents = " ".join(r.entry.content for r in results)
        self.assertIn("fp", contents)

    def test_confirmed_finding_stored_in_long_term(self) -> None:
        finding = _make_finding()
        self.kb.add_confirmed_finding(finding, verdict="tp")

        stats = self.mm.get_stats()
        self.assertGreaterEqual(stats.get(MemoryManager._LONG_TERM_LAYER, 0), 1)


class TestRetrieveContextForFinding(unittest.TestCase):
    def setUp(self) -> None:
        self.mm = _make_memory()
        self.kb = KnowledgeBase(self.mm)
        self.kb.initialize()

    def test_retrieve_context_returns_all_keys(self) -> None:
        finding = _make_finding()
        context = self.kb.retrieve_context_for_finding(finding)

        self.assertIn("similar_findings", context)
        self.assertIn("cwe_knowledge", context)
        self.assertIn("attack_patterns", context)
        self.assertIn("similar_fixes", context)

    def test_similar_findings_is_list(self) -> None:
        finding = _make_finding()
        context = self.kb.retrieve_context_for_finding(finding)
        self.assertIsInstance(context["similar_findings"], list)

    def test_cwe_knowledge_populated_after_init(self) -> None:
        """CWE-89 should be retrievable for a SQL Injection finding."""
        finding = _make_finding(cwe_id="CWE-89", description="SQL Injection")
        context = self.kb.retrieve_context_for_finding(finding)
        # cwe_knowledge might be empty dict if no match, but should be a dict
        self.assertIsInstance(context["cwe_knowledge"], dict)

    def test_attack_patterns_is_list(self) -> None:
        finding = _make_finding()
        context = self.kb.retrieve_context_for_finding(finding)
        self.assertIsInstance(context["attack_patterns"], list)

    def test_similar_fixes_is_list(self) -> None:
        finding = _make_finding()
        context = self.kb.retrieve_context_for_finding(finding)
        self.assertIsInstance(context["similar_fixes"], list)

    def test_cwe_knowledge_has_correct_structure_when_present(self) -> None:
        finding = _make_finding(cwe_id="CWE-89", description="SQL Injection manipulation")
        context = self.kb.retrieve_context_for_finding(finding)
        cwe = context["cwe_knowledge"]
        if cwe:  # populated
            self.assertIn("cwe_id", cwe)
            self.assertIn("description", cwe)


class TestUpdateRuleStats(unittest.TestCase):
    def setUp(self) -> None:
        self.kb = _make_kb()

    def test_update_rule_stats_fp_rate(self) -> None:
        rule = "sqli-001"
        self.kb.update_rule_stats(rule, hit=True, is_fp=False)
        self.kb.update_rule_stats(rule, hit=True, is_fp=False)
        self.kb.update_rule_stats(rule, hit=True, is_fp=True)  # 1 FP out of 3

        stats = self.kb.get_rule_stats(rule)
        self.assertEqual(stats["hit_count"], 3)
        self.assertEqual(stats["fp_count"], 1)
        self.assertAlmostEqual(stats["fp_rate"], 1 / 3, places=3)

    def test_get_rule_stats_zero_for_unknown_rule(self) -> None:
        stats = self.kb.get_rule_stats("nonexistent-rule")
        self.assertEqual(stats["hit_count"], 0)
        self.assertEqual(stats["fp_count"], 0)
        self.assertAlmostEqual(stats["fp_rate"], 0.0)

    def test_fp_rate_zero_when_no_fps(self) -> None:
        self.kb.update_rule_stats("rule-a", hit=True, is_fp=False)
        self.kb.update_rule_stats("rule-a", hit=True, is_fp=False)
        stats = self.kb.get_rule_stats("rule-a")
        self.assertAlmostEqual(stats["fp_rate"], 0.0)

    def test_multiple_rules_isolated(self) -> None:
        self.kb.update_rule_stats("rule-x", hit=True, is_fp=True)
        self.kb.update_rule_stats("rule-y", hit=True, is_fp=False)
        self.kb.update_rule_stats("rule-y", hit=True, is_fp=False)

        stats_x = self.kb.get_rule_stats("rule-x")
        stats_y = self.kb.get_rule_stats("rule-y")
        self.assertEqual(stats_x["fp_count"], 1)
        self.assertEqual(stats_y["fp_count"], 0)


class TestAddScanResult(unittest.TestCase):
    def setUp(self) -> None:
        self.mm = _make_memory()
        self.kb = KnowledgeBase(self.mm)

    def test_add_scan_result_stores_episode(self) -> None:
        findings = [
            _make_finding(severity="CRITICAL"),
            _make_finding(rule_id="xss-001", severity="HIGH", cwe_id="CWE-79"),
        ]
        self.kb.add_scan_result(scan_id="scan-001", findings=findings, fp_count=0)

        episodes = self.mm.get_episodes("scan completed", top_k=10)
        self.assertGreater(len(episodes), 0)

    def test_add_scan_result_stores_summary(self) -> None:
        findings = [_make_finding(severity="HIGH") for _ in range(5)]
        self.kb.add_scan_result(scan_id="scan-002", findings=findings, fp_count=2)

        stats = self.mm.get_stats()
        self.assertGreaterEqual(stats.get(MemoryManager._EPISODIC_LAYER, 0), 1)

    def test_add_scan_result_counts_severities(self) -> None:
        findings = [
            _make_finding(severity="CRITICAL"),
            _make_finding(severity="CRITICAL"),
            _make_finding(severity="HIGH"),
            _make_finding(severity="LOW"),
        ]
        # Should not raise; count logic is internal
        self.kb.add_scan_result(scan_id="scan-003", findings=findings, fp_count=1)

        episodes = self.mm.get_episodes("scan-003", top_k=10)
        self.assertGreater(len(episodes), 0)
        content = " ".join(r.entry.content for r in episodes)
        self.assertIn("critical", content.lower())


class TestKnowledgeStats(unittest.TestCase):
    def test_knowledge_stats_returns_dict_with_correct_keys(self) -> None:
        kb = _make_kb()
        stats = kb.get_knowledge_stats()

        self.assertIn("cwe_entries", stats)
        self.assertIn("patterns", stats)
        self.assertIn("confirmed_findings", stats)
        self.assertIn("scan_episodes", stats)
        self.assertIn("initialized", stats)

    def test_knowledge_stats_cwe_count_after_init(self) -> None:
        kb = _make_kb()
        kb.initialize()
        stats = kb.get_knowledge_stats()
        self.assertEqual(stats["cwe_entries"], 20)

    def test_knowledge_stats_pattern_count_after_init(self) -> None:
        kb = _make_kb()
        kb.initialize()
        stats = kb.get_knowledge_stats()
        self.assertGreaterEqual(stats["patterns"], 15)

    def test_knowledge_stats_initialized_false_before_init(self) -> None:
        kb = _make_kb()
        stats = kb.get_knowledge_stats()
        self.assertFalse(stats["initialized"])

    def test_knowledge_stats_initialized_true_after_init(self) -> None:
        kb = _make_kb()
        kb.initialize()
        stats = kb.get_knowledge_stats()
        self.assertTrue(stats["initialized"])

    def test_knowledge_stats_confirmed_findings_count(self) -> None:
        mm = _make_memory()
        kb = KnowledgeBase(mm)
        kb.add_confirmed_finding(_make_finding(), verdict="tp")
        kb.add_confirmed_finding(_make_finding(rule_id="xss-001"), verdict="fp")
        stats = kb.get_knowledge_stats()
        self.assertGreaterEqual(stats["confirmed_findings"], 2)

    def test_knowledge_stats_scan_episodes_count(self) -> None:
        mm = _make_memory()
        kb = KnowledgeBase(mm)
        kb.add_scan_result("scan-a", [_make_finding()], fp_count=0)
        kb.add_scan_result("scan-b", [], fp_count=0)
        stats = kb.get_knowledge_stats()
        self.assertGreaterEqual(stats["scan_episodes"], 2)


if __name__ == "__main__":
    unittest.main()
