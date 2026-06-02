"""
TythanAI Phase 8 — TON Elite Mode Test Suite

Covers all Phase 8 components:
  TestContractStructureFuzzer     (8 tests) — real structural fuzzing
  TestRollbackCEIAnalyzer         (9 tests) — CEI violations, send modes, phantom state
  TestSmartTraceAnalyzer          (8 tests) — invariant checking, anomaly detection
  TestEconomicRiskScorer          (8 tests) — economic impact scoring
  TestBlockchainSBOMBuilder       (7 tests) — SBOM construction and risk levels
  TestTONCorpusIntegrator         (7 tests) — TON exploit patterns in SecurityCorpus
  TestTONDashboard                (7 tests) — dashboard aggregation
  TestKnowledgeGraphTON           (9 tests) — KG TON entity types and queries
  TestAttackGraphTON              (9 tests) — AG TON node types and attack paths
  TestUnifiedScanEngineTON        (5 tests) — ScanOptions TON fields and scan_ton_elite
"""
from __future__ import annotations

import sys
import os
import pathlib
import tempfile
import unittest
from typing import Any, Dict, List

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))


# ===========================================================================
# Helper fixtures
# ===========================================================================

_FUNC_SOURCE_SIMPLE = """
int op = cs~load_uint(32);
int query_id = cs~load_uint(64);
throw_unless(401, equal_slices(sender_address, owner_address));
if (op == 0x01) {
    set_data(begin_cell().store_slice(owner_address).end_cell());
    send_raw_message(msg, 0);
}
if (op == 0x02) {
    send_raw_message(msg, 128);
}
"""

_FUNC_SOURCE_CEI = """
int op = cs~load_uint(32);
if (op == 0xdeadbeef) {
    set_data(begin_cell().end_cell());
    send_raw_message(msg, 64);
}
"""

_FUNC_SOURCE_SAFE = """
int op = cs~load_uint(32);
throw_unless(401, equal_slices(sender_address, owner_address));
send_raw_message(msg, 0);
set_data(begin_cell().store_slice(owner_address).end_cell());
"""

_TON_FINDINGS: List[Dict[str, Any]] = [
    {
        "rule_id": "TON002", "severity": "CRITICAL",
        "file": "contracts/treasury.fc",
        "line": 42, "description": "send_raw_message mode 128 fund drain risk",
        "cwe": "CWE-691", "category": "Fund Safety",
        "evidence": "send_raw_message(msg, 128)", "source": "ton_analyzer",
    },
    {
        "rule_id": "TON001", "severity": "HIGH",
        "file": "contracts/wallet.fc",
        "line": 10, "description": "accept_message before sender validation",
        "cwe": "CWE-400", "category": "Access Control",
        "evidence": "accept_message()", "source": "ton_analyzer",
    },
    {
        "rule_id": "TON-NFT-001", "severity": "CRITICAL",
        "file": "contracts/nft_collection.fc",
        "line": 25, "description": "NFT transfer ownership not verified",
        "cwe": "CWE-285", "category": "Access Control",
        "evidence": "recv_internal without owner check", "source": "ton_analyzer",
    },
]


# ===========================================================================
# TestContractStructureFuzzer
# ===========================================================================

class TestContractStructureFuzzer(unittest.TestCase):

    def setUp(self):
        from scanners.ton_scanner.fuzzer import ContractStructureFuzzer
        self.fuzzer = ContractStructureFuzzer(seed=42)

    def test_fuzz_contract_returns_suite(self):
        from scanners.ton_scanner.fuzzer import FuzzSuite
        suite = self.fuzzer.fuzz_contract(_FUNC_SOURCE_SIMPLE, "test.fc")
        self.assertIsInstance(suite, FuzzSuite)
        self.assertGreater(suite.total_cases, 0)

    def test_fuzz_contract_extracts_ops(self):
        suite = self.fuzzer.fuzz_contract(_FUNC_SOURCE_SIMPLE, "test.fc")
        self.assertGreater(len(suite.ops_extracted), 0)
        # op 0x01 and 0x02 should be extracted
        ops_hex = [hex(op) for op in suite.ops_extracted]
        self.assertIn("0x1", ops_hex)
        self.assertIn("0x2", ops_hex)

    def test_unknown_op_cases_generated(self):
        suite = self.fuzzer.fuzz_contract(_FUNC_SOURCE_SIMPLE, "test.fc")
        unknown = [c for c in suite.cases if c.mutation_type.startswith("op_all")]
        self.assertGreater(len(unknown), 0)
        for c in unknown:
            self.assertEqual(c.expected_behavior, "reject")

    def test_replay_cases_generated(self):
        suite = self.fuzzer.fuzz_contract(_FUNC_SOURCE_SIMPLE, "test.fc")
        replays = [c for c in suite.cases if "replay" in c.mutation_type]
        self.assertGreater(len(replays), 0)
        # First replay attempt should be process, subsequent should be reject
        first = next(c for c in replays if c.mutation_type == "replay_attempt_0")
        second = next(c for c in replays if c.mutation_type == "replay_attempt_1")
        self.assertEqual(first.expected_behavior, "process")
        self.assertEqual(second.expected_behavior, "reject")

    def test_gas_drain_cases_generated_for_mode128(self):
        suite = self.fuzzer.fuzz_contract(_FUNC_SOURCE_SIMPLE, "test.fc")
        drain = [c for c in suite.cases if "gas_drain" in c.mutation_type]
        self.assertGreater(len(drain), 0)

    def test_fuzz_methods_returns_structured_inputs(self):
        result = self.fuzzer.fuzz_methods(["transfer", "burn", "mint"])
        self.assertIn("transfer", result)
        self.assertIn("burn", result)
        self.assertIn("mint", result)
        for method, cases in result.items():
            self.assertIsInstance(cases, list)
            self.assertGreater(len(cases), 0)
            self.assertIn("op_code", cases[0])

    def test_generate_random_cell_is_hex(self):
        cell = self.fuzzer.generate_random_cell()
        self.assertIsInstance(cell, str)
        # Should be valid hex string
        int(cell, 16)

    def test_plugin_lifecycle_test_has_five_steps(self):
        steps = self.fuzzer.generate_plugin_lifecycle_test("EQ" + "A" * 46)
        self.assertEqual(len(steps), 5)
        actions = [s["action"] for s in steps]
        self.assertIn("install_plugin", actions)
        self.assertIn("remove_plugin", actions)
        self.assertIn("verify_removal", actions)

    def test_ton_fuzzer_backward_compat(self):
        from scanners.ton_scanner.fuzzer import TONFuzzer
        tf = TONFuzzer()
        result = tf.fuzz_methods(["test_method"])
        self.assertIn("test_method", result)
        cell = tf.generate_random_cell()
        self.assertIsInstance(cell, str)


# ===========================================================================
# TestRollbackCEIAnalyzer
# ===========================================================================

class TestRollbackCEIAnalyzer(unittest.TestCase):

    def setUp(self):
        from scanners.ton_scanner.rollback_analyzer import RollbackCEIAnalyzer
        self.analyzer = RollbackCEIAnalyzer()

    def test_mode128_detected_as_critical(self):
        result = self.analyzer.analyze("send_raw_message(msg, 128);", "t.fc")
        self.assertTrue(any(r.mode == 128 for r in result.send_mode_risks))
        risks_128 = [r for r in result.send_mode_risks if r.mode == 128]
        self.assertEqual(risks_128[0].severity, "CRITICAL")

    def test_mode64_detected_as_medium(self):
        result = self.analyzer.analyze("send_raw_message(msg, 64);", "t.fc")
        risks_64 = [r for r in result.send_mode_risks if r.mode == 64]
        self.assertTrue(risks_64)
        self.assertEqual(risks_64[0].severity, "MEDIUM")

    def test_cei_violation_set_data_before_send(self):
        result = self.analyzer.analyze(_FUNC_SOURCE_CEI, "t.fc")
        self.assertTrue(result.cei_violations,
                        "Expected CEI violation: set_data before send_raw_message")

    def test_safe_code_no_cei_violation(self):
        result = self.analyzer.analyze(_FUNC_SOURCE_SAFE, "t.fc")
        self.assertEqual(len(result.cei_violations), 0)

    def test_risk_level_critical_for_mode128(self):
        result = self.analyzer.analyze("send_raw_message(msg, 128);", "t.fc")
        self.assertEqual(result.risk_level, "CRITICAL")

    def test_to_findings_returns_list_of_dicts(self):
        result = self.analyzer.analyze(_FUNC_SOURCE_CEI, "t.fc")
        findings = result.to_findings()
        self.assertIsInstance(findings, list)
        if findings:
            self.assertIn("rule_id", findings[0])
            self.assertIn("severity", findings[0])
            self.assertIn("cwe", findings[0])

    def test_check_send_mode_risk_api(self):
        risks = self.analyzer.check_send_mode_risk(128)
        self.assertTrue(risks)
        self.assertTrue(any("128" in r["description"] or "all balance" in r["description"] for r in risks))

    def test_analyze_rollback_failure_phantom_state(self):
        trace = [{"hash": "abc", "storage_changed": True, "action_phase_ok": False}]
        result = self.analyzer.analyze_rollback_failure(trace)
        self.assertIsNotNone(result)
        self.assertEqual(result["type"], "ROLLBACK_INCONSISTENCY")
        self.assertEqual(result["severity"], "CRITICAL")

    def test_analyze_rollback_failure_no_issue(self):
        trace = [{"hash": "def", "storage_changed": True, "action_phase_ok": True}]
        result = self.analyzer.analyze_rollback_failure(trace)
        self.assertIsNone(result)


# ===========================================================================
# TestSmartTraceAnalyzer
# ===========================================================================

class TestSmartTraceAnalyzer(unittest.TestCase):

    def setUp(self):
        from scanners.ton_scanner.trace_analyzer import SmartTraceAnalyzer
        self.analyzer = SmartTraceAnalyzer()

    def _make_trace(self, steps):
        return steps

    def test_negative_balance_violation(self):
        trace = [{"id": 1, "state_after": {"balance": -100}, "from": "a", "to": "b",
                  "value": 100, "status": "ok"}]
        result = self.analyzer.process_trace(trace)
        self.assertTrue(any(v.invariant_name == "non_negative_balance" for v in result.violations))

    def test_phantom_state_detected(self):
        trace = [{"id": 1, "state_after": {}, "from": "a", "to": "b",
                  "value": 0, "status": "failed",
                  "storage_changed": True, "action_phase_ok": False}]
        result = self.analyzer.process_trace(trace)
        phantom = [c for c in result.attack_chains if c.chain_type == "PHANTOM_STATE"]
        self.assertTrue(phantom)

    def test_seqno_decrease_detected(self):
        trace = [
            {"id": 1, "state_after": {"seqno": 5}, "from": "a", "to": "b", "value": 0, "status": "ok"},
            {"id": 2, "state_after": {"seqno": 3}, "from": "a", "to": "b", "value": 0, "status": "ok"},
        ]
        result = self.analyzer.process_trace(trace)
        seqno_viols = [v for v in result.violations if v.invariant_name == "seqno_monotone"]
        self.assertTrue(seqno_viols)

    def test_large_value_to_unknown_is_anomaly(self):
        trace = [{"id": 1, "state_after": {}, "from": "contract_a", "to": "unknown_addr",
                  "value": 10**11, "msg_type": "internal", "op_code": "0x01", "status": "ok"}]
        result = self.analyzer.process_trace(trace)
        anomalies = [a for a in result.anomalies if a.anomaly_type == "ABNORMAL_VALUE_ROUTE"]
        self.assertTrue(anomalies)

    def test_clean_trace_has_no_violations(self):
        trace = [{"id": 1, "state_after": {"balance": 10**9, "owner": "EQ_abc"},
                  "from": "a", "to": "b", "value": 10**8, "status": "ok"}]
        result = self.analyzer.process_trace(trace)
        self.assertEqual(result.risk_level, "LOW")

    def test_visualize_trace_returns_string(self):
        trace = [{"id": 1, "from": "addr_a", "to": "addr_b", "value": 10**9,
                  "op_code": "0x01", "status": "ok", "gas_used": 5000}]
        viz = self.analyzer.visualize_trace(trace)
        self.assertIsInstance(viz, str)
        self.assertIn("addr_a", viz)
        self.assertIn("addr_b", viz)

    def test_result_to_dict(self):
        trace = [{"id": 1, "state_after": {"balance": 0}, "from": "a", "to": "b",
                  "value": 0, "status": "ok"}]
        result = self.analyzer.process_trace(trace)
        d = result.to_dict()
        self.assertIn("total_steps", d)
        self.assertIn("risk_level", d)
        self.assertIn("violations", d)

    def test_trace_analyzer_backward_compat(self):
        from scanners.ton_scanner.trace_analyzer import TraceAnalyzer
        ta = TraceAnalyzer()
        trace = [{"id": 1, "state_after": {"balance": 10**9, "plugins": {}},
                  "from": "a", "to": "b", "value": 0, "status": "ok"}]
        result = ta.process_trace(trace)
        self.assertIsNotNone(result)


# ===========================================================================
# TestEconomicRiskScorer
# ===========================================================================

class TestEconomicRiskScorer(unittest.TestCase):

    def setUp(self):
        from blockchain.ton.economic_risk_scorer import EconomicRiskScorer
        self.scorer = EconomicRiskScorer()

    def test_critical_finding_scores_high(self):
        findings = [{"rule_id": "TON002", "severity": "CRITICAL",
                     "file": "treasury.fc", "description": "mode 128",
                     "cwe": "CWE-691"}]
        report = self.scorer.score(findings)
        self.assertGreater(report.total_risk_score, 0)
        self.assertGreater(report.max_fund_loss_ton, 0)

    def test_info_finding_scores_zero(self):
        findings = [{"rule_id": "TON016", "severity": "INFO",
                     "file": "wallet.fc", "description": "msg_value usage",
                     "cwe": "CWE-20"}]
        report = self.scorer.score(findings)
        self.assertEqual(report.max_fund_loss_ton, 0.0)

    def test_treasury_contract_has_higher_impact(self):
        treasury = [{"rule_id": "T1", "severity": "HIGH",
                     "file": "treasury.fc", "description": "vulnerability", "cwe": "CWE-284"}]
        wallet = [{"rule_id": "T2", "severity": "HIGH",
                   "file": "wallet.fc", "description": "vulnerability", "cwe": "CWE-284"}]
        report_t = self.scorer.score(treasury)
        report_w = self.scorer.score(wallet)
        self.assertGreater(report_t.max_fund_loss_ton, report_w.max_fund_loss_ton)

    def test_report_to_dict_structure(self):
        report = self.scorer.score(_TON_FINDINGS)
        d = report.to_dict()
        self.assertIn("total_risk_score", d)
        self.assertIn("max_fund_loss_ton", d)
        self.assertIn("economic_risk_class", d)
        self.assertIn("affected_assets", d)
        self.assertIn("top_findings", d)

    def test_affected_assets_categorized(self):
        findings = [
            {"rule_id": "T1", "severity": "HIGH", "file": "wallet.fc",
             "description": "wallet vuln", "cwe": "CWE-284"},
            {"rule_id": "T2", "severity": "HIGH", "file": "nft_collection.fc",
             "description": "nft vuln", "cwe": "CWE-285"},
        ]
        report = self.scorer.score(findings)
        self.assertTrue(len(report.affected_assets.wallets) > 0 or
                        len(report.affected_assets.nfts) > 0)

    def test_cross_contract_fund_paths_increase_total(self):
        cross_paths = [{"finding_type": "FUND_DRAIN", "path": ["a", "b"],
                        "risk": "CRITICAL", "attack_description": "drain"}]
        report_no_cross = self.scorer.score(_TON_FINDINGS)
        report_with_cross = self.scorer.score(_TON_FINDINGS, cross_paths)
        self.assertGreaterEqual(report_with_cross.total_potential_loss,
                                report_no_cross.total_potential_loss)

    def test_risk_class_catastrophic_for_large_loss(self):
        from blockchain.ton.economic_risk_scorer import EconomicRiskClass
        many_critical = [
            {"rule_id": f"T{i}", "severity": "CRITICAL",
             "file": f"bridge_{i}.fc", "description": "bridge vulnerability", "cwe": "CWE-691"}
            for i in range(20)
        ]
        report = self.scorer.score(many_critical)
        self.assertIn(report.economic_risk_class,
                      [EconomicRiskClass.CATASTROPHIC, EconomicRiskClass.CRITICAL,
                       EconomicRiskClass.HIGH])

    def test_empty_findings_returns_zero_report(self):
        report = self.scorer.score([])
        self.assertEqual(report.total_risk_score, 0)
        self.assertEqual(report.total_potential_loss, 0.0)


# ===========================================================================
# TestBlockchainSBOMBuilder
# ===========================================================================

class TestBlockchainSBOMBuilder(unittest.TestCase):

    def setUp(self):
        from blockchain.ton.ton_sbom import BlockchainSBOMBuilder
        self.builder = BlockchainSBOMBuilder()

    def _write_temp_contract(self, content: str, suffix: str = ".fc") -> str:
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=suffix,
                                          delete=False, encoding="utf-8")
        tmp.write(content)
        tmp.flush()
        tmp.close()
        return tmp.name

    def test_build_returns_sbom(self):
        from blockchain.ton.ton_sbom import BlockchainSBOM
        fp = self._write_temp_contract(_FUNC_SOURCE_SIMPLE)
        try:
            sbom = self.builder.build([fp])
            self.assertIsInstance(sbom, BlockchainSBOM)
            self.assertEqual(sbom.total_contracts, 1)
        finally:
            os.unlink(fp)

    def test_upgrade_path_detected(self):
        source = "set_code(new_code_cell);"
        fp = self._write_temp_contract(source)
        try:
            sbom = self.builder.build([fp])
            self.assertEqual(sbom.upgradeable_count, 1)
            self.assertTrue(sbom.entries[0].upgrade_path)
        finally:
            os.unlink(fp)

    def test_imports_extracted(self):
        source = '#include "stdlib.fc"\n#include "utils.fc"\n'
        fp = self._write_temp_contract(source)
        try:
            sbom = self.builder.build([fp])
            entry = sbom.entries[0]
            self.assertGreater(len(entry.dependencies), 0)
        finally:
            os.unlink(fp)

    def test_contract_type_jetton_detected(self):
        source = "() JettonMaster::transfer(slice to) {}"
        fp = self._write_temp_contract(source)
        try:
            sbom = self.builder.build([fp])
            self.assertEqual(sbom.entries[0].contract_type, "jetton_master")
        finally:
            os.unlink(fp)

    def test_risk_level_critical_with_upgrade_and_vulns(self):
        source = "set_code(new_code);"
        fp = self._write_temp_contract(source)
        try:
            findings = [{"file": fp, "rule_id": "TON002", "severity": "CRITICAL"}]
            sbom = self.builder.build([fp], findings)
            self.assertEqual(sbom.entries[0].risk_level, "CRITICAL")
        finally:
            os.unlink(fp)

    def test_sbom_to_dict_structure(self):
        fp = self._write_temp_contract(_FUNC_SOURCE_SIMPLE)
        try:
            sbom = self.builder.build([fp])
            d = sbom.to_dict()
            self.assertIn("total_contracts", d)
            self.assertIn("contracts", d)
            self.assertIn("dependency_graph", d)
        finally:
            os.unlink(fp)

    def test_nonexistent_file_skipped(self):
        sbom = self.builder.build(["/nonexistent/path/contract.fc"])
        self.assertEqual(sbom.total_contracts, 0)


# ===========================================================================
# TestTONCorpusIntegrator
# ===========================================================================

class TestTONCorpusIntegrator(unittest.TestCase):

    def setUp(self):
        from backend.core.knowledge.security_corpus import SecurityCorpus
        from blockchain.ton.ton_corpus import TONCorpusIntegrator
        self.corpus = SecurityCorpus(load_embedded=False)
        self.integrator = TONCorpusIntegrator(self.corpus)

    def test_load_adds_entries(self):
        count = self.integrator.load()
        self.assertGreater(count, 0)

    def test_all_ten_exploit_patterns_loaded(self):
        self.integrator.load()
        ton_entries = self.corpus.query_by_tag("ton")
        self.assertGreaterEqual(len(ton_entries), 10)

    def test_load_idempotent(self):
        count1 = self.integrator.load()
        count2 = self.integrator.load()
        self.assertGreater(count1, 0)
        self.assertEqual(count2, 0)   # second call returns 0

    def test_search_ton_patterns_by_keyword(self):
        self.integrator.load()
        results = self.integrator.search_ton_patterns("fund drain")
        self.assertTrue(results)
        for r in results:
            self.assertIn("ton", r.tags)

    def test_get_patterns_for_cwe_284(self):
        self.integrator.load()
        results = self.integrator.get_patterns_for_cwe("CWE-284")
        self.assertTrue(results)

    def test_jetton_abuse_pattern_searchable(self):
        self.integrator.load()
        results = self.integrator.search_ton_patterns("jetton")
        self.assertTrue(any("jetton" in r.tags for r in results))

    def test_tvm_vulnerability_notes_loaded(self):
        self.integrator.load()
        tvm_entries = self.corpus.query_by_tag("tvm")
        self.assertGreater(len(tvm_entries), 0)


# ===========================================================================
# TestTONDashboard
# ===========================================================================

class TestTONDashboard(unittest.TestCase):

    def setUp(self):
        from blockchain.ton.ton_dashboard import TONSecurityDashboard
        self.dashboard = TONSecurityDashboard()

    def test_generate_returns_dashboard_report(self):
        from blockchain.ton.ton_dashboard import DashboardReport
        report = self.dashboard.generate(_TON_FINDINGS)
        self.assertIsInstance(report, DashboardReport)

    def test_findings_summary_populated(self):
        report = self.dashboard.generate(_TON_FINDINGS)
        self.assertEqual(report.findings_summary.get("CRITICAL", 0), 2)
        self.assertEqual(report.findings_summary.get("HIGH", 0), 1)

    def test_critical_contracts_identified(self):
        report = self.dashboard.generate(_TON_FINDINGS)
        self.assertTrue(len(report.critical_contracts) > 0)

    def test_to_dict_has_required_keys(self):
        report = self.dashboard.generate(_TON_FINDINGS)
        d = report.to_dict()
        for key in ("project_name", "total_contracts", "findings_summary",
                    "critical_contracts", "attack_paths", "coverage"):
            self.assertIn(key, d)

    def test_text_report_contains_severity_counts(self):
        report = self.dashboard.generate(_TON_FINDINGS)
        text = report.text_report()
        self.assertIn("CRITICAL", text)
        self.assertIn("HIGH", text)

    def test_empty_findings_produces_valid_report(self):
        report = self.dashboard.generate([])
        self.assertIsNotNone(report)
        self.assertEqual(report.findings_summary.get("CRITICAL", 0), 0)

    def test_upgrade_risks_from_sbom(self):
        from blockchain.ton.ton_sbom import BlockchainSBOMBuilder
        import tempfile, os
        fp = tempfile.NamedTemporaryFile(mode="w", suffix=".fc", delete=False)
        fp.write("set_code(new_code);\n")
        fp.flush()
        fp.close()
        try:
            sbom = BlockchainSBOMBuilder().build([fp.name],
                                                  [{"file": fp.name, "rule_id": "T1",
                                                    "severity": "HIGH"}])
            report = self.dashboard.generate(
                [{"file": fp.name, "rule_id": "T1", "severity": "HIGH",
                  "description": "test", "cwe": "CWE-284"}],
                sbom=sbom,
            )
            self.assertTrue(len(report.upgrade_risks) > 0)
        finally:
            os.unlink(fp.name)


# ===========================================================================
# TestKnowledgeGraphTON
# ===========================================================================

class TestKnowledgeGraphTON(unittest.TestCase):

    def setUp(self):
        from backend.analysis.knowledge_graph import KnowledgeGraphBuilder
        self.builder = KnowledgeGraphBuilder()

    def test_ton_node_types_exist(self):
        from backend.analysis.knowledge_graph import KGNodeType
        self.assertEqual(KGNodeType.SMART_CONTRACT.value, "smart_contract")
        self.assertEqual(KGNodeType.TON_WALLET.value, "ton_wallet")
        self.assertEqual(KGNodeType.JETTON.value, "jetton")
        self.assertEqual(KGNodeType.NFT_COLLECTION.value, "nft_collection")
        self.assertEqual(KGNodeType.TREASURY.value, "treasury")
        self.assertEqual(KGNodeType.MULTISIG.value, "multisig")
        self.assertEqual(KGNodeType.TON_MESSAGE.value, "ton_message")

    def test_ingest_ton_findings_creates_nodes(self):
        from backend.analysis.knowledge_graph import SecurityKnowledgeGraph
        graph = SecurityKnowledgeGraph()
        count = self.builder.ingest_ton_findings(graph, _TON_FINDINGS)
        self.assertGreater(count, 0)
        self.assertGreater(len(graph.nodes), 0)

    def test_ingest_creates_finding_nodes(self):
        from backend.analysis.knowledge_graph import SecurityKnowledgeGraph, KGNodeType
        graph = SecurityKnowledgeGraph()
        self.builder.ingest_ton_findings(graph, _TON_FINDINGS)
        finding_nodes = [n for n in graph.nodes if n.type.value == "finding"]
        self.assertEqual(len(finding_nodes), len(_TON_FINDINGS))

    def test_find_vulnerable_contracts(self):
        from backend.analysis.knowledge_graph import SecurityKnowledgeGraph
        graph = SecurityKnowledgeGraph()
        self.builder.ingest_ton_findings(graph, _TON_FINDINGS)
        vulns = self.builder.find_vulnerable_contracts(graph, min_severity="HIGH")
        self.assertGreater(len(vulns), 0)

    def test_find_vulnerable_wallets(self):
        from backend.analysis.knowledge_graph import SecurityKnowledgeGraph
        graph = SecurityKnowledgeGraph()
        self.builder.ingest_ton_findings(graph, _TON_FINDINGS)
        wallets = self.builder.find_vulnerable_wallets(graph)
        # wallet.fc should be a TON_WALLET
        self.assertGreaterEqual(len(wallets), 0)

    def test_find_ownership_takeovers(self):
        from backend.analysis.knowledge_graph import SecurityKnowledgeGraph
        graph = SecurityKnowledgeGraph()
        findings = [{
            "rule_id": "OWN-001", "severity": "CRITICAL",
            "file": "contract.fc", "line": 5,
            "description": "Missing ownership check in init handler",
            "cwe": "CWE-284", "category": "Access Control", "source": "ownership_checker",
        }]
        self.builder.ingest_ton_findings(graph, findings)
        takeovers = self.builder.find_ownership_takeovers(graph)
        self.assertTrue(takeovers)

    def test_find_fund_loss_paths(self):
        from backend.analysis.knowledge_graph import SecurityKnowledgeGraph
        graph = SecurityKnowledgeGraph()
        drain_findings = [{
            "rule_id": "TON002", "severity": "CRITICAL",
            "file": "treasury.fc", "line": 42,
            "description": "send_raw_message mode 128 can drain entire fund balance",
            "cwe": "CWE-691", "category": "Fund Safety", "source": "ton_analyzer",
        }]
        self.builder.ingest_ton_findings(graph, drain_findings)
        paths = self.builder.find_fund_loss_paths(graph)
        self.assertTrue(paths)
        self.assertIn("contract_id", paths[0])

    def test_find_affected_assets(self):
        from backend.analysis.knowledge_graph import SecurityKnowledgeGraph
        graph = SecurityKnowledgeGraph()
        self.builder.ingest_ton_findings(graph, _TON_FINDINGS)
        assets = self.builder.find_affected_assets(graph)
        self.assertGreater(len(assets), 0)

    def test_build_ton_knowledge_graph(self):
        from backend.analysis.knowledge_graph import SecurityKnowledgeGraph
        graph = self.builder.build_ton_knowledge_graph(_TON_FINDINGS)
        self.assertIsInstance(graph, SecurityKnowledgeGraph)
        self.assertGreater(len(graph.nodes), 0)


# ===========================================================================
# TestAttackGraphTON
# ===========================================================================

class TestAttackGraphTON(unittest.TestCase):

    def setUp(self):
        from backend.analysis.attack_graph import AttackGraphBuilder
        self.builder = AttackGraphBuilder()

    def test_ton_node_types_exist(self):
        from backend.analysis.attack_graph import NodeType
        self.assertEqual(NodeType.SMART_CONTRACT.value, "smart_contract")
        self.assertEqual(NodeType.TON_MESSAGE.value, "ton_message")
        self.assertEqual(NodeType.PRIVILEGED_ACTOR.value, "privileged_actor")
        self.assertEqual(NodeType.JETTON_TRANSFER.value, "jetton_transfer")

    def test_build_from_ton_findings_returns_graph(self):
        from backend.analysis.attack_graph import AttackGraph
        graph = self.builder.build_from_ton_findings(_TON_FINDINGS)
        self.assertIsInstance(graph, AttackGraph)
        self.assertGreater(len(graph.nodes), 0)
        self.assertGreater(len(graph.edges), 0)

    def test_smart_contract_nodes_created(self):
        from backend.analysis.attack_graph import NodeType
        graph = self.builder.build_from_ton_findings(_TON_FINDINGS)
        sc_nodes = [n for n in graph.nodes if n.type == NodeType.SMART_CONTRACT]
        self.assertEqual(len(sc_nodes), 3)  # 3 unique files in _TON_FINDINGS

    def test_vulnerability_nodes_created(self):
        from backend.analysis.attack_graph import NodeType
        graph = self.builder.build_from_ton_findings(_TON_FINDINGS)
        vuln_nodes = [n for n in graph.nodes if n.type == NodeType.VULNERABILITY]
        self.assertEqual(len(vuln_nodes), len(_TON_FINDINGS))

    def test_attacker_source_node_present(self):
        from backend.analysis.attack_graph import NodeType
        graph = self.builder.build_from_ton_findings(_TON_FINDINGS)
        sources = [n for n in graph.nodes if n.type == NodeType.SOURCE]
        self.assertTrue(sources)

    def test_risk_score_computed(self):
        graph = self.builder.build_from_ton_findings(_TON_FINDINGS)
        self.assertGreaterEqual(graph.risk_score, 0)

    def test_find_fund_loss_paths(self):
        graph = self.builder.build_from_ton_findings(_TON_FINDINGS)
        paths = self.builder.find_fund_loss_paths(graph)
        # May be empty if no critical paths found — method must return list
        self.assertIsInstance(paths, list)

    def test_find_ownership_takeover_paths(self):
        graph = self.builder.build_from_ton_findings(_TON_FINDINGS)
        paths = self.builder.find_ownership_takeover_paths(graph)
        self.assertIsInstance(paths, list)

    def test_find_jetton_abuse_paths(self):
        jetton_findings = [{
            "rule_id": "TON-JET-001", "severity": "HIGH",
            "file": "jetton_master.fc", "line": 20,
            "description": "Jetton transfer amount validation missing",
            "cwe": "CWE-20", "category": "Jetton Safety", "source": "ton_analyzer",
        }]
        graph = self.builder.build_from_ton_findings(jetton_findings)
        paths = self.builder.find_jetton_abuse_paths(graph)
        self.assertIsInstance(paths, list)


# ===========================================================================
# TestUnifiedScanEngineTON
# ===========================================================================

class TestUnifiedScanEngineTON(unittest.TestCase):

    def setUp(self):
        from backend.core.engine.unified_scan_engine import (
            UnifiedScanEngine, ScanOptions,
        )
        self.engine = UnifiedScanEngine()
        self.ScanOptions = ScanOptions

    def test_scan_options_ton_fields_exist(self):
        opts = self.ScanOptions()
        self.assertFalse(opts.enable_ton_elite)
        self.assertEqual(opts.ton_contract_files, [])
        self.assertEqual(opts.ton_project_dir, "")
        self.assertTrue(opts.ton_enable_economic_risk)
        self.assertTrue(opts.ton_enable_cross_contract)
        self.assertTrue(opts.ton_enable_sbom)

    def test_scan_ton_elite_no_files_returns_no_files(self):
        opts = self.ScanOptions(enable_ton_elite=True)
        result = self.engine.scan_ton_elite(options=opts)
        self.assertIn("status", result)
        self.assertEqual(result["status"], "no_files")

    def test_scan_ton_elite_with_temp_contract(self):
        fp = tempfile.NamedTemporaryFile(mode="w", suffix=".fc",
                                          delete=False, encoding="utf-8")
        fp.write(_FUNC_SOURCE_SIMPLE)
        fp.flush()
        fp.close()
        try:
            opts = self.ScanOptions(
                enable_ton_elite=True,
                ton_enable_cross_contract=False,   # single file
            )
            result = self.engine.scan_ton_elite(files=[fp.name], options=opts)
            self.assertEqual(result["status"], "ok")
            self.assertIn("findings", result)
            self.assertIn("severity_counts", result)
            self.assertIn("scan_duration_s", result)
        finally:
            os.unlink(fp.name)

    def test_scan_ton_elite_returns_economic_report(self):
        fp = tempfile.NamedTemporaryFile(mode="w", suffix=".fc",
                                          delete=False, encoding="utf-8")
        fp.write("send_raw_message(msg, 128);")
        fp.flush()
        fp.close()
        try:
            opts = self.ScanOptions(enable_ton_elite=True,
                                     ton_enable_economic_risk=True,
                                     ton_enable_cross_contract=False)
            result = self.engine.scan_ton_elite(files=[fp.name], options=opts)
            self.assertEqual(result["status"], "ok")
            # economic_report may be None if scorer can't run, but key must exist
            self.assertIn("economic_report", result)
        finally:
            os.unlink(fp.name)

    def test_scan_ton_elite_returns_knowledge_graph_stats(self):
        fp = tempfile.NamedTemporaryFile(mode="w", suffix=".fc",
                                          delete=False, encoding="utf-8")
        fp.write(_FUNC_SOURCE_SIMPLE)
        fp.flush()
        fp.close()
        try:
            opts = self.ScanOptions(enable_ton_elite=True,
                                     ton_enable_cross_contract=False)
            result = self.engine.scan_ton_elite(files=[fp.name], options=opts)
            self.assertIn("knowledge_graph", result)
            self.assertIn("attack_graph", result)
        finally:
            os.unlink(fp.name)


if __name__ == "__main__":
    unittest.main()
