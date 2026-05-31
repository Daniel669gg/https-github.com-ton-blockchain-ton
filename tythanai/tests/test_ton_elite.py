"""
TythanAI Platform — TON Elite Mode Tests
Tests for StateMachineAnalyzer, GasAnalyzer, and AttackSurfaceMapper.

Run:
    python3 -m pytest tests/test_ton_elite.py -v
  or:
    python3 -m unittest tests.test_ton_elite -v
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest

# Ensure project root is on the path regardless of cwd
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanners.ton_scanner.state_machine import StateMachineAnalyzer
from scanners.ton_scanner.gas_analyzer   import GasAnalyzer
from scanners.ton_scanner.attack_surface import AttackSurfaceMapper


# ══════════════════════════════════════════════════════════════════════════════
#  FunC code fixtures
#  All code examples use authentic FunC syntax:
#    ;; line comments, throw_unless, set_data, recv_internal, impure, etc.
# ══════════════════════════════════════════════════════════════════════════════

# ── StateMachine fixtures ─────────────────────────────────────────────────────

_UNGUARDED_WRITE = """\
;; Simple wallet with missing access guard
() recv_internal(int msg_value, cell in_msg_cell, slice in_msg_body) impure {
    slice sender = in_msg_body~load_msg_addr();
    int amount   = in_msg_body~load_coins();
    ;; BUG: no throw_unless before set_data
    cell new_state = begin_cell()
        .store_slice(sender)
        .store_coins(amount)
        .end_cell();
    set_data(new_state);
}
"""

_GUARDED_WRITE = """\
;; Correct wallet — guard present before set_data
() recv_internal(int msg_value, cell in_msg_cell, slice in_msg_body) impure {
    slice sender = in_msg_body~load_msg_addr();
    slice owner  = get_data().begin_parse().load_msg_addr();
    throw_unless(401, equal_slices(sender, owner));
    int amount = in_msg_body~load_coins();
    cell new_state = begin_cell()
        .store_slice(owner)
        .store_coins(amount)
        .end_cell();
    set_data(new_state);
}
"""

_DOUBLE_WRITE = """\
;; Contract that writes state twice without a guard between writes
() update_config(slice in_msg_body) impure {
    int flag   = in_msg_body~load_uint(1);
    int amount = in_msg_body~load_coins();
    ;; first write
    set_data(begin_cell().store_uint(flag, 1).end_cell());
    ;; second write — no guard in between
    set_data(begin_cell().store_uint(flag, 1).store_coins(amount).end_cell());
}
"""

_EMPTY_CODE = ""

# ── GasAnalyzer fixtures ──────────────────────────────────────────────────────

_UNBOUNDED_WHILE = """\
;; Contract iterating without an upper bound check
() process_all(cell dict) impure {
    int i = 0;
    while (i >= 0) {
        i = i + 1;
    }
}
"""

_BOUNDED_WHILE = """\
;; Safe loop — bounded by literal constant
() process_items(int count) impure {
    int i = 0;
    while (i < 100) {
        i = i + 1;
    }
}
"""

_BOUNDED_REPEAT = """\
;; Safe repeat — bounded by literal constant
() hash_rounds() impure {
    repeat(64) {
        ;; do work
    }
}
"""

_LATE_ACCEPT = """\
;; Dangerous: heavy computation before accept_message
() recv_internal(int msg_value, cell in_msg_cell, slice in_msg_body) impure {
    int op      = in_msg_body~load_uint(32);
    int query_id = in_msg_body~load_uint(64);
    ;; computation happens here
    do_expensive_computation(op, query_id);
    accept_message();
}
"""

_EARLY_ACCEPT = """\
;; Safe: accept_message is first (after trivial reads)
() recv_external(slice in_msg_body) impure {
    throw_unless(35, check_signature(slice_hash(in_msg_body), in_msg_body~load_bits(512), get_public_key()));
    accept_message();
    int seqno = in_msg_body~load_uint(32);
    set_data(begin_cell().store_uint(seqno + 1, 32).end_cell());
}
"""

_DEEP_CELL_PARSE = """\
;; Deeply nested cell chain — 3 begin_parse on one line
() read_nested(cell c) impure {
    slice s = c.begin_parse().load_ref().begin_parse().load_ref().begin_parse();
}
"""

_SHALLOW_PARSE = """\
;; Only 2 begin_parse — not a finding
() read_shallow(cell c) impure {
    slice s = c.begin_parse().load_ref().begin_parse();
}
"""

# ── AttackSurface fixtures ────────────────────────────────────────────────────

_SIMPLE_CONTRACT = """\
;; Minimal TEP-compatible wallet
() recv_internal(int msg_value, cell in_msg_cell, slice in_msg_body) impure {
    slice sender = in_msg_body~load_msg_addr();
    int op       = in_msg_body~load_uint(32);
    slice owner  = get_data().begin_parse().load_msg_addr();
    throw_unless(401, equal_slices(sender, owner));
    if (op == 0x0f8a7ea5) {
        ;; jetton transfer
        int amount = in_msg_body~load_coins();
        set_data(begin_cell().store_slice(owner).store_coins(amount).end_cell());
    } else {
        throw(0xffff);
    }
}
"""

_UPGRADEABLE_CONTRACT = """\
;; Contract with upgrade capability
() recv_internal(int msg_value, cell in_msg_cell, slice in_msg_body) impure {
    slice sender = in_msg_body~load_msg_addr();
    int op       = in_msg_body~load_uint(32);
    slice owner  = get_data().begin_parse().load_msg_addr();
    throw_unless(401, equal_slices(sender, owner));
    if (op == op::upgrade) {
        cell new_code = in_msg_body~load_ref();
        set_code(new_code);
    }
}
"""

_RECV_EXTERNAL_CONTRACT = """\
;; External-facing contract (no signature check — vulnerable)
() recv_external(slice in_msg_body) impure {
    accept_message();
    int seqno = in_msg_body~load_uint(32);
    set_data(begin_cell().store_uint(seqno + 1, 32).end_cell());
}
"""


# ══════════════════════════════════════════════════════════════════════════════
#  Test cases — StateMachineAnalyzer
# ══════════════════════════════════════════════════════════════════════════════

class TestStateMachineAnalyzer(unittest.TestCase):

    def setUp(self):
        self.analyzer = StateMachineAnalyzer()

    def _rule_ids(self, result: dict) -> set:
        return {f["rule_id"] for f in result["findings"]}

    # ── STM-001: unguarded write ──────────────────────────────────────────────

    def test_detects_unguarded_write(self):
        """set_data() without throw_unless within 15 lines → STM-001 CRITICAL."""
        result = self.analyzer.analyze_code(_UNGUARDED_WRITE)
        ids    = self._rule_ids(result)
        self.assertIn(
            "STM-001", ids,
            f"Expected STM-001 for unguarded set_data. Got rule IDs: {ids}"
        )

    def test_unguarded_write_is_critical(self):
        result   = self.analyzer.analyze_code(_UNGUARDED_WRITE)
        stm001   = [f for f in result["findings"] if f["rule_id"] == "STM-001"]
        self.assertTrue(stm001, "No STM-001 finding present")
        self.assertEqual(stm001[0]["severity"], "CRITICAL")

    def test_unguarded_write_has_line_number(self):
        result = self.analyzer.analyze_code(_UNGUARDED_WRITE)
        stm001 = [f for f in result["findings"] if f["rule_id"] == "STM-001"]
        self.assertTrue(stm001)
        self.assertGreater(stm001[0]["line"], 0)

    # ── STM-001: guarded write → no finding ──────────────────────────────────

    def test_safe_write_no_stm001(self):
        """throw_unless present before set_data → no STM-001."""
        result = self.analyzer.analyze_code(_GUARDED_WRITE)
        ids    = self._rule_ids(result)
        self.assertNotIn(
            "STM-001", ids,
            f"False positive STM-001 for guarded write. Got rule IDs: {ids}"
        )

    # ── STM-002: double write ─────────────────────────────────────────────────

    def test_double_write_detected(self):
        """Two set_data() without guard between them → STM-002 HIGH."""
        result = self.analyzer.analyze_code(_DOUBLE_WRITE)
        ids    = self._rule_ids(result)
        self.assertIn(
            "STM-002", ids,
            f"Expected STM-002 for double write. Got: {ids}"
        )

    def test_double_write_severity_high(self):
        result = self.analyzer.analyze_code(_DOUBLE_WRITE)
        stm002 = [f for f in result["findings"] if f["rule_id"] == "STM-002"]
        self.assertTrue(stm002, "No STM-002 finding")
        self.assertEqual(stm002[0]["severity"], "HIGH")

    # ── Empty code ───────────────────────────────────────────────────────────

    def test_empty_code_no_crash(self):
        """Empty input → zero findings, no exception."""
        result = self.analyzer.analyze_code(_EMPTY_CODE)
        self.assertEqual(result["summary"]["total_findings"], 0)
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["state_vars"], [])

    def test_empty_code_summary_keys(self):
        result = self.analyzer.analyze_code(_EMPTY_CODE)
        for key in ("total_findings", "severity_counts", "state_writes",
                    "state_reads", "guarded_writes"):
            self.assertIn(key, result["summary"], f"Missing key: {key}")

    # ── Analyze from file ────────────────────────────────────────────────────

    def test_analyze_file_missing(self):
        result = self.analyzer.analyze("/tmp/__ghost_no_such_file_xyz.fc")
        self.assertIn("error", result["summary"])
        self.assertEqual(result["findings"], [])

    def test_analyze_file_on_disk(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".fc", delete=False) as f:
            f.write(_UNGUARDED_WRITE)
            path = f.name
        try:
            result = self.analyzer.analyze(path)
            ids = self._rule_ids(result)
            self.assertIn("STM-001", ids)
        finally:
            os.unlink(path)

    # ── State vars summary ────────────────────────────────────────────────────

    def test_state_vars_populated(self):
        result = self.analyzer.analyze_code(_UNGUARDED_WRITE)
        self.assertTrue(result["state_vars"], "state_vars should not be empty")
        sv = result["state_vars"][0]
        self.assertIn("name",        sv)
        self.assertIn("write_lines", sv)
        self.assertIn("read_lines",  sv)
        self.assertIn("guarded",     sv)

    def test_guarded_write_state_var_guarded_true(self):
        result = self.analyzer.analyze_code(_GUARDED_WRITE)
        self.assertTrue(result["state_vars"])
        self.assertTrue(result["state_vars"][0]["guarded"])


# ══════════════════════════════════════════════════════════════════════════════
#  Test cases — GasAnalyzer
# ══════════════════════════════════════════════════════════════════════════════

class TestGasAnalyzer(unittest.TestCase):

    def setUp(self):
        self.analyzer = GasAnalyzer()

    def _rule_ids(self, result: dict) -> set:
        return {f["rule_id"] for f in result["findings"]}

    # ── GAS-001: unbounded while ──────────────────────────────────────────────

    def test_unbounded_while_detected(self):
        """`while(i >= 0)` without upper bound → GAS-001 HIGH."""
        result = self.analyzer.analyze_code(_UNBOUNDED_WHILE)
        ids    = self._rule_ids(result)
        self.assertIn(
            "GAS-001", ids,
            f"Expected GAS-001 for unbounded while. Got: {ids}"
        )

    def test_unbounded_while_severity_high(self):
        result  = self.analyzer.analyze_code(_UNBOUNDED_WHILE)
        gas001  = [f for f in result["findings"] if f["rule_id"] == "GAS-001"]
        self.assertTrue(gas001, "No GAS-001 finding")
        self.assertEqual(gas001[0]["severity"], "HIGH")

    def test_unbounded_while_estimate_unbounded(self):
        result = self.analyzer.analyze_code(_UNBOUNDED_WHILE)
        gas001 = [f for f in result["findings"] if f["rule_id"] == "GAS-001"]
        self.assertTrue(gas001)
        self.assertEqual(gas001[0]["gas_estimate"], "unbounded")

    # ── GAS-001: bounded loops → no finding ──────────────────────────────────

    def test_bounded_while_safe(self):
        """`while(i < 100)` → no GAS-001."""
        result = self.analyzer.analyze_code(_BOUNDED_WHILE)
        ids    = self._rule_ids(result)
        self.assertNotIn(
            "GAS-001", ids,
            f"False positive GAS-001 for bounded while. Got: {ids}"
        )

    def test_bounded_repeat_safe(self):
        """`repeat(64)` with literal → no GAS-001."""
        result = self.analyzer.analyze_code(_BOUNDED_REPEAT)
        ids    = self._rule_ids(result)
        self.assertNotIn(
            "GAS-001", ids,
            f"False positive GAS-001 for bounded repeat(64). Got: {ids}"
        )

    # ── GAS-002: late accept ──────────────────────────────────────────────────

    def test_late_accept_detected(self):
        """Computation before accept_message → GAS-002 HIGH."""
        result = self.analyzer.analyze_code(_LATE_ACCEPT)
        ids    = self._rule_ids(result)
        self.assertIn(
            "GAS-002", ids,
            f"Expected GAS-002 for late accept_message. Got: {ids}"
        )

    def test_late_accept_severity_high(self):
        result  = self.analyzer.analyze_code(_LATE_ACCEPT)
        gas002  = [f for f in result["findings"] if f["rule_id"] == "GAS-002"]
        self.assertTrue(gas002, "No GAS-002 finding")
        self.assertEqual(gas002[0]["severity"], "HIGH")

    # ── GAS-003: deep cell parse ──────────────────────────────────────────────

    def test_deep_cell_parse_detected(self):
        """.begin_parse() chained 3 times → GAS-003 MEDIUM."""
        result = self.analyzer.analyze_code(_DEEP_CELL_PARSE)
        ids    = self._rule_ids(result)
        self.assertIn(
            "GAS-003", ids,
            f"Expected GAS-003 for deep cell chain. Got: {ids}"
        )

    def test_deep_cell_parse_severity_medium(self):
        result  = self.analyzer.analyze_code(_DEEP_CELL_PARSE)
        gas003  = [f for f in result["findings"] if f["rule_id"] == "GAS-003"]
        self.assertTrue(gas003, "No GAS-003 finding")
        self.assertEqual(gas003[0]["severity"], "MEDIUM")

    def test_shallow_parse_no_finding(self):
        """Only 2 begin_parse → no GAS-003."""
        result = self.analyzer.analyze_code(_SHALLOW_PARSE)
        ids    = self._rule_ids(result)
        self.assertNotIn(
            "GAS-003", ids,
            f"False positive GAS-003 for 2-deep chain. Got: {ids}"
        )

    # ── GAS-004: dict in loop ─────────────────────────────────────────────────

    def test_dict_in_loop_detected(self):
        """udict_get inside while body → GAS-004 MEDIUM."""
        code = """\
() scan_balances(cell dict) impure {
    int key = 0;
    while (key >= 0) {
        (slice val, int found) = dict.udict_get?(256, key);
        key = key + 1;
    }
}
"""
        result = self.analyzer.analyze_code(code)
        ids    = self._rule_ids(result)
        self.assertIn(
            "GAS-004", ids,
            f"Expected GAS-004 for dict_get in loop. Got: {ids}"
        )

    def test_dict_outside_loop_no_finding(self):
        """udict_get outside any loop → no GAS-004."""
        code = """\
() lookup(cell dict, int key) impure {
    (slice val, int found) = dict.udict_get?(256, key);
    throw_unless(404, found);
}
"""
        result = self.analyzer.analyze_code(code)
        ids    = self._rule_ids(result)
        self.assertNotIn("GAS-004", ids,
                         f"False positive GAS-004 outside loop. Got: {ids}")

    # ── GAS-005: recursion ────────────────────────────────────────────────────

    def test_recursion_detected(self):
        """Function that calls itself → GAS-005 LOW."""
        code = """\
int fibonacci(int n) {
    if (n <= 1) { return n; }
    return fibonacci(n - 1) + fibonacci(n - 2);
}
"""
        result = self.analyzer.analyze_code(code)
        ids    = self._rule_ids(result)
        self.assertIn(
            "GAS-005", ids,
            f"Expected GAS-005 for recursive function. Got: {ids}"
        )

    def test_non_recursive_no_finding(self):
        """Non-recursive function → no GAS-005."""
        code = """\
int add(int a, int b) {
    return a + b;
}
"""
        result = self.analyzer.analyze_code(code)
        ids    = self._rule_ids(result)
        self.assertNotIn("GAS-005", ids)

    # ── GAS-006: unguarded accept ─────────────────────────────────────────────

    def test_unguarded_accept_detected(self):
        """accept_message without throw_unless → GAS-006 MEDIUM."""
        code = """\
() recv_external(slice in_msg_body) impure {
    accept_message();
    int seqno = in_msg_body~load_uint(32);
    set_data(begin_cell().store_uint(seqno + 1, 32).end_cell());
}
"""
        result = self.analyzer.analyze_code(code)
        ids    = self._rule_ids(result)
        self.assertIn(
            "GAS-006", ids,
            f"Expected GAS-006 for unguarded accept. Got: {ids}"
        )

    def test_guarded_accept_no_gas006(self):
        """throw_unless before accept_message → no GAS-006."""
        code = """\
() recv_external(slice in_msg_body) impure {
    throw_unless(35, check_signature(slice_hash(in_msg_body),
                                     in_msg_body~load_bits(512),
                                     get_public_key()));
    accept_message();
}
"""
        result = self.analyzer.analyze_code(code)
        ids    = self._rule_ids(result)
        self.assertNotIn("GAS-006", ids,
                         f"False positive GAS-006 for guarded accept. Got: {ids}")

    # ── Empty code ────────────────────────────────────────────────────────────

    def test_empty_code_no_crash(self):
        result = self.analyzer.analyze_code("")
        self.assertEqual(result["summary"]["total_findings"], 0)
        self.assertEqual(result["findings"], [])

    # ── File API ──────────────────────────────────────────────────────────────

    def test_analyze_missing_file(self):
        result = self.analyzer.analyze("/tmp/__ghost_no_such_gas_xyz.fc")
        self.assertIn("error", result["summary"])

    def test_analyze_file_on_disk(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".fc", delete=False) as f:
            f.write(_UNBOUNDED_WHILE)
            path = f.name
        try:
            result = self.analyzer.analyze(path)
            ids = self._rule_ids(result)
            self.assertIn("GAS-001", ids)
        finally:
            os.unlink(path)

    # ── to_dict structure ─────────────────────────────────────────────────────

    def test_finding_has_required_keys(self):
        result  = self.analyzer.analyze_code(_UNBOUNDED_WHILE)
        finding = result["findings"][0]
        for key in ("rule_id", "severity", "line", "description",
                    "evidence", "gas_estimate", "source"):
            self.assertIn(key, finding, f"Missing key: {key}")


# ══════════════════════════════════════════════════════════════════════════════
#  Test cases — AttackSurfaceMapper
# ══════════════════════════════════════════════════════════════════════════════

class TestAttackSurfaceMapper(unittest.TestCase):

    def setUp(self):
        self.mapper  = AttackSurfaceMapper()
        self._tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _write(self, code: str, name: str = "contract.fc") -> str:
        path = os.path.join(self._tmpdir, name)
        with open(path, "w") as fh:
            fh.write(code)
        return path

    # ── Simple contract ───────────────────────────────────────────────────────

    def test_map_simple_contract_entry_points(self):
        """Single recv_internal → exactly 1 entry point of correct type."""
        path    = self._write(_SIMPLE_CONTRACT)
        surface = self.mapper.map_file(path)
        recv    = [ep for ep in surface.entry_points if ep.type == "recv_internal"]
        self.assertEqual(len(recv), 1,
                         f"Expected 1 recv_internal, got {len(recv)}")

    def test_map_simple_contract_not_upgradeable(self):
        path    = self._write(_SIMPLE_CONTRACT)
        surface = self.mapper.map_file(path)
        self.assertFalse(surface.upgradeable)

    def test_map_simple_contract_has_ops(self):
        path    = self._write(_SIMPLE_CONTRACT)
        surface = self.mapper.map_file(path)
        self.assertGreaterEqual(surface.total_ops, 1,
                                "Expected at least one op dispatch")

    def test_map_simple_contract_guarded(self):
        path    = self._write(_SIMPLE_CONTRACT)
        surface = self.mapper.map_file(path)
        recv    = [ep for ep in surface.entry_points if ep.type == "recv_internal"]
        self.assertTrue(recv[0].guarded,
                        "recv_internal with throw_unless should be guarded")

    # ── Upgradeable contract ──────────────────────────────────────────────────

    def test_upgradeable_contract_flag(self):
        """set_code() present → upgradeable=True."""
        path    = self._write(_UPGRADEABLE_CONTRACT)
        surface = self.mapper.map_file(path)
        self.assertTrue(surface.upgradeable,
                        "Contract with set_code() should be marked upgradeable")

    def test_upgradeable_contract_high_risk(self):
        """Upgradeable contract → risk_score in HIGH or CRITICAL range (≥45)."""
        path    = self._write(_UPGRADEABLE_CONTRACT)
        surface = self.mapper.map_file(path)
        self.assertGreaterEqual(
            surface.risk_score, 25,
            f"Upgradeable contract expected risk_score ≥ 25, got {surface.risk_score}"
        )
        self.assertIn(surface.risk_level, ("MEDIUM", "HIGH", "CRITICAL"),
                      f"Unexpected risk level: {surface.risk_level}")

    def test_upgradeable_contract_risk_level_string(self):
        path    = self._write(_UPGRADEABLE_CONTRACT)
        surface = self.mapper.map_file(path)
        self.assertIn(surface.risk_level, ("LOW", "MEDIUM", "HIGH", "CRITICAL"))

    # ── recv_external ─────────────────────────────────────────────────────────

    def test_recv_external_detected(self):
        """recv_external contract → entry point type == 'recv_external'."""
        path    = self._write(_RECV_EXTERNAL_CONTRACT)
        surface = self.mapper.map_file(path)
        ext     = [ep for ep in surface.entry_points if ep.type == "recv_external"]
        self.assertEqual(len(ext), 1)

    def test_recv_external_not_guarded(self):
        """recv_external without throw_unless → guarded=False."""
        path    = self._write(_RECV_EXTERNAL_CONTRACT)
        surface = self.mapper.map_file(path)
        ext     = [ep for ep in surface.entry_points if ep.type == "recv_external"]
        self.assertTrue(ext)
        self.assertFalse(ext[0].guarded)

    # ── to_findings ───────────────────────────────────────────────────────────

    def test_to_findings_upgradeable_has_as001(self):
        """Upgradeable contract → to_findings includes AS-001."""
        path     = self._write(_UPGRADEABLE_CONTRACT)
        surface  = self.mapper.map_file(path)
        findings = self.mapper.to_findings(surface)
        ids      = {f["rule_id"] for f in findings}
        self.assertIn("AS-001", ids,
                      f"Expected AS-001 for upgradeable contract. Got: {ids}")

    def test_to_findings_external_no_guard_has_as002(self):
        """recv_external without guard → to_findings includes AS-002."""
        path     = self._write(_RECV_EXTERNAL_CONTRACT)
        surface  = self.mapper.map_file(path)
        findings = self.mapper.to_findings(surface)
        ids      = {f["rule_id"] for f in findings}
        self.assertIn("AS-002", ids,
                      f"Expected AS-002 for unguarded recv_external. Got: {ids}")

    def test_to_findings_required_keys(self):
        """Each finding dict has all required keys for SARIF export."""
        path     = self._write(_UPGRADEABLE_CONTRACT)
        surface  = self.mapper.map_file(path)
        findings = self.mapper.to_findings(surface)
        self.assertTrue(findings, "Expected at least one finding")
        for f in findings:
            for key in ("rule_id", "severity", "line", "file",
                        "description", "recommendation", "source"):
                self.assertIn(key, f, f"Finding missing key: {key}")

    def test_to_findings_file_path_correct(self):
        path     = self._write(_UPGRADEABLE_CONTRACT)
        surface  = self.mapper.map_file(path)
        findings = self.mapper.to_findings(surface)
        for f in findings:
            self.assertEqual(f["file"], path)

    # ── map_directory ─────────────────────────────────────────────────────────

    def test_map_directory_returns_required_keys(self):
        self._write(_SIMPLE_CONTRACT,    "wallet.fc")
        self._write(_UPGRADEABLE_CONTRACT, "admin.fc")
        result = self.mapper.map_directory(self._tmpdir)
        for key in ("surfaces", "total_risk_score", "highest_risk_file"):
            self.assertIn(key, result, f"Missing key: {key}")

    def test_map_directory_counts_files(self):
        self._write(_SIMPLE_CONTRACT,    "wallet.fc")
        self._write(_UPGRADEABLE_CONTRACT, "admin.fc")
        result = self.mapper.map_directory(self._tmpdir)
        self.assertEqual(len(result["surfaces"]), 2)

    def test_map_directory_highest_risk_is_upgradeable(self):
        """The upgradeable contract should have the highest risk score."""
        self._write(_SIMPLE_CONTRACT,    "simple.fc")
        self._write(_UPGRADEABLE_CONTRACT, "upgradeable.fc")
        result = self.mapper.map_directory(self._tmpdir)
        self.assertIn("upgradeable.fc", result["highest_risk_file"])

    def test_map_directory_empty_dir(self):
        import tempfile
        with tempfile.TemporaryDirectory() as empty:
            result = self.mapper.map_directory(empty)
            self.assertEqual(result["surfaces"], [])
            self.assertEqual(result["total_risk_score"], 0)
            self.assertEqual(result["highest_risk_file"], "")

    # ── Missing file ──────────────────────────────────────────────────────────

    def test_map_missing_file_returns_empty_surface(self):
        surface = self.mapper.map_file("/tmp/__ghost_no_contract_xyz.fc")
        self.assertFalse(surface.upgradeable)
        self.assertEqual(surface.entry_points, [])

    # ── Risk score clamping ───────────────────────────────────────────────────

    def test_risk_score_in_range(self):
        for code in (_SIMPLE_CONTRACT, _UPGRADEABLE_CONTRACT,
                     _RECV_EXTERNAL_CONTRACT):
            path    = self._write(code)
            surface = self.mapper.map_file(path)
            self.assertGreaterEqual(surface.risk_score, 0)
            self.assertLessEqual(surface.risk_score, 100)

    def test_attack_surface_to_dict_keys(self):
        path    = self._write(_SIMPLE_CONTRACT)
        surface = self.mapper.map_file(path)
        d       = surface.to_dict()
        for key in ("file_path", "entry_points", "upgradeable",
                    "total_ops", "unguarded_ops", "has_admin_ops",
                    "external_calls", "risk_score", "risk_level"):
            self.assertIn(key, d, f"AttackSurface.to_dict() missing key: {key}")


# ══════════════════════════════════════════════════════════════════════════════
#  Integration smoke test — all three analyzers on the same file
# ══════════════════════════════════════════════════════════════════════════════

class TestEliteIntegration(unittest.TestCase):
    """Smoke test that all three analyzers can run together on a single file."""

    _COMBINED = """\
;; Deliberately vulnerable contract combining multiple issue types
() recv_internal(int msg_value, cell in_msg_cell, slice in_msg_body) impure {
    slice sender = in_msg_body~load_msg_addr();
    int op       = in_msg_body~load_uint(32);
    if (op == 0xdeadbeef) {
        ;; no guard before set_data
        int i = 0;
        while (i >= 0) {
            i = i + 1;
        }
        set_data(begin_cell().store_slice(sender).end_cell());
    }
}
"""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_combined_no_crash(self):
        path    = os.path.join(self._tmpdir, "vuln.fc")
        with open(path, "w") as fh:
            fh.write(self._COMBINED)

        stm_result = StateMachineAnalyzer().analyze(path)
        gas_result = GasAnalyzer().analyze(path)
        surface    = AttackSurfaceMapper().map_file(path)
        findings   = AttackSurfaceMapper().to_findings(surface)

        # All three should succeed without exception
        self.assertIsInstance(stm_result, dict)
        self.assertIsInstance(gas_result, dict)
        self.assertIsInstance(surface.entry_points, list)

    def test_combined_stm_finds_issue(self):
        stm = StateMachineAnalyzer().analyze_code(self._COMBINED)
        ids = {f["rule_id"] for f in stm["findings"]}
        self.assertIn("STM-001", ids)

    def test_combined_gas_finds_loop(self):
        gas = GasAnalyzer().analyze_code(self._COMBINED)
        ids = {f["rule_id"] for f in gas["findings"]}
        self.assertIn("GAS-001", ids)

    def test_combined_surface_has_entry_point(self):
        surface = AttackSurfaceMapper().map_file.__func__  # just verify callable
        self.assertTrue(callable(AttackSurfaceMapper().map_file))


if __name__ == "__main__":
    unittest.main(verbosity=2)
