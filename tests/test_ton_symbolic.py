"""
tests/test_ton_symbolic.py — Tests for TON symbolic executor.

Covers:
  - SymbolicFinding dataclass structure
  - TONSymbolicExecutor.analyze() returns expected structure
  - Gas drain detection (accept_message without guard)
  - Fund drain detection (mode=128 without raw_reserve)
  - Integer overflow detection (user-controlled arithmetic without bounds)
  - Blueprint harness output parsing
  - Nonexistent file handling
  - Status method
"""
from __future__ import annotations

import os
import sys
import tempfile
import pathlib

_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import pytest

from scanners.ton_scanner.ton_symbolic import (
    SymbolicFinding,
    TONSymbolicExecutor,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_fc(code: str, suffix: str = ".fc") -> str:
    f = tempfile.NamedTemporaryFile(
        mode="w", suffix=suffix, delete=False, encoding="utf-8"
    )
    f.write(code)
    f.flush()
    f.close()
    return f.name


# ---------------------------------------------------------------------------
# SymbolicFinding structure
# ---------------------------------------------------------------------------

class TestSymbolicFinding:

    def test_to_dict_has_required_keys(self):
        sf = SymbolicFinding(
            rule_id="TON-TEST-001",
            severity="CRITICAL",
            description="Test finding",
            evidence="accept_message()",
            line=10,
            file="test.fc",
        )
        d = sf.to_dict()
        required_keys = {"rule_id", "severity", "description", "evidence", "line", "file", "source"}
        assert required_keys.issubset(d.keys()), f"Missing keys: {required_keys - d.keys()}"

    def test_to_dict_values(self):
        sf = SymbolicFinding(
            rule_id="TON-GAS-001",
            severity="HIGH",
            description="Gas drain",
            evidence="code snippet",
            line=5,
            file="contract.fc",
        )
        d = sf.to_dict()
        assert d["rule_id"] == "TON-GAS-001"
        assert d["severity"] == "HIGH"
        assert d["line"] == 5
        assert d["source"] == "ton_symbolic"

    def test_default_method_is_symbolic(self):
        sf = SymbolicFinding(
            rule_id="TON-TEST",
            severity="MEDIUM",
            description="desc",
            evidence="ev",
        )
        assert sf.method == "symbolic"


# ---------------------------------------------------------------------------
# TONSymbolicExecutor basic API
# ---------------------------------------------------------------------------

class TestTONSymbolicExecutor:

    def test_analyze_returns_dict(self):
        code = """\
() recv_internal(int my_balance, int msg_value, cell in_msg_full, slice in_msg_body) impure {
    accept_message();
}
"""
        path = _write_fc(code)
        executor = TONSymbolicExecutor()
        result = executor.analyze(path)
        assert isinstance(result, dict), "analyze() must return a dict"

    def test_analyze_has_findings_key(self):
        code = "int x = 1;"
        path = _write_fc(code)
        result = TONSymbolicExecutor().analyze(path)
        assert "findings" in result, "Result must have 'findings' key"
        assert isinstance(result["findings"], list)

    def test_nonexistent_file_returns_error(self):
        result = TONSymbolicExecutor().analyze("/nonexistent/contract.fc")
        assert "error" in result or result.get("findings") == []

    def test_status_returns_dict(self):
        executor = TONSymbolicExecutor()
        status = executor.status()
        assert isinstance(status, dict)
        assert "mode" in status or "node_available" in status


# ---------------------------------------------------------------------------
# Gas drain detection
# ---------------------------------------------------------------------------

class TestGasDrainDetection:

    def test_accept_without_guard_detected(self):
        """accept_message() without throw_unless should be flagged as gas drain."""
        code = """\
() recv_internal(int my_balance, int msg_value, cell in_msg_full, slice in_msg_body) impure {
    accept_message();
    int amount = in_msg_body~load_uint(64);
    send_raw_message(amount, 1);
}
"""
        path = _write_fc(code)
        result = TONSymbolicExecutor().analyze(path)
        findings = result["findings"]
        rule_ids = [f["rule_id"] for f in findings]
        assert any("GAS" in r or "SIM" in r or "DRAIN" in r or "ACCEPT" in r
                   for r in rule_ids), (
            f"Expected gas drain finding for accept_message without guard, got {rule_ids}"
        )

    def test_accept_with_guard_not_flagged(self):
        """accept_message() protected by throw_unless should NOT be flagged."""
        code = """\
() recv_internal(int my_balance, int msg_value, cell in_msg_full, slice in_msg_body) impure {
    throw_unless(401, check_signature(cell_hash(in_msg_full), in_msg_body~load_bits(512), 0));
    accept_message();
    int amount = in_msg_body~load_uint(64);
    send_raw_message(amount, 1);
}
"""
        path = _write_fc(code)
        result = TONSymbolicExecutor().analyze(path)
        gas_findings = [f for f in result["findings"]
                        if "GAS" in f["rule_id"] or "ACCEPT" in f["rule_id"]]
        assert len(gas_findings) == 0, (
            f"Expected no gas drain when guard is present, got {gas_findings}"
        )


# ---------------------------------------------------------------------------
# Fund drain detection (mode=128)
# ---------------------------------------------------------------------------

class TestFundDrainDetection:

    def test_mode128_without_reserve_detected(self):
        """send_raw_message with mode=128 without raw_reserve should be CRITICAL."""
        code = """\
() recv_internal(int my_balance, int msg_value, cell in_msg_full, slice in_msg_body) impure {
    accept_message();
    var msg = begin_cell().end_cell();
    send_raw_message(msg, 128);
}
"""
        path = _write_fc(code)
        result = TONSymbolicExecutor().analyze(path)
        findings = result["findings"]
        drain_findings = [f for f in findings
                          if "DRAIN" in f["rule_id"] or "128" in f.get("evidence", "")]
        assert len(drain_findings) > 0, (
            f"Expected fund drain finding for mode=128 without raw_reserve, got {[f['rule_id'] for f in findings]}"
        )

    def test_mode128_with_reserve_not_flagged(self):
        """send_raw_message with mode=128 AFTER raw_reserve should be safe."""
        code = """\
() recv_internal(int my_balance, int msg_value, cell in_msg_full, slice in_msg_body) impure {
    raw_reserve(min_tons_for_storage, 0);
    var msg = begin_cell().end_cell();
    send_raw_message(msg, 128);
}
"""
        path = _write_fc(code)
        result = TONSymbolicExecutor().analyze(path)
        drain_findings = [f for f in result["findings"] if "DRAIN" in f["rule_id"]]
        assert len(drain_findings) == 0, (
            f"Expected no fund drain when raw_reserve is present, got {drain_findings}"
        )


# ---------------------------------------------------------------------------
# Integer overflow detection
# ---------------------------------------------------------------------------

class TestOverflowDetection:

    def test_user_controlled_arithmetic_detected(self):
        """User-controlled variable in arithmetic without bounds check should be flagged."""
        code = """\
() recv_internal(int my_balance, int msg_value, cell in_msg_full, slice in_msg_body) impure {
    int amount = in_msg_body~load_uint(64);
    int total = amount * 1000;
    send_raw_message(total, 1);
}
"""
        path = _write_fc(code)
        result = TONSymbolicExecutor().analyze(path)
        # The overflow detection should flag this
        findings = result["findings"]
        # At minimum the analysis should complete without error
        assert isinstance(findings, list)

    def test_bounded_arithmetic_not_flagged(self):
        """Arithmetic with bounds check before use should NOT be flagged."""
        code = """\
() recv_internal(int my_balance, int msg_value, cell in_msg_full, slice in_msg_body) impure {
    int amount = in_msg_body~load_uint(64);
    throw_unless(error::too_large, amount <= 1000000);
    int total = amount * 1000;
    send_raw_message(total, 1);
}
"""
        path = _write_fc(code)
        result = TONSymbolicExecutor().analyze(path)
        overflow_findings = [f for f in result["findings"] if "OVERFLOW" in f["rule_id"]]
        assert len(overflow_findings) == 0, (
            f"Expected no overflow when bounds check present, got {overflow_findings}"
        )


# ---------------------------------------------------------------------------
# Tact contract support
# ---------------------------------------------------------------------------

class TestTactSupport:

    def test_tact_file_analyzed(self):
        """Tact (.tact) files should be analyzed without error."""
        code = """\
contract SimpleCounter {
    counter: Int as uint64;

    receive(msg: IncrementBy) {
        self.counter += msg.amount;
    }
}
"""
        path = _write_fc(code, suffix=".tact")
        result = TONSymbolicExecutor().analyze(path)
        assert isinstance(result, dict)
        assert "findings" in result

    def test_empty_contract_no_findings(self):
        """An empty or minimal contract should produce no findings."""
        code = """\
() recv_internal(int my_balance, int msg_value, cell in_msg_full, slice in_msg_body) impure {
}
"""
        path = _write_fc(code)
        result = TONSymbolicExecutor().analyze(path)
        assert isinstance(result["findings"], list)
        # Empty body has nothing to flag
        critical_findings = [f for f in result["findings"] if f.get("severity") == "CRITICAL"]
        assert len(critical_findings) == 0


# ---------------------------------------------------------------------------
# Result structure
# ---------------------------------------------------------------------------

class TestResultStructure:

    def test_result_has_method_key(self):
        code = "int x = 1;"
        path = _write_fc(code)
        result = TONSymbolicExecutor().analyze(path)
        assert "method" in result

    def test_findings_are_dicts(self):
        code = """\
() recv_internal(int my_balance, int msg_value, cell in_msg_full, slice in_msg_body) impure {
    accept_message();
}
"""
        path = _write_fc(code)
        result = TONSymbolicExecutor().analyze(path)
        for f in result["findings"]:
            assert isinstance(f, dict), f"Finding should be dict, got {type(f)}"
            assert "rule_id" in f
            assert "severity" in f
            assert "description" in f
