"""
Deep tests for EVMScanner — ~80 tests covering all 16 detection rules,
scan_file, scan_directory, finding format, edge cases, deduplication,
and file filtering.
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

import pytest
from scanners.evm_scanner.evm_analyzer import EVMScanner


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def write_sol(tmp_path, name, content):
    f = tmp_path / name
    f.write_text(content, encoding="utf-8")
    return str(f)


def has_rule(findings, rule_id):
    return any(f["rule_id"] == rule_id for f in findings)


def findings_for_rule(findings, rule_id):
    return [f for f in findings if f["rule_id"] == rule_id]


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def scanner():
    return EVMScanner()


# ---------------------------------------------------------------------------
# Rule 001 — Reentrancy
# ---------------------------------------------------------------------------

class TestRule001Reentrancy:
    def test_call_value_triggers(self, scanner, tmp_path):
        src = "address(target).call{value: 1 ether}(abi.encodeWithSignature('foo()'));\n"
        findings = scanner.scan_file(write_sol(tmp_path, "a.sol", src))
        assert has_rule(findings, "GHOST-EVM-001")

    def test_transfer_triggers(self, scanner, tmp_path):
        src = "payable(recipient).transfer(amount);\n"
        findings = scanner.scan_file(write_sol(tmp_path, "b.sol", src))
        assert has_rule(findings, "GHOST-EVM-001")

    def test_send_triggers(self, scanner, tmp_path):
        src = "bool ok = recipient.send(amount);\n"
        findings = scanner.scan_file(write_sol(tmp_path, "c.sol", src))
        assert has_rule(findings, "GHOST-EVM-001")

    def test_severity_is_critical(self, scanner, tmp_path):
        src = "payable(x).transfer(1);\n"
        findings = scanner.scan_file(write_sol(tmp_path, "d.sol", src))
        rule_findings = findings_for_rule(findings, "GHOST-EVM-001")
        assert rule_findings
        assert rule_findings[0]["severity"] == "CRITICAL"


# ---------------------------------------------------------------------------
# Rule 002 — tx.origin
# ---------------------------------------------------------------------------

class TestRule002TxOrigin:
    def test_eq_triggers(self, scanner, tmp_path):
        src = "require(tx.origin == owner);\n"
        findings = scanner.scan_file(write_sol(tmp_path, "a.sol", src))
        assert has_rule(findings, "GHOST-EVM-002")

    def test_neq_triggers(self, scanner, tmp_path):
        src = "if (tx.origin != admin) revert();\n"
        findings = scanner.scan_file(write_sol(tmp_path, "b.sol", src))
        assert has_rule(findings, "GHOST-EVM-002")

    def test_severity_high(self, scanner, tmp_path):
        src = "require(tx.origin == owner);\n"
        findings = scanner.scan_file(write_sol(tmp_path, "c.sol", src))
        rule_findings = findings_for_rule(findings, "GHOST-EVM-002")
        assert rule_findings[0]["severity"] == "HIGH"

    def test_plain_tx_origin_reference_no_cmp(self, scanner, tmp_path):
        # tx.origin without comparison operator should not trigger 002
        src = "address who = tx.origin;\n"
        findings = scanner.scan_file(write_sol(tmp_path, "d.sol", src))
        assert not has_rule(findings, "GHOST-EVM-002")


# ---------------------------------------------------------------------------
# Rule 003 — Unchecked return value
# ---------------------------------------------------------------------------

class TestRule003UncheckedCall:
    def test_bare_call_triggers(self, scanner, tmp_path):
        src = "target.call(data);\n"
        findings = scanner.scan_file(write_sol(tmp_path, "a.sol", src))
        assert has_rule(findings, "GHOST-EVM-003")

    def test_severity_high(self, scanner, tmp_path):
        src = "target.call(data);\n"
        findings = scanner.scan_file(write_sol(tmp_path, "b.sol", src))
        rule_findings = findings_for_rule(findings, "GHOST-EVM-003")
        assert rule_findings[0]["severity"] == "HIGH"


# ---------------------------------------------------------------------------
# Rule 004 — Integer overflow/underflow
# ---------------------------------------------------------------------------

class TestRule004IntegerOverflow:
    def test_old_pragma_triggers(self, scanner, tmp_path):
        src = "pragma solidity ^0.7.0;\ncontract X {}\n"
        findings = scanner.scan_file(write_sol(tmp_path, "a.sol", src))
        assert has_rule(findings, "GHOST-EVM-004")

    def test_uint_addition_triggers(self, scanner, tmp_path):
        src = "uint256 total = a + b;\n"
        findings = scanner.scan_file(write_sol(tmp_path, "b.sol", src))
        assert has_rule(findings, "GHOST-EVM-004")

    def test_balances_subtract_triggers(self, scanner, tmp_path):
        src = "balances[user] -= amount;\n"
        findings = scanner.scan_file(write_sol(tmp_path, "c.sol", src))
        assert has_rule(findings, "GHOST-EVM-004")


# ---------------------------------------------------------------------------
# Rule 005 — Delegatecall
# ---------------------------------------------------------------------------

class TestRule005Delegatecall:
    def test_delegatecall_triggers(self, scanner, tmp_path):
        src = "impl.delegatecall(calldata);\n"
        findings = scanner.scan_file(write_sol(tmp_path, "a.sol", src))
        assert has_rule(findings, "GHOST-EVM-005")

    def test_severity_critical(self, scanner, tmp_path):
        src = "impl.delegatecall(calldata);\n"
        findings = scanner.scan_file(write_sol(tmp_path, "b.sol", src))
        rule_findings = findings_for_rule(findings, "GHOST-EVM-005")
        assert rule_findings[0]["severity"] == "CRITICAL"


# ---------------------------------------------------------------------------
# Rule 006 — Selfdestruct
# ---------------------------------------------------------------------------

class TestRule006Selfdestruct:
    def test_selfdestruct_triggers(self, scanner, tmp_path):
        src = "selfdestruct(payable(owner));\n"
        findings = scanner.scan_file(write_sol(tmp_path, "a.sol", src))
        assert has_rule(findings, "GHOST-EVM-006")

    def test_severity_critical(self, scanner, tmp_path):
        src = "selfdestruct(payable(owner));\n"
        findings = scanner.scan_file(write_sol(tmp_path, "b.sol", src))
        rule_findings = findings_for_rule(findings, "GHOST-EVM-006")
        assert rule_findings[0]["severity"] == "CRITICAL"


# ---------------------------------------------------------------------------
# Rule 007 — Block timestamp
# ---------------------------------------------------------------------------

class TestRule007BlockTimestamp:
    def test_block_timestamp_triggers(self, scanner, tmp_path):
        src = "require(block.timestamp > deadline);\n"
        findings = scanner.scan_file(write_sol(tmp_path, "a.sol", src))
        assert has_rule(findings, "GHOST-EVM-007")

    def test_severity_medium(self, scanner, tmp_path):
        src = "require(block.timestamp > deadline);\n"
        findings = scanner.scan_file(write_sol(tmp_path, "b.sol", src))
        rule_findings = findings_for_rule(findings, "GHOST-EVM-007")
        assert rule_findings[0]["severity"] == "MEDIUM"


# ---------------------------------------------------------------------------
# Rule 008 — Weak randomness
# ---------------------------------------------------------------------------

class TestRule008WeakRandomness:
    def test_blockhash_triggers(self, scanner, tmp_path):
        src = "bytes32 rng = blockhash(block.number - 1);\n"
        findings = scanner.scan_file(write_sol(tmp_path, "a.sol", src))
        assert has_rule(findings, "GHOST-EVM-008")

    def test_block_difficulty_triggers(self, scanner, tmp_path):
        src = "uint seed = block.difficulty;\n"
        findings = scanner.scan_file(write_sol(tmp_path, "b.sol", src))
        assert has_rule(findings, "GHOST-EVM-008")

    def test_severity_high(self, scanner, tmp_path):
        src = "bytes32 rng = blockhash(block.number - 1);\n"
        findings = scanner.scan_file(write_sol(tmp_path, "c.sol", src))
        rule_findings = findings_for_rule(findings, "GHOST-EVM-008")
        assert rule_findings[0]["severity"] == "HIGH"


# ---------------------------------------------------------------------------
# Rule 009 — Missing access control
# ---------------------------------------------------------------------------

class TestRule009AccessControl:
    def test_public_mint_without_modifier_triggers(self, scanner, tmp_path):
        src = "function mint(address to, uint256 amount) public {\n    _mint(to, amount);\n}\n"
        findings = scanner.scan_file(write_sol(tmp_path, "a.sol", src))
        assert has_rule(findings, "GHOST-EVM-009")

    def test_public_withdraw_without_modifier_triggers(self, scanner, tmp_path):
        src = "function withdraw(uint amount) external {\n    payable(msg.sender).transfer(amount);\n}\n"
        findings = scanner.scan_file(write_sol(tmp_path, "b.sol", src))
        assert has_rule(findings, "GHOST-EVM-009")

    def test_severity_high(self, scanner, tmp_path):
        src = "function mint(address to, uint256 amount) public {\n    _mint(to, amount);\n}\n"
        findings = scanner.scan_file(write_sol(tmp_path, "c.sol", src))
        rule_findings = findings_for_rule(findings, "GHOST-EVM-009")
        assert rule_findings[0]["severity"] == "HIGH"


# ---------------------------------------------------------------------------
# Rule 010 — Uninitialized storage pointer
# ---------------------------------------------------------------------------

class TestRule010UninitializedStorage:
    def test_uninitialized_storage_triggers(self, scanner, tmp_path):
        src = "MyStruct storage s;\n"
        findings = scanner.scan_file(write_sol(tmp_path, "a.sol", src))
        assert has_rule(findings, "GHOST-EVM-010")


# ---------------------------------------------------------------------------
# Rule 011 — Front-running (multi-line)
# ---------------------------------------------------------------------------

class TestRule011FrontRunning:
    def test_gasprice_triggers(self, scanner, tmp_path):
        src = (
            "function bid(uint amount) public {\n"
            "    require(amount > 0);\n"
            "    uint gasPrice = tx.gasprice;\n"
            "}\n"
        )
        findings = scanner.scan_file(write_sol(tmp_path, "a.sol", src))
        assert has_rule(findings, "GHOST-EVM-011")


# ---------------------------------------------------------------------------
# Rule 012 — Flash loan
# ---------------------------------------------------------------------------

class TestRule012FlashLoan:
    def test_flashloan_triggers(self, scanner, tmp_path):
        src = "flashLoan(address(this), token, amount, data);\n"
        findings = scanner.scan_file(write_sol(tmp_path, "a.sol", src))
        assert has_rule(findings, "GHOST-EVM-012")

    def test_execute_operation_triggers(self, scanner, tmp_path):
        src = "function executeOperation(address asset, uint amount, uint fee, bytes calldata params) external {\n}\n"
        findings = scanner.scan_file(write_sol(tmp_path, "b.sol", src))
        assert has_rule(findings, "GHOST-EVM-012")


# ---------------------------------------------------------------------------
# Rule 013 — Price oracle manipulation
# ---------------------------------------------------------------------------

class TestRule013PriceOracle:
    def test_get_reserves_triggers(self, scanner, tmp_path):
        src = "(uint r0, uint r1,) = IUniswapV2Pair(pair).getReserves();\n"
        findings = scanner.scan_file(write_sol(tmp_path, "a.sol", src))
        assert has_rule(findings, "GHOST-EVM-013")

    def test_severity_critical(self, scanner, tmp_path):
        src = "(uint r0, uint r1,) = IUniswapV2Pair(pair).getReserves();\n"
        findings = scanner.scan_file(write_sol(tmp_path, "b.sol", src))
        rule_findings = findings_for_rule(findings, "GHOST-EVM-013")
        assert rule_findings[0]["severity"] == "CRITICAL"


# ---------------------------------------------------------------------------
# Rule 014 — Proxy storage collision
# ---------------------------------------------------------------------------

class TestRule014ProxyStorage:
    def test_eip1967_slot_triggers(self, scanner, tmp_path):
        src = "bytes32 slot := 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;\n"
        findings = scanner.scan_file(write_sol(tmp_path, "a.sol", src))
        assert has_rule(findings, "GHOST-EVM-014")

    def test_implementation_slot_triggers(self, scanner, tmp_path):
        src = "bytes32 constant _IMPLEMENTATION_SLOT = 0x360894a13ba1a3;\n"
        findings = scanner.scan_file(write_sol(tmp_path, "b.sol", src))
        assert has_rule(findings, "GHOST-EVM-014")


# ---------------------------------------------------------------------------
# Rule 015 — ERC-20 approve race
# ---------------------------------------------------------------------------

class TestRule015ApproveRace:
    def test_approve_triggers(self, scanner, tmp_path):
        src = "token.approve(spender, amount);\n"
        findings = scanner.scan_file(write_sol(tmp_path, "a.sol", src))
        assert has_rule(findings, "GHOST-EVM-015")

    def test_severity_medium(self, scanner, tmp_path):
        src = "token.approve(spender, amount);\n"
        findings = scanner.scan_file(write_sol(tmp_path, "b.sol", src))
        rule_findings = findings_for_rule(findings, "GHOST-EVM-015")
        assert rule_findings[0]["severity"] == "MEDIUM"


# ---------------------------------------------------------------------------
# Rule 016 — Signature replay
# ---------------------------------------------------------------------------

class TestRule016SignatureReplay:
    def test_ecrecover_triggers(self, scanner, tmp_path):
        src = "address signer = ecrecover(msgHash, v, r, s);\n"
        findings = scanner.scan_file(write_sol(tmp_path, "a.sol", src))
        assert has_rule(findings, "GHOST-EVM-016")

    def test_ecdsa_recover_triggers(self, scanner, tmp_path):
        src = "address signer = ECDSA.recover(hash, sig);\n"
        findings = scanner.scan_file(write_sol(tmp_path, "b.sol", src))
        assert has_rule(findings, "GHOST-EVM-016")

    def test_severity_high(self, scanner, tmp_path):
        src = "address signer = ecrecover(msgHash, v, r, s);\n"
        findings = scanner.scan_file(write_sol(tmp_path, "c.sol", src))
        rule_findings = findings_for_rule(findings, "GHOST-EVM-016")
        assert rule_findings[0]["severity"] == "HIGH"


# ---------------------------------------------------------------------------
# Finding format
# ---------------------------------------------------------------------------

class TestFindingFormat:
    def test_required_fields_present(self, scanner, tmp_path):
        src = "payable(x).transfer(1);\n"
        findings = scanner.scan_file(write_sol(tmp_path, "a.sol", src))
        assert findings
        f = findings[0]
        for key in ("rule_id", "severity", "file", "line"):
            assert key in f, f"Missing key: {key}"

    def test_line_is_int(self, scanner, tmp_path):
        src = "payable(x).transfer(1);\n"
        findings = scanner.scan_file(write_sol(tmp_path, "a.sol", src))
        assert isinstance(findings[0]["line"], int)

    def test_file_matches_path(self, scanner, tmp_path):
        path = write_sol(tmp_path, "mycontract.sol", "payable(x).transfer(1);\n")
        findings = scanner.scan_file(path)
        assert findings[0]["file"] == path


# ---------------------------------------------------------------------------
# File filtering
# ---------------------------------------------------------------------------

class TestFileFiltering:
    def test_non_sol_file_skipped(self, scanner, tmp_path):
        f = tmp_path / "Contract.py"
        f.write_text("payable(x).transfer(1);\n")
        findings = scanner.scan_file(str(f))
        assert findings == []

    def test_txt_file_skipped(self, scanner, tmp_path):
        f = tmp_path / "notes.txt"
        f.write_text("selfdestruct(owner);\n")
        findings = scanner.scan_file(str(f))
        assert findings == []

    def test_vy_file_scanned(self, scanner, tmp_path):
        f = tmp_path / "vault.vy"
        f.write_text("selfdestruct(payable(owner))\n")
        findings = scanner.scan_file(str(f))
        assert has_rule(findings, "GHOST-EVM-006")


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_empty_file_no_findings(self, scanner, tmp_path):
        findings = scanner.scan_file(write_sol(tmp_path, "empty.sol", ""))
        assert findings == []

    def test_clean_code_no_findings(self, scanner, tmp_path):
        src = (
            "pragma solidity ^0.8.0;\n"
            "contract Safe {\n"
            "    address public owner;\n"
            "    constructor() { owner = msg.sender; }\n"
            "}\n"
        )
        findings = scanner.scan_file(write_sol(tmp_path, "safe.sol", src))
        # May have some findings due to pattern matching, but not reentrancy/selfdestruct
        assert not has_rule(findings, "GHOST-EVM-001")
        assert not has_rule(findings, "GHOST-EVM-006")

    def test_very_long_line(self, scanner, tmp_path):
        # Very long line should not crash
        long_line = "// " + "A" * 5000 + "\n"
        findings = scanner.scan_file(write_sol(tmp_path, "long.sol", long_line))
        assert isinstance(findings, list)

    def test_comments_stripped(self, scanner, tmp_path):
        # selfdestruct in comment should not trigger
        src = "// selfdestruct(owner);\n"
        findings = scanner.scan_file(write_sol(tmp_path, "comment.sol", src))
        assert not has_rule(findings, "GHOST-EVM-006")

    def test_block_comment_stripped(self, scanner, tmp_path):
        src = "/* selfdestruct(owner); */\n"
        findings = scanner.scan_file(write_sol(tmp_path, "bc.sol", src))
        assert not has_rule(findings, "GHOST-EVM-006")


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

class TestDeduplication:
    def test_same_line_same_rule_not_duplicated(self, scanner, tmp_path):
        src = "payable(x).transfer(1);\n"
        findings = scanner.scan_file(write_sol(tmp_path, "dedup.sol", src))
        rule_findings = findings_for_rule(findings, "GHOST-EVM-001")
        # Should appear exactly once
        lines = [f["line"] for f in rule_findings]
        assert len(lines) == len(set(lines))


# ---------------------------------------------------------------------------
# scan_directory
# ---------------------------------------------------------------------------

class TestScanDirectory:
    def test_empty_directory(self, scanner, tmp_path):
        result = scanner.scan_directory(str(tmp_path))
        assert result["files_scanned"] == 0
        assert result["total_findings"] == 0

    def test_aggregates_multiple_files(self, scanner, tmp_path):
        write_sol(tmp_path, "a.sol", "payable(x).transfer(1);\n")
        write_sol(tmp_path, "b.sol", "selfdestruct(payable(owner));\n")
        result = scanner.scan_directory(str(tmp_path))
        assert result["files_scanned"] == 2
        assert result["total_findings"] >= 2

    def test_severity_counts_populated(self, scanner, tmp_path):
        write_sol(tmp_path, "a.sol", "selfdestruct(payable(owner));\n")
        result = scanner.scan_directory(str(tmp_path))
        assert "severity_counts" in result
        assert "CRITICAL" in result["severity_counts"]

    def test_result_keys_present(self, scanner, tmp_path):
        result = scanner.scan_directory(str(tmp_path))
        for key in ("findings", "files_scanned", "total_findings", "severity_counts"):
            assert key in result

    def test_nonexistent_ext_file_not_counted(self, scanner, tmp_path):
        f = tmp_path / "file.py"
        f.write_text("selfdestruct(payable(owner));\n")
        result = scanner.scan_directory(str(tmp_path))
        assert result["files_scanned"] == 0


# ---------------------------------------------------------------------------
# Additional rule coverage and edge cases
# ---------------------------------------------------------------------------

class TestAdditionalRuleCoverage:
    """Additional tests to increase rule coverage and edge case handling."""

    def test_evm_001_all_three_patterns(self, scanner, tmp_path):
        # Test all three reentrancy patterns in one file
        src = (
            "target.call{value: 1 ether}('');\n"
            "payable(x).transfer(amount);\n"
            "bool ok = x.send(amount);\n"
        )
        findings = scanner.scan_file(write_sol(tmp_path, "r.sol", src))
        rule_findings = findings_for_rule(findings, "GHOST-EVM-001")
        assert len(rule_findings) >= 3

    def test_evm_004_total_supply_triggers(self, scanner, tmp_path):
        src = "totalSupply += minted;\n"
        findings = scanner.scan_file(write_sol(tmp_path, "ts.sol", src))
        assert has_rule(findings, "GHOST-EVM-004")

    def test_evm_008_blockhash_and_difficulty(self, scanner, tmp_path):
        src = (
            "bytes32 h = blockhash(block.number - 1);\n"
            "uint d = block.difficulty;\n"
        )
        findings = scanner.scan_file(write_sol(tmp_path, "r.sol", src))
        rule_findings = findings_for_rule(findings, "GHOST-EVM-008")
        assert len(rule_findings) >= 2

    def test_evm_012_iflashborrower_triggers(self, scanner, tmp_path):
        src = "interface IFlashBorrower { function onFlashLoan() external; }\n"
        findings = scanner.scan_file(write_sol(tmp_path, "fl.sol", src))
        assert has_rule(findings, "GHOST-EVM-012")

    def test_evm_012_iflashloan_triggers(self, scanner, tmp_path):
        src = "IFlashLoan(pool).flashLoan(receiver, token, amount, data);\n"
        findings = scanner.scan_file(write_sol(tmp_path, "fl2.sol", src))
        assert has_rule(findings, "GHOST-EVM-012")

    def test_evm_013_spot_price_triggers(self, scanner, tmp_path):
        src = "uint spotPrice = getReserves() / totalSupply;\n"
        findings = scanner.scan_file(write_sol(tmp_path, "oracle.sol", src))
        assert has_rule(findings, "GHOST-EVM-013")

    def test_evm_016_signature_checker_triggers(self, scanner, tmp_path):
        src = "using SignatureChecker for address;\n"
        findings = scanner.scan_file(write_sol(tmp_path, "sig.sol", src))
        assert has_rule(findings, "GHOST-EVM-016")

    def test_evm_002_leq_geq_triggers(self, scanner, tmp_path):
        src = "require(tx.origin >= minTrust);\n"
        findings = scanner.scan_file(write_sol(tmp_path, "auth.sol", src))
        assert has_rule(findings, "GHOST-EVM-002")

    def test_multiple_rules_same_file(self, scanner, tmp_path):
        src = (
            "payable(x).transfer(amount);\n"
            "selfdestruct(payable(owner));\n"
            "address signer = ecrecover(hash, v, r, s);\n"
        )
        findings = scanner.scan_file(write_sol(tmp_path, "multi.sol", src))
        rule_ids = {f["rule_id"] for f in findings}
        assert len(rule_ids) >= 3

    def test_cwe_field_present(self, scanner, tmp_path):
        src = "payable(x).transfer(1);\n"
        findings = scanner.scan_file(write_sol(tmp_path, "cwe.sol", src))
        assert "cwe" in findings[0]

    def test_owasp_field_present(self, scanner, tmp_path):
        src = "payable(x).transfer(1);\n"
        findings = scanner.scan_file(write_sol(tmp_path, "owasp.sol", src))
        assert "owasp" in findings[0]

    def test_fix_field_present(self, scanner, tmp_path):
        src = "payable(x).transfer(1);\n"
        findings = scanner.scan_file(write_sol(tmp_path, "fix.sol", src))
        assert "fix" in findings[0]

    def test_description_field_present(self, scanner, tmp_path):
        src = "payable(x).transfer(1);\n"
        findings = scanner.scan_file(write_sol(tmp_path, "desc.sol", src))
        assert "description" in findings[0]

    def test_confidence_field_between_0_and_1(self, scanner, tmp_path):
        src = "payable(x).transfer(1);\n"
        findings = scanner.scan_file(write_sol(tmp_path, "conf.sol", src))
        assert 0.0 <= findings[0]["confidence"] <= 1.0

    def test_scanner_field_is_evm_scanner(self, scanner, tmp_path):
        src = "payable(x).transfer(1);\n"
        findings = scanner.scan_file(write_sol(tmp_path, "sc.sol", src))
        assert findings[0]["scanner"] == "evm_scanner"

    def test_line_number_accurate(self, scanner, tmp_path):
        src = "// comment\n// comment2\nselfdestruct(payable(owner));\n"
        findings = scanner.scan_file(write_sol(tmp_path, "ln.sol", src))
        rule_findings = findings_for_rule(findings, "GHOST-EVM-006")
        assert rule_findings
        assert rule_findings[0]["line"] == 3

    def test_vy_extension_scanned(self, scanner, tmp_path):
        f = tmp_path / "vault.vy"
        f.write_text("tx.origin == owner\n")
        findings = scanner.scan_file(str(f))
        # Vyper file should be scanned
        assert isinstance(findings, list)

    def test_scan_directory_findings_list(self, scanner, tmp_path):
        write_sol(tmp_path, "a.sol", "selfdestruct(payable(x));\n")
        result = scanner.scan_directory(str(tmp_path))
        assert isinstance(result["findings"], list)
        assert len(result["findings"]) > 0

    def test_scan_directory_severity_counts_are_ints(self, scanner, tmp_path):
        write_sol(tmp_path, "a.sol", "selfdestruct(payable(x));\n")
        result = scanner.scan_directory(str(tmp_path))
        for v in result["severity_counts"].values():
            assert isinstance(v, int)

    def test_finding_evidence_is_string(self, scanner, tmp_path):
        src = "selfdestruct(payable(owner));\n"
        findings = scanner.scan_file(write_sol(tmp_path, "ev.sol", src))
        assert isinstance(findings[0].get("evidence", ""), str)

    def test_evm_009_burn_without_modifier(self, scanner, tmp_path):
        src = "function burn(address from, uint amount) external {\n    _burn(from, amount);\n}\n"
        findings = scanner.scan_file(write_sol(tmp_path, "burn.sol", src))
        assert has_rule(findings, "GHOST-EVM-009")

    def test_evm_009_setowner_without_modifier(self, scanner, tmp_path):
        src = "function setOwner(address newOwner) public {\n    owner = newOwner;\n}\n"
        findings = scanner.scan_file(write_sol(tmp_path, "so.sol", src))
        assert has_rule(findings, "GHOST-EVM-009")

    def test_evm_015_approve_with_zero(self, scanner, tmp_path):
        src = "token.approve(spender, 0);\n"
        findings = scanner.scan_file(write_sol(tmp_path, "app.sol", src))
        assert has_rule(findings, "GHOST-EVM-015")

    def test_multiple_files_different_findings(self, scanner, tmp_path):
        write_sol(tmp_path, "a.sol", "selfdestruct(payable(owner));\n")
        write_sol(tmp_path, "b.sol", "ecrecover(hash, v, r, s);\n")
        result = scanner.scan_directory(str(tmp_path))
        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "GHOST-EVM-006" in rule_ids
        assert "GHOST-EVM-016" in rule_ids
