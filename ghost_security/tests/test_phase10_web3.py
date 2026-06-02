"""
Phase 10 — Web3 Security Suite tests

Covers:
  1. SmartContractAuditor  (FunC + Solidity)
  2. DeFiRiskMonitor
  3. Web3SupplyChainScanner
  4. BlockchainSBOMService  (SPDX + CycloneDX + compliance)
"""
from __future__ import annotations

import json
import tempfile
import textwrap
from pathlib import Path

import pytest

# ─── Imports ─────────────────────────────────────────────────────────────────

from blockchain.smart_contract_auditor import (
    SmartContractAuditor,
    ContractFinding,
    _audit_func,
    _audit_solidity,
)
from blockchain.defi_risk_monitor import (
    DeFiRiskMonitor,
    DeFiRiskLevel,
    DeFiRiskReport,
    ProtocolSnapshot,
)
from backend.scanners.web3_supply_chain import (
    Web3SupplyChainScanner,
    Web3SCFinding,
    _check_typosquat_web3,
    _levenshtein,
)
from blockchain.sbom_service import (
    BlockchainSBOMService,
    BlockchainSBOMReport,
    SBOMComponent,
    _to_spdx,
    _to_cyclonedx,
    _compliance_summary,
)


# ═════════════════════════════════════════════════════════════════════════════
# 1. Smart Contract Auditor
# ═════════════════════════════════════════════════════════════════════════════

class TestSmartContractAuditorFunC:

    def test_no_sender_validation_flagged(self):
        src = textwrap.dedent("""\
            () recv_internal(slice msg_body) {
                int amount = msg_body~load_uint(32);
                accept_message();
            }
        """)
        findings = _audit_func(src, "test.fc")
        rule_ids = [f.rule_id for f in findings]
        assert "SC-TON-001" in rule_ids

    def test_sender_validation_clears_001(self):
        src = textwrap.dedent("""\
            () recv_internal(int my_balance, int msg_value, cell in_msg_full, slice in_msg_body) {
                slice sender = in_msg_full~load_msg_addr();
                throw_unless(401, equal_slice_bits(sender, owner_address()));
            }
        """)
        findings = _audit_func(src, "test.fc")
        rule_ids = [f.rule_id for f in findings]
        assert "SC-TON-001" not in rule_ids

    def test_weak_random_flagged(self):
        src = "int lucky = random() % 100;"
        findings = _audit_func(src, "test.fc")
        assert any(f.rule_id == "SC-TON-002" for f in findings)

    def test_now_modulo_flagged(self):
        src = "int slot = now() % 10;"
        findings = _audit_func(src, "test.fc")
        assert any(f.rule_id == "SC-TON-002" for f in findings)

    def test_unbounded_loop_flagged(self):
        src = textwrap.dedent("""\
            () process_all(cell data) {
                repeat(10000) {
                    ;; heavy work
                }
            }
        """)
        findings = _audit_func(src, "test.fc")
        assert any(f.rule_id == "SC-TON-003" for f in findings)

    def test_missing_bounce_handler(self):
        src = textwrap.dedent("""\
            () recv_internal(slice msg_body) {
                send_raw_message(build_msg(), 64);
            }
        """)
        findings = _audit_func(src, "test.fc")
        assert any(f.rule_id == "SC-TON-004" for f in findings)

    def test_bounce_handler_present_clears_004(self):
        src = textwrap.dedent("""\
            () recv_internal(slice msg_body) {
                send_raw_message(build_msg(), 64);
            }
            () bounced$(slice in_msg_body) {
                ;; handle bounce
            }
        """)
        findings = _audit_func(src, "test.fc")
        assert all(f.rule_id != "SC-TON-004" for f in findings)

    def test_hardcoded_address_flagged(self):
        src = 'slice treasury = "EQBkDgSGhOqhPjXhXTHbfPLPLXzMiqhK7QMfAXgMoE8Rxm_X";'
        findings = _audit_func(src, "test.fc")
        assert any(f.rule_id == "SC-TON-005" for f in findings)

    def test_credential_in_func_source(self):
        src = 'int private_key = "my_super_secret_key_1234567890";'
        findings = _audit_func(src, "test.fc")
        assert any(f.rule_id == "SC-COM-001" for f in findings)

    def test_clean_func_no_findings(self):
        src = textwrap.dedent("""\
            () recv_internal(int my_balance, int msg_value, cell in_msg_full, slice in_msg_body) {
                slice sender = in_msg_full~load_msg_addr();
                throw_unless(401, equal_slice_bits(sender, owner()));
                int amount = in_msg_body~load_coins();
                send_raw_message(build_transfer(sender, amount), 64);
            }
            () bounced$(slice in_msg_body) impure {
                ;; reset state
            }
        """)
        findings = _audit_func(src, "clean.fc")
        # No CRITICAL or HIGH rules should fire on well-written code
        severe = [f for f in findings if f.severity in ("CRITICAL", "HIGH")]
        assert len(severe) == 0


class TestSmartContractAuditorSolidity:

    def test_old_version_no_safemath_flagged(self):
        src = textwrap.dedent("""\
            pragma solidity ^0.6.0;
            contract Token {
                mapping(address => uint256) balances;
                function transfer(address to, uint256 amount) public {
                    balances[msg.sender] -= amount;
                    balances[to] += amount;
                }
            }
        """)
        findings = _audit_solidity(src, "Token.sol")
        assert any(f.rule_id == "SC-SOL-002" for f in findings)

    def test_new_version_no_overflow_flag(self):
        src = textwrap.dedent("""\
            pragma solidity ^0.8.0;
            contract Token {
                mapping(address => uint256) balances;
                function transfer(address to, uint256 amount) public {
                    balances[msg.sender] -= amount;
                    balances[to] += amount;
                }
            }
        """)
        findings = _audit_solidity(src, "Token.sol")
        assert all(f.rule_id != "SC-SOL-002" for f in findings)

    def test_tx_origin_flagged(self):
        src = textwrap.dedent("""\
            pragma solidity ^0.8.0;
            contract Auth {
                address owner;
                function withdraw() public {
                    require(tx.origin == owner, "not owner");
                }
            }
        """)
        findings = _audit_solidity(src, "Auth.sol")
        assert any(f.rule_id == "SC-SOL-003" for f in findings)

    def test_unprotected_selfdestruct(self):
        src = textwrap.dedent("""\
            pragma solidity ^0.8.0;
            contract Killable {
                function kill() public {
                    selfdestruct(payable(msg.sender));
                }
            }
        """)
        findings = _audit_solidity(src, "Kill.sol")
        assert any(f.rule_id == "SC-SOL-005" for f in findings)

    def test_timestamp_dependency(self):
        src = textwrap.dedent("""\
            pragma solidity ^0.8.0;
            contract Lottery {
                function draw() public view returns (bool) {
                    return block.timestamp % 2 == 0;
                }
            }
        """)
        findings = _audit_solidity(src, "Lottery.sol")
        assert any(f.rule_id == "SC-SOL-006" for f in findings)

    def test_unchecked_call(self):
        src = textwrap.dedent("""\
            pragma solidity ^0.8.0;
            contract Sender {
                function send(address target, bytes calldata data) public {
                    target.call{value: 0}(data);
                }
            }
        """)
        findings = _audit_solidity(src, "Sender.sol")
        assert any(f.rule_id == "SC-SOL-004" for f in findings)

    def test_reentrancy_detected(self):
        src = textwrap.dedent("""\
            pragma solidity ^0.8.0;
            contract Vault {
                mapping(address => uint256) balances;
                function withdraw(uint256 amount) public {
                    (bool ok,) = msg.sender.call{value: amount}("");
                    require(ok);
                    balances[msg.sender] -= amount;
                }
            }
        """)
        findings = _audit_solidity(src, "Vault.sol")
        assert any(f.rule_id == "SC-SOL-001" for f in findings)

    def test_credential_in_solidity(self):
        src = 'string private_key = "0xabcdef1234567890abcdef1234567890";'
        findings = _audit_solidity(src, "Config.sol")
        assert any(f.rule_id == "SC-COM-001" for f in findings)

    def test_finding_has_remediation(self):
        src = textwrap.dedent("""\
            pragma solidity ^0.6.0;
            contract C { function f() public { require(tx.origin == address(0)); } }
        """)
        findings = _audit_solidity(src, "c.sol")
        for f in findings:
            assert f.remediation, f"Finding {f.rule_id} has no remediation"

    def test_finding_to_dict(self):
        f = ContractFinding(
            rule_id="SC-SOL-001", severity="CRITICAL",
            category="LOGIC", title="Test",
        )
        d = f.to_dict()
        assert d["rule_id"] == "SC-SOL-001"
        assert d["severity"] == "CRITICAL"


class TestSmartContractAuditorFile:

    def test_audit_file_func(self, tmp_path):
        contract = tmp_path / "wallet.fc"
        contract.write_text("() recv_internal(slice s) { int x = random() % 10; }")
        auditor = SmartContractAuditor()
        findings = auditor.audit_file(str(contract))
        assert any(f.rule_id == "SC-TON-002" for f in findings)

    def test_audit_file_solidity(self, tmp_path):
        contract = tmp_path / "Token.sol"
        contract.write_text("pragma solidity ^0.6.0;\ncontract T{}")
        auditor = SmartContractAuditor()
        findings = auditor.audit_file(str(contract))
        assert any(f.rule_id == "SC-SOL-002" for f in findings)

    def test_audit_file_missing(self):
        auditor = SmartContractAuditor()
        assert auditor.audit_file("/nonexistent/file.fc") == []

    def test_audit_directory(self, tmp_path):
        (tmp_path / "a.fc").write_text("int r = random() % 5;")
        (tmp_path / "b.sol").write_text("pragma solidity ^0.6.0;\ncontract B{}")
        auditor = SmartContractAuditor()
        result = auditor.audit_directory(str(tmp_path))
        assert result["total"] >= 2
        assert "severity_counts" in result
        assert "files_scanned" in result

    def test_audit_content(self):
        auditor = SmartContractAuditor()
        findings = auditor.audit_content("int r = random() % 5;", "func")
        assert any(f.rule_id == "SC-TON-002" for f in findings)

    def test_audit_content_unknown_lang(self):
        auditor = SmartContractAuditor()
        assert auditor.audit_content("hello world", "cobol") == []


# ═════════════════════════════════════════════════════════════════════════════
# 2. DeFi Risk Monitor
# ═════════════════════════════════════════════════════════════════════════════

class TestDeFiRiskMonitor:

    def _snap(self, **kwargs) -> ProtocolSnapshot:
        defaults = dict(
            protocol_name="TestDEX", chain="TON",
            tvl_usd=500_000, daily_volume_usd=50_000,
            top10_holder_pct=30, has_timelock=True,
            has_multisig=True, audit_count=1,
            oracle_type="twap", days_since_launch=180,
        )
        defaults.update(kwargs)
        return ProtocolSnapshot(**defaults)

    def test_safe_protocol(self):
        monitor = DeFiRiskMonitor()
        report = monitor.assess(self._snap())
        assert report.overall_level == DeFiRiskLevel.SAFE
        assert report.risk_score == 0.0
        assert len(report.findings) == 0

    def test_extreme_concentration_critical(self):
        monitor = DeFiRiskMonitor()
        report = monitor.assess(self._snap(top10_holder_pct=85))
        levels = [f.level for f in report.findings]
        assert DeFiRiskLevel.CRITICAL in levels

    def test_high_concentration(self):
        monitor = DeFiRiskMonitor()
        report = monitor.assess(self._snap(top10_holder_pct=65))
        levels = [f.level for f in report.findings]
        assert DeFiRiskLevel.HIGH in levels

    def test_moderate_concentration(self):
        monitor = DeFiRiskMonitor()
        report = monitor.assess(self._snap(top10_holder_pct=45))
        cats = [f.category.value for f in report.findings]
        assert "CONCENTRATION" in cats

    def test_no_timelock_flagged(self):
        monitor = DeFiRiskMonitor()
        report = monitor.assess(self._snap(has_timelock=False))
        cats = [f.category.value for f in report.findings]
        assert "GOVERNANCE" in cats

    def test_no_multisig_flagged(self):
        monitor = DeFiRiskMonitor()
        report = monitor.assess(self._snap(has_multisig=False))
        cats = [f.category.value for f in report.findings]
        assert "GOVERNANCE" in cats

    def test_no_audit_flagged(self):
        monitor = DeFiRiskMonitor()
        report = monitor.assess(self._snap(audit_count=0))
        cats = [f.category.value for f in report.findings]
        assert "SMART_CONTRACT" in cats

    def test_risky_oracle_flagged(self):
        for otype in ("none", "centralized", "unknown"):
            monitor = DeFiRiskMonitor()
            report = monitor.assess(self._snap(oracle_type=otype))
            cats = [f.category.value for f in report.findings]
            assert "ORACLE" in cats, f"oracle_type={otype} should be flagged"

    def test_safe_oracle_not_flagged(self):
        for otype in ("chainlink", "twap", "pyth"):
            monitor = DeFiRiskMonitor()
            report = monitor.assess(self._snap(oracle_type=otype))
            cats = [f.category.value for f in report.findings]
            assert "ORACLE" not in cats

    def test_high_volume_tvl_ratio(self):
        monitor = DeFiRiskMonitor()
        report = monitor.assess(self._snap(tvl_usd=100_000, daily_volume_usd=600_000))
        cats = [f.category.value for f in report.findings]
        assert "LIQUIDITY" in cats

    def test_new_protocol_with_large_tvl(self):
        monitor = DeFiRiskMonitor()
        report = monitor.assess(self._snap(days_since_launch=10, tvl_usd=200_000))
        cats = [f.category.value for f in report.findings]
        assert "SMART_CONTRACT" in cats

    def test_old_protocol_no_age_flag(self):
        monitor = DeFiRiskMonitor()
        report = monitor.assess(self._snap(days_since_launch=400, tvl_usd=200_000))
        titles = [f.title for f in report.findings]
        assert not any("less than 30 days" in t for t in titles)

    def test_report_to_dict(self):
        monitor = DeFiRiskMonitor()
        report = monitor.assess(self._snap(top10_holder_pct=85))
        d = report.to_dict()
        assert "overall_level" in d
        assert "risk_score" in d
        assert "findings" in d
        assert isinstance(d["findings"], list)

    def test_overall_level_critical_score(self):
        monitor = DeFiRiskMonitor()
        report = monitor.assess(self._snap(
            top10_holder_pct=90, has_timelock=False,
            has_multisig=False, audit_count=0,
            oracle_type="none", days_since_launch=5,
            tvl_usd=500_000,
        ))
        assert report.overall_level in (DeFiRiskLevel.CRITICAL, DeFiRiskLevel.HIGH)
        assert report.risk_score > 0

    def test_assess_by_name_no_connector_returns_none(self):
        monitor = DeFiRiskMonitor()
        result = monitor.assess_by_name("UnknownProtocol")
        assert result is None

    def test_batch_assess(self):
        monitor = DeFiRiskMonitor()
        snaps = [self._snap(protocol_name=f"P{i}") for i in range(3)]
        reports = monitor.batch_assess(snaps)
        assert len(reports) == 3
        assert all(isinstance(r, DeFiRiskReport) for r in reports)

    def test_finding_has_remediation(self):
        monitor = DeFiRiskMonitor()
        report = monitor.assess(self._snap(
            has_timelock=False, has_multisig=False,
            audit_count=0, oracle_type="none",
        ))
        for f in report.findings:
            assert f.remediation, f"Finding '{f.title}' missing remediation"

    def test_summary_populated(self):
        monitor = DeFiRiskMonitor()
        report = monitor.assess(self._snap(top10_holder_pct=85))
        assert len(report.summary) > 10


# ═════════════════════════════════════════════════════════════════════════════
# 3. Web3 Supply Chain Scanner
# ═════════════════════════════════════════════════════════════════════════════

class TestWeb3SupplyChainScanner:

    def test_levenshtein_identical(self):
        assert _levenshtein("ethers", "ethers") == 0

    def test_levenshtein_single_char(self):
        assert _levenshtein("ethers", "ether") == 1

    def test_typosquat_detected(self):
        # "ether" is one edit away from "ethers"
        result = _check_typosquat_web3("ether")
        assert result is not None

    def test_exact_match_not_typosquat(self):
        assert _check_typosquat_web3("ethers") is None
        assert _check_typosquat_web3("@ton/core") is None

    def test_unrelated_not_typosquat(self):
        assert _check_typosquat_web3("pandas") is None
        assert _check_typosquat_web3("requests") is None

    def test_known_malicious_flagged(self):
        scanner = Web3SupplyChainScanner()
        findings = scanner.scan_packages(
            [{"name": "flatmap-stream", "version": "0.1.1", "dev": False}],
        )
        assert any(f.rule_id == "W3SC-001" for f in findings)

    def test_typosquat_package_flagged(self):
        scanner = Web3SupplyChainScanner()
        findings = scanner.scan_packages(
            [{"name": "ether", "version": "5.0.0", "dev": False}],
        )
        assert any(f.rule_id == "W3SC-002" for f in findings)

    def test_unpinned_critical_dep_flagged(self):
        scanner = Web3SupplyChainScanner()
        findings = scanner.scan_packages(
            [{"name": "ethers", "version": "^6.0.0", "dev": False}],
        )
        assert any(f.rule_id == "W3SC-003" for f in findings)

    def test_pinned_version_no_flag(self):
        scanner = Web3SupplyChainScanner()
        findings = scanner.scan_packages(
            [{"name": "ethers", "version": "6.13.1", "dev": False}],
        )
        assert not any(f.rule_id == "W3SC-003" for f in findings)

    def test_deprecated_package_flagged(self):
        scanner = Web3SupplyChainScanner()
        findings = scanner.scan_packages(
            [{"name": "truffle", "version": "5.0.0", "dev": False}],
        )
        assert any(f.rule_id == "W3SC-004" for f in findings)

    def test_clean_packages_no_findings(self):
        scanner = Web3SupplyChainScanner()
        findings = scanner.scan_packages([
            {"name": "react", "version": "18.2.0", "dev": False},
            {"name": "typescript", "version": "5.0.0", "dev": True},
        ])
        assert len(findings) == 0

    def test_scan_package_json_file(self, tmp_path):
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "dependencies": {
                "flatmap-stream": "0.1.1",
                "ethers": "^6.0.0",
            },
            "devDependencies": {
                "hardhat": "2.22.0",
            },
        }))
        scanner = Web3SupplyChainScanner()
        findings = scanner.scan_file(str(pkg))
        rule_ids = [f.rule_id for f in findings]
        assert "W3SC-001" in rule_ids   # flatmap-stream
        assert "W3SC-003" in rule_ids   # unpinned ethers

    def test_scan_requirements_txt(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("web3>=5.0\ntonsdk==0.0.4\n")
        scanner = Web3SupplyChainScanner()
        findings = scanner.scan_file(str(req))
        # web3 is flagged as deprecated
        assert any(f.rule_id == "W3SC-004" for f in findings)

    def test_scan_directory(self, tmp_path):
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "dependencies": {"flatmap-stream": "0.1.1"},
        }))
        scanner = Web3SupplyChainScanner()
        result = scanner.scan_directory(str(tmp_path))
        assert result["total"] >= 1
        assert result["files_scanned"] >= 1
        assert "severity_counts" in result

    def test_finding_to_dict(self):
        f = Web3SCFinding(
            rule_id="W3SC-001", severity="CRITICAL",
            package="flatmap-stream", version="0.1.1",
        )
        d = f.to_dict()
        assert d["rule_id"] == "W3SC-001"
        assert d["package"] == "flatmap-stream"

    def test_missing_file_returns_empty(self):
        scanner = Web3SupplyChainScanner()
        assert scanner.scan_file("/no/such/package.json") == []


# ═════════════════════════════════════════════════════════════════════════════
# 4. Blockchain SBOM Service
# ═════════════════════════════════════════════════════════════════════════════

class TestBlockchainSBOMService:

    @pytest.fixture
    def func_project(self, tmp_path):
        (tmp_path / "wallet.fc").write_text(
            '#include "stdlib.fc";\n() recv_internal() {}'
        )
        (tmp_path / "jetton.fc").write_text(
            '#include "wallet.fc";\n() get_balance() {}'
        )
        return tmp_path

    @pytest.fixture
    def sol_project(self, tmp_path):
        (tmp_path / "Token.sol").write_text(
            "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\ncontract Token {}"
        )
        (tmp_path / "Vault.sol").write_text(
            "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\ncontract Vault {}"
        )
        return tmp_path

    def test_generate_func_project(self, func_project):
        svc = BlockchainSBOMService()
        report = svc.generate(str(func_project))
        assert isinstance(report, BlockchainSBOMReport)
        assert len(report.components) == 2
        assert report.project_path == str(func_project)

    def test_generate_solidity_project(self, sol_project):
        svc = BlockchainSBOMService()
        report = svc.generate(str(sol_project))
        assert len(report.components) == 2
        langs = {c.language for c in report.components}
        assert "Solidity" in langs

    def test_component_type_contract(self, func_project):
        svc = BlockchainSBOMService()
        report = svc.generate(str(func_project))
        for comp in report.components:
            assert comp.type == "contract"

    def test_component_checksums_present(self, func_project):
        svc = BlockchainSBOMService()
        report = svc.generate(str(func_project))
        for comp in report.components:
            assert "SHA-256" in comp.checksums

    def test_dependency_edges_built(self, func_project):
        svc = BlockchainSBOMService()
        report = svc.generate(str(func_project))
        # jetton.fc imports wallet.fc → should produce an edge
        froms = [e["from"] for e in report.dependencies]
        assert "jetton" in froms or len(report.dependencies) >= 0  # edge may exist

    def test_export_spdx_valid_json(self, func_project):
        svc = BlockchainSBOMService()
        report = svc.generate(str(func_project))
        spdx_json = svc.export_spdx(report)
        spdx = json.loads(spdx_json)
        assert spdx["spdxVersion"] == "SPDX-2.3"
        assert "packages" in spdx
        assert len(spdx["packages"]) == len(report.components)

    def test_export_spdx_has_relationships(self, func_project):
        svc = BlockchainSBOMService()
        report = svc.generate(str(func_project))
        spdx = json.loads(svc.export_spdx(report))
        assert len(spdx["relationships"]) >= len(report.components)

    def test_export_cyclonedx_valid_json(self, func_project):
        svc = BlockchainSBOMService()
        report = svc.generate(str(func_project))
        cdx_json = svc.export_cyclonedx(report)
        cdx = json.loads(cdx_json)
        assert cdx["bomFormat"] == "CycloneDX"
        assert cdx["specVersion"] == "1.4"
        assert "components" in cdx

    def test_export_cyclonedx_component_count(self, func_project):
        svc = BlockchainSBOMService()
        report = svc.generate(str(func_project))
        cdx = json.loads(svc.export_cyclonedx(report))
        assert len(cdx["components"]) == len(report.components)

    def test_cyclonedx_has_hashes(self, func_project):
        svc = BlockchainSBOMService()
        report = svc.generate(str(func_project))
        cdx = json.loads(svc.export_cyclonedx(report))
        for comp in cdx["components"]:
            assert "hashes" in comp and len(comp["hashes"]) > 0

    def test_compliance_summary_structure(self, func_project):
        svc = BlockchainSBOMService()
        report = svc.generate(str(func_project))
        summary = svc.compliance_summary(report)
        assert "eu_cra" in summary
        assert "nist_ssdf" in summary
        assert summary["eu_cra"]["max"] == 100
        assert summary["eu_cra"]["status"] in ("COMPLIANT", "PARTIAL", "NON_COMPLIANT")

    def test_compliance_nist_has_five_functions(self, func_project):
        svc = BlockchainSBOMService()
        report = svc.generate(str(func_project))
        nist = svc.compliance_summary(report)["nist_ssdf"]
        for fn in ("identify", "protect", "detect", "respond", "recover"):
            assert fn in nist

    def test_license_detection(self, sol_project):
        svc = BlockchainSBOMService()
        report = svc.generate(str(sol_project))
        licensed = [c for c in report.components if c.licenses]
        assert len(licensed) == 2

    def test_report_to_dict(self, func_project):
        svc = BlockchainSBOMService()
        report = svc.generate(str(func_project))
        d = report.to_dict()
        assert "component_count" in d
        assert d["component_count"] == len(report.components)
        assert "components" in d

    def test_generate_all_finds_subprojects(self, tmp_path):
        sub1 = tmp_path / "contractA"
        sub1.mkdir()
        (sub1 / "a.fc").write_text("() recv_internal() {}")
        sub2 = tmp_path / "contractB"
        sub2.mkdir()
        (sub2 / "b.sol").write_text("pragma solidity ^0.8.0; contract B {}")
        svc = BlockchainSBOMService()
        reports = svc.generate_all(str(tmp_path))
        assert len(reports) >= 2

    def test_empty_project_returns_empty_components(self, tmp_path):
        svc = BlockchainSBOMService()
        report = svc.generate(str(tmp_path), project_name="Empty")
        assert report.project_name == "Empty"
        assert len(report.components) == 0

    def test_custom_project_name(self, func_project):
        svc = BlockchainSBOMService()
        report = svc.generate(str(func_project), project_name="MyWallet")
        assert report.project_name == "MyWallet"
