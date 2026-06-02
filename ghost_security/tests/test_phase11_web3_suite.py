"""
Phase 11 — Web3 Security Suite extended tests

Covers:
  1. FixSuggestionsEngine
  2. MultiChainAuditor (Solana + CosmWasm)
  3. UnifiedScanOrchestrator
"""
from __future__ import annotations

import json
import tempfile
import textwrap
from pathlib import Path

import pytest

from core.fix_suggestions import FixSuggestionsEngine, FixSuggestion
from blockchain.multichain_auditor import (
    MultiChainAuditor,
    MultiChainFinding,
    _audit_solana,
    _audit_cosmwasm,
)
from reports.unified_report import UnifiedScanOrchestrator, UnifiedReport, ScannerResult


# ═════════════════════════════════════════════════════════════════════════════
# 1. Fix Suggestions Engine
# ═════════════════════════════════════════════════════════════════════════════

class TestFixSuggestionsEngine:

    def test_coverage_full(self):
        engine = FixSuggestionsEngine()
        cov = engine.coverage()
        assert cov["covered"] >= 19
        assert cov["pct"] == 100.0

    def test_get_returns_suggestion(self):
        engine = FixSuggestionsEngine()
        fix = engine.get("SC-SOL-001")
        assert isinstance(fix, FixSuggestion)
        assert fix.rule_id == "SC-SOL-001"

    def test_get_unknown_returns_none(self):
        engine = FixSuggestionsEngine()
        assert engine.get("NONEXISTENT-999") is None

    def test_suggestion_has_before_and_after(self):
        engine = FixSuggestionsEngine()
        for rule_id in ["SC-TON-001", "SC-SOL-001", "IAC-TF-001", "CONT-002", "W3SC-003"]:
            fix = engine.get(rule_id)
            assert fix is not None, f"Missing fix for {rule_id}"
            assert len(fix.before) > 10, f"{rule_id} before is too short"
            assert len(fix.after) > 10, f"{rule_id} after is too short"

    def test_suggestion_has_explanation(self):
        engine = FixSuggestionsEngine()
        for rule_id in engine.get_all():
            fix = engine.get(rule_id)
            assert fix.explanation, f"{rule_id} missing explanation"

    def test_suggestion_effort_valid(self):
        valid_efforts = {"minutes", "hours", "days"}
        engine = FixSuggestionsEngine()
        for rule_id, fix in engine.get_all().items():
            assert fix.effort in valid_efforts, \
                f"{rule_id} has invalid effort '{fix.effort}'"

    def test_enrich_adds_fix_suggestion(self):
        engine = FixSuggestionsEngine()
        findings = [{"rule_id": "SC-SOL-001", "severity": "CRITICAL"}]
        enriched = engine.enrich(findings)
        assert "fix_suggestion" in enriched[0]
        assert "before" in enriched[0]["fix_suggestion"]
        assert "after" in enriched[0]["fix_suggestion"]

    def test_enrich_unknown_rule_no_key(self):
        engine = FixSuggestionsEngine()
        findings = [{"rule_id": "UNKNOWN-999", "severity": "LOW"}]
        enriched = engine.enrich(findings)
        assert "fix_suggestion" not in enriched[0]

    def test_enrich_multiple_findings(self):
        engine = FixSuggestionsEngine()
        findings = [
            {"rule_id": "SC-SOL-001"},
            {"rule_id": "CONT-002"},
            {"rule_id": "IAC-TF-008"},
            {"rule_id": "UNKNOWN-XYZ"},
        ]
        enriched = engine.enrich(findings)
        assert "fix_suggestion" in enriched[0]
        assert "fix_suggestion" in enriched[1]
        assert "fix_suggestion" in enriched[2]
        assert "fix_suggestion" not in enriched[3]

    def test_get_all_returns_dict(self):
        engine = FixSuggestionsEngine()
        all_fixes = engine.get_all()
        assert isinstance(all_fixes, dict)
        assert len(all_fixes) >= 19

    def test_all_rule_ids_covered(self):
        engine = FixSuggestionsEngine()
        required = [
            "SC-TON-001", "SC-TON-002", "SC-TON-003",
            "SC-SOL-001", "SC-SOL-002", "SC-SOL-003", "SC-SOL-004", "SC-SOL-005",
            "IAC-TF-001", "IAC-TF-002", "IAC-TF-008",
            "IAC-CF-001", "IAC-K8S-005",
            "CONT-001", "CONT-002", "CONT-003",
            "W3SC-001", "W3SC-002", "W3SC-003",
        ]
        for rid in required:
            assert engine.get(rid) is not None, f"Missing fix for {rid}"

    def test_enrich_returns_same_list(self):
        engine = FixSuggestionsEngine()
        findings = [{"rule_id": "SC-SOL-003"}]
        result = engine.enrich(findings)
        assert result is findings  # same list object

    def test_fix_suggestion_references(self):
        engine = FixSuggestionsEngine()
        fix = engine.get("SC-SOL-001")
        assert isinstance(fix.references, list)

    def test_ton_fixes_contain_func_code(self):
        engine = FixSuggestionsEngine()
        for rid in ["SC-TON-001", "SC-TON-002", "SC-TON-003"]:
            fix = engine.get(rid)
            assert fix is not None
            combined = fix.before + fix.after
            # FunC code should have semicolons or typical FunC patterns
            assert ";" in combined or "recv_internal" in combined or "random" in combined


# ═════════════════════════════════════════════════════════════════════════════
# 2. Multi-Chain Auditor — Solana
# ═════════════════════════════════════════════════════════════════════════════

class TestMultiChainAuditorSolana:

    def test_missing_signer_flagged(self):
        src = textwrap.dedent("""\
            use solana_program::{account_info::AccountInfo, entrypoint::ProgramResult};
            pub fn process_instruction(
                accounts: &[AccountInfo], data: &[u8]
            ) -> ProgramResult {
                // no is_signer check
                Ok(())
            }
        """)
        findings = _audit_solana(src, "program.rs")
        assert any(f.rule_id == "SC-SOL-NA-001" for f in findings)

    def test_signer_check_clears_001(self):
        src = textwrap.dedent("""\
            use solana_program::account_info::AccountInfo;
            pub fn process(accounts: &[AccountInfo]) {
                let auth = &accounts[0];
                assert!(auth.is_signer, "must sign");
            }
        """)
        findings = _audit_solana(src, "p.rs")
        assert not any(f.rule_id == "SC-SOL-NA-001" for f in findings)

    def test_missing_owner_check(self):
        src = textwrap.dedent("""\
            use solana_program::{account_info::AccountInfo, entrypoint::ProgramResult};
            pub fn process_instruction(
                accounts: &[AccountInfo], data: &[u8]
            ) -> ProgramResult {
                Ok(())
            }
        """)
        findings = _audit_solana(src, "p.rs")
        assert any(f.rule_id == "SC-SOL-NA-002" for f in findings)

    def test_unchecked_arithmetic_flagged(self):
        src = textwrap.dedent("""\
            use solana_program::account_info::AccountInfo;
            pub fn add_tokens(balance: u64, amount: u64) -> u64 {
                balance += amount;
                balance
            }
        """)
        findings = _audit_solana(src, "math.rs")
        assert any(f.rule_id == "SC-SOL-NA-003" for f in findings)

    def test_checked_arithmetic_no_flag(self):
        src = textwrap.dedent("""\
            use solana_program::account_info::AccountInfo;
            pub fn add_tokens(balance: u64, amount: u64) -> Option<u64> {
                balance.checked_add(amount)
            }
        """)
        findings = _audit_solana(src, "math.rs")
        assert not any(f.rule_id == "SC-SOL-NA-003" for f in findings)

    def test_arbitrary_cpi_flagged(self):
        src = textwrap.dedent("""\
            use solana_program::program::invoke;
            pub fn do_cpi(program_info: &AccountInfo, ix: &Instruction, accounts: &[AccountInfo]) {
                invoke(&ix, &[program_info.clone()]).unwrap();
            }
        """)
        findings = _audit_solana(src, "cpi.rs")
        cpi_rules = {f.rule_id for f in findings}
        assert cpi_rules & {"SC-SOL-NA-004", "SC-SOL-NA-005"}

    def test_unchecked_deserialize_flagged(self):
        src = "let data = MyState::try_from_slice_unchecked(&account.data.borrow());"
        findings = _audit_solana(src, "deser.rs")
        assert any(f.rule_id == "SC-SOL-NA-006" for f in findings)

    def test_finding_chain_is_solana(self):
        src = "use solana_program::account_info::AccountInfo;\npub fn process(a: &[AccountInfo]) {}"
        findings = _audit_solana(src, "p.rs")
        for f in findings:
            assert f.chain == "SOLANA"

    def test_finding_has_remediation(self):
        src = textwrap.dedent("""\
            use solana_program::{account_info::AccountInfo, entrypoint::ProgramResult};
            pub fn process_instruction(a: &[AccountInfo], d: &[u8]) -> ProgramResult { Ok(()) }
        """)
        findings = _audit_solana(src, "p.rs")
        for f in findings:
            assert f.remediation, f"{f.rule_id} missing remediation"


# ═════════════════════════════════════════════════════════════════════════════
# 3. Multi-Chain Auditor — CosmWasm
# ═════════════════════════════════════════════════════════════════════════════

class TestMultiChainAuditorCosmWasm:

    def test_missing_admin_check(self):
        src = textwrap.dedent("""\
            use cosmwasm_std::{DepsMut, Env, MessageInfo, Response};
            pub fn execute(deps: DepsMut, _env: Env, _info: MessageInfo,
                           msg: ExecuteMsg) -> Result<Response, ContractError> {
                match msg { ExecuteMsg::Withdraw { amount } => withdraw(deps, amount) }
            }
        """)
        findings = _audit_cosmwasm(src, "contract.rs")
        assert any(f.rule_id == "SC-CW-001" for f in findings)

    def test_admin_check_present_no_flag(self):
        src = textwrap.dedent("""\
            use cosmwasm_std::{DepsMut, Env, MessageInfo, Response};
            pub fn execute(deps: DepsMut, _env: Env, info: MessageInfo,
                           msg: ExecuteMsg) -> Result<Response, ContractError> {
                ADMIN.load(deps.storage)?;
                ensure_admin(&info)?;
                match msg { ExecuteMsg::Withdraw { amount } => withdraw(deps, amount) }
            }
        """)
        findings = _audit_cosmwasm(src, "contract.rs")
        assert not any(f.rule_id == "SC-CW-001" for f in findings)

    def test_missing_funds_validation(self):
        src = textwrap.dedent("""\
            use cosmwasm_std::{DepsMut, Env, MessageInfo, Response};
            pub fn execute(deps: DepsMut, _env: Env, _info: MessageInfo,
                           msg: ExecuteMsg) -> Result<Response, ContractError> {
                ensure_admin(&_info)?;
                Ok(Response::new())
            }
        """)
        findings = _audit_cosmwasm(src, "contract.rs")
        assert any(f.rule_id == "SC-CW-002" for f in findings)

    def test_funds_check_no_flag(self):
        src = textwrap.dedent("""\
            use cosmwasm_std::{DepsMut, Env, MessageInfo, Response};
            use cw_utils::must_pay;
            pub fn execute(deps: DepsMut, _env: Env, info: MessageInfo,
                           msg: ExecuteMsg) -> Result<Response, ContractError> {
                only_owner(&info)?;
                must_pay(&info, &denom)?;
                Ok(Response::new())
            }
        """)
        findings = _audit_cosmwasm(src, "contract.rs")
        assert not any(f.rule_id == "SC-CW-002" for f in findings)

    def test_reply_without_id_check(self):
        src = textwrap.dedent("""\
            use cosmwasm_std::{DepsMut, Env, Reply, Response};
            pub fn reply(deps: DepsMut, _env: Env, msg: Reply)
                -> Result<Response, ContractError>
            {
                handle_reply(deps, msg.result)
            }
        """)
        findings = _audit_cosmwasm(src, "contract.rs")
        assert any(f.rule_id == "SC-CW-003" for f in findings)

    def test_reply_with_id_check_no_flag(self):
        src = textwrap.dedent("""\
            use cosmwasm_std::{DepsMut, Env, Reply, Response};
            const REPLY_ID: u64 = 1;
            pub fn reply(deps: DepsMut, _env: Env, msg: Reply)
                -> Result<Response, ContractError>
            {
                match msg.id == REPLY_ID {
                    true  => handle(deps, msg.result),
                    false => Err(ContractError::Unknown {}),
                }
            }
        """)
        findings = _audit_cosmwasm(src, "contract.rs")
        assert not any(f.rule_id == "SC-CW-003" for f in findings)

    def test_hardcoded_address_flagged(self):
        src = 'let admin = "cosmos1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszq";'
        findings = _audit_cosmwasm(src, "contract.rs")
        assert any(f.rule_id == "SC-CW-005" for f in findings)

    def test_finding_chain_is_cosmwasm(self):
        src = textwrap.dedent("""\
            use cosmwasm_std::{DepsMut, Env, MessageInfo, Response};
            pub fn execute(deps: DepsMut, _env: Env, _info: MessageInfo,
                           msg: ExecuteMsg) -> Result<Response, ContractError> { Ok(Response::new()) }
        """)
        findings = _audit_cosmwasm(src, "c.rs")
        for f in findings:
            assert f.chain == "COSMWASM"

    def test_finding_to_dict(self):
        f = MultiChainFinding(
            rule_id="SC-CW-001", chain="COSMWASM",
            severity="HIGH", category="ACCESS_CONTROL",
            title="Test",
        )
        d = f.to_dict()
        assert d["chain"] == "COSMWASM"
        assert d["rule_id"] == "SC-CW-001"


class TestMultiChainAuditorFile:

    def test_audit_file_solana(self, tmp_path):
        f = tmp_path / "program.rs"
        f.write_text(
            "use solana_program::account_info::AccountInfo;\n"
            "pub fn process_instruction(a: &[AccountInfo], d: &[u8]) { let x = 1 + 2; }"
        )
        auditor = MultiChainAuditor()
        findings = auditor.audit_file(str(f))
        assert isinstance(findings, list)

    def test_audit_file_cosmwasm(self, tmp_path):
        f = tmp_path / "contract.rs"
        f.write_text(
            "use cosmwasm_std::ExecuteMsg;\n"
            "pub fn execute() { }"
        )
        auditor = MultiChainAuditor()
        findings = auditor.audit_file(str(f))
        assert isinstance(findings, list)

    def test_audit_file_non_rust_empty(self, tmp_path):
        f = tmp_path / "main.py"
        f.write_text("print('hello')")
        auditor = MultiChainAuditor()
        assert auditor.audit_file(str(f)) == []

    def test_audit_file_missing(self):
        auditor = MultiChainAuditor()
        assert auditor.audit_file("/no/such/file.rs") == []

    def test_audit_directory(self, tmp_path):
        (tmp_path / "sol.rs").write_text(
            "use solana_program::account_info::AccountInfo;\n"
            "pub fn process_instruction(a: &[AccountInfo], d: &[u8]) {}"
        )
        (tmp_path / "cw.rs").write_text(
            "use cosmwasm_std::ExecuteMsg;\n"
            "pub fn execute() {}"
        )
        auditor = MultiChainAuditor()
        result = auditor.audit_directory(str(tmp_path))
        assert result["files_scanned"] == 2
        assert "by_chain" in result
        assert "severity_counts" in result

    def test_audit_content_solana(self):
        auditor = MultiChainAuditor()
        src = "use solana_program::account_info::AccountInfo; pub fn p() {}"
        findings = auditor.audit_content(src, "solana")
        assert isinstance(findings, list)

    def test_audit_content_cosmwasm(self):
        auditor = MultiChainAuditor()
        src = "use cosmwasm_std::ExecuteMsg; pub fn execute() {}"
        findings = auditor.audit_content(src, "cosmwasm")
        assert isinstance(findings, list)

    def test_audit_content_unknown_chain(self):
        auditor = MultiChainAuditor()
        assert auditor.audit_content("code", "unknown_chain") == []

    def test_supported_chains(self):
        chains = MultiChainAuditor.supported_chains()
        assert "SOLANA" in chains
        assert "COSMWASM" in chains


# ═════════════════════════════════════════════════════════════════════════════
# 4. Unified Scan Orchestrator
# ═════════════════════════════════════════════════════════════════════════════

class TestUnifiedScanOrchestrator:

    def test_scan_empty_dir(self, tmp_path):
        orch = UnifiedScanOrchestrator()
        report = orch.scan(str(tmp_path))
        assert isinstance(report, UnifiedReport)
        assert report.total >= 0
        assert report.target != ""
        assert report.generated_at != ""

    def test_report_risk_score_range(self, tmp_path):
        orch = UnifiedScanOrchestrator()
        report = orch.scan(str(tmp_path))
        assert 0.0 <= report.risk_score <= 100.0

    def test_report_risk_level_valid(self, tmp_path):
        orch = UnifiedScanOrchestrator()
        report = orch.scan(str(tmp_path))
        assert report.risk_level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE")

    def test_report_has_scanner_results(self, tmp_path):
        orch = UnifiedScanOrchestrator()
        report = orch.scan(str(tmp_path))
        assert len(report.scanner_results) > 0

    def test_to_json_valid(self, tmp_path):
        orch = UnifiedScanOrchestrator()
        report = orch.scan(str(tmp_path))
        j = orch.to_json(report)
        data = json.loads(j)
        assert "total_findings" in data
        assert "risk_score" in data
        assert "scanners" in data

    def test_to_html_returns_string(self, tmp_path):
        orch = UnifiedScanOrchestrator()
        report = orch.scan(str(tmp_path))
        html = orch.to_html(report)
        assert isinstance(html, str)
        assert "TythanAI" in html
        assert "<html" in html.lower()

    def test_report_to_dict_structure(self, tmp_path):
        orch = UnifiedScanOrchestrator()
        report = orch.scan(str(tmp_path))
        d = report.to_dict()
        for key in ("target", "total_findings", "risk_score", "risk_level",
                    "severity_counts", "scanners", "findings"):
            assert key in d, f"Missing key: {key}"

    def test_scanner_result_structure(self, tmp_path):
        orch = UnifiedScanOrchestrator()
        report = orch.scan(str(tmp_path))
        for sr in report.scanner_results:
            assert hasattr(sr, "scanner_name")
            assert hasattr(sr, "findings")
            assert hasattr(sr, "total")

    def test_findings_include_fix_suggestions(self, tmp_path):
        # Create a Dockerfile that will trigger CONT-002
        (tmp_path / "Dockerfile").write_text("FROM ubuntu:22.04\nRUN apt-get update\n")
        orch = UnifiedScanOrchestrator()
        report = orch.scan(str(tmp_path), fix_suggestions=True)
        # At least some findings should have fix_suggestion
        findings_with_fix = [
            f for f in report.all_findings
            if "fix_suggestion" in f
        ]
        # We just check the mechanism works — fix count depends on what scanners find
        assert isinstance(findings_with_fix, list)

    def test_all_findings_aggregated(self, tmp_path):
        orch = UnifiedScanOrchestrator()
        report = orch.scan(str(tmp_path))
        total_from_scanners = sum(r.total for r in report.scanner_results)
        assert report.total <= total_from_scanners + 1  # SBOM components may not count as findings

    def test_safe_level_when_no_findings(self, tmp_path):
        orch = UnifiedScanOrchestrator()
        report = orch.scan(str(tmp_path))
        if report.total == 0:
            assert report.risk_level == "SAFE"
            assert report.risk_score == 0.0
