"""
TythanAI Phase 11 — Multi-Chain Smart Contract Auditor

Extends SmartContractAuditor with Solana (Rust) and CosmWasm (Rust) support.

Rule IDs:
  Solana:
    SC-SOL-NA-001: Missing signer check (account not validated as signer)
    SC-SOL-NA-002: Missing owner check (account owner not verified)
    SC-SOL-NA-003: Unchecked arithmetic (potential overflow in Rust without checked_*)
    SC-SOL-NA-004: Unsafe use of invoke (CPI without signer seeds validation)
    SC-SOL-NA-005: Arbitrary program CPI (target program not validated)
    SC-SOL-NA-006: Account confusion (missing discriminator check)

  CosmWasm:
    SC-CW-001: Missing admin/ownership check in execute handler
    SC-CW-002: Unchecked funds in execute (funds not validated)
    SC-CW-003: Unsafe reply handling (reply without id validation)
    SC-CW-004: Reentrancy via sub-messages (state written before reply)
    SC-CW-005: Hardcoded address in contract
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class MultiChainFinding:
    rule_id:     str
    chain:       str        # SOLANA | COSMWASM
    severity:    str        # CRITICAL | HIGH | MEDIUM | LOW
    category:    str
    title:       str
    description: str = ""
    file:        str = ""
    line:        int = 0
    evidence:    str = ""
    cwe:         str = ""
    remediation: str = ""

    def to_dict(self) -> dict:
        return {
            "rule_id":     self.rule_id,
            "chain":       self.chain,
            "severity":    self.severity,
            "category":    self.category,
            "title":       self.title,
            "description": self.description,
            "file":        self.file,
            "line":        self.line,
            "evidence":    self.evidence,
            "cwe":         self.cwe,
            "remediation": self.remediation,
        }


# ─── Solana / Anchor patterns ─────────────────────────────────────────────────

_SOL_SIGNER_CHECK   = re.compile(r'\.is_signer', re.I)
_SOL_OWNER_CHECK    = re.compile(r'\.owner\s*==|check_id\s*\(|owner\s*\.\s*key', re.I)
_SOL_UNCHECKED_ARITH = re.compile(r'\b(\w+)\s*\+=\s*|\b(\w+)\s*\-=\s*|\b(\w+)\s*\*=\s*')
_SOL_CHECKED_ARITH  = re.compile(r'\.(checked_add|checked_sub|checked_mul|saturating_add|saturating_sub)\s*\(')
_SOL_INVOKE         = re.compile(r'\binvoke\s*\(|\binvoke_signed\s*\(')
_SOL_ARBITRARY_CPI  = re.compile(r'invoke\s*\(\s*&\s*\w+_info\.clone\(\)', re.I)
_SOL_DISCRIMINATOR  = re.compile(r'try_from_slice_unchecked|deserialize_unchecked', re.I)
_SOL_ANCHOR_ACCOUNT = re.compile(r'#\[account\(')
_SOL_ANCHOR_SIGNER  = re.compile(r'Signer\s*<|#\[account\([^)]*signer', re.I)

_CRED_PATTERN = re.compile(
    r'(private_key|secret_key|mnemonic|seed|api_key)\s*=\s*"[^"]{8,}"',
    re.I,
)


def _audit_solana(content: str, path: str) -> List[MultiChainFinding]:
    findings: List[MultiChainFinding] = []
    lines = content.splitlines()

    has_signer_check = _SOL_SIGNER_CHECK.search(content) is not None
    has_owner_check  = _SOL_OWNER_CHECK.search(content) is not None
    has_checked_arith = _SOL_CHECKED_ARITH.search(content) is not None
    is_anchor = _SOL_ANCHOR_ACCOUNT.search(content) is not None
    has_anchor_signer = _SOL_ANCHOR_SIGNER.search(content) is not None

    # SC-SOL-NA-001: missing signer check
    if not has_signer_check and not has_anchor_signer and "process_instruction" in content:
        findings.append(MultiChainFinding(
            rule_id="SC-SOL-NA-001",
            chain="SOLANA", severity="CRITICAL",
            category="ACCESS_CONTROL",
            title="No signer validation found",
            description="Instruction handler does not validate that the caller "
                        "account is a required signer. Any account can invoke the instruction.",
            file=path, cwe="CWE-284",
            remediation="Check account.is_signer before processing privileged operations. "
                        "With Anchor, add Signer<'info> to the accounts struct.",
        ))

    # SC-SOL-NA-002: missing owner check
    if not has_owner_check and not is_anchor and "process_instruction" in content:
        findings.append(MultiChainFinding(
            rule_id="SC-SOL-NA-002",
            chain="SOLANA", severity="HIGH",
            category="ACCESS_CONTROL",
            title="No account owner check",
            description="Account ownership is not verified. An attacker can pass "
                        "a malicious account owned by a different program.",
            file=path, cwe="CWE-284",
            remediation="Verify account.owner == &program_id before reading/writing account data.",
        ))

    # SC-SOL-NA-003: unchecked arithmetic
    if _SOL_UNCHECKED_ARITH.search(content) and not has_checked_arith:
        for i, line in enumerate(lines, 1):
            if _SOL_UNCHECKED_ARITH.search(line) and not _SOL_CHECKED_ARITH.search(line):
                findings.append(MultiChainFinding(
                    rule_id="SC-SOL-NA-003",
                    chain="SOLANA", severity="HIGH",
                    category="ARITHMETIC",
                    title="Unchecked arithmetic (potential overflow)",
                    description="Arithmetic operation without checked_add/checked_sub/checked_mul. "
                                "In release builds, overflow panics are disabled by default in Solana.",
                    file=path, line=i, evidence=line.strip(), cwe="CWE-190",
                    remediation="Replace += with .checked_add().ok_or(ProgramError::Overflow)? "
                                "or enable overflow-checks = true in Cargo.toml.",
                ))
                break

    # SC-SOL-NA-004 / SC-SOL-NA-005: unsafe CPI
    for i, line in enumerate(lines, 1):
        if _SOL_INVOKE.search(line):
            if _SOL_ARBITRARY_CPI.search(line):
                findings.append(MultiChainFinding(
                    rule_id="SC-SOL-NA-005",
                    chain="SOLANA", severity="CRITICAL",
                    category="ACCESS_CONTROL",
                    title="Arbitrary program CPI — target program not validated",
                    description="Calling invoke() on an account that is not validated as a "
                                "specific program allows an attacker to substitute a malicious program.",
                    file=path, line=i, evidence=line.strip(), cwe="CWE-284",
                    remediation="Check cpi_program.key == &expected_program_id before invoke().",
                ))
            else:
                findings.append(MultiChainFinding(
                    rule_id="SC-SOL-NA-004",
                    chain="SOLANA", severity="MEDIUM",
                    category="ACCESS_CONTROL",
                    title="Cross-program invocation — verify signer seeds",
                    description="CPI detected. Ensure signer_seeds are correct when using "
                                "invoke_signed and that the callee program is the expected one.",
                    file=path, line=i, evidence=line.strip(), cwe="CWE-284",
                    remediation="Always validate the CPI target program key and use invoke_signed "
                                "with correct PDA seeds.",
                ))
            break

    # SC-SOL-NA-006: unchecked deserialization
    for i, line in enumerate(lines, 1):
        if _SOL_DISCRIMINATOR.search(line):
            findings.append(MultiChainFinding(
                rule_id="SC-SOL-NA-006",
                chain="SOLANA", severity="HIGH",
                category="LOGIC",
                title="Unchecked account deserialization",
                description="try_from_slice_unchecked skips discriminator validation. "
                            "An attacker can pass an account of a different type.",
                file=path, line=i, evidence=line.strip(), cwe="CWE-345",
                remediation="Use try_from_slice() which validates the 8-byte Anchor discriminator, "
                            "or manually check the discriminator bytes.",
            ))

    return findings


# ─── CosmWasm patterns ────────────────────────────────────────────────────────

_CW_ADMIN_CHECK     = re.compile(r'ADMIN\.load|admin\s*==\s*info\.sender|ensure_admin|only_owner', re.I)
_CW_EXECUTE_FN      = re.compile(r'pub fn execute\s*\(|ExecuteMsg::', re.I)
_CW_FUNDS_CHECK     = re.compile(r'info\.funds|must_pay|nonpayable|one_coin', re.I)
_CW_REPLY_MATCH     = re.compile(r'pub fn reply\s*\(')
_CW_REPLY_ID        = re.compile(r'REPLY_ID|reply_id|msg\.id\s*==')
_CW_STATE_BEFORE    = re.compile(r'\bSAVE\b|\bstore\(\)|\.save\s*\(', re.I)
_CW_SUBMSG          = re.compile(r'SubMsg::reply_on_success|SubMsg::new|SubMsg::reply_always')
_CW_HARDCODED_ADDR  = re.compile(r'"cosmos[0-9a-z]{39}"|"osmo[0-9a-z]{39}"|"juno[0-9a-z]{39}"')


def _audit_cosmwasm(content: str, path: str) -> List[MultiChainFinding]:
    findings: List[MultiChainFinding] = []
    lines = content.splitlines()

    has_execute   = _CW_EXECUTE_FN.search(content) is not None
    has_admin     = _CW_ADMIN_CHECK.search(content) is not None
    has_funds     = _CW_FUNDS_CHECK.search(content) is not None
    has_reply_id  = _CW_REPLY_ID.search(content) is not None
    has_reply_fn  = _CW_REPLY_MATCH.search(content) is not None
    has_submsg    = _CW_SUBMSG.search(content) is not None

    # SC-CW-001: no admin check in execute
    if has_execute and not has_admin:
        findings.append(MultiChainFinding(
            rule_id="SC-CW-001",
            chain="COSMWASM", severity="HIGH",
            category="ACCESS_CONTROL",
            title="Execute handler missing admin/ownership check",
            description="ExecuteMsg handler does not appear to validate the caller "
                        "against a stored admin address.",
            file=path, cwe="CWE-284",
            remediation="Load admin from storage and assert info.sender == admin. "
                        "Use cw-ownable crate for standardized ownership.",
        ))

    # SC-CW-002: execute without funds validation
    if has_execute and not has_funds:
        findings.append(MultiChainFinding(
            rule_id="SC-CW-002",
            chain="COSMWASM", severity="MEDIUM",
            category="LOGIC",
            title="Execute handler does not validate attached funds",
            description="No funds validation found. If the contract expects payment, "
                        "callers could invoke without sending tokens.",
            file=path, cwe="CWE-754",
            remediation="Use cw_utils::must_pay(&info, &denom) or nonpayable(&info) "
                        "to explicitly handle fund expectations.",
        ))

    # SC-CW-003: reply without id check
    if has_reply_fn and not has_reply_id:
        findings.append(MultiChainFinding(
            rule_id="SC-CW-003",
            chain="COSMWASM", severity="HIGH",
            category="LOGIC",
            title="Reply handler missing msg.id validation",
            description="Reply handler does not check msg.id. Multiple sub-messages "
                        "with different IDs may be handled incorrectly.",
            file=path, cwe="CWE-754",
            remediation="Match on msg.id: match msg.id { REPLY_ID_A => ..., REPLY_ID_B => ..., "
                        "_ => Err(ContractError::UnknownReplyId) }",
        ))

    # SC-CW-004: state write before sub-message reply
    if has_submsg:
        for i, line in enumerate(lines, 1):
            if _CW_STATE_BEFORE.search(line):
                after = "\n".join(lines[i:min(len(lines), i+8)])
                if _CW_SUBMSG.search(after):
                    findings.append(MultiChainFinding(
                        rule_id="SC-CW-004",
                        chain="COSMWASM", severity="MEDIUM",
                        category="LOGIC",
                        title="State written before sub-message reply",
                        description="State is saved before dispatching a sub-message whose reply "
                                    "may fail. On sub-message failure, state may be inconsistent.",
                        file=path, line=i, evidence=line.strip(), cwe="CWE-362",
                        remediation="Write state in the reply handler after confirming success, "
                                    "not before dispatching the sub-message.",
                    ))
                    break

    # SC-CW-005: hardcoded address
    for i, line in enumerate(lines, 1):
        if _CW_HARDCODED_ADDR.search(line):
            findings.append(MultiChainFinding(
                rule_id="SC-CW-005",
                chain="COSMWASM", severity="LOW",
                category="LOGIC",
                title="Hardcoded bech32 address",
                description="A hardcoded chain address reduces portability across networks "
                            "(mainnet/testnet) and makes upgrades harder.",
                file=path, line=i, evidence=line.strip(), cwe="CWE-547",
                remediation="Store addresses in InstantiateMsg and save to contract state.",
            ))

    return findings


# ─── MultiChainAuditor ───────────────────────────────────────────────────────

class MultiChainAuditor:
    """
    Multi-chain smart contract auditor supporting Solana (Rust/Anchor)
    and CosmWasm (Rust) in addition to the Phase 10 TON/Solidity auditor.

    Usage:
        auditor = MultiChainAuditor()
        findings = auditor.audit_file("/path/to/program.rs")
        result   = auditor.audit_directory("/path/to/project")
    """

    def audit_file(self, file_path: str) -> List[MultiChainFinding]:
        p = Path(file_path)
        if not p.exists() or p.suffix.lower() != ".rs":
            return []
        content = p.read_text(errors="replace")
        chain   = self._detect_chain(content)
        if chain == "SOLANA":
            return _audit_solana(content, file_path)
        if chain == "COSMWASM":
            return _audit_cosmwasm(content, file_path)
        return []

    def audit_content(self, content: str, chain: str,
                      virtual_path: str = "<input>") -> List[MultiChainFinding]:
        """Audit raw Rust source. chain: 'solana' | 'cosmwasm'."""
        c = chain.lower()
        if c == "solana":
            return _audit_solana(content, virtual_path)
        if c == "cosmwasm":
            return _audit_cosmwasm(content, virtual_path)
        return []

    def audit_directory(self, directory: str) -> dict:
        root = Path(directory)
        findings: List[MultiChainFinding] = []
        files_scanned = 0

        for p in root.rglob("*.rs"):
            if "__pycache__" in str(p) or "target" in str(p).split("/"):
                continue
            new = self.audit_file(str(p))
            findings.extend(new)
            files_scanned += 1

        by_chain: Dict[str, int] = {}
        severity_counts: Dict[str, int] = {}
        for f in findings:
            by_chain[f.chain] = by_chain.get(f.chain, 0) + 1
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        return {
            "findings":        [f.to_dict() for f in findings],
            "total":           len(findings),
            "files_scanned":   files_scanned,
            "by_chain":        by_chain,
            "severity_counts": severity_counts,
        }

    @staticmethod
    def _detect_chain(content: str) -> Optional[str]:
        if "cosmwasm_std" in content or "cw_storage_plus" in content or "ExecuteMsg" in content:
            return "COSMWASM"
        if "solana_program" in content or "anchor_lang" in content or "AccountInfo" in content:
            return "SOLANA"
        return None

    @staticmethod
    def supported_chains() -> List[str]:
        return ["SOLANA", "COSMWASM"]
