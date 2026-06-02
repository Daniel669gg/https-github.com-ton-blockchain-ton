"""
TythanAI Phase 10 — Smart Contract Auditor

Static analysis for TON (FunC/Tolk) and EVM (Solidity) smart contracts.
Detects common vulnerability patterns and produces structured findings.

Rule IDs:
  SC-TON-001: Unchecked message sender (missing sender validation)
  SC-TON-002: Unsafe random (block-based or weak PRNG)
  SC-TON-003: Unbounded gas consumption loop
  SC-TON-004: Missing bounce handler
  SC-TON-005: Hardcoded address in contract logic
  SC-SOL-001: Reentrancy pattern (state after external call)
  SC-SOL-002: Integer overflow without SafeMath / Solidity <0.8
  SC-SOL-003: tx.origin used for authentication
  SC-SOL-004: Unchecked low-level call return value
  SC-SOL-005: Unprotected selfdestruct
  SC-SOL-006: Block timestamp dependency
  SC-COM-001: Hardcoded credentials / private key in source
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


# ─── Finding dataclass ────────────────────────────────────────────────────────

@dataclass
class ContractFinding:
    rule_id:     str
    severity:    str        # CRITICAL | HIGH | MEDIUM | LOW | INFO
    category:    str        # ACCESS_CONTROL | ARITHMETIC | RANDOMNESS | GAS | LOGIC
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


# ─── FunC / Tolk analyzer ────────────────────────────────────────────────────

_FUNC_RANDOM   = re.compile(r'\brandom\(\s*\)|\bnow\(\s*\)\s*%', re.I)
_FUNC_LOOP     = re.compile(r'\brepeat\s*\(|while\s*\(true\)', re.I)
_FUNC_HARDADDR = re.compile(r'addr_none|"[EUk][Qq][A-Za-z0-9_\-]{44,48}"')
_FUNC_SENDER   = re.compile(r'get_sender\(\)|sender_address', re.I)
_FUNC_BOUNCE   = re.compile(r'bounced\$', re.I)
_FUNC_LOAD_MSG = re.compile(r'load_msg_addr\b')

_CRED_PATTERN  = re.compile(
    r'(private_key|secret_key|mnemonic|seed)\s*=\s*"[^"]{8,}"',
    re.I,
)


def _audit_func(content: str, path: str) -> List[ContractFinding]:
    findings: List[ContractFinding] = []
    lines = content.splitlines()

    has_bounce  = _FUNC_BOUNCE.search(content) is not None
    has_sender  = _FUNC_SENDER.search(content) is not None or _FUNC_LOAD_MSG.search(content) is not None

    # SC-TON-001: missing sender validation
    if not has_sender:
        findings.append(ContractFinding(
            rule_id="SC-TON-001",
            severity="HIGH",
            category="ACCESS_CONTROL",
            title="No sender address validation found",
            description="Contract does not appear to validate the message sender. "
                        "Any account can call privileged operations.",
            file=path, cwe="CWE-284",
            remediation="Call load_msg_addr() on in_msg_full and compare against stored owner/admin.",
        ))

    # SC-TON-004: missing bounce handler
    if not has_bounce and "recv_internal" in content:
        findings.append(ContractFinding(
            rule_id="SC-TON-004",
            severity="MEDIUM",
            category="LOGIC",
            title="No bounce message handler",
            description="Contract sends messages but has no bounced$ handler. "
                        "Failed messages may lead to incorrect state.",
            file=path, cwe="CWE-754",
            remediation="Add a bounced$ handler to reset state when outbound messages bounce back.",
        ))

    for i, line in enumerate(lines, 1):
        stripped = line.strip()

        # SC-TON-002: weak randomness
        if _FUNC_RANDOM.search(line):
            findings.append(ContractFinding(
                rule_id="SC-TON-002",
                severity="HIGH",
                category="RANDOMNESS",
                title="Weak or block-dependent randomness",
                description="Using now() % N or random() is predictable. "
                            "Miners/validators can influence the outcome.",
                file=path, line=i, evidence=stripped, cwe="CWE-338",
                remediation="Use commit-reveal scheme or TON randomize_lt().",
            ))

        # SC-TON-003: unbounded loop
        if _FUNC_LOOP.search(line):
            findings.append(ContractFinding(
                rule_id="SC-TON-003",
                severity="MEDIUM",
                category="GAS",
                title="Potentially unbounded loop",
                description="Unbounded repeat() or while(true) may exhaust gas and cause DoS.",
                file=path, line=i, evidence=stripped, cwe="CWE-400",
                remediation="Bound all loops with a safe maximum iteration count.",
            ))

        # SC-TON-005: hardcoded address
        if _FUNC_HARDADDR.search(line):
            findings.append(ContractFinding(
                rule_id="SC-TON-005",
                severity="LOW",
                category="LOGIC",
                title="Hardcoded address in contract",
                description="Hardcoded addresses reduce upgradeability and may expose privileged roles.",
                file=path, line=i, evidence=stripped, cwe="CWE-547",
                remediation="Store privileged addresses in contract storage and allow authorized updates.",
            ))

        # SC-COM-001: credential in source
        if _CRED_PATTERN.search(line):
            findings.append(ContractFinding(
                rule_id="SC-COM-001",
                severity="CRITICAL",
                category="SECRETS",
                title="Hardcoded credential or private key",
                description="A private key, mnemonic, or secret is embedded in source code.",
                file=path, line=i,
                evidence=re.sub(r'"[^"]{4,}"', '"***"', stripped),
                cwe="CWE-798",
                remediation="Remove credentials from source. Use environment variables or a secrets manager.",
            ))

    return findings


# ─── Solidity analyzer ───────────────────────────────────────────────────────

_SOL_VERSION     = re.compile(r'pragma\s+solidity\s+([^;]+);')
_SOL_EXTCALL     = re.compile(r'\.(call|delegatecall|transfer|send)\s*[\(\{]')
_SOL_STATE_WRITE = re.compile(r'\b\w+\s*[\+\-\*]?=\s*(?!.*require)')
_SOL_TX_ORIGIN   = re.compile(r'\btx\.origin\b')
_SOL_SELFDEST    = re.compile(r'\bselfdestruct\s*\(|\bsuicide\s*\(')
_SOL_TIMESTAMP   = re.compile(r'\bblock\.timestamp\b|\bnow\b')
_SOL_LOW_CALL    = re.compile(r'\.call\{[^}]*\}\s*\(|\.call\s*\(')
_SOL_CALL_RET    = re.compile(r'(bool\s+\w+\s*,?\s*)?\(bool\s+success')


def _solidity_version_old(content: str) -> bool:
    m = _SOL_VERSION.search(content)
    if not m:
        return False
    ver_str = m.group(1).strip()
    m2 = re.search(r'(\d+)\.(\d+)', ver_str)
    if m2:
        major, minor = int(m2.group(1)), int(m2.group(2))
        return major == 0 and minor < 8
    return False


def _audit_solidity(content: str, path: str) -> List[ContractFinding]:
    findings: List[ContractFinding] = []
    lines = content.splitlines()
    old_version = _solidity_version_old(content)

    # SC-SOL-002: integer overflow with old compiler
    if old_version and "SafeMath" not in content:
        findings.append(ContractFinding(
            rule_id="SC-SOL-002",
            severity="HIGH",
            category="ARITHMETIC",
            title="Integer overflow risk (Solidity <0.8 without SafeMath)",
            description="Solidity <0.8 does not revert on overflow. Without SafeMath, "
                        "arithmetic operations can wrap silently.",
            file=path, cwe="CWE-190",
            remediation="Upgrade to Solidity >=0.8.0 or use OpenZeppelin SafeMath.",
        ))

    call_lines: List[int] = []
    for i, line in enumerate(lines, 1):
        stripped = line.strip()

        # SC-SOL-003: tx.origin auth
        if _SOL_TX_ORIGIN.search(line) and re.search(r'require|if\s*\(', line):
            findings.append(ContractFinding(
                rule_id="SC-SOL-003",
                severity="HIGH",
                category="ACCESS_CONTROL",
                title="tx.origin used for authentication",
                description="tx.origin refers to the original transaction sender, not the immediate caller. "
                            "Phishing contracts can bypass this check.",
                file=path, line=i, evidence=stripped, cwe="CWE-284",
                remediation="Replace tx.origin with msg.sender.",
            ))

        # SC-SOL-005: unprotected selfdestruct
        if _SOL_SELFDEST.search(line):
            has_modifier = any(
                kw in lines[max(0, i-10):i]
                for kw in ["onlyOwner", "require(msg.sender", "modifier"]
            )
            if not has_modifier:
                findings.append(ContractFinding(
                    rule_id="SC-SOL-005",
                    severity="CRITICAL",
                    category="ACCESS_CONTROL",
                    title="Unprotected selfdestruct",
                    description="selfdestruct() is callable without an owner check. "
                                "Any caller can destroy the contract and drain its balance.",
                    file=path, line=i, evidence=stripped, cwe="CWE-284",
                    remediation="Guard selfdestruct with onlyOwner or equivalent access control.",
                ))

        # SC-SOL-006: timestamp dependency
        if _SOL_TIMESTAMP.search(line) and re.search(r'require|if\s*\(|<=|>=|==', line):
            findings.append(ContractFinding(
                rule_id="SC-SOL-006",
                severity="MEDIUM",
                category="LOGIC",
                title="Block timestamp dependency",
                description="block.timestamp can be manipulated by miners within ~15 seconds. "
                            "Do not use it for precise timing or randomness.",
                file=path, line=i, evidence=stripped, cwe="CWE-829",
                remediation="Use block.number for ordering or Chainlink VRF for randomness.",
            ))

        # Track external calls for reentrancy check
        if _SOL_EXTCALL.search(line):
            call_lines.append(i)

        # SC-SOL-004: unchecked low-level call
        if _SOL_LOW_CALL.search(line):
            # Look ahead: if next few lines don't check return value
            lookahead = "\n".join(lines[i:min(len(lines), i+4)])
            if "success" not in lookahead and "require" not in lookahead:
                findings.append(ContractFinding(
                    rule_id="SC-SOL-004",
                    severity="HIGH",
                    category="LOGIC",
                    title="Unchecked low-level call return value",
                    description="Low-level .call() return value is not checked. "
                                "Silent failures can leave contract in inconsistent state.",
                    file=path, line=i, evidence=stripped, cwe="CWE-252",
                    remediation="Always check: (bool success,) = addr.call{...}(); require(success);",
                ))

    # SC-SOL-001: reentrancy heuristic
    if call_lines:
        for call_line in call_lines:
            after = "\n".join(lines[call_line:min(len(lines), call_line + 8)])
            if re.search(r'\b\w+\s*[\+\-]?=\s*\w+|\bbalances?\s*\[', after):
                findings.append(ContractFinding(
                    rule_id="SC-SOL-001",
                    severity="CRITICAL",
                    category="LOGIC",
                    title="Potential reentrancy: state written after external call",
                    description="State variables are modified after an external call. "
                                "A malicious contract can re-enter before state is updated.",
                    file=path, line=call_line, cwe="CWE-841",
                    remediation="Apply checks-effects-interactions pattern or use ReentrancyGuard.",
                ))
                break

    # SC-COM-001
    for i, line in enumerate(lines, 1):
        if _CRED_PATTERN.search(line):
            findings.append(ContractFinding(
                rule_id="SC-COM-001",
                severity="CRITICAL",
                category="SECRETS",
                title="Hardcoded credential in Solidity source",
                description="A private key or secret is embedded in source code.",
                file=path, line=i,
                evidence=re.sub(r'"[^"]{4,}"', '"***"', line.strip()),
                cwe="CWE-798",
                remediation="Remove credentials from source code.",
            ))

    return findings


# ─── SmartContractAuditor ────────────────────────────────────────────────────

class SmartContractAuditor:
    """
    Static auditor for TON (FunC/Tolk) and EVM (Solidity) smart contracts.

    Usage:
        auditor = SmartContractAuditor()
        result = auditor.audit_file("/path/to/contract.fc")
        result = auditor.audit_directory("/path/to/project")
    """

    # Extensions → analyzer
    _FUNC_EXTS = {".fc", ".func", ".tolk"}
    _SOL_EXTS  = {".sol"}

    def audit_file(self, file_path: str) -> List[ContractFinding]:
        p = Path(file_path)
        if not p.exists():
            return []
        content = p.read_text(errors="replace")
        ext = p.suffix.lower()

        if ext in self._FUNC_EXTS:
            return _audit_func(content, file_path)
        if ext in self._SOL_EXTS:
            return _audit_solidity(content, file_path)
        return []

    def audit_directory(self, directory: str) -> dict:
        root = Path(directory)
        findings: List[ContractFinding] = []
        files_scanned = 0
        all_exts = self._FUNC_EXTS | self._SOL_EXTS

        for p in root.rglob("*"):
            if p.is_file() and p.suffix.lower() in all_exts:
                findings.extend(self.audit_file(str(p)))
                files_scanned += 1

        severity_counts: Dict[str, int] = {}
        for f in findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        return {
            "findings":         [f.to_dict() for f in findings],
            "total":            len(findings),
            "files_scanned":    files_scanned,
            "severity_counts":  severity_counts,
            "critical":         severity_counts.get("CRITICAL", 0),
            "high":             severity_counts.get("HIGH", 0),
            "medium":           severity_counts.get("MEDIUM", 0),
            "low":              severity_counts.get("LOW", 0),
        }

    def audit_content(self, content: str, language: str, virtual_path: str = "<input>") -> List[ContractFinding]:
        """Audit raw source string. language: 'func' | 'tolk' | 'solidity'."""
        lang = language.lower()
        if lang in ("func", "tolk", "funC"):
            return _audit_func(content, virtual_path)
        if lang in ("solidity", "sol"):
            return _audit_solidity(content, virtual_path)
        return []
