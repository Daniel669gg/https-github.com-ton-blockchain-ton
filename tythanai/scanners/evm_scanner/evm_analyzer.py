"""
TythanAI Platform — EVM / Solidity Security Scanner
Static analysis for EVM-compatible smart contracts (.sol, .vy).

Detects: reentrancy, tx.origin auth, unchecked return values, integer
overflow/underflow, delegatecall to user address, selfdestruct exposure,
block timestamp dependency, weak randomness, missing access control,
uninitialized storage pointers, front-running, flash loan vectors, price
oracle manipulation, proxy storage collision, ERC-20 approve race, and
signature replay attacks.
"""

import re
from pathlib import Path
from typing import Dict, List, Tuple


# ---------------------------------------------------------------------------
# Rule definitions
# Each rule: id, name, severity, cwe, owasp, pattern (line-level regex or
# multi-line flag), confidence, fix, description, scanner, multi (bool)
# ---------------------------------------------------------------------------

_EVM_RULES: List[Dict] = [
    # ── GHOST-EVM-001  Reentrancy ──────────────────────────────────────────
    {
        "rule_id": "GHOST-EVM-001",
        "name": "Reentrancy vulnerability",
        "severity": "CRITICAL",
        "cwe": "CWE-841",
        "owasp": "A01:2021",
        "pattern": r"""(?x)
            \.call\s*\{[^}]*\}\s*\(    # .call{value:...}(
            | \.transfer\s*\(           # .transfer(
            | \.send\s*\(               # .send(
        """,
        "confidence": 0.82,
        "description": (
            "External call before state change allows reentrancy — attacker "
            "can re-enter the function before balances/state are updated."
        ),
        "fix": (
            "Apply checks-effects-interactions pattern: update all state "
            "variables BEFORE any external call. Use OpenZeppelin "
            "ReentrancyGuard (nonReentrant modifier) on vulnerable functions."
        ),
        "scanner": "evm_scanner",
        "multi": False,
    },

    # ── GHOST-EVM-002  tx.origin authentication ────────────────────────────
    {
        "rule_id": "GHOST-EVM-002",
        "name": "tx.origin used for authentication",
        "severity": "HIGH",
        "cwe": "CWE-284",
        "owasp": "A01:2021",
        "pattern": r"tx\.origin\s*(?:==|!=|<=|>=)",
        "confidence": 0.92,
        "description": (
            "tx.origin returns the original EOA that initiated the transaction. "
            "A malicious intermediate contract can trick legitimate users into "
            "calling it and bypass tx.origin-based auth checks."
        ),
        "fix": "Replace tx.origin with msg.sender for all authorization checks.",
        "scanner": "evm_scanner",
        "multi": False,
    },

    # ── GHOST-EVM-003  Unchecked return value ─────────────────────────────
    {
        "rule_id": "GHOST-EVM-003",
        "name": "Unchecked low-level call return value",
        "severity": "HIGH",
        "cwe": "CWE-252",
        "owasp": "A05:2021",
        "pattern": (
            r"(?<!\(bool\s)\b\w+\.call\s*\{[^}]*\}\s*\([^)]*\)\s*;"
            r"|(?<!\(bool\s)\b\w+\.call\s*\([^)]*\)\s*;"
        ),
        "confidence": 0.75,
        "description": (
            "Low-level .call() return value is not checked. If the call "
            "fails silently, the contract continues execution as if it "
            "succeeded, leading to lost funds or inconsistent state."
        ),
        "fix": (
            "(bool success, ) = target.call{...}(...); "
            "require(success, 'Call failed');"
        ),
        "scanner": "evm_scanner",
        "multi": False,
    },

    # ── GHOST-EVM-004  Integer overflow/underflow (pre-0.8) ───────────────
    {
        "rule_id": "GHOST-EVM-004",
        "name": "Integer overflow/underflow (pre-0.8.0 style)",
        "severity": "HIGH",
        "cwe": "CWE-190",
        "owasp": "A02:2021",
        "pattern": (
            r"pragma solidity\s+[\^~]?0\.[0-7]\."
            r"|uint\d*\s+\w+\s*=\s*\w+\s*\+\s*\w+"
            r"|balances\[\w+\]\s*[+\-]=\s*"
            r"|totalSupply\s*[+\-]=\s*"
        ),
        "confidence": 0.70,
        "description": (
            "Arithmetic operation without overflow/underflow protection "
            "detected (or a pre-0.8 pragma is in use). In Solidity <0.8.0 "
            "integers wrap silently, allowing balance manipulation."
        ),
        "fix": (
            "Upgrade to Solidity >=0.8.0 (built-in overflow checks) or "
            "use OpenZeppelin SafeMath for all arithmetic on untrusted values."
        ),
        "scanner": "evm_scanner",
        "multi": False,
    },

    # ── GHOST-EVM-005  Delegatecall to user-supplied address ──────────────
    {
        "rule_id": "GHOST-EVM-005",
        "name": "Delegatecall to user-controlled address",
        "severity": "CRITICAL",
        "cwe": "CWE-829",
        "owasp": "A08:2021",
        "pattern": r"delegatecall\s*\(",
        "confidence": 0.80,
        "description": (
            "delegatecall executes arbitrary code in the calling contract's "
            "storage context. If the target address is user-supplied or "
            "untrusted, an attacker can wipe or corrupt storage and steal funds."
        ),
        "fix": (
            "Only delegatecall to hardcoded, audited implementation addresses. "
            "Use EIP-1967 proxy pattern and store implementation in a "
            "collision-resistant slot. Never pass user-supplied addresses."
        ),
        "scanner": "evm_scanner",
        "multi": False,
    },

    # ── GHOST-EVM-006  Selfdestruct accessibility ─────────────────────────
    {
        "rule_id": "GHOST-EVM-006",
        "name": "Selfdestruct without access control",
        "severity": "CRITICAL",
        "cwe": "CWE-284",
        "owasp": "A01:2021",
        "pattern": r"\bselfdestruct\s*\(",
        "confidence": 0.88,
        "description": (
            "selfdestruct destroys the contract and sends its ETH balance to a "
            "specified address. If callable by anyone, attackers can destroy the "
            "contract and steal its balance."
        ),
        "fix": (
            "Protect selfdestruct with onlyOwner or a multi-sig guard. "
            "Consider removing selfdestruct entirely in new contracts per EIP-6780."
        ),
        "scanner": "evm_scanner",
        "multi": False,
    },

    # ── GHOST-EVM-007  Block timestamp dependency ─────────────────────────
    {
        "rule_id": "GHOST-EVM-007",
        "name": "Block timestamp dependency",
        "severity": "MEDIUM",
        "cwe": "CWE-338",
        "owasp": "A02:2021",
        "pattern": r"\bblock\.timestamp\b",
        "confidence": 0.72,
        "description": (
            "block.timestamp can be manipulated by validators/miners within a "
            "roughly 15-second window. Using it for critical logic (deadlines, "
            "lotteries, order matching) creates exploitable race conditions."
        ),
        "fix": (
            "Avoid block.timestamp for randomness or fine-grained timing. "
            "For deadlines, use >=15 second tolerances. "
            "Consider block.number + average block-time calculations instead."
        ),
        "scanner": "evm_scanner",
        "multi": False,
    },

    # ── GHOST-EVM-008  Weak randomness ────────────────────────────────────
    {
        "rule_id": "GHOST-EVM-008",
        "name": "Weak on-chain randomness",
        "severity": "HIGH",
        "cwe": "CWE-338",
        "owasp": "A02:2021",
        "pattern": (
            r"\bblockhash\s*\("
            r"|\bblock\.difficulty\b"
            r"|\bblock\.prevrandao\b(?=.*rand)"
        ),
        "confidence": 0.85,
        "description": (
            "blockhash and block.difficulty/prevrandao are known to miners "
            "and validators and can be manipulated. Contracts relying on these "
            "for randomness are exploitable in lotteries and NFT minting."
        ),
        "fix": (
            "Use Chainlink VRF (Verifiable Random Function) for secure "
            "on-chain randomness. As a fallback, use a commit-reveal scheme "
            "but note it is only manipulation-resistant, not unpredictable."
        ),
        "scanner": "evm_scanner",
        "multi": False,
    },

    # ── GHOST-EVM-009  Missing access control on critical functions ────────
    {
        "rule_id": "GHOST-EVM-009",
        "name": "Missing access control on state-changing function",
        "severity": "HIGH",
        "cwe": "CWE-284",
        "owasp": "A01:2021",
        "pattern": (
            r"function\s+(?:mint|burn|withdraw|setOwner|setAdmin|pause|unpause|"
            r"upgrade|initialize|emergencyWithdraw|drainFunds|setFee|"
            r"transferOwnership)\s*\([^)]*\)\s*(?:public|external)\s*"
            r"(?!.*(?:onlyOwner|onlyRole|onlyAdmin|require\s*\())"
        ),
        "confidence": 0.75,
        "description": (
            "Sensitive administrative function (mint/burn/withdraw/upgrade) "
            "appears to be publicly callable without an access control modifier. "
            "An attacker could call it to drain funds or take control."
        ),
        "fix": (
            "Add onlyOwner or OpenZeppelin AccessControl role modifier. "
            "Alternatively, add require(msg.sender == owner, 'Unauthorized') "
            "as the first statement in the function body."
        ),
        "scanner": "evm_scanner",
        "multi": False,
    },

    # ── GHOST-EVM-010  Uninitialized storage pointer ──────────────────────
    {
        "rule_id": "GHOST-EVM-010",
        "name": "Uninitialized storage pointer",
        "severity": "HIGH",
        "cwe": "CWE-457",
        "owasp": "A02:2021",
        "pattern": r"\bstorage\b\s+\w+\s*;(?!\s*=)",
        "confidence": 0.70,
        "description": (
            "A storage pointer is declared but not initialized. In Solidity "
            "<0.5.0 this defaults to slot 0, allowing an attacker to overwrite "
            "critical state variables. Even in newer versions, explicit "
            "initialization is required for correctness."
        ),
        "fix": (
            "Always initialize storage pointers: "
            "MyStruct storage s = myMapping[key]; "
            "Upgrade to Solidity >=0.5.0 which rejects uninitialized pointers."
        ),
        "scanner": "evm_scanner",
        "multi": False,
    },

    # ── GHOST-EVM-011  Front-running vulnerability ────────────────────────
    {
        "rule_id": "GHOST-EVM-011",
        "name": "Front-running vulnerability",
        "severity": "MEDIUM",
        "cwe": "CWE-362",
        "owasp": "A02:2021",
        "pattern": (
            r"function\s+\w+\s*\([^)]*\)\s*(?:public|external).*\n"
            r"(?:.*\n){0,8}.*(?:tx\.gasprice|block\.basefee|gasleft\s*\()"
        ),
        "confidence": 0.65,
        "description": (
            "Function uses gas price or block base fee in logic, creating "
            "front-running opportunities. MEV bots can observe pending "
            "transactions and pay more gas to be included first."
        ),
        "fix": (
            "Use commit-reveal schemes or a DEX aggregator with slippage "
            "protection. Consider using Flashbots or private mempools for "
            "sensitive operations. Add deadline and minAmountOut parameters."
        ),
        "scanner": "evm_scanner",
        "multi": True,
    },

    # ── GHOST-EVM-012  Flash loan attack vector ───────────────────────────
    {
        "rule_id": "GHOST-EVM-012",
        "name": "Flash loan attack vector",
        "severity": "HIGH",
        "cwe": "CWE-841",
        "owasp": "A01:2021",
        "pattern": (
            r"\bflashLoan\s*\("
            r"|\bflash_loan\s*\("
            r"|\bexecuteOperation\s*\("
            r"|\bIFlashLoan\b"
            r"|\bIFlashBorrower\b"
        ),
        "confidence": 0.78,
        "description": (
            "Flash loan interface or callback detected. Contracts that alter "
            "state during a flash loan callback without re-entrancy protection "
            "or balance locks are vulnerable to single-transaction manipulation."
        ),
        "fix": (
            "Ensure flash loan callbacks cannot re-enter other contract "
            "functions. Use nonReentrant guards. Lock critical reads/writes "
            "during the loan period using a mutex flag."
        ),
        "scanner": "evm_scanner",
        "multi": False,
    },

    # ── GHOST-EVM-013  Price oracle manipulation ──────────────────────────
    {
        "rule_id": "GHOST-EVM-013",
        "name": "Price oracle manipulation",
        "severity": "CRITICAL",
        "cwe": "CWE-20",
        "owasp": "A06:2021",
        "pattern": (
            r"getReserves\s*\("
            r"|token0\s*\.\s*balanceOf\s*\("
            r"|price\s*=\s*.*balanceOf"
            r"|spot\s*[Pp]rice"
            r"|IUniswapV2Pair.*getReserves"
        ),
        "confidence": 0.72,
        "description": (
            "Contract derives price from on-chain AMM reserves (e.g., "
            "Uniswap getReserves) without using a TWAP or external oracle. "
            "An attacker can manipulate spot prices with a flash loan within "
            "a single transaction."
        ),
        "fix": (
            "Use time-weighted average price (TWAP) over multiple blocks. "
            "Integrate Chainlink price feeds or Uniswap V3 TWAP oracle. "
            "Never use instantaneous reserve ratios as prices."
        ),
        "scanner": "evm_scanner",
        "multi": False,
    },

    # ── GHOST-EVM-014  Proxy storage collision ────────────────────────────
    {
        "rule_id": "GHOST-EVM-014",
        "name": "Proxy pattern storage collision",
        "severity": "HIGH",
        "cwe": "CWE-119",
        "owasp": "A02:2021",
        "pattern": (
            r"assembly\s*\{[^}]*sload\s*\(0\)"
            r"|assembly\s*\{[^}]*sstore\s*\(0"
            r"|slot\s*:=\s*0x360894"
            r"|_IMPLEMENTATION_SLOT\s*="
        ),
        "confidence": 0.75,
        "description": (
            "Proxy contract stores implementation address or admin at a "
            "specific storage slot. If the implementation contract uses the "
            "same slot for its own variables, a storage collision occurs, "
            "allowing attackers to overwrite the implementation pointer."
        ),
        "fix": (
            "Use EIP-1967 pseudo-random storage slots for proxy variables: "
            "bytes32(uint256(keccak256('eip1967.proxy.implementation')) - 1). "
            "Use OpenZeppelin TransparentUpgradeableProxy or UUPS pattern."
        ),
        "scanner": "evm_scanner",
        "multi": False,
    },

    # ── GHOST-EVM-015  ERC-20 approve race condition ──────────────────────
    {
        "rule_id": "GHOST-EVM-015",
        "name": "ERC-20 approve/transferFrom race condition",
        "severity": "MEDIUM",
        "cwe": "CWE-362",
        "owasp": "A02:2021",
        "pattern": r"\bapprove\s*\(\s*\w+\s*,\s*\w+\s*\)",
        "confidence": 0.65,
        "description": (
            "Direct ERC-20 approve() call detected. The standard approve() "
            "is vulnerable to a front-running race: if allowance is changed "
            "from N to M, the spender can transfer N+M tokens by watching "
            "the mempool."
        ),
        "fix": (
            "Use increaseAllowance()/decreaseAllowance() (OpenZeppelin) "
            "instead of direct approve(). Alternatively reset to 0 before "
            "setting a new non-zero allowance: approve(spender, 0); "
            "approve(spender, newAmount);"
        ),
        "scanner": "evm_scanner",
        "multi": False,
    },

    # ── GHOST-EVM-016  Signature replay attack ────────────────────────────
    {
        "rule_id": "GHOST-EVM-016",
        "name": "Signature replay attack",
        "severity": "HIGH",
        "cwe": "CWE-294",
        "owasp": "A07:2021",
        "pattern": (
            r"ecrecover\s*\("
            r"|\bISIGNATURE\b"
            r"|\bSignatureChecker\b"
            r"|\bECDSA\.recover\b"
        ),
        "confidence": 0.72,
        "description": (
            "Signature verification detected without an apparent nonce or "
            "expiry check. A valid signature can be replayed in multiple "
            "transactions unless domain-separated and tied to a nonce that "
            "is consumed on use."
        ),
        "fix": (
            "Include a nonce (incremented per use) and chain ID in the signed "
            "message. Use EIP-712 structured hashing with DOMAIN_SEPARATOR. "
            "Store and invalidate used nonces: usedNonces[nonce] = true."
        ),
        "scanner": "evm_scanner",
        "multi": False,
    },
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _strip_comments(source: str) -> Tuple[str, List[str]]:
    """Remove single-line (//) and multi-line (/* */) comments.

    Returns cleaned source and a list of original lines (for line numbers).
    """
    # Remove /* ... */ (non-greedy, multi-line)
    no_block = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group().count("\n"), source, flags=re.DOTALL)
    lines_original = source.splitlines()
    # Remove // ... (single line)
    cleaned_lines = []
    for line in no_block.splitlines():
        cleaned_lines.append(re.sub(r"//.*$", "", line))
    return "\n".join(cleaned_lines), lines_original


def _build_finding(rule: Dict, file_path: str, lineno: int, evidence: str) -> Dict:
    return {
        "rule_id": rule["rule_id"],
        "name": rule["name"],
        "severity": rule["severity"],
        "file": str(file_path),
        "line": lineno,
        "column": 0,
        "description": rule["description"],
        "cwe": rule["cwe"],
        "owasp": rule.get("owasp", ""),
        "fix": rule["fix"],
        "confidence": rule["confidence"],
        "scanner": rule["scanner"],
        "evidence": evidence[:160],
    }


# ---------------------------------------------------------------------------
# EVMScanner
# ---------------------------------------------------------------------------

class EVMScanner:
    """
    Static security analyzer for EVM smart contracts (Solidity .sol, Vyper .vy).

    Usage::

        scanner = EVMScanner()
        findings = scanner.scan_file("/path/to/Contract.sol")
        result   = scanner.scan_directory("/path/to/contracts/")
    """

    SUPPORTED_EXTENSIONS = {".sol", ".vy"}

    def __init__(self) -> None:
        # Pre-compile patterns for performance
        self._compiled: List[Dict] = []
        for rule in _EVM_RULES:
            flags = re.IGNORECASE | re.MULTILINE | re.DOTALL if rule.get("multi") else re.MULTILINE
            try:
                compiled_pat = re.compile(rule["pattern"], flags)
            except re.error:
                compiled_pat = re.compile(re.escape(rule["pattern"]), flags)
            self._compiled.append({**rule, "_compiled": compiled_pat})

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_file(self, path: str) -> List[Dict]:
        """Scan a single .sol or .vy file and return a list of findings."""
        p = Path(path)
        if p.suffix.lower() not in self.SUPPORTED_EXTENSIONS:
            return []
        try:
            raw = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []

        cleaned, original_lines = _strip_comments(raw)

        findings: List[Dict] = []
        seen: set = set()

        for rule in self._compiled:
            if rule.get("multi"):
                # Multi-line scan: find match positions and map back to line numbers
                for m in rule["_compiled"].finditer(cleaned):
                    lineno = cleaned[: m.start()].count("\n") + 1
                    key = (rule["rule_id"], lineno)
                    if key in seen:
                        continue
                    seen.add(key)
                    evidence = (original_lines[lineno - 1] if lineno <= len(original_lines) else "").strip()
                    findings.append(_build_finding(rule, p, lineno, evidence))
            else:
                # Line-by-line scan
                for lineno, line in enumerate(cleaned.splitlines(), 1):
                    stripped = line.strip()
                    if not stripped:
                        continue
                    if rule["_compiled"].search(stripped):
                        key = (rule["rule_id"], lineno)
                        if key in seen:
                            continue
                        seen.add(key)
                        orig = (original_lines[lineno - 1] if lineno <= len(original_lines) else "").strip()
                        findings.append(_build_finding(rule, p, lineno, orig))

        return findings

    def scan_directory(self, path: str) -> Dict:
        """Recursively scan a directory for EVM contracts.

        Returns::

            {
                "findings": [...],
                "files_scanned": N,
                "total_findings": N,
                "severity_counts": {"CRITICAL": N, ...},
            }
        """
        root = Path(path)
        all_findings: List[Dict] = []
        files_scanned = 0
        severity_counts: Dict[str, int] = {
            "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0
        }

        for ext in self.SUPPORTED_EXTENSIONS:
            for file in root.rglob(f"*{ext}"):
                if ".git" in file.parts or "node_modules" in file.parts:
                    continue
                file_findings = self.scan_file(str(file))
                all_findings.extend(file_findings)
                files_scanned += 1
                for f in file_findings:
                    sev = f.get("severity", "INFO")
                    severity_counts[sev] = severity_counts.get(sev, 0) + 1

        return {
            "findings": all_findings,
            "files_scanned": files_scanned,
            "total_findings": len(all_findings),
            "severity_counts": severity_counts,
        }
