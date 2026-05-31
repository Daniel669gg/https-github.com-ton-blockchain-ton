"""
TythanAI — Solidity / Vyper Smart Contract Analyzer (Phase 15)
=====================================================================
Dual-mode analyzer:
  1. External: invokes Slither (https://github.com/crytic/slither) via
     subprocess if the binary is found on PATH or at the configured path.
  2. Native:   pure-Python regex + AST-style pattern matching as fallback.

Covers:
  - Reentrancy (CEI violations, call.value / .call{value:} before state)
  - Integer overflow (unsafe arithmetic on uint without SafeMath/0.8 guards)
  - Access control (missing onlyOwner, tx.origin auth, unprotected selfdestruct)
  - Oracle manipulation (single-DEX price, block.timestamp usage)
  - Flash loan patterns (large single-tx balance deltas without loan guard)
  - Unchecked external calls (low-level .call without require(success))
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import time
from pathlib import Path
from typing import List, Optional, Tuple

from .base import LangAnalysisResult, LangFinding


# ---------------------------------------------------------------------------
# Helper: extract a code snippet around a line
# ---------------------------------------------------------------------------

def _snippet(lines: List[str], lineno: int, ctx: int = 2) -> str:
    """Return up to 2*ctx+1 lines centred on lineno (1-based)."""
    lo = max(0, lineno - 1 - ctx)
    hi = min(len(lines), lineno - 1 + ctx + 1)
    return "\n".join(lines[lo:hi]).strip()


def _col(line: str, pattern: re.Pattern) -> int:
    """Return 1-based column of first match in line, or 1."""
    m = pattern.search(line)
    return (m.start() + 1) if m else 1


# ---------------------------------------------------------------------------
# SolidityAnalyzer
# ---------------------------------------------------------------------------

class SolidityAnalyzer:
    """
    Analyze Solidity (.sol) and Vyper (.vy) smart-contract source trees.

    Parameters
    ----------
    slither_path : path to the slither binary; defaults to 'slither' (PATH).
    """

    LANGUAGE = "Solidity"
    SUPPORTED_EXTS = {".sol", ".vy"}

    def __init__(self, slither_path: str = "slither") -> None:
        self.slither_path = slither_path
        self._slither_ok: Optional[bool] = None   # cached probe result

    # ------------------------------------------------------------------ public

    def analyze(self, path: str) -> LangAnalysisResult:
        """
        Scan *path* (file or directory) and return a :class:`LangAnalysisResult`.

        Slither is attempted first; native analysis is always run in parallel
        so that findings from the native rules are merged in when Slither
        succeeds (avoiding duplicates by rule_id + line).
        """
        t0 = time.monotonic()
        target = Path(path)
        errors: List[str] = []
        findings: List[LangFinding] = []

        # Collect source files
        if target.is_file():
            files = [target] if target.suffix in self.SUPPORTED_EXTS else []
        else:
            files = [
                p for p in target.rglob("*")
                if p.suffix in self.SUPPORTED_EXTS
                and "node_modules" not in p.parts
            ]

        if not files:
            return LangAnalysisResult.build(
                self.LANGUAGE, [], 0, False,
                time.monotonic() - t0, ["No Solidity/Vyper files found."]
            )

        # Try Slither on the whole target
        slither_findings: List[LangFinding] = []
        try:
            slither_findings = self.run_slither(path)
        except Exception as exc:
            errors.append(f"Slither error: {exc}")

        native_findings: List[LangFinding] = []
        for fpath in files:
            try:
                native_findings.extend(self.run_native(str(fpath)))
            except Exception as exc:
                errors.append(f"Native analysis error on {fpath}: {exc}")

        # Merge: prefer Slither findings; add native only when no Slither hit
        # on the same (file, line, category) triple.
        slither_keys = {
            (f.filepath, f.line, f.category) for f in slither_findings
        }
        merged = list(slither_findings)
        for f in native_findings:
            if (f.filepath, f.line, f.category) not in slither_keys:
                merged.append(f)

        return LangAnalysisResult.build(
            self.LANGUAGE, merged, len(files),
            bool(slither_findings),
            time.monotonic() - t0, errors,
        )

    # ------------------------------------------------------------------ slither

    def run_slither(self, path: str) -> List[LangFinding]:
        """
        Invoke Slither with ``--json -`` and parse its JSON output.
        Returns an empty list (not an exception) when Slither is unavailable.
        """
        if self._slither_ok is False:
            return []
        try:
            result = subprocess.run(
                [self.slither_path, path, "--json", "-"],
                capture_output=True, text=True, timeout=120,
            )
            self._slither_ok = True
        except FileNotFoundError:
            self._slither_ok = False
            return []
        except subprocess.TimeoutExpired:
            raise RuntimeError("Slither timed out after 120 s")

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return []

        findings: List[LangFinding] = []
        for det in data.get("results", {}).get("detectors", []):
            severity_map = {
                "High": "HIGH", "Medium": "MEDIUM",
                "Low": "LOW", "Informational": "INFO",
                "Optimization": "INFO",
            }
            severity = severity_map.get(det.get("impact", "Medium"), "MEDIUM")
            for elem in det.get("elements", []):
                src = elem.get("source_mapping", {})
                fp = src.get("filename_absolute", path)
                line = src.get("lines", [0])[0]
                findings.append(LangFinding(
                    filepath=fp,
                    line=line or 1,
                    column=1,
                    rule_id=f"SLITHER-{det.get('check', 'UNKNOWN').upper()}",
                    title=det.get("check", "Unknown"),
                    description=det.get("description", "").strip(),
                    severity=severity,
                    category=det.get("check", "unknown").replace("-", "_"),
                    code_snippet=elem.get("name", ""),
                    recommendation="See Slither documentation for this detector.",
                    tool="slither",
                    confidence=0.9,
                    cwe="",
                ))
        return findings

    # ------------------------------------------------------------------ native

    def run_native(self, path: str) -> List[LangFinding]:
        """Run all native checks on a single source file."""
        source = Path(path).read_text(errors="replace")
        findings: List[LangFinding] = []
        checks = [
            self.check_reentrancy,
            self.check_integer_overflow,
            self.check_access_control,
            self.check_oracle_manipulation,
            self.check_flash_loan_patterns,
            self.check_unchecked_calls,
        ]
        for check in checks:
            try:
                results = check(source)
                # Inject filepath for results that lack it
                for f in results:
                    if not f.filepath:
                        f.filepath = path
                findings.extend(results)
            except Exception:
                pass
        # Back-fill filepath
        for f in findings:
            f.filepath = path
        return findings

    # ------------------------------------------------------------------ checks

    def check_reentrancy(self, source: str) -> List[LangFinding]:
        """
        Detect CEI (Checks-Effects-Interactions) violations.

        Heuristic: inside a function body, find .call{value: / .call.value(
        that appears BEFORE an assignment to a storage variable (balance/mapping
        update), which is the classic reentrancy pattern.
        """
        findings: List[LangFinding] = []
        lines = source.splitlines()

        # Pattern A: call.value() legacy syntax
        pat_legacy = re.compile(
            r'\.\s*call\s*\.\s*value\s*\(', re.IGNORECASE
        )
        # Pattern B: .call{value: ...}(
        pat_modern = re.compile(
            r'\.\s*call\s*\{[^}]*value\s*:', re.IGNORECASE
        )
        # Broad pattern: either
        pat_any = re.compile(
            r'\.\s*call\s*(?:\.\s*value\s*\(|\{[^}]*value\s*:)',
            re.IGNORECASE,
        )
        # State update after: assignment to mapping/balance
        pat_state = re.compile(
            r'(?:balances?|balance|_balance|amount)\s*\[.*?\]\s*[-+]?=|'
            r'\w+\s*[-+]?=\s*\w+.*?;',
            re.IGNORECASE,
        )

        func_pat = re.compile(
            r'function\s+(\w+)\s*\([^)]*\)[^{]*\{', re.DOTALL
        )

        for m in func_pat.finditer(source):
            func_start = source.count("\n", 0, m.end())
            # Find matching closing brace
            depth = 1
            pos = m.end()
            while pos < len(source) and depth:
                if source[pos] == "{":
                    depth += 1
                elif source[pos] == "}":
                    depth -= 1
                pos += 1
            func_body = source[m.end(): pos]
            call_m = pat_any.search(func_body)
            if not call_m:
                continue
            call_line_offset = func_body.count("\n", 0, call_m.start())
            lineno = func_start + call_line_offset + 1

            # Check if state update follows the external call
            after_call = func_body[call_m.end():]
            if pat_state.search(after_call):
                snippet = _snippet(lines, lineno)
                findings.append(LangFinding(
                    filepath="",
                    line=lineno,
                    column=_col(lines[lineno - 1] if lineno <= len(lines) else "", pat_any),
                    rule_id="SOL-RE-001",
                    title="Reentrancy: CEI Pattern Violation",
                    description=(
                        f"Function '{m.group(1)}' performs an external call before "
                        "updating state. This violates the Checks-Effects-Interactions "
                        "pattern and may allow a reentrant call to drain funds."
                    ),
                    severity="CRITICAL",
                    category="reentrancy",
                    code_snippet=snippet,
                    recommendation=(
                        "Update all state variables BEFORE making external calls. "
                        "Use OpenZeppelin ReentrancyGuard or the nonReentrant modifier."
                    ),
                    tool="native",
                    confidence=0.85,
                    cwe="CWE-362",
                ))

        # Pattern C: .transfer() / .send() — lower severity, but still flag
        pat_transfer = re.compile(r'\.\s*(?:transfer|send)\s*\(', re.IGNORECASE)
        for i, line in enumerate(lines, 1):
            if pat_transfer.search(line) and not line.strip().startswith("//"):
                findings.append(LangFinding(
                    filepath="",
                    line=i,
                    column=_col(line, pat_transfer),
                    rule_id="SOL-RE-002",
                    title="External Value Transfer",
                    description=(
                        "transfer()/send() forwards 2300 gas stipend. While safer "
                        "than raw .call, verify that state is updated before this call."
                    ),
                    severity="MEDIUM",
                    category="reentrancy",
                    code_snippet=line.strip(),
                    recommendation=(
                        "Prefer the pull-payment pattern. If push is required, "
                        "ensure state updates occur before the transfer."
                    ),
                    tool="native",
                    confidence=0.6,
                    cwe="CWE-362",
                ))
        return findings

    def check_integer_overflow(self, source: str) -> List[LangFinding]:
        """
        Flag arithmetic on uint/int types that may overflow.
        Specifically targets Solidity < 0.8 patterns (no unchecked guard).
        """
        findings: List[LangFinding] = []
        lines = source.splitlines()

        # Detect compiler version pragma
        ver_pat = re.compile(r'pragma\s+solidity\s+[^0-9]*(\d+)\.(\d+)')
        is_safe_version = False
        vm = ver_pat.search(source)
        if vm:
            major, minor = int(vm.group(1)), int(vm.group(2))
            if major > 0 or minor >= 8:
                is_safe_version = True

        # Arithmetic without SafeMath and outside unchecked{}
        arith_pat = re.compile(
            r'(uint\d*|int\d*)\s+\w+\s*=\s*[^;]+[+\-\*][^;]+;',
            re.IGNORECASE,
        )
        unchecked_pat = re.compile(r'\bunchecked\s*\{')

        # Build set of line ranges inside unchecked blocks
        unchecked_lines: set = set()
        for um in unchecked_pat.finditer(source):
            ub_start = source.count("\n", 0, um.end())
            depth = 1
            pos = um.end()
            while pos < len(source) and depth:
                if source[pos] == "{":
                    depth += 1
                elif source[pos] == "}":
                    depth -= 1
                pos += 1
            ub_end = source.count("\n", 0, pos)
            unchecked_lines.update(range(ub_start, ub_end + 1))

        # SafeMath usage
        has_safemath = bool(re.search(r'SafeMath', source, re.IGNORECASE))

        for i, line in enumerate(lines, 1):
            if line.strip().startswith("//"):
                continue
            m = arith_pat.search(line)
            if not m:
                continue
            if i in unchecked_lines:
                continue
            if is_safe_version and "unchecked" not in source[
                max(0, source.find(line) - 20): source.find(line) + len(line)
            ]:
                continue
            if has_safemath and re.search(r'\.add\(|\.sub\(|\.mul\(', line):
                continue
            findings.append(LangFinding(
                filepath="",
                line=i,
                column=_col(line, arith_pat),
                rule_id="SOL-OF-001",
                title="Potential Integer Overflow/Underflow",
                description=(
                    "Arithmetic operation on integer type without SafeMath "
                    "or Solidity 0.8+ overflow protection detected."
                ),
                severity="HIGH",
                category="overflow",
                code_snippet=line.strip(),
                recommendation=(
                    "Upgrade to Solidity >=0.8.0 (built-in overflow checks) or "
                    "use OpenZeppelin SafeMath library."
                ),
                tool="native",
                confidence=0.75,
                cwe="CWE-190",
            ))
        return findings

    def check_access_control(self, source: str) -> List[LangFinding]:
        """
        Detect missing access controls on sensitive functions and tx.origin usage.
        """
        findings: List[LangFinding] = []
        lines = source.splitlines()

        # tx.origin authentication
        txorigin_pat = re.compile(r'\btx\.origin\b')
        for i, line in enumerate(lines, 1):
            if txorigin_pat.search(line) and not line.strip().startswith("//"):
                findings.append(LangFinding(
                    filepath="",
                    line=i,
                    column=_col(line, txorigin_pat),
                    rule_id="SOL-AC-001",
                    title="tx.origin Authentication",
                    description=(
                        "tx.origin returns the original EOA, not the immediate caller. "
                        "A phishing contract can trick a user into calling it, "
                        "passing a tx.origin check."
                    ),
                    severity="HIGH",
                    category="access_control",
                    code_snippet=line.strip(),
                    recommendation=(
                        "Replace tx.origin with msg.sender for access control checks."
                    ),
                    tool="native",
                    confidence=0.95,
                    cwe="CWE-284",
                ))

        # selfdestruct without obvious guard
        sd_pat = re.compile(r'\bselfdestruct\s*\(')
        modifier_pat = re.compile(
            r'\b(onlyOwner|onlyAdmin|onlyRole|require\s*\(\s*msg\.sender)',
            re.IGNORECASE,
        )
        func_pat = re.compile(
            r'function\s+\w+[^{]*\{', re.DOTALL
        )
        for m in sd_pat.finditer(source):
            lineno = source.count("\n", 0, m.start()) + 1
            # Walk backwards to find the function header
            pre = source[:m.start()]
            last_func = list(func_pat.finditer(pre))
            if last_func:
                func_src = pre[last_func[-1].start():]
                if not modifier_pat.search(func_src):
                    findings.append(LangFinding(
                        filepath="",
                        line=lineno,
                        column=1,
                        rule_id="SOL-AC-002",
                        title="Unprotected selfdestruct",
                        description=(
                            "selfdestruct() appears in a function without an "
                            "obvious access-control modifier. Any caller could "
                            "destroy the contract."
                        ),
                        severity="CRITICAL",
                        category="access_control",
                        code_snippet=_snippet(lines, lineno),
                        recommendation=(
                            "Guard selfdestruct with onlyOwner or equivalent. "
                            "Consider removing it entirely (deprecated in EIP-6049)."
                        ),
                        tool="native",
                        confidence=0.8,
                        cwe="CWE-284",
                    ))

        # Missing onlyOwner on sensitive state-changing functions
        sensitive_funcs = re.compile(
            r'function\s+(withdraw|mint|burn|pause|unpause|setOwner|'
            r'transferOwnership|upgrade|initialize|setPrice|setFee)\s*\(',
            re.IGNORECASE,
        )
        for m in sensitive_funcs.finditer(source):
            lineno = source.count("\n", 0, m.start()) + 1
            header_end = source.find("{", m.start())
            header = source[m.start(): header_end]
            if not re.search(
                r'\b(onlyOwner|onlyAdmin|onlyRole|whenNotPaused|'
                r'require\s*\(\s*msg\.sender)\b',
                header, re.IGNORECASE
            ):
                findings.append(LangFinding(
                    filepath="",
                    line=lineno,
                    column=1,
                    rule_id="SOL-AC-003",
                    title=f"Sensitive Function Without Access Control: {m.group(1)}",
                    description=(
                        f"Function '{m.group(1)}' modifies critical state but "
                        "does not appear to have an access-control modifier."
                    ),
                    severity="HIGH",
                    category="access_control",
                    code_snippet=_snippet(lines, lineno),
                    recommendation=(
                        "Add onlyOwner, a role-based modifier, or an explicit "
                        "require(msg.sender == owner) check."
                    ),
                    tool="native",
                    confidence=0.7,
                    cwe="CWE-284",
                ))
        return findings

    def check_oracle_manipulation(self, source: str) -> List[LangFinding]:
        """
        Detect single-block/single-DEX price reads without TWAP or other
        manipulation-resistance measures.
        """
        findings: List[LangFinding] = []
        lines = source.splitlines()

        # block.timestamp as price / oracle
        ts_pat = re.compile(r'\bblock\.timestamp\b')
        for i, line in enumerate(lines, 1):
            if ts_pat.search(line) and not line.strip().startswith("//"):
                findings.append(LangFinding(
                    filepath="",
                    line=i,
                    column=_col(line, ts_pat),
                    rule_id="SOL-ORM-001",
                    title="block.timestamp Usage",
                    description=(
                        "block.timestamp can be manipulated by validators within "
                        "~15 seconds. Using it as an oracle or for price/time "
                        "comparisons may allow manipulation."
                    ),
                    severity="MEDIUM",
                    category="oracle_manipulation",
                    code_snippet=line.strip(),
                    recommendation=(
                        "Avoid using block.timestamp for precise time comparisons. "
                        "For oracle data, use Chainlink or a TWAP-based oracle."
                    ),
                    tool="native",
                    confidence=0.65,
                    cwe="CWE-330",
                ))

        # Single DEX price (e.g. getReserves without TWAP)
        dex_price_pat = re.compile(
            r'\bgetReserves\s*\(|\bgetAmountsOut\s*\(|'
            r'\bcurrentPrice\s*\(|\bspot\s*[Pp]rice\b',
            re.IGNORECASE,
        )
        twap_pat = re.compile(r'\bTWAP\b|\bprice0CumulativeLast\b|'
                              r'\bprice1CumulativeLast\b|\bpriceCumulative\b',
                              re.IGNORECASE)
        has_twap = bool(twap_pat.search(source))
        if not has_twap:
            for i, line in enumerate(lines, 1):
                if dex_price_pat.search(line) and not line.strip().startswith("//"):
                    findings.append(LangFinding(
                        filepath="",
                        line=i,
                        column=_col(line, dex_price_pat),
                        rule_id="SOL-ORM-002",
                        title="Single-Block DEX Price Read Without TWAP",
                        description=(
                            "Spot price from a single DEX call can be flash-loan "
                            "manipulated within one transaction. No TWAP mechanism "
                            "was detected in this file."
                        ),
                        severity="HIGH",
                        category="oracle_manipulation",
                        code_snippet=line.strip(),
                        recommendation=(
                            "Use a time-weighted average price (TWAP) from "
                            "Uniswap v3 OracleLibrary or Chainlink price feeds."
                        ),
                        tool="native",
                        confidence=0.75,
                        cwe="CWE-682",
                    ))
        return findings

    def check_flash_loan_patterns(self, source: str) -> List[LangFinding]:
        """
        Detect patterns common in flash-loan attack vectors:
        large single-tx balance changes without a loan-guard check.
        """
        findings: List[LangFinding] = []
        lines = source.splitlines()

        fl_receiver = re.compile(
            r'function\s+(?:onFlashLoan|executeOperation|uniswapV2Call|'
            r'pancakeCall|balancerVault|receiveFlashLoan)\s*\(',
            re.IGNORECASE,
        )
        balance_check = re.compile(
            r'require\s*\(\s*\w*[Bb]alance|'
            r'assert\s*\(\s*\w*[Bb]alance',
            re.IGNORECASE,
        )

        for m in fl_receiver.finditer(source):
            lineno = source.count("\n", 0, m.start()) + 1
            # Extract function body
            start = source.find("{", m.start())
            depth = 1
            pos = start + 1
            while pos < len(source) and depth:
                if source[pos] == "{":
                    depth += 1
                elif source[pos] == "}":
                    depth -= 1
                pos += 1
            func_body = source[start:pos]
            if not balance_check.search(func_body):
                findings.append(LangFinding(
                    filepath="",
                    line=lineno,
                    column=1,
                    rule_id="SOL-FL-001",
                    title="Flash Loan Callback Without Balance Verification",
                    description=(
                        f"Flash loan callback function '{m.group(0).strip()}' "
                        "does not appear to verify the post-operation balance, "
                        "which may allow incomplete repayment."
                    ),
                    severity="HIGH",
                    category="flash_loan",
                    code_snippet=_snippet(lines, lineno),
                    recommendation=(
                        "Verify that the loaned amount plus fee has been repaid "
                        "before the callback returns, using require(balance >= loan + fee)."
                    ),
                    tool="native",
                    confidence=0.7,
                    cwe="CWE-841",
                ))

        # Suspicious large constant in single-tx context
        large_num_pat = re.compile(r'\b(\d{10,})\b|\b0x[0-9a-fA-F]{10,}\b')
        for i, line in enumerate(lines, 1):
            if large_num_pat.search(line) and re.search(
                r'\bflash\b|\bloan\b|\bborrow\b', source, re.IGNORECASE
            ):
                findings.append(LangFinding(
                    filepath="",
                    line=i,
                    column=_col(line, large_num_pat),
                    rule_id="SOL-FL-002",
                    title="Large Constant in Flash-Loan Context",
                    description=(
                        "A large numeric constant appears in a contract that "
                        "also contains flash-loan keywords. This may indicate "
                        "an unvalidated loan amount."
                    ),
                    severity="LOW",
                    category="flash_loan",
                    code_snippet=line.strip(),
                    recommendation=(
                        "Ensure all borrowed amounts are validated and bounded."
                    ),
                    tool="native",
                    confidence=0.4,
                    cwe="CWE-841",
                ))
                break   # one warning per file is sufficient
        return findings

    def check_unchecked_calls(self, source: str) -> List[LangFinding]:
        """
        Find low-level .call() invocations whose boolean return is not checked.
        """
        findings: List[LangFinding] = []
        lines = source.splitlines()

        # .call{...}(...) not preceded by (bool ...) =
        call_pat = re.compile(
            r'(?<!\(bool\s)(?<!\bbool\b)\s*\.\s*call\s*\{[^}]*\}\s*\([^)]*\)\s*;'
        )
        # Also match .call(...) legacy
        call_legacy = re.compile(
            r'(?<!\(bool\s)(?<!\bbool\b)\s*\.\s*call\s*\([^)]*\)\s*;'
        )

        for i, line in enumerate(lines, 1):
            if line.strip().startswith("//"):
                continue
            for pat in (call_pat, call_legacy):
                if pat.search(line):
                    # Check if the result is captured
                    if not re.search(
                        r'\(\s*bool\s+\w*\s*,?\s*\w*\s*\)\s*=', line
                    ):
                        findings.append(LangFinding(
                            filepath="",
                            line=i,
                            column=_col(line, pat),
                            rule_id="SOL-UC-001",
                            title="Unchecked Low-Level Call Return Value",
                            description=(
                                "Low-level .call() return value is not captured "
                                "or checked. A failed call silently continues execution."
                            ),
                            severity="HIGH",
                            category="unchecked_call",
                            code_snippet=line.strip(),
                            recommendation=(
                                "(bool success, bytes memory data) = addr.call{...}(...);\n"
                                "require(success, 'call failed');"
                            ),
                            tool="native",
                            confidence=0.8,
                            cwe="CWE-703",
                        ))
                    break
        return findings
