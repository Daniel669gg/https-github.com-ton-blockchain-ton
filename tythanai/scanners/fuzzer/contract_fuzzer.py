"""
TythanAI Platform — Smart Contract Fuzzer
Static mutation/fuzzing analysis engine for TON FunC/Tact and EVM Solidity contracts.

Generates boundary and edge-case test inputs that would trigger integer overflows,
reentrancy paths, access control bypasses, and TON-specific attack scenarios.
Each finding is a FuzzFinding dataclass with severity, attack_vector, input_values,
and expected_impact.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Integer boundary constants
# ---------------------------------------------------------------------------
MAX_UINT8   = 0xFF
MAX_UINT16  = 0xFFFF
MAX_UINT32  = 0xFFFF_FFFF
MAX_UINT64  = 0xFFFF_FFFF_FFFF_FFFF
MAX_UINT128 = (1 << 128) - 1
MAX_UINT256 = (1 << 256) - 1
MAX_INT256  = (1 << 255) - 1
MIN_INT256  = -(1 << 255)

BOUNDARY_UINT = [
    0, 1,
    MAX_UINT8, MAX_UINT8 - 1, MAX_UINT8 + 1,
    MAX_UINT16, MAX_UINT16 - 1,
    MAX_UINT32, MAX_UINT32 - 1,
    MAX_UINT64, MAX_UINT64 - 1,
    MAX_UINT128, MAX_UINT128 - 1,
    MAX_UINT256, MAX_UINT256 - 1,
]

BOUNDARY_INT = [
    0, 1, -1,
    MAX_INT256, MAX_INT256 - 1,
    MIN_INT256, MIN_INT256 + 1,
]

TON_COINS_BOUNDARY = [
    0, 1, 1_000_000_000,            # 1 TON in nanotons
    10_000_000_000_000,              # 10000 TON — typical large balance
    (1 << 120) - 1,                  # max coins type in TVM
]

# ---------------------------------------------------------------------------
# FuzzFinding
# ---------------------------------------------------------------------------

@dataclass
class FuzzFinding:
    """A single fuzz/mutation analysis finding."""
    finding_id:      str
    severity:        str            # CRITICAL / HIGH / MEDIUM / LOW
    attack_vector:   str            # brief label, e.g. "integer_overflow"
    input_values:    Dict           # param_name → fuzz_value
    expected_impact: str            # human-readable impact description
    function_name:   str = ""
    file:            str = ""
    line:            int = 0
    cwe:             str = ""
    category:        str = ""
    source:          str = "contract_fuzzer"

    def to_dict(self) -> Dict:
        return {
            "type":            "FUZZ_FINDING",
            "id":              self.finding_id,
            "severity":        self.severity,
            "attack_vector":   self.attack_vector,
            "input_values":    self.input_values,
            "expected_impact": self.expected_impact,
            "function_name":   self.function_name,
            "file":            self.file,
            "line":            self.line,
            "cwe":             self.cwe,
            "category":        self.category,
            "source":          self.source,
        }


# ---------------------------------------------------------------------------
# Type parsing helpers
# ---------------------------------------------------------------------------

def _parse_solidity_params(signature: str) -> List[Tuple[str, str]]:
    """Parse 'function foo(uint256 amount, address to)' → [('uint256','amount'), ('address','to')]."""
    m = re.search(r'\(([^)]*)\)', signature)
    if not m:
        return []
    raw = m.group(1).strip()
    if not raw:
        return []
    result: List[Tuple[str, str]] = []
    for part in raw.split(","):
        tokens = part.strip().split()
        if len(tokens) >= 2:
            result.append((tokens[0], tokens[-1]))
        elif len(tokens) == 1:
            result.append((tokens[0], "param"))
    return result


def _parse_func_params(signature: str) -> List[Tuple[str, str]]:
    """Parse FunC/Tact-style param lists → [(type, name), ...]."""
    m = re.search(r'\(([^)]*)\)', signature)
    if not m:
        return []
    raw = m.group(1).strip()
    if not raw:
        return []
    result: List[Tuple[str, str]] = []
    for part in raw.split(","):
        tokens = part.strip().split()
        if len(tokens) >= 2:
            result.append((tokens[0], tokens[-1]))
        elif len(tokens) == 1:
            result.append(("int", tokens[0]))
    return result


# ---------------------------------------------------------------------------
# ContractFuzzer
# ---------------------------------------------------------------------------

class ContractFuzzer:
    """
    Static fuzzing/mutation analysis engine for smart contracts.

    Supported formats: .sol, .vy (EVM), .fc (FunC), .tact (Tact), .move (Move).
    Generates FuzzFinding objects describing inputs that would trigger
    integer overflows, reentrancy, access control bypasses, and
    TON-specific exploit scenarios.
    """

    SUPPORTED_EXTENSIONS = {".sol", ".vy", ".fc", ".tact", ".move"}

    def fuzz_file(self, path: str) -> List[Dict]:
        """
        Fuzz a contract source file and return all findings as dicts.

        Dispatches to language-appropriate sub-analysers and merges results.
        """
        p = Path(path)
        if p.suffix.lower() not in self.SUPPORTED_EXTENSIONS:
            return []
        try:
            source = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []

        findings: List[FuzzFinding] = []
        ext = p.suffix.lower()

        # Integer boundary detection applies to all languages
        findings.extend(self._detect_integer_issues_raw(source, str(p)))

        if ext in {".sol", ".vy"}:
            findings.extend(self._detect_reentrancy_path_raw(source, str(p)))
            findings.extend(self._detect_access_control_bypass_raw(source, str(p)))
            findings.extend(self._fuzz_evm_functions(source, str(p)))
        elif ext in {".fc", ".tact"}:
            findings.extend(self._detect_ton_attacks(source, str(p)))
            findings.extend(self._fuzz_ton_functions(source, str(p)))
        elif ext == ".move":
            findings.extend(self._detect_move_issues(source, str(p)))

        return [f.to_dict() for f in findings]

    def fuzz_function(self, func_source: str, func_name: str) -> List[Dict]:
        """
        Fuzz a single function given its source text and name.

        Detects issues within the function body and generates boundary inputs
        for all detected parameter types.
        """
        findings: List[FuzzFinding] = []

        # Detect integer issues in the function body
        findings.extend(self._detect_integer_issues_raw(func_source, "<inline>", func_name))

        # Extract and fuzz parameters
        params = _parse_solidity_params(func_source) or _parse_func_params(func_source)
        if params:
            boundary_findings = self._generate_boundary_findings(
                params, func_name, file="<inline>"
            )
            findings.extend(boundary_findings)

        # Reentrancy check in function body
        findings.extend(self._detect_reentrancy_path_raw(func_source, "<inline>", func_name))

        return [f.to_dict() for f in findings]

    def generate_boundary_inputs(self, param_types: List[str]) -> List[Dict]:
        """
        Given a list of Solidity/FunC type strings, return a list of input
        dicts that represent boundary/edge-case values for those types.

        Example: ['uint256', 'address', 'bool'] →
            [{'param_0': 0, 'param_1': '0x0000...', 'param_2': False}, ...]
        """
        all_sets: List[Dict] = []
        # Build per-param boundary lists
        per_param: List[List] = []
        for ptype in param_types:
            per_param.append(self._boundary_values_for_type(ptype))

        # Enumerate: one set per boundary index (zip-style, not full product)
        max_len = max((len(v) for v in per_param), default=0)
        for i in range(max_len):
            row: Dict = {}
            for j, vals in enumerate(per_param):
                row[f"param_{j}"] = vals[i % len(vals)]
            all_sets.append(row)

        # Also add all-zero and all-max sets explicitly
        zeros: Dict = {}
        maxes: Dict = {}
        for j, ptype in enumerate(param_types):
            vals = self._boundary_values_for_type(ptype)
            zeros[f"param_{j}"] = vals[0] if vals else 0
            maxes[f"param_{j}"] = vals[-1] if vals else 0
        if zeros not in all_sets:
            all_sets.insert(0, zeros)
        if maxes not in all_sets:
            all_sets.append(maxes)

        return all_sets

    # ------------------------------------------------------------------
    # Public detection wrappers (return List[dict] for API compatibility)
    # ------------------------------------------------------------------

    def _detect_integer_issues(self, source: str) -> List[Dict]:
        return [f.to_dict() for f in self._detect_integer_issues_raw(source, "<source>")]

    def _detect_reentrancy_path(self, source: str) -> List[Dict]:
        return [f.to_dict() for f in self._detect_reentrancy_path_raw(source, "<source>")]

    def _detect_access_control_bypass(self, source: str) -> List[Dict]:
        return [f.to_dict() for f in self._detect_access_control_bypass_raw(source, "<source>")]

    # ------------------------------------------------------------------
    # Internal: integer boundary detection
    # ------------------------------------------------------------------

    def _detect_integer_issues_raw(
        self,
        source: str,
        file: str,
        func_name: str = "",
    ) -> List[FuzzFinding]:
        findings: List[FuzzFinding] = []
        lines = source.splitlines()

        # Patterns that signal unchecked arithmetic
        overflow_patterns = [
            (r'\bbalances?\[.*?\]\s*[+\-\*]=',         "balance arithmetic",   "CWE-190"),
            (r'\btotalSupply\s*[+\-\*]=',               "totalSupply mutation",  "CWE-190"),
            (r'\buint\d*\s+\w+\s*=\s*\w+\s*[+\-\*]',   "uint assignment op",    "CWE-190"),
            (r'\bint\s+\w+\s*=\s*\w+~load_(?:uint|int)\(\d+\)',
                                                         "TVM user-supplied int", "CWE-190"),
            (r'\w+\s*\+=\s*\w+',                         "accumulate without check","CWE-190"),
            (r'\w+\s*-=\s*\w+',                          "decrement without check", "CWE-191"),
        ]

        seen: set = set()
        for lineno, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith(("//", "/*", "*", "#", ";", "///")):
                continue
            for pattern, label, cwe in overflow_patterns:
                if re.search(pattern, stripped):
                    key = (pattern[:20], lineno)
                    if key in seen:
                        continue
                    seen.add(key)
                    # Extract variable or type info to produce boundary inputs
                    type_hint = "uint256"
                    type_match = re.search(r'\b(uint\d*|int\d*|coins?)\b', stripped)
                    if type_match:
                        type_hint = type_match.group(1)

                    for val, val_label in self._critical_boundary_pairs(type_hint):
                        findings.append(FuzzFinding(
                            finding_id=f"FUZZ-INT-{len(findings):03d}",
                            severity="HIGH",
                            attack_vector="integer_overflow",
                            input_values={"value": val, "description": val_label},
                            expected_impact=(
                                f"{label} at line {lineno}: input {val_label} "
                                f"may overflow/underflow — {cwe}"
                            ),
                            function_name=func_name,
                            file=file,
                            line=lineno,
                            cwe=cwe,
                            category="Integer Boundary",
                        ))
        return findings

    # ------------------------------------------------------------------
    # Internal: reentrancy detection
    # ------------------------------------------------------------------

    def _detect_reentrancy_path_raw(
        self,
        source: str,
        file: str,
        func_name: str = "",
    ) -> List[FuzzFinding]:
        findings: List[FuzzFinding] = []
        lines = source.splitlines()

        # Look for external call patterns followed by state updates
        call_patterns = [
            r'\.call\s*\{[^}]*\}\s*\(',
            r'\.transfer\s*\(',
            r'\.send\s*\(',
            r'IFlash\w+\s*\(',
        ]
        state_patterns = [
            r'balances?\[',
            r'mapping\s*\(',
            r'\w+\s*[+\-\*]?=\s*',
        ]

        seen: set = set()
        for lineno, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith(("//", "/*", "*")):
                continue

            for cpat in call_patterns:
                if re.search(cpat, stripped):
                    # Check the 10 lines AFTER the call for state mutations
                    window = "\n".join(lines[lineno:min(lineno + 10, len(lines))])
                    for spat in state_patterns:
                        if re.search(spat, window):
                            key = (lineno, "reentrant")
                            if key in seen:
                                break
                            seen.add(key)
                            findings.append(FuzzFinding(
                                finding_id=f"FUZZ-REENT-{len(findings):03d}",
                                severity="CRITICAL",
                                attack_vector="reentrancy",
                                input_values={
                                    "attacker_contract": "0x<MaliciousReentrantContract>",
                                    "call_value":        MAX_UINT256,
                                    "reentrancy_depth":  10,
                                },
                                expected_impact=(
                                    f"External call at line {lineno} precedes "
                                    "state update — attacker's fallback can "
                                    "re-enter and drain funds before balance decrements."
                                ),
                                function_name=func_name,
                                file=file,
                                line=lineno,
                                cwe="CWE-841",
                                category="Reentrancy",
                            ))
                            break

        return findings

    # ------------------------------------------------------------------
    # Internal: access control bypass
    # ------------------------------------------------------------------

    def _detect_access_control_bypass_raw(
        self,
        source: str,
        file: str,
        func_name: str = "",
    ) -> List[FuzzFinding]:
        findings: List[FuzzFinding] = []
        lines = source.splitlines()

        # Sensitive functions that should have guards
        sensitive = re.compile(
            r'function\s+(mint|burn|withdraw|setOwner|setAdmin|pause|unpause|'
            r'upgrade|initialize|emergencyWithdraw|drainFunds|setFee|'
            r'transferOwnership|destroyContract)\s*\(',
            re.IGNORECASE,
        )
        guard = re.compile(
            r'onlyOwner|onlyRole|onlyAdmin|require\s*\(\s*msg\.sender'
            r'|modifier\s+only|AccessControl|_checkRole',
            re.IGNORECASE,
        )

        full_source = "\n".join(lines)
        for m in sensitive.finditer(full_source):
            lineno = full_source[: m.start()].count("\n") + 1
            fn_name = m.group(1)
            # Scan from function definition up to next 20 lines for a guard
            window = "\n".join(lines[lineno - 1 : min(lineno + 20, len(lines))])
            if not guard.search(window):
                findings.append(FuzzFinding(
                    finding_id=f"FUZZ-AC-{len(findings):03d}",
                    severity="CRITICAL",
                    attack_vector="access_control_bypass",
                    input_values={
                        "caller":     "0x<ArbitraryAddress>",
                        "function":   fn_name,
                        "msg_sender": "0xdeadbeefdeadbeef",
                    },
                    expected_impact=(
                        f"Function '{fn_name}' (line {lineno}) lacks an access "
                        "control guard — any address can call it to drain funds, "
                        "change ownership, or destroy the contract."
                    ),
                    function_name=fn_name,
                    file=file,
                    line=lineno,
                    cwe="CWE-284",
                    category="Access Control",
                ))

        # tx.origin bypass
        for lineno, line in enumerate(lines, 1):
            if re.search(r'tx\.origin\s*==', line):
                findings.append(FuzzFinding(
                    finding_id=f"FUZZ-AC-{len(findings):03d}",
                    severity="HIGH",
                    attack_vector="tx_origin_bypass",
                    input_values={
                        "tx_origin":  "0x<LegitimateUser>",
                        "msg_sender": "0x<AttackerIntermediaryContract>",
                    },
                    expected_impact=(
                        f"tx.origin authentication at line {lineno}: a malicious "
                        "intermediate contract tricks the legitimate tx.origin user "
                        "into calling it, bypassing the check."
                    ),
                    file=file,
                    line=lineno,
                    cwe="CWE-284",
                    category="Access Control",
                ))

        return findings

    # ------------------------------------------------------------------
    # Internal: EVM function-level fuzzing
    # ------------------------------------------------------------------

    def _fuzz_evm_functions(self, source: str, file: str) -> List[FuzzFinding]:
        findings: List[FuzzFinding] = []
        func_pat = re.compile(
            r'function\s+(\w+)\s*\(([^)]*)\)\s*(?:public|external)',
            re.MULTILINE,
        )
        for m in func_pat.finditer(source):
            fn_name  = m.group(1)
            raw_params = m.group(2)
            lineno   = source[: m.start()].count("\n") + 1
            params   = _parse_solidity_params(f"f({raw_params})")
            if not params:
                continue
            for boundary_set in self._generate_boundary_findings(params, fn_name, file, lineno):
                findings.append(boundary_set)
        return findings

    # ------------------------------------------------------------------
    # Internal: TON-specific attack scenarios
    # ------------------------------------------------------------------

    def _detect_ton_attacks(self, source: str, file: str) -> List[FuzzFinding]:
        findings: List[FuzzFinding] = []
        lines = source.splitlines()

        checks = [
            # Replay attack: recv_external without seqno check
            (
                r'\brecv_external\b',
                r'\bseqno\b|\bcheck_signature\b',
                "replay_attack",
                "CRITICAL",
                "CWE-294",
                "recv_external without seqno/signature check — any message can be replayed",
                {
                    "replayed_message": "<original_valid_boc>",
                    "replay_count":     1000,
                    "sender":           "EQ<AnyAddress>",
                },
                "Attacker replays a previously valid external message indefinitely, "
                "draining gas or triggering state changes multiple times.",
            ),
            # Gas drain: accept_message before auth guard
            (
                r'\baccept_message\s*\(\s*\)',
                r'\bequal_slices\b|\bcheck_signature\b|\bthrow_unless\b',
                "gas_drain",
                "CRITICAL",
                "CWE-400",
                "accept_message without prior auth — attacker can drain gas",
                {
                    "spam_messages": 10000,
                    "msg_value":     0,
                    "sender":        "EQ<Attacker>",
                },
                "Attacker sends thousands of messages; contract accepts each, "
                "paying storage/gas fees from its own balance until drained.",
            ),
            # Mode-128 fund drain
            (
                r'send_raw_message\s*\([^,]+,\s*128\s*\)',
                r'\braw_reserve\s*\(',
                "fund_drain_mode128",
                "CRITICAL",
                "CWE-691",
                "send_raw_message mode=128 without raw_reserve — drains entire balance",
                {
                    "trigger_value":  1,
                    "expected_drain": "entire_contract_balance",
                },
                "Mode-128 sends ALL remaining contract balance. Without raw_reserve "
                "call first, a single triggered message empties the contract.",
            ),
            # Bounce attack: missing bounced$ handler
            (
                r'\brecv_internal\b',
                r'\bbounced\b|\b~skip_bits\b',
                "bounce_attack",
                "HIGH",
                "CWE-754",
                "recv_internal without bounce message handling — double-spend via bounce",
                {
                    "bounce_flag":   True,
                    "msg_value":     1_000_000_000,
                    "payload":       "0x",
                },
                "Attacker sends a message that bounces back. Without bounce handling, "
                "the contract may credit funds before the bounce, then fail to debit.",
            ),
        ]

        full_source = source
        for (trigger_pat, guard_pat, vector, severity, cwe, desc, inputs, impact) in checks:
            trigger_matches = list(re.finditer(trigger_pat, full_source))
            for tm in trigger_matches:
                pos    = tm.start()
                before = full_source[max(0, pos - 400): pos]
                lineno = full_source[:pos].count("\n") + 1
                if not re.search(guard_pat, before):
                    findings.append(FuzzFinding(
                        finding_id=f"FUZZ-TON-{len(findings):03d}",
                        severity=severity,
                        attack_vector=vector,
                        input_values=inputs,
                        expected_impact=f"Line {lineno}: {impact}",
                        file=file,
                        line=lineno,
                        cwe=cwe,
                        category="TON Attack",
                    ))

        # Coin integer boundary fuzzing
        coin_loads = list(re.finditer(r'~load_coins\s*\(\s*\)', full_source))
        for m in coin_loads:
            lineno = full_source[: m.start()].count("\n") + 1
            for val in TON_COINS_BOUNDARY:
                findings.append(FuzzFinding(
                    finding_id=f"FUZZ-TON-COIN-{len(findings):03d}",
                    severity="MEDIUM",
                    attack_vector="coin_boundary",
                    input_values={"coins_value": val},
                    expected_impact=(
                        f"load_coins at line {lineno} with value {val} nanotons "
                        "may trigger overflow or zero-value edge cases."
                    ),
                    file=file,
                    line=lineno,
                    cwe="CWE-190",
                    category="TON Coin Boundary",
                ))

        return findings

    # ------------------------------------------------------------------
    # Internal: TON function-level fuzzing
    # ------------------------------------------------------------------

    def _fuzz_ton_functions(self, source: str, file: str) -> List[FuzzFinding]:
        findings: List[FuzzFinding] = []
        # Match FunC function signatures: () fname(params)
        func_pat = re.compile(
            r'^\s*\(\)\s+(\w+)\s*\(([^)]*)\)',
            re.MULTILINE,
        )
        # Also match recv_internal
        recv_pat = re.compile(
            r'\b(recv_internal|recv_external)\s*\(([^)]*)\)',
        )
        for m in list(func_pat.finditer(source)) + list(recv_pat.finditer(source)):
            fn_name = m.group(1)
            raw_params = m.group(2) if m.lastindex >= 2 else ""
            lineno  = source[: m.start()].count("\n") + 1
            params  = _parse_func_params(f"f({raw_params})")
            for boundary_set in self._generate_boundary_findings(params, fn_name, file, lineno):
                findings.append(boundary_set)
        return findings

    # ------------------------------------------------------------------
    # Internal: Move language checks
    # ------------------------------------------------------------------

    def _detect_move_issues(self, source: str, file: str) -> List[FuzzFinding]:
        findings: List[FuzzFinding] = []
        lines = source.splitlines()

        overflow_pat = re.compile(r'\b(\w+)\s*\+\s*(\w+)\b|\b(\w+)\s*-\s*(\w+)\b')
        abort_pat    = re.compile(r'\babort\b|\bassert!\b|\bcheck_abort\b')

        for lineno, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("//"):
                continue
            if overflow_pat.search(stripped):
                # Check nearby lines for an abort
                window = "\n".join(lines[max(0, lineno - 3): min(lineno + 3, len(lines))])
                if not abort_pat.search(window):
                    findings.append(FuzzFinding(
                        finding_id=f"FUZZ-MOVE-{len(findings):03d}",
                        severity="HIGH",
                        attack_vector="move_arithmetic_abort",
                        input_values={"value": MAX_UINT64, "description": "u64 max"},
                        expected_impact=(
                            f"Arithmetic at line {lineno} without abort guard — "
                            "Move's built-in overflow will abort at runtime; "
                            "confirm this is the intended behaviour."
                        ),
                        file=file,
                        line=lineno,
                        cwe="CWE-190",
                        category="Move Arithmetic",
                    ))

        return findings

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _generate_boundary_findings(
        self,
        params: List[Tuple[str, str]],
        func_name: str,
        file: str,
        lineno: int = 0,
    ) -> List[FuzzFinding]:
        """For each parameter, generate FuzzFinding objects for critical boundaries."""
        findings: List[FuzzFinding] = []
        for ptype, pname in params:
            for val, label in self._critical_boundary_pairs(ptype):
                findings.append(FuzzFinding(
                    finding_id=f"FUZZ-BOUND-{func_name[:12]}-{pname[:10]}-{len(findings):03d}",
                    severity="MEDIUM",
                    attack_vector="boundary_input",
                    input_values={pname: val, "_boundary_label": label},
                    expected_impact=(
                        f"Parameter '{pname}' ({ptype}) in '{func_name}' with "
                        f"value {label} may expose integer boundary condition."
                    ),
                    function_name=func_name,
                    file=file,
                    line=lineno,
                    cwe="CWE-190",
                    category="Boundary Input",
                ))
        return findings

    def _boundary_values_for_type(self, ptype: str) -> List:
        """Return all boundary values appropriate for a given type string."""
        pt = ptype.lower().strip()
        if pt in ("address", "addr"):
            return [
                "0x0000000000000000000000000000000000000000",
                "0xffffffffffffffffffffffffffffffffffffffff",
                "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            ]
        if pt == "bool":
            return [True, False]
        if pt == "bytes32":
            return ["0x" + "00" * 32, "0x" + "ff" * 32]
        if pt == "string":
            return ["", "A" * 1024, "\x00", "<script>alert(1)</script>"]
        if "coins" in pt:
            return TON_COINS_BOUNDARY
        if "int" in pt:
            if pt.startswith("uint"):
                bits = int(re.sub(r'\D', '', pt) or "256")
                top  = (1 << bits) - 1
                return [0, 1, top - 1, top]
            else:
                bits = int(re.sub(r'\D', '', pt) or "256")
                top  = (1 << (bits - 1)) - 1
                bot  = -(1 << (bits - 1))
                return [bot, bot + 1, -1, 0, 1, top - 1, top]
        # Default: treat as uint256
        return [0, 1, MAX_UINT256 - 1, MAX_UINT256]

    def _critical_boundary_pairs(self, ptype: str) -> List[Tuple]:
        """Return (value, label) pairs for the most dangerous boundary cases."""
        vals = self._boundary_values_for_type(ptype)
        labels = [
            "zero",
            "one",
            "max_minus_one",
            "max",
        ]
        pairs = []
        for i, v in enumerate(vals):
            lbl = labels[i] if i < len(labels) else f"boundary_{i}"
            pairs.append((v, lbl))
        return pairs
