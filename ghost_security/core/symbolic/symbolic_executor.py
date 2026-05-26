"""
Ghost Security — Symbolic Execution Engine (Phase 15)

Performs symbolic execution on Solidity source files and raw EVM bytecode,
building a control-flow graph and exploring execution paths to surface
vulnerabilities that static regex patterns miss.

External tools (slither, mythril) are used when available; otherwise the
native engine takes over:
  * EVM — opcode-level pattern matching and CFG construction
  * Solidity AST — regex-derived AST node explorer for path-sensitive checks

No external dependencies are required for the native fallback.
"""
from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple

log = logging.getLogger("ghost.symbolic")

# ─── EVM opcode table (subset relevant for security analysis) ─────────────────

# Opcodes are represented as integers matching their EVM byte values.
_OP = {
    "STOP": 0x00, "ADD": 0x01, "MUL": 0x02, "SUB": 0x03, "DIV": 0x04,
    "SDIV": 0x05, "MOD": 0x06, "SMOD": 0x07, "ADDMOD": 0x08, "MULMOD": 0x09,
    "EXP": 0x0A, "SIGNEXTEND": 0x0B, "LT": 0x10, "GT": 0x11, "SLT": 0x12,
    "SGT": 0x13, "EQ": 0x14, "ISZERO": 0x15, "AND": 0x16, "OR": 0x17,
    "XOR": 0x18, "NOT": 0x19, "BYTE": 0x1A, "SHL": 0x1B, "SHR": 0x1C,
    "SAR": 0x1D, "SHA3": 0x20, "ADDRESS": 0x30, "BALANCE": 0x31,
    "ORIGIN": 0x32, "CALLER": 0x33, "CALLVALUE": 0x34, "CALLDATALOAD": 0x35,
    "CALLDATASIZE": 0x36, "CALLDATACOPY": 0x37, "CODESIZE": 0x38,
    "CODECOPY": 0x39, "GASPRICE": 0x3A, "EXTCODESIZE": 0x3B,
    "EXTCODECOPY": 0x3C, "RETURNDATASIZE": 0x3D, "RETURNDATACOPY": 0x3E,
    "BLOCKHASH": 0x40, "COINBASE": 0x41, "TIMESTAMP": 0x42, "NUMBER": 0x43,
    "DIFFICULTY": 0x44, "GASLIMIT": 0x45, "CHAINID": 0x46, "SELFBALANCE": 0x47,
    "POP": 0x50, "MLOAD": 0x51, "MSTORE": 0x52, "MSTORE8": 0x53,
    "SLOAD": 0x54, "SSTORE": 0x55, "JUMP": 0x56, "JUMPI": 0x57,
    "PC": 0x58, "MSIZE": 0x59, "GAS": 0x5A, "JUMPDEST": 0x5B,
    "PUSH1": 0x60, "PUSH32": 0x7F, "DUP1": 0x80, "DUP16": 0x8F,
    "SWAP1": 0x90, "SWAP16": 0x9F, "LOG0": 0xA0, "LOG4": 0xA4,
    "CREATE": 0xF0, "CALL": 0xF1, "CALLCODE": 0xF2, "RETURN": 0xF3,
    "DELEGATECALL": 0xF4, "CREATE2": 0xF5, "STATICCALL": 0xFA,
    "REVERT": 0xFD, "SELFDESTRUCT": 0xFF,
}

_OP_REV: Dict[int, str] = {v: k for k, v in _OP.items()}

# Arithmetic opcodes susceptible to overflow
_ARITH_OPS: Set[int] = {_OP["ADD"], _OP["MUL"], _OP["EXP"]}
_SHIFT_SIGN_OPS: Set[int] = {_OP["SAR"], _OP["SHR"], _OP["SHL"]}


# ─── Data classes ──────────────────────────────────────────────────────────────


@dataclass
class SymbolicVuln:
    vuln_type: str        # "reentrancy", "integer_overflow", "unchecked_call",
                          # "access_control", "flash_loan"
    severity: str         # "critical" | "high" | "medium" | "low"
    path: str             # execution-path description
    pc: Optional[int]     # EVM program counter if applicable
    description: str
    recommendation: str

    def to_dict(self) -> dict:
        return {
            "vuln_type": self.vuln_type,
            "severity": self.severity,
            "path": self.path,
            "pc": self.pc,
            "description": self.description,
            "recommendation": self.recommendation,
        }


@dataclass
class SymbolicResult:
    paths_explored: int
    vulnerabilities: List[SymbolicVuln]
    uncovered_paths: int
    tool_used: str          # "slither" | "mythril" | "native"
    execution_time: float   # seconds

    def to_dict(self) -> dict:
        return {
            "paths_explored": self.paths_explored,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "uncovered_paths": self.uncovered_paths,
            "tool_used": self.tool_used,
            "execution_time": self.execution_time,
            "total_vulns": len(self.vulnerabilities),
        }


class ExecutionPath:
    """Represents one feasible execution path through contract code."""

    def __init__(
        self,
        path_id: int,
        steps: Optional[List[str]] = None,
        constraints: Optional[List[str]] = None,
        terminal: str = "STOP",
    ) -> None:
        self.path_id = path_id
        self.steps: List[str] = steps or []
        self.constraints: List[str] = constraints or []
        self.terminal = terminal        # STOP | RETURN | REVERT | SELFDESTRUCT
        self.state_writes: List[int] = []    # SSTORE PCs
        self.external_calls: List[int] = []  # CALL / DELEGATECALL PCs
        self.arithmetic_ops: List[int] = []  # ADD/MUL PCs without SAR guard

    def add_step(self, description: str) -> None:
        self.steps.append(description)

    def add_constraint(self, constraint: str) -> None:
        self.constraints.append(constraint)

    def __repr__(self) -> str:
        return (
            f"ExecutionPath(id={self.path_id}, "
            f"steps={len(self.steps)}, "
            f"terminal={self.terminal})"
        )


# ─── CFG node ─────────────────────────────────────────────────────────────────


@dataclass
class _CFGBlock:
    """A basic block in the EVM control flow graph."""
    start_pc: int
    opcodes: List[Tuple[int, int, Optional[int]]] = field(default_factory=list)
    # Each entry: (pc, opcode_byte, push_value_or_None)
    successors: List[int] = field(default_factory=list)   # start_pc of next blocks
    is_jumpdest: bool = False


# ─── Symbolic Executor ────────────────────────────────────────────────────────


class SymbolicExecutor:
    """
    Multi-layer symbolic execution engine.

    Priority order:
      1. slither — if installed and source is Solidity
      2. mythril  — if installed and source is Solidity/bytecode
      3. native   — pure-Python EVM + AST analysis (always available)
    """

    # Maximum number of unique execution paths to explore
    _DEFAULT_MAX_PATHS = 200

    def __init__(self, config: Optional[dict] = None) -> None:
        self.config = config or {}
        self._max_paths: int = self.config.get("max_paths", self._DEFAULT_MAX_PATHS)
        self._timeout: int = self.config.get("timeout", 60)
        self._prefer_native: bool = self.config.get("prefer_native", False)

    # ── Public API ─────────────────────────────────────────────────────────────

    def analyze_file(self, path: str) -> SymbolicResult:
        """Dispatch analysis based on file extension."""
        ext = Path(path).suffix.lower()
        if ext == ".sol":
            return self.analyze_solidity(path)
        if ext in (".hex", ".bin", ".evm"):
            raw = Path(path).read_text(errors="replace").strip()
            return self.analyze_evm_bytecode(raw)
        # Attempt to read as hex bytecode for extensionless / unknown files
        try:
            raw = Path(path).read_text(errors="replace").strip()
            if re.fullmatch(r"[0-9a-fA-F]+", raw):
                return self.analyze_evm_bytecode(raw)
        except OSError:
            pass
        return self.analyze_solidity(path)  # fall through to source analysis

    def analyze_solidity(self, source_path: str) -> SymbolicResult:
        """Analyse a Solidity source file."""
        t0 = time.monotonic()

        if not self._prefer_native:
            result = self._try_slither(source_path, t0)
            if result is not None:
                return result
            result = self._try_mythril_source(source_path, t0)
            if result is not None:
                return result

        return self._native_solidity(source_path, t0)

    def analyze_evm_bytecode(self, bytecode_hex: str) -> SymbolicResult:
        """Analyse raw EVM bytecode (hex string, with or without 0x prefix)."""
        t0 = time.monotonic()

        if not self._prefer_native:
            result = self._try_mythril_bytecode(bytecode_hex, t0)
            if result is not None:
                return result

        return self._native_evm(bytecode_hex, t0)

    def explore_paths(
        self,
        ast_node: dict,
        max_depth: int = 50,
    ) -> List[ExecutionPath]:
        """
        DFS exploration of execution paths from a Solidity-style AST dict.

        Expected structure mirrors what _parse_solidity_ast() produces:
            {
                "type": "Contract",
                "name": "...",
                "functions": [
                    {
                        "name": "...",
                        "visibility": "public",
                        "body": [<statement_nodes>]
                    }, ...
                ]
            }
        Each statement node has at minimum {"type": str, "line": int}.
        """
        paths: List[ExecutionPath] = []
        pid = 0
        for fn in ast_node.get("functions", []):
            body = fn.get("body", [])
            for path in self._dfs_body(body, [], [], max_depth, 0):
                path.path_id = pid
                paths.append(path)
                pid += 1
                if pid >= self._max_paths:
                    return paths
        return paths

    def check_invariant(self, path: ExecutionPath, invariant: str) -> bool:
        """
        Check whether a named invariant holds on the given path.

        Supported invariants:
          "no_reentrancy"        — no SSTORE after CALL on the same path
          "no_overflow"          — no unchecked arithmetic
          "no_selfdestruct"      — path does not terminate in SELFDESTRUCT
          "state_before_call"    — state writes precede external calls
        """
        inv = invariant.lower()

        if inv == "no_reentrancy":
            # Violated if any CALL PC comes before any SSTORE PC
            for call_pc in path.external_calls:
                for sstore_pc in path.state_writes:
                    if sstore_pc > call_pc:
                        return False
            return True

        if inv == "no_overflow":
            return len(path.arithmetic_ops) == 0

        if inv == "no_selfdestruct":
            return path.terminal != "SELFDESTRUCT"

        if inv == "state_before_call":
            # All SSTOREs must come before all CALLs
            if path.state_writes and path.external_calls:
                return max(path.state_writes) < min(path.external_calls)
            return True

        log.warning("Unknown invariant '%s' — returning True", invariant)
        return True

    def generate_report(self, result: SymbolicResult) -> str:
        """Render a human-readable text report from a SymbolicResult."""
        lines: List[str] = [
            "=" * 70,
            "Ghost Security — Symbolic Execution Report",
            "=" * 70,
            f"Tool used      : {result.tool_used}",
            f"Paths explored : {result.paths_explored}",
            f"Uncovered paths: {result.uncovered_paths}",
            f"Execution time : {result.execution_time:.2f}s",
            f"Vulnerabilities: {len(result.vulnerabilities)}",
            "",
        ]

        if not result.vulnerabilities:
            lines.append("No vulnerabilities detected.")
        else:
            sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            sorted_vulns = sorted(
                result.vulnerabilities,
                key=lambda v: sev_order.get(v.severity, 9),
            )
            for i, v in enumerate(sorted_vulns, 1):
                pc_str = f"  PC           : 0x{v.pc:04x}\n" if v.pc is not None else ""
                lines += [
                    f"[{i}] {v.vuln_type.upper()} ({v.severity.upper()})",
                    f"  Path         : {v.path}",
                    pc_str.rstrip() or "",
                    f"  Description  : {v.description}",
                    f"  Recommendation: {v.recommendation}",
                    "",
                ]

        lines.append("=" * 70)
        return "\n".join(lines)

    # ── External tool wrappers ─────────────────────────────────────────────────

    def _try_slither(self, source_path: str, t0: float) -> Optional[SymbolicResult]:
        if not shutil.which("slither"):
            return None
        try:
            proc = subprocess.run(
                ["slither", source_path, "--json", "-"],
                capture_output=True, text=True, timeout=self._timeout,
            )
            if proc.returncode not in (0, 1):
                log.debug("slither returned %d", proc.returncode)
                return None
            import json
            data = json.loads(proc.stdout)
            return self._parse_slither_output(data, time.monotonic() - t0)
        except Exception as exc:
            log.debug("slither failed: %s", exc)
            return None

    def _parse_slither_output(self, data: dict, elapsed: float) -> SymbolicResult:
        vulns: List[SymbolicVuln] = []
        detectors = data.get("results", {}).get("detectors", [])
        sev_map = {
            "High": "high", "Medium": "medium", "Low": "low",
            "Informational": "low", "Optimization": "low",
        }
        type_map = {
            "reentrancy-eth": "reentrancy",
            "reentrancy-no-eth": "reentrancy",
            "reentrancy-benign": "reentrancy",
            "integer-overflow": "integer_overflow",
            "arbitrary-send": "access_control",
            "controlled-delegatecall": "access_control",
            "selfdestruct": "access_control",
            "unchecked-lowlevel": "unchecked_call",
            "flash-loan": "flash_loan",
        }
        for det in detectors:
            check = det.get("check", "unknown")
            vuln_type = type_map.get(check, check.replace("-", "_"))
            sev = sev_map.get(det.get("impact", "Medium"), "medium")
            elements = det.get("elements", [])
            path_str = " → ".join(
                e.get("name", "?") for e in elements[:3]
            ) or "unknown"
            vulns.append(SymbolicVuln(
                vuln_type=vuln_type,
                severity=sev,
                path=path_str,
                pc=None,
                description=det.get("description", "").strip(),
                recommendation=det.get("recommendation", "Review flagged code.").strip(),
            ))
        return SymbolicResult(
            paths_explored=len(detectors),
            vulnerabilities=vulns,
            uncovered_paths=0,
            tool_used="slither",
            execution_time=elapsed,
        )

    def _try_mythril_source(self, source_path: str, t0: float) -> Optional[SymbolicResult]:
        if not shutil.which("myth"):
            return None
        try:
            proc = subprocess.run(
                ["myth", "analyze", source_path, "-o", "json",
                 "--execution-timeout", str(min(self._timeout, 30))],
                capture_output=True, text=True, timeout=self._timeout + 5,
            )
            if proc.returncode not in (0, 1):
                return None
            import json
            data = json.loads(proc.stdout)
            return self._parse_mythril_output(data, time.monotonic() - t0)
        except Exception as exc:
            log.debug("mythril (source) failed: %s", exc)
            return None

    def _try_mythril_bytecode(self, bytecode_hex: str, t0: float) -> Optional[SymbolicResult]:
        if not shutil.which("myth"):
            return None
        try:
            proc = subprocess.run(
                ["myth", "analyze", "--bin-runtime", "-",
                 "-o", "json",
                 "--execution-timeout", str(min(self._timeout, 30))],
                input=bytecode_hex, capture_output=True, text=True,
                timeout=self._timeout + 5,
            )
            if proc.returncode not in (0, 1):
                return None
            import json
            data = json.loads(proc.stdout)
            return self._parse_mythril_output(data, time.monotonic() - t0)
        except Exception as exc:
            log.debug("mythril (bytecode) failed: %s", exc)
            return None

    def _parse_mythril_output(self, data: dict, elapsed: float) -> SymbolicResult:
        vulns: List[SymbolicVuln] = []
        issues = data.get("issues", [])
        sev_map = {"High": "high", "Medium": "medium", "Low": "low"}
        type_map = {
            "Reentrancy": "reentrancy",
            "Integer Overflow": "integer_overflow",
            "Integer Underflow": "integer_overflow",
            "Unchecked Call Return Value": "unchecked_call",
            "Access Control": "access_control",
            "Dependence on Predictable Variable": "weak_randomness",
        }
        for issue in issues:
            title = issue.get("title", "Unknown")
            vuln_type = type_map.get(title, title.lower().replace(" ", "_"))
            sev = sev_map.get(issue.get("severity", "Medium"), "medium")
            pc_val = issue.get("address")
            vulns.append(SymbolicVuln(
                vuln_type=vuln_type,
                severity=sev,
                path=issue.get("function", "unknown"),
                pc=int(pc_val) if pc_val is not None else None,
                description=issue.get("description", "").strip(),
                recommendation=issue.get("recommendation", "Review flagged code.").strip(),
            ))
        return SymbolicResult(
            paths_explored=len(issues),
            vulnerabilities=vulns,
            uncovered_paths=0,
            tool_used="mythril",
            execution_time=elapsed,
        )

    # ── Native EVM analysis ────────────────────────────────────────────────────

    def _native_evm(self, bytecode_hex: str, t0: float) -> SymbolicResult:
        """Decode bytecode, build CFG, walk paths, detect vulnerabilities."""
        hex_str = bytecode_hex.strip()
        if hex_str.startswith("0x") or hex_str.startswith("0X"):
            hex_str = hex_str[2:]
        try:
            raw = bytes.fromhex(hex_str)
        except ValueError as exc:
            log.warning("Invalid bytecode hex: %s", exc)
            return SymbolicResult(0, [], 0, "native", time.monotonic() - t0)

        opcodes = self._decode_opcodes(raw)
        cfg = self._build_cfg(opcodes)
        paths = self._explore_cfg(cfg, opcodes)
        vulns = self._detect_evm_vulns(paths, opcodes)

        uncovered = max(0, len(cfg) - len(paths))
        return SymbolicResult(
            paths_explored=len(paths),
            vulnerabilities=vulns,
            uncovered_paths=uncovered,
            tool_used="native",
            execution_time=time.monotonic() - t0,
        )

    def _decode_opcodes(
        self, raw: bytes
    ) -> List[Tuple[int, int, Optional[int]]]:
        """
        Return list of (pc, opcode_byte, push_immediate_or_None).
        PUSH1..PUSH32 consume the following N bytes as immediate.
        """
        result: List[Tuple[int, int, Optional[int]]] = []
        pc = 0
        while pc < len(raw):
            op = raw[pc]
            if _OP["PUSH1"] <= op <= _OP["PUSH32"]:
                n = op - _OP["PUSH1"] + 1
                imm_bytes = raw[pc + 1: pc + 1 + n]
                imm = int.from_bytes(imm_bytes, "big") if imm_bytes else 0
                result.append((pc, op, imm))
                pc += 1 + n
            else:
                result.append((pc, op, None))
                pc += 1
        return result

    def _build_cfg(
        self, opcodes: List[Tuple[int, int, Optional[int]]]
    ) -> Dict[int, _CFGBlock]:
        """
        Build a basic-block CFG.
        A new block starts at:
          - PC=0
          - every JUMPDEST
          - immediately after a JUMP/JUMPI/STOP/RETURN/REVERT/SELFDESTRUCT
        """
        # First pass: identify block-start PCs
        block_starts: Set[int] = {0}
        terminals = {
            _OP["JUMP"], _OP["JUMPI"], _OP["STOP"],
            _OP["RETURN"], _OP["REVERT"], _OP["SELFDESTRUCT"],
        }
        for pc, op, _ in opcodes:
            if op == _OP["JUMPDEST"]:
                block_starts.add(pc)
        prev_was_terminal = False
        for pc, op, _ in opcodes:
            if prev_was_terminal:
                block_starts.add(pc)
            prev_was_terminal = op in terminals

        sorted_starts = sorted(block_starts)
        pc_to_block: Dict[int, int] = {}  # pc → block_start
        for i, s in enumerate(sorted_starts):
            end = sorted_starts[i + 1] if i + 1 < len(sorted_starts) else float("inf")
            for pc, op, _ in opcodes:
                if s <= pc < end:
                    pc_to_block[pc] = s

        blocks: Dict[int, _CFGBlock] = {}
        for s in sorted_starts:
            blocks[s] = _CFGBlock(start_pc=s)

        # Second pass: fill blocks and resolve successors
        for i, (pc, op, imm) in enumerate(opcodes):
            blk_start = pc_to_block.get(pc)
            if blk_start is None:
                continue
            blk = blocks[blk_start]
            blk.opcodes.append((pc, op, imm))
            if op == _OP["JUMPDEST"]:
                blk.is_jumpdest = True

            if op == _OP["JUMP"]:
                # Target is top-of-stack; look back for last PUSH
                for j in range(i - 1, max(i - 10, -1), -1):
                    prev_pc, prev_op, prev_imm = opcodes[j]
                    if _OP["PUSH1"] <= prev_op <= _OP["PUSH32"] and prev_imm is not None:
                        if prev_imm in blocks:
                            blk.successors.append(prev_imm)
                        break

            elif op == _OP["JUMPI"]:
                # Conditional: both taken and fall-through
                for j in range(i - 1, max(i - 10, -1), -1):
                    prev_pc, prev_op, prev_imm = opcodes[j]
                    if _OP["PUSH1"] <= prev_op <= _OP["PUSH32"] and prev_imm is not None:
                        if prev_imm in blocks:
                            blk.successors.append(prev_imm)
                        break
                # Fall-through
                if i + 1 < len(opcodes):
                    next_pc = opcodes[i + 1][0]
                    if next_pc in blocks:
                        blk.successors.append(next_pc)

            elif op not in {
                _OP["STOP"], _OP["RETURN"], _OP["REVERT"], _OP["SELFDESTRUCT"],
            }:
                # Fall-through for non-terminal, non-jump opcodes
                # Only add successor at block boundary
                is_last_in_block = (
                    i + 1 >= len(opcodes)
                    or pc_to_block.get(opcodes[i + 1][0]) != blk_start
                )
                if is_last_in_block and i + 1 < len(opcodes):
                    next_pc = opcodes[i + 1][0]
                    if next_pc in blocks:
                        blk.successors.append(next_pc)

        return blocks

    def _explore_cfg(
        self,
        cfg: Dict[int, _CFGBlock],
        opcodes: List[Tuple[int, int, Optional[int]]],
    ) -> List[ExecutionPath]:
        """
        DFS over CFG blocks up to self._max_paths unique paths.
        Each path records the sequence of block start PCs visited.
        """
        if not cfg:
            return []

        paths: List[ExecutionPath] = []
        # Stack items: (current_block_pc, path_so_far, visited_set)
        start = min(cfg.keys())
        terminal_ops = {
            _OP["STOP"], _OP["RETURN"], _OP["REVERT"], _OP["SELFDESTRUCT"],
        }
        stack: List[Tuple[int, List[int], Set[int]]] = [
            (start, [start], {start})
        ]

        pc_to_op: Dict[int, int] = {pc: op for pc, op, _ in opcodes}

        while stack and len(paths) < self._max_paths:
            cur_pc, path_pcs, visited = stack.pop()
            blk = cfg.get(cur_pc)
            if blk is None:
                continue

            # Determine terminal opcode for this block
            terminal_name = "STOP"
            for _, op, _ in blk.opcodes:
                if op in terminal_ops:
                    terminal_name = _OP_REV.get(op, "STOP")
                    break

            has_terminal = any(op in terminal_ops for _, op, _ in blk.opcodes)
            successors = [s for s in blk.successors if s not in visited]

            if has_terminal or not successors:
                # End of path
                ep = self._build_execution_path(len(paths), path_pcs, cfg, terminal_name)
                paths.append(ep)
            else:
                for succ in successors:
                    stack.append((succ, path_pcs + [succ], visited | {succ}))

        return paths

    def _build_execution_path(
        self,
        pid: int,
        block_pcs: List[int],
        cfg: Dict[int, _CFGBlock],
        terminal: str,
    ) -> ExecutionPath:
        ep = ExecutionPath(
            path_id=pid,
            terminal=terminal,
        )
        call_ops = {_OP["CALL"], _OP["DELEGATECALL"], _OP["CALLCODE"], _OP["STATICCALL"]}
        for bpc in block_pcs:
            blk = cfg.get(bpc)
            if blk is None:
                continue
            ep.add_step(f"block@0x{bpc:04x}")
            for pc, op, _ in blk.opcodes:
                if op == _OP["SSTORE"]:
                    ep.state_writes.append(pc)
                elif op in call_ops:
                    ep.external_calls.append(pc)
                elif op in _ARITH_OPS:
                    ep.arithmetic_ops.append(pc)
        return ep

    def _detect_evm_vulns(
        self,
        paths: List[ExecutionPath],
        opcodes: List[Tuple[int, int, Optional[int]]],
    ) -> List[SymbolicVuln]:
        vulns: List[SymbolicVuln] = []
        seen: Set[str] = set()

        def _add(v: SymbolicVuln) -> None:
            key = f"{v.vuln_type}:{v.pc}"
            if key not in seen:
                seen.add(key)
                vulns.append(v)

        # Per-path analysis
        for ep in paths:
            path_str = " → ".join(ep.steps[:6])
            if len(ep.steps) > 6:
                path_str += " → ..."

            # Reentrancy: SSTORE after CALL on same path
            if ep.external_calls and ep.state_writes:
                for call_pc in ep.external_calls:
                    for sstore_pc in ep.state_writes:
                        if sstore_pc > call_pc:
                            _add(SymbolicVuln(
                                vuln_type="reentrancy",
                                severity="critical",
                                path=path_str,
                                pc=call_pc,
                                description=(
                                    f"SSTORE at 0x{sstore_pc:04x} follows CALL at "
                                    f"0x{call_pc:04x} — classic reentrancy pattern. "
                                    "External call executes before state is committed."
                                ),
                                recommendation=(
                                    "Apply Checks-Effects-Interactions: update state "
                                    "variables before any external calls, or use a "
                                    "reentrancy guard (ReentrancyGuard modifier)."
                                ),
                            ))
                            break

            # SELFDESTRUCT reached on this path
            if ep.terminal == "SELFDESTRUCT":
                _add(SymbolicVuln(
                    vuln_type="access_control",
                    severity="critical",
                    path=path_str,
                    pc=None,
                    description=(
                        "Execution path reaches SELFDESTRUCT. If this path is "
                        "reachable without proper access control, an attacker "
                        "can destroy the contract."
                    ),
                    recommendation=(
                        "Restrict SELFDESTRUCT to owner/admin only via "
                        "onlyOwner modifier or equivalent access control."
                    ),
                ))

        # Global opcode scan — independent of path
        self._scan_opcode_patterns(opcodes, seen, vulns)
        return vulns

    def _scan_opcode_patterns(
        self,
        opcodes: List[Tuple[int, int, Optional[int]]],
        seen: Set[str],
        vulns: List[SymbolicVuln],
    ) -> None:
        """
        Linear scan for EVM vulnerability patterns:
          1. CALL without GAS check (gas forwarding without limit)
          2. ADD/MUL not followed by SAR within next 5 ops (potential overflow)
        """
        op_sequence = [(pc, op) for pc, op, _ in opcodes]
        n = len(op_sequence)

        for i, (pc, op) in enumerate(op_sequence):
            # Pattern 1: CALL opcode with no GAS opcode in previous 3 ops
            if op == _OP["CALL"]:
                window = [op_sequence[j][1] for j in range(max(0, i - 3), i)]
                if _OP["GAS"] not in window:
                    key = f"unchecked_call:{pc}"
                    if key not in seen:
                        seen.add(key)
                        vulns.append(SymbolicVuln(
                            vuln_type="unchecked_call",
                            severity="high",
                            path=f"opcode@0x{pc:04x}",
                            pc=pc,
                            description=(
                                f"CALL at 0x{pc:04x} does not appear to use the "
                                "GAS opcode within the preceding instructions. "
                                "The return value of low-level CALL should be checked."
                            ),
                            recommendation=(
                                "Check the boolean return value of CALL. "
                                "Use Solidity's require(success, ...) pattern "
                                "or a higher-level transfer/send with revert."
                            ),
                        ))

            # Pattern 2: ADD or MUL not followed by SAR/overflow check
            if op in _ARITH_OPS:
                lookahead = [
                    op_sequence[j][1]
                    for j in range(i + 1, min(i + 6, n))
                ]
                if not any(o in _SHIFT_SIGN_OPS for o in lookahead):
                    # Only emit once per PC to avoid flood
                    key = f"integer_overflow:{pc}"
                    if key not in seen:
                        seen.add(key)
                        op_name = _OP_REV.get(op, str(op))
                        vulns.append(SymbolicVuln(
                            vuln_type="integer_overflow",
                            severity="medium",
                            path=f"opcode@0x{pc:04x}",
                            pc=pc,
                            description=(
                                f"{op_name} at 0x{pc:04x} is not followed by a "
                                "SAR/SHR sign-extension check within 5 opcodes. "
                                "Potential integer overflow if operating on "
                                "unchecked user-controlled values."
                            ),
                            recommendation=(
                                "Use Solidity 0.8+ (built-in overflow protection) "
                                "or OpenZeppelin SafeMath. Alternatively use "
                                "ADDMOD/MULMOD where wrapping is expected."
                            ),
                        ))

    # ── Native Solidity analysis ───────────────────────────────────────────────

    def _native_solidity(self, source_path: str, t0: float) -> SymbolicResult:
        try:
            source = Path(source_path).read_text(errors="replace")
        except OSError as exc:
            log.warning("Cannot read %s: %s", source_path, exc)
            return SymbolicResult(0, [], 0, "native", time.monotonic() - t0)

        ast_node = self._parse_solidity_ast(source, source_path)
        paths = self.explore_paths(ast_node, max_depth=50)
        vulns = self._detect_solidity_vulns(paths, source, source_path)
        # Also scan raw source patterns
        vulns += self._scan_solidity_source(source, source_path)
        # Deduplicate by (type, description prefix)
        seen_desc: Set[str] = set()
        unique_vulns: List[SymbolicVuln] = []
        for v in vulns:
            key = f"{v.vuln_type}:{v.description[:60]}"
            if key not in seen_desc:
                seen_desc.add(key)
                unique_vulns.append(v)

        return SymbolicResult(
            paths_explored=len(paths),
            vulnerabilities=unique_vulns,
            uncovered_paths=0,
            tool_used="native",
            execution_time=time.monotonic() - t0,
        )

    def _parse_solidity_ast(self, source: str, filepath: str) -> dict:
        """
        Build a lightweight AST-like structure from Solidity source using
        regex parsing.  Captures function signatures and their body text
        for path exploration.
        """
        contract_name = "UnknownContract"
        m = re.search(r"\bcontract\s+(\w+)", source)
        if m:
            contract_name = m.group(1)

        functions: List[dict] = []
        # Match function definitions including visibility, modifiers, body
        fn_re = re.compile(
            r"\bfunction\s+(\w+)\s*\(([^)]*)\)\s*"
            r"((?:public|external|internal|private|view|pure|payable|"
            r"virtual|override|returns\s*\([^)]*\)|\w+\s*)*)\s*\{",
            re.DOTALL,
        )
        for fm in fn_re.finditer(source):
            fn_name = fm.group(1)
            visibility = "public"
            for vis in ("public", "external", "internal", "private"):
                if vis in fm.group(3):
                    visibility = vis
                    break
            body_start = fm.end()
            body_text, body_nodes = self._extract_body(source, body_start)
            functions.append({
                "name": fn_name,
                "visibility": visibility,
                "start_line": source[: fm.start()].count("\n") + 1,
                "body_text": body_text,
                "body": body_nodes,
            })

        return {
            "type": "Contract",
            "name": contract_name,
            "file": filepath,
            "functions": functions,
        }

    def _extract_body(self, source: str, body_start: int) -> Tuple[str, List[dict]]:
        """
        Extract the text of a function body by matching braces.
        Returns (body_text, list_of_statement_nodes).
        """
        depth = 1
        pos = body_start
        while pos < len(source) and depth > 0:
            ch = source[pos]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
            pos += 1
        body_text = source[body_start: pos - 1]
        nodes = self._parse_body_statements(body_text, body_start, source)
        return body_text, nodes

    def _parse_body_statements(
        self, body: str, offset: int, full_source: str
    ) -> List[dict]:
        """
        Parse body text into a list of statement nodes with type annotations.
        """
        nodes: List[dict] = []
        line_base = full_source[: offset].count("\n") + 1

        # Patterns and their node types
        patterns = [
            ("require", re.compile(r"\brequire\s*\(")),
            ("revert", re.compile(r"\brevert\s*(?:\w*\s*)?\(")),
            ("call", re.compile(r"\.\s*call\s*(?:\{[^}]*\})?\s*\(")),
            ("delegatecall", re.compile(r"\.\s*delegatecall\s*\(")),
            ("transfer", re.compile(r"\.\s*transfer\s*\(")),
            ("send", re.compile(r"\.\s*send\s*\(")),
            ("sstore", re.compile(r"\b(\w+)\s*=")),
            ("selfdestruct", re.compile(r"\bselfdestruct\s*\(")),
            ("emit", re.compile(r"\bemit\s+\w+")),
            ("if_guard", re.compile(r"\bif\s*\(")),
        ]
        for stmt_type, rx in patterns:
            for m in rx.finditer(body):
                line = line_base + body[: m.start()].count("\n")
                nodes.append({
                    "type": stmt_type,
                    "line": line,
                    "text": m.group(0),
                    "pos": m.start(),
                })

        nodes.sort(key=lambda n: n["pos"])
        return nodes

    def _dfs_body(
        self,
        stmts: List[dict],
        current_steps: List[str],
        current_constraints: List[str],
        max_depth: int,
        depth: int,
    ) -> Iterator[ExecutionPath]:
        """
        DFS over statement nodes producing ExecutionPath objects.
        Branches at if_guard nodes; returns at terminal nodes.
        """
        if depth >= max_depth:
            ep = ExecutionPath(
                path_id=0,
                steps=list(current_steps),
                constraints=list(current_constraints),
                terminal="DEPTH_LIMIT",
            )
            yield ep
            return

        if not stmts:
            ep = ExecutionPath(
                path_id=0,
                steps=list(current_steps),
                constraints=list(current_constraints),
                terminal="RETURN",
            )
            yield ep
            return

        stmt = stmts[0]
        rest = stmts[1:]
        step_str = f"{stmt['type']}@line{stmt['line']}"

        if stmt["type"] == "if_guard":
            # Branch: taken path and fall-through path
            yield from self._dfs_body(
                rest, current_steps + [step_str + "(taken)"],
                current_constraints + [f"if_taken@{stmt['line']}"],
                max_depth, depth + 1,
            )
            yield from self._dfs_body(
                rest, current_steps + [step_str + "(skip)"],
                current_constraints + [f"if_skip@{stmt['line']}"],
                max_depth, depth + 1,
            )
        elif stmt["type"] in ("selfdestruct",):
            ep = ExecutionPath(
                path_id=0,
                steps=current_steps + [step_str],
                constraints=list(current_constraints),
                terminal="SELFDESTRUCT",
            )
            yield ep
        elif stmt["type"] in ("revert",):
            ep = ExecutionPath(
                path_id=0,
                steps=current_steps + [step_str],
                constraints=list(current_constraints),
                terminal="REVERT",
            )
            yield ep
        else:
            yield from self._dfs_body(
                rest, current_steps + [step_str],
                list(current_constraints),
                max_depth, depth + 1,
            )

    def _detect_solidity_vulns(
        self,
        paths: List[ExecutionPath],
        source: str,
        filepath: str,
    ) -> List[SymbolicVuln]:
        vulns: List[SymbolicVuln] = []

        for ep in paths:
            path_str = " → ".join(ep.steps[:8])
            types = [s.split("@")[0] for s in ep.steps]

            # Reentrancy: call before sstore (state update after external call)
            call_idx = next((i for i, t in enumerate(types) if t == "call"), None)
            sstore_idx = next((i for i, t in enumerate(types) if t == "sstore"), None)
            if call_idx is not None and sstore_idx is not None and sstore_idx > call_idx:
                vulns.append(SymbolicVuln(
                    vuln_type="reentrancy",
                    severity="critical",
                    path=path_str,
                    pc=None,
                    description=(
                        "External .call() at step "
                        f"{ep.steps[call_idx]} precedes state update "
                        f"at {ep.steps[sstore_idx]}. "
                        "Reentrancy: an attacker can re-enter before state is committed."
                    ),
                    recommendation=(
                        "Move all state changes before external calls "
                        "(Checks-Effects-Interactions). Use ReentrancyGuard."
                    ),
                ))

            # Missing require guard before call
            if call_idx is not None:
                has_guard = any(t in ("require", "if_guard") for t in types[:call_idx])
                if not has_guard:
                    vulns.append(SymbolicVuln(
                        vuln_type="access_control",
                        severity="high",
                        path=path_str,
                        pc=None,
                        description=(
                            "External .call() at "
                            f"{ep.steps[call_idx]} is not preceded by a "
                            "require() or if-guard on this path. "
                            "Missing access-control check."
                        ),
                        recommendation=(
                            "Add require(msg.sender == owner) or equivalent "
                            "access control before external calls."
                        ),
                    ))

            # SELFDESTRUCT reachable
            if ep.terminal == "SELFDESTRUCT":
                has_guard = any(t in ("require", "if_guard") for t in types)
                severity = "critical" if not has_guard else "high"
                vulns.append(SymbolicVuln(
                    vuln_type="access_control",
                    severity=severity,
                    path=path_str,
                    pc=None,
                    description=(
                        "selfdestruct() is reachable"
                        + (" without access-control guard" if not has_guard else "")
                        + " on this execution path."
                    ),
                    recommendation=(
                        "Restrict selfdestruct() with onlyOwner or "
                        "multi-sig governance. Consider removing selfdestruct."
                    ),
                ))

        return vulns

    def _scan_solidity_source(
        self, source: str, filepath: str
    ) -> List[SymbolicVuln]:
        """Additional raw-source pattern scan for patterns not captured by AST paths."""
        vulns: List[SymbolicVuln] = []
        lines = source.splitlines()

        # Flash-loan pattern: balanceBefore / balanceAfter + require pattern
        if re.search(r"balance\w*Before|flashLoan|onFlashLoan", source, re.IGNORECASE):
            vulns.append(SymbolicVuln(
                vuln_type="flash_loan",
                severity="high",
                path="source_pattern",
                pc=None,
                description=(
                    "Flash-loan related balance check detected. "
                    "Verify price oracle and balance checks cannot be "
                    "manipulated within a single transaction."
                ),
                recommendation=(
                    "Use TWAP oracles, add reentrancy guards around "
                    "flash-loan callbacks, and validate callback origin."
                ),
            ))

        # tx.origin authentication
        for lineno, line in enumerate(lines, 1):
            if "tx.origin" in line and "==" in line:
                vulns.append(SymbolicVuln(
                    vuln_type="access_control",
                    severity="critical",
                    path=f"line:{lineno}",
                    pc=None,
                    description=(
                        f"Line {lineno}: tx.origin used for authentication. "
                        "Phishing contracts can bypass this check."
                    ),
                    recommendation=(
                        "Replace tx.origin with msg.sender for authorization checks."
                    ),
                ))

        # Solidity version < 0.8.0 (no built-in overflow protection)
        m = re.search(r"pragma\s+solidity\s+([^;]+);", source)
        if m:
            ver_str = m.group(1).strip()
            if re.search(r"(?:\^|>=|>)\s*0\.[0-7]\.", ver_str):
                vulns.append(SymbolicVuln(
                    vuln_type="integer_overflow",
                    severity="high",
                    path="pragma",
                    pc=None,
                    description=(
                        f"Solidity version constraint '{ver_str}' may compile "
                        "with a version < 0.8.0 where integer overflow is not "
                        "automatically checked."
                    ),
                    recommendation=(
                        "Upgrade to Solidity ^0.8.0 or use OpenZeppelin SafeMath."
                    ),
                ))

        return vulns
