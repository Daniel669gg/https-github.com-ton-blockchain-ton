"""
TythanAI Phase 8 — TON Contract Structure Fuzzer

Structure-aware mutation fuzzer for TON smart contracts.
Generates mutation-based test inputs targeting:
- op-code boundaries (known vs unknown op-codes)
- Integer edge cases (257-bit TVM boundaries)
- Message body malformations (extra/missing bits, truncated slices)
- Ownership-probe messages (spoofed sender addresses)
- Replay attack inputs (duplicate query_id/seqno)
- Bounce message edge cases (is_bounced flag)
- Gas drain scenarios (mode 128/64 targeting)

Works on FunC/Tact SOURCE to extract op-codes and message formats,
then generates structured test cases as dicts ready for simulation.
"""
from __future__ import annotations

import random
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Pattern matchers for source analysis
# ---------------------------------------------------------------------------

_OPCODE_HEX   = re.compile(r"op\s*==\s*0x([0-9a-fA-F]+)", re.IGNORECASE)
_OPCODE_DEC   = re.compile(r"op\s*==\s*(\d+)\b")
_OPCODE_CONST = re.compile(r"op::\w+\s*=\s*0x([0-9a-fA-F]+)", re.IGNORECASE)
_SEND_MODE    = re.compile(r"send_raw_message\s*\([^,]+,\s*(\d+)\s*\)")
_UINT_LOAD    = re.compile(r"load_uint\s*\((\d+)\)")
_INT_LOAD     = re.compile(r"load_int\s*\((\d+)\)")

# Well-known TEP op-codes
_KNOWN_OPS: Dict[int, str] = {
    0x0f8a7ea5: "jetton_transfer",
    0x7362d09c: "jetton_transfer_notification",
    0x178d4519: "internal_transfer",
    0x7bdd97de: "jetton_excesses",
    0x595f07bc: "jetton_burn",
    0xd53276db: "excesses",
    0x5fcc3d14: "nft_transfer",
    0x693d3950: "nft_get_static_data",
    0x8b771735: "nft_ownership_assigned",
    0x2504f7e6: "multisig_new_order",
    0xc1387443: "multisig_approve",
    0xffffffff: "op_bounce",
}

# 257-bit TVM integer boundary values
_INT_BOUNDARIES: List[int] = [
    0, 1, -1,
    2**63 - 1, -(2**63),
    2**127, 2**128 - 1,
    2**256 - 1, -(2**256),
    10**9,      # 1 TON in nanotons
    10**18,     # 1 billion TON
]

_BOGUS_SENDERS: List[str] = [
    "0x" + "00" * 32,
    "0x" + "ff" * 32,
    "0xdeadbeef" + "00" * 28,
]


@dataclass
class FuzzMessage:
    """A single structured fuzz test input (simulated TON message)."""
    msg_type:         str               # "internal" | "external"
    op_code:          int
    op_name:          str
    body_fields:      Dict[str, Any]    # field_name → value
    sender:           str               # symbolic address
    value_nanoton:    int               # attached TON value in nanotons
    bounce:           bool = True
    is_bounced:       bool = False
    query_id:         int = 0
    mutation_type:    str = ""          # label describing mutation applied
    expected_behavior: str = ""        # "reject" | "process" | "conditional"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "msg_type":          self.msg_type,
            "op_code":           hex(self.op_code),
            "op_name":           self.op_name,
            "body_fields":       self.body_fields,
            "sender":            self.sender,
            "value_nanoton":     self.value_nanoton,
            "bounce":            self.bounce,
            "is_bounced":        self.is_bounced,
            "query_id":          self.query_id,
            "mutation_type":     self.mutation_type,
            "expected_behavior": self.expected_behavior,
        }


@dataclass
class FuzzSuite:
    """Collection of fuzz test cases for a single contract."""
    contract_file: str
    ops_extracted: List[int]
    cases: List[FuzzMessage] = field(default_factory=list)

    @property
    def total_cases(self) -> int:
        return len(self.cases)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "contract_file": self.contract_file,
            "ops_extracted": [hex(op) for op in self.ops_extracted],
            "total_cases":   self.total_cases,
            "cases":         [c.to_dict() for c in self.cases],
        }


class ContractStructureFuzzer:
    """
    Structure-aware mutation fuzzer for TON smart contracts.

    Extracts op-codes, field widths, and send modes from FunC/Tact source,
    then generates mutation-based test inputs for edge cases and
    security boundaries.
    """

    def __init__(self, seed: Optional[int] = None) -> None:
        self._rng = random.Random(seed if seed is not None else 42)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def fuzz_contract(self, source: str, file_path: str = "contract.fc") -> FuzzSuite:
        """Generate a complete fuzz suite for a contract source string."""
        ops        = self._extract_op_codes(source)
        fwidths    = self._extract_field_widths(source)
        send_modes = self._extract_send_modes(source)
        suite      = FuzzSuite(contract_file=file_path, ops_extracted=list(ops))

        for op in ops:
            suite.cases.extend(self._gen_valid_cases(op, fwidths))

        suite.cases.extend(self._gen_unknown_op_cases(ops))
        suite.cases.extend(self._gen_int_boundary_cases(ops, fwidths))
        suite.cases.extend(self._gen_ownership_probe_cases(ops))
        suite.cases.extend(self._gen_replay_cases(ops))
        suite.cases.extend(self._gen_bounce_cases(ops))
        suite.cases.extend(self._gen_empty_body_cases(ops))

        if any(m in (64, 128, 130, 66) for m in send_modes):
            suite.cases.extend(self._gen_gas_drain_cases(ops))

        return suite

    def fuzz_methods(self, methods: List[str]) -> Dict[str, List[Dict[str, Any]]]:
        """Generate structured fuzz inputs per method name."""
        result: Dict[str, List[Dict[str, Any]]] = {}
        for method in methods:
            op = abs(hash(method)) % 0xFFFFFF or 0x1
            cases = self._gen_valid_cases(op, {})
            cases.extend(self._gen_int_boundary_cases([op], {}))
            result[method] = [c.to_dict() for c in cases]
        return result

    def generate_random_cell(self) -> str:
        """Return a random hex string representing a BOC cell."""
        length = self._rng.randint(8, 64) * 2
        return "".join(self._rng.choice("0123456789abcdef") for _ in range(length))

    def generate_plugin_lifecycle_test(self, wallet_address: str) -> List[Dict[str, Any]]:
        """Generate full plugin lifecycle probe sequence for wallet contracts."""
        chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        plugin_addr = "EQ" + "".join(self._rng.choice(chars) for _ in range(46))
        return [
            {
                "action": "install_plugin",
                "wallet": wallet_address,
                "plugin": plugin_addr,
                "value_nanoton": 10_000_000,
                "expected": "success",
                "probe": "normal_install",
            },
            {
                "action": "probe_privilege_escalation",
                "wallet": wallet_address,
                "plugin": plugin_addr,
                "payload": self.generate_random_cell(),
                "expected": "reject_if_unauthorized",
                "probe": "plugin_privilege",
            },
            {
                "action": "execute_plugin",
                "wallet": wallet_address,
                "plugin": plugin_addr,
                "payload": self.generate_random_cell(),
                "expected": "conditional",
                "probe": "execute_after_install",
            },
            {
                "action": "remove_plugin",
                "wallet": wallet_address,
                "plugin": plugin_addr,
                "expected": "success",
                "probe": "normal_remove",
            },
            {
                "action": "verify_removal",
                "wallet": wallet_address,
                "plugin": plugin_addr,
                "expected": "plugin_not_found",
                "probe": "verify_removed",
            },
        ]

    # ------------------------------------------------------------------
    # Source analysis
    # ------------------------------------------------------------------

    def _extract_op_codes(self, source: str) -> List[int]:
        ops: List[int] = []
        for m in _OPCODE_HEX.finditer(source):
            try:
                ops.append(int(m.group(1), 16))
            except ValueError:
                pass
        for m in _OPCODE_DEC.finditer(source):
            try:
                val = int(m.group(1))
                if val > 0:
                    ops.append(val)
            except ValueError:
                pass
        for m in _OPCODE_CONST.finditer(source):
            try:
                ops.append(int(m.group(1), 16))
            except ValueError:
                pass
        seen: set = set()
        result: List[int] = []
        for op in ops:
            if op not in seen:
                seen.add(op)
                result.append(op)
        return result or [0x1]

    def _extract_field_widths(self, source: str) -> Dict[str, int]:
        widths: Dict[str, int] = {}
        for m in _UINT_LOAD.finditer(source):
            widths[f"uint_{m.group(1)}"] = int(m.group(1))
        for m in _INT_LOAD.finditer(source):
            widths[f"int_{m.group(1)}"] = int(m.group(1))
        return widths

    def _extract_send_modes(self, source: str) -> List[int]:
        modes: List[int] = []
        for m in _SEND_MODE.finditer(source):
            try:
                modes.append(int(m.group(1)))
            except ValueError:
                pass
        return modes

    # ------------------------------------------------------------------
    # Case generators
    # ------------------------------------------------------------------

    def _gen_valid_cases(self, op: int, fwidths: Dict[str, int]) -> List[FuzzMessage]:
        op_name = _KNOWN_OPS.get(op, f"op_{hex(op)}")
        qid = self._rng.randint(1, 2**62)
        return [
            FuzzMessage(
                msg_type="internal", op_code=op, op_name=op_name,
                body_fields={"query_id": qid, "amount": 10**9},
                sender="owner_address", value_nanoton=10**8,
                query_id=qid, mutation_type="valid_nominal",
                expected_behavior="process",
            ),
            FuzzMessage(
                msg_type="internal", op_code=op, op_name=op_name,
                body_fields={"query_id": qid + 1, "amount": 0},
                sender="owner_address", value_nanoton=0,
                query_id=qid + 1, mutation_type="zero_value",
                expected_behavior="reject",
            ),
        ]

    def _gen_unknown_op_cases(self, known_ops: List[int]) -> List[FuzzMessage]:
        known_set = set(known_ops)
        cases: List[FuzzMessage] = []
        candidates = [
            ("off_by_one_high", (max(known_ops) + 1) if known_ops else 0x99),
            ("off_by_one_low",  max(0, (min(known_ops) - 1)) if known_ops else 0x0),
            ("op_all_zeros",    0x00000000),
            ("op_all_ones",     0xFFFFFFFF),
            ("op_random",       self._rng.randint(0x10000000, 0xEFFFFFFF)),
        ]
        for mut, op in candidates:
            if op not in known_set:
                cases.append(FuzzMessage(
                    msg_type="internal", op_code=op,
                    op_name=f"unknown_{hex(op)}",
                    body_fields={}, sender="attacker_address",
                    value_nanoton=10**7, mutation_type=mut,
                    expected_behavior="reject",
                ))
        return cases

    def _gen_int_boundary_cases(
        self, ops: List[int], fwidths: Dict[str, int]
    ) -> List[FuzzMessage]:
        op = ops[0] if ops else 0x1
        op_name = _KNOWN_OPS.get(op, f"op_{hex(op)}")
        cases: List[FuzzMessage] = []
        for boundary in _INT_BOUNDARIES:
            nanoton = boundary if 0 <= boundary <= 10**18 else 10**8
            cases.append(FuzzMessage(
                msg_type="internal", op_code=op, op_name=op_name,
                body_fields={"query_id": 1, "amount": boundary},
                sender="owner_address", value_nanoton=nanoton,
                mutation_type=f"int_boundary_{boundary}",
                expected_behavior="reject" if boundary < 0 or boundary > 2**256 else "conditional",
            ))
        return cases

    def _gen_ownership_probe_cases(self, ops: List[int]) -> List[FuzzMessage]:
        cases: List[FuzzMessage] = []
        sensitive = [op for op in ops if op in _KNOWN_OPS and
                     "transfer" in _KNOWN_OPS[op] or "assign" in _KNOWN_OPS.get(op, "")]
        probe_ops = (sensitive or ops)[:2]
        for op in probe_ops:
            op_name = _KNOWN_OPS.get(op, f"op_{hex(op)}")
            for i, bogus in enumerate(_BOGUS_SENDERS):
                cases.append(FuzzMessage(
                    msg_type="internal", op_code=op, op_name=op_name,
                    body_fields={"query_id": 1, "new_owner": bogus},
                    sender=bogus, value_nanoton=10**7,
                    mutation_type=f"ownership_probe_{i}",
                    expected_behavior="reject",
                ))
        return cases

    def _gen_replay_cases(self, ops: List[int]) -> List[FuzzMessage]:
        op = ops[0] if ops else 0x1
        op_name = _KNOWN_OPS.get(op, f"op_{hex(op)}")
        shared_qid = self._rng.randint(100, 200)
        cases: List[FuzzMessage] = []
        for i in range(3):
            cases.append(FuzzMessage(
                msg_type="internal", op_code=op, op_name=op_name,
                body_fields={"query_id": shared_qid, "amount": 10**9},
                sender="owner_address", value_nanoton=10**8,
                query_id=shared_qid, mutation_type=f"replay_attempt_{i}",
                expected_behavior="reject" if i > 0 else "process",
            ))
        cases.append(FuzzMessage(
            msg_type="external", op_code=op, op_name=op_name,
            body_fields={"seqno": 0, "valid_until": 2**32 - 1},
            sender="external", value_nanoton=0,
            mutation_type="seqno_zero_replay",
            expected_behavior="reject",
        ))
        return cases

    def _gen_bounce_cases(self, ops: List[int]) -> List[FuzzMessage]:
        op = ops[0] if ops else 0x1
        op_name = _KNOWN_OPS.get(op, f"op_{hex(op)}")
        return [
            FuzzMessage(
                msg_type="internal", op_code=0xFFFFFFFF,
                op_name="bounce_handler",
                body_fields={"original_op": op, "query_id": 1},
                sender="some_contract", value_nanoton=10**7,
                bounce=False, is_bounced=True,
                mutation_type="bounce_with_original_op",
                expected_behavior="conditional",
            ),
            FuzzMessage(
                msg_type="internal", op_code=0xFFFFFFFF,
                op_name="bounce_zero_value",
                body_fields={"original_op": op, "query_id": 0},
                sender="some_contract", value_nanoton=0,
                bounce=False, is_bounced=True,
                mutation_type="bounce_zero_value",
                expected_behavior="reject",
            ),
        ]

    def _gen_gas_drain_cases(self, ops: List[int]) -> List[FuzzMessage]:
        op = ops[0] if ops else 0x1
        op_name = _KNOWN_OPS.get(op, f"op_{hex(op)}")
        return [
            FuzzMessage(
                msg_type="internal", op_code=op, op_name=op_name,
                body_fields={"query_id": 999, "mode": 128},
                sender="attacker_address", value_nanoton=10**7,
                mutation_type="gas_drain_mode128",
                expected_behavior="reject",
            ),
            FuzzMessage(
                msg_type="external", op_code=op, op_name=op_name,
                body_fields={"seqno": 9999, "valid_until": 2**32 - 1},
                sender="external", value_nanoton=0,
                mutation_type="accept_message_spam",
                expected_behavior="reject",
            ),
        ]

    def _gen_empty_body_cases(self, ops: List[int]) -> List[FuzzMessage]:
        op = ops[0] if ops else 0x1
        op_name = _KNOWN_OPS.get(op, f"op_{hex(op)}")
        return [
            FuzzMessage(
                msg_type="internal", op_code=op, op_name=op_name,
                body_fields={},
                sender="attacker_address", value_nanoton=10**7,
                mutation_type="empty_body",
                expected_behavior="reject",
            ),
            FuzzMessage(
                msg_type="internal", op_code=op, op_name=op_name,
                body_fields={"_truncated": True},
                sender="attacker_address", value_nanoton=10**7,
                mutation_type="truncated_after_opcode",
                expected_behavior="reject",
            ),
        ]


# ---------------------------------------------------------------------------
# Backward-compatible alias
# ---------------------------------------------------------------------------

class TONFuzzer(ContractStructureFuzzer):
    """Legacy name kept for backward compatibility."""

    def fuzz_methods(self, methods):  # type: ignore[override]
        return super().fuzz_methods(list(methods))

    def generate_random_cell(self) -> str:  # type: ignore[override]
        return super().generate_random_cell()

    def generate_plugin_lifecycle_test(self, wallet_address: str) -> list:  # type: ignore[override]
        return super().generate_plugin_lifecycle_test(wallet_address)
