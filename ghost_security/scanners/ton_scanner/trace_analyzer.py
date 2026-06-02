"""
TythanAI Phase 8 — TON Transaction Trace Analyzer

Analyzes TON transaction traces for:
1. Contract invariant violations (balance, ownership, plugin map integrity)
2. Multi-step attack pattern detection (fund drain, ownership takeover chains)
3. Message flow anomalies (unexpected senders, abnormal value routing)
4. Cross-contract attack path reconstruction
5. Value conservation checks (total TON in ≈ total TON out + gas)

A "trace" is a list of transaction dicts (as returned by TON sandbox or
lite-client trace APIs) with keys:
  id, from, to, value, op_code, status, state_before, state_after,
  outgoing_messages, gas_used, action_phase_ok, storage_changed, hash
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Invariant definitions
# ---------------------------------------------------------------------------

@dataclass
class Invariant:
    name:       str
    description: str
    severity:   str                     # CRITICAL / HIGH / MEDIUM
    check:      Callable[[Dict], bool]  # check(state_after) → True means OK

    def violated_by(self, state: Dict[str, Any]) -> bool:
        try:
            return not self.check(state)
        except Exception:
            return False


_DEFAULT_INVARIANTS: List[Invariant] = [
    Invariant(
        name="non_negative_balance",
        description="Contract balance must never be negative",
        severity="CRITICAL",
        check=lambda s: s.get("balance", 0) >= 0,
    ),
    Invariant(
        name="valid_plugin_map",
        description="Plugin map must exist in wallet state",
        severity="HIGH",
        check=lambda s: "plugins" not in s or isinstance(s["plugins"], (dict, list)),
    ),
    Invariant(
        name="owner_not_zero",
        description="Owner address must not be the zero address",
        severity="CRITICAL",
        check=lambda s: s.get("owner", "non-zero") not in ("", "0x00", "0" * 64),
    ),
    Invariant(
        name="seqno_monotone",
        description="Sequence number must be monotonically increasing",
        severity="HIGH",
        check=lambda s: True,           # requires cross-step context; checked in process_trace
    ),
    Invariant(
        name="initialized_flag",
        description="Initialized flag must not flip back to False",
        severity="CRITICAL",
        check=lambda s: True,           # cross-step check
    ),
]


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class InvariantViolation:
    invariant_name: str
    step_id:        Any
    severity:       str
    state_after:    Dict[str, Any]
    description:    str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "invariant":   self.invariant_name,
            "step":        self.step_id,
            "severity":    self.severity,
            "description": self.description,
        }


@dataclass
class MessageFlowAnomaly:
    anomaly_type:  str      # UNEXPECTED_SENDER, ABNORMAL_VALUE_ROUTE, MISSING_OP_CHECK
    step_id:       Any
    severity:      str
    from_addr:     str
    to_addr:       str
    value:         int
    op_code:       str
    description:   str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "anomaly_type": self.anomaly_type,
            "step":         self.step_id,
            "severity":     self.severity,
            "from":         self.from_addr,
            "to":           self.to_addr,
            "value":        self.value,
            "op_code":      self.op_code,
            "description":  self.description,
        }


@dataclass
class AttackChainSegment:
    chain_type:  str        # FUND_DRAIN, OWNERSHIP_TAKEOVER, REENTRANCY
    steps:       List[Any]  # step IDs involved
    description: str
    severity:    str = "CRITICAL"


@dataclass
class TraceAnalysisResult:
    total_steps:         int
    violations:          List[InvariantViolation] = field(default_factory=list)
    anomalies:           List[MessageFlowAnomaly] = field(default_factory=list)
    attack_chains:       List[AttackChainSegment] = field(default_factory=list)
    value_conservation:  Optional[Dict[str, Any]] = None
    risk_level:          str = "LOW"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_steps":      self.total_steps,
            "risk_level":       self.risk_level,
            "violations":       [v.to_dict() for v in self.violations],
            "anomalies":        [a.to_dict() for a in self.anomalies],
            "attack_chains":    [
                {"type": c.chain_type, "steps": c.steps,
                 "severity": c.severity, "description": c.description}
                for c in self.attack_chains
            ],
            "value_conservation": self.value_conservation,
        }


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

class SmartTraceAnalyzer:
    """
    Full TON transaction trace analyzer with invariant checking,
    anomaly detection, and attack chain reconstruction.
    """

    def __init__(
        self, extra_invariants: Optional[List[Invariant]] = None
    ) -> None:
        self.invariants: List[Invariant] = list(_DEFAULT_INVARIANTS)
        if extra_invariants:
            self.invariants.extend(extra_invariants)

    # ------------------------------------------------------------------
    # Primary API
    # ------------------------------------------------------------------

    def process_trace(
        self, trace_data: List[Dict[str, Any]]
    ) -> TraceAnalysisResult:
        """
        Analyze a full transaction trace. Returns TraceAnalysisResult.
        trace_data: list of step dicts from sandbox/lite-client.
        """
        violations    = self._check_invariants(trace_data)
        anomalies     = self._detect_message_anomalies(trace_data)
        chains        = self._reconstruct_attack_chains(trace_data, violations, anomalies)
        value_check   = self._check_value_conservation(trace_data)

        # Compute risk level
        if any(v.severity == "CRITICAL" for v in violations) or chains:
            risk = "CRITICAL"
        elif any(v.severity == "HIGH" for v in violations) or anomalies:
            risk = "HIGH"
        elif violations:
            risk = "MEDIUM"
        elif (value_check is not None
              and not value_check.get("conserved")
              and value_check.get("total_in_nanoton", 0) > 0):
            risk = "MEDIUM"
        else:
            risk = "LOW"

        return TraceAnalysisResult(
            total_steps=len(trace_data),
            violations=violations,
            anomalies=anomalies,
            attack_chains=chains,
            value_conservation=value_check,
            risk_level=risk,
        )

    def visualize_trace(self, trace_data: List[Dict[str, Any]]) -> str:
        """
        Generate a human-readable text representation of the transaction chain.
        Includes value flow, op-codes, and status per step.
        """
        lines: List[str] = ["═" * 70, "TON TRANSACTION TRACE", "═" * 70]
        for step in trace_data:
            step_id = step.get("id", "?")
            from_a  = str(step.get("from", "?"))[:20]
            to_a    = str(step.get("to", "?"))[:20]
            value   = step.get("value", 0)
            op      = step.get("op_code", step.get("op", "?"))
            status  = step.get("status", "?")
            gas     = step.get("gas_used", "?")

            value_ton = value / 10**9 if isinstance(value, int) and value > 0 else value
            lines.append(
                f"[{step_id:>4}] {from_a:<22} → {to_a:<22} "
                f"| {value_ton:.3f} TON | op={op} | {status} | gas={gas}"
            )
            # Flag suspicious steps
            if status in ("failed", "aborted"):
                lines.append(f"       ⚠ FAILED STEP — check storage_changed flag")
            if step.get("storage_changed") and not step.get("action_phase_ok", True):
                lines.append(f"       🔴 PHANTOM STATE: storage changed but actions failed")
        lines.append("═" * 70)
        return "\n".join(lines)

    def add_invariant(self, invariant: Invariant) -> None:
        """Register a custom invariant for this analyzer instance."""
        self.invariants.append(invariant)

    # ------------------------------------------------------------------
    # Invariant checking
    # ------------------------------------------------------------------

    def _check_invariants(
        self, trace: List[Dict[str, Any]]
    ) -> List[InvariantViolation]:
        violations: List[InvariantViolation] = []
        prev_seqno: Optional[int] = None
        prev_initialized: Optional[bool] = None

        for step in trace:
            state = step.get("state_after", {})
            step_id = step.get("id", "?")

            for inv in self.invariants:
                if inv.name == "seqno_monotone":
                    seqno = state.get("seqno")
                    if seqno is not None and prev_seqno is not None:
                        if seqno < prev_seqno:
                            violations.append(InvariantViolation(
                                invariant_name=inv.name,
                                step_id=step_id,
                                severity=inv.severity,
                                state_after=state,
                                description=(
                                    f"seqno decreased: {prev_seqno} → {seqno}. "
                                    "Possible replay attack or state rollback."
                                ),
                            ))
                    if seqno is not None:
                        prev_seqno = seqno
                    continue

                if inv.name == "initialized_flag":
                    initialized = state.get("initialized")
                    if (initialized is not None and prev_initialized is True
                            and initialized is False):
                        violations.append(InvariantViolation(
                            invariant_name=inv.name,
                            step_id=step_id,
                            severity=inv.severity,
                            state_after=state,
                            description=(
                                "initialized flag flipped False after being True. "
                                "Contract re-initialization attack detected."
                            ),
                        ))
                    if initialized is not None:
                        prev_initialized = initialized
                    continue

                if inv.violated_by(state):
                    violations.append(InvariantViolation(
                        invariant_name=inv.name,
                        step_id=step_id,
                        severity=inv.severity,
                        state_after=state,
                        description=f"Invariant '{inv.name}' violated: {inv.description}",
                    ))

        return violations

    # ------------------------------------------------------------------
    # Anomaly detection
    # ------------------------------------------------------------------

    def _detect_message_anomalies(
        self, trace: List[Dict[str, Any]]
    ) -> List[MessageFlowAnomaly]:
        anomalies: List[MessageFlowAnomaly] = []

        # Build known-contracts set from addresses that have SENT messages
        # (i.e. appeared as from_addr — these are contracts we've observed acting)
        contracts_seen: set = set()
        for step in trace:
            from_addr = str(step.get("from", ""))
            if from_addr:
                contracts_seen.add(from_addr)

        for step in trace:
            step_id  = step.get("id", "?")
            from_a   = str(step.get("from", ""))
            to_a     = str(step.get("to", ""))
            value    = step.get("value", 0)
            op       = str(step.get("op_code", step.get("op", "")))
            status   = step.get("status", "ok")

            # Unexpected sender: message from address never seen as a contract
            if from_a and from_a not in contracts_seen and step.get("msg_type") == "internal":
                # External-looking sender sending as if internal
                anomalies.append(MessageFlowAnomaly(
                    anomaly_type="UNEXPECTED_SENDER",
                    step_id=step_id,
                    severity="MEDIUM",
                    from_addr=from_a,
                    to_addr=to_a,
                    value=value,
                    op_code=op,
                    description=(
                        f"Internal message from unknown address {from_a[:20]}. "
                        "Verify sender is a trusted contract."
                    ),
                ))

            # Abnormal value routing: large value transfer to external (non-contract) address
            if isinstance(value, int) and value > 10**10:  # > 10 TON
                if to_a and to_a not in contracts_seen:
                    anomalies.append(MessageFlowAnomaly(
                        anomaly_type="ABNORMAL_VALUE_ROUTE",
                        step_id=step_id,
                        severity="HIGH",
                        from_addr=from_a,
                        to_addr=to_a,
                        value=value,
                        op_code=op,
                        description=(
                            f"Large value ({value/10**9:.2f} TON) routed to "
                            f"unknown address {to_a[:20]}. Possible fund drain."
                        ),
                    ))

            # Failed step with value > 0 (gas-drain via intentional failure)
            if status in ("failed", "aborted") and isinstance(value, int) and value > 10**7:
                anomalies.append(MessageFlowAnomaly(
                    anomaly_type="FAILED_STEP_WITH_VALUE",
                    step_id=step_id,
                    severity="MEDIUM",
                    from_addr=from_a,
                    to_addr=to_a,
                    value=value,
                    op_code=op,
                    description=(
                        f"Step failed but had attached value {value/10**9:.3f} TON. "
                        "Check if gas fees are being artificially inflated."
                    ),
                ))

        return anomalies

    # ------------------------------------------------------------------
    # Attack chain reconstruction
    # ------------------------------------------------------------------

    def _reconstruct_attack_chains(
        self,
        trace: List[Dict[str, Any]],
        violations: List[InvariantViolation],
        anomalies: List[MessageFlowAnomaly],
    ) -> List[AttackChainSegment]:
        chains: List[AttackChainSegment] = []

        # Pattern 1: FUND_DRAIN — multiple large value sends in sequence
        drain_steps = [
            a.step_id for a in anomalies
            if a.anomaly_type == "ABNORMAL_VALUE_ROUTE"
        ]
        if len(drain_steps) >= 2:
            chains.append(AttackChainSegment(
                chain_type="FUND_DRAIN",
                steps=drain_steps,
                severity="CRITICAL",
                description=(
                    f"{len(drain_steps)} large value transfers to unknown addresses. "
                    "Possible coordinated fund drain attack."
                ),
            ))

        # Pattern 2: OWNERSHIP_TAKEOVER — owner invariant violated after unexpected sender
        owner_violations = [v for v in violations if "owner" in v.invariant_name.lower()]
        unexpected_senders = [a for a in anomalies if a.anomaly_type == "UNEXPECTED_SENDER"]
        if owner_violations and unexpected_senders:
            chains.append(AttackChainSegment(
                chain_type="OWNERSHIP_TAKEOVER",
                steps=[a.step_id for a in unexpected_senders]
                      + [v.step_id for v in owner_violations],
                severity="CRITICAL",
                description=(
                    "Unexpected sender followed by owner invariant violation. "
                    "Possible ownership takeover attack."
                ),
            ))

        # Pattern 3: PHANTOM_STATE — storage changed but action failed
        phantom_steps = [
            step.get("id", "?")
            for step in trace
            if step.get("storage_changed") and not step.get("action_phase_ok", True)
        ]
        if phantom_steps:
            chains.append(AttackChainSegment(
                chain_type="PHANTOM_STATE",
                steps=phantom_steps,
                severity="CRITICAL",
                description=(
                    "Storage committed in compute phase while action phase failed. "
                    "Contract state is permanently inconsistent."
                ),
            ))

        return chains

    # ------------------------------------------------------------------
    # Value conservation
    # ------------------------------------------------------------------

    def _check_value_conservation(
        self, trace: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Check that total TON flowing in ≈ total TON flowing out + gas fees.
        Large discrepancies may indicate value leakage bugs.
        """
        total_in  = sum(
            step.get("value", 0)
            for step in trace
            if step.get("msg_type") == "external"
            and isinstance(step.get("value"), int)
        )
        total_out = sum(
            sum(
                msg.get("value", 0)
                for msg in step.get("outgoing_messages", [])
                if isinstance(msg.get("value"), int)
            )
            for step in trace
        )
        total_gas = sum(
            step.get("gas_used", 0)
            for step in trace
            if isinstance(step.get("gas_used"), int)
        )
        # Allow 5% tolerance for gas estimation
        expected_out = total_in - total_gas
        conserved = abs(total_out - expected_out) <= max(10**7, total_in * 0.05)
        return {
            "total_in_nanoton":  total_in,
            "total_out_nanoton": total_out,
            "total_gas":         total_gas,
            "conserved":         conserved,
            "discrepancy":       abs(total_out - expected_out),
        }


# ---------------------------------------------------------------------------
# Backward-compatible alias
# ---------------------------------------------------------------------------

class TraceAnalyzer(SmartTraceAnalyzer):
    """Legacy class name kept for backward compatibility."""

    def __init__(self) -> None:
        super().__init__()
        # Expose invariants as the legacy list format
        self.invariants_legacy = [
            {"name": "non_negative_balance",
             "check": lambda s: s.get("balance", 0) >= 0},
            {"name": "valid_plugin_map",
             "check": lambda s: "plugins" not in s or isinstance(s["plugins"], (dict, list))},
        ]
