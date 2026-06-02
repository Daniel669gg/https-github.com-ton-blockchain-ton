"""
TythanAI Phase 8 — TON Rollback & CEI Analyzer

Detects TON-specific storage/action ordering vulnerabilities:

1. CEI violations (Checks-Effects-Interactions):
   TON commits c4 storage in the COMPUTE phase BEFORE sending messages.
   If the action phase fails, storage is NOT rolled back.
   Pattern: set_data() BEFORE send_raw_message() with no raw_reserve guard.

2. Send mode risk analysis:
   mode 128 — sends ALL contract balance (catastrophic drain)
   mode 64  — sends remaining msg_value (can over-drain)
   mode 32  — destroys contract after send

3. Phantom state detection from execution traces:
   storage_changed=True but action_phase_ok=False → orphaned state.

4. Missing bounce handler detection:
   Contract sends messages with bounce=True but has no recv_internal
   handler for bounced messages.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Send-mode constants
# ---------------------------------------------------------------------------

_MODE_CARRY_REMAINING_GAS  = 1
_MODE_IGNORE_ERRORS        = 2
_MODE_CARRY_REMAINING_BODY = 32   # destroy contract
_MODE_CARRY_REMAINING_MSG  = 64   # carry all incoming value
_MODE_CARRY_ALL_BALANCE    = 128  # carry ENTIRE contract balance


# ---------------------------------------------------------------------------
# Source analysis patterns
# ---------------------------------------------------------------------------

_SET_DATA   = re.compile(r"\bset_data\s*\(", re.IGNORECASE)
_SAVE_DATA  = re.compile(r"\bsave_data\s*\(", re.IGNORECASE)
_SEND_MSG   = re.compile(r"\bsend_raw_message\s*\([^,]+,\s*(\d+)\s*\)")
_RAW_RESERVE = re.compile(r"\braw_reserve\s*\(")
_THROW_GUARD = re.compile(r"\b(throw_unless|throw_if|require)\s*\(")
_BOUNCE_HANDLER = re.compile(
    r"\brecv_internal\b.*\bbounced\b|\bif\s*\(.*is_bounced\b", re.DOTALL
)
_ACCEPT_MSG = re.compile(r"\baccept_message\s*\(\s*\)")


@dataclass
class CEIViolation:
    """A detected Checks-Effects-Interactions ordering violation."""
    rule_id:         str
    severity:        str
    description:     str
    set_data_line:   int
    send_line:       int
    mode:            int
    evidence:        str
    recommendation:  str
    cwe_id:          str = "CWE-362"


@dataclass
class SendModeRisk:
    """Risk record for a specific send_raw_message call."""
    line:        int
    mode:        int
    severity:    str
    description: str
    cwe_id:      str = "CWE-691"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "line":        self.line,
            "mode":        self.mode,
            "severity":    self.severity,
            "description": self.description,
            "cwe_id":      self.cwe_id,
        }


@dataclass
class PhantomStateResult:
    """Result from trace-based phantom state detection."""
    detected:        bool
    tx_hash:         str
    storage_changed: bool
    action_ok:       bool
    description:     str
    severity:        str = "CRITICAL"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "detected":        self.detected,
            "tx_hash":         self.tx_hash,
            "storage_changed": self.storage_changed,
            "action_ok":       self.action_ok,
            "severity":        self.severity,
            "description":     self.description,
        }


@dataclass
class RollbackAnalysisResult:
    """Aggregated result from rollback/CEI analysis."""
    file:              str
    cei_violations:    List[CEIViolation] = field(default_factory=list)
    send_mode_risks:   List[SendModeRisk] = field(default_factory=list)
    missing_bounce_handler: bool = False
    missing_raw_reserve:    bool = False
    phantom_states:    List[PhantomStateResult] = field(default_factory=list)

    @property
    def risk_level(self) -> str:
        if any(v.severity == "CRITICAL" for v in self.cei_violations):
            return "CRITICAL"
        if any(r.severity == "CRITICAL" for r in self.send_mode_risks):
            return "CRITICAL"
        if any(r.severity == "HIGH" for r in self.send_mode_risks):
            return "HIGH"
        if self.cei_violations or self.missing_bounce_handler:
            return "HIGH"
        return "MEDIUM" if self.send_mode_risks else "LOW"

    def to_findings(self) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for v in self.cei_violations:
            findings.append({
                "rule_id":      v.rule_id,
                "severity":     v.severity,
                "file":         self.file,
                "line":         v.set_data_line,
                "description":  v.description,
                "evidence":     v.evidence,
                "recommendation": v.recommendation,
                "cwe":          v.cwe_id,
                "category":     "State Management",
                "source":       "rollback_analyzer",
            })
        for r in self.send_mode_risks:
            findings.append({
                "rule_id":      f"TON-MODE-{r.mode:03d}",
                "severity":     r.severity,
                "file":         self.file,
                "line":         r.line,
                "description":  r.description,
                "evidence":     f"send_raw_message(msg, {r.mode})",
                "recommendation": _mode_recommendation(r.mode),
                "cwe":          r.cwe_id,
                "category":     "Fund Safety",
                "source":       "rollback_analyzer",
            })
        if self.missing_bounce_handler:
            findings.append({
                "rule_id":      "TON-BOUNCE-MISSING",
                "severity":     "HIGH",
                "file":         self.file,
                "line":         0,
                "description":  "Contract sends bounce=true messages but has no bounced message handler",
                "evidence":     "send_raw_message present; is_bounced handler absent",
                "recommendation": "Add handler for bounced messages to prevent phantom state on failed sends",
                "cwe":          "CWE-754",
                "category":     "Bounce Safety",
                "source":       "rollback_analyzer",
            })
        return findings


def _mode_recommendation(mode: int) -> str:
    if mode & _MODE_CARRY_ALL_BALANCE:
        return "Never use mode 128 without strict ownership check. Prefer mode 0 or 1."
    if mode & _MODE_CARRY_REMAINING_BODY:
        return "Mode 32 destroys the contract after send. Ensure this is intentional."
    if mode & _MODE_CARRY_REMAINING_MSG:
        return "Mode 64 forwards all incoming value. Add raw_reserve to protect contract balance."
    return "Verify send mode matches intended behavior."


class RollbackCEIAnalyzer:
    """
    Detects CEI ordering violations and send mode risks in FunC/Tact source.
    """

    def analyze(self, source: str, file_path: str = "contract.fc") -> RollbackAnalysisResult:
        lines = source.splitlines()
        result = RollbackAnalysisResult(file=file_path)

        result.send_mode_risks = self._check_send_modes(lines)
        result.cei_violations  = self._check_cei_order(source, lines)
        result.missing_bounce_handler = self._check_missing_bounce_handler(source)
        result.missing_raw_reserve = self._check_missing_raw_reserve(source)

        return result

    def check_send_mode_risk(self, mode: int) -> List[Dict[str, Any]]:
        """Backward-compatible API: analyze a single send mode integer."""
        risks: List[Dict[str, Any]] = []
        if mode & _MODE_CARRY_REMAINING_MSG:
            risks.append({
                "severity":    "MEDIUM",
                "description": (
                    "Mode 64 (carry remaining incoming value) can lead to unexpected "
                    "balance drain if msg_value is large."
                ),
                "cwe_id": "CWE-691",
            })
        if mode & _MODE_CARRY_ALL_BALANCE:
            risks.append({
                "severity":    "HIGH",
                "description": (
                    "Mode 128 (carry entire contract balance) empties the contract. "
                    "Catastrophic if reachable without auth check."
                ),
                "cwe_id": "CWE-691",
            })
        if mode & _MODE_CARRY_REMAINING_BODY:
            risks.append({
                "severity":    "HIGH",
                "description": "Mode 32 self-destructs the contract after send.",
                "cwe_id": "CWE-691",
            })
        return risks

    def analyze_rollback_failure(self, trace: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        Backward-compatible API: detect phantom state from a transaction trace.

        In TON, storage is committed in the compute phase BEFORE actions are executed.
        If action phase fails, storage changes are NOT rolled back.
        """
        for tx in trace:
            if tx.get("storage_changed") and not tx.get("action_phase_ok", True):
                return {
                    "type": "ROLLBACK_INCONSISTENCY",
                    "severity": "CRITICAL",
                    "tx_hash": tx.get("hash", "unknown"),
                    "description": (
                        "Storage was modified in compute phase but action phase failed. "
                        "State is now inconsistent — storage committed with no confirmation sent."
                    ),
                }
            # Also flag: action phase ok but status=failed (out-of-gas on actions)
            if tx.get("status") == "failed" and tx.get("storage_changed"):
                return {
                    "type": "ROLLBACK_INCONSISTENCY",
                    "severity": "CRITICAL",
                    "tx_hash": tx.get("hash", "unknown"),
                    "description": (
                        "Transaction failed but storage was already modified. "
                        "This creates a 'phantom' state where storage is updated "
                        "but intended effects (sends) did not occur."
                    ),
                }
        return None

    def analyze_trace_phantom_states(
        self, trace: List[Dict[str, Any]]
    ) -> List[PhantomStateResult]:
        """Detect all phantom state occurrences in a transaction trace."""
        results: List[PhantomStateResult] = []
        for tx in trace:
            storage_changed = bool(tx.get("storage_changed"))
            action_ok = tx.get("action_phase_ok", tx.get("status") != "failed")
            if storage_changed and not action_ok:
                results.append(PhantomStateResult(
                    detected=True,
                    tx_hash=tx.get("hash", tx.get("id", "unknown")),
                    storage_changed=storage_changed,
                    action_ok=action_ok,
                    description=(
                        "Storage committed in compute phase but action phase failed. "
                        "State is permanently inconsistent."
                    ),
                ))
        return results

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _check_send_modes(self, lines: List[str]) -> List[SendModeRisk]:
        risks: List[SendModeRisk] = []
        for lineno, line in enumerate(lines, 1):
            for m in _SEND_MSG.finditer(line):
                try:
                    mode = int(m.group(1))
                except ValueError:
                    continue
                if mode & _MODE_CARRY_ALL_BALANCE:
                    risks.append(SendModeRisk(
                        line=lineno, mode=mode, severity="CRITICAL",
                        description=(
                            f"send_raw_message mode {mode} carries entire contract balance. "
                            "Reachable without auth check = catastrophic fund drain."
                        ),
                        cwe_id="CWE-691",
                    ))
                elif mode & _MODE_CARRY_REMAINING_BODY:
                    risks.append(SendModeRisk(
                        line=lineno, mode=mode, severity="HIGH",
                        description=f"send_raw_message mode {mode} self-destructs contract after send.",
                        cwe_id="CWE-691",
                    ))
                elif mode & _MODE_CARRY_REMAINING_MSG:
                    risks.append(SendModeRisk(
                        line=lineno, mode=mode, severity="MEDIUM",
                        description=(
                            f"send_raw_message mode {mode} forwards remaining incoming value. "
                            "Ensure raw_reserve protects minimum balance."
                        ),
                        cwe_id="CWE-691",
                    ))
        return risks

    def _check_cei_order(self, source: str, lines: List[str]) -> List[CEIViolation]:
        """
        Detect set_data() calls that appear BEFORE send_raw_message() in the same
        function block with no raw_reserve() guard between them.
        """
        violations: List[CEIViolation] = []
        # Find all set_data positions
        set_data_positions: List[int] = []
        for i, line in enumerate(lines, 1):
            if _SET_DATA.search(line) or _SAVE_DATA.search(line):
                set_data_positions.append(i)

        # Find all send_raw_message positions with mode
        send_positions: List[tuple] = []  # (lineno, mode)
        for i, line in enumerate(lines, 1):
            m = _SEND_MSG.search(line)
            if m:
                try:
                    send_positions.append((i, int(m.group(1))))
                except ValueError:
                    send_positions.append((i, 0))

        for sd_line in set_data_positions:
            for send_line, mode in send_positions:
                if sd_line < send_line:
                    # Check if raw_reserve appears between sd_line and send_line
                    window = "\n".join(lines[sd_line - 1:send_line - 1])
                    has_reserve = bool(_RAW_RESERVE.search(window))
                    if not has_reserve:
                        violations.append(CEIViolation(
                            rule_id="TON-CEI-001",
                            severity="HIGH",
                            description=(
                                "Storage written (set_data) before message send with no "
                                "raw_reserve guard. If action phase fails, storage persists "
                                "in inconsistent state (phantom state / CEI violation)."
                            ),
                            set_data_line=sd_line,
                            send_line=send_line,
                            mode=mode,
                            evidence=f"set_data at line {sd_line}, send_raw_message at line {send_line}",
                            recommendation=(
                                "Either: (1) move set_data AFTER send_raw_message, or "
                                "(2) add raw_reserve(min_balance, 2) before send to ensure "
                                "action phase cannot fail due to insufficient balance."
                            ),
                        ))
                    break  # only flag first send per set_data

        return violations

    def _check_missing_bounce_handler(self, source: str) -> bool:
        """
        Returns True if contract sends messages with bounce=true but
        has no handler for bounced incoming messages.
        """
        has_send = bool(_SEND_MSG.search(source))
        # In TON, bounce=true is default for internal messages
        if not has_send:
            return False
        has_bounce_handler = bool(_BOUNCE_HANDLER.search(source))
        return not has_bounce_handler

    def _check_missing_raw_reserve(self, source: str) -> bool:
        """Returns True if mode-64 send exists but no raw_reserve guard."""
        for m in _SEND_MSG.finditer(source):
            try:
                mode = int(m.group(1))
            except ValueError:
                continue
            if mode & _MODE_CARRY_REMAINING_MSG:
                if not _RAW_RESERVE.search(source):
                    return True
        return False


# Backward-compatible alias
class RollbackAnalyzer(RollbackCEIAnalyzer):
    """Legacy class name kept for backward compatibility."""
    pass
