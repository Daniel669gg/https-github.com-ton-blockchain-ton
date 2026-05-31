"""
TythanAI Platform — TON State Machine Analyzer
Formal state transition validator for FunC/Tact smart contracts.

Detects:
  STM-001  Unguarded set_data() — write without throw_unless/throw_if guard
  STM-002  Multiple set_data() calls in a 20-line window without guard
  STM-003  get_data() read with no validation before function return
  STM-004  Missing seqno increment after state write (replay risk)
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# ── Patterns ───────────────────────────────────────────────────────────────────

_SET_DATA_RE  = re.compile(r"\bset_data\s*\(")
_GET_DATA_RE  = re.compile(r"\bget_data\s*\(\s*\)")
_GUARD_RE     = re.compile(r"\b(throw_unless|throw_if)\s*\(")
_SEQNO_INC_RE = re.compile(r"\bseqno\b.*?\+[+=]|\+[+=]\s*1.*?\bseqno\b|seqno\s*=\s*seqno\s*\+")
_COMMENT_RE   = re.compile(r";;.*$")
_RETURN_RE    = re.compile(r"\breturn\b")
_FUNC_START_RE = re.compile(
    r"^\s*(?:\w[\w\s\*]*\s+)?"           # optional return type
    r"(\w+)\s*\([^)]*\)\s*(?:impure\s*)?(?:inline\s*)?\{"
)


# ── Data classes ───────────────────────────────────────────────────────────────

@dataclass
class StateVar:
    """Represents an inferred persistent state variable access."""
    name: str                       # inferred name / context label
    write_lines: List[int] = field(default_factory=list)
    read_lines:  List[int] = field(default_factory=list)
    guarded:     bool = False       # True if every write is preceded by a guard


@dataclass
class StateTransitionFinding:
    rule_id:        str
    severity:       str
    description:    str
    line:           int
    evidence:       str
    recommendation: str

    def to_dict(self) -> Dict:
        return {
            "type":           "TON_STATE_MACHINE",
            "id":             self.rule_id,
            "rule_id":        self.rule_id,
            "severity":       self.severity,
            "line":           self.line,
            "description":    self.description,
            "evidence":       self.evidence,
            "recommendation": self.recommendation,
            "source":         "state_machine_analyzer",
            "category":       "State Management",
        }


# ── Helpers ────────────────────────────────────────────────────────────────────

def _strip_comment(line: str) -> str:
    """Remove FunC inline comment from a line."""
    return _COMMENT_RE.sub("", line)


def _is_comment_line(line: str) -> bool:
    return line.lstrip().startswith(";;")


# ── Analyzer ───────────────────────────────────────────────────────────────────

class StateMachineAnalyzer:
    """
    Analyses FunC/Tact contract source for state machine vulnerabilities.

    Public API
    ----------
    analyze(file_path)          → Dict
    analyze_code(code, filename) → Dict
    """

    # Window sizes (in lines) for guard lookback / double-write window
    GUARD_LOOKBACK  = 15
    DOUBLE_WIN      = 20

    def analyze(self, file_path: str) -> Dict:
        """Analyse a file on disk.  Returns Ghost-format result dict."""
        path = Path(file_path)
        if not path.exists():
            return self._empty_result(file_path, error="File not found")
        try:
            code = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return self._empty_result(file_path, error=str(exc))
        return self.analyze_code(code, filename=file_path)

    def analyze_code(self, code: str, filename: str = "<code>") -> Dict:
        """Analyse a FunC/Tact snippet supplied as a string."""
        lines = code.splitlines()

        writes = self._find_state_writes(lines)
        guards = self._find_guards(lines)
        reads  = self._find_state_reads(lines)

        findings: List[StateTransitionFinding] = []
        findings += self._check_unguarded_writes(writes, guards, lines)
        findings += self._check_double_write(writes, guards, lines)
        findings += self._check_read_without_validate(reads, guards, lines)
        findings += self._check_missing_seqno_increment(writes, lines)

        # Build StateVar summary
        state_vars = self._build_state_vars(writes, reads, guards)

        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        findings.sort(key=lambda f: severity_order.get(f.severity, 9))

        counts: Dict[str, int] = {}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        return {
            "file":       filename,
            "findings":   [f.to_dict() for f in findings],
            "state_vars": [vars(sv) for sv in state_vars],
            "summary": {
                "total_findings":  len(findings),
                "severity_counts": counts,
                "state_writes":    len(writes),
                "state_reads":     len(reads),
                "guarded_writes":  sum(
                    1 for (ln, _) in writes
                    if any(g <= ln and ln - g <= self.GUARD_LOOKBACK for g in guards)
                ),
            },
        }

    # ── Internal finders ──────────────────────────────────────────────────────

    def _find_state_writes(self, lines: List[str]) -> List[Tuple[int, str]]:
        """Return (1-based line number, stripped line text) for every set_data() call."""
        result = []
        for i, raw in enumerate(lines, start=1):
            if _is_comment_line(raw):
                continue
            stripped = _strip_comment(raw)
            if _SET_DATA_RE.search(stripped):
                result.append((i, stripped.strip()))
        return result

    def _find_guards(self, lines: List[str]) -> List[int]:
        """Return 1-based line numbers of throw_unless / throw_if calls."""
        result = []
        for i, raw in enumerate(lines, start=1):
            if _is_comment_line(raw):
                continue
            stripped = _strip_comment(raw)
            if _GUARD_RE.search(stripped):
                result.append(i)
        return result

    def _find_state_reads(self, lines: List[str]) -> List[Tuple[int, str]]:
        """Return (1-based line, text) for every get_data() call."""
        result = []
        for i, raw in enumerate(lines, start=1):
            if _is_comment_line(raw):
                continue
            stripped = _strip_comment(raw)
            if _GET_DATA_RE.search(stripped):
                result.append((i, stripped.strip()))
        return result

    # ── Checkers ──────────────────────────────────────────────────────────────

    def _check_unguarded_writes(
        self,
        writes: List[Tuple[int, str]],
        guards: List[int],
        lines: List[str],
    ) -> List[StateTransitionFinding]:
        """STM-001: set_data() with no guard within GUARD_LOOKBACK lines above."""
        findings = []
        guard_set = set(guards)
        for (ln, evidence) in writes:
            window_start = max(1, ln - self.GUARD_LOOKBACK)
            has_guard = any(g in guard_set for g in range(window_start, ln))
            if not has_guard:
                findings.append(StateTransitionFinding(
                    rule_id="STM-001",
                    severity="CRITICAL",
                    description=(
                        "set_data() called without a throw_unless/throw_if guard "
                        f"in the preceding {self.GUARD_LOOKBACK} lines — "
                        "any caller can overwrite contract state"
                    ),
                    line=ln,
                    evidence=evidence,
                    recommendation=(
                        "Add throw_unless(<error_code>, equal_slices(sender, owner)) "
                        "before every set_data() call to restrict who may mutate state"
                    ),
                ))
        return findings

    def _check_double_write(
        self,
        writes: List[Tuple[int, str]],
        guards: List[int],
        lines: List[str],
    ) -> List[StateTransitionFinding]:
        """STM-002: two or more set_data() within DOUBLE_WIN lines without a guard between them."""
        findings = []
        guard_set = set(guards)
        n = len(writes)
        for i in range(n):
            for j in range(i + 1, n):
                ln_a = writes[i][0]
                ln_b = writes[j][0]
                if ln_b - ln_a > self.DOUBLE_WIN:
                    break
                # Check for guard strictly between the two writes
                has_guard = any(ln_a < g < ln_b for g in guard_set)
                if not has_guard:
                    findings.append(StateTransitionFinding(
                        rule_id="STM-002",
                        severity="HIGH",
                        description=(
                            f"Multiple set_data() calls at lines {ln_a} and {ln_b} "
                            f"within a {self.DOUBLE_WIN}-line window with no "
                            "intervening guard — partial state write possible on failure"
                        ),
                        line=ln_a,
                        evidence=f"line {ln_a}: {writes[i][1]} | line {ln_b}: {writes[j][1]}",
                        recommendation=(
                            "Consolidate state into a single set_data() call at the end "
                            "of the function, or add a throw_unless guard between the writes"
                        ),
                    ))
                    break  # report once per first write
        return findings

    def _check_read_without_validate(
        self,
        reads: List[Tuple[int, str]],
        guards: List[int],
        lines: List[str],
    ) -> List[StateTransitionFinding]:
        """STM-003: get_data() with no guard between the read and the next return."""
        findings = []
        guard_set = set(guards)
        n_lines = len(lines)

        for (ln, evidence) in reads:
            # Find the next 'return' after this read (within 30 lines)
            return_line: Optional[int] = None
            for k in range(ln, min(ln + 30, n_lines + 1)):
                raw = lines[k - 1]
                if _is_comment_line(raw):
                    continue
                if _RETURN_RE.search(_strip_comment(raw)):
                    return_line = k
                    break

            if return_line is None:
                continue  # no return found nearby — skip

            # Check for a guard between get_data and return
            has_guard = any(ln < g <= return_line for g in guard_set)
            if not has_guard:
                findings.append(StateTransitionFinding(
                    rule_id="STM-003",
                    severity="HIGH",
                    description=(
                        f"get_data() at line {ln} is followed by a return at line "
                        f"{return_line} with no validation — state is read but "
                        "values are never checked before use"
                    ),
                    line=ln,
                    evidence=evidence,
                    recommendation=(
                        "After get_data() decompose the state cell and immediately "
                        "validate critical fields with throw_unless before proceeding"
                    ),
                ))
        return findings

    def _check_missing_seqno_increment(
        self,
        writes: List[Tuple[int, str]],
        lines: List[str],
    ) -> List[StateTransitionFinding]:
        """STM-004: set_data() present but no seqno increment visible in the file."""
        if not writes:
            return []

        full_text = "\n".join(lines)
        # Only relevant when the contract uses seqno at all
        if "seqno" not in full_text:
            return []

        # Check for seqno increment anywhere in the file
        has_increment = bool(_SEQNO_INC_RE.search(full_text))
        if not has_increment:
            # Report on first write line
            ln, evidence = writes[0]
            return [StateTransitionFinding(
                rule_id="STM-004",
                severity="MEDIUM",
                description=(
                    "Contract uses seqno but no seqno increment (seqno += 1 or similar) "
                    "was found near set_data() — replay attack possible if seqno is not saved"
                ),
                line=ln,
                evidence=evidence,
                recommendation=(
                    "Increment seqno before every set_data() call and persist it: "
                    "seqno += 1; set_data(pack_storage(seqno, ...));"
                ),
            )]
        return []

    # ── State var summary ─────────────────────────────────────────────────────

    def _build_state_vars(
        self,
        writes: List[Tuple[int, str]],
        reads:  List[Tuple[int, str]],
        guards: List[int],
    ) -> List[StateVar]:
        """Produce a single aggregate StateVar representing contract persistent storage."""
        if not writes and not reads:
            return []

        guard_set = set(guards)
        all_guarded = all(
            any(g in guard_set for g in range(max(1, ln - self.GUARD_LOOKBACK), ln))
            for (ln, _) in writes
        ) if writes else True

        sv = StateVar(
            name="persistent_storage",
            write_lines=[ln for (ln, _) in writes],
            read_lines=[ln for (ln, _) in reads],
            guarded=all_guarded,
        )
        return [sv]

    # ── Utility ───────────────────────────────────────────────────────────────

    @staticmethod
    def _empty_result(filename: str, error: str = "") -> Dict:
        return {
            "file":       filename,
            "findings":   [],
            "state_vars": [],
            "summary": {
                "total_findings":  0,
                "severity_counts": {},
                "state_writes":    0,
                "state_reads":     0,
                "guarded_writes":  0,
                "error":           error,
            },
        }
