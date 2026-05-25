"""
Ghost Security Platform — TON Gas Consumption Risk Analyzer
Detects gas-related vulnerabilities in FunC/Tact smart contracts.

Rules:
  GAS-001  HIGH     Unbounded while/repeat loop (no upper-bound check)
  GAS-002  HIGH     accept_message() called after computation (not first in recv_internal)
  GAS-003  MEDIUM   Deep cell chain — .begin_parse() chained 3+ times on one line
  GAS-004  MEDIUM   dict_get / udict_get inside a loop body
  GAS-005  LOW      Recursive function call (function calls itself)
  GAS-006  MEDIUM   accept_message() without a preceding throw_unless guard (DoS griefing)
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# ── Patterns ────────────────────────────────────────────────────────────────────

# Loop keywords
_WHILE_RE    = re.compile(r"\bwhile\s*\(")
_REPEAT_RE   = re.compile(r"\brepeat\s*\(")
# A "bounded" indicator — the loop condition references a `<` comparison with a
# literal integer constant, e.g. `i < 100` or `count < MAX_ITER`
_BOUND_RE    = re.compile(r"<\s*\d+")

# accept_message
_ACCEPT_RE   = re.compile(r"\baccept_message\s*\(\s*\)")

# recv_internal / recv_external function starts
_RECV_INT_RE = re.compile(r"\brecv_internal\s*\(")

# Deep cell parse — count occurrences of .begin_parse( on a single line
_BEGIN_PARSE_RE = re.compile(r"\.begin_parse\s*\(")

# Dict iteration
_DICT_GET_RE = re.compile(r"\b(?:udict_get|dict_get)\s*\??")

# Loop body markers
_LOOP_START_RE = re.compile(r"\b(?:while|repeat)\s*\([^)]*\)\s*\{")

# guard
_GUARD_RE    = re.compile(r"\b(throw_unless|throw_if)\s*\(")

# comment
_COMMENT_RE  = re.compile(r";;.*$")

# Function definition: capture name
_FUNC_DEF_RE = re.compile(
    r"^\s*(?:[\w\s\*]+\s+)?(\w+)\s*\([^)]*\)\s*(?:impure\s*)?(?:inline\s*)?\{"
)


# ── Data classes ────────────────────────────────────────────────────────────────

@dataclass
class GasRisk:
    """Represents a single gas-related vulnerability finding."""
    rule_id:      str
    severity:     str           # HIGH / MEDIUM / LOW
    description:  str
    line:         int
    evidence:     str
    gas_estimate: str           # "unbounded" / "O(n)" / "high" / "moderate"

    def to_dict(self) -> Dict:
        return {
            "type":         "TON_GAS_RISK",
            "id":           self.rule_id,
            "rule_id":      self.rule_id,
            "severity":     self.severity,
            "line":         self.line,
            "description":  self.description,
            "evidence":     self.evidence,
            "gas_estimate": self.gas_estimate,
            "source":       "gas_analyzer",
            "category":     "Gas / DoS",
        }


# ── Helpers ─────────────────────────────────────────────────────────────────────

def _strip_comment(line: str) -> str:
    return _COMMENT_RE.sub("", line)


def _is_comment(line: str) -> bool:
    return line.lstrip().startswith(";;")


def _stripped_lines(lines: List[str]) -> List[Tuple[int, str]]:
    """Return (1-based line number, stripped text) for non-comment lines."""
    result = []
    for i, raw in enumerate(lines, start=1):
        if _is_comment(raw):
            continue
        result.append((i, _strip_comment(raw)))
    return result


# ── Analyzer ─────────────────────────────────────────────────────────────────────

class GasAnalyzer:
    """
    Analyses FunC/Tact contract source for gas consumption vulnerabilities.

    Public API
    ----------
    analyze(file_path)            → Dict
    analyze_code(code, filename)  → Dict
    """

    def analyze(self, file_path: str) -> Dict:
        """Analyse a file on disk."""
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

        risks: List[GasRisk] = []
        risks += self._check_unbounded_loops(lines)
        risks += self._check_late_accept(lines)
        risks += self._check_deep_cell_parse(lines)
        risks += self._check_dict_iteration(lines)
        risks += self._check_recursion(lines)
        risks += self._check_unguarded_accept(lines)

        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        risks.sort(key=lambda r: sev_order.get(r.severity, 9))

        counts: Dict[str, int] = {}
        for r in risks:
            counts[r.severity] = counts.get(r.severity, 0) + 1

        return {
            "file":     filename,
            "findings": [r.to_dict() for r in risks],
            "summary": {
                "total_findings":  len(risks),
                "severity_counts": counts,
            },
        }

    # ── GAS-001: Unbounded loops ───────────────────────────────────────────────

    def _check_unbounded_loops(self, lines: List[str]) -> List[GasRisk]:
        """
        GAS-001: while() or repeat() whose condition/argument contains no
        upper-bound comparison with a literal integer (<N).
        """
        findings: List[GasRisk] = []
        for i, raw in enumerate(lines, start=1):
            if _is_comment(raw):
                continue
            stripped = _strip_comment(raw)

            # Check for while( or repeat(
            is_while  = bool(_WHILE_RE.search(stripped))
            is_repeat = bool(_REPEAT_RE.search(stripped))
            if not (is_while or is_repeat):
                continue

            # Extract the condition / argument up to first matching close-paren
            # We grab a window of a few lines to handle multi-line conditions
            window = stripped
            # Also peek at next 2 lines for multi-line conditions
            for look in range(1, 3):
                if i - 1 + look < len(lines):
                    window += " " + _strip_comment(lines[i - 1 + look])

            # Consider bounded if: the loop condition has `< <integer>` OR
            # the repeat argument is a plain integer literal (repeat(100) {...})
            is_bounded = bool(_BOUND_RE.search(window))
            if not is_bounded and is_repeat:
                # repeat(<integer literal>) is safe
                m = re.search(r"\brepeat\s*\(\s*(\d+)\s*\)", window)
                if m:
                    is_bounded = True

            if not is_bounded:
                keyword = "while" if is_while else "repeat"
                findings.append(GasRisk(
                    rule_id="GAS-001",
                    severity="HIGH",
                    description=(
                        f"`{keyword}` loop with no upper-bound check — user-controlled "
                        "iteration count enables unbounded gas consumption / DoS"
                    ),
                    line=i,
                    evidence=stripped.strip()[:120],
                    gas_estimate="unbounded",
                ))
        return findings

    # ── GAS-002: Late accept_message ──────────────────────────────────────────

    def _check_late_accept(self, lines: List[str]) -> List[GasRisk]:
        """
        GAS-002: accept_message() appears after at least one computation line
        inside a recv_internal / recv_external function.
        A "computation line" is any non-blank, non-comment line that is NOT
        a pure variable declaration or load_* slice read used only to route
        the message (we use a heuristic: any line that calls a function other
        than load_uint/load_int/load_msg_addr/load_coins/load_ref before
        accept_message qualifies).
        """
        findings: List[GasRisk] = []
        text = "\n".join(lines)

        # Find each recv_internal / recv_external block
        for m in re.finditer(r"\brecv_(?:internal|external)\s*\(", text):
            func_start = m.start()
            # Locate the opening brace
            brace_pos = text.find("{", func_start)
            if brace_pos == -1:
                continue

            # Walk forward to find the matching closing brace
            depth, idx = 1, brace_pos + 1
            while idx < len(text) and depth > 0:
                if text[idx] == "{":
                    depth += 1
                elif text[idx] == "}":
                    depth -= 1
                idx += 1
            body = text[brace_pos + 1: idx - 1]

            # Split body into lines and scan
            body_lines = body.splitlines()
            found_computation = False
            accept_line_offset: Optional[int] = None
            recv_lineno = text[:func_start].count("\n") + 1

            # Lines that are "trivial" (not computation): blank, comment,
            # or pure destructuring reads (load_uint, load_msg_addr, etc.)
            _TRIVIAL_RE = re.compile(
                r"^\s*(?:;;|//|$"
                r"|(?:int|slice|cell|builder|var)\s+\w+"  # var decl
                r"|[\w\s]+~load_(?:uint|int|msg_addr|coins|ref|bits)\s*\("
                r"|int\s+\w+\s*=\s*in_msg_body~load"
                r"|slice\s+\w+\s*=.*~load"
                r"|int\s+\w+\s*=\s*\w+~load"
                r")"
            )

            body_start_lineno = text[:brace_pos + 1].count("\n") + 1

            for bl_idx, bl in enumerate(body_lines):
                abs_lineno = body_start_lineno + bl_idx
                bl_stripped = _strip_comment(bl).strip()

                if not bl_stripped:
                    continue
                if _is_comment(bl):
                    continue

                if _ACCEPT_RE.search(bl_stripped):
                    accept_line_offset = abs_lineno
                    if found_computation:
                        findings.append(GasRisk(
                            rule_id="GAS-002",
                            severity="HIGH",
                            description=(
                                "accept_message() called after computation in "
                                "recv_internal/recv_external — allows caller to force "
                                "contract to pay for expensive work"
                            ),
                            line=accept_line_offset,
                            evidence=bl.strip()[:120],
                            gas_estimate="high",
                        ))
                    break  # only one accept per function

                # Check for computation: any function call that isn't a trivial read
                if not _TRIVIAL_RE.match(bl):
                    # If the line has a function call (parenthesis), flag as computation
                    if re.search(r"\w+\s*\(", bl_stripped):
                        found_computation = True

        return findings

    # ── GAS-003: Deep cell chain parse ────────────────────────────────────────

    def _check_deep_cell_parse(self, lines: List[str]) -> List[GasRisk]:
        """
        GAS-003: .begin_parse() appears 3+ times on the same source line,
        indicating a chained cell traversal of depth >= 3.
        """
        findings: List[GasRisk] = []
        for i, raw in enumerate(lines, start=1):
            if _is_comment(raw):
                continue
            stripped = _strip_comment(raw)
            count = len(_BEGIN_PARSE_RE.findall(stripped))
            if count >= 3:
                findings.append(GasRisk(
                    rule_id="GAS-003",
                    severity="MEDIUM",
                    description=(
                        f".begin_parse() chained {count} times in one line — "
                        "deep cell traversal increases gas cost and cell depth limit risk"
                    ),
                    line=i,
                    evidence=stripped.strip()[:120],
                    gas_estimate="O(n)",
                ))
        return findings

    # ── GAS-004: Dict iteration ───────────────────────────────────────────────

    def _check_dict_iteration(self, lines: List[str]) -> List[GasRisk]:
        """
        GAS-004: dict_get or udict_get called inside a while/repeat loop body.
        We detect this by tracking brace depth for loop bodies.

        Strategy: when we see a while/repeat line, record the brace depth
        AFTER that line's braces are processed.  Any subsequent line whose
        brace depth is still >= that saved depth is inside the loop body.
        We pop the saved depth when brace_depth drops below it.
        """
        findings: List[GasRisk] = []
        # Each entry is the brace depth at which the loop body begins
        # (i.e. the depth after the opening '{' of the while/repeat line).
        loop_body_depths: List[int] = []
        brace_depth = 0

        for i, raw in enumerate(lines, start=1):
            if _is_comment(raw):
                continue
            stripped = _strip_comment(raw)

            opens  = stripped.count("{")
            closes = stripped.count("}")

            # Update depth first so we can record the post-open depth
            brace_depth += opens - closes

            # Did we enter a loop on this line?
            if _WHILE_RE.search(stripped) or _REPEAT_RE.search(stripped):
                # The body starts at the current brace_depth (after the '{').
                # We only push if the line actually opened a brace for the body.
                if opens > 0:
                    loop_body_depths.append(brace_depth)
                else:
                    # Multi-line: while (...) \n { — next line will open
                    loop_body_depths.append(brace_depth + 1)

            # Pop any loop depths we have exited
            while loop_body_depths and brace_depth < loop_body_depths[-1]:
                loop_body_depths.pop()

            # Are we inside a loop body right now?
            inside_loop = bool(loop_body_depths) and brace_depth >= loop_body_depths[-1]

            if inside_loop and _DICT_GET_RE.search(stripped):
                findings.append(GasRisk(
                    rule_id="GAS-004",
                    severity="MEDIUM",
                    description=(
                        "dict_get / udict_get called inside a loop body — "
                        "O(n·log n) gas per message; add a size check or limit iterations"
                    ),
                    line=i,
                    evidence=stripped.strip()[:120],
                    gas_estimate="O(n)",
                ))

        return findings

    # ── GAS-005: Recursion ────────────────────────────────────────────────────

    def _check_recursion(self, lines: List[str]) -> List[GasRisk]:
        """
        GAS-005: A function directly calls itself (self-recursion).
        We extract function names from definitions and check their bodies for
        self-calls.
        """
        findings: List[GasRisk] = []
        text = "\n".join(lines)

        # Collect all function definitions: (name, start_char, end_char)
        func_spans: List[Tuple[str, int, int]] = []
        for m in _FUNC_DEF_RE.finditer(text):
            fname = m.group(1)
            # Skip keywords that look like function names
            if fname in ("if", "else", "while", "repeat", "do", "until"):
                continue
            brace_pos = text.find("{", m.start())
            if brace_pos == -1:
                continue
            depth, idx = 1, brace_pos + 1
            while idx < len(text) and depth > 0:
                if text[idx] == "{":
                    depth += 1
                elif text[idx] == "}":
                    depth -= 1
                idx += 1
            func_spans.append((fname, brace_pos + 1, idx - 1))

        for fname, body_start, body_end in func_spans:
            body = text[body_start:body_end]
            # Look for self-call: fname( not preceded by _ (avoids partial matches)
            self_call_re = re.compile(r"(?<!\w)" + re.escape(fname) + r"\s*\(")
            m = self_call_re.search(body)
            if m:
                call_line = text[:body_start + m.start()].count("\n") + 1
                snippet   = body[max(0, m.start() - 10): m.end() + 40].strip()[:120]
                findings.append(GasRisk(
                    rule_id="GAS-005",
                    severity="LOW",
                    description=(
                        f"Function `{fname}` calls itself recursively — "
                        "TVM stack depth is limited; deep recursion will throw exception 5"
                    ),
                    line=call_line,
                    evidence=snippet,
                    gas_estimate="moderate",
                ))
        return findings

    # ── GAS-006: Unguarded accept_message ────────────────────────────────────

    def _check_unguarded_accept(self, lines: List[str]) -> List[GasRisk]:
        """
        GAS-006: accept_message() called without a throw_unless/throw_if in
        the preceding 15 lines (DoS griefing — anyone can drain contract gas).
        """
        LOOKBACK = 15
        findings: List[GasRisk] = []
        guard_lines = set()
        for i, raw in enumerate(lines, start=1):
            if _is_comment(raw):
                continue
            if _GUARD_RE.search(_strip_comment(raw)):
                guard_lines.add(i)

        for i, raw in enumerate(lines, start=1):
            if _is_comment(raw):
                continue
            stripped = _strip_comment(raw)
            if _ACCEPT_RE.search(stripped):
                window_start = max(1, i - LOOKBACK)
                has_guard = any(g in guard_lines for g in range(window_start, i))
                if not has_guard:
                    findings.append(GasRisk(
                        rule_id="GAS-006",
                        severity="MEDIUM",
                        description=(
                            "accept_message() called without a preceding throw_unless/"
                            "throw_if guard — any sender can force this contract to pay "
                            "for message processing (griefing / gas drain)"
                        ),
                        line=i,
                        evidence=stripped.strip()[:120],
                        gas_estimate="high",
                    ))
        return findings

    # ── Utility ───────────────────────────────────────────────────────────────

    @staticmethod
    def _empty_result(filename: str, error: str = "") -> Dict:
        return {
            "file":     filename,
            "findings": [],
            "summary": {
                "total_findings":  0,
                "severity_counts": {},
                "error":           error,
            },
        }
