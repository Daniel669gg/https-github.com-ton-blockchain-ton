"""
backend/core/rule_dsl.py — Custom Rule DSL loader and executor for source/sink taint rules.

Enables users to define taint analysis rules in YAML without modifying Python code.
Supports hot-reloading and runtime rule addition.

DSL Format example::

    version: "1.0"
    rules:
      - id: custom-sqli-flask
        name: Flask SQL Injection
        language: python
        severity: CRITICAL
        cwe: [CWE-89]
        owasp: [A03:2021]
        sources:
          - flask.request.args
          - flask.request.form
        sinks:
          - cursor.execute
          - db.execute
        sanitizers:
          - sqlalchemy.text
          - "parameterized"
        message: "SQL injection via user-controlled input"
        confidence: 0.90
        dataflow: true

      - id: custom-weak-hash
        name: Weak Hash Algorithm
        language: python
        severity: HIGH
        cwe: [CWE-327]
        patterns:
          - "hashlib.md5("
          - "hashlib.sha1("
        message: "Weak cryptographic hash function"
        confidence: 0.85
        dataflow: false
"""
from __future__ import annotations

import collections
import logging
import math
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

import yaml

from backend.core.confidence import Finding

logger = logging.getLogger("tythanai.rule_dsl")

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class DSLSource:
    """A taint source pattern, e.g. 'flask.request.args' or 'os.environ.get'."""

    pattern: str  # e.g. "flask.request.args"
    is_method: bool = False


@dataclass
class DSLSink:
    """A taint sink pattern, e.g. 'cursor.execute' or 'os.system'."""

    pattern: str  # e.g. "cursor.execute"
    is_method: bool = False


@dataclass
class DSLRule:
    """A fully parsed DSL rule."""

    rule_id: str
    name: str
    language: str  # "python" | "javascript" | "go" | "any"
    severity: str
    message: str
    confidence: float
    cwe: List[str] = field(default_factory=list)
    owasp: List[str] = field(default_factory=list)
    sources: List[DSLSource] = field(default_factory=list)
    sinks: List[DSLSink] = field(default_factory=list)
    sanitizers: List[str] = field(default_factory=list)
    patterns: List[str] = field(default_factory=list)  # simple pattern match
    dataflow: bool = False  # use dataflow engine


@dataclass
class DSLLoadResult:
    """Result of loading one or more rule files."""

    rules: List[DSLRule]
    errors: List[str]
    files_loaded: int
    rules_count: int


# ---------------------------------------------------------------------------
# Validation constants
# ---------------------------------------------------------------------------

_VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
_VALID_LANGUAGES = {"python", "javascript", "js", "typescript", "ts", "go", "any"}

# Extension → language tag mapping (for execute_all)
_EXT_LANGUAGE: Dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".go": "go",
}


# ---------------------------------------------------------------------------
# Internal regex builder helpers
# ---------------------------------------------------------------------------

_IDENT_SEP_RE = re.compile(r"[.\s]+")


def _pattern_to_regex(pattern: str) -> re.Pattern[str]:
    """
    Convert a DSL source/sink pattern string into a compiled regex.

    "flask.request.args" matches:
      - request.args
      - request.args.get(
      - request.args["key"]
      - request.args.get("key")

    "cursor.execute" matches:
      - cursor.execute(
      - db.execute(
      - conn.execute(   (last component only for short patterns)
    """
    parts = [p for p in _IDENT_SEP_RE.split(pattern) if p]
    if not parts:
        return re.compile(re.escape(pattern))

    # Use the last two meaningful parts as the match target (e.g. "request.args")
    # to avoid being too strict about the object name.
    if len(parts) >= 2:
        tail = re.escape(parts[-2]) + r"\." + re.escape(parts[-1])
    else:
        tail = re.escape(parts[-1])

    # Allow any trailing access: .get(, ["key"], (
    suffix = r"""(?:[.([\s]|$)"""
    return re.compile(tail + suffix)


def _sink_pattern_to_regex(pattern: str, tainted_vars: Set[str]) -> re.Pattern[str]:
    """
    Build a regex that matches a sink call where at least one tainted variable
    appears as an argument.

    For example, sink="cursor.execute" and tainted_vars={"query"} produces a
    regex that matches lines like:   cursor.execute(query
    """
    parts = [p for p in _IDENT_SEP_RE.split(pattern) if p]
    if not parts:
        return re.compile(r"(?!)")  # never matches

    if len(parts) >= 2:
        sink_re = re.escape(parts[-2]) + r"\." + re.escape(parts[-1]) + r"\s*\("
    else:
        sink_re = re.escape(parts[-1]) + r"\s*\("

    if not tainted_vars:
        return re.compile(sink_re)

    var_alts = "|".join(re.escape(v) for v in sorted(tainted_vars))
    # Sink call that references any tainted var somewhere on the same line
    return re.compile(r"(?=.*\b(?:" + var_alts + r")\b)" + sink_re)


# ---------------------------------------------------------------------------
# RuleDSL
# ---------------------------------------------------------------------------


class RuleDSL:
    """
    Custom Rule DSL loader and executor for source/sink taint rules.

    Enables users to define taint analysis rules in YAML without modifying
    Python code.  Supports hot-reloading and runtime rule addition.
    """

    def __init__(self) -> None:
        self._rules: List[DSLRule] = []
        self._rule_index: Dict[str, DSLRule] = {}
        self._watchers: List[Callable[[], None]] = []

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_yaml_text(text: str) -> str:
        """Fix YAML that has top-level '- id:' items outside the rules: block.

        Handles YAML files produced by concatenating two rule YAML snippets where
        the second snippet's list items appear at column-0 instead of being
        indented under 'rules:'.  Adds 2 spaces to every line of each such block.
        """
        import re
        # Only apply if text has a top-level 'rules:' key AND bare '- ' at col 0
        if not re.search(r'^rules:', text, re.MULTILINE):
            return text
        if not re.search(r'^- ', text, re.MULTILINE):
            return text

        lines = text.splitlines(keepends=True)

        # Find line indices where a new top-level list block starts (col-0 '- ')
        # after the 'rules:' header line.
        rules_line_idx = -1
        for i, ln in enumerate(lines):
            if re.match(r'^rules:', ln.rstrip()):
                rules_line_idx = i
                break

        if rules_line_idx < 0:
            return text

        # Identify contiguous blocks of lines that form top-level list items
        # (col-0 '- ') appearing AFTER the rules header.  Each such block starts
        # at a '- ' line and continues until the next col-0 non-space line or EOF.
        # We record (start, end) inclusive line index pairs to re-indent.
        blocks_to_indent: list = []  # list of (start_idx, end_idx)
        i = rules_line_idx + 1
        while i < len(lines):
            ln = lines[i]
            s = ln.rstrip('\n\r')
            if re.match(r'^- ', s):
                # Start of a block at col-0 after rules header
                block_start = i
                j = i + 1
                while j < len(lines):
                    nxt = lines[j].rstrip('\n\r')
                    # Block ends when we hit another col-0 '- ' item or a
                    # col-0 mapping key (word: value) or blank line followed by
                    # a col-0 mapping key.
                    if re.match(r'^- ', nxt):
                        break
                    if re.match(r'^\w', nxt) and ':' in nxt:
                        break
                    j += 1
                blocks_to_indent.append((block_start, j - 1))
                i = j
            else:
                i += 1

        if not blocks_to_indent:
            return text

        result: list = list(lines)
        # Re-indent each identified block: add 2 spaces to every line
        for start, end in blocks_to_indent:
            for k in range(start, end + 1):
                result[k] = '  ' + result[k]

        return ''.join(result)

    def load_file(self, path: str) -> DSLLoadResult:
        """Load DSL rules from a YAML file. Returns a DSLLoadResult (non-fatal errors)."""
        errors: List[str] = []
        loaded_rules: List[DSLRule] = []

        try:
            text = Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return DSLLoadResult(
                rules=[],
                errors=[f"Cannot read {path}: {exc}"],
                files_loaded=0,
                rules_count=0,
            )

        # Attempt 1: parse as-is
        data = None
        parse_error: Optional[str] = None
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            parse_error = str(exc)

        # Attempt 2: normalize and retry if the first parse failed
        if data is None:
            normalized = self._normalize_yaml_text(text)
            if normalized != text:
                try:
                    data = yaml.safe_load(normalized)
                    parse_error = None
                except yaml.YAMLError:
                    pass

        if data is None:
            return DSLLoadResult(
                rules=[],
                errors=[f"YAML parse error in {path}: {parse_error}"],
                files_loaded=0,
                rules_count=0,
            )

        if not isinstance(data, dict):
            return DSLLoadResult(
                rules=[],
                errors=[f"Expected a YAML mapping at top level in {path}"],
                files_loaded=0,
                rules_count=0,
            )

        raw_rules = data.get("rules", [])
        if not isinstance(raw_rules, list):
            return DSLLoadResult(
                rules=[],
                errors=[f"'rules' must be a list in {path}"],
                files_loaded=0,
                rules_count=0,
            )

        for idx, raw in enumerate(raw_rules):
            if not isinstance(raw, dict):
                errors.append(f"{path}[{idx}]: rule must be a mapping, skipping")
                continue
            rule, err = self._parse_rule(raw, path, idx)
            if err:
                errors.append(err)
                continue
            if rule is not None:
                loaded_rules.append(rule)
                self._add_rule_internal(rule)

        return DSLLoadResult(
            rules=loaded_rules,
            errors=errors,
            files_loaded=1,
            rules_count=len(loaded_rules),
        )

    def load_directory(self, directory: str, recursive: bool = False) -> DSLLoadResult:
        """Load all .yaml and .yml files in a directory."""
        root = Path(directory)
        if not root.is_dir():
            return DSLLoadResult(
                rules=[],
                errors=[f"Not a directory: {directory}"],
                files_loaded=0,
                rules_count=0,
            )

        pattern = "**/*.yaml" if recursive else "*.yaml"
        yml_pattern = "**/*.yml" if recursive else "*.yml"

        yaml_files = list(root.glob(pattern)) + list(root.glob(yml_pattern))
        yaml_files = sorted(set(yaml_files))

        all_rules: List[DSLRule] = []
        all_errors: List[str] = []
        total_files = 0

        for yf in yaml_files:
            result = self.load_file(str(yf))
            all_rules.extend(result.rules)
            all_errors.extend(result.errors)
            total_files += result.files_loaded

        return DSLLoadResult(
            rules=all_rules,
            errors=all_errors,
            files_loaded=total_files,
            rules_count=len(all_rules),
        )

    def reload(self, path: str) -> DSLLoadResult:
        """Hot-reload rules from file without restarting. Notifies watchers."""
        # Remove all rules that originated from this path prefix
        # (we track by rule_id; reload replaces existing IDs)
        result = self.load_file(path)
        for callback in self._watchers:
            try:
                callback()
            except Exception as exc:  # noqa: BLE001
                logger.warning("Rule reload watcher raised: %s", exc)
        return result

    # ------------------------------------------------------------------
    # Rule management
    # ------------------------------------------------------------------

    def add_rule(self, rule: DSLRule) -> None:
        """Add a rule programmatically (replaces existing rule with same ID)."""
        self._add_rule_internal(rule)

    def get_rules_for_language(self, language: str) -> List[DSLRule]:
        """Return all rules applicable to *language* (includes 'any' rules)."""
        lang = language.lower()
        return [
            r for r in self._rules
            if r.language.lower() in (lang, "any")
        ]

    def on_reload(self, callback: Callable[[], None]) -> None:
        """Register a callback that is called when rules are hot-reloaded."""
        self._watchers.append(callback)

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def execute_rule(self, rule: DSLRule, file_path: str, source_code: str) -> List[Finding]:
        """Execute a single DSL rule against source_code.

        If rule.dataflow is True and sources + sinks are defined:
          - Find source occurrences and collect tainted variable names.
          - Propagate taint through simple assignment chains.
          - Find sink calls that receive tainted variables.
          - Skip findings where a sanitizer is present between source and sink.

        If rule.dataflow is False or only patterns are defined:
          - Pattern-match each rule.patterns string in source_code.
        """
        findings: List[Finding] = []

        if rule.dataflow and rule.sources and rule.sinks:
            findings.extend(self._execute_dataflow_rule(rule, file_path, source_code))
        elif rule.patterns:
            findings.extend(self._execute_pattern_rule(rule, file_path, source_code))
        else:
            # Dataflow rule with sources+sinks even if dataflow flag not set
            if rule.sources and rule.sinks:
                findings.extend(self._execute_dataflow_rule(rule, file_path, source_code))

        return findings

    def execute_all(self, file_path: str, source_code: str) -> List[Finding]:
        """Execute all loaded rules applicable to file_path's language."""
        suffix = Path(file_path).suffix.lower()
        language = _EXT_LANGUAGE.get(suffix, "any")
        applicable = self.get_rules_for_language(language)

        findings: List[Finding] = []
        for rule in applicable:
            try:
                findings.extend(self.execute_rule(rule, file_path, source_code))
            except Exception as exc:  # noqa: BLE001
                logger.warning("Rule %s raised during execution: %s", rule.rule_id, exc)
        return findings

    # ------------------------------------------------------------------
    # Internal execution helpers
    # ------------------------------------------------------------------

    def _execute_pattern_rule(
        self, rule: DSLRule, file_path: str, source_code: str
    ) -> List[Finding]:
        """Simple substring / regex pattern matching."""
        findings: List[Finding] = []
        lines = source_code.splitlines()

        for pat in rule.patterns:
            try:
                regex = re.compile(re.escape(pat))
            except re.error:
                regex = re.compile(pat)

            for lineno, line in enumerate(lines, start=1):
                if regex.search(line):
                    findings.append(
                        Finding(
                            rule_id=rule.rule_id,
                            file=file_path,
                            line=lineno,
                            severity=rule.severity,
                            confidence=rule.confidence,
                            cwe_id=", ".join(rule.cwe),
                            description=rule.message,
                            recommendation=(
                                "Review this usage and replace with a safer alternative."
                            ),
                            sources=["pattern_match"],
                            context_lines=[line.rstrip()],
                        )
                    )
        return findings

    def _execute_dataflow_rule(
        self, rule: DSLRule, file_path: str, source_code: str
    ) -> List[Finding]:
        """Source→sink dataflow analysis using simple taint propagation."""
        findings: List[Finding] = []
        lines = source_code.splitlines()

        # Step 1: find all source occurrences
        source_hits: List[Tuple[int, str]] = []
        for src in rule.sources:
            hits = self._match_source(src, source_code)
            source_hits.extend(hits)

        if not source_hits:
            return []

        # Step 2: collect tainted variable names from source lines
        source_line_nos = [h[0] for h in source_hits]
        tainted_vars = self._track_taint_simple(source_code, source_line_nos)

        if not tainted_vars:
            return []

        # Step 3: find sink violations
        for sink in rule.sinks:
            sink_hits = self._match_sink(sink, source_code, tainted_vars)
            for sink_lineno, matched_text in sink_hits:
                # Check for sanitizers between the earliest source and this sink
                earliest_source = min(source_line_nos)
                code_slice = "\n".join(lines[earliest_source - 1 : sink_lineno])
                if self._is_sanitized(code_slice, rule.sanitizers):
                    continue

                ctx_start = max(0, sink_lineno - 2)
                ctx_end = min(len(lines), sink_lineno + 1)
                context = lines[ctx_start:ctx_end]

                findings.append(
                    Finding(
                        rule_id=rule.rule_id,
                        file=file_path,
                        line=sink_lineno,
                        severity=rule.severity,
                        confidence=rule.confidence,
                        cwe_id=", ".join(rule.cwe),
                        description=rule.message,
                        recommendation=(
                            "Validate and sanitize all user-supplied data before "
                            "passing it to sensitive operations."
                        ),
                        sources=[s.pattern for s in rule.sources],
                        context_lines=context,
                    )
                )

        return findings

    # ------------------------------------------------------------------
    # Matching helpers
    # ------------------------------------------------------------------

    def _match_source(self, source: DSLSource, code: str) -> List[Tuple[int, str]]:
        """Find all source occurrences in code.

        Returns list of (line_number, matched_text).
        """
        regex = _pattern_to_regex(source.pattern)
        results: List[Tuple[int, str]] = []
        for lineno, line in enumerate(code.splitlines(), start=1):
            m = regex.search(line)
            if m:
                results.append((lineno, line.strip()))
        return results

    def _match_sink(
        self, sink: DSLSink, code: str, tainted_vars: Set[str]
    ) -> List[Tuple[int, str]]:
        """Find sink calls that use tainted variables.

        Returns list of (line_number, matched_text).
        """
        sink_regex = _pattern_to_regex(sink.pattern)
        results: List[Tuple[int, str]] = []

        for lineno, line in enumerate(code.splitlines(), start=1):
            # The sink function must appear on the line
            if not sink_regex.search(line):
                continue
            # At least one tainted variable must appear on the line
            for var in tainted_vars:
                if re.search(r"\b" + re.escape(var) + r"\b", line):
                    results.append((lineno, line.strip()))
                    break

        return results

    def _is_sanitized(self, code_slice: str, sanitizers: List[str]) -> bool:
        """Return True if any sanitizer appears within code_slice."""
        for san in sanitizers:
            if san in code_slice:
                return True
        return False

    def _track_taint_simple(self, code: str, source_lines: List[int]) -> Set[str]:
        """Simple taint propagation via assignment chains (no AST needed).

        Algorithm:
        1. Find variable names assigned on source lines.
        2. For each subsequent assignment `var = expr`, if any tainted name
           appears in expr → mark var as tainted.
        3. Iterate until fixed-point (no new tainted vars).
        4. Return all tainted variable names.
        """
        lines = code.splitlines()
        tainted: Set[str] = set()

        # Regex for simple assignment: varname = ...
        assign_re = re.compile(r"^\s*([A-Za-z_]\w*)\s*=\s*(.+)$")
        # Attribute assignment: self.x = ...  → track just the var name
        attr_assign_re = re.compile(r"^\s*\w+\.\s*([A-Za-z_]\w*)\s*=\s*(.+)$")

        # Step 1: collect variables assigned on source lines
        for lineno in source_lines:
            if 1 <= lineno <= len(lines):
                line = lines[lineno - 1]
                m = assign_re.match(line)
                if m:
                    tainted.add(m.group(1))
                # Also handle: something.attr = source (track attr)
                m2 = attr_assign_re.match(line)
                if m2:
                    tainted.add(m2.group(1))

        if not tainted:
            # Fallback: extract any identifiers from source lines
            for lineno in source_lines:
                if 1 <= lineno <= len(lines):
                    line = lines[lineno - 1]
                    # Look for assignment target before '='
                    m = assign_re.match(line)
                    if m:
                        tainted.add(m.group(1))

        # Step 2: propagate (fixed-point iteration)
        changed = True
        while changed:
            changed = False
            for line in lines:
                m = assign_re.match(line)
                if not m:
                    continue
                lhs, rhs = m.group(1), m.group(2)
                if lhs in tainted:
                    continue  # already tainted
                # Check if any tainted var appears in rhs
                for tv in tainted:
                    if re.search(r"\b" + re.escape(tv) + r"\b", rhs):
                        tainted.add(lhs)
                        changed = True
                        break

        return tainted

    # ------------------------------------------------------------------
    # Private rule parsing
    # ------------------------------------------------------------------

    def _parse_rule(
        self, raw: Dict[str, Any], path: str, idx: int
    ) -> Tuple[Optional[DSLRule], Optional[str]]:
        """Parse a raw dict into a DSLRule. Returns (rule, error_str)."""

        def err(msg: str) -> Tuple[None, str]:
            return None, f"{path}[{idx}] ({raw.get('id', '?')}): {msg}"

        rule_id = raw.get("id")
        if not rule_id or not isinstance(rule_id, str):
            return err("'id' is required and must be a string")

        name = str(raw.get("name", rule_id))
        language = str(raw.get("language", "any")).lower()
        severity = str(raw.get("severity", "MEDIUM")).upper()
        if severity not in _VALID_SEVERITIES:
            severity = "MEDIUM"

        message = str(raw.get("message", f"Rule {rule_id} matched"))
        confidence = float(raw.get("confidence", 0.80))
        confidence = max(0.0, min(1.0, confidence))
        dataflow = bool(raw.get("dataflow", False))

        # CWE / OWASP — accept string or list
        cwe_raw = raw.get("cwe", [])
        cwe = [str(c) for c in (cwe_raw if isinstance(cwe_raw, list) else [cwe_raw])]

        owasp_raw = raw.get("owasp", [])
        owasp = [str(o) for o in (owasp_raw if isinstance(owasp_raw, list) else [owasp_raw])]

        # Sources
        sources: List[DSLSource] = []
        for s in raw.get("sources", []):
            if isinstance(s, str):
                sources.append(DSLSource(pattern=s))
            elif isinstance(s, dict):
                sources.append(
                    DSLSource(
                        pattern=str(s.get("pattern", "")),
                        is_method=bool(s.get("is_method", False)),
                    )
                )

        # Sinks
        sinks: List[DSLSink] = []
        for s in raw.get("sinks", []):
            if isinstance(s, str):
                sinks.append(DSLSink(pattern=s))
            elif isinstance(s, dict):
                sinks.append(
                    DSLSink(
                        pattern=str(s.get("pattern", "")),
                        is_method=bool(s.get("is_method", False)),
                    )
                )

        # Sanitizers
        sanitizers = [str(s) for s in raw.get("sanitizers", [])]

        # Patterns (simple string matching)
        patterns = [str(p) for p in raw.get("patterns", [])]

        rule = DSLRule(
            rule_id=rule_id,
            name=name,
            language=language,
            severity=severity,
            message=message,
            confidence=confidence,
            cwe=cwe,
            owasp=owasp,
            sources=sources,
            sinks=sinks,
            sanitizers=sanitizers,
            patterns=patterns,
            dataflow=dataflow,
        )
        return rule, None

    def _add_rule_internal(self, rule: DSLRule) -> None:
        """Add or replace a rule in internal storage."""
        if rule.rule_id in self._rule_index:
            # Replace existing rule
            old = self._rule_index[rule.rule_id]
            self._rules = [r for r in self._rules if r.rule_id != rule.rule_id]
        self._rules.append(rule)
        self._rule_index[rule.rule_id] = rule


# ---------------------------------------------------------------------------
# Module-level singleton and convenience functions
# ---------------------------------------------------------------------------

_default_dsl = RuleDSL()


def load_dsl_rules(path: str) -> DSLLoadResult:
    """Load DSL rules into the default singleton from a YAML file."""
    return _default_dsl.load_file(path)


def execute_dsl_rules(file_path: str, source_code: str) -> List[Finding]:
    """Execute all loaded DSL rules against source_code using the default singleton."""
    return _default_dsl.execute_all(file_path, source_code)
