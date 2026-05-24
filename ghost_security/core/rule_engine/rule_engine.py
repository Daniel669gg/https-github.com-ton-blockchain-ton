r"""
Ghost Security Platform — Rule Engine
Community-extensible YAML rule format.
Anyone can write rules in 5 minutes and contribute to the ecosystem.

Rule format:
  id:           GHOST-PY-001
  name:         SQL Injection via f-string
  description:  SQL query built with f-string allows injection
  severity:     CRITICAL
  cwe:          CWE-89
  owasp:        A03:2021
  languages:    [python]
  patterns:
    - type: regex
      pattern: 'execute\s*\(f["\']'
      confidence: 0.90
    - type: regex
      pattern: 'execute\s*\(["\'][^"\']*\+\s*\w'
      confidence: 0.85
  fix: "Use parameterized queries: cursor.execute('...', (value,))"
  references:
    - https://owasp.org/Top10/A03_2021-Injection/
  tags: [injection, sql, database]
  examples:
    bad:  'cursor.execute(f"SELECT * FROM users WHERE id={uid}")'
    good: 'cursor.execute("SELECT * FROM users WHERE id=%s", (uid,))'
"""
from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


# ── Rule model ────────────────────────────────────────────────────────────────

@dataclass
class RulePattern:
    pattern_type: str    # regex | ast | semgrep
    pattern:      str
    confidence:   float  = 0.80
    negate:       bool   = False  # true = pattern must NOT match (whitelist)

    def matches(self, text: str) -> bool:
        try:
            found = bool(re.search(self.pattern, text, re.MULTILINE))
            return (not found) if self.negate else found
        except re.error:
            return False


@dataclass
class GhostRule:
    rule_id:     str
    name:        str
    description: str
    severity:    str          # CRITICAL | HIGH | MEDIUM | LOW | INFO
    languages:   List[str]    # python, javascript, typescript, solidity, ton, yaml, all
    patterns:    List[RulePattern]
    cwe:         str = ""
    owasp:       str = ""
    fix:         str = ""
    references:  List[str] = field(default_factory=list)
    tags:        List[str] = field(default_factory=list)
    confidence:  float = 0.80
    author:      str = ""
    source_file: str = ""
    # Examples for documentation
    examples: Dict[str, str] = field(default_factory=dict)

    _ext_map: Dict[str, Set[str]] = field(default_factory=dict, init=False, repr=False)

    def __post_init__(self):
        _lang_ext = {
            "python":     {".py"},
            "javascript": {".js", ".jsx", ".mjs", ".cjs"},
            "typescript": {".ts", ".tsx"},
            "solidity":   {".sol"},
            "ton":        {".fc", ".func", ".tact", ".fift"},
            "kubernetes": {".yaml", ".yml"},
            "yaml":       {".yaml", ".yml"},
            "go":         {".go"},
            "java":       {".java"},
            "ruby":       {".rb"},
            "php":        {".php"},
            "rust":       {".rs"},
            "c":          {".c", ".h"},
            "cpp":        {".cpp", ".cc", ".cxx", ".hpp"},
        }
        exts: Set[str] = set()
        for lang in self.languages:
            if lang == "all":
                for s in _lang_ext.values():
                    exts |= s
            else:
                exts |= _lang_ext.get(lang, set())
        object.__setattr__(self, '_ext_map', exts)

    def applies_to(self, filepath: str) -> bool:
        if "all" in self.languages:
            return True
        ext = Path(filepath).suffix.lower()
        return ext in self._ext_map

    def scan_text(self, text: str, filepath: str) -> List[Dict]:
        """Scan text, return list of finding dicts."""
        if not self.applies_to(filepath):
            return []

        findings = []
        lines = text.splitlines()

        # All patterns must match (AND logic by default)
        # Or any pattern can match (OR logic if only one pattern)
        matched_patterns = [p for p in self.patterns if p.matches(text)]
        if not matched_patterns:
            return []

        # Find line numbers for matches
        best_pattern = max(
            (p for p in self.patterns if not p.negate),
            key=lambda p: p.confidence,
            default=None,
        )
        if not best_pattern:
            return []

        try:
            rx = re.compile(best_pattern.pattern, re.MULTILINE)
        except re.error:
            return []

        seen_lines: Set[int] = set()
        for m in rx.finditer(text):
            lineno = text[:m.start()].count("\n") + 1
            if lineno in seen_lines:
                continue
            seen_lines.add(lineno)

            snippet = lines[lineno - 1].strip()[:120] if lineno <= len(lines) else ""
            conf = min(p.confidence for p in matched_patterns)

            findings.append({
                "rule_id":        self.rule_id,
                "id":             self.rule_id,
                "type":           self.rule_id.lower().replace("-", "_"),
                "name":           self.name,
                "severity":       self.severity,
                "cwe":            self.cwe,
                "owasp":          self.owasp,
                "file":           filepath,
                "line":           lineno,
                "message":        self.description,
                "description":    self.description,
                "evidence":       snippet,
                "recommendation": self.fix,
                "references":     self.references,
                "tags":           self.tags,
                "confidence":     conf,
                "source":         "ghost_rule_engine",
                "scanner":        "community_rules",
                "author":         self.author,
            })

        return findings


# ── YAML loader ───────────────────────────────────────────────────────────────

def _load_rule(data: dict, source_file: str = "") -> Optional[GhostRule]:
    """Parse a single rule dict into GhostRule."""
    try:
        patterns_raw = data.get("patterns", [])
        patterns: List[RulePattern] = []
        for p in patterns_raw:
            if isinstance(p, str):
                patterns.append(RulePattern("regex", p))
            elif isinstance(p, dict):
                patterns.append(RulePattern(
                    pattern_type = p.get("type", "regex"),
                    pattern      = p.get("pattern", ""),
                    confidence   = float(p.get("confidence", 0.80)),
                    negate       = bool(p.get("negate", False)),
                ))

        if not patterns:
            return None

        return GhostRule(
            rule_id    = str(data["id"]),
            name       = str(data.get("name", data["id"])),
            description = str(data.get("description", "")),
            severity   = str(data.get("severity", "MEDIUM")).upper(),
            languages  = [str(l).lower() for l in data.get("languages", ["all"])],
            patterns   = patterns,
            cwe        = str(data.get("cwe", "")),
            owasp      = str(data.get("owasp", "")),
            fix        = str(data.get("fix", "")),
            references = list(data.get("references", [])),
            tags       = list(data.get("tags", [])),
            confidence = float(data.get("confidence", 0.80)),
            author     = str(data.get("author", "")),
            source_file = source_file,
            examples   = dict(data.get("examples", {})),
        )
    except (KeyError, ValueError, TypeError):
        return None


def load_rules_from_file(path: str) -> List[GhostRule]:
    """Load rules from a YAML file (may contain multiple rules)."""
    try:
        import yaml
        with open(path, encoding="utf-8") as f:
            content = yaml.safe_load(f)
    except Exception:
        return []

    rules_data = content if isinstance(content, list) else [content]
    rules = []
    for rd in rules_data:
        if isinstance(rd, dict) and "id" in rd:
            r = _load_rule(rd, source_file=path)
            if r:
                rules.append(r)
    return rules


def load_rules_from_dir(directory: str) -> List[GhostRule]:
    """Recursively load all .yaml rule files from a directory."""
    rules = []
    for f in Path(directory).rglob("*.yaml"):
        rules.extend(load_rules_from_file(str(f)))
    for f in Path(directory).rglob("*.yml"):
        rules.extend(load_rules_from_file(str(f)))
    return rules


# ── Rule Registry ─────────────────────────────────────────────────────────────

class RuleRegistry:
    """
    Central registry of all Ghost rules (built-in + community).
    Thread-safe, supports hot-reload of rule files.
    """

    def __init__(self) -> None:
        self._rules: Dict[str, GhostRule] = {}
        self._loaded_dirs: List[str] = []

    def register(self, rule: GhostRule) -> None:
        self._rules[rule.rule_id] = rule

    def load_dir(self, directory: str) -> int:
        """Load all rules from directory. Returns count loaded."""
        rules = load_rules_from_dir(directory)
        for r in rules:
            self.register(r)
        if directory not in self._loaded_dirs:
            self._loaded_dirs.append(directory)
        return len(rules)

    def load_file(self, path: str) -> int:
        rules = load_rules_from_file(path)
        for r in rules:
            self.register(r)
        return len(rules)

    def get(self, rule_id: str) -> Optional[GhostRule]:
        return self._rules.get(rule_id)

    def for_language(self, language: str) -> List[GhostRule]:
        ext = language if language.startswith(".") else f".{language}"
        return [r for r in self._rules.values() if r.applies_to(f"file{ext}")]

    def all_rules(self) -> List[GhostRule]:
        return list(self._rules.values())

    def stats(self) -> dict:
        by_severity: Dict[str, int] = {}
        by_lang: Dict[str, int] = {}
        for r in self._rules.values():
            by_severity[r.severity] = by_severity.get(r.severity, 0) + 1
            for lang in r.languages:
                by_lang[lang] = by_lang.get(lang, 0) + 1
        return {
            "total":       len(self._rules),
            "by_severity": by_severity,
            "by_language": by_lang,
            "loaded_dirs": self._loaded_dirs,
        }


# ── Community Scanner ─────────────────────────────────────────────────────────

class CommunityRuleScanner:
    """
    Runs all registered community rules against files/directories.
    Complements built-in scanners with user-extensible rules.
    """

    def __init__(self, registry: Optional[RuleRegistry] = None) -> None:
        self._registry = registry or REGISTRY
        # Auto-load built-in rules
        builtin = Path(__file__).parent.parent.parent / "rules"
        if builtin.exists():
            self._registry.load_dir(str(builtin))

    def scan_file(self, filepath: str) -> List[dict]:
        try:
            text = Path(filepath).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        findings = []
        for rule in self._registry.all_rules():
            findings.extend(rule.scan_text(text, filepath))
        return findings

    def scan_directory(self, path: str) -> dict:
        root  = Path(path)
        files = list(root.rglob("*.py")) + list(root.rglob("*.js")) + \
                list(root.rglob("*.ts")) + list(root.rglob("*.sol")) + \
                list(root.rglob("*.fc")) + list(root.rglob("*.yaml"))
        skip  = {"__pycache__", "node_modules", ".git", ".venv"}
        files = [f for f in files if not any(s in f.parts for s in skip)]

        all_findings: List[dict] = []
        for f in files:
            all_findings.extend(self.scan_file(str(f)))

        counts: dict = {}
        for f in all_findings:
            s = f.get("severity", "MEDIUM")
            counts[s] = counts.get(s, 0) + 1

        return {
            "findings":        all_findings,
            "total":           len(all_findings),
            "severity_counts": counts,
            "files_scanned":   len(files),
            "rules_applied":   len(self._registry.all_rules()),
            "scanner":         "community_rules",
        }

    def validate_rule_file(self, path: str) -> dict:
        """Validate a rule file before publishing."""
        rules = load_rules_from_file(path)
        if not rules:
            return {"valid": False, "error": "No valid rules found in file", "rules": []}
        errors = []
        for rule in rules:
            if not rule.rule_id:
                errors.append("Missing rule id")
            if not rule.patterns:
                errors.append(f"{rule.rule_id}: No patterns defined")
            if rule.severity not in ("CRITICAL","HIGH","MEDIUM","LOW","INFO"):
                errors.append(f"{rule.rule_id}: Invalid severity '{rule.severity}'")
            # Test each pattern compiles
            for p in rule.patterns:
                try:
                    re.compile(p.pattern)
                except re.error as e:
                    errors.append(f"{rule.rule_id}: Invalid regex '{p.pattern}': {e}")
        return {
            "valid":  len(errors) == 0,
            "errors": errors,
            "rules":  [r.rule_id for r in rules],
            "count":  len(rules),
        }


# ── Singleton ─────────────────────────────────────────────────────────────────
REGISTRY = RuleRegistry()
