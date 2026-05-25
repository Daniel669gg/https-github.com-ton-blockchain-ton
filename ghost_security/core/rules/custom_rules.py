"""
Ghost Security Platform — Custom Rule Engine

Lets users write Ghost security rules in YAML files and scan source code
against them using regex patterns.

Rule files are searched in (in order):
  ~/.ghost/rules/
  .ghost/rules/          (relative to CWD)
  ghost_rules/
  .ghostrules/

Rule YAML format::

    version: 1
    rules:
      - id: MY-COMPANY-001
        name: "Insecure direct object reference"
        message: "User-supplied ID used directly without authorization check"
        severity: HIGH
        cwe: CWE-639
        languages: [python, javascript]
        tags: [owasp-a01, custom]
        pattern: "request\\.args\\.get\\(['\"]id['\"]\\)"
        fix: "Validate that the current user owns the requested resource"

      - id: MY-COMPANY-002
        name: "Logging PII"
        message: "Potential PII logged"
        severity: MEDIUM
        cwe: CWE-532
        languages: [python]
        pattern: "(?:log(?:ger)?|print).*(?:email|phone|ssn|credit_card)"
        flags: IGNORECASE
"""
from __future__ import annotations

import os
import re
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import yaml  # PyYAML


# ---------------------------------------------------------------------------
# Language extension map
# ---------------------------------------------------------------------------
_EXT_TO_LANG: Dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "javascript",
    ".jsx": "javascript",
    ".tsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".java": "java",
    ".kt": "java",
    ".kts": "java",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".rs": "rust",
    ".c": "cpp",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".h": "cpp",
    ".hpp": "cpp",
    ".hxx": "cpp",
}

# Valid severity levels
_VALID_SEVERITIES = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}

# re flag names → actual flag values
_FLAG_MAP: Dict[str, int] = {
    "IGNORECASE": re.IGNORECASE,
    "I": re.IGNORECASE,
    "MULTILINE": re.MULTILINE,
    "M": re.MULTILINE,
    "DOTALL": re.DOTALL,
    "S": re.DOTALL,
    "VERBOSE": re.VERBOSE,
    "X": re.VERBOSE,
}


# ---------------------------------------------------------------------------
# CustomRule dataclass
# ---------------------------------------------------------------------------
@dataclass
class CustomRule:
    """
    A single compiled custom security rule loaded from a YAML file.

    Attributes:
        id:          Unique rule identifier (e.g. "MY-COMPANY-001").
        name:        Short descriptive name.
        message:     Finding message shown to the user.
        severity:    One of INFO | LOW | MEDIUM | HIGH | CRITICAL.
        cwe:         CWE reference string (e.g. "CWE-639").
        languages:   List of language names this rule applies to, or ["all"].
        pattern:     Compiled regex pattern.
        fix:         Remediation advice.
        tags:        List of tag strings (e.g. ["owasp-a01", "custom"]).
        source_file: Absolute path of the YAML file this rule was loaded from.
    """
    id: str
    name: str
    message: str
    severity: str
    cwe: str
    languages: List[str]
    pattern: re.Pattern
    fix: str
    tags: List[str]
    source_file: str


# ---------------------------------------------------------------------------
# CustomRuleLoader
# ---------------------------------------------------------------------------
class CustomRuleLoader:
    """
    Discovers and loads custom rule YAML files from well-known paths.

    Search order (first to last):
      ~/.ghost/rules/
      .ghost/rules/   (relative to process CWD)
      ghost_rules/
      .ghostrules/

    Additional paths can be supplied via ``extra_paths``.
    """

    SEARCH_PATHS: List[str] = [
        "~/.ghost/rules",
        ".ghost/rules",
        "ghost_rules",
        ".ghostrules",
    ]

    def __init__(self, extra_paths: Optional[List[str]] = None) -> None:
        self._extra_paths: List[str] = extra_paths or []
        self._rules: Optional[List[CustomRule]] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load_all(self) -> List[CustomRule]:
        """
        Load rules from all known search paths plus any extra paths.
        Results are cached after the first call.

        Returns a flat list of all successfully parsed CustomRule objects.
        """
        if self._rules is not None:
            return self._rules

        rules: List[CustomRule] = []
        seen_ids: Dict[str, str] = {}  # id → source_file (de-duplicate)

        all_paths = [*self.SEARCH_PATHS, *self._extra_paths]
        for raw_path in all_paths:
            expanded = Path(raw_path).expanduser()
            if not expanded.is_dir():
                continue
            for yaml_file in sorted(expanded.rglob("*.yml")) + sorted(expanded.rglob("*.yaml")):
                try:
                    file_rules = self.load_file(str(yaml_file))
                except Exception:
                    # Skip malformed rule files gracefully
                    continue
                for rule in file_rules:
                    if rule.id in seen_ids:
                        # Later file takes precedence; log the override silently
                        continue
                    seen_ids[rule.id] = rule.source_file
                    rules.append(rule)

        self._rules = rules
        return rules

    def load_file(self, path: str) -> List[CustomRule]:
        """
        Parse a single YAML rule file and return a list of CustomRule objects.

        Raises:
            FileNotFoundError: if the file does not exist.
            ValueError: if the YAML structure is invalid.
        """
        fpath = Path(path)
        if not fpath.exists():
            raise FileNotFoundError(f"Rule file not found: {path}")

        raw = fpath.read_text(encoding="utf-8")
        data = yaml.safe_load(raw)

        if not isinstance(data, dict):
            raise ValueError(f"Rule file must be a YAML mapping, got {type(data).__name__}: {path}")

        version = data.get("version", 1)
        if version not in (1,):
            raise ValueError(f"Unsupported rule file version {version} in {path}")

        raw_rules = data.get("rules", [])
        if not isinstance(raw_rules, list):
            raise ValueError(f"'rules' must be a list in {path}")

        result: List[CustomRule] = []
        for entry in raw_rules:
            rule = self._parse_rule(entry, str(fpath.resolve()))
            if rule is not None:
                result.append(rule)

        return result

    def rule_count(self) -> int:
        """Return the total number of loaded rules (triggers load_all if needed)."""
        return len(self.load_all())

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_rule(entry: Dict, source_file: str) -> Optional[CustomRule]:
        """
        Parse one rule dict from YAML.  Returns None if the rule is missing
        required fields or has an invalid regex.
        """
        if not isinstance(entry, dict):
            return None

        rule_id = str(entry.get("id") or "").strip()
        name = str(entry.get("name") or "").strip()
        message = str(entry.get("message") or name).strip()
        pattern_str = str(entry.get("pattern") or "").strip()

        if not rule_id or not pattern_str:
            return None  # Required fields missing

        severity = str(entry.get("severity") or "MEDIUM").upper()
        if severity not in _VALID_SEVERITIES:
            severity = "MEDIUM"

        cwe = str(entry.get("cwe") or "").strip()
        fix = str(entry.get("fix") or "").strip()

        # Languages — normalize to lowercase list
        raw_langs = entry.get("languages") or ["all"]
        if isinstance(raw_langs, str):
            raw_langs = [raw_langs]
        languages = [str(lang).strip().lower() for lang in raw_langs if lang]

        # Tags
        raw_tags = entry.get("tags") or []
        if isinstance(raw_tags, str):
            raw_tags = [raw_tags]
        tags = [str(t).strip().lower() for t in raw_tags if t]

        # Compile regex flags
        raw_flags = entry.get("flags") or ""
        flag_bits = 0
        for token in re.split(r"[|,\s]+", str(raw_flags).upper()):
            token = token.strip()
            if token in _FLAG_MAP:
                flag_bits |= _FLAG_MAP[token]

        try:
            compiled = re.compile(pattern_str, flag_bits)
        except re.error as exc:
            # Invalid regex — skip rule with a warning
            import warnings
            warnings.warn(
                f"Custom rule '{rule_id}' has an invalid regex pattern: {exc}",
                stacklevel=2,
            )
            return None

        return CustomRule(
            id=rule_id,
            name=name,
            message=message,
            severity=severity,
            cwe=cwe,
            languages=languages,
            pattern=compiled,
            fix=fix,
            tags=tags,
            source_file=source_file,
        )


# ---------------------------------------------------------------------------
# CustomRuleScanner
# ---------------------------------------------------------------------------
class CustomRuleScanner:
    """
    Scan source files or directories using custom YAML-defined rules.

    Usage::

        scanner = CustomRuleScanner(project_root="/path/to/project")
        result  = scanner.scan_directory(".")
        # or
        findings = scanner.scan_file("app/routes.py")
    """

    def __init__(
        self,
        project_root: str = ".",
        extra_rule_paths: Optional[List[str]] = None,
    ) -> None:
        self.project_root = str(Path(project_root).resolve())
        self._loader = CustomRuleLoader(extra_paths=extra_rule_paths)
        self._rules: Optional[List[CustomRule]] = None

    @property
    def rules(self) -> List[CustomRule]:
        if self._rules is None:
            self._rules = self._loader.load_all()
        return self._rules

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_file(self, file_path: str) -> List[Dict]:
        """
        Scan a single source file against all applicable custom rules.

        Language is auto-detected from the file extension.  Rules whose
        ``languages`` list does not include the detected language (or "all")
        are skipped.

        Returns a list of finding dicts, each containing::

            type, id, severity, cwe, file, line, message, description,
            evidence, recommendation, source, scanner, tags, confidence
        """
        self._ensure_rules()
        lang = self._get_language(file_path)
        rules = self._rules_for_language(lang)

        if not rules:
            return []

        try:
            source = Path(file_path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []

        lines = source.splitlines()
        findings: List[Dict] = []

        for rule in rules:
            for lineno, line in enumerate(lines, start=1):
                if rule.pattern.search(line):
                    findings.append(self._make_finding(rule, file_path, lineno, line))

        return findings

    def scan_directory(self, directory: str, max_files: int = 500) -> Dict:
        """
        Recursively scan a directory for custom rule violations.

        Returns a dict with::

            {
                "files_scanned":   int,
                "total_findings":  int,
                "rules_loaded":    int,
                "findings":        List[Dict],
                "scanner":         "custom_rules",
            }
        """
        self._ensure_rules()
        root = Path(directory).resolve()

        skip_dirs = {
            ".git", "__pycache__", "node_modules", ".venv", "venv",
            "env", ".env", "dist", "build", ".eggs", ".tox",
        }
        supported_exts = set(_EXT_TO_LANG.keys())

        all_findings: List[Dict] = []
        files_scanned = 0

        for fpath in sorted(root.rglob("*")):
            if files_scanned >= max_files:
                break
            if not fpath.is_file():
                continue
            if fpath.suffix not in supported_exts:
                continue
            if any(part in skip_dirs or (part.startswith(".") and part not in (".", ".."))
                   for part in fpath.parts[len(root.parts):]
                   if part not in (".ghost", ".ghostrules")):
                # Allow .ghost directory itself
                skip_part = any(
                    part in skip_dirs for part in fpath.parts[len(root.parts):]
                )
                if skip_part:
                    continue

            file_findings = self.scan_file(str(fpath))
            all_findings.extend(file_findings)
            files_scanned += 1

        return {
            "files_scanned": files_scanned,
            "total_findings": len(all_findings),
            "rules_loaded": len(self._rules or []),
            "findings": all_findings,
            "scanner": "custom_rules",
        }

    # ------------------------------------------------------------------
    # Language detection
    # ------------------------------------------------------------------

    @staticmethod
    def _get_language(file_path: str) -> str:
        """
        Detect source language from file extension.

        .py → python
        .js / .ts / .jsx / .tsx → javascript
        .java / .kt → java
        .go → go
        .rb → ruby
        .php → php
        .cs → csharp
        .rs → rust
        .c / .cpp / .h / .hpp → cpp

        Returns "unknown" for unrecognized extensions.
        """
        ext = Path(file_path).suffix.lower()
        return _EXT_TO_LANG.get(ext, "unknown")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _ensure_rules(self) -> None:
        if self._rules is None:
            self._rules = self._loader.load_all()

    def _rules_for_language(self, lang: str) -> List[CustomRule]:
        """Return rules that apply to the given language."""
        if not self._rules:
            return []
        return [
            r for r in self._rules
            if "all" in r.languages or lang in r.languages
        ]

    @staticmethod
    def _make_finding(
        rule: CustomRule, file_path: str, lineno: int, line: str
    ) -> Dict:
        """Build a finding dict from a matched rule and source line."""
        return {
            "type": "CUSTOM_RULE",
            "id": rule.id,
            "severity": rule.severity,
            "cwe": rule.cwe,
            "file": file_path,
            "line": lineno,
            "message": rule.message,
            "description": rule.name,
            "evidence": line.strip()[:120],
            "recommendation": rule.fix,
            "source": "custom_rules",
            "scanner": "custom",
            "tags": rule.tags,
            "confidence": 70,
        }


# ---------------------------------------------------------------------------
# CLI helper — create example rules file
# ---------------------------------------------------------------------------
def create_example_rules(output_dir: str) -> str:
    """
    Write a well-commented example rules file to ``<output_dir>/.ghost/rules/example.yml``.

    Creates parent directories as needed.  Returns the absolute path of the
    written file.
    """
    rules_dir = Path(output_dir) / ".ghost" / "rules"
    rules_dir.mkdir(parents=True, exist_ok=True)
    out_path = rules_dir / "example.yml"

    # NOTE: patterns use YAML single-quoted scalars so backslashes are literal
    # (no YAML escape processing). This is the recommended way to embed regexes.
    content = textwrap.dedent("""\
        # Ghost Security -- Custom Rules Example
        # Place this file (or any *.yml file) in:
        #   ~/.ghost/rules/          (global)
        #   .ghost/rules/            (per-project)
        #   ghost_rules/             (per-project alternative)
        #
        # Supported languages: python, javascript, java, go, ruby, php, csharp, rust, cpp
        # Use "all" to match every language.
        #
        # Pattern: Python regex applied line-by-line.
        #   Use YAML single-quoted strings for patterns so backslashes are literal.
        # Flags: IGNORECASE, MULTILINE, DOTALL (pipe or space-separated).

        version: 1

        rules:
          - id: MY-COMPANY-001
            name: Insecure direct object reference
            message: User-supplied ID used directly without authorization check
            severity: HIGH
            cwe: CWE-639
            languages: [python, javascript]
            tags: [owasp-a01, custom, idor]
            pattern: 'request\.args\.get\([''"]id[''"]\)'
            fix: Validate that the current user owns the requested resource before returning it.

          - id: MY-COMPANY-002
            name: Logging PII
            message: Potential PII (email/phone/SSN/credit card) in log statement
            severity: MEDIUM
            cwe: CWE-532
            languages: [python]
            tags: [pii, privacy, cwe-532]
            pattern: '(?:log(?:ger)?|print).*(?:email|phone|ssn|credit_card|dob)'
            flags: IGNORECASE
            fix: Remove or redact PII before logging. Use structured logging with field masking.

          - id: MY-COMPANY-003
            name: Hardcoded secret or API key
            message: Possible hardcoded credential or API key detected
            severity: CRITICAL
            cwe: CWE-798
            languages: [all]
            tags: [secrets, credentials, owasp-a02]
            pattern: '(?:api_key|secret_key|password|passwd|auth_token)\s*=\s*[''"][A-Za-z0-9+/]{16,}[''""]'
            flags: IGNORECASE
            fix: Move secrets to environment variables or a secrets manager (Vault, AWS Secrets Manager, etc.).

          - id: MY-COMPANY-004
            name: SQL query built with string concatenation
            message: SQL query constructed via string concatenation -- possible injection
            severity: HIGH
            cwe: CWE-89
            languages: [python, java, javascript]
            tags: [sqli, owasp-a03, injection]
            pattern: '(?:SELECT|INSERT|UPDATE|DELETE).*[+%].*(?:request|user_input|params|body)'
            flags: IGNORECASE
            fix: Use parameterized queries or an ORM. Never concatenate user input into SQL strings.

          - id: MY-COMPANY-005
            name: Disabled SSL/TLS verification
            message: SSL certificate verification is disabled -- vulnerable to MITM attacks
            severity: HIGH
            cwe: CWE-295
            languages: [python, javascript]
            tags: [tls, mitm, owasp-a02]
            pattern: 'verify\s*=\s*False|rejectUnauthorized\s*:\s*false'
            flags: IGNORECASE
            fix: Never disable TLS verification in production. Use a proper CA bundle instead.

          - id: MY-COMPANY-006
            name: Unsafe deserialization with pickle
            message: pickle.loads() / pickle.load() used -- unsafe with untrusted data
            severity: CRITICAL
            cwe: CWE-502
            languages: [python]
            tags: [deserialization, rce, owasp-a08]
            pattern: 'pickle\.(?:loads?|Unpickler)\s*\('
            fix: Replace pickle with a safe serialization format (JSON, msgpack). Never deserialize untrusted pickle data.

          - id: MY-COMPANY-007
            name: Debug mode enabled in production config
            message: DEBUG=True or debug=True found -- ensure this is not a production configuration
            severity: MEDIUM
            cwe: CWE-94
            languages: [python, javascript]
            tags: [debug, misconfiguration]
            pattern: 'DEBUG\s*=\s*True|debug\s*:\s*true'
            flags: IGNORECASE
            fix: Set DEBUG=False in production and use environment-based configuration.
    """)

    out_path.write_text(content, encoding="utf-8")
    return str(out_path.resolve())
