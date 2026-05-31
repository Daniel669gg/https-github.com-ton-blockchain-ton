"""
tests/test_rule_dsl.py — Tests for the Rule DSL (backend/core/rule_dsl.py).

12 tests covering:
  - test_load_valid_yaml
  - test_load_invalid_yaml
  - test_execute_pattern_rule
  - test_execute_dataflow_rule_detects_sqli
  - test_execute_dataflow_rule_sanitized
  - test_reload_rules
  - test_get_rules_for_language
  - test_multiple_files_loaded
  - test_add_rule_programmatic
  - test_source_matching
  - test_sink_matching
  - test_taint_tracking_chain
"""
from __future__ import annotations

import sys
import pathlib
import tempfile
import textwrap

_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import pytest

from backend.core.rule_dsl import (
    DSLRule,
    DSLSource,
    DSLSink,
    RuleDSL,
    DSLLoadResult,
    load_dsl_rules,
    execute_dsl_rules,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SQLI_YAML = textwrap.dedent("""\
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
          - flask.request.json
        sinks:
          - sqlalchemy.execute
          - cursor.execute
          - db.execute
        sanitizers:
          - sqlalchemy.text
          - "parameterized"
        message: "SQL injection via user-controlled input from Flask request"
        confidence: 0.90
        dataflow: true
""")

_WEAK_HASH_YAML = textwrap.dedent("""\
    version: "1.0"
    rules:
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
""")

_CMDI_YAML = textwrap.dedent("""\
    version: "1.0"
    rules:
      - id: custom-cmdi
        name: Command Injection
        language: python
        severity: CRITICAL
        cwe: [CWE-78]
        sources:
          - flask.request.args
          - os.environ.get
        sinks:
          - subprocess.run
          - os.system
        sanitizers:
          - shlex.quote
        message: "Command injection via unvalidated input"
        confidence: 0.92
        dataflow: true
""")

_JS_RULE_YAML = textwrap.dedent("""\
    version: "1.0"
    rules:
      - id: js-sqli
        name: JS SQL Injection
        language: javascript
        severity: HIGH
        cwe: [CWE-89]
        sources:
          - req.body
          - req.query
        sinks:
          - db.query
          - pool.query
        message: "SQL injection in JS"
        confidence: 0.85
        dataflow: true
""")

_INVALID_YAML = "this: is: not: valid: yaml: [\n"
_EMPTY_RULES_YAML = "version: '1.0'\nrules: []\n"


def _write_yaml(content: str, directory: str = None) -> str:
    kw = {"dir": directory} if directory else {}
    f = tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False, encoding="utf-8", **kw
    )
    f.write(content)
    f.flush()
    f.close()
    return f.name


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestLoadValidYaml:
    def test_load_valid_yaml(self):
        """Loading a valid YAML file should produce the correct rules."""
        dsl = RuleDSL()
        path = _write_yaml(_SQLI_YAML)
        result = dsl.load_file(path)

        assert result.files_loaded == 1
        assert result.rules_count == 1
        assert len(result.errors) == 0
        assert result.rules[0].rule_id == "custom-sqli-flask"
        assert result.rules[0].severity == "CRITICAL"
        assert result.rules[0].confidence == pytest.approx(0.90)
        assert result.rules[0].dataflow is True
        assert "CWE-89" in result.rules[0].cwe
        assert any(s.pattern == "flask.request.args" for s in result.rules[0].sources)
        assert any(s.pattern == "cursor.execute" for s in result.rules[0].sinks)


class TestLoadInvalidYaml:
    def test_load_invalid_yaml(self):
        """Loading invalid YAML should return errors without crashing."""
        dsl = RuleDSL()
        path = _write_yaml(_INVALID_YAML)
        result = dsl.load_file(path)

        assert result.files_loaded == 0
        assert len(result.errors) > 0
        assert result.rules_count == 0

    def test_load_nonexistent_file(self):
        """Loading a non-existent file should return errors."""
        dsl = RuleDSL()
        result = dsl.load_file("/nonexistent/path/rules.yaml")

        assert result.files_loaded == 0
        assert len(result.errors) > 0


class TestExecutePatternRule:
    def test_execute_pattern_rule(self):
        """Pattern-only rule should match the pattern in source code."""
        dsl = RuleDSL()
        path = _write_yaml(_WEAK_HASH_YAML)
        dsl.load_file(path)

        code = textwrap.dedent("""\
            import hashlib
            digest = hashlib.md5(data).hexdigest()
        """)
        findings = dsl.execute_all("/tmp/test_app.py", code)

        assert len(findings) > 0
        assert findings[0].rule_id == "custom-weak-hash"
        assert findings[0].severity == "HIGH"
        assert findings[0].confidence == pytest.approx(0.85)

    def test_pattern_rule_no_match(self):
        """Pattern rule should not match when pattern is absent."""
        dsl = RuleDSL()
        path = _write_yaml(_WEAK_HASH_YAML)
        dsl.load_file(path)

        code = "import hashlib\ndigest = hashlib.sha256(data).hexdigest()\n"
        findings = dsl.execute_all("/tmp/test_app.py", code)
        rule_ids = [f.rule_id for f in findings]
        assert "custom-weak-hash" not in rule_ids


class TestExecuteDataflowRule:
    def test_execute_dataflow_rule_detects_sqli(self):
        """Source+sink dataflow rule should detect SQL injection."""
        dsl = RuleDSL()
        path = _write_yaml(_SQLI_YAML)
        dsl.load_file(path)

        code = textwrap.dedent("""\
            from flask import request
            import sqlite3

            def handler(db):
                user_id = request.args.get("id")
                query = "SELECT * FROM users WHERE id = " + user_id
                cursor = db.cursor()
                cursor.execute(query)
        """)
        findings = dsl.execute_all("/tmp/app.py", code)

        sqli_findings = [f for f in findings if f.rule_id == "custom-sqli-flask"]
        assert len(sqli_findings) > 0, f"Expected SQLi finding, got: {[f.rule_id for f in findings]}"
        assert sqli_findings[0].severity == "CRITICAL"

    def test_execute_dataflow_rule_sanitized(self):
        """Sanitizer present between source and sink should suppress finding."""
        dsl = RuleDSL()
        path = _write_yaml(_SQLI_YAML)
        dsl.load_file(path)

        code = textwrap.dedent("""\
            from flask import request
            from sqlalchemy import text
            import sqlite3

            def handler(db):
                user_id = request.args.get("id")
                # Using parameterized query — safe
                cursor = db.cursor()
                cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
                # Also test explicit sanitizer
                safe_query = sqlalchemy.text("SELECT * FROM users WHERE id = :id")
                cursor.execute(safe_query)
        """)
        findings = dsl.execute_all("/tmp/app.py", code)
        sqli_findings = [f for f in findings if f.rule_id == "custom-sqli-flask"]
        # The explicit sanitizer 'sqlalchemy.text' should suppress the finding
        assert len(sqli_findings) == 0, (
            f"Expected no SQLi finding with sanitizer, got: {sqli_findings}"
        )


class TestReloadRules:
    def test_reload_rules(self):
        """Hot-reload should update rule count when file contents change."""
        dsl = RuleDSL()

        # Load initial file with 1 rule
        path = _write_yaml(_WEAK_HASH_YAML)
        result1 = dsl.load_file(path)
        initial_count = len(dsl._rules)
        assert initial_count >= 1

        # Overwrite file with 2 rules and reload
        two_rules_yaml = _WEAK_HASH_YAML + textwrap.dedent("""\
              - id: custom-weak-hash-extra
                name: Extra Weak Hash
                language: python
                severity: MEDIUM
                cwe: [CWE-327]
                patterns:
                  - "hashlib.md4("
                message: "Extra weak hash"
                confidence: 0.75
                dataflow: false
        """)
        with open(path, "w") as f:
            f.write(two_rules_yaml)

        result2 = dsl.reload(path)
        assert result2.rules_count == 2

    def test_watcher_called_on_reload(self):
        """Watcher callback should be called when rules are reloaded."""
        dsl = RuleDSL()
        call_count = [0]

        def watcher():
            call_count[0] += 1

        dsl.on_reload(watcher)
        path = _write_yaml(_WEAK_HASH_YAML)
        dsl.reload(path)

        assert call_count[0] == 1


class TestGetRulesForLanguage:
    def test_get_rules_for_language(self):
        """Python rules should not be returned for JavaScript language."""
        dsl = RuleDSL()
        dsl.load_file(_write_yaml(_SQLI_YAML))   # python rule
        dsl.load_file(_write_yaml(_JS_RULE_YAML)) # javascript rule

        py_rules = dsl.get_rules_for_language("python")
        js_rules = dsl.get_rules_for_language("javascript")

        py_ids = {r.rule_id for r in py_rules}
        js_ids = {r.rule_id for r in js_rules}

        assert "custom-sqli-flask" in py_ids
        assert "js-sqli" not in py_ids
        assert "js-sqli" in js_ids
        assert "custom-sqli-flask" not in js_ids

    def test_any_language_rule_included_for_all(self):
        """Rules with language='any' should appear for every language."""
        dsl = RuleDSL()
        any_rule_yaml = textwrap.dedent("""\
            version: "1.0"
            rules:
              - id: universal-rule
                name: Universal
                language: any
                severity: INFO
                patterns:
                  - "TODO:"
                message: "Found TODO"
                confidence: 0.50
                dataflow: false
        """)
        dsl.load_file(_write_yaml(any_rule_yaml))

        py_rules = dsl.get_rules_for_language("python")
        js_rules = dsl.get_rules_for_language("javascript")
        go_rules = dsl.get_rules_for_language("go")

        ids_py = {r.rule_id for r in py_rules}
        ids_js = {r.rule_id for r in js_rules}
        ids_go = {r.rule_id for r in go_rules}

        assert "universal-rule" in ids_py
        assert "universal-rule" in ids_js
        assert "universal-rule" in ids_go


class TestMultipleFilesLoaded:
    def test_multiple_files_loaded(self):
        """load_directory should load all YAML files from a directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            _write_yaml(_SQLI_YAML, directory=tmpdir)
            _write_yaml(_WEAK_HASH_YAML, directory=tmpdir)
            _write_yaml(_CMDI_YAML, directory=tmpdir)

            dsl = RuleDSL()
            result = dsl.load_directory(tmpdir)

            assert result.files_loaded == 3
            assert result.rules_count == 3
            rule_ids = {r.rule_id for r in result.rules}
            assert "custom-sqli-flask" in rule_ids
            assert "custom-weak-hash" in rule_ids
            assert "custom-cmdi" in rule_ids


class TestAddRuleProgrammatic:
    def test_add_rule_programmatic(self):
        """Rules added programmatically should be executed."""
        dsl = RuleDSL()
        rule = DSLRule(
            rule_id="prog-rule-001",
            name="Programmatic Rule",
            language="python",
            severity="HIGH",
            message="Found eval() call",
            confidence=0.88,
            patterns=["eval("],
            dataflow=False,
        )
        dsl.add_rule(rule)

        code = "result = eval(user_input)\n"
        findings = dsl.execute_all("/tmp/test.py", code)
        assert any(f.rule_id == "prog-rule-001" for f in findings)

    def test_add_rule_replaces_existing(self):
        """Adding a rule with an existing ID should replace it."""
        dsl = RuleDSL()
        rule1 = DSLRule(
            rule_id="replace-me",
            name="Original",
            language="python",
            severity="LOW",
            message="Original",
            confidence=0.5,
            patterns=["pattern_a"],
        )
        rule2 = DSLRule(
            rule_id="replace-me",
            name="Replacement",
            language="python",
            severity="HIGH",
            message="Replacement",
            confidence=0.9,
            patterns=["pattern_b"],
        )
        dsl.add_rule(rule1)
        dsl.add_rule(rule2)

        rules = dsl.get_rules_for_language("python")
        same_id = [r for r in rules if r.rule_id == "replace-me"]
        assert len(same_id) == 1
        assert same_id[0].severity == "HIGH"
        assert same_id[0].name == "Replacement"


class TestSourceMatching:
    def test_source_matching(self):
        """_match_source should find request.args, request.form, etc."""
        dsl = RuleDSL()
        code = textwrap.dedent("""\
            user_id = request.args.get("id")
            name = request.form["name"]
            payload = request.json
        """)
        for pattern in ("flask.request.args", "flask.request.form", "flask.request.json"):
            src = DSLSource(pattern=pattern)
            hits = dsl._match_source(src, code)
            assert len(hits) > 0, f"Expected source hit for pattern '{pattern}'"

    def test_os_environ_source_matching(self):
        """_match_source should find os.environ.get accesses."""
        dsl = RuleDSL()
        code = "secret = os.environ.get('SECRET_KEY')\n"
        src = DSLSource(pattern="os.environ.get")
        hits = dsl._match_source(src, code)
        assert len(hits) > 0


class TestSinkMatching:
    def test_sink_matching(self):
        """_match_sink should find cursor.execute, os.system, etc. with tainted vars."""
        dsl = RuleDSL()
        code = textwrap.dedent("""\
            query = user_input
            cursor.execute(query)
        """)
        tainted = {"query", "user_input"}
        sink = DSLSink(pattern="cursor.execute")
        hits = dsl._match_sink(sink, code, tainted)
        assert len(hits) > 0, "Expected sink hit for cursor.execute with tainted var"

    def test_sink_not_matched_without_tainted_var(self):
        """_match_sink should not fire when no tainted variable is present."""
        dsl = RuleDSL()
        code = 'cursor.execute("SELECT * FROM users WHERE id = 1")\n'
        tainted: set = set()  # no tainted vars
        sink = DSLSink(pattern="cursor.execute")
        hits = dsl._match_sink(sink, code, tainted)
        assert len(hits) == 0


class TestTaintTrackingChain:
    def test_taint_tracking_chain(self):
        """a=source, b=a, exec(b) — b should be detected as tainted."""
        dsl = RuleDSL()
        code = textwrap.dedent("""\
            from flask import request
            a = request.args.get("cmd")
            b = a
            result = b
            os.system(result)
        """)
        # Source lines: line 2 where a = request.args.get(...)
        tainted = dsl._track_taint_simple(code, [2])
        # 'a' should be tainted from source line
        assert "a" in tainted or "b" in tainted or "result" in tainted, (
            f"Expected taint propagation through a→b→result, tainted={tainted}"
        )
        # Check full chain: b should be tainted since b = a
        assert "b" in tainted, f"Expected 'b' to be tainted (b=a), got {tainted}"
        assert "result" in tainted, f"Expected 'result' to be tainted (result=b), got {tainted}"

    def test_taint_no_propagation_without_source(self):
        """Without source lines, taint tracking should return empty set or minimal set."""
        dsl = RuleDSL()
        code = textwrap.dedent("""\
            x = 42
            y = x + 1
            z = y
        """)
        # No source lines provided → no taint
        tainted = dsl._track_taint_simple(code, [])
        # Should be empty (no seeds)
        assert "z" not in tainted or len(tainted) == 0
