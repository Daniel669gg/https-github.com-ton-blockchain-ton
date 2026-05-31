"""
Deep tests for ASTEngine — ~80 tests covering Python vulnerability patterns,
taint flow detection, JS/TS patterns, Solidity patterns, analyze_directory,
safe code, and malformed file handling.
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

import pytest
from core.ast_engine.ast_engine import ASTEngine


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def write_file(tmp_path, name, content):
    f = tmp_path / name
    f.write_text(content, encoding="utf-8")
    return str(f)


def has_rule(findings, rule_id):
    return any(f.get("rule_id") == rule_id for f in findings)


def has_category(findings, category):
    return any(f.get("category") == category for f in findings)


def has_severity(findings, severity):
    return any(f.get("severity") == severity for f in findings)


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def engine():
    return ASTEngine()


# ---------------------------------------------------------------------------
# Python — SQL injection
# ---------------------------------------------------------------------------

class TestPythonSQLInjection:
    def test_fstring_execute_triggers(self, engine, tmp_path):
        src = (
            "import sqlite3\n"
            "def get_user(uid):\n"
            "    cursor.execute(f'SELECT * FROM users WHERE id={uid}')\n"
        )
        findings = engine.analyze_file(write_file(tmp_path, "app.py", src))
        assert has_rule(findings, "PY-SQL-001")

    def test_rule_id_py_sql_001(self, engine, tmp_path):
        src = "cursor.execute(f'SELECT * FROM t WHERE id={user_id}')\n"
        findings = engine.analyze_file(write_file(tmp_path, "q.py", src))
        assert any(f["rule_id"] == "PY-SQL-001" for f in findings)

    def test_severity_critical_for_fstring(self, engine, tmp_path):
        src = "cursor.execute(f'SELECT * FROM t WHERE id={uid}')\n"
        findings = engine.analyze_file(write_file(tmp_path, "q.py", src))
        assert any(f["severity"] == "critical" for f in findings if f.get("rule_id") == "PY-SQL-001")

    def test_literal_string_no_sql_injection(self, engine, tmp_path):
        src = "cursor.execute('SELECT * FROM users')\n"
        findings = engine.analyze_file(write_file(tmp_path, "q.py", src))
        assert not has_rule(findings, "PY-SQL-001")


# ---------------------------------------------------------------------------
# Python — eval/exec
# ---------------------------------------------------------------------------

class TestPythonEval:
    def test_eval_variable_triggers(self, engine, tmp_path):
        src = "result = eval(user_input)\n"
        findings = engine.analyze_file(write_file(tmp_path, "e.py", src))
        assert has_rule(findings, "PY-EVAL-001")

    def test_exec_variable_triggers(self, engine, tmp_path):
        src = "exec(code_string)\n"
        findings = engine.analyze_file(write_file(tmp_path, "e.py", src))
        assert has_rule(findings, "PY-EVAL-001")

    def test_eval_literal_no_finding(self, engine, tmp_path):
        src = "result = eval('1 + 1')\n"
        findings = engine.analyze_file(write_file(tmp_path, "e.py", src))
        assert not has_rule(findings, "PY-EVAL-001")

    def test_severity_critical(self, engine, tmp_path):
        src = "result = eval(user_input)\n"
        findings = engine.analyze_file(write_file(tmp_path, "e.py", src))
        assert any(f["severity"] == "critical" for f in findings if f.get("rule_id") == "PY-EVAL-001")


# ---------------------------------------------------------------------------
# Python — pickle.loads
# ---------------------------------------------------------------------------

class TestPythonPickle:
    def test_pickle_loads_triggers(self, engine, tmp_path):
        src = "import pickle\nobj = pickle.loads(data)\n"
        findings = engine.analyze_file(write_file(tmp_path, "p.py", src))
        assert has_rule(findings, "PY-DESER-001")

    def test_severity_critical(self, engine, tmp_path):
        src = "import pickle\nobj = pickle.loads(data)\n"
        findings = engine.analyze_file(write_file(tmp_path, "p.py", src))
        assert any(f["severity"] == "critical" for f in findings if f.get("rule_id") == "PY-DESER-001")


# ---------------------------------------------------------------------------
# Python — yaml.load without Loader
# ---------------------------------------------------------------------------

class TestPythonYaml:
    def test_yaml_load_no_loader_triggers(self, engine, tmp_path):
        src = "import yaml\ndata = yaml.load(stream)\n"
        findings = engine.analyze_file(write_file(tmp_path, "y.py", src))
        assert has_rule(findings, "PY-DESER-003")

    def test_yaml_safe_load_no_finding(self, engine, tmp_path):
        src = "import yaml\ndata = yaml.safe_load(stream)\n"
        findings = engine.analyze_file(write_file(tmp_path, "y.py", src))
        assert not has_rule(findings, "PY-DESER-003")

    def test_yaml_load_with_loader_no_finding(self, engine, tmp_path):
        src = "import yaml\ndata = yaml.load(stream, Loader=yaml.SafeLoader)\n"
        findings = engine.analyze_file(write_file(tmp_path, "y.py", src))
        assert not has_rule(findings, "PY-DESER-003")


# ---------------------------------------------------------------------------
# Python — subprocess shell=True
# ---------------------------------------------------------------------------

class TestPythonSubprocess:
    def test_popen_shell_true_variable_triggers(self, engine, tmp_path):
        src = (
            "import subprocess\n"
            "subprocess.Popen(user_cmd, shell=True)\n"
        )
        findings = engine.analyze_file(write_file(tmp_path, "s.py", src))
        assert has_rule(findings, "PY-CMD-001")

    def test_run_shell_true_variable_triggers(self, engine, tmp_path):
        src = (
            "import subprocess\n"
            "subprocess.run(cmd, shell=True)\n"
        )
        findings = engine.analyze_file(write_file(tmp_path, "s.py", src))
        assert has_rule(findings, "PY-CMD-001")

    def test_run_shell_false_no_finding(self, engine, tmp_path):
        src = "import subprocess\nsubprocess.run(['ls', '-la'], shell=False)\n"
        findings = engine.analyze_file(write_file(tmp_path, "s.py", src))
        assert not has_rule(findings, "PY-CMD-001")

    def test_severity_critical(self, engine, tmp_path):
        src = "import subprocess\nsubprocess.Popen(user_cmd, shell=True)\n"
        findings = engine.analyze_file(write_file(tmp_path, "s.py", src))
        assert any(f["severity"] == "critical" for f in findings if f.get("rule_id") == "PY-CMD-001")


# ---------------------------------------------------------------------------
# Python — hardcoded passwords
# ---------------------------------------------------------------------------

class TestPythonHardcodedCreds:
    def test_password_constant_triggers(self, engine, tmp_path):
        src = "password = 'super_secret_pass'\n"
        findings = engine.analyze_file(write_file(tmp_path, "c.py", src))
        assert has_rule(findings, "PY-CRED-001")

    def test_api_key_constant_triggers(self, engine, tmp_path):
        src = "api_key = 'sk-abcdef1234567890'\n"
        findings = engine.analyze_file(write_file(tmp_path, "c.py", src))
        assert has_rule(findings, "PY-CRED-001")

    def test_secret_constant_triggers(self, engine, tmp_path):
        src = "secret = 'mysecretvalue123'\n"
        findings = engine.analyze_file(write_file(tmp_path, "c.py", src))
        assert has_rule(findings, "PY-CRED-001")

    def test_empty_string_no_finding(self, engine, tmp_path):
        src = "password = ''\n"
        findings = engine.analyze_file(write_file(tmp_path, "c.py", src))
        assert not has_rule(findings, "PY-CRED-001")


# ---------------------------------------------------------------------------
# JS/TS patterns
# ---------------------------------------------------------------------------

class TestJSPatterns:
    def test_inner_html_triggers(self, engine, tmp_path):
        src = "element.innerHTML = userInput;\n"
        findings = engine.analyze_file(write_file(tmp_path, "app.js", src))
        assert has_rule(findings, "JS-XSS-001")

    def test_document_write_triggers(self, engine, tmp_path):
        src = "document.write(content);\n"
        findings = engine.analyze_file(write_file(tmp_path, "app.js", src))
        assert has_rule(findings, "JS-XSS-002")

    def test_eval_triggers(self, engine, tmp_path):
        src = "const result = eval(userCode);\n"
        findings = engine.analyze_file(write_file(tmp_path, "app.js", src))
        assert has_rule(findings, "JS-EVAL-001")

    def test_new_function_triggers(self, engine, tmp_path):
        src = "const fn = new Function('return 1');\n"
        findings = engine.analyze_file(write_file(tmp_path, "app.js", src))
        assert has_rule(findings, "JS-EVAL-002")

    def test_ts_file_analyzed(self, engine, tmp_path):
        src = "const result = eval(userCode);\n"
        findings = engine.analyze_file(write_file(tmp_path, "app.ts", src))
        assert has_rule(findings, "JS-EVAL-001")

    def test_hardcoded_secret_triggers(self, engine, tmp_path):
        src = 'const apiKey = "sk-abcdef1234567890";\n'
        findings = engine.analyze_file(write_file(tmp_path, "config.js", src))
        assert has_rule(findings, "JS-CRED-001")


# ---------------------------------------------------------------------------
# Solidity patterns
# ---------------------------------------------------------------------------

class TestSolidityPatterns:
    def test_tx_origin_triggers(self, engine, tmp_path):
        src = "require(tx.origin == owner);\n"
        findings = engine.analyze_file(write_file(tmp_path, "token.sol", src))
        assert has_rule(findings, "SOL-AUTH-001")

    def test_low_level_call_triggers(self, engine, tmp_path):
        src = "target.call{value: 1 ether}('');\n"
        findings = engine.analyze_file(write_file(tmp_path, "token.sol", src))
        assert has_rule(findings, "SOL-REENT-001")

    def test_selfdestruct_triggers(self, engine, tmp_path):
        src = "selfdestruct(payable(owner));\n"
        findings = engine.analyze_file(write_file(tmp_path, "token.sol", src))
        assert has_rule(findings, "SOL-DEST-001")

    def test_block_timestamp_triggers(self, engine, tmp_path):
        src = "require(block.timestamp > deadline);\n"
        findings = engine.analyze_file(write_file(tmp_path, "token.sol", src))
        assert has_rule(findings, "SOL-RAND-001")


# ---------------------------------------------------------------------------
# analyze_directory
# ---------------------------------------------------------------------------

class TestAnalyzeDirectory:
    def test_empty_directory(self, engine, tmp_path):
        result = engine.analyze_directory(str(tmp_path))
        assert result["files_scanned"] == 0
        assert result["total_findings"] == 0
        assert "findings_by_file" in result
        assert "summary" in result

    def test_multiple_files_aggregated(self, engine, tmp_path):
        write_file(tmp_path, "a.py", "password = 'abc123'\n")
        write_file(tmp_path, "b.js", "eval(userInput);\n")
        result = engine.analyze_directory(str(tmp_path))
        assert result["files_scanned"] >= 2
        assert result["total_findings"] >= 2

    def test_findings_by_file_populated(self, engine, tmp_path):
        path = write_file(tmp_path, "bad.py", "password = 'abc123'\n")
        result = engine.analyze_directory(str(tmp_path))
        assert path in result["findings_by_file"]

    def test_summary_keys(self, engine, tmp_path):
        result = engine.analyze_directory(str(tmp_path))
        for key in ("critical", "high", "medium", "low", "info"):
            assert key in result["summary"]

    def test_nonrecursive_mode(self, engine, tmp_path):
        subdir = tmp_path / "sub"
        subdir.mkdir()
        write_file(subdir, "a.py", "password = 'abc123'\n")
        write_file(tmp_path, "b.py", "password = 'abc123'\n")
        result = engine.analyze_directory(str(tmp_path), recursive=False)
        # Only direct files should be scanned
        assert result["files_scanned"] == 1


# ---------------------------------------------------------------------------
# Safe code — no false positives
# ---------------------------------------------------------------------------

class TestSafeCode:
    def test_clean_python_no_findings(self, engine, tmp_path):
        src = (
            "def add(a, b):\n"
            "    return a + b\n\n"
            "result = add(1, 2)\n"
        )
        findings = engine.analyze_file(write_file(tmp_path, "math.py", src))
        assert findings == []

    def test_parameterized_query_no_sql_injection(self, engine, tmp_path):
        src = "cursor.execute('SELECT * FROM users WHERE id = ?', (uid,))\n"
        findings = engine.analyze_file(write_file(tmp_path, "db.py", src))
        assert not has_rule(findings, "PY-SQL-001")


# ---------------------------------------------------------------------------
# Malformed / syntax-error files
# ---------------------------------------------------------------------------

class TestMalformedFiles:
    def test_syntax_error_python_no_crash(self, engine, tmp_path):
        src = "def broken(:\n    pass\n"
        findings = engine.analyze_file(write_file(tmp_path, "broken.py", src))
        assert isinstance(findings, list)

    def test_empty_file_returns_empty_list(self, engine, tmp_path):
        findings = engine.analyze_file(write_file(tmp_path, "empty.py", ""))
        assert findings == []

    def test_unknown_extension_returns_list(self, engine, tmp_path):
        src = "password = 'hello world'\n"
        findings = engine.analyze_file(write_file(tmp_path, "config.toml", src))
        assert isinstance(findings, list)

    def test_finding_has_required_keys(self, engine, tmp_path):
        src = "password = 'super_secret'\n"
        findings = engine.analyze_file(write_file(tmp_path, "c.py", src))
        assert findings
        f = findings[0]
        for key in ("rule_id", "severity", "category", "message", "file", "line"):
            assert key in f, f"Missing key: {key}"


# ---------------------------------------------------------------------------
# Additional Python vulnerability patterns
# ---------------------------------------------------------------------------

class TestAdditionalPythonPatterns:
    def test_executemany_fstring_triggers(self, engine, tmp_path):
        src = "cursor.executemany(f'INSERT INTO t VALUES ({val})', data)\n"
        findings = engine.analyze_file(write_file(tmp_path, "em.py", src))
        assert has_rule(findings, "PY-SQL-001")

    def test_executescript_fstring_triggers(self, engine, tmp_path):
        src = "conn.executescript(f'DROP TABLE {table_name}')\n"
        findings = engine.analyze_file(write_file(tmp_path, "es.py", src))
        assert has_rule(findings, "PY-SQL-001")

    def test_compile_variable_triggers(self, engine, tmp_path):
        src = "code = compile(user_source, '<string>', 'exec')\n"
        findings = engine.analyze_file(write_file(tmp_path, "comp.py", src))
        assert has_rule(findings, "PY-EVAL-001")

    def test_pickle_load_triggers(self, engine, tmp_path):
        src = "import pickle\nobj = pickle.load(file_handle)\n"
        findings = engine.analyze_file(write_file(tmp_path, "pl.py", src))
        assert has_rule(findings, "PY-DESER-001")

    def test_subprocess_check_output_shell_true_triggers(self, engine, tmp_path):
        src = "import subprocess\nsubprocess.check_output(cmd, shell=True)\n"
        findings = engine.analyze_file(write_file(tmp_path, "co.py", src))
        assert has_rule(findings, "PY-CMD-001")

    def test_token_constant_triggers(self, engine, tmp_path):
        src = "token = 'Bearer abc123def456ghi789'\n"
        findings = engine.analyze_file(write_file(tmp_path, "tok.py", src))
        assert has_rule(findings, "PY-CRED-001")

    def test_private_key_constant_triggers(self, engine, tmp_path):
        src = "private_key = 'abcdef1234567890abcdef1234567890'\n"
        findings = engine.analyze_file(write_file(tmp_path, "pk.py", src))
        assert has_rule(findings, "PY-CRED-001")

    def test_access_token_triggers(self, engine, tmp_path):
        src = "access_token = 'ghp_abcdefghijklmnopqrstuvwxyz0123'\n"
        findings = engine.analyze_file(write_file(tmp_path, "at.py", src))
        assert has_rule(findings, "PY-CRED-001")

    def test_finding_snippet_populated(self, engine, tmp_path):
        src = "password = 'super_secret'\n"
        findings = engine.analyze_file(write_file(tmp_path, "snip.py", src))
        assert findings
        assert findings[0].get("snippet") is not None

    def test_finding_line_number_correct(self, engine, tmp_path):
        src = "x = 1\ny = 2\npassword = 'secret'\n"
        findings = engine.analyze_file(write_file(tmp_path, "ln.py", src))
        cred_findings = [f for f in findings if f.get("rule_id") == "PY-CRED-001"]
        assert cred_findings
        assert cred_findings[0]["line"] == 3


# ---------------------------------------------------------------------------
# Additional JS patterns
# ---------------------------------------------------------------------------

class TestAdditionalJSPatterns:
    def test_settimeout_string_triggers(self, engine, tmp_path):
        src = "setTimeout('alert(1)', 1000);\n"
        findings = engine.analyze_file(write_file(tmp_path, "st.js", src))
        assert has_rule(findings, "JS-EVAL-003")

    def test_exec_sync_shell_injection(self, engine, tmp_path):
        src = "execSync('ls ' + userInput);\n"
        findings = engine.analyze_file(write_file(tmp_path, "ex.js", src))
        assert has_rule(findings, "JS-CMD-001")

    def test_proto_pollution_triggers(self, engine, tmp_path):
        src = "obj.__proto__['admin'] = true;\n"
        findings = engine.analyze_file(write_file(tmp_path, "proto.js", src))
        assert has_rule(findings, "JS-PROTO-001")

    def test_fetch_with_dynamic_url_triggers(self, engine, tmp_path):
        src = "fetch(baseUrl + userPath).then(r => r.json());\n"
        findings = engine.analyze_file(write_file(tmp_path, "fetch.js", src))
        assert has_rule(findings, "JS-SSRF-001")

    def test_jsx_file_analyzed(self, engine, tmp_path):
        src = "const el = <div dangerouslySetInnerHTML={{__html: input}} />;\n"
        findings = engine.analyze_file(write_file(tmp_path, "App.jsx", src))
        assert isinstance(findings, list)

    def test_mjs_file_analyzed(self, engine, tmp_path):
        src = "const result = eval(userCode);\n"
        findings = engine.analyze_file(write_file(tmp_path, "mod.mjs", src))
        assert has_rule(findings, "JS-EVAL-001")


# ---------------------------------------------------------------------------
# Additional Solidity patterns
# ---------------------------------------------------------------------------

class TestAdditionalSolidityPatterns:
    def test_sol_old_pragma_triggers(self, engine, tmp_path):
        src = "pragma solidity ^0.6.0;\ncontract T {}\n"
        findings = engine.analyze_file(write_file(tmp_path, "old.sol", src))
        assert has_rule(findings, "SOL-ARITH-001")

    def test_sol_send_triggers(self, engine, tmp_path):
        src = "bool ok = payable(recipient).send(amount);\n"
        findings = engine.analyze_file(write_file(tmp_path, "send.sol", src))
        assert has_rule(findings, "SOL-SEND-001")

    def test_sol_delegatecall_triggers(self, engine, tmp_path):
        src = "target.delegatecall(calldata);\n"
        findings = engine.analyze_file(write_file(tmp_path, "dc.sol", src))
        assert has_rule(findings, "SOL-REENT-002")

    def test_sol_hardcoded_address_triggers(self, engine, tmp_path):
        src = "address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;\n"
        findings = engine.analyze_file(write_file(tmp_path, "addr.sol", src))
        assert has_rule(findings, "SOL-ADDR-001")

    def test_sol_unchecked_block_triggers(self, engine, tmp_path):
        src = "unchecked { total += amount; }\n"
        findings = engine.analyze_file(write_file(tmp_path, "unc.sol", src))
        assert has_rule(findings, "SOL-ARITH-002")

    def test_analyze_dir_extensions_filter(self, engine, tmp_path):
        write_file(tmp_path, "app.py", "password = 'secret'\n")
        write_file(tmp_path, "app.js", "eval(code);\n")
        # Scan only .py files
        result = engine.analyze_directory(str(tmp_path), extensions=["py"])
        assert result["files_scanned"] == 1

    def test_analyze_dir_total_findings_matches_summary(self, engine, tmp_path):
        write_file(tmp_path, "a.py", "password = 'abc'\napi_key = 'xyz'\n")
        result = engine.analyze_directory(str(tmp_path))
        assert result["total_findings"] == sum(result["summary"].values())
