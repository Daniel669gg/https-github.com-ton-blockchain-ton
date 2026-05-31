"""Tests for backend/scanners/taint_analyzer.py — Module 4.

True positive: SQL injection must be detected.
True negative: parameterized query must NOT produce a finding.
Benchmark: precision >= 0.85, recall >= 0.80.
"""
import os
import textwrap
import tempfile
import pytest
from pathlib import Path

from backend.scanners.taint_analyzer import TaintAnalyzer
from backend.core.benchmark import BenchmarkRunner, GroundTruthItem
from backend.core.confidence import Finding


ANALYZER = TaintAnalyzer(confidence_threshold=0.4)
RUNNER = BenchmarkRunner(precision_threshold=0.85, recall_threshold=0.80, line_tolerance=2)


def _analyze(code: str) -> list[Finding]:
    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
        f.write(textwrap.dedent(code))
        fname = f.name
    try:
        return ANALYZER.analyze_file(fname)
    finally:
        os.unlink(fname)


# ─────────────────────────────────────────────────────────────────────────────
# True Positive tests
# ─────────────────────────────────────────────────────────────────────────────

class TestTruePositives:

    def test_sql_injection_via_format(self):
        code = """
            import os
            user_id = os.getenv("USER_ID")
            cursor.execute("SELECT * FROM users WHERE id = " + user_id)
        """
        findings = _analyze(code)
        sqli = [f for f in findings if "sql_injection" in f.rule_id.lower()]
        assert len(sqli) >= 1, f"Expected SQL injection finding, got: {findings}"

    def test_sql_injection_via_fstring(self):
        code = """
            import os
            name = os.getenv("NAME")
            cursor.execute(f"SELECT * FROM users WHERE name='{name}'")
        """
        findings = _analyze(code)
        sqli = [f for f in findings if "sql" in f.rule_id.lower()]
        assert len(sqli) >= 1

    def test_shell_injection_via_subprocess(self):
        code = """
            import os, subprocess
            cmd = os.getenv("CMD")
            subprocess.run(cmd, shell=True)
        """
        findings = _analyze(code)
        shell = [f for f in findings if "shell" in f.rule_id.lower()]
        assert len(shell) >= 1

    def test_eval_injection(self):
        code = """
            import os
            expr = os.getenv("EXPR")
            eval(expr)
        """
        findings = _analyze(code)
        code_exec = [f for f in findings if "code" in f.rule_id.lower() or "eval" in str(f.description).lower()]
        assert len(code_exec) >= 1

    def test_pickle_deserialization(self):
        code = """
            import os, pickle
            data = open(os.getenv("FILE"), "rb").read()
            obj = pickle.loads(data)
        """
        findings = _analyze(code)
        deser = [f for f in findings if "deserializ" in f.rule_id.lower() or "pickle" in str(f.description).lower()]
        assert len(deser) >= 1

    def test_fastapi_query_to_sql(self):
        code = """
            from fastapi import Query
            def search(q: str = Query()):
                cursor.execute("SELECT * FROM items WHERE name='" + q + "'")
        """
        findings = _analyze(code)
        assert len(findings) >= 1

    def test_os_system_shell_injection(self):
        code = """
            import os
            cmd = os.getenv("CMD")
            os.system(cmd)
        """
        findings = _analyze(code)
        shell = [f for f in findings if "shell" in f.rule_id.lower()]
        assert len(shell) >= 1

    def test_log_injection(self):
        code = """
            import logging, os
            user_input = os.getenv("X")
            logging.info(user_input)
        """
        findings = _analyze(code)
        log_f = [f for f in findings if "log" in f.rule_id.lower()]
        assert len(log_f) >= 1

    def test_exec_injection(self):
        code = """
            import os
            code = os.getenv("CODE")
            exec(code)
        """
        findings = _analyze(code)
        assert len(findings) >= 1

    def test_subprocess_popen_injection(self):
        code = """
            import os, subprocess
            arg = os.getenv("ARG")
            subprocess.Popen(arg)
        """
        findings = _analyze(code)
        assert len(findings) >= 1


# ─────────────────────────────────────────────────────────────────────────────
# True Negative tests
# ─────────────────────────────────────────────────────────────────────────────

class TestTrueNegatives:

    def test_parameterized_query_not_flagged(self):
        code = """
            import os
            user_id = os.getenv("USER_ID")
            cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        """
        findings = _analyze(code)
        sqli = [f for f in findings if "sql_injection" in f.rule_id.lower()]
        assert len(sqli) == 0, f"Parameterized query should not be flagged: {sqli}"

    def test_parameterized_named_placeholder(self):
        code = """
            import os
            name = os.getenv("NAME")
            cursor.execute("SELECT * FROM t WHERE name=:name", {"name": name})
        """
        findings = _analyze(code)
        sqli = [f for f in findings if "sql_injection" in f.rule_id.lower()]
        assert len(sqli) == 0

    def test_safe_subprocess_list(self):
        """subprocess with a literal list (not user input) is not flagged."""
        code = """
            import subprocess
            subprocess.run(["ls", "-la"])
        """
        findings = _analyze(code)
        # No tainted variable — should produce no findings
        shell = [f for f in findings if "shell" in f.rule_id.lower()]
        assert len(shell) == 0

    def test_no_taint_source(self):
        code = """
            hardcoded = "SELECT * FROM users"
            cursor.execute(hardcoded)
        """
        findings = _analyze(code)
        # hardcoded is not a taint source
        sqli = [f for f in findings if "sql_injection" in f.rule_id.lower()]
        assert len(sqli) == 0

    def test_validated_input_confidence_reduced(self):
        code = """
            import os
            raw = os.getenv("ID")
            user_id = int(raw)
            cursor.execute("SELECT * FROM users WHERE id = " + str(user_id))
        """
        findings = _analyze(code)
        sqli = [f for f in findings if "sql" in f.rule_id.lower()]
        # If still found, confidence should be reduced
        for f in sqli:
            assert f.confidence < 0.85


# ─────────────────────────────────────────────────────────────────────────────
# Benchmark test
# ─────────────────────────────────────────────────────────────────────────────

class TestTaintBenchmark:
    """
    Benchmarks taint analyzer against a known ground-truth corpus.
    precision >= 0.85, recall >= 0.80.
    """

    # (code, expected_rule_id_exact)
    TP_CASES = [
        (
            """
import os
v = os.getenv("X")
cursor.execute("SELECT * FROM t WHERE x='" + v + "'")
""",
            "TAINT-SQL_INJECTION",
        ),
        (
            """
import os, subprocess
cmd = os.getenv("CMD")
subprocess.run(cmd, shell=True)
""",
            "TAINT-SHELL_INJECTION",
        ),
        (
            """
import os
code = os.getenv("CODE")
eval(code)
""",
            "TAINT-CODE_EXECUTION",
        ),
        (
            """
import os, pickle
data = open(os.getenv("F"), "rb").read()
pickle.loads(data)
""",
            "TAINT-DESERIALIZATION",
        ),
        (
            """
import os
cmd = os.getenv("CMD")
os.system(cmd)
""",
            "TAINT-SHELL_INJECTION",
        ),
    ]

    TN_CASES = [
        """
        import os
        uid = os.getenv("UID")
        cursor.execute("SELECT * FROM t WHERE id=?", (uid,))
        """,
        """
        import subprocess
        subprocess.run(["ls", "-la"])
        """,
        """
        hardcoded = "static"
        cursor.execute(hardcoded)
        """,
    ]

    def test_benchmark_passes(self):
        predicted: list[Finding] = []
        ground_truth: list[GroundTruthItem] = []

        with tempfile.TemporaryDirectory() as tmpdir:
            for i, (code, expected_rule_id) in enumerate(self.TP_CASES):
                fpath = os.path.join(tmpdir, f"tp_{i}.py")
                Path(fpath).write_text(textwrap.dedent(code))
                findings = ANALYZER.analyze_file(fpath)
                match = next(
                    (f for f in findings if f.rule_id == expected_rule_id), None
                )
                if match:
                    predicted.append(match)
                    ground_truth.append(GroundTruthItem(
                        rule_id=expected_rule_id, file=fpath, line=match.line,
                    ))
                else:
                    # Not detected — still add to GT so recall suffers
                    ground_truth.append(GroundTruthItem(
                        rule_id=expected_rule_id, file=fpath, line=4,
                    ))

            for i, code in enumerate(self.TN_CASES):
                fpath = os.path.join(tmpdir, f"tn_{i}.py")
                Path(fpath).write_text(textwrap.dedent(code))
                findings = ANALYZER.analyze_file(fpath)
                sqli_fp = [f for f in findings if "sql_injection" in f.rule_id.lower()]
                for fp in sqli_fp:
                    predicted.append(fp)
                # No ground-truth entry for TN cases

        report = RUNNER.evaluate(predicted, ground_truth, module_name="taint_analyzer")
        print(report.summary())
        assert report.passed, (
            f"Taint benchmark FAILED: precision={report.precision:.3f} recall={report.recall:.3f}\n"
            f"{report.details}"
        )
