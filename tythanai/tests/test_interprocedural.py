"""
Tests for backend/analysis/interprocedural.py — InterproceduralTaintAnalyzer.

Each test uses tempfile.mkdtemp() to create an isolated project directory.
Tests are pytest-style plain functions (no class required).
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
import textwrap
from pathlib import Path
from typing import List

import pytest

# Ensure project root is on sys.path for `backend.*` imports
_PROJECT_ROOT = Path(__file__).parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from backend.analysis.interprocedural import (
    InterproceduralTaintAnalyzer,
    IPTaintFinding,
    TaintState,
    analyze_project_taint,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_project(files: dict[str, str]) -> str:
    """
    Create a temporary directory, write each filename → source entry into it,
    and return the directory path.  The caller is responsible for cleanup.
    """
    tmp = tempfile.mkdtemp()
    for filename, source in files.items():
        path = os.path.join(tmp, filename)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        Path(path).write_text(textwrap.dedent(source), encoding="utf-8")
    return tmp


# ---------------------------------------------------------------------------
# Test 1 — Direct taint: input() → exec() in the same function
# ---------------------------------------------------------------------------


def test_direct_taint_input_to_exec() -> None:
    """
    A variable assigned from input() and passed directly to exec() must
    produce at least one IPTaintFinding with the correct source and sink rules.
    """
    tmp = _make_project({
        "app.py": """\
            def main():
                x = input("Enter command: ")
                exec(x)
        """,
    })
    try:
        analyzer = InterproceduralTaintAnalyzer(tmp, max_depth=10)
        findings = analyzer.analyze()

        assert findings, "Expected at least one finding for input() -> exec()"
        sink_findings = [f for f in findings if f.sink_rule == "sink/exec"]
        assert sink_findings, (
            f"Expected a finding with sink_rule='sink/exec'; got: {findings}"
        )
        f = sink_findings[0]
        assert f.source_rule == "taint/input", (
            f"Expected source_rule='taint/input'; got: {f.source_rule}"
        )
        assert f.severity == "CRITICAL", (
            f"exec() sink must be CRITICAL severity; got: {f.severity}"
        )
        assert 0.0 < f.confidence <= 1.0
        assert isinstance(f.taint_path, list) and len(f.taint_path) >= 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# Test 2 — No taint: literal string → exec() must NOT produce a finding
# ---------------------------------------------------------------------------


def test_no_taint_literal_to_exec() -> None:
    """
    A variable assigned from a string literal and passed to exec() must
    NOT produce any IPTaintFinding (no user-controlled data).
    """
    tmp = _make_project({
        "app.py": """\
            def main():
                x = "print('hello')"
                exec(x)
        """,
    })
    try:
        analyzer = InterproceduralTaintAnalyzer(tmp, max_depth=10)
        findings = analyzer.analyze()

        exec_findings = [f for f in findings if f.sink_rule == "sink/exec"]
        assert not exec_findings, (
            f"Literal string to exec() must NOT produce a finding; got: {exec_findings}"
        )
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# Test 3 — Cross-function taint: taint flows from caller into callee that
#           reaches a sink
# ---------------------------------------------------------------------------


def test_cross_function_taint_caller_to_callee_sink() -> None:
    """
    Taint introduced by input() in the caller must flow into the callee
    parameter and be detected at the exec() sink inside the callee.
    """
    tmp = _make_project({
        "app.py": """\
            def run_code(cmd):
                exec(cmd)

            def main():
                user_input = input("cmd> ")
                run_code(user_input)
        """,
    })
    try:
        analyzer = InterproceduralTaintAnalyzer(tmp, max_depth=10)
        findings = analyzer.analyze()

        exec_findings = [f for f in findings if f.sink_rule == "sink/exec"]
        assert exec_findings, (
            "Cross-function taint from input() through run_code(cmd) to exec(cmd) "
            f"must produce a finding; got: {findings}"
        )
        f = exec_findings[0]
        assert f.source_rule == "taint/input"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# Test 4 — Multi-hop taint: source → func1(arg) → func2(arg) → sink (2 hops)
# ---------------------------------------------------------------------------


def test_multi_hop_taint_two_function_chain() -> None:
    """
    Taint must propagate through a two-function call chain:
      main()  →  func1(val)  →  func2(data)  →  exec(data)
    """
    tmp = _make_project({
        "app.py": """\
            def func2(data):
                exec(data)

            def func1(val):
                func2(val)

            def main():
                user_input = input("Enter: ")
                func1(user_input)
        """,
    })
    try:
        analyzer = InterproceduralTaintAnalyzer(tmp, max_depth=10)
        findings = analyzer.analyze()

        exec_findings = [f for f in findings if f.sink_rule == "sink/exec"]
        assert exec_findings, (
            "Multi-hop taint (main→func1→func2→exec) must produce a finding; "
            f"got: {findings}"
        )
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# Test 5 — Sanitized path: taint through sanitize() still reaches exec/eval
#           (we do NOT model sanitization as safe for code-execution sinks)
# ---------------------------------------------------------------------------


def test_sanitized_taint_still_reaches_exec_sink() -> None:
    """
    Taint flowing through a function that performs str.replace() is NOT
    considered sanitized for exec()/eval() sinks.  The finding must still
    be emitted because replace() does not guarantee safety for code execution.
    """
    tmp = _make_project({
        "app.py": """\
            def sanitize(x):
                return x.replace("'", "")

            def main():
                raw = input("cmd: ")
                cleaned = sanitize(raw)
                exec(cleaned)
        """,
    })
    try:
        analyzer = InterproceduralTaintAnalyzer(tmp, max_depth=10)
        findings = analyzer.analyze()

        # The taint flows: raw = input() → cleaned = sanitize(raw) → exec(cleaned)
        # Since cleaned is assigned from sanitize(raw) and raw is tainted,
        # cleaned is also tainted (assignment propagation from tainted raw).
        exec_findings = [f for f in findings if f.sink_rule == "sink/exec"]
        assert exec_findings, (
            "Taint through sanitize(x.replace(...)) to exec() must still be flagged; "
            f"got: {findings}"
        )
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# Test 6 — OS environ source: os.environ["HOST"] → os.system(f"ping {host}")
# ---------------------------------------------------------------------------


def test_os_environ_source_to_os_system_sink() -> None:
    """
    A variable populated from os.environ subscript access and used in
    os.system() via an f-string must produce a CRITICAL finding.
    """
    tmp = _make_project({
        "app.py": """\
            import os

            def ping_host():
                host = os.environ["HOST"]
                os.system(f"ping {host}")
        """,
    })
    try:
        analyzer = InterproceduralTaintAnalyzer(tmp, max_depth=10)
        findings = analyzer.analyze()

        shell_findings = [f for f in findings if f.sink_rule == "sink/os.system"]
        assert shell_findings, (
            "os.environ['HOST'] flowing into os.system() must produce a finding; "
            f"got: {findings}"
        )
        f = shell_findings[0]
        assert f.source_rule == "taint/os.environ", (
            f"Expected source_rule='taint/os.environ'; got: {f.source_rule}"
        )
        assert f.severity == "CRITICAL"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# Test 7 — SQL injection via f-string formatting + cursor.execute()
# ---------------------------------------------------------------------------


def test_sql_injection_via_fstring_and_cursor_execute() -> None:
    """
    A tainted variable (os.environ) used inside an f-string that is then
    passed to cursor.execute() must be detected as a SQL injection.
    """
    tmp = _make_project({
        "app.py": """\
            import os

            def fetch_user(cursor):
                user_id = os.environ["USER_ID"]
                query = f"SELECT * FROM users WHERE id = {user_id}"
                cursor.execute(query)
        """,
    })
    try:
        analyzer = InterproceduralTaintAnalyzer(tmp, max_depth=10)
        findings = analyzer.analyze()

        sql_findings = [f for f in findings if f.sink_rule == "sink/sql_injection"]
        assert sql_findings, (
            "Tainted f-string passed to cursor.execute() must produce a SQL injection finding; "
            f"got: {findings}"
        )
        f = sql_findings[0]
        assert f.source_rule == "taint/os.environ"
        assert f.severity == "HIGH"
        assert 0.0 < f.confidence <= 1.0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# Test 8 — Depth limit: chain of 15 functions, depth=5 → must not crash
# ---------------------------------------------------------------------------


def test_depth_limit_stops_propagation_without_crash() -> None:
    """
    A call chain of 15 functions (f0 → f1 → … → f14 → exec) with max_depth=5
    must not crash and must stop propagation before depth 15.

    With depth=5 the taint cannot reach f14 (exec sink), so the number of
    exec-sink findings must be 0.  The important assertion is that the
    analysis completes without RecursionError or any other exception.
    """
    # Build: f14 calls exec(x); f13 calls f14(x); …; f0 calls f1(x)
    # main() seeds taint via input() and calls f0(data)
    lines: list[str] = []
    for i in range(14, -1, -1):
        lines.append(f"def f{i}(x):")
        if i == 14:
            lines.append("    exec(x)")
        else:
            lines.append(f"    f{i + 1}(x)")
    lines.append("def main():")
    lines.append("    data = input('cmd: ')")
    lines.append("    f0(data)")
    source = "\n".join(lines) + "\n"

    tmp = _make_project({"chain.py": source})
    try:
        analyzer = InterproceduralTaintAnalyzer(tmp, max_depth=5)
        # Must not raise
        findings = analyzer.analyze()

        # With depth=5, f0→f1→f2→f3→f4→f5 is the deepest reachable path
        # (depth increments on each inter-function hop from the seed).
        # The exec() is in f14, which requires 14 hops — unreachable at depth 5.
        exec_findings = [f for f in findings if f.sink_rule == "sink/exec"]
        assert len(exec_findings) == 0, (
            f"Depth-5 limit must prevent reaching f14's exec(); got: {exec_findings}"
        )
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
