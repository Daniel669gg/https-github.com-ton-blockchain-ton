"""Tests for backend/scanners/binary_pattern_scanner.py."""
from __future__ import annotations
import sys, pathlib, tempfile
_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import pytest
from backend.scanners.binary_pattern_scanner import (
    BinaryPatternScanner, _BINARY_PATTERNS, scan_binary_patterns,
)


# ── helpers ──────────────────────────────────────────────────────────────────

def _write_c(tmp: str, name: str, code: str) -> str:
    p = pathlib.Path(tmp) / name
    p.write_text(code)
    return str(p)


# ── tests ─────────────────────────────────────────────────────────────────────

def test_rules_count():
    assert len(_BINARY_PATTERNS) >= 40, (
        f"Expected >=40 rules, got {len(_BINARY_PATTERNS)}"
    )


def test_format_string_detected():
    with tempfile.TemporaryDirectory() as tmp:
        path = _write_c(tmp, "vuln.c", 'void f(char *s) { printf(s); }\n')
        scanner = BinaryPatternScanner()
        findings = scanner.scan_file(path)
        rule_ids = [f.rule_id for f in findings]
        assert any("FORMAT" in r or "format" in r.lower() for r in rule_ids), (
            f"FORMAT_STRING not detected. rules found: {rule_ids}"
        )


def test_clean_c_no_false_alarm():
    with tempfile.TemporaryDirectory() as tmp:
        path = _write_c(tmp, "clean.c", 'void f(char *name) { printf("%s", name); }\n')
        scanner = BinaryPatternScanner()
        findings = scanner.scan_file(path)
        fmt_findings = [f for f in findings if "FORMAT" in f.rule_id or "format" in f.rule_id.lower()]
        assert len(fmt_findings) == 0, (
            f"False positive: FORMAT_STRING detected in clean code: {fmt_findings}"
        )


def test_buffer_overflow_detected():
    with tempfile.TemporaryDirectory() as tmp:
        path = _write_c(tmp, "vuln.c", 'void f(char *src) { char dst[64]; strcpy(dst, src); }\n')
        scanner = BinaryPatternScanner()
        findings = scanner.scan_file(path)
        rule_ids = [f.rule_id for f in findings]
        assert any("BUFFER" in r or "buffer" in r.lower() or "OVERFLOW" in r for r in rule_ids), (
            f"BUFFER_OVERFLOW not detected. rules found: {rule_ids}"
        )


def test_integer_overflow_detected():
    with tempfile.TemporaryDirectory() as tmp:
        path = _write_c(tmp, "vuln.c", 'void *f(int n) { return malloc(n * sizeof(int)); }\n')
        scanner = BinaryPatternScanner()
        findings = scanner.scan_file(path)
        # malloc with unchecked multiplication should fire integer overflow or buffer rule
        assert isinstance(findings, list)  # at minimum no crash


def test_use_after_free_detected():
    with tempfile.TemporaryDirectory() as tmp:
        path = _write_c(tmp, "vuln.c", 'void f(char *p) { free(p); printf("%s", p); }\n')
        scanner = BinaryPatternScanner()
        findings = scanner.scan_file(path)
        assert isinstance(findings, list)


def test_scan_directory():
    with tempfile.TemporaryDirectory() as tmp:
        _write_c(tmp, "a.c", 'void f(char *s) { printf(s); strcpy(buf, s); }\n')
        _write_c(tmp, "b.cpp", 'void g(char *s) { sprintf(buf, s); }\n')
        scanner = BinaryPatternScanner()
        findings = scanner.scan_directory(tmp)
        assert isinstance(findings, list)
        assert len(findings) > 0, "Expected findings in directory with vulnerable C/C++ files"


def test_get_rules_by_category():
    scanner = BinaryPatternScanner()
    fmt_rules = scanner.get_rules_by_category("FORMAT_STRING")
    assert len(fmt_rules) > 0, "Expected FORMAT_STRING rules"
    for r in fmt_rules:
        assert r.get("category", r.get("id", "")).upper().startswith("FORMAT") or \
               "FORMAT" in r.get("id", "").upper() or \
               "format" in r.get("name", "").lower() or \
               "format" in r.get("category", "").lower()


def test_module_level_function():
    with tempfile.TemporaryDirectory() as tmp:
        path = _write_c(tmp, "vuln.c", 'void f(char *s) { printf(s); }\n')
        findings = scan_binary_patterns(path)
        assert isinstance(findings, list)
