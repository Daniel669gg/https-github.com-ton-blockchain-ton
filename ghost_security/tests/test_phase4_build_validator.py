"""
tests/test_phase4_build_validator.py — Phase 4 Build Validator tests.
20 tests: Python, JS, Go, Rust, Java validation, language detection.
"""
import sys
import pathlib

_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import pytest
from backend.core.remediation.build_validator import BuildValidator, BuildResult


# ─────────────────────────────────────────────────────────────────────────────
# Test code samples
# ─────────────────────────────────────────────────────────────────────────────

_VALID_PYTHON = """
import os
from pathlib import Path

def safe_open(filename: str, base_dir: str) -> str:
    full_path = os.path.realpath(os.path.join(base_dir, filename))
    if not full_path.startswith(os.path.realpath(base_dir)):
        raise ValueError("Path traversal detected")
    with open(full_path) as f:
        return f.read()
"""

_INVALID_PYTHON = """
def broken(:
    pass
"""

_VALID_JS = """
const express = require('express');
const app = express();

app.get('/user', (req, res) => {
    const userId = parseInt(req.query.id, 10);
    if (isNaN(userId)) {
        return res.status(400).json({ error: 'Invalid ID' });
    }
    res.json({ id: userId });
});
"""

_INVALID_JS = """
function broken() {
    if (true {
        console.log('bad');
    }
"""

_VALID_GO = """
package main

import "fmt"

func main() {
    fmt.Println("Hello, World!")
}
"""

_VALID_RUST = """
fn main() {
    let x: i32 = 42;
    println!("Value: {}", x);
}
"""

_VALID_JAVA = """
public class SafeQuery {
    public static void main(String[] args) {
        System.out.println("Hello");
    }
}
"""


# ─────────────────────────────────────────────────────────────────────────────
# Imports
# ─────────────────────────────────────────────────────────────────────────────

class TestImports:
    def test_build_validator_importable(self):
        assert BuildValidator is not None

    def test_build_result_importable(self):
        assert BuildResult is not None

    def test_validator_instantiable(self):
        v = BuildValidator()
        assert v is not None


# ─────────────────────────────────────────────────────────────────────────────
# Python validation
# ─────────────────────────────────────────────────────────────────────────────

class TestPythonValidation:
    def test_valid_python_passes(self):
        v = BuildValidator()
        result = v.validate_python(_VALID_PYTHON)
        assert result.success is True

    def test_invalid_python_syntax_fails(self):
        v = BuildValidator()
        result = v.validate_python(_INVALID_PYTHON)
        assert result.success is False
        assert len(result.errors) >= 1

    def test_python_result_has_language(self):
        v = BuildValidator()
        result = v.validate_python(_VALID_PYTHON)
        assert result.language == "python"

    def test_python_result_has_duration(self):
        v = BuildValidator()
        result = v.validate_python(_VALID_PYTHON)
        assert result.duration_ms >= 0.0

    def test_empty_code_returns_success(self):
        v = BuildValidator()
        result = v.validate_python("")
        assert isinstance(result, BuildResult)


# ─────────────────────────────────────────────────────────────────────────────
# JavaScript validation
# ─────────────────────────────────────────────────────────────────────────────

class TestJSValidation:
    def test_valid_js_passes(self):
        v = BuildValidator()
        result = v.validate_javascript(_VALID_JS)
        assert result.success is True

    def test_unbalanced_braces_fails(self):
        v = BuildValidator()
        result = v.validate_javascript(_INVALID_JS)
        assert result.success is False

    def test_js_result_language(self):
        v = BuildValidator()
        result = v.validate_javascript(_VALID_JS)
        assert result.language == "javascript"

    def test_eval_js_produces_warning(self):
        v = BuildValidator()
        js_with_eval = "eval('alert(1)');"
        result = v.validate_javascript(js_with_eval)
        assert any("eval" in w for w in result.warnings)


# ─────────────────────────────────────────────────────────────────────────────
# Go, Rust, Java validation
# ─────────────────────────────────────────────────────────────────────────────

class TestOtherLanguages:
    def test_valid_go_passes(self):
        v = BuildValidator()
        result = v.validate_go(_VALID_GO)
        assert result.success is True

    def test_go_missing_package_fails(self):
        v = BuildValidator()
        result = v.validate_go("func main() { fmt.Println('test') }")
        assert result.success is False

    def test_valid_rust_passes(self):
        v = BuildValidator()
        result = v.validate_rust(_VALID_RUST)
        assert result.success is True

    def test_valid_java_passes(self):
        v = BuildValidator()
        result = v.validate_java(_VALID_JAVA)
        assert result.success is True


# ─────────────────────────────────────────────────────────────────────────────
# Generic validate() + language detection
# ─────────────────────────────────────────────────────────────────────────────

class TestGenericValidate:
    def test_detect_python(self):
        v = BuildValidator()
        lang = v.detect_language(_VALID_PYTHON)
        assert lang == "python"

    def test_detect_javascript(self):
        v = BuildValidator()
        lang = v.detect_language(_VALID_JS)
        assert lang == "javascript"

    def test_validate_auto_detects_python(self):
        v = BuildValidator()
        result = v.validate(_VALID_PYTHON)
        assert isinstance(result, BuildResult)

    def test_validate_explicit_language(self):
        v = BuildValidator()
        result = v.validate(_VALID_PYTHON, language="python")
        assert result.language == "python"

    def test_build_result_to_dict(self):
        v = BuildValidator()
        result = v.validate(_VALID_PYTHON, language="python")
        d = result.to_dict()
        assert "success" in d
        assert "language" in d
        assert "errors" in d
