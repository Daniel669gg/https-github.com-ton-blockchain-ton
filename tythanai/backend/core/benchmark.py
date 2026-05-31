"""
backend/core/benchmark.py
Benchmark Suite: OWASP-style test cases, precision/recall metrics.

Provides:
- ``TestCase`` / ``BenchmarkResult`` / ``BenchmarkSuite`` Pydantic models
- ``OWASP_TEST_CASES`` — 20+ concrete security test cases
- ``BenchmarkRunner`` — runs a scanner callable against test cases and reports metrics
- ``run_owasp_benchmark`` — convenience function

Also re-exports the original ground-truth evaluator models for backward
compatibility (``GroundTruthItem``, ``BenchmarkReport``, the old ``BenchmarkRunner``
is replaced by the new one which is a superset).
"""
from __future__ import annotations

import logging
import os
import tempfile
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from pydantic import BaseModel, Field

from backend.core.confidence import Finding

logger = logging.getLogger("tythanai.benchmark")


# ---------------------------------------------------------------------------
# GroundTruthItem + BenchmarkReport (original evaluator models, kept for compat)
# ---------------------------------------------------------------------------

class GroundTruthItem(BaseModel):
    rule_id: str
    file: str
    line: int = 0
    severity: str = "MEDIUM"
    description: str = ""

    def match_key(self) -> Tuple[str, str, int]:
        return (self.rule_id, self.file, self.line)


class BenchmarkReport(BaseModel):
    precision: float = Field(ge=0.0, le=1.0)
    recall: float = Field(ge=0.0, le=1.0)
    f1: float = Field(ge=0.0, le=1.0)
    true_positives: int
    false_positives: int
    false_negatives: int
    total_ground_truth: int
    total_predicted: int
    passed: bool
    precision_threshold: float
    recall_threshold: float
    scanner_name: str = ""
    module_name: str = ""
    duration_s: float = 0.0
    details: Dict[str, Any] = Field(default_factory=dict)

    def summary(self) -> str:
        status = "PASS" if self.passed else "FAIL"
        return (
            f"[{status}] {self.module_name or self.scanner_name} | "
            f"Precision={self.precision:.3f} (≥{self.precision_threshold:.2f}) | "
            f"Recall={self.recall:.3f} (≥{self.recall_threshold:.2f}) | "
            f"TP={self.true_positives} FP={self.false_positives} FN={self.false_negatives} | "
            f"F1={self.f1:.3f}"
        )


# ---------------------------------------------------------------------------
# OWASP test-case models
# ---------------------------------------------------------------------------

class TestCase(BaseModel):
    """A single scanner test case with expected and unexpected rule firings."""

    name: str
    code: str                                       # Python/JS/etc source snippet
    language: str = "python"
    expected_findings: List[str] = Field(default_factory=list)   # rule_ids that SHOULD fire
    expected_no_findings: List[str] = Field(default_factory=list)  # rule_ids that should NOT fire
    description: str = ""
    category: str = ""  # SQLI / XSS / TAINT / SSRF / etc.


class BenchmarkResult(BaseModel):
    test_name: str
    passed: bool
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    findings: List[str] = Field(default_factory=list)  # actual rule_ids returned by scanner


class BenchmarkSuite(BaseModel):
    name: str
    total: int = 0
    passed: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    results: List[BenchmarkResult] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# OWASP Test Cases (20+ cases)
# ---------------------------------------------------------------------------

OWASP_TEST_CASES: List[TestCase] = [
    # ── 1. SQL Injection — direct string concatenation ─────────────────────────
    TestCase(
        name="sqli_direct_concatenation",
        category="SQLI",
        language="python",
        description="Direct SQL string concatenation from user input (classic SQLi)",
        code="""
import sqlite3

def get_user(username):
    conn = sqlite3.connect("db.sqlite3")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchall()
""",
        expected_findings=["SQLI001", "SQLI", "SQL_INJECTION"],
        expected_no_findings=["XSS001", "CMDI001"],
    ),

    # ── 2. SQL Injection — parameterized (safe, no finding expected) ───────────
    TestCase(
        name="sqli_parameterized_safe",
        category="SQLI",
        language="python",
        description="Parameterized SQL query — no injection possible",
        code="""
import sqlite3

def get_user(username):
    conn = sqlite3.connect("db.sqlite3")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cursor.fetchall()
""",
        expected_findings=[],
        expected_no_findings=["SQLI001", "SQL_INJECTION"],
    ),

    # ── 3. XSS — reflected ─────────────────────────────────────────────────────
    TestCase(
        name="xss_reflected",
        category="XSS",
        language="python",
        description="Reflected XSS: user input echoed directly into HTML",
        code="""
from flask import Flask, request

app = Flask(__name__)

@app.route("/search")
def search():
    query = request.args.get("q", "")
    return "<html><body>Results for: " + query + "</body></html>"
""",
        expected_findings=["XSS001", "XSS", "TAINT_XSS"],
        expected_no_findings=["SQLI001"],
    ),

    # ── 4. XSS — stored ───────────────────────────────────────────────────────
    TestCase(
        name="xss_stored",
        category="XSS",
        language="python",
        description="Stored XSS via template rendering without escaping",
        code="""
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route("/comment", methods=["POST"])
def post_comment():
    comment = request.form.get("comment", "")
    # Stored in DB then re-rendered without sanitization
    return render_template_string("<p>{{ comment }}</p>", comment=comment)
""",
        expected_findings=["XSS", "TAINT_XSS"],
        expected_no_findings=["SQLI001"],
    ),

    # ── 5. Command Injection — os.system ──────────────────────────────────────
    TestCase(
        name="cmdi_os_system",
        category="CMDI",
        language="python",
        description="Command injection via os.system with user-controlled input",
        code="""
import os

def ping_host(hostname):
    os.system("ping -c 4 " + hostname)
""",
        expected_findings=["CMDI001", "CMDI", "INJECTION_COMMAND"],
        expected_no_findings=["SQLI001", "XSS001"],
    ),

    # ── 6. Command Injection — subprocess.Popen (shell=True) ──────────────────
    TestCase(
        name="cmdi_subprocess_shell_true",
        category="CMDI",
        language="python",
        description="Command injection via subprocess with shell=True",
        code="""
import subprocess

def run_command(user_input):
    result = subprocess.Popen(user_input, shell=True, stdout=subprocess.PIPE)
    return result.communicate()
""",
        expected_findings=["CMDI001", "CMDI"],
        expected_no_findings=["XSS001"],
    ),

    # ── 7. Path Traversal ─────────────────────────────────────────────────────
    TestCase(
        name="path_traversal",
        category="PATH_TRAVERSAL",
        language="python",
        description="Path traversal via user-controlled filename without sanitization",
        code="""
import os

def read_file(filename):
    base_dir = "/var/www/uploads/"
    path = os.path.join(base_dir, filename)
    with open(path, "r") as f:
        return f.read()
""",
        expected_findings=["PATH_TRAVERSAL", "LFI001", "TAINT_PATH"],
        expected_no_findings=["SQLI001"],
    ),

    # ── 8. SSRF — requests to user-controlled URL ─────────────────────────────
    TestCase(
        name="ssrf_requests",
        category="SSRF",
        language="python",
        description="SSRF via requests.get with user-controlled URL",
        code="""
import requests
from flask import request as flask_request

def fetch_url():
    url = flask_request.args.get("url")
    response = requests.get(url)
    return response.text
""",
        expected_findings=["SSRF001", "SSRF"],
        expected_no_findings=["SQLI001"],
    ),

    # ── 9. XXE — unsafe XML parsing ───────────────────────────────────────────
    TestCase(
        name="xxe_xml_parsing",
        category="XXE",
        language="python",
        description="XXE via lxml etree without disabling external entities",
        code="""
from lxml import etree

def parse_xml(xml_data):
    parser = etree.XMLParser()
    tree = etree.fromstring(xml_data, parser)
    return tree
""",
        expected_findings=["XXE001", "XXE"],
        expected_no_findings=["SQLI001"],
    ),

    # ── 10. Insecure Deserialization — pickle.loads ────────────────────────────
    TestCase(
        name="insecure_deserialization_pickle",
        category="DESERIALIZATION",
        language="python",
        description="Insecure deserialization via pickle.loads on untrusted data",
        code="""
import pickle

def deserialize_data(data):
    return pickle.loads(data)
""",
        expected_findings=["INSECURE_DESERIALIZATION", "DESERIALIZATION001", "PICKLE"],
        expected_no_findings=["SQLI001"],
    ),

    # ── 11. Hardcoded Credentials ─────────────────────────────────────────────
    TestCase(
        name="hardcoded_credentials",
        category="HARDCODED_SECRETS",
        language="python",
        description="Hardcoded password in source code",
        code="""
import psycopg2

DB_PASSWORD = "s3cr3tP@ssw0rd!"
DB_HOST = "db.internal.example.com"

def get_db_connection():
    return psycopg2.connect(
        host=DB_HOST,
        user="admin",
        password=DB_PASSWORD,
    )
""",
        expected_findings=["HARDCODED_SECRET", "SECRET001", "CREDENTIAL"],
        expected_no_findings=["SQLI001"],
    ),

    # ── 12. Weak Crypto — MD5 ─────────────────────────────────────────────────
    TestCase(
        name="weak_crypto_md5",
        category="WEAK_CRYPTO",
        language="python",
        description="MD5 used for password hashing (cryptographically broken)",
        code="""
import hashlib

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()
""",
        expected_findings=["WEAK_CRYPTO", "CRYPTO001", "INSECURE_HASH"],
        expected_no_findings=["SQLI001"],
    ),

    # ── 13. Weak Crypto — SHA-1 ───────────────────────────────────────────────
    TestCase(
        name="weak_crypto_sha1",
        category="WEAK_CRYPTO",
        language="python",
        description="SHA-1 used for sensitive data hashing (deprecated)",
        code="""
import hashlib

def fingerprint(data):
    return hashlib.sha1(data.encode()).hexdigest()
""",
        expected_findings=["WEAK_CRYPTO", "CRYPTO001"],
        expected_no_findings=["SQLI001"],
    ),

    # ── 14. Missing Auth Check ────────────────────────────────────────────────
    TestCase(
        name="missing_auth_check",
        category="BROKEN_ACCESS_CONTROL",
        language="python",
        description="Admin endpoint with no authentication check",
        code="""
from flask import Flask, jsonify

app = Flask(__name__)

@app.route("/admin/users")
def admin_list_users():
    # No authentication check at all
    users = ["alice", "bob", "charlie"]
    return jsonify(users)
""",
        expected_findings=["MISSING_AUTH", "AUTH001", "CWE-306"],
        expected_no_findings=["SQLI001"],
    ),

    # ── 15. Open Redirect ─────────────────────────────────────────────────────
    TestCase(
        name="open_redirect",
        category="OPEN_REDIRECT",
        language="python",
        description="Open redirect via user-controlled URL parameter",
        code="""
from flask import Flask, redirect, request

app = Flask(__name__)

@app.route("/login")
def login():
    next_url = request.args.get("next", "/dashboard")
    return redirect(next_url)
""",
        expected_findings=["OPEN_REDIRECT", "REDIRECT001"],
        expected_no_findings=["SQLI001"],
    ),

    # ── 16. IDOR ──────────────────────────────────────────────────────────────
    TestCase(
        name="idor",
        category="IDOR",
        language="python",
        description="IDOR: accessing resources by user-controlled ID without ownership check",
        code="""
from flask import Flask, jsonify, request

app = Flask(__name__)

@app.route("/api/documents/<int:doc_id>")
def get_document(doc_id):
    # No ownership check — any authenticated user can access any doc
    doc = fetch_document_from_db(doc_id)
    return jsonify(doc)
""",
        expected_findings=["IDOR", "BROKEN_ACCESS_CONTROL"],
        expected_no_findings=["SQLI001"],
    ),

    # ── 17. Log Injection ─────────────────────────────────────────────────────
    TestCase(
        name="log_injection",
        category="LOG_INJECTION",
        language="python",
        description="Log injection via unsanitized user input in log messages",
        code="""
import logging

logger = logging.getLogger(__name__)

def process_login(username, password):
    logger.info("Login attempt for user: " + username)
    # ... authenticate ...
""",
        expected_findings=["LOG_INJECTION", "INJECTION_LOG"],
        expected_no_findings=["SQLI001"],
    ),

    # ── 18. Template Injection ────────────────────────────────────────────────
    TestCase(
        name="template_injection",
        category="SSTI",
        language="python",
        description="Server-side template injection via user-controlled template string",
        code="""
from jinja2 import Environment

env = Environment()

def render_template(user_template, context):
    template = env.from_string(user_template)
    return template.render(**context)
""",
        expected_findings=["SSTI", "TEMPLATE_INJECTION", "INJECTION_TEMPLATE"],
        expected_no_findings=["SQLI001"],
    ),

    # ── 19. Regex DoS (ReDoS) ─────────────────────────────────────────────────
    TestCase(
        name="regex_dos",
        category="REDOS",
        language="python",
        description="Catastrophic backtracking regex applied to user input",
        code="""
import re

def validate_email(email):
    # Vulnerable regex with catastrophic backtracking
    pattern = re.compile(r"^(a+)+$")
    return bool(pattern.match(email))
""",
        expected_findings=["REDOS", "REGEX_DOS", "DENIAL_OF_SERVICE"],
        expected_no_findings=["SQLI001"],
    ),

    # ── 20. JWT Algorithm Confusion ───────────────────────────────────────────
    TestCase(
        name="jwt_algorithm_confusion",
        category="JWT",
        language="python",
        description="JWT decoded with algorithms=None — allows algorithm confusion attack",
        code="""
import jwt

def decode_token(token, public_key):
    payload = jwt.decode(token, public_key, algorithms=None)
    return payload
""",
        expected_findings=["JWT_ALGORITHM_CONFUSION", "JWT001", "INSECURE_JWT"],
        expected_no_findings=["SQLI001"],
    ),

    # ── 21. CORS Misconfiguration ─────────────────────────────────────────────
    TestCase(
        name="cors_misconfiguration",
        category="CORS",
        language="python",
        description="Wildcard CORS allowing credentials from any origin",
        code="""
from flask import Flask
from flask_cors import CORS

app = Flask(__name__)
CORS(app, origins="*", supports_credentials=True)
""",
        expected_findings=["CORS_MISCONFIGURATION", "CORS001"],
        expected_no_findings=["SQLI001"],
    ),

    # ── 22. Buffer Overflow Indicator ─────────────────────────────────────────
    TestCase(
        name="buffer_overflow_ctypes",
        category="BUFFER_OVERFLOW",
        language="python",
        description="Unchecked buffer write via ctypes (potential buffer overflow)",
        code="""
import ctypes

def write_buffer(data):
    buf = ctypes.create_string_buffer(64)
    ctypes.memmove(buf, data, len(data))  # no bounds check
    return buf.raw
""",
        expected_findings=["BUFFER_OVERFLOW", "UNSAFE_MEMORY"],
        expected_no_findings=["SQLI001"],
    ),

    # ── 23. Race Condition ────────────────────────────────────────────────────
    TestCase(
        name="race_condition_toctou",
        category="RACE_CONDITION",
        language="python",
        description="TOCTOU race condition: check then act on a file",
        code="""
import os

def process_file(path):
    if os.path.exists(path):
        # Race condition window here
        with open(path, "r") as f:
            return f.read()
""",
        expected_findings=["RACE_CONDITION", "TOCTOU"],
        expected_no_findings=["SQLI001"],
    ),

    # ── 24. Prototype Pollution (JS — stored as JS snippet) ───────────────────
    TestCase(
        name="prototype_pollution_js",
        category="PROTOTYPE_POLLUTION",
        language="javascript",
        description="Prototype pollution via deep merge of user-controlled object",
        code="""
function merge(target, source) {
    for (let key in source) {
        if (typeof source[key] === 'object') {
            target[key] = target[key] || {};
            merge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

// User controls userInput which can contain __proto__
const result = merge({}, userInput);
""",
        expected_findings=["PROTOTYPE_POLLUTION", "PROTO_POLLUTION"],
        expected_no_findings=["SQLI001"],
    ),

    # ── 25. Exec / eval injection ─────────────────────────────────────────────
    TestCase(
        name="eval_code_injection",
        category="CODE_INJECTION",
        language="python",
        description="Code injection via eval() on user-controlled input",
        code="""
def calculate(expression):
    # Dangerous: allows arbitrary code execution
    result = eval(expression)
    return result
""",
        expected_findings=["CODE_INJECTION", "EVAL_INJECTION", "CMDI"],
        expected_no_findings=["SQLI001"],
    ),
]


# ---------------------------------------------------------------------------
# BenchmarkRunner
# ---------------------------------------------------------------------------

class BenchmarkRunner:
    """
    Runs :py:class:`TestCase` instances against a scanner callable and
    produces per-test and aggregate :py:class:`BenchmarkResult` /
    :py:class:`BenchmarkSuite` metrics.

    Also provides the original ground-truth evaluator interface via
    :py:meth:`evaluate` and :py:meth:`run_suite` (dict-of-cases form).
    """

    precision_threshold: float = 0.85
    recall_threshold: float = 0.80

    def __init__(
        self,
        precision_threshold: float = 0.85,
        recall_threshold: float = 0.80,
        line_tolerance: int = 2,
    ) -> None:
        self.precision_threshold = precision_threshold
        self.recall_threshold = recall_threshold
        self.line_tolerance = line_tolerance

    # ------------------------------------------------------------------
    # OWASP-style test runner
    # ------------------------------------------------------------------

    def run_test(
        self,
        test_case: TestCase,
        scanner_fn: Callable[[str], List[Finding]],
    ) -> BenchmarkResult:
        """
        Write *test_case.code* to a temp file, invoke *scanner_fn*, then
        compute TP / FP / FN / precision / recall / F1.

        A rule_id is a True Positive if it appears in *expected_findings*
        and was returned by the scanner.  A rule_id is a False Positive if
        returned by the scanner but NOT in *expected_findings*.  A rule_id
        is a False Negative if in *expected_findings* but NOT returned.

        Also penalises firings that appear in *expected_no_findings*.
        """
        suffix = ".js" if test_case.language == "javascript" else ".py"
        tmp_path: Optional[str] = None
        actual_rule_ids: List[str] = []

        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                suffix=suffix,
                delete=False,
                encoding="utf-8",
            ) as tmp:
                tmp.write(test_case.code)
                tmp_path = tmp.name

            try:
                findings: List[Finding] = scanner_fn(tmp_path)
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "scanner_fn raised for test '%s': %s", test_case.name, exc
                )
                findings = []

            actual_rule_ids = [f.rule_id for f in findings]

        finally:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

        expected = set(test_case.expected_findings)
        actual_set = set(actual_rule_ids)

        # TP: expected rule fired
        tp = len(expected & actual_set)
        # FN: expected rule did NOT fire
        fn = len(expected - actual_set)
        # FP: unexpected rule fired (not in expected, possibly in no_findings)
        fp = len(actual_set - expected)

        precision = tp / (tp + fp) if (tp + fp) > 0 else (1.0 if not expected else 0.0)
        recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
        f1 = (
            2 * precision * recall / (precision + recall)
            if (precision + recall) > 0
            else 0.0
        )

        # A test passes when:
        # 1. No expected findings AND no actual findings, OR
        # 2. Expected findings present AND precision+recall above thresholds AND
        #    none of the expected_no_findings fired
        no_unwanted = not (actual_set & set(test_case.expected_no_findings))
        if not expected:
            # Negative test: passes if no findings (or no expected rules fired)
            passed = (tp == 0 and fn == 0) and no_unwanted
        else:
            passed = (
                precision >= self.precision_threshold
                and recall >= self.recall_threshold
                and no_unwanted
            )

        return BenchmarkResult(
            test_name=test_case.name,
            passed=passed,
            true_positives=tp,
            false_positives=fp,
            false_negatives=fn,
            precision=round(precision, 4),
            recall=round(recall, 4),
            f1_score=round(f1, 4),
            findings=actual_rule_ids,
        )

    def run_suite(
        self,
        test_cases: List[TestCase],
        scanner_fn: Callable[[str], List[Finding]],
        suite_name: str = "OWASP",
    ) -> BenchmarkSuite:
        """
        Run all *test_cases*, aggregate metrics, and return a
        :py:class:`BenchmarkSuite`.
        """
        results: List[BenchmarkResult] = []
        for tc in test_cases:
            result = self.run_test(tc, scanner_fn)
            results.append(result)
            status = "PASS" if result.passed else "FAIL"
            logger.debug(
                "[%s] %s — precision=%.3f recall=%.3f f1=%.3f",
                status,
                tc.name,
                result.precision,
                result.recall,
                result.f1_score,
            )

        total = len(results)
        passed = sum(1 for r in results if r.passed)
        avg_precision = (
            sum(r.precision for r in results) / total if total > 0 else 0.0
        )
        avg_recall = (
            sum(r.recall for r in results) / total if total > 0 else 0.0
        )
        avg_f1 = sum(r.f1_score for r in results) / total if total > 0 else 0.0

        suite = BenchmarkSuite(
            name=suite_name,
            total=total,
            passed=passed,
            precision=round(avg_precision, 4),
            recall=round(avg_recall, 4),
            f1_score=round(avg_f1, 4),
            results=results,
        )
        logger.info(
            "BenchmarkSuite '%s': %d/%d passed | avg precision=%.3f recall=%.3f f1=%.3f",
            suite_name,
            passed,
            total,
            avg_precision,
            avg_recall,
            avg_f1,
        )
        return suite

    def meets_thresholds(self, suite: BenchmarkSuite) -> bool:
        """Return True if both precision and recall meet configured thresholds."""
        return (
            suite.precision >= self.precision_threshold
            and suite.recall >= self.recall_threshold
        )

    # ------------------------------------------------------------------
    # Original ground-truth evaluator interface (backward compat)
    # ------------------------------------------------------------------

    def evaluate(
        self,
        predicted: Sequence[Finding],
        ground_truth: Sequence[GroundTruthItem],
        module_name: str = "",
        scanner_name: str = "",
    ) -> BenchmarkReport:
        """Precision/recall evaluation against a ground-truth corpus."""
        t0 = time.time()

        gt_keys = {_gt_key(g, self.line_tolerance) for g in ground_truth}
        pred_keys = [_finding_key(f, self.line_tolerance) for f in predicted]

        tp = sum(1 for k in pred_keys if k in gt_keys)
        fp = sum(1 for k in pred_keys if k not in gt_keys)
        fn = len(gt_keys) - tp

        precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
        f1 = (
            2 * precision * recall / (precision + recall)
            if (precision + recall) > 0
            else 0.0
        )
        passed = (
            precision >= self.precision_threshold
            and recall >= self.recall_threshold
        )

        matched_pred_keys = {k for k in pred_keys if k in gt_keys}
        missed_gt = [
            g for g in ground_truth
            if _gt_key(g, self.line_tolerance) not in matched_pred_keys
        ]
        extra_preds = [
            f for f, k in zip(predicted, pred_keys)
            if k not in gt_keys
        ]

        report = BenchmarkReport(
            precision=round(precision, 4),
            recall=round(recall, 4),
            f1=round(f1, 4),
            true_positives=tp,
            false_positives=fp,
            false_negatives=fn,
            total_ground_truth=len(ground_truth),
            total_predicted=len(predicted),
            passed=passed,
            precision_threshold=self.precision_threshold,
            recall_threshold=self.recall_threshold,
            scanner_name=scanner_name,
            module_name=module_name,
            duration_s=round(time.time() - t0, 4),
            details={
                "missed_findings": [
                    {"rule_id": g.rule_id, "file": g.file, "line": g.line}
                    for g in missed_gt
                ],
                "false_positive_findings": [
                    {"rule_id": f.rule_id, "file": f.file, "line": f.line}
                    for f in extra_preds
                ],
            },
        )

        if passed:
            logger.info(report.summary())
        else:
            logger.warning(report.summary())

        return report

    def run_suite_gt(
        self,
        cases: List[Dict[str, Any]],
    ) -> Dict[str, BenchmarkReport]:
        """
        Ground-truth evaluation for multiple cases.

        Each case dict::

            {
                "name": str,
                "predicted": List[Finding],
                "ground_truth": List[GroundTruthItem],
            }
        """
        results: Dict[str, BenchmarkReport] = {}
        for case in cases:
            name = case["name"]
            results[name] = self.evaluate(
                predicted=case["predicted"],
                ground_truth=case["ground_truth"],
                module_name=name,
            )
        return results

    @staticmethod
    def from_raw_dicts(
        raw_findings: List[Dict[str, Any]],
        raw_gt: List[Dict[str, Any]],
    ) -> Tuple[List[Finding], List[GroundTruthItem]]:
        """Convert raw dicts to typed objects."""
        findings = []
        for d in raw_findings:
            try:
                findings.append(Finding(**d))
            except Exception:
                pass
        gt_items = []
        for d in raw_gt:
            try:
                gt_items.append(GroundTruthItem(**d))
            except Exception:
                pass
        return findings, gt_items


# ---------------------------------------------------------------------------
# Key helpers (shared with original evaluator)
# ---------------------------------------------------------------------------

def _finding_key(f: Finding, line_tolerance: int = 2) -> Tuple[str, str, int]:
    bucketed_line = (f.line // max(line_tolerance, 1)) * max(line_tolerance, 1)
    return (f.rule_id, f.file, bucketed_line)


def _gt_key(gt: GroundTruthItem, line_tolerance: int = 2) -> Tuple[str, str, int]:
    bucketed = (gt.line // max(line_tolerance, 1)) * max(line_tolerance, 1)
    return (gt.rule_id, gt.file, bucketed)


# ---------------------------------------------------------------------------
# Module-level convenience
# ---------------------------------------------------------------------------

def run_owasp_benchmark(scanner_fn: Callable[[str], List[Finding]]) -> BenchmarkSuite:
    """
    Run the full OWASP test suite against *scanner_fn* and return a
    :py:class:`BenchmarkSuite` with aggregated metrics.
    """
    runner = BenchmarkRunner()
    return runner.run_suite(OWASP_TEST_CASES, scanner_fn, "OWASP-Benchmark")
