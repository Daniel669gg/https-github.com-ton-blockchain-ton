"""
TythanAI — Known-Findings Benchmark Corpus
=================================================
Regression fixtures for detection-quality testing.

Each entry in TRUE_POSITIVE_CORPUS is a realistic code snippet that **must**
produce at least one finding matching ``expected_rule``.

Each entry in FALSE_POSITIVE_CORPUS is code that is genuinely safe and
**must not** produce a finding for ``expected_no_rule``.

Usage::

    from tests.corpus.known_findings import CorpusValidator, TRUE_POSITIVE_CORPUS, FALSE_POSITIVE_CORPUS

    validator = CorpusValidator()
    results   = validator.validate_all(TRUE_POSITIVE_CORPUS + FALSE_POSITIVE_CORPUS)
    print(validator.report(results))
"""
from __future__ import annotations

import os
import sys
import tempfile
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Ensure project root is importable regardless of how tests are invoked
# ---------------------------------------------------------------------------
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


# ===========================================================================
# TRUE-POSITIVE CORPUS
# Each snippet contains a genuine vulnerability that a Ghost scanner *should*
# flag.  The ``expected_rule`` is the finding ID prefix that must appear.
# ===========================================================================

TRUE_POSITIVE_CORPUS: List[Dict[str, Any]] = [
    # ------------------------------------------------------------------
    # 1. Python SQL injection via f-string — OWASP A03 / CWE-89
    # ------------------------------------------------------------------
    {
        "name": "sql_injection_fstring",
        "language": "python",
        "code": """\
from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)

@app.route('/users')
def search_users():
    username = request.args.get('username', '')
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    # Vulnerable: user input directly interpolated into SQL
    cursor.execute(f"SELECT id, email FROM users WHERE username = '{username}'")
    rows = cursor.fetchall()
    conn.close()
    return jsonify(rows)
""",
        "scanner": "owasp",
        "expected_rule": "OW-A03-001",
        "expected_severity": "HIGH",
    },

    # ------------------------------------------------------------------
    # 2. JavaScript eval() injection — OWASP A03 / CWE-95
    # ------------------------------------------------------------------
    {
        "name": "js_eval_injection",
        "language": "javascript",
        "code": """\
const express = require('express');
const app     = express();

// Calculator endpoint — dangerous: executes arbitrary JS from query param
app.get('/calculate', (req, res) => {
    const expr   = req.query.expr;     // untrusted
    const result = eval(expr);         // VULNERABLE — remote code execution
    res.json({ result });
});

app.listen(3000);
""",
        "scanner": "owasp",
        "expected_rule": "OW-A03-004",
        "expected_severity": "CRITICAL",
    },

    # ------------------------------------------------------------------
    # 3. Java SQL injection via string concatenation — CWE-89
    # ------------------------------------------------------------------
    {
        "name": "java_sql_string_concat",
        "language": "java",
        "code": """\
import java.sql.*;

public class UserRepository {
    private Connection connection;

    public ResultSet findByUsername(String username) throws SQLException {
        // Vulnerable: executeQuery called with a concatenated, user-controlled string
        return connection.createStatement().executeQuery(
            "SELECT id, email FROM users WHERE username='" + username + "'"
        );
    }
}
""",
        "scanner": "java",
        "expected_rule": "JAVA-001",
        "expected_severity": "HIGH",
    },

    # ------------------------------------------------------------------
    # 4. Go SQL injection via fmt.Sprintf in db.Query — CWE-89
    # ------------------------------------------------------------------
    {
        "name": "go_sql_sprintf",
        "language": "go",
        "code": """\
package main

import (
\t"database/sql"
\t"fmt"
\t"net/http"
)

func getUserHandler(db *sql.DB, w http.ResponseWriter, r *http.Request) {
\tuserID := r.URL.Query().Get("id")
\t// Vulnerable: fmt.Sprintf injects user data into SQL
\trows, err := db.Query(fmt.Sprintf("SELECT name, email FROM users WHERE id = '%s'", userID))
\tif err != nil {
\t\thttp.Error(w, "db error", http.StatusInternalServerError)
\t\treturn
\t}
\tdefer rows.Close()
}
""",
        "scanner": "go",
        "expected_rule": "GO-001",
        "expected_severity": "CRITICAL",
    },

    # ------------------------------------------------------------------
    # 5. Hardcoded AWS access key — CWE-798
    # ------------------------------------------------------------------
    {
        "name": "hardcoded_aws_key",
        "language": "python",
        "code": """\
import boto3

# Credentials committed directly — never do this in production
AWS_ACCESS_KEY_ID     = 'AKIAIOSFODNN7EXAMPLE'
AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'

s3 = boto3.client(
    's3',
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
)

def list_buckets():
    return s3.list_buckets()['Buckets']
""",
        "scanner": "secret",
        "expected_rule": "SEC-AWS_ACCESS_KEY",
        "expected_severity": "CRITICAL",
    },

    # ------------------------------------------------------------------
    # 6. JWT algorithm:none — disables signature verification — CWE-347
    # ------------------------------------------------------------------
    {
        "name": "jwt_alg_none",
        "language": "python",
        "code": """\
import jwt
from flask import request

def authenticate():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    # Dangerous: accepting 'none' algorithm means any unsigned token is valid
    payload = jwt.decode(
        token,
        algorithms=['none'],
        options={'verify_signature': False},
    )
    return payload.get('user_id')
""",
        "scanner": "jwt",
        "expected_rule": "JWT-001",
        "expected_severity": "CRITICAL",
    },

    # ------------------------------------------------------------------
    # 7. GraphQL introspection enabled (graphene.Schema without introspection=False)
    # ------------------------------------------------------------------
    {
        "name": "graphql_introspection_enabled",
        "language": "python",
        "code": """\
import graphene
from graphene import ObjectType, String, List, Schema

class UserType(ObjectType):
    id    = String()
    email = String()
    role  = String()

class Query(ObjectType):
    users = List(UserType)

    def resolve_users(root, info):
        return fetch_all_users()

# No introspection=False — full schema exposed to any client in production
schema = graphene.Schema(query=Query)
""",
        "scanner": "graphql",
        "expected_rule": "GQL-010",
        "expected_severity": "MEDIUM",
    },

    # ------------------------------------------------------------------
    # 8. TON FunC — unguarded set_code (unauthorized upgrade) — CWE-284
    # ------------------------------------------------------------------
    {
        "name": "ton_unguarded_upgrade",
        "language": "func",
        "code": """\
() recv_internal(int my_balance, int msg_value, cell in_msg_full, slice in_msg_body) impure {
    int op = in_msg_body~load_uint(32);

    ;; Missing ownership check before allowing code upgrade
    if (op == 0xdeadbeef) {
        cell new_code = in_msg_body~load_ref();
        set_code(new_code);            ;; TON-UPG-001: anyone can replace contract code
        set_data(in_msg_body~load_ref());
    }
}
""",
        "scanner": "ton",
        "expected_rule": "TON-UPG-001",
        "expected_severity": "CRITICAL",
    },

    # ------------------------------------------------------------------
    # 9. Solidity reentrancy — balance deducted AFTER external call — CWE-841
    # ------------------------------------------------------------------
    {
        "name": "solidity_reentrancy",
        "language": "solidity",
        "code": """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableVault {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // Vulnerable: external call before state update (reentrancy vector)
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        // Balance decremented AFTER the call — attacker can re-enter withdraw()
        balances[msg.sender] -= amount;
    }
}
""",
        "scanner": "solidity",
        "expected_rule": "SOL001",
        "expected_severity": "CRITICAL",
    },

    # ------------------------------------------------------------------
    # 10. Python taint — subprocess injection from request arg — CWE-78
    # ------------------------------------------------------------------
    {
        "name": "taint_subprocess_injection",
        "language": "python",
        "code": """\
import subprocess
from flask import Flask, request

app = Flask(__name__)

@app.route('/ping')
def ping():
    host = request.args.get('host', 'localhost')
    # Vulnerable: user-supplied host passed directly to shell command
    result = subprocess.run(
        f'ping -c 1 {host}',
        shell=True,
        capture_output=True,
        text=True,
    )
    return result.stdout
""",
        "scanner": "taint",
        "expected_rule": "TAINT-SUBPROCESS",
        "expected_severity": "CRITICAL",
    },
]


# ===========================================================================
# FALSE-POSITIVE CORPUS
# Each snippet is genuinely safe.  The ``expected_no_rule`` must NOT appear
# in the scanner output.
# ===========================================================================

FALSE_POSITIVE_CORPUS: List[Dict[str, Any]] = [
    # ------------------------------------------------------------------
    # 1. Parameterized query — safe, must NOT fire SQL injection rule
    # ------------------------------------------------------------------
    {
        "name": "parameterized_query_safe",
        "language": "python",
        "code": """\
import sqlite3
from flask import request

def get_user(conn):
    user_id = request.args.get('id')
    cursor = conn.cursor()
    # Safe: using parameterized query placeholder
    cursor.execute('SELECT name, email FROM users WHERE id = ?', (user_id,))
    return cursor.fetchone()
""",
        "scanner": "owasp",
        "expected_no_rule": "OW-A03-001",
    },

    # ------------------------------------------------------------------
    # 2. Test file with test credentials — should not fire secret rule
    # ------------------------------------------------------------------
    {
        "name": "test_file_hardcoded_creds",
        "language": "python",
        "code": """\
import pytest
from myapp.auth import authenticate_user

# These are fixture credentials used ONLY in unit tests against a local
# in-memory database — not real production secrets.

TEST_USER     = 'fixture_user_do_not_deploy'
TEST_PASSWORD = 'test_only_not_production'


class TestAuthentication:
    def test_valid_login(self):
        result = authenticate_user(TEST_USER, TEST_PASSWORD)
        assert result is not None

    def test_invalid_password_rejected(self):
        result = authenticate_user(TEST_USER, 'wrongpassword')
        assert result is None

    def test_unknown_user_rejected(self):
        result = authenticate_user('no_such_user', TEST_PASSWORD)
        assert result is None
""",
        "scanner": "secret",
        "expected_no_rule": "SEC-AWS_ACCESS_KEY",
    },

    # ------------------------------------------------------------------
    # 3. SQL keyword appears only in a comment — must not fire SQL injection
    # ------------------------------------------------------------------
    {
        "name": "sql_in_comment",
        "language": "python",
        "code": """\
# Documentation example showing what NOT to do:
#   BAD:  cursor.execute(f\"SELECT * FROM users WHERE id={user_id}\")
#   GOOD: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))

def fetch_user(conn, user_id: int):
    \"\"\"
    Fetch a user row safely.

    Example query: SELECT id, name FROM users WHERE id = ?
    The query uses a positional placeholder to prevent SQL injection.
    \"\"\"
    cur = conn.cursor()
    cur.execute('SELECT id, name, email FROM users WHERE id = ?', (user_id,))
    return cur.fetchone()
""",
        "scanner": "owasp",
        "expected_no_rule": "OW-A03-001",
    },

    # ------------------------------------------------------------------
    # 4. JWT decode with explicit algorithm and valid secret — safe
    # ------------------------------------------------------------------
    {
        "name": "jwt_safe_verify",
        "language": "python",
        "code": """\
import jwt
import os
from flask import request

_SECRET = os.environ.get('JWT_SECRET', '')

def get_current_user():
    token = request.headers.get('Authorization', '').removeprefix('Bearer ')
    try:
        payload = jwt.decode(
            token,
            _SECRET,
            algorithms=['HS256'],     # explicit allow-list — none is excluded
        )
        return payload['user_id']
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None
""",
        "scanner": "jwt",
        "expected_no_rule": "JWT-001",
    },

    # ------------------------------------------------------------------
    # 5. GraphQL schema with introspection explicitly disabled — safe
    # ------------------------------------------------------------------
    {
        "name": "graphql_introspection_disabled",
        "language": "python",
        "code": """\
import graphene
from graphene import ObjectType, String, Schema

class Query(ObjectType):
    status = String()

    def resolve_status(root, info):
        return 'ok'

# introspection=False prevents schema enumeration in production environments
schema = graphene.Schema(query=Query, introspection=False)
""",
        "scanner": "graphql",
        "expected_no_rule": "GQL-010",
    },

    # ------------------------------------------------------------------
    # 6. Logging statement with user data — log injection low risk, not code injection
    # ------------------------------------------------------------------
    {
        "name": "logging_not_injection",
        "language": "python",
        "code": """\
import logging
from flask import request

_log = logging.getLogger(__name__)

def handle_upload():
    # Using %-style formatting prevents log-injection from altering structure
    filename = request.args.get('filename', 'unnamed')
    _log.info('File upload requested: %s', filename)
    # Process the file ...
    return {'status': 'queued', 'filename': filename}
""",
        "scanner": "owasp",
        "expected_no_rule": "OW-A03-001",
    },

    # ------------------------------------------------------------------
    # 7. Secrets loaded from environment — must not fire secret scanner
    # ------------------------------------------------------------------
    {
        "name": "env_var_secrets_safe",
        "language": "python",
        "code": """\
import os
import boto3

# All credentials loaded from environment — no hardcoded values
_aws_key    = os.environ.get('AWS_ACCESS_KEY_ID',     '')
_aws_secret = os.environ.get('AWS_SECRET_ACCESS_KEY', '')
_region     = os.environ.get('AWS_DEFAULT_REGION',    'us-east-1')

def get_s3_client():
    return boto3.client(
        's3',
        aws_access_key_id=_aws_key,
        aws_secret_access_key=_aws_secret,
        region_name=_region,
    )
""",
        "scanner": "secret",
        "expected_no_rule": "SEC-AWS_ACCESS_KEY",
    },
]


# ===========================================================================
# CorpusValidator
# ===========================================================================

class CorpusValidator:
    """
    Run corpus entries through the appropriate TythanAI scanner and
    compare actual findings against the expected outcome declared in each
    corpus entry.

    Supports both true-positive entries (``expected_rule`` must appear) and
    false-positive entries (``expected_no_rule`` must NOT appear).
    """

    # Map scanner names used in corpus entries to callables
    _SCANNER_MAP: Dict[str, str] = {
        "owasp":    "_run_owasp",
        "java":     "_run_java",
        "go":       "_run_go",
        "secret":   "_run_secret",
        "jwt":      "_run_jwt",
        "graphql":  "_run_graphql",
        "ton":      "_run_ton",
        "solidity": "_run_solidity",
        "taint":    "_run_taint",
    }

    # Map language names to file extensions
    _EXT_MAP: Dict[str, str] = {
        "python":     ".py",
        "javascript": ".js",
        "java":       ".java",
        "go":         ".go",
        "func":       ".fc",
        "solidity":   ".sol",
        "yaml":       ".yaml",
    }

    def validate_entry(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate a single corpus entry.

        Returns a dict with keys:
            ``passed``   — bool
            ``reason``   — human-readable explanation
            ``findings`` — list of raw finding dicts from the scanner
        """
        is_tp = "expected_rule" in entry
        scanner_name = entry.get("scanner", "owasp")
        method_name  = self._SCANNER_MAP.get(scanner_name)

        if method_name is None:
            return {
                "passed":   False,
                "reason":   f"Unknown scanner '{scanner_name}'",
                "findings": [],
            }

        scanner_fn = getattr(self, method_name, None)
        if scanner_fn is None:
            return {
                "passed":   False,
                "reason":   f"Scanner method '{method_name}' not implemented",
                "findings": [],
            }

        code     = entry.get("code", "")
        language = entry.get("language", "python")
        ext      = self._EXT_MAP.get(language, ".py")

        findings: List[Dict] = []
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=ext, delete=False, encoding="utf-8"
            ) as tmp:
                tmp.write(code)
                tmp_path = tmp.name

            findings = scanner_fn(tmp_path)
        except Exception as exc:
            return {
                "passed":   False,
                "reason":   f"Scanner raised exception: {exc}",
                "findings": [],
            }
        finally:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass

        finding_ids = {f.get("id", "") for f in findings}

        if is_tp:
            expected = entry["expected_rule"]
            matched  = any(fid.startswith(expected) or fid == expected for fid in finding_ids)
            if matched:
                return {"passed": True, "reason": f"Found expected rule '{expected}'", "findings": findings}
            else:
                return {
                    "passed": False,
                    "reason": (
                        f"Expected rule '{expected}' not found. "
                        f"Got: {sorted(finding_ids) or '(no findings)'}"
                    ),
                    "findings": findings,
                }
        else:
            excluded = entry["expected_no_rule"]
            matched  = any(fid.startswith(excluded) or fid == excluded for fid in finding_ids)
            if not matched:
                return {
                    "passed": True,
                    "reason": f"Rule '{excluded}' correctly absent",
                    "findings": findings,
                }
            else:
                triggered = [f for f in findings if (f.get("id","")).startswith(excluded)]
                return {
                    "passed": False,
                    "reason": (
                        f"False-positive: rule '{excluded}' fired but should not. "
                        f"Evidence: {triggered[0].get('evidence','')[:80] if triggered else '?'}"
                    ),
                    "findings": findings,
                }

    def validate_all(self, corpus: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Validate every entry in *corpus*.

        Returns::

            {
                "total":   int,
                "passed":  int,
                "failed":  int,
                "details": [{"name": str, "passed": bool, "reason": str, "findings": [...]}]
            }
        """
        details: List[Dict] = []
        passed  = 0
        failed  = 0

        for entry in corpus:
            result = self.validate_entry(entry)
            details.append({
                "name":     entry.get("name", "<unnamed>"),
                "passed":   result["passed"],
                "reason":   result["reason"],
                "findings": result["findings"],
            })
            if result["passed"]:
                passed += 1
            else:
                failed += 1

        return {
            "total":   len(corpus),
            "passed":  passed,
            "failed":  failed,
            "details": details,
        }

    def report(self, results: Dict[str, Any]) -> str:
        """Return a human-readable summary report of *validate_all* output."""
        total  = results.get("total",  0)
        passed = results.get("passed", 0)
        failed = results.get("failed", 0)
        rate   = (passed / total * 100) if total else 0.0
        details: List[Dict] = results.get("details", [])

        lines = [
            "=" * 68,
            "TythanAI — Corpus Validation Report",
            "=" * 68,
            f"Total entries : {total}",
            f"Passed        : {passed}  ({rate:.1f}%)",
            f"Failed        : {failed}",
            "-" * 68,
        ]

        for item in details:
            icon = "PASS" if item["passed"] else "FAIL"
            lines.append(f"[{icon}]  {item['name']}")
            if not item["passed"]:
                lines.append(f"       Reason: {item['reason']}")

        lines.append("=" * 68)
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Private scanner runners — each accepts a temp file path and returns
    # a list of finding dicts.
    # ------------------------------------------------------------------

    def _run_owasp(self, path: str) -> List[Dict]:
        from scanners.owasp_scanner import OWASPScanner
        return OWASPScanner().scan_file(path)

    def _run_java(self, path: str) -> List[Dict]:
        from scanners.java_scanner import JavaScanner
        return JavaScanner().scan_file(path)

    def _run_go(self, path: str) -> List[Dict]:
        from scanners.go_scanner import GoScanner
        return GoScanner().scan_file(path)

    def _run_secret(self, path: str) -> List[Dict]:
        from scanners.secret_scanner.secret_detector import SecretDetector
        return SecretDetector().scan_file(path)

    def _run_jwt(self, path: str) -> List[Dict]:
        from scanners.jwt_scanner import JWTScanner
        return JWTScanner().scan_file(path)

    def _run_graphql(self, path: str) -> List[Dict]:
        from scanners.graphql_scanner import GraphQLScanner
        return GraphQLScanner().scan_file(path)

    def _run_ton(self, path: str) -> List[Dict]:
        from scanners.ton_scanner.ton_analyzer import TONAnalyzer
        return TONAnalyzer().analyze_file(path)

    def _run_solidity(self, path: str) -> List[Dict]:
        from scanners.solidity_scanner import SolidityScanner
        return SolidityScanner().analyze_file(path)

    def _run_taint(self, path: str) -> List[Dict]:
        from core.analysis.taint_tracker import TaintTracker
        return TaintTracker().analyze_file(path)
