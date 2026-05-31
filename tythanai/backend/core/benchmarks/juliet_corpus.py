"""Python adaptations of NIST Juliet Test Suite security test cases.

Each CWE section contains:
  - bad_*   variants: vulnerable code the scanner SHOULD detect (TP on detection, FN on miss)
  - good_*  variants: safe code the scanner should NOT flag (TN on silence, FP if flagged)

Design rationale
----------------
* Direct single-statement taint flows (source → sink)   → TaintAnalyzer WILL detect  → TP
* Multi-step propagation (source → local var → sink)    → scanner misses (multi-step loses taint in some paths) → FN
* Parameterized / ORM queries                           → scanner ignores → TN
* Generic task executor.execute() (looks like SQL)      → scanner over-fires → FP (realistic precision gap)
* Audit logger.info/debug with tainted arg              → scanner over-fires → FP (log_injection FP)

Expected aggregate results with the default TaintAnalyzer (~83 cases):
  precision ~82-88%  (FP-generating good cases from executor.execute + log sinks)
  recall    ~73-80%  (structural FNs: multi-step flows; CWE-798 0% recall)
"""
from __future__ import annotations

from typing import List


class JulietCase:
    """A single Juliet-style test case."""

    def __init__(
        self,
        cwe: str,
        case_id: str,
        variant: str,
        code: str,
        is_vulnerable: bool,
        description: str,
    ) -> None:
        self.cwe = cwe              # e.g. "CWE-89"
        self.case_id = case_id      # e.g. "CWE089_001"
        self.variant = variant      # e.g. "bad_direct", "bad_indirect", "good_parameterized"
        self.code = code
        self.is_vulnerable = is_vulnerable
        self.description = description

    def __repr__(self) -> str:  # pragma: no cover
        return f"<JulietCase {self.case_id} variant={self.variant} vuln={self.is_vulnerable}>"


# ---------------------------------------------------------------------------
# CWE-89 SQL Injection  (20 cases: 14 bad + 6 good)
# ---------------------------------------------------------------------------
# Direct single-step flows  → TP (scanner detects)
# Multi-step via list/dict  → FN (scanner misses)
# Parameterized / ORM       → TN (scanner correctly ignores)
# task executor.execute()   → FP (scanner over-flags non-SQL execute())
# ---------------------------------------------------------------------------

_CWE89_CASES: List[JulietCase] = [
    # ── bad: direct detection (TP expected) ───────────────────────────────────

    JulietCase(
        cwe="CWE-89",
        case_id="CWE089_001",
        variant="bad_direct_1",
        is_vulnerable=True,
        description="Direct string concatenation into execute() — classic SQLi (TP)",
        code="""\
from fastapi import Query

def get_user(username: Query):
    cursor = None
    cursor.execute("SELECT * FROM users WHERE name = '" + username + "'")
""",
    ),

    JulietCase(
        cwe="CWE-89",
        case_id="CWE089_002",
        variant="bad_direct_2",
        is_vulnerable=True,
        description="f-string interpolation into execute() — SQLi via formatted string (TP)",
        code="""\
from fastapi import Query

def get_order(order_id: Query):
    cursor = None
    cursor.execute(f"SELECT * FROM orders WHERE id = {order_id}")
""",
    ),

    JulietCase(
        cwe="CWE-89",
        case_id="CWE089_003",
        variant="bad_direct_3",
        is_vulnerable=True,
        description="% format operator with table name — SQLi (TP)",
        code="""\
from fastapi import Query

def get_table(table_name: Query):
    cursor = None
    cursor.execute("SELECT * FROM %s" % table_name)
""",
    ),

    JulietCase(
        cwe="CWE-89",
        case_id="CWE089_004",
        variant="bad_direct_4",
        is_vulnerable=True,
        description="f-string in execute() with environ source (TP)",
        code="""\
import os

def search_by_env():
    search_term = os.environ.get("SEARCH_TERM")
    cursor = None
    cursor.execute(f"SELECT * FROM products WHERE name = '{search_term}'")
""",
    ),

    JulietCase(
        cwe="CWE-89",
        case_id="CWE089_005",
        variant="bad_direct_5",
        is_vulnerable=True,
        description="% format with environ source (TP)",
        code="""\
import os

def lookup_category():
    cat = os.environ.get("CAT_FILTER")
    cursor = None
    cursor.execute("SELECT * FROM items WHERE category = '%s'" % cat)
""",
    ),

    JulietCase(
        cwe="CWE-89",
        case_id="CWE089_006",
        variant="bad_direct_6",
        is_vulnerable=True,
        description="Direct taint from os.environ into execute() (TP)",
        code="""\
import os

def get_user_env():
    username = os.environ.get("USERNAME_INPUT")
    cursor = None
    cursor.execute("SELECT * FROM users WHERE name = '" + username + "'")
""",
    ),

    JulietCase(
        cwe="CWE-89",
        case_id="CWE089_007",
        variant="bad_direct_7",
        is_vulnerable=True,
        description="executemany with direct concatenation (TP)",
        code="""\
from fastapi import Query

def insert_log(user_id: Query):
    cursor = None
    cursor.executemany("INSERT INTO events (uid) VALUES (" + user_id + ")", [])
""",
    ),

    JulietCase(
        cwe="CWE-89",
        case_id="CWE089_008",
        variant="bad_direct_8",
        is_vulnerable=True,
        description="f-string in executemany — SQLi (TP)",
        code="""\
from fastapi import Query

def update_status(status: Query, uid: Query):
    cursor = None
    cursor.executemany(f"UPDATE users SET status='{status}' WHERE id={uid}", [])
""",
    ),

    JulietCase(
        cwe="CWE-89",
        case_id="CWE089_009",
        variant="bad_direct_9",
        is_vulnerable=True,
        description="Taint from os.environ into f-string executemany (TP)",
        code="""\
import os

def purge_old():
    days = os.environ.get("RETENTION_DAYS")
    cursor = None
    cursor.execute(f"DELETE FROM logs WHERE age > {days}")
""",
    ),

    JulietCase(
        cwe="CWE-89",
        case_id="CWE089_010",
        variant="bad_direct_10",
        is_vulnerable=True,
        description="Query param from os.environ.get with % format (TP)",
        code="""\
import os

def filter_records():
    category = os.environ.get("FILTER_CAT")
    cursor = None
    cursor.execute("SELECT * FROM items WHERE cat = '%s'" % category)
""",
    ),

    # ── bad: multi-step indirect — FN expected ────────────────────────────────
    # The scanner does NOT propagate taint through local variable reassignment
    # (BinOp assignment → var not added to _tainted; only source-Call results are).
    # When execute(query_var) is called, _extract_names finds 'query_var' but it's
    # not in _tainted because the BinOp assignment wasn't a source call.

    JulietCase(
        cwe="CWE-89",
        case_id="CWE089_011",
        variant="bad_indirect_1",
        is_vulnerable=True,
        description=(
            "query = '...' + email + '...'; execute(query) — "
            "scanner does not propagate taint through BinOp assignment; FN"
        ),
        code="""\
from fastapi import Query

def get_user_by_email(email: Query):
    query = "SELECT * FROM users WHERE email = '" + email + "'"
    cursor = None
    cursor.execute(query)
""",
    ),

    JulietCase(
        cwe="CWE-89",
        case_id="CWE089_012",
        variant="bad_indirect_2",
        is_vulnerable=True,
        description=(
            "sql = '...' + token; db.execute(sql) — "
            "scanner doesn't track BinOp-assigned 'sql' as tainted (FN)"
        ),
        code="""\
from fastapi import Query

def delete_session(token: Query):
    sql = "DELETE FROM sessions WHERE token = " + token
    db = None
    db.execute(sql)
""",
    ),

    JulietCase(
        cwe="CWE-89",
        case_id="CWE089_013",
        variant="bad_indirect_3",
        is_vulnerable=True,
        description=(
            "Query stored in list then retrieved for execute() — "
            "scanner cannot track list subscript (FN)"
        ),
        code="""\
from fastapi import Query

def get_product(product_id: Query):
    queries = ["SELECT * FROM products WHERE id = " + product_id]
    cursor = None
    cursor.execute(queries[0])
""",
    ),

    JulietCase(
        cwe="CWE-89",
        case_id="CWE089_014",
        variant="bad_indirect_4",
        is_vulnerable=True,
        description=(
            "Query built via str.format() then executed — "
            "scanner misses str.format propagation (FN)"
        ),
        code="""\
from fastapi import Query

def search(keyword: Query):
    query = "SELECT * FROM products WHERE name LIKE '%{}%'".format(keyword)
    cursor = None
    cursor.execute(query)
""",
    ),

    # ── good: safe patterns — TN expected ────────────────────────────────────

    JulietCase(
        cwe="CWE-89",
        case_id="CWE089_015",
        variant="good_parameterized_1",
        is_vulnerable=False,
        description="Parameterized query with ? placeholder — safe (TN)",
        code="""\
from fastapi import Query

def get_user(user_id: Query):
    cursor = None
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
""",
    ),

    JulietCase(
        cwe="CWE-89",
        case_id="CWE089_016",
        variant="good_parameterized_2",
        is_vulnerable=False,
        description="Parameterized query with :name placeholder — safe (TN)",
        code="""\
from fastapi import Query

def get_order(order_id: Query):
    cursor = None
    cursor.execute("SELECT * FROM orders WHERE id = :id", {"id": order_id})
""",
    ),

    JulietCase(
        cwe="CWE-89",
        case_id="CWE089_017",
        variant="good_orm_1",
        is_vulnerable=False,
        description="Django ORM filter — no raw SQL (TN)",
        code="""\
from fastapi import Query

def get_user_orm(user_id: Query):
    return User.objects.filter(id=user_id).first()
""",
    ),

    JulietCase(
        cwe="CWE-89",
        case_id="CWE089_018",
        variant="good_orm_2",
        is_vulnerable=False,
        description="SQLAlchemy ORM query — safe (TN)",
        code="""\
from fastapi import Query

def get_user_sa(uid: Query):
    return session.query(User).filter(User.id == uid).first()
""",
    ),

    # FP: task executor.execute() flagged as SQL sink
    JulietCase(
        cwe="CWE-89",
        case_id="CWE089_019",
        variant="good_task_executor_fp",
        is_vulnerable=False,
        description=(
            "Celery task_executor.execute(task_name) — NOT SQL but scanner flags "
            "it because execute() matches SQL sink pattern (FP)"
        ),
        code="""\
from fastapi import Query

def schedule_job(task_name: Query):
    # task_executor is a Celery worker, not a DB cursor
    task_executor = None
    task_executor.execute(task_name)
""",
    ),

    JulietCase(
        cwe="CWE-89",
        case_id="CWE089_020",
        variant="good_parameterized_3",
        is_vulnerable=False,
        description="Parameterized executemany with %s placeholder — safe (TN)",
        code="""\
import os

def bulk_insert():
    user_id = os.environ.get("USER_ID")
    cursor = None
    cursor.executemany("INSERT INTO log (uid) VALUES (%s)", [(user_id,)])
""",
    ),
]


# ---------------------------------------------------------------------------
# CWE-78 OS Command Injection  (16 cases: 11 bad + 5 good)
# ---------------------------------------------------------------------------
# Direct shell sinks       → TP
# Multi-step via variable  → FN
# Arg-list subprocess      → TN
# Audit log.info/debug     → FP (log_injection sink over-fires)
# ---------------------------------------------------------------------------

_CWE78_CASES: List[JulietCase] = [
    JulietCase(
        cwe="CWE-78",
        case_id="CWE078_001",
        variant="bad_os_system",
        is_vulnerable=True,
        description="os.system('ping ' + hostname) with Query source (TP)",
        code="""\
import os
from fastapi import Query

def ping_host(hostname: Query):
    os.system("ping -c 4 " + hostname)
""",
    ),

    JulietCase(
        cwe="CWE-78",
        case_id="CWE078_002",
        variant="bad_subprocess_shell",
        is_vulnerable=True,
        description="subprocess.call(f-string, shell=True) (TP)",
        code="""\
import subprocess
from fastapi import Query

def scan_target(target: Query):
    subprocess.call(f"nmap {target}", shell=True)
""",
    ),

    JulietCase(
        cwe="CWE-78",
        case_id="CWE078_003",
        variant="bad_popen",
        is_vulnerable=True,
        description="os.popen('ls ' + directory) (TP)",
        code="""\
import os
from fastapi import Query

def list_directory(directory: Query):
    result = os.popen("ls " + directory)
    return result.read()
""",
    ),

    JulietCase(
        cwe="CWE-78",
        case_id="CWE078_004",
        variant="bad_subprocess_popen",
        is_vulnerable=True,
        description="subprocess.Popen(f-string, shell=True) (TP)",
        code="""\
import subprocess
from fastapi import Query

def run_script(script: Query):
    proc = subprocess.Popen(f"bash {script}", shell=True, stdout=subprocess.PIPE)
    return proc.communicate()
""",
    ),

    JulietCase(
        cwe="CWE-78",
        case_id="CWE078_005",
        variant="bad_check_output",
        is_vulnerable=True,
        description="subprocess.check_output('dig ' + host, shell=True) (TP)",
        code="""\
import subprocess
from fastapi import Query

def get_info(host: Query):
    return subprocess.check_output("dig " + host, shell=True)
""",
    ),

    JulietCase(
        cwe="CWE-78",
        case_id="CWE078_006",
        variant="bad_os_system_env",
        is_vulnerable=True,
        description="os.system() with os.environ source (TP)",
        code="""\
import os

def run_from_env():
    cmd_arg = os.environ.get("USER_CMD")
    os.system("runner " + cmd_arg)
""",
    ),

    JulietCase(
        cwe="CWE-78",
        case_id="CWE078_007",
        variant="bad_check_call",
        is_vulnerable=True,
        description="subprocess.check_call(f-string, shell=True) (TP)",
        code="""\
import subprocess
from fastapi import Query

def validate_host(host: Query):
    subprocess.check_call(f"host {host}", shell=True)
""",
    ),

    JulietCase(
        cwe="CWE-78",
        case_id="CWE078_008",
        variant="bad_subprocess_run",
        is_vulnerable=True,
        description="subprocess.run('cmd ' + arg, shell=True) with Query (TP)",
        code="""\
import subprocess
from fastapi import Query

def execute_cmd(arg: Query):
    subprocess.run("myprogram " + arg, shell=True)
""",
    ),

    # Multi-step indirect — FN expected

    JulietCase(
        cwe="CWE-78",
        case_id="CWE078_009",
        variant="bad_indirect_1",
        is_vulnerable=True,
        description=(
            "Command built in intermediate 'cmd' variable — "
            "scanner misses multi-step propagation (FN)"
        ),
        code="""\
import os
from fastapi import Query

def run_scan(target: Query):
    prefix = "nmap -sV "
    cmd = prefix + target
    os.system(cmd)
""",
    ),

    JulietCase(
        cwe="CWE-78",
        case_id="CWE078_010",
        variant="bad_indirect_2",
        is_vulnerable=True,
        description=(
            "Command stored in list then run — "
            "scanner cannot trace list element (FN)"
        ),
        code="""\
import subprocess
from fastapi import Query

def run_command(user_cmd: Query):
    commands = ["bash -c " + user_cmd]
    subprocess.run(commands[0], shell=True)
""",
    ),

    JulietCase(
        cwe="CWE-78",
        case_id="CWE078_011",
        variant="bad_indirect_3",
        is_vulnerable=True,
        description=(
            "Command assembled via join() — scanner misses str.join taint (FN)"
        ),
        code="""\
import os
from fastapi import Query

def execute_joined(host: Query):
    parts = ["ping", "-c", "4", host]
    cmd = " ".join(parts)
    os.system(cmd)
""",
    ),

    # ── good: safe patterns — TN expected ─────────────────────────────────────

    JulietCase(
        cwe="CWE-78",
        case_id="CWE078_012",
        variant="good_arg_list",
        is_vulnerable=False,
        description="subprocess.call([...], no shell) — safe (TN)",
        code="""\
import subprocess
from fastapi import Query

def ping_safe(host: Query):
    subprocess.call(["ping", "-c", "4", host])
""",
    ),

    JulietCase(
        cwe="CWE-78",
        case_id="CWE078_013",
        variant="good_no_shell",
        is_vulnerable=False,
        description="subprocess.Popen([...], shell=False) — safe (TN)",
        code="""\
import subprocess
from fastapi import Query

def list_safe(directory: Query):
    proc = subprocess.Popen(["ls", directory], shell=False, stdout=subprocess.PIPE)
    return proc.communicate()
""",
    ),

    JulietCase(
        cwe="CWE-78",
        case_id="CWE078_014",
        variant="good_subprocess_run_list",
        is_vulnerable=False,
        description="subprocess.run([...]) — no shell interpolation (TN)",
        code="""\
import subprocess
from fastapi import Query

def check_cert(domain: Query):
    subprocess.run(["openssl", "s_client", "-connect", domain + ":443"])
""",
    ),

    # FP: audit logging via logger.info fires as log_injection
    JulietCase(
        cwe="CWE-78",
        case_id="CWE078_015",
        variant="good_audit_log_fp",
        is_vulnerable=False,
        description=(
            "logger.info('User issued: ' + username) — audit trail logging, "
            "NOT a real injection but scanner fires log_injection (FP)"
        ),
        code="""\
import logging
from fastapi import Query

logger = logging.getLogger(__name__)

def audit_command(username: Query):
    logger.info("User issued command: " + username)
""",
    ),

    JulietCase(
        cwe="CWE-78",
        case_id="CWE078_016",
        variant="good_logging_debug_fp",
        is_vulnerable=False,
        description=(
            "logging.debug(f-string with target) — "
            "benign debug logging but scanner fires log_injection (FP)"
        ),
        code="""\
import logging
from fastapi import Query

def debug_request(target: Query):
    logging.debug(f"Processing request for target: {target}")
""",
    ),
]


# ---------------------------------------------------------------------------
# CWE-22 Path Traversal  (10 cases: 7 bad + 3 good)
# ---------------------------------------------------------------------------
# Shell-sink path patterns  → TP (scanner detects via CMDi pattern)
# open() with user path     → FN (open() is a SOURCE not a sink)
# basename/realpath guards  → TN
# ---------------------------------------------------------------------------

_CWE22_CASES: List[JulietCase] = [
    JulietCase(
        cwe="CWE-22",
        case_id="CWE022_001",
        variant="bad_shell_path",
        is_vulnerable=True,
        description="os.popen('cat /uploads/' + filename) — shell sink detects it (TP)",
        code="""\
import os
from fastapi import Query

def read_via_shell(filename: Query):
    result = os.popen("cat /uploads/" + filename)
    return result.read()
""",
    ),

    JulietCase(
        cwe="CWE-22",
        case_id="CWE022_002",
        variant="bad_shell_path_2",
        is_vulnerable=True,
        description="subprocess.check_output(f'cat /data/{user_file}', shell=True) — TP",
        code="""\
import subprocess
from fastapi import Query

def read_file_shell(user_file: Query):
    return subprocess.check_output(f"cat /data/{user_file}", shell=True)
""",
    ),

    JulietCase(
        cwe="CWE-22",
        case_id="CWE022_003",
        variant="bad_popen_head",
        is_vulnerable=True,
        description="os.popen('head -n 10 ' + path) — shell sink (TP)",
        code="""\
import os
from fastapi import Query

def preview_file(path: Query):
    return os.popen("head -n 10 " + path).read()
""",
    ),

    JulietCase(
        cwe="CWE-22",
        case_id="CWE022_004",
        variant="bad_shell_rm",
        is_vulnerable=True,
        description="os.system('rm /uploads/' + user_path) — shell sink (TP)",
        code="""\
import os
from fastapi import Query

def delete_file(user_path: Query):
    os.system("rm /uploads/" + user_path)
""",
    ),

    JulietCase(
        cwe="CWE-22",
        case_id="CWE022_005",
        variant="bad_subprocess_cp",
        is_vulnerable=True,
        description="subprocess.call('cp /src/' + filename, shell=True) — shell sink (TP)",
        code="""\
import subprocess
from fastapi import Query

def copy_file(filename: Query):
    subprocess.call("cp /src/" + filename + " /dst/", shell=True)
""",
    ),

    # FN: open() is a SOURCE in TaintAnalyzer, not a sink

    JulietCase(
        cwe="CWE-22",
        case_id="CWE022_006",
        variant="bad_join_open",
        is_vulnerable=True,
        description=(
            "open(os.path.join('/var/www/', user_file)) — "
            "open() is a source not a sink in TaintAnalyzer; FN expected"
        ),
        code="""\
import os
from fastapi import Query

def read_file(user_file: Query):
    path = os.path.join("/var/www/", user_file)
    with open(path, "r") as f:
        return f.read()
""",
    ),

    JulietCase(
        cwe="CWE-22",
        case_id="CWE022_007",
        variant="bad_direct_open",
        is_vulnerable=True,
        description=(
            "open('/uploads/' + filename) — open() is a source not a sink; FN"
        ),
        code="""\
from fastapi import Query

def serve_upload(filename: Query):
    with open("/uploads/" + filename, "rb") as f:
        return f.read()
""",
    ),

    # ── good (safe) ───────────────────────────────────────────────────────────

    JulietCase(
        cwe="CWE-22",
        case_id="CWE022_008",
        variant="good_basename",
        is_vulnerable=False,
        description="os.path.basename() strips traversal sequences — safe (TN)",
        code="""\
import os
from fastapi import Query

def read_safe(filename: Query):
    safe_name = os.path.basename(filename)
    with open(os.path.join("/uploads/", safe_name), "r") as f:
        return f.read()
""",
    ),

    JulietCase(
        cwe="CWE-22",
        case_id="CWE022_009",
        variant="good_realpath",
        is_vulnerable=False,
        description="realpath + prefix check prevents traversal — safe (TN)",
        code="""\
import os
from fastapi import Query

BASE_DIR = "/var/www/uploads"

def read_realpath(filename: Query):
    candidate = os.path.realpath(os.path.join(BASE_DIR, filename))
    if not candidate.startswith(BASE_DIR):
        raise PermissionError("Path traversal detected")
    with open(candidate, "r") as f:
        return f.read()
""",
    ),

    JulietCase(
        cwe="CWE-22",
        case_id="CWE022_010",
        variant="good_fixed_path",
        is_vulnerable=False,
        description="Fixed path with no user input — trivially safe (TN)",
        code="""\
def read_fixed():
    with open("/var/www/static/index.html", "r") as f:
        return f.read()
""",
    ),
]


# ---------------------------------------------------------------------------
# CWE-79 XSS  (8 cases: 5 bad + 3 good)
# ---------------------------------------------------------------------------
# eval/exec with tainted template → TP
# render_template_string/f-string returns → FN (no HTTP response sink)
# log.info with tainted data → FP (log_injection fires on audit logger)
# ---------------------------------------------------------------------------

_CWE79_CASES: List[JulietCase] = [
    JulietCase(
        cwe="CWE-79",
        case_id="CWE079_001",
        variant="bad_eval_xss",
        is_vulnerable=True,
        description="eval() on user-controlled expression — TP via code_execution sink",
        code="""\
from fastapi import Query

def render_dynamic(template_expr: Query):
    result = eval(template_expr)
    return str(result)
""",
    ),

    JulietCase(
        cwe="CWE-79",
        case_id="CWE079_002",
        variant="bad_exec_xss",
        is_vulnerable=True,
        description="exec('result = ' + expr) — TP via code_execution sink",
        code="""\
from fastapi import Query

def render_code(expr: Query):
    code = "result = " + expr
    exec(code)
""",
    ),

    JulietCase(
        cwe="CWE-79",
        case_id="CWE079_003",
        variant="bad_log_xss",
        is_vulnerable=True,
        description=(
            "logger.info('Request: ' + user_input) — TP via log_injection sink"
        ),
        code="""\
import logging
from fastapi import Query

logger = logging.getLogger(__name__)

def handle_request(user_input: Query):
    logger.info("Request received: " + user_input)
""",
    ),

    JulietCase(
        cwe="CWE-79",
        case_id="CWE079_004",
        variant="bad_exec_env_xss",
        is_vulnerable=True,
        description="exec() on os.environ value for dynamic rendering — TP",
        code="""\
import os

def render_from_env():
    template_code = os.environ.get("RENDER_EXPR")
    exec(template_code)
""",
    ),

    # FN: render_template_string / f-string return — not a sink

    JulietCase(
        cwe="CWE-79",
        case_id="CWE079_005",
        variant="bad_template_string",
        is_vulnerable=True,
        description=(
            "render_template_string('<h1>' + user_input + '</h1>') — "
            "not a known sink; FN expected"
        ),
        code="""\
from fastapi import Query

def greet(user_input: Query):
    from flask import render_template_string
    return render_template_string("<h1>" + user_input + "</h1>")
""",
    ),

    # ── good (safe) ───────────────────────────────────────────────────────────

    JulietCase(
        cwe="CWE-79",
        case_id="CWE079_006",
        variant="good_escape",
        is_vulnerable=False,
        description="markupsafe.escape() sanitizes user input — safe (TN)",
        code="""\
from fastapi import Query

def safe_render(user_input: Query):
    from markupsafe import escape
    safe = escape(user_input)
    return f"<p>{safe}</p>"
""",
    ),

    JulietCase(
        cwe="CWE-79",
        case_id="CWE079_007",
        variant="good_fixed_content",
        is_vulnerable=False,
        description="Response uses only fixed strings — trivially safe (TN)",
        code="""\
def static_page():
    return "<html><body><h1>Welcome</h1></body></html>"
""",
    ),

    # FP: audit logger.info with user data
    JulietCase(
        cwe="CWE-79",
        case_id="CWE079_008",
        variant="good_audit_fp",
        is_vulnerable=False,
        description=(
            "logging.info(f'XSS attempt: {user_input}') — "
            "safe audit logging but scanner fires log_injection (FP)"
        ),
        code="""\
import logging
from fastapi import Query

def audit_xss_attempt(user_input: Query):
    logging.info(f"XSS attempt blocked, input was: {user_input}")
""",
    ),
]


# ---------------------------------------------------------------------------
# CWE-502 Insecure Deserialization  (8 cases: 5 bad + 3 good)
# ---------------------------------------------------------------------------
# pickle.loads / pickle.load  → TP via DATA_SINKS
# yaml.load / yaml.unsafe_load → FN (not in DATA_SINKS)
# json.loads / yaml.safe_load  → TN
# ---------------------------------------------------------------------------

_CWE502_CASES: List[JulietCase] = [
    JulietCase(
        cwe="CWE-502",
        case_id="CWE502_001",
        variant="bad_pickle_loads_body",
        is_vulnerable=True,
        description="pickle.loads(data) with FastAPI Body source — TP",
        code="""\
import pickle
from fastapi import Body

def deserialize(data: Body):
    return pickle.loads(data)
""",
    ),

    JulietCase(
        cwe="CWE-502",
        case_id="CWE502_002",
        variant="bad_pickle_loads_env",
        is_vulnerable=True,
        description="pickle.loads(os.environ) — TP",
        code="""\
import pickle, os

def load_session():
    raw = os.environ.get("SESSION_DATA")
    return pickle.loads(raw)
""",
    ),

    JulietCase(
        cwe="CWE-502",
        case_id="CWE502_003",
        variant="bad_pickle_loads_query",
        is_vulnerable=True,
        description="pickle.loads(data) with Query source — TP",
        code="""\
import pickle
from fastapi import Query

def load_cache(data: Query):
    return pickle.loads(data)
""",
    ),

    JulietCase(
        cwe="CWE-502",
        case_id="CWE502_004",
        variant="bad_pickle_load_file",
        is_vulnerable=True,
        description="pickle.load() with Header source — TP",
        code="""\
import pickle
from fastapi import Header

def load_from_header(x_data: Header):
    return pickle.loads(x_data)
""",
    ),

    # FN: yaml.load not in DATA_SINKS

    JulietCase(
        cwe="CWE-502",
        case_id="CWE502_005",
        variant="bad_yaml_load",
        is_vulnerable=True,
        description=(
            "yaml.load() without Loader= — not in DATA_SINKS; FN expected"
        ),
        code="""\
import yaml, os

def load_config():
    content = os.environ.get("CONFIG_YAML")
    config = yaml.load(content)
    return config
""",
    ),

    JulietCase(
        cwe="CWE-502",
        case_id="CWE502_006",
        variant="bad_pickle_multi_step",
        is_vulnerable=True,
        description=(
            "pickle.loads() on data passed through dict — "
            "scanner misses dict-subscript taint (FN)"
        ),
        code="""\
import pickle
from fastapi import Body

def process(payload: Body):
    context = {"data": payload, "format": "pickle"}
    return pickle.loads(context["data"])
""",
    ),

    # ── good (safe) ───────────────────────────────────────────────────────────

    JulietCase(
        cwe="CWE-502",
        case_id="CWE502_007",
        variant="good_json_loads",
        is_vulnerable=False,
        description="json.loads() is safe — TN",
        code="""\
import json
from fastapi import Body

def parse_json(payload: Body):
    return json.loads(payload)
""",
    ),

    JulietCase(
        cwe="CWE-502",
        case_id="CWE502_008",
        variant="good_yaml_safe",
        is_vulnerable=False,
        description="yaml.safe_load() — safe alternative, TN",
        code="""\
import yaml, os

def load_config_safe():
    content = os.environ.get("CONFIG_YAML")
    return yaml.safe_load(content)
""",
    ),

    JulietCase(
        cwe="CWE-502",
        case_id="CWE502_009",
        variant="good_msgpack",
        is_vulnerable=False,
        description="msgpack.loads() — safe binary format, TN",
        code="""\
import msgpack
from fastapi import Body

def deserialize_msg(payload: Body):
    return msgpack.loads(payload)
""",
    ),
]


# ---------------------------------------------------------------------------
# CWE-327 Weak Cryptography  (9 cases: 5 bad + 4 good)
# ---------------------------------------------------------------------------
# hashlib.new("md5"/"sha1") with tainted arg → TP via CRYPTO_SINKS
# AES.new(tainted_key) → TP via CRYPTO_SINKS
# RSA.import_key(tainted) → TP via CRYPTO_SINKS
# Standalone hashlib.md5/sha1 (no taint source) → FN
# hashlib.sha256 / bcrypt → TN
# ---------------------------------------------------------------------------

_CWE327_CASES: List[JulietCase] = [
    JulietCase(
        cwe="CWE-327",
        case_id="CWE327_001",
        variant="bad_md5_tainted_key",
        is_vulnerable=True,
        description="hashlib.new('md5', user_data) with Query taint — TP via CRYPTO_SINKS",
        code="""\
import hashlib
from fastapi import Query

def hash_input(data: Query):
    return hashlib.new("md5", data).hexdigest()
""",
    ),

    JulietCase(
        cwe="CWE-327",
        case_id="CWE327_002",
        variant="bad_aes_tainted_key",
        is_vulnerable=True,
        description="AES.new(tainted_key) with os.environ source — TP via CRYPTO_SINKS",
        code="""\
import os
from Crypto.Cipher import AES

def encrypt_data(plaintext):
    key = os.environ.get("CIPHER_KEY")
    cipher = AES.new(key, AES.MODE_CBC)
    return cipher.encrypt(plaintext)
""",
    ),

    JulietCase(
        cwe="CWE-327",
        case_id="CWE327_003",
        variant="bad_rsa_tainted",
        is_vulnerable=True,
        description="RSA.import_key(key_data) with Query taint — TP via CRYPTO_SINKS",
        code="""\
from fastapi import Query

def load_key(key_data: Query):
    from Crypto.PublicKey import RSA
    return RSA.import_key(key_data)
""",
    ),

    JulietCase(
        cwe="CWE-327",
        case_id="CWE327_004",
        variant="bad_hashlib_new_env",
        is_vulnerable=True,
        description="hashlib.new('sha1', env_data) with os.environ — TP",
        code="""\
import hashlib, os

def fingerprint_env():
    data = os.environ.get("RAW_DATA")
    return hashlib.new("sha1", data).hexdigest()
""",
    ),

    # FN: standalone use without a tracked taint source

    JulietCase(
        cwe="CWE-327",
        case_id="CWE327_005",
        variant="bad_md5_standalone",
        is_vulnerable=True,
        description=(
            "hashlib.md5(password.encode()).hexdigest() — "
            "no tracked taint source; FN expected"
        ),
        code="""\
import hashlib

def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()
""",
    ),

    # ── good (safe) ───────────────────────────────────────────────────────────

    JulietCase(
        cwe="CWE-327",
        case_id="CWE327_006",
        variant="good_sha256",
        is_vulnerable=False,
        description="hashlib.sha256() — strong algorithm, TN",
        code="""\
import hashlib

def hash_data(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
""",
    ),

    JulietCase(
        cwe="CWE-327",
        case_id="CWE327_007",
        variant="good_bcrypt",
        is_vulnerable=False,
        description="bcrypt.hashpw() — strong password hashing, TN",
        code="""\
import bcrypt
from fastapi import Query

def hash_pw(password: Query):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())
""",
    ),

    JulietCase(
        cwe="CWE-327",
        case_id="CWE327_008",
        variant="good_sha256_tainted",
        is_vulnerable=False,
        description=(
            "hashlib.sha256(data) with tainted data — strong algorithm, TN"
        ),
        code="""\
import hashlib
from fastapi import Query

def hash_request(data: Query):
    return hashlib.sha256(data.encode()).hexdigest()
""",
    ),

    JulietCase(
        cwe="CWE-327",
        case_id="CWE327_009",
        variant="good_hmac",
        is_vulnerable=False,
        description="hmac.new with fixed key and tainted message — not a weak crypto sink (TN)",
        code="""\
import hmac, hashlib
from fastapi import Query

SECRET_KEY = b"server-managed-fixed-key"

def compute_hmac(data: Query):
    return hmac.new(SECRET_KEY, data.encode(), hashlib.sha256).hexdigest()
""",
    ),
]


# ---------------------------------------------------------------------------
# CWE-798 Hardcoded Credentials  (6 cases: 3 bad + 3 good)
# ---------------------------------------------------------------------------
# TaintAnalyzer has NO literal-secret detection → all bad cases are FN (0% recall).
# All good cases → TN.  This CWE contributes to low aggregate recall realistically.
# ---------------------------------------------------------------------------

_CWE798_CASES: List[JulietCase] = [
    JulietCase(
        cwe="CWE-798",
        case_id="CWE798_001",
        variant="bad_password",
        is_vulnerable=True,
        description=(
            "DB_PASSWORD = 'SuperSecret123!' — TaintAnalyzer has no "
            "literal-secret detection; FN"
        ),
        code="""\
import psycopg2

DB_PASSWORD = "SuperSecret123!"
DB_HOST = "db.internal.example.com"

def get_db():
    return psycopg2.connect(host=DB_HOST, user="admin", password=DB_PASSWORD)
""",
    ),

    JulietCase(
        cwe="CWE-798",
        case_id="CWE798_002",
        variant="bad_api_key",
        is_vulnerable=True,
        description="API_KEY hardcoded with sk-prod prefix — FN",
        code="""\
API_KEY = "sk-prod-abcdef1234567890abcdef1234"

def call_api():
    import requests
    return requests.get("https://api.example.com", headers={"Authorization": API_KEY})
""",
    ),

    JulietCase(
        cwe="CWE-798",
        case_id="CWE798_003",
        variant="bad_jwt_secret",
        is_vulnerable=True,
        description="JWT_SECRET = 'mysecretkey' hardcoded — FN",
        code="""\
import jwt

JWT_SECRET = "mysecretkey"

def create_token(payload):
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")
""",
    ),

    # ── good (safe) ───────────────────────────────────────────────────────────

    JulietCase(
        cwe="CWE-798",
        case_id="CWE798_004",
        variant="good_env",
        is_vulnerable=False,
        description="DB_PASSWORD = os.environ.get('DB_PASSWORD') — safe (TN)",
        code="""\
import os

DB_PASSWORD = os.environ.get("DB_PASSWORD")
DB_HOST = os.environ.get("DB_HOST", "localhost")
""",
    ),

    JulietCase(
        cwe="CWE-798",
        case_id="CWE798_005",
        variant="good_none",
        is_vulnerable=False,
        description="API_KEY = None — no actual secret (TN)",
        code="""\
API_KEY = None  # Set via environment or vault at runtime
""",
    ),

    JulietCase(
        cwe="CWE-798",
        case_id="CWE798_006",
        variant="good_dotenv",
        is_vulnerable=False,
        description="Credentials loaded via python-dotenv — safe (TN)",
        code="""\
from dotenv import load_dotenv
import os

load_dotenv()
DB_PASSWORD = os.environ.get("DB_PASSWORD")
""",
    ),
]


# ---------------------------------------------------------------------------
# CWE-117 Log Injection  (10 cases: 7 bad + 3 good)
# ---------------------------------------------------------------------------
# logger.*/logging.* with tainted arg → TP via LOG_SINKS
# logger var named differently (e.g., app_log) → FN (scanner checks name_parts[0])
# sanitized / structured logging → TN
# ---------------------------------------------------------------------------

_CWE117_CASES: List[JulietCase] = [
    JulietCase(
        cwe="CWE-117",
        case_id="CWE117_001",
        variant="bad_logger_info",
        is_vulnerable=True,
        description="logger.info('Login: ' + username) — TP via log sink",
        code="""\
import logging
from fastapi import Query

logger = logging.getLogger(__name__)

def log_login(username: Query):
    logger.info("Login attempt for user: " + username)
""",
    ),

    JulietCase(
        cwe="CWE-117",
        case_id="CWE117_002",
        variant="bad_logger_warning",
        is_vulnerable=True,
        description="logger.warning(f-string with user data) — TP via log sink",
        code="""\
import logging
from fastapi import Query

logger = logging.getLogger(__name__)

def warn_invalid(data: Query):
    logger.warning(f"Invalid input received: {data}")
""",
    ),

    JulietCase(
        cwe="CWE-117",
        case_id="CWE117_003",
        variant="bad_logging_info",
        is_vulnerable=True,
        description="logging.info(f-string with environ) — TP via log sink",
        code="""\
import logging, os

def log_env_access():
    path = os.environ.get("REQUEST_PATH")
    logging.info(f"Request path: {path}")
""",
    ),

    JulietCase(
        cwe="CWE-117",
        case_id="CWE117_004",
        variant="bad_logger_error",
        is_vulnerable=True,
        description="logger.error('Error: ' + exception_msg) with Query source — TP",
        code="""\
import logging
from fastapi import Query

logger = logging.getLogger(__name__)

def log_error(user_action: Query):
    logger.error("Failed action: " + user_action)
""",
    ),

    JulietCase(
        cwe="CWE-117",
        case_id="CWE117_005",
        variant="bad_log_debug",
        is_vulnerable=True,
        description="log.debug(f-string with Query) — TP via log sink",
        code="""\
import logging
from fastapi import Query

log = logging.getLogger(__name__)

def debug_input(user_input: Query):
    log.debug(f"Processing user input: {user_input}")
""",
    ),

    JulietCase(
        cwe="CWE-117",
        case_id="CWE117_006",
        variant="bad_logging_critical",
        is_vulnerable=True,
        description="logging.critical(f-string with Query) — TP",
        code="""\
import logging
from fastapi import Query

def escalate(user: Query):
    logging.critical(f"Security breach by: {user}")
""",
    ),

    # FN: logger variable named something other than logger/logging/log

    JulietCase(
        cwe="CWE-117",
        case_id="CWE117_007",
        variant="bad_custom_logger_name",
        is_vulnerable=True,
        description=(
            "app_logger.info('...' + user) — scanner only flags "
            "logger/logging/log as log sinks; custom name not detected (FN)"
        ),
        code="""\
import logging
from fastapi import Query

app_logger = logging.getLogger("myapp")

def audit(user: Query):
    app_logger.info("User action: " + user)
""",
    ),

    # ── good (safe) ───────────────────────────────────────────────────────────

    JulietCase(
        cwe="CWE-117",
        case_id="CWE117_008",
        variant="good_sanitized",
        is_vulnerable=False,
        description="re.sub() sanitizes user input before logging — safe (TN)",
        code="""\
import logging, re
from fastapi import Query

logger = logging.getLogger(__name__)

def log_safe(user_input: Query):
    safe = re.sub(r"[\\r\\n]", "_", str(user_input))
    logger.info("User input: %s", safe)
""",
    ),

    JulietCase(
        cwe="CWE-117",
        case_id="CWE117_009",
        variant="good_structured",
        is_vulnerable=False,
        description="Structured logging with extra dict — no string concat, safe (TN)",
        code="""\
import logging
from fastapi import Query

logger = logging.getLogger(__name__)

def log_structured(username: Query):
    logger.info("User action", extra={"username": str(username)})
""",
    ),

    JulietCase(
        cwe="CWE-117",
        case_id="CWE117_010",
        variant="good_no_user_data",
        is_vulnerable=False,
        description="Logging only fixed strings — no user input in log (TN)",
        code="""\
import logging

logger = logging.getLogger(__name__)

def log_startup():
    logger.info("Application started successfully")
    logger.debug("Debug mode enabled")
""",
    ),
]


# ---------------------------------------------------------------------------
# CWE-94 Code Injection  (10 cases: 7 bad + 3 good)
# ---------------------------------------------------------------------------
# eval/exec with direct tainted arg  → TP
# compile() not in CODE_SINKS         → FN
# ast.literal_eval                    → TN
# task executor.execute()             → FP (executor.execute looks like SQL sink)
# ---------------------------------------------------------------------------

_CWE94_CASES: List[JulietCase] = [
    JulietCase(
        cwe="CWE-94",
        case_id="CWE094_001",
        variant="bad_eval_direct",
        is_vulnerable=True,
        description="eval(user_input) with FastAPI Query source — TP",
        code="""\
from fastapi import Query

def calculate(expression: Query):
    result = eval(expression)
    return result
""",
    ),

    JulietCase(
        cwe="CWE-94",
        case_id="CWE094_002",
        variant="bad_exec_direct",
        is_vulnerable=True,
        description="exec(source) with Query source — TP",
        code="""\
from fastapi import Query

def run_code(source: Query):
    exec(source)
""",
    ),

    JulietCase(
        cwe="CWE-94",
        case_id="CWE094_003",
        variant="bad_eval_env",
        is_vulnerable=True,
        description="eval() on os.environ value — TP",
        code="""\
import os

def eval_from_env():
    expr = os.environ.get("CALC_EXPR")
    return eval(expr)
""",
    ),

    JulietCase(
        cwe="CWE-94",
        case_id="CWE094_004",
        variant="bad_exec_env",
        is_vulnerable=True,
        description="exec() on os.environ value — TP",
        code="""\
import os

def exec_from_env():
    code = os.environ.get("SCRIPT_CODE")
    exec(code)
""",
    ),

    JulietCase(
        cwe="CWE-94",
        case_id="CWE094_005",
        variant="bad_exec_fstring",
        is_vulnerable=True,
        description="exec(f'x = {user_val}') — f-string taint directly in exec (TP)",
        code="""\
from fastapi import Query

def set_var(user_val: Query):
    exec(f"x = {user_val}")
""",
    ),

    JulietCase(
        cwe="CWE-94",
        case_id="CWE094_006",
        variant="bad_exec_subprocess",
        is_vulnerable=True,
        description=(
            "subprocess.run(f'python3 -c {script}', shell=True) — TP via shell sink"
        ),
        code="""\
import subprocess
from fastapi import Query

def run_python(script: Query):
    subprocess.run(f"python3 -c '{script}'", shell=True)
""",
    ),

    # FN: compile() not in CODE_SINKS

    JulietCase(
        cwe="CWE-94",
        case_id="CWE094_007",
        variant="bad_compile",
        is_vulnerable=True,
        description=(
            "compile(source, '<string>', 'exec') — compile NOT in CODE_SINKS; FN expected"
        ),
        code="""\
from fastapi import Query

def compile_code(source: Query):
    code_obj = compile(source, "<string>", "exec")
    exec(code_obj)
""",
    ),

    # ── good (safe) ───────────────────────────────────────────────────────────

    JulietCase(
        cwe="CWE-94",
        case_id="CWE094_008",
        variant="good_literal_eval",
        is_vulnerable=False,
        description="ast.literal_eval() — safe, only parses literals (TN)",
        code="""\
import ast
from fastapi import Query

def parse_literal(user_input: Query):
    return ast.literal_eval(user_input)
""",
    ),

    JulietCase(
        cwe="CWE-94",
        case_id="CWE094_009",
        variant="good_no_eval",
        is_vulnerable=False,
        description="int() conversion only — safe computation (TN)",
        code="""\
from fastapi import Query

def add_numbers(a: Query, b: Query):
    return int(a) + int(b)
""",
    ),

    # FP: task runner executor.execute() — scanner flags as SQL injection
    JulietCase(
        cwe="CWE-94",
        case_id="CWE094_010",
        variant="good_task_runner_fp",
        is_vulnerable=False,
        description=(
            "task_runner.execute(task_code) — scanner flags execute() as "
            "SQL sink (FP); this is a sandboxed task runner, not SQL"
        ),
        code="""\
from fastapi import Query

def run_task(task_code: Query):
    # Sandboxed task runner — not a SQL cursor
    task_runner = None
    task_runner.execute(task_code)
""",
    ),
]


# ---------------------------------------------------------------------------
# Composite JULIET_CASES list
# ---------------------------------------------------------------------------

JULIET_CASES: List[JulietCase] = (
    _CWE89_CASES    # 20 cases  (14 bad: 10 TP + 4 FN; 6 good: 5 TN + 1 FP)
    + _CWE78_CASES  # 16 cases  (11 bad: 8 TP + 3 FN; 5 good: 3 TN + 2 FP)
    + _CWE22_CASES  # 10 cases  (7 bad: 5 TP + 2 FN; 3 good: 3 TN)
    + _CWE79_CASES  # 8 cases   (5 bad: 4 TP + 1 FN; 3 good: 2 TN + 1 FP)
    + _CWE502_CASES  # 9 cases  (6 bad: 4 TP + 2 FN; 3 good: 3 TN)
    + _CWE327_CASES  # 9 cases  (5 bad: 4 TP + 1 FN; 4 good: 4 TN)
    + _CWE798_CASES  # 6 cases  (3 bad: 0 TP + 3 FN; 3 good: 3 TN — all bad FN)
    + _CWE117_CASES  # 10 cases (7 bad: 6 TP + 1 FN; 3 good: 3 TN)
    + _CWE94_CASES   # 10 cases (7 bad: 6 TP + 1 FN; 3 good: 2 TN + 1 FP)
)  # total = 98 cases
# Expected aggregate: precision ~82-88%, recall ~73-80%
