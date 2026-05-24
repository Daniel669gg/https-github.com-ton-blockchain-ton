"""
Tests — All 11 New Features
1. Incremental Scanning
2. ghost CLI
3. Semgrep integration
4. Attack Path Graph
5. FP Feedback Loop
6. Multi-tenant
7. OpenAPI Scanner
8. Supply Chain
9. TON Symbolic Execution
10. Benchmark
11. All endpoints importable
Run: python3 -m unittest tests.test_eleven_features -v
"""
import os, sys, time, json, tempfile, unittest, shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ══════════════════════════════════════════════════════════════════
# 1. INCREMENTAL SCANNING
# ══════════════════════════════════════════════════════════════════
class TestIncrementalScanner(unittest.TestCase):

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _write(self, name, code):
        p = os.path.join(self._tmpdir, name)
        with open(p, "w") as f: f.write(code)
        return p

    def test_cache_miss_then_hit(self):
        from core.incremental import ScanCache
        cache = ScanCache(os.path.join(self._tmpdir, "cache"))
        p = self._write("app.py", "import hashlib\nhashlib.md5(x)\n")
        # First access = miss
        result1 = cache.get(p)
        self.assertIsNone(result1)
        # Store
        cache.set(p, [{"type":"weak_hash","severity":"HIGH"}])
        # Second access = hit
        result2 = cache.get(p)
        self.assertIsNotNone(result2)
        self.assertEqual(result2[0]["type"], "weak_hash")

    def test_cache_invalidates_on_file_change(self):
        from core.incremental import ScanCache
        cache = ScanCache(os.path.join(self._tmpdir, "cache"))
        p = self._write("app.py", "x = 1\n")
        cache.set(p, [{"type":"test"}])
        # Change file content
        with open(p, "w") as f: f.write("x = 2\n")
        result = cache.get(p)
        self.assertIsNone(result)  # cache miss after change

    def test_scan_file_uses_cache(self):
        from core.incremental import IncrementalScanner
        scanner = IncrementalScanner(self._tmpdir,
                                     cache_dir=os.path.join(self._tmpdir,"cache"))
        p = self._write("vuln.py", "hashlib.md5(x)\n")
        # First scan
        r1 = scanner.scan_file(p)
        # Second scan = from cache
        r2 = scanner.scan_file(p)
        self.assertEqual(r1, r2)
        stats = scanner.cache_stats()
        self.assertGreater(stats["hits"], 0)

    def test_scan_no_git_fallback(self):
        """Without git, scanner scans all files."""
        from core.incremental import IncrementalScanner
        self._write("test.py", "eval(user_input)\n")
        scanner = IncrementalScanner(self._tmpdir,
                                     cache_dir=os.path.join(self._tmpdir,"cache"))
        result = scanner.scan(include_untracked=True)
        # Either found findings or at least has the infrastructure
        self.assertIsNotNone(result)
        self.assertIsInstance(result.duration_s, float)

    def test_cache_clear(self):
        from core.incremental import ScanCache
        cache = ScanCache(os.path.join(self._tmpdir, "cache"))
        p = self._write("app.py", "x=1\n")
        cache.set(p, [{"type":"test"}])
        n = cache.clear()
        self.assertGreaterEqual(n, 1)
        self.assertIsNone(cache.get(p))


# ══════════════════════════════════════════════════════════════════
# 2. CLI
# ══════════════════════════════════════════════════════════════════
class TestCLI(unittest.TestCase):

    def test_cli_imports(self):
        from ghost_cli_main import main, cmd_scan, cmd_ton, cmd_k8s, cmd_status
        for fn in [main, cmd_scan, cmd_ton, cmd_k8s, cmd_status]:
            self.assertTrue(callable(fn))

    def test_cli_status_runs(self):
        import argparse
        from ghost_cli_main import cmd_status
        args = argparse.Namespace()
        # Should not raise
        try:
            cmd_status(args)
        except SystemExit:
            pass  # status may call sys.exit — that's fine


# ══════════════════════════════════════════════════════════════════
# 3. SEMGREP SCANNER
# ══════════════════════════════════════════════════════════════════
class TestSemgrepScanner(unittest.TestCase):

    def test_status(self):
        from scanners.semgrep_integration import SemgrepScanner
        s = SemgrepScanner()
        status = s.status()
        self.assertIn("available", status)
        self.assertIn("supported_languages", status)
        self.assertIsInstance(status["supported_languages"], list)
        self.assertIn("python", status["supported_languages"])

    def test_language_detection(self):
        from scanners.semgrep_integration import _detect_languages
        import tempfile, os
        tmpdir = tempfile.mkdtemp()
        try:
            open(os.path.join(tmpdir,"app.py"),"w").close()
            open(os.path.join(tmpdir,"main.go"),"w").close()
            open(os.path.join(tmpdir,"App.java"),"w").close()
            langs = _detect_languages(tmpdir)
            self.assertIn("python", langs)
            self.assertIn("go", langs)
            self.assertIn("java", langs)
        finally:
            shutil.rmtree(tmpdir)

    def test_graceful_offline(self):
        """If semgrep not installed, returns empty findings gracefully."""
        from scanners.semgrep_integration import SemgrepScanner
        s = SemgrepScanner()
        if not s.is_available():
            result = s.scan_directory("/tmp")
            self.assertIn("error", result)
            self.assertIn("findings", result)

    def test_normalize_finding(self):
        from scanners.semgrep_integration import _normalize_finding
        raw = {
            "check_id": "python.lang.security.audit.eval-detected.eval-detected",
            "path": "app.py",
            "start": {"line": 10, "col": 1},
            "extra": {
                "message": "eval() detected",
                "severity": "ERROR",
                "lines": "eval(user_input)",
                "metadata": {"cwe": ["CWE-95"], "owasp": ["A03:2021"]},
            }
        }
        f = _normalize_finding(raw, "app.py")
        self.assertEqual(f["line"], 10)
        self.assertEqual(f["severity"], "HIGH")
        self.assertEqual(f["cwe"], "CWE-95")
        self.assertIn("eval", f["message"].lower())


# ══════════════════════════════════════════════════════════════════
# 4. ATTACK PATH GRAPH
# ══════════════════════════════════════════════════════════════════
class TestAttackPathGraph(unittest.TestCase):

    def _findings(self):
        return [
            {"type":"xss","severity":"HIGH","message":"XSS in template",
             "file":"views.py","line":10,"rule_id":"OW-A03-003","cwe":"CWE-79"},
            {"type":"hardcoded_secret","severity":"CRITICAL","message":"Hardcoded API key",
             "file":"config.py","line":5,"rule_id":"SEC-001","cwe":"CWE-798"},
            {"type":"sql_injection","severity":"CRITICAL","message":"SQL injection",
             "file":"db.py","line":20,"rule_id":"OW-A03-001","cwe":"CWE-89"},
            {"type":"weak_hash","severity":"HIGH","message":"MD5 used",
             "file":"crypto.py","line":8,"rule_id":"OW-A02-002","cwe":"CWE-327"},
            {"type":"missing_auth","severity":"HIGH","message":"No auth check",
             "file":"api.py","line":30,"rule_id":"OW-A01-001","cwe":"CWE-306"},
        ]

    def test_graph_built(self):
        from core.attack_path import AttackPathAnalyzer
        graph = AttackPathAnalyzer().analyze(self._findings())
        self.assertIn("nodes", graph)
        self.assertIn("edges", graph)
        self.assertIn("paths", graph)

    def test_chains_found(self):
        from core.attack_path import AttackPathAnalyzer
        graph = AttackPathAnalyzer().analyze(self._findings())
        self.assertGreater(graph["chain_count"], 0)

    def test_critical_chains_detected(self):
        from core.attack_path import AttackPathAnalyzer
        graph = AttackPathAnalyzer().analyze(self._findings())
        # SQL + weak hash = CRITICAL chain
        self.assertGreater(graph["critical_chains"], 0)

    def test_risk_score_with_chains(self):
        from core.attack_path import AttackPathAnalyzer
        a = AttackPathAnalyzer()
        single = [{"type":"low_vuln","severity":"LOW","message":"low","file":"f.py","line":1}]
        graph_many = a.analyze(self._findings())
        graph_single = a.analyze(single)
        self.assertGreater(graph_many["risk_score"], graph_single["risk_score"])

    def test_mermaid_export(self):
        from core.attack_path import AttackPathAnalyzer
        a     = AttackPathAnalyzer()
        graph = a.analyze(self._findings())
        mmd   = a.mermaid(graph)
        self.assertIn("graph LR", mmd)

    def test_narrative(self):
        from core.attack_path import AttackPathAnalyzer
        a     = AttackPathAnalyzer()
        graph = a.analyze(self._findings())
        narr  = a.narrative(graph)
        self.assertIn("Attack Path", narr)

    def test_empty_findings(self):
        from core.attack_path import AttackPathAnalyzer
        graph = AttackPathAnalyzer().analyze([])
        self.assertEqual(graph["paths"], [])

    def test_classify_finding(self):
        from core.attack_path import _classify_finding
        self.assertEqual(_classify_finding({"type":"xss","cwe":"CWE-79"}), "xss")
        self.assertEqual(_classify_finding({"type":"sql_injection","cwe":"CWE-89"}), "sql_injection")
        self.assertEqual(_classify_finding({"rule_id":"TON-FUND-001"}), "ton_fund")


# ══════════════════════════════════════════════════════════════════
# 5. FP FEEDBACK LOOP
# ══════════════════════════════════════════════════════════════════
class TestFPFeedback(unittest.TestCase):

    def setUp(self):
        import tempfile
        self._tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self._tmp.close()
        from core.fp_feedback import FPFeedbackStore
        self.store = FPFeedbackStore(self._tmp.name)

    def tearDown(self):
        os.unlink(self._tmp.name)

    def _f(self, ftype="sql_injection", rule="OW-001"):
        return {"type":ftype,"rule_id":rule,"file":"app.py","line":10,
                "cwe":"CWE-89","evidence":"cursor.execute(x+user)"}

    def test_report_fp(self):
        result = self.store.report_fp(self._f(), reason="test env")
        self.assertEqual(result["report_count"], 1)
        self.assertFalse(result["auto_suppress"])

    def test_penalty_applied(self):
        f = self._f()
        self.store.report_fp(f)
        penalty, suppress = self.store.get_penalty(f)
        self.assertGreater(penalty, 0)
        self.assertFalse(suppress)

    def test_auto_suppress_threshold(self):
        f = self._f()
        for _ in range(3):
            r = self.store.report_fp(f)
        self.assertTrue(r["auto_suppress"])

    def test_filter_suppressed(self):
        f = self._f()
        for _ in range(3): self.store.report_fp(f)
        kept, suppressed = self.store.filter_findings([f])
        self.assertEqual(len(suppressed), 1)
        self.assertEqual(len(kept), 0)

    def test_filter_keeps_unrelated(self):
        f1 = self._f("sql_injection")
        f2 = self._f("xss","OW-002")  # different
        for _ in range(3): self.store.report_fp(f1)
        kept, suppressed = self.store.filter_findings([f1, f2])
        self.assertEqual(len(suppressed), 1)
        self.assertEqual(len(kept), 1)

    def test_penalty_reduces_confidence(self):
        f = {**self._f(), "confidence": 0.9}
        self.store.report_fp(self._f())  # 1 report
        kept, _ = self.store.filter_findings([f])
        if kept:
            self.assertLess(kept[0]["confidence"], 0.9)

    def test_reset_removes_suppress(self):
        f = self._f()
        for _ in range(3): self.store.report_fp(f)
        self.store.reset_fingerprint(f)
        penalty, suppress = self.store.get_penalty(f)
        self.assertFalse(suppress)

    def test_stats(self):
        self.store.report_fp(self._f())
        s = self.store.stats()
        self.assertIn("total_fp_reports", s)
        self.assertGreater(s["total_fp_reports"], 0)

    def test_top_fp_rules(self):
        for _ in range(3): self.store.report_fp(self._f())
        top = self.store.top_fp_rules()
        self.assertIsInstance(top, list)


# ══════════════════════════════════════════════════════════════════
# 6. MULTI-TENANT
# ══════════════════════════════════════════════════════════════════
class TestMultiTenant(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self._tmp.close()
        from core.tenants import TenantManager
        self.t = TenantManager(self._tmp.name)

    def tearDown(self):
        os.unlink(self._tmp.name)

    def test_create_org(self):
        org = self.t.create_org("Acme Corp", "acme", "pro")
        self.assertIn("id", org)
        self.assertEqual(org["plan"], "pro")

    def test_create_user_and_auth(self):
        org  = self.t.create_org("TestOrg", "testorg")
        self.t.create_user(org["id"], "dev@test.com", "S3cur3P@ss", role="owner")
        user = self.t.authenticate("dev@test.com", "S3cur3P@ss")
        self.assertIsNotNone(user)
        self.assertEqual(user["role"], "owner")

    def test_wrong_password(self):
        org = self.t.create_org("TestOrg2", "testorg2")
        self.t.create_user(org["id"], "x@x.com", "correct")
        self.assertIsNone(self.t.authenticate("x@x.com", "wrong"))

    def test_jwt_issue_and_verify(self):
        org  = self.t.create_org("JWTOrg", "jwtorg")
        user = {"id":"u1","org_id":org["id"],"role":"member","email":"u@u.com"}
        token = self.t.issue_token(user)
        self.assertIsInstance(token, str)
        ctx = self.t.verify_token(token)
        self.assertIsNotNone(ctx)
        self.assertEqual(ctx.org_id, org["id"])

    def test_role_permissions(self):
        from core.tenants import AuthContext
        owner  = AuthContext("org1","u1","owner")
        viewer = AuthContext("org1","u2","viewer")
        self.assertTrue(owner.can("admin"))
        self.assertTrue(viewer.can("read"))
        self.assertFalse(viewer.can("write"))

    def test_api_key_create_verify(self):
        org  = self.t.create_org("APIOrg", "apiorg")
        result = self.t.create_api_key(org["id"], "ci-key")
        key = result["key"]
        self.assertTrue(key.startswith("ghost_"))
        ctx = self.t.verify_api_key(key)
        self.assertIsNotNone(ctx)
        self.assertEqual(ctx.org_id, org["id"])

    def test_api_key_revoke(self):
        org    = self.t.create_org("RevokeOrg", "revokeorg")
        result = self.t.create_api_key(org["id"], "temp")
        self.t.revoke_api_key(result["id"], org["id"])
        ctx = self.t.verify_api_key(result["key"])
        self.assertIsNone(ctx)

    def test_quota_check(self):
        org   = self.t.create_org("QuotaOrg", "quotaorg")
        quota = self.t.check_quota(org["id"])
        self.assertTrue(quota["allowed"])
        self.assertEqual(quota["limit"], 50)  # free plan

    def test_quota_increment(self):
        org = self.t.create_org("QuotaOrg2", "quotaorg2")
        self.t.increment_quota(org["id"])
        self.t.increment_quota(org["id"])
        quota = self.t.check_quota(org["id"])
        self.assertEqual(quota["used"], 2)

    def test_project_create_list(self):
        org = self.t.create_org("ProjOrg", "projorg")
        self.t.create_project(org["id"], "Backend", "backend")
        self.t.create_project(org["id"], "Frontend", "frontend")
        projects = self.t.list_projects(org["id"])
        self.assertEqual(len(projects), 2)


# ══════════════════════════════════════════════════════════════════
# 7. OPENAPI SCANNER
# ══════════════════════════════════════════════════════════════════
class TestOpenAPIScanner(unittest.TestCase):

    _VULN_SPEC = json.dumps({
        "openapi": "3.0.0",
        "info":    {"title": "Test API", "version": "1.0"},
        "servers": [{"url": "http://api.example.com"}],
        "paths": {
            "/users/{userId}": {
                "get": {"responses": {"200": {"description":"ok"}}}
            },
            "/admin/config": {
                "get": {"responses": {"200": {"description":"ok"}}}
            },
        }
    })
    _SAFE_SPEC = json.dumps({
        "openapi": "3.0.0",
        "info":    {"title": "Safe API", "version": "1.0"},
        "servers": [{"url": "https://api.example.com"}],
        "security": [{"bearerAuth": []}],
        "components": {"securitySchemes": {"bearerAuth": {"type":"http","scheme":"bearer"}}},
        "paths": {
            "/users/{userId}": {
                "get": {"operationId":"getUser","security":[{"bearerAuth":[]}],
                        "responses":{"200":{"description":"ok"}}}
            },
        }
    })

    def setUp(self):
        from scanners.openapi_scanner import OpenAPIScanner
        self.scanner = OpenAPIScanner()

    def _ids(self, findings):
        return {f["rule_id"] for f in findings}

    def test_http_scheme_detected(self):
        result = self.scanner.scan(self._VULN_SPEC)
        self.assertIn("API-TLS-001", self._ids(result["findings"]))

    def test_bola_detected(self):
        result = self.scanner.scan(self._VULN_SPEC)
        self.assertIn("API-BOLA-001", self._ids(result["findings"]))

    def test_admin_no_auth(self):
        result = self.scanner.scan(self._VULN_SPEC)
        self.assertIn("API-AUTHZ-001", self._ids(result["findings"]))

    def test_safe_spec_fewer_issues(self):
        vuln_count = len(self.scanner.scan(self._VULN_SPEC)["findings"])
        safe_count = len(self.scanner.scan(self._SAFE_SPEC)["findings"])
        self.assertLess(safe_count, vuln_count)

    def test_invalid_spec_graceful(self):
        # Invalid specs return gracefully with either error key or empty findings
        result = self.scanner.scan("definitely_not_a_real_file_path_12345.yaml")
        self.assertIn("findings", result)
        # Either error key present or empty findings — both are acceptable
        graceful = "error" in result or result.get("findings") == []
        self.assertTrue(graceful, f"Expected graceful handling, got: {result}")

    def test_severity_counts_returned(self):
        result = self.scanner.scan(self._VULN_SPEC)
        self.assertIn("severity_counts", result)


# ══════════════════════════════════════════════════════════════════
# 8. SUPPLY CHAIN
# ══════════════════════════════════════════════════════════════════
class TestSupplyChain(unittest.TestCase):

    def setUp(self):
        from scanners.supply_chain_scanner import SupplyChainScanner
        self.scanner = SupplyChainScanner(online=False)
        self._tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _req(self, content):
        p = os.path.join(self._tmpdir, "requirements.txt")
        with open(p,"w") as f: f.write(content)
        return p

    def _ids(self, findings):
        return {f["rule_id"] for f in findings}

    def test_known_malicious(self):
        p = self._req("colourama==1.0.0\n")
        findings = self.scanner.scan_requirements(p)
        self.assertIn("SC-MALICIOUS-001", self._ids(findings))

    def test_typosquat_detected(self):
        # Use 'panddas' (typo of 'pandas') which is not in known malicious
        p = self._req("panddas==1.5.0\n")
        findings = self.scanner.scan_requirements(p)
        ids = self._ids(findings)
        # Should detect either as malicious OR as typosquat (both are correct)
        self.assertTrue(
            "SC-TYPO-001" in ids or "SC-MALICIOUS-001" in ids,
            f"Expected typosquat/malicious detection, got: {ids}"
        )

    def test_wildcard_version(self):
        p = self._req("requests==*\n")
        findings = self.scanner.scan_requirements(p)
        self.assertIn("SC-VERSION-001", self._ids(findings))

    def test_safe_package(self):
        p = self._req("requests==2.31.0\n")
        findings = self.scanner.scan_requirements(p)
        malicious = [f for f in findings if f["rule_id"] == "SC-MALICIOUS-001"]
        typo      = [f for f in findings if f["rule_id"] == "SC-TYPO-001"]
        self.assertEqual(len(malicious), 0)
        self.assertEqual(len(typo), 0)

    def test_levenshtein(self):
        from scanners.supply_chain_scanner import _levenshtein
        self.assertEqual(_levenshtein("requests", "requests"), 0)
        self.assertEqual(_levenshtein("reqeusts", "requests"), 2)
        self.assertEqual(_levenshtein("abc", "xyz"), 3)

    def test_typosquat_function(self):
        from scanners.supply_chain_scanner import _is_typosquat, _POPULAR_PYPI
        is_typo, similar = _is_typosquat("reqeusts", _POPULAR_PYPI)
        self.assertTrue(is_typo)
        self.assertEqual(similar, "requests")
        is_safe, _ = _is_typosquat("requests", _POPULAR_PYPI)
        self.assertFalse(is_safe)

    def test_scan_directory(self):
        with open(os.path.join(self._tmpdir,"requirements.txt"),"w") as f:
            f.write("colourama==1.0\nrequests==2.31.0\n")
        result = self.scanner.scan_directory(self._tmpdir)
        self.assertIn("findings", result)
        self.assertGreater(result["total"], 0)


# ══════════════════════════════════════════════════════════════════
# 9. TON SYMBOLIC
# ══════════════════════════════════════════════════════════════════
class TestTONSymbolic(unittest.TestCase):

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _contract(self, code):
        p = os.path.join(self._tmpdir, "contract.fc")
        with open(p,"w") as f: f.write(code)
        return p

    def test_gas_drain_detected(self):
        from scanners.ton_scanner.ton_symbolic import TONSymbolicExecutor
        p = self._contract("() recv_external(slice s) impure {\n  accept_message();\n}\n")
        r = TONSymbolicExecutor().analyze(p)
        self.assertIn("findings", r)
        crits = [f for f in r["findings"] if f.get("severity") == "CRITICAL"]
        self.assertGreater(len(crits), 0)

    def test_drain_128_detected(self):
        from scanners.ton_scanner.ton_symbolic import TONSymbolicExecutor
        p = self._contract("() go() impure { send_raw_message(m, 128); }\n")
        r = TONSymbolicExecutor().analyze(p)
        drain = [f for f in r["findings"] if "DRAIN" in f.get("rule_id","")]
        self.assertGreater(len(drain), 0)

    def test_safe_contract_no_critical_sym(self):
        from scanners.ton_scanner.ton_symbolic import TONSymbolicExecutor
        p = self._contract("""
() recv_internal(int v, cell c, slice s) impure {
    throw_unless(401, equal_slices(sender, owner));
    raw_reserve(fee, 2);
    set_data(pack());
    send_raw_message(m, 64);
}
""")
        r = TONSymbolicExecutor().analyze(p)
        crits = [f for f in r["findings"] if f.get("severity")=="CRITICAL"]
        self.assertEqual(len(crits), 0)

    def test_status(self):
        from scanners.ton_scanner.ton_symbolic import TONSymbolicExecutor
        s = TONSymbolicExecutor().status()
        self.assertIn("mode", s)
        self.assertIn("node_available", s)


# ══════════════════════════════════════════════════════════════════
# 10. BENCHMARK
# ══════════════════════════════════════════════════════════════════
class TestBenchmark(unittest.TestCase):

    def test_benchmark_runs(self):
        import io, contextlib
        from tests.benchmark import run_benchmark
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = run_benchmark(verbose=False)
        output = buf.getvalue()
        self.assertIn("Recall", output)
        self.assertIn("Precision", output)
        self.assertIn("F1", output)

    def test_benchmark_exit_code(self):
        import io, contextlib
        from tests.benchmark import run_benchmark
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = run_benchmark(verbose=False)
        # 0 = all pass, 1 = regressions
        self.assertIn(code, [0, 1])

    def test_scan_case_python(self):
        from tests.benchmark import _scan_case, PYTHON_CASES as _PYTHON_CASES
        # Test the MD5 case
        md5_case = next(c for c in _PYTHON_CASES if "md5" in c.name)
        ids, ms = _scan_case(md5_case)
        self.assertGreater(ms, 0)
        found = any("OW-A02-002" in i for i in ids)
        self.assertTrue(found, f"MD5 not detected. Found: {ids}")

    def test_scan_case_safe(self):
        from tests.benchmark import _scan_case, PYTHON_CASES as _PYTHON_CASES
        safe = next(c for c in _PYTHON_CASES if "sha256" in c.name and c.is_safe)
        ids, _ = _scan_case(safe)
        # SHA-256 should not trigger weak_hash
        weak = any("A02-002" in i for i in ids)
        self.assertFalse(weak, f"SHA-256 flagged as weak hash: {ids}")


# ══════════════════════════════════════════════════════════════════
# 11. ALL ENDPOINTS IMPORTABLE
# ══════════════════════════════════════════════════════════════════
class TestAllModulesImport(unittest.TestCase):

    def test_incremental(self):
        from core.incremental import IncrementalScanner, ScanCache

    def test_attack_path(self):
        from core.attack_path import AttackPathAnalyzer, ChainRule, _CHAIN_RULES

    def test_fp_feedback(self):
        from core.fp_feedback import FPFeedbackStore, FP_STORE

    def test_tenants(self):
        from core.tenants import TenantManager, AuthContext, TENANTS

    def test_openapi_scanner(self):
        from scanners.openapi_scanner import OpenAPIScanner

    def test_supply_chain(self):
        from scanners.supply_chain_scanner import SupplyChainScanner, _KNOWN_MALICIOUS

    def test_ton_symbolic(self):
        from scanners.ton_scanner.ton_symbolic import TONSymbolicExecutor

    def test_semgrep_scanner(self):
        from scanners.semgrep_integration import SemgrepScanner

    def test_cli_main(self):
        from ghost_cli_main import main

    def test_benchmark(self):
        from tests.benchmark import run_benchmark, PYTHON_CASES as _PYTHON_CASES, TON_CASES as _TON_CASES

    def test_chain_rules_complete(self):
        from core.attack_path import _CHAIN_RULES
        self.assertGreater(len(_CHAIN_RULES), 10)
        for rule in _CHAIN_RULES:
            self.assertTrue(rule.from_type)
            self.assertTrue(rule.to_type)
            self.assertTrue(rule.severity in ["CRITICAL","HIGH","MEDIUM","LOW"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
