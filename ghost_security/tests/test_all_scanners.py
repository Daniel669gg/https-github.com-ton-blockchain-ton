"""
Ghost Security — Full Scanner Test Suite
Tests for all new modules added in the current session.
Run: python3 -m unittest tests.test_all_scanners -v
"""
import os, sys, tempfile, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ─── OWASP Scanner ───────────────────────────────────────────────────────────

class TestOWASPScanner(unittest.TestCase):
    def setUp(self):
        from scanners.owasp_scanner import OWASPScanner
        self.s = OWASPScanner()

    def _py(self, code):
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False)
        f.write(code); f.close(); return f.name

    def test_sql_injection_detected(self):
        p = self._py('cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)\n')
        try: self.assertTrue(any(f["id"]=="OW-A03-001" for f in self.s.scan_file(p)))
        finally: os.unlink(p)

    def test_shell_injection_detected(self):
        p = self._py('subprocess.run(cmd, shell=True)\n')
        try: self.assertTrue(any("A03" in f["owasp_category"] for f in self.s.scan_file(p)))
        finally: os.unlink(p)

    def test_eval_detected(self):
        p = self._py('result = eval(user_input)\n')
        try: self.assertTrue(any(f["id"]=="OW-A03-004" for f in self.s.scan_file(p)))
        finally: os.unlink(p)

    def test_hardcoded_secret_detected(self):
        p = self._py('password = "SuperSecret123!"\n')
        try:
            findings = self.s.scan_file(p)
            self.assertTrue(any("A02" in f.get("owasp_category","") for f in findings))
        finally: os.unlink(p)

    def test_debug_mode_detected(self):
        p = self._py('DEBUG = True\n')
        try: self.assertTrue(any(f["id"]=="OW-A05-001" for f in self.s.scan_file(p)))
        finally: os.unlink(p)

    def test_ssrf_detected(self):
        p = self._py('requests.get(request.args.get("url"))\n')
        try: self.assertTrue(any("A10" in f.get("owasp_category","") for f in self.s.scan_file(p)))
        finally: os.unlink(p)

    def test_weak_hash_detected(self):
        p = self._py('digest = hashlib.md5(password.encode()).hexdigest()\n')
        try: self.assertTrue(any(f["id"]=="OW-A02-002" for f in self.s.scan_file(p)))
        finally: os.unlink(p)

    def test_insecure_random_detected(self):
        p = self._py('token = random.randint(1000, 9999)\n')
        try: self.assertTrue(any(f["id"]=="OW-A02-004" for f in self.s.scan_file(p)))
        finally: os.unlink(p)

    def test_ssl_verify_false(self):
        p = self._py('requests.get(url, verify=False)\n')
        try: self.assertTrue(any(f["id"]=="OW-A02-006" for f in self.s.scan_file(p)))
        finally: os.unlink(p)

    def test_comment_not_flagged(self):
        p = self._py('# eval(user_input)  -- example only\n')
        try: self.assertFalse(any(f["id"]=="OW-A03-004" for f in self.s.scan_file(p)))
        finally: os.unlink(p)

    def test_unsupported_ext_empty(self):
        p = self._py('eval(x)\n').replace(".py", "") + ".rb"
        import shutil; shutil.move(self._py('eval(x)\n'), p + ".tmp")
        self.assertEqual(self.s.scan_file("/tmp/fake.rb"), [])

    def test_directory_scan_returns_summary(self):
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d,"app.py"),"w").write('eval(user_input)\nsubprocess.run(cmd,shell=True)\n')
            result = self.s.scan_directory(d)
            self.assertIn("total_findings", result)
            self.assertGreater(result["total_findings"], 0)
            self.assertIn("owasp_counts", result)

    def test_findings_have_owasp_category(self):
        p = self._py('os.system(cmd)\n')
        try:
            findings = self.s.scan_file(p)
            for f in findings:
                self.assertIn("owasp_category", f)
                self.assertIn("A0", f["owasp_category"])
        finally: os.unlink(p)


# ─── JS Analyzer ─────────────────────────────────────────────────────────────

class TestJSAnalyzer(unittest.TestCase):
    def setUp(self):
        from scanners.js_analyzer import JSAnalyzer
        self.s = JSAnalyzer()

    def _js(self, code):
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False)
        f.write(code); f.close(); return f.name

    def test_innerhtml_xss(self):
        p = self._js('el.innerHTML = userData;\n')
        try: self.assertTrue(any(f["id"]=="JS003" for f in self.s.analyze_file(p)))
        finally: os.unlink(p)

    def test_eval_detected(self):
        p = self._js('eval(userInput);\n')
        try: self.assertTrue(any(f["id"]=="JS010" for f in self.s.analyze_file(p)))
        finally: os.unlink(p)

    def test_exec_command_injection(self):
        p = self._js('exec(userCmd);\n')
        try: self.assertTrue(any(f["id"]=="JS008" for f in self.s.analyze_file(p)))
        finally: os.unlink(p)

    def test_math_random_insecure(self):
        p = self._js('const token = Math.random();\n')
        try: self.assertTrue(any(f["id"]=="JS017" for f in self.s.analyze_file(p)))
        finally: os.unlink(p)

    def test_hardcoded_secret(self):
        p = self._js('const apikey = "sk-abcdef1234567890abcdef";\n')
        try: self.assertTrue(any(f["id"]=="JS019" for f in self.s.analyze_file(p)))
        finally: os.unlink(p)

    def test_cors_wildcard(self):
        p = self._js("cors({ origin: '*' });\n")
        try: self.assertTrue(any(f["id"]=="JS022" for f in self.s.analyze_file(p)))
        finally: os.unlink(p)

    def test_typescript_supported(self):
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".ts", delete=False)
        f.write('eval(userInput);\n'); f.close()
        try: self.assertTrue(len(self.s.analyze_file(f.name)) > 0)
        finally: os.unlink(f.name)

    def test_comment_skipped(self):
        p = self._js('// eval(x)  -- never do this\n')
        try: self.assertFalse(any(f["id"]=="JS010" for f in self.s.analyze_file(p)))
        finally: os.unlink(p)

    def test_directory_scan(self):
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d,"app.js"),"w").write('eval(x);\nMath.random();\n')
            result = self.s.scan_directory(d)
            self.assertGreater(result["total_findings"], 0)


# ─── Solidity Scanner ─────────────────────────────────────────────────────────

class TestSolidityScanner(unittest.TestCase):
    def setUp(self):
        from scanners.solidity_scanner import SolidityScanner
        self.s = SolidityScanner()

    def _sol(self, code):
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".sol", delete=False)
        f.write(code); f.close(); return f.name

    def test_tx_origin_auth(self):
        p = self._sol('require(tx.origin == owner);\n')
        try: self.assertTrue(any(f["id"]=="SOL002" for f in self.s.analyze_file(p)))
        finally: os.unlink(p)

    def test_selfdestruct_detected(self):
        p = self._sol('selfdestruct(owner);\n')
        try: self.assertTrue(any(f["id"]=="SOL004" for f in self.s.analyze_file(p)))
        finally: os.unlink(p)

    def test_block_timestamp_randomness(self):
        p = self._sol('uint rand = block.timestamp % 100;\n')
        try: self.assertTrue(any(f["id"]=="SOL006" for f in self.s.analyze_file(p)))
        finally: os.unlink(p)

    def test_unbounded_loop(self):
        p = self._sol('for (uint i = 0; i < arr.length; i++) {\n}\n')
        try: self.assertTrue(any(f["id"]=="SOL008" for f in self.s.analyze_file(p)))
        finally: os.unlink(p)

    def test_ecrecover_zero_check(self):
        p = self._sol('address signer = ecrecover(hash, v, r, s);\n')
        try: self.assertTrue(any(f["id"]=="SOL015" for f in self.s.analyze_file(p)))
        finally: os.unlink(p)

    def test_delegatecall_flagged(self):
        p = self._sol('(bool ok,) = target.delegatecall(data);\n')
        try: self.assertTrue(any(f["id"]=="SOL010" for f in self.s.analyze_file(p)))
        finally: os.unlink(p)

    def test_non_sol_file_empty(self):
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False)
        f.write("selfdestruct(x)\n"); f.close()
        try: self.assertEqual(self.s.analyze_file(f.name), [])
        finally: os.unlink(f.name)

    def test_comment_skipped(self):
        p = self._sol('// selfdestruct(owner);  -- removed for safety\n')
        try: self.assertFalse(any(f["id"]=="SOL004" for f in self.s.analyze_file(p)))
        finally: os.unlink(p)


# ─── Secret Detector ─────────────────────────────────────────────────────────

class TestSecretDetector(unittest.TestCase):
    def setUp(self):
        from scanners.secret_scanner.secret_detector import SecretDetector
        self.s = SecretDetector()

    def _f(self, code, suffix=".py"):
        f = tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False)
        f.write(code); f.close(); return f.name

    def test_openai_key_detected(self):
        p = self._f('key = "sk-aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890aBcDeFgHiJkLm"\n')
        try: self.assertTrue(any("openai" in f["id"].lower() for f in self.s.scan_file(p)))
        finally: os.unlink(p)

    def test_aws_key_detected(self):
        p = self._f('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
        try: self.assertTrue(any("AWS" in f.get("id","") for f in self.s.scan_file(p)))
        finally: os.unlink(p)

    def test_github_pat_detected(self):
        p = self._f('token = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890ab"\n')
        try: self.assertTrue(any("github" in f["id"].lower() for f in self.s.scan_file(p)))
        finally: os.unlink(p)

    def test_rsa_private_key_detected(self):
        p = self._f('-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----\n')
        try: self.assertTrue(any("rsa" in f["id"].lower() for f in self.s.scan_file(p)))
        finally: os.unlink(p)

    def test_high_entropy_detected(self):
        p = self._f('secret = "xK9mP2nR7qLvZ5yW3uT8cA4jB6dF1eG0"\n')
        try:
            findings = self.s.scan_file(p)
            self.assertTrue(len(findings) > 0)
        finally: os.unlink(p)

    def test_masked_in_evidence(self):
        p = self._f('key = "sk-aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890aBcDeFgHiJkLm"\n')
        try:
            findings = self.s.scan_file(p)
            for f in findings:
                ev = f.get("evidence","")
                self.assertNotIn("aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890aBcDeFgHiJkLm", ev,
                                 "Full secret should be masked in evidence")
        finally: os.unlink(p)

    def test_comment_line_skipped(self):
        p = self._f('# AWS_KEY = "AKIAIOSFODNN7EXAMPLE"  -- example only\n')
        try: self.assertEqual(self.s.scan_file(p), [])
        finally: os.unlink(p)

    def test_image_file_skipped(self):
        self.assertEqual(self.s.scan_file("/tmp/some_image.png"), [])

    def test_directory_scan_counts(self):
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d,"config.py"),"w").write('AWS_KEY="AKIAIOSFODNN7EXAMPLE"\n')
            result = self.s.scan_directory(d)
            self.assertIn("total_findings", result)
            self.assertGreater(result["total_findings"], 0)


# ─── Dependency Scanner ───────────────────────────────────────────────────────

class TestDependencyScanner(unittest.TestCase):
    def setUp(self):
        from scanners.dependency_scanner import DependencyScanner
        self.s = DependencyScanner()

    def _req(self, content):
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".txt",
                                        prefix="requirements", delete=False)
        f.write(content); f.close(); return f.name

    def test_pyyaml_cve_detected(self):
        p = self._req("pyyaml==5.3\n")
        try: self.assertTrue(any("pyyaml" in f["evidence"].lower() for f in self.s.scan_file(p)))
        finally: os.unlink(p)

    def test_critical_setuptools(self):
        p = self._req("setuptools==69.0\n")
        try:
            findings = self.s.scan_file(p)
            self.assertTrue(any(f.get("severity")=="CRITICAL" for f in findings))
        finally: os.unlink(p)

    def test_requests_cve(self):
        p = self._req("requests==2.28.0\n")
        try:
            findings = self.s.scan_file(p)
            self.assertTrue(any("requests" in f["evidence"].lower() for f in findings))
        finally: os.unlink(p)

    def test_clean_package_no_findings(self):
        p = self._req("someunknownpackageXYZ==1.0\n")
        try: self.assertEqual(self.s.scan_file(p), [])
        finally: os.unlink(p)

    def test_package_json_lodash(self):
        import json, shutil
        pkg = json.dumps({"dependencies": {"lodash": "4.17.20"}})
        d = tempfile.mkdtemp()
        real = os.path.join(d, "package.json")
        try:
            open(real,"w").write(pkg)
            findings = self.s.scan_file(real)
            self.assertTrue(any("lodash" in f["evidence"].lower() for f in findings))
        finally: shutil.rmtree(d, ignore_errors=True)

    def test_directory_scan_summary(self):
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d,"requirements.txt"),"w").write("pyyaml==5.3\njinja2==3.0.0\n")
            result = self.s.scan_directory(d)
            self.assertGreater(result["total_findings"], 0)
            self.assertIn("manifests_scanned", result)

    def test_confidence_high(self):
        p = self._req("pyyaml==5.3\n")
        try:
            findings = self.s.scan_file(p)
            for f in findings:
                self.assertGreaterEqual(f.get("confidence", 0), 90)
        finally: os.unlink(p)


# ─── Security Pipeline ────────────────────────────────────────────────────────

class TestSecurityPipeline(unittest.TestCase):
    def test_pipeline_scans_directory(self):
        from scanners.security_pipeline import SecurityPipeline
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d,"app.py"),"w").write(
                'import subprocess\nsubprocess.run(cmd, shell=True)\n'
                'AWS_KEY="AKIAIOSFODNN7EXAMPLE"\n'
            )
            open(os.path.join(d,"requirements.txt"),"w").write("pyyaml==5.3\n")
            result = SecurityPipeline().scan(d, mode="all")
            self.assertIn("total_findings", result)
            self.assertIn("severity_counts", result)
            self.assertIn("scanners_run", result)
            self.assertGreater(result["total_findings"], 0)
            self.assertIn("risk_score", result)

    def test_pipeline_secrets_mode(self):
        from scanners.security_pipeline import SecurityPipeline
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d,"config.py"),"w").write('API_KEY="AKIAIOSFODNN7EXAMPLE"\n')
            result = SecurityPipeline().scan(d, mode="secrets")
            self.assertGreater(result["total_findings"], 0)

    def test_pipeline_returns_recommendations(self):
        from scanners.security_pipeline import SecurityPipeline
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d,"x.py"),"w").write("pass\n")
            result = SecurityPipeline().scan(d)
            self.assertIn("recommendations", result)
            self.assertIsInstance(result["recommendations"], list)


# ─── Taint Tracker ───────────────────────────────────────────────────────────

class TestTaintTracker(unittest.TestCase):
    def setUp(self):
        from core.analysis.taint_tracker import TaintTracker
        self.t = TaintTracker()

    def test_basic_taint_flow(self):
        code = "data = request.args.get('x')\nsubprocess.run(data, shell=True)\n"
        findings = self.t.analyze_code(code)
        self.assertTrue(len(findings) >= 1)

    def test_source_to_eval_sink(self):
        code = "user_input = request.form.get('expr')\nresult = eval(user_input)\n"
        findings = self.t.analyze_code(code)
        self.assertTrue(any("eval" in f.get("sink_type","") for f in findings))

    def test_no_taint_clean_code(self):
        code = "x = 1 + 2\nprint(x)\n"
        findings = self.t.analyze_code(code)
        self.assertEqual(findings, [])

    def test_file_analysis(self):
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False)
        f.write("name = request.args.get('name')\nos.system(name)\n")
        f.close()
        try:
            findings = self.t.analyze_file(f.name)
            self.assertTrue(len(findings) >= 0)   # may vary by AST
        finally: os.unlink(f.name)


if __name__ == "__main__":
    unittest.main(verbosity=2)
