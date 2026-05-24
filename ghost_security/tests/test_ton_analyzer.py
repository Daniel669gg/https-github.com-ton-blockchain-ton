"""
Ghost Security Platform — TON Analyzer Unit Tests
Run: python3 -m pytest tests/test_ton_analyzer.py -v
  or: python3 tests/test_ton_analyzer.py
"""
import os, sys, tempfile, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scanners.ton_scanner.ton_analyzer import TONAnalyzer

def w(content, suffix=".fc"):
    f = tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False)
    f.write(content); f.close(); return f.name

class TestFiltering(unittest.TestCase):
    def setUp(self): self.a = TONAnalyzer()
    def test_unsupported_ext(self):
        p = w("accept_message()", ".py")
        try: self.assertEqual(self.a.analyze_file(p), [])
        finally: os.unlink(p)
    def test_missing_file(self):
        self.assertEqual(self.a.analyze_file("/tmp/ghost_no_exist_xyz.fc"), [])

class TestTON001(unittest.TestCase):
    def setUp(self): self.a = TONAnalyzer()
    def test_detected(self):
        p = w("accept_message();\n")
        try: self.assertIn("TON001", [f["id"] for f in self.a.analyze_file(p)])
        finally: os.unlink(p)
    def test_comment_skipped(self):
        p = w(";; accept_message()\n")
        try: self.assertNotIn("TON001", [f["id"] for f in self.a.analyze_file(p)])
        finally: os.unlink(p)

class TestTON002(unittest.TestCase):
    def setUp(self): self.a = TONAnalyzer()
    def test_mode64(self):
        """Mode 64 = forward inbound value, safe — no CRITICAL drain finding."""
        p = w("send_raw_message(m, 64);\n")
        try:
            crits = [f for f in self.a.analyze_file(p) if f.get("severity") == "CRITICAL"]
            self.assertEqual(len(crits), 0)
        finally: os.unlink(p)
    def test_mode128(self):
        p = w("send_raw_message(m, 128);\n")
        try: self.assertIn("TON002", [f["id"] for f in self.a.analyze_file(p)])
        finally: os.unlink(p)
    def test_mode0_safe(self):
        p = w("send_raw_message(m, 0);\n")
        try: self.assertNotIn("TON002", [f["id"] for f in self.a.analyze_file(p)])
        finally: os.unlink(p)

class TestTON008Randomness(unittest.TestCase):
    def setUp(self): self.a = TONAnalyzer()
    def test_now_flagged(self):
        p = w("int s = now();\n")
        try: self.assertIn("TON008", [f["id"] for f in self.a.analyze_file(p)])
        finally: os.unlink(p)
    def test_rand_flagged(self):
        p = w("int r = rand(100);\n")
        try: self.assertIn("TON024", [f["id"] for f in self.a.analyze_file(p)])
        finally: os.unlink(p)

class TestTON015(unittest.TestCase):
    def setUp(self): self.a = TONAnalyzer()
    def test_no_sig_flagged(self):
        p = w("() recv_external(slice s) impure {\n  accept_message();\n}\n")
        try: self.assertIn("TON015", [f["id"] for f in self.a.analyze_file(p)])
        finally: os.unlink(p)
    def test_with_sig_ok(self):
        p = w("() recv_external(slice s) impure {\n  throw_unless(35, check_signature(h,sig,pk));\n  accept_message();\n}\n")
        try: self.assertNotIn("TON015", [f["id"] for f in self.a.analyze_file(p)])
        finally: os.unlink(p)

class TestTON022(unittest.TestCase):
    def setUp(self): self.a = TONAnalyzer()
    def test_zero_code_flagged(self):
        p = w("throw_if(0, c);\n")
        try: self.assertIn("TON022", [f["id"] for f in self.a.analyze_file(p)])
        finally: os.unlink(p)
    def test_nonzero_ok(self):
        p = w("throw_if(401, c);\n")
        try: self.assertNotIn("TON022", [f["id"] for f in self.a.analyze_file(p)])
        finally: os.unlink(p)

class TestOther(unittest.TestCase):
    def setUp(self): self.a = TONAnalyzer()
    def test_set_code(self):
        p = w("set_code(new);\n")
        try: self.assertIn("TON018", [f["id"] for f in self.a.analyze_file(p)])
        finally: os.unlink(p)
    def test_repeat(self):
        p = w("repeat(n) { x(); }\n")
        try: self.assertIn("TON007", [f["id"] for f in self.a.analyze_file(p)])
        finally: os.unlink(p)
    def test_preload_uint(self):
        p = w("int op = s.preload_uint(32);\n")
        try: self.assertIn("TON014", [f["id"] for f in self.a.analyze_file(p)])
        finally: os.unlink(p)

class TestSorted(unittest.TestCase):
    def test_severity_order(self):
        a = TONAnalyzer()
        p = w("now();\naccept_message();\nrand(10);\n")
        try:
            findings = a.analyze_file(p)
            order = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}
            sevs = [order[f["severity"]] for f in findings]
            self.assertEqual(sevs, sorted(sevs))
        finally: os.unlink(p)

class TestTact(unittest.TestCase):
    def setUp(self): self.a = TONAnalyzer()
    def test_owner_no_getter(self):
        p = w("contract C {\n  owner: Address;\n  init(o: Address) { self.owner = o; }\n}\n", ".tact")
        try: self.assertIn("TON032", [f["id"] for f in self.a.analyze_file(p)])
        finally: os.unlink(p)
    def test_owner_with_getter(self):
        p = w("contract C {\n  owner: Address;\n  init(o: Address) { self.owner = o; }\n  get fun owner(): Address { return self.owner; }\n}\n", ".tact")
        try: self.assertNotIn("TON032", [f["id"] for f in self.a.analyze_file(p)])
        finally: os.unlink(p)
    def test_receive_no_guard(self):
        p = w("contract C {\n  v: Int;\n  receive(m: M) {\n    self.v = m.x;\n  }\n}\n", ".tact")
        try: self.assertIn("TON033", [f["id"] for f in self.a.analyze_file(p)])
        finally: os.unlink(p)

class TestDirectory(unittest.TestCase):
    def test_scan_dir(self):
        a = TONAnalyzer()
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d,"w.fc"),"w").write("accept_message();\n")
            open(os.path.join(d,"x.py"),"w").write("pass\n")
            r = a.scan_directory(d)
            self.assertEqual(r["files_scanned"], 1)
            self.assertGreater(r["total_findings"], 0)

class TestRules(unittest.TestCase):
    def test_rules_count(self):
        self.assertGreaterEqual(len(TONAnalyzer().get_rules_summary()), 20)
    def test_rules_sorted(self):
        rules = TONAnalyzer().get_rules_summary()
        ids = [r["id"] for r in rules]
        self.assertEqual(ids, sorted(ids))

if __name__ == "__main__":
    unittest.main(verbosity=2)


# ── Dependency Scanner tests ──────────────────────────────────────────────────

class TestDependencyScanner(unittest.TestCase):
    def setUp(self):
        from scanners.dependency_scanner import DependencyScanner
        self.d = DependencyScanner()

    def _tmp(self, content, suffix=".txt"):
        f = tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False)
        f.write(content); f.close(); return f.name

    def test_detects_pyyaml_cve(self):
        p = self._tmp("pyyaml==5.3\n")
        try:
            findings = self.d.scan_file(p)
            self.assertTrue(any("pyyaml" in f["evidence"].lower() for f in findings))
        finally: os.unlink(p)

    def test_detects_setuptools_critical(self):
        p = self._tmp("setuptools==69.0\n")
        try:
            findings = self.d.scan_file(p)
            crits = [f for f in findings if f.get("severity") == "CRITICAL"]
            self.assertGreater(len(crits), 0)
        finally: os.unlink(p)

    def test_clean_requirements_no_findings(self):
        # Made-up package with no known CVEs
        p = self._tmp("myunknownpackage==1.0\n")
        try:
            findings = self.d.scan_file(p)
            self.assertEqual(findings, [])
        finally: os.unlink(p)

    def test_package_json_parsed(self):
        import json, shutil
        pkg = json.dumps({"dependencies": {"lodash": "4.17.20", "safe-lib": "1.0.0"}})
        d = tempfile.mkdtemp()
        real = os.path.join(d, "package.json")
        try:
            open(real,"w").write(pkg)
            findings = self.d.scan_file(real)
            self.assertTrue(any("lodash" in f["evidence"].lower() for f in findings))
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_directory_scan_returns_summary(self):
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d,"requirements.txt"),"w").write("pyyaml==5.3\n")
            result = self.d.scan_directory(d)
            self.assertIn("manifests_scanned", result)
            self.assertGreater(result["total_findings"], 0)


# ── SARIF Exporter tests ──────────────────────────────────────────────────────

class TestSARIFExporter(unittest.TestCase):
    def setUp(self):
        from reports.sarif_exporter import SARIFExporter
        self.exp = SARIFExporter()
        self.sample_report = {
            "target": "test.fc",
            "timestamp": "2025-01-01T00:00:00Z",
            "risk_score": 42,
            "risk_level": "MEDIUM",
            "findings": [{
                "id": "TON001", "type": "TON_VULNERABILITY",
                "severity": "HIGH", "file": "wallet.fc", "line": 5,
                "description": "Unconditional accept_message()",
                "evidence": "accept_message();",
                "recommendation": "Validate sender first",
                "cwe": "CWE-284", "source": "ton_analyzer", "category": "Access Control",
            }],
        }

    def test_sarif_version(self):
        sarif = self.exp.export(self.sample_report)
        self.assertEqual(sarif["version"], "2.1.0")

    def test_sarif_has_one_result(self):
        sarif = self.exp.export(self.sample_report)
        self.assertEqual(len(sarif["runs"][0]["results"]), 1)

    def test_sarif_rule_generated(self):
        sarif = self.exp.export(self.sample_report)
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        self.assertTrue(any(r["id"] == "TON001" for r in rules))

    def test_sarif_severity_mapping(self):
        sarif = self.exp.export(self.sample_report)
        result = sarif["runs"][0]["results"][0]
        self.assertEqual(result["level"], "error")  # HIGH → error

    def test_sarif_empty_findings(self):
        report = dict(self.sample_report, findings=[])
        sarif = self.exp.export(report)
        self.assertEqual(sarif["runs"][0]["results"], [])

    def test_sarif_export_to_file(self):
        with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as f:
            path = f.name
        try:
            self.exp.export_to_file(self.sample_report, path)
            import json
            data = json.loads(open(path).read())
            self.assertEqual(data["version"], "2.1.0")
        finally:
            os.unlink(path)


# ── CVSS Calculator tests ─────────────────────────────────────────────────────

class TestCVSSCalculator(unittest.TestCase):
    def setUp(self):
        from scanners.llm_analyzer import CVSSCalculator
        self.calc = CVSSCalculator

    def test_known_cwe_returns_score(self):
        res = self.calc.score_from_cwe("CWE-78")
        self.assertGreater(res["score"], 0)
        self.assertIn("CVSS:3.1", res["vector"])

    def test_unknown_cwe_returns_zero(self):
        res = self.calc.score_from_cwe("CWE-9999")
        self.assertEqual(res["score"], 0.0)

    def test_dos_cwe_mapped(self):
        res = self.calc.score_from_cwe("CWE-400")
        self.assertGreater(res["score"], 0)

    def test_auth_bypass_critical(self):
        res = self.calc.score_from_cwe("CWE-78")
        self.assertGreaterEqual(res["score"], 7.0)


# ── LLM Analyzer fallback (no API key) ───────────────────────────────────────

class TestLLMAnalyzerFallback(unittest.TestCase):
    def test_fallback_adds_confidence(self):
        from scanners.llm_analyzer import LLMAnalyzer
        analyzer = LLMAnalyzer()
        findings = [{"id":"TON001","severity":"HIGH","description":"test","evidence":"x"}]
        result = analyzer.enrich_findings(list(findings))
        self.assertIn("confidence", result[0])
        self.assertIn("cvss_score", result[0])
        self.assertIn("false_positive_risk", result[0])

    def test_fallback_critical_higher_score(self):
        from scanners.llm_analyzer import LLMAnalyzer
        analyzer = LLMAnalyzer()
        findings = [
            {"id":"A","severity":"CRITICAL","description":"x","evidence":"y"},
            {"id":"B","severity":"INFO","description":"x","evidence":""},
        ]
        result = analyzer.enrich_findings(list(findings))
        scores = {f["id"]: f["cvss_score"] for f in result}
        self.assertGreater(scores["A"], scores["B"])


# ── ModelRouter tests ─────────────────────────────────────────────────────────

class TestModelRouter(unittest.TestCase):
    def test_status_has_required_keys(self):
        from runtime.model_router import ModelRouter
        status = ModelRouter().status()
        for key in ("ollama_available","cloud_available","active_backend","routes"):
            self.assertIn(key, status)

    def test_route_returns_string(self):
        from runtime.model_router import ModelRouter
        router = ModelRouter()
        for task in ("planning","coding","security","ton","default"):
            model = router.route(task)
            self.assertIsInstance(model, str)
            self.assertGreater(len(model), 0)

    def test_unknown_task_falls_back(self):
        from runtime.model_router import ModelRouter
        model = ModelRouter().route("nonexistent_task_xyz")
        self.assertIsInstance(model, str)


# ── ReportGenerator tests ─────────────────────────────────────────────────────

class TestReportGenerator(unittest.TestCase):
    def setUp(self):
        from reports.report_generator import ReportGenerator
        self.rg = ReportGenerator()
        self.report = {
            "target":"wallet.fc","session_id":"x","timestamp":"2025-01-01",
            "risk_score":75,"risk_level":"HIGH","executive_summary":"Found 1 issue.",
            "severity_counts":{"CRITICAL":0,"HIGH":1,"MEDIUM":0,"LOW":0,"INFO":0},
            "total_findings":1,"recommendations":["Fix access control"],
            "findings":[{
                "id":"TON001","type":"TON_VULNERABILITY","severity":"HIGH",
                "file":"wallet.fc","line":3,"description":"Unguarded accept_message",
                "evidence":"accept_message();","recommendation":"Add sender check",
                "cwe":"CWE-284","category":"Access Control","source":"ton_analyzer",
            }],
        }

    def test_html_contains_chartjs(self):
        html = self.rg.generate_html(self.report)
        self.assertIn("chart.js", html.lower())

    def test_html_contains_finding(self):
        html = self.rg.generate_html(self.report)
        self.assertIn("TON001", html)

    def test_html_has_filter_buttons(self):
        html = self.rg.generate_html(self.report)
        self.assertIn("filter-btn", html)

    def test_markdown_has_sections(self):
        md = self.rg.generate_markdown(self.report)
        for section in ("# Ghost Security", "## Severity Summary", "## Findings"):
            self.assertIn(section, md)

    def test_markdown_contains_cwe_link(self):
        md = self.rg.generate_markdown(self.report)
        self.assertIn("CWE-284", md)

    def test_json_valid(self):
        import json
        j = self.rg.generate_json(self.report)
        parsed = json.loads(j)
        self.assertEqual(parsed["risk_level"], "HIGH")
