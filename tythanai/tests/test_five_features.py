"""
Tests for all 5 new features:
1. Multi-LLM Router
2. Vector Memory
3. Telemetry
4. Kubernetes Scanner
5. Remediation Engine
Run: python3 -m unittest tests.test_five_features -v
"""
import os, sys, time, unittest, tempfile, json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ══════════════════════════════════════════════════════════════════
# 1. MULTI-LLM ROUTER
# ══════════════════════════════════════════════════════════════════

class TestMultiLLMRouter(unittest.TestCase):

    def setUp(self):
        from runtime.providers.multi_llm_router import MultiLLMRouter
        self.router = MultiLLMRouter()

    def test_status_structure(self):
        status = self.router.status()
        self.assertIn("providers", status)
        for p in ["claude", "openai", "gemini", "ollama"]:
            self.assertIn(p, status["providers"])

    def test_routing_tasks_exist(self):
        status = self.router.status()
        for task in ["security", "coding", "fast", "ton", "remediation"]:
            self.assertIn(task, status["routing_tasks"])

    def test_call_all_offline_returns_error(self):
        """When no API keys set, router returns error response gracefully."""
        resp = self.router.call("default", "test prompt")
        # Either ok (if Ollama running) or error (if nothing available)
        self.assertIsNotNone(resp)
        self.assertIsNotNone(resp.text is not None or resp.error)

    def test_cost_tracker_records(self):
        from runtime.providers.multi_llm_router import LLMResponse, Provider, CostTracker
        tracker = CostTracker()
        resp = LLMResponse("hello", Provider.OPENAI, "gpt-4o-mini",
                           tokens_in=100, tokens_out=50, cost_usd=0.000075)
        tracker.record(resp)
        summary = tracker.summary()
        self.assertEqual(summary["total_calls"], 1)
        self.assertAlmostEqual(summary["total_cost_usd"], 0.000075, places=6)

    def test_consensus_engine_vote(self):
        from runtime.providers.multi_llm_router import ConsensusEngine, LLMResponse, Provider
        engine = ConsensusEngine()
        r1 = LLMResponse("parameterized queries prevent SQL injection", Provider.CLAUDE, "c")
        r2 = LLMResponse("use parameterized queries to prevent SQL injection attacks", Provider.OPENAI, "o")
        r3 = LLMResponse("SQL injection prevented via parameterized queries", Provider.GEMINI, "g")
        result = engine.run([r1, r2, r3], strategy="vote")
        self.assertTrue(result.winner.ok)
        self.assertGreater(result.agreement, 0)

    def test_consensus_all_failed(self):
        from runtime.providers.multi_llm_router import ConsensusEngine, LLMResponse, Provider
        engine = ConsensusEngine()
        bad = [LLMResponse("", Provider.CLAUDE, "c", error="fail"),
               LLMResponse("", Provider.OPENAI, "o", error="fail")]
        result = engine.run(bad)
        self.assertEqual(result.method, "fallback")

    def test_consensus_fastest_strategy(self):
        from runtime.providers.multi_llm_router import ConsensusEngine, LLMResponse, Provider
        engine = ConsensusEngine()
        fast = LLMResponse("quick answer", Provider.GEMINI, "flash", latency_ms=200)
        slow = LLMResponse("detailed answer here", Provider.CLAUDE, "sonnet", latency_ms=1500)
        result = engine.run([fast, slow], strategy="fastest")
        self.assertEqual(result.winner.provider, Provider.GEMINI)

    def test_pricing_calc(self):
        from runtime.providers.multi_llm_router import _calc_cost
        cost = _calc_cost("gpt-4o-mini", 1_000_000, 1_000_000)
        self.assertAlmostEqual(cost, 0.75, places=2)  # 0.15 + 0.60


# ══════════════════════════════════════════════════════════════════
# 2. VECTOR MEMORY
# ══════════════════════════════════════════════════════════════════

class TestVectorMemory(unittest.TestCase):

    def setUp(self):
        from memory.vector.ghost_memory import GhostMemory
        self.memory = GhostMemory()

    def _finding(self, ftype: str, sev: str = "HIGH") -> dict:
        return {"type": ftype, "severity": sev, "message": f"{ftype} vulnerability detected",
                "cwe": "CWE-89", "file": "app.py", "line": 10}

    def test_backend_available(self):
        self.assertIn(self.memory.backend, ["qdrant", "chromadb", "in-memory"])

    def test_store_and_retrieve(self):
        f = self._finding("sql_injection", "CRITICAL")
        self.memory.store_finding(f, scan_id="test_scan")
        results = self.memory.similar_findings(f, limit=3)
        self.assertGreater(len(results), 0)
        self.assertGreater(results[0].score, 0)

    def test_similar_finds_same_type(self):
        self.memory.store_finding(self._finding("xss", "HIGH"), "s1")
        self.memory.store_finding(self._finding("sql_injection", "CRITICAL"), "s1")
        self.memory.store_finding(self._finding("ssrf", "HIGH"), "s1")
        query   = self._finding("sql_injection")
        results = self.memory.similar_findings(query, limit=5)
        if results:
            top_text = results[0].text.lower()
            # SQL injection should rank highest
            self.assertIn("sql", top_text)

    def test_batch_store(self):
        findings = [self._finding(t) for t in ["xss", "csrf", "xxe", "ssrf"]]
        self.memory.store_findings_batch(findings, "batch_test")
        results = self.memory.similar_findings(self._finding("xss"), limit=5)
        self.assertGreater(len(results), 0)

    def test_embedding_provider_tfidf(self):
        from memory.vector.ghost_memory import EmbeddingProvider
        ep  = EmbeddingProvider()
        vec = ep._tfidf_embed("SQL injection attack via user input")
        self.assertEqual(len(vec), 64)
        self.assertAlmostEqual(sum(x**2 for x in vec)**0.5, 1.0, places=3)

    def test_cosine_similarity(self):
        from memory.vector.ghost_memory import QdrantMemory
        a = [1.0, 0.0, 0.0]
        b = [1.0, 0.0, 0.0]
        c = [0.0, 1.0, 0.0]
        self.assertAlmostEqual(QdrantMemory._cosine(a, b), 1.0)
        self.assertAlmostEqual(QdrantMemory._cosine(a, c), 0.0)

    def test_finding_text_format(self):
        from memory.vector.ghost_memory import QdrantMemory
        f    = {"type": "xss", "message": "XSS detected", "cwe": "CWE-79", "severity": "HIGH"}
        text = QdrantMemory._finding_text(f)
        self.assertIn("xss", text.lower())
        self.assertIn("CWE-79", text)


# ══════════════════════════════════════════════════════════════════
# 3. TELEMETRY
# ══════════════════════════════════════════════════════════════════

class TestTelemetry(unittest.TestCase):

    def setUp(self):
        from telemetry.metrics import MetricsRegistry, OTelTracer
        self.metrics = MetricsRegistry()
        self.tracer  = OTelTracer("test-service")

    def test_scan_metrics(self):
        self.metrics.scan_started("all", "/app")
        self.metrics.scan_finished("all", 5.2, 15, "success")
        exported = self.metrics.export()
        self.assertIn("ghost_scans_total", exported)
        self.assertIn("ghost_scan_duration_seconds", exported)

    def test_finding_metrics(self):
        self.metrics.finding_recorded("CRITICAL", "TON", "ton_analyzer")
        self.metrics.finding_recorded("HIGH",     "OWASP", "owasp_scanner")
        exported = self.metrics.export()
        self.assertIn("ghost_findings_total", exported)
        self.assertIn("CRITICAL", exported)

    def test_llm_metrics(self):
        self.metrics.llm_call("claude", "claude-haiku-4-5", "security", 800, 0.002, True)
        exported = self.metrics.export()
        self.assertIn("ghost_llm_calls_total", exported)
        self.assertIn("ghost_llm_cost_usd_total", exported)

    def test_api_metrics(self):
        self.metrics.api_call("POST", "/api/scan", 200, 1.5)
        exported = self.metrics.export()
        self.assertIn("ghost_api_requests_total", exported)

    def test_prometheus_format(self):
        exported = self.metrics.export()
        self.assertIn("# HELP", exported)
        self.assertIn("# TYPE", exported)
        self.assertIn("counter", exported)
        self.assertIn("histogram", exported)

    def test_findings_batch(self):
        findings = [
            {"severity": "CRITICAL", "category": "TON", "source": "ton_analyzer"},
            {"severity": "HIGH",     "category": "OWASP", "source": "owasp_scanner"},
        ]
        self.metrics.findings_batch(findings)
        exported = self.metrics.export()
        self.assertIn("ghost_findings_total", exported)

    def test_tracer_context_manager(self):
        with self.tracer.span("test_operation", {"key": "value"}):
            time.sleep(0.01)
        traces = self.tracer.recent_traces()
        self.assertGreater(len(traces), 0)
        last = traces[-1]
        self.assertEqual(last["span"], "test_operation")
        self.assertGreater(last["duration_ms"], 0)

    def test_grafana_dashboard_json(self):
        from telemetry.metrics import GRAFANA_DASHBOARD
        self.assertIn("title", GRAFANA_DASHBOARD)
        self.assertIn("panels", GRAFANA_DASHBOARD)
        self.assertGreater(len(GRAFANA_DASHBOARD["panels"]), 5)

    def test_time_scan_context(self):
        with self.metrics.time_scan("ton"):
            time.sleep(0.01)
        exported = self.metrics.export()
        self.assertIn("ghost_scan_duration_seconds", exported)


# ══════════════════════════════════════════════════════════════════
# 4. KUBERNETES SCANNER
# ══════════════════════════════════════════════════════════════════

class TestK8sScanner(unittest.TestCase):

    _PRIVILEGED_MANIFEST = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vuln-app
  namespace: production
spec:
  template:
    spec:
      hostNetwork: true
      containers:
      - name: app
        image: nginx:latest
        securityContext:
          privileged: true
          runAsUser: 0
        env:
        - name: DB_PASSWORD
          value: supersecret
        resources: {}
"""
    _CLUSTER_ADMIN_MANIFEST = """
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: dangerous
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: ServiceAccount
  name: myapp
  namespace: prod
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: all-perms
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
"""
    _SAFE_MANIFEST = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secure-app
  namespace: production
spec:
  template:
    spec:
      containers:
      - name: app
        image: nginx:1.25.3
        securityContext:
          privileged: false
          runAsNonRoot: true
          runAsUser: 1000
          allowPrivilegeEscalation: false
        resources:
          limits:
            cpu: "500m"
            memory: "256Mi"
          requests:
            cpu: "100m"
            memory: "64Mi"
"""

    def setUp(self):
        from scanners.k8s_scanner.k8s_scanner import ManifestScanner
        self.scanner = ManifestScanner()

    def _ids(self, findings) -> set:
        return {f.rule_id if hasattr(f, "rule_id") else f.get("rule_id") for f in findings}

    def test_privileged_detected(self):
        findings = self.scanner.scan_string(self._PRIVILEGED_MANIFEST)
        ids = self._ids(findings)
        self.assertIn("K8S-POD-004", ids)

    def test_root_user_detected(self):
        findings = self.scanner.scan_string(self._PRIVILEGED_MANIFEST)
        ids = self._ids(findings)
        self.assertIn("K8S-POD-005", ids)

    def test_secret_env_detected(self):
        findings = self.scanner.scan_string(self._PRIVILEGED_MANIFEST)
        ids = self._ids(findings)
        self.assertIn("K8S-SEC-001", ids)

    def test_latest_tag_detected(self):
        findings = self.scanner.scan_string(self._PRIVILEGED_MANIFEST)
        ids = self._ids(findings)
        self.assertIn("K8S-IMG-001", ids)

    def test_cluster_admin_detected(self):
        findings = self.scanner.scan_string(self._CLUSTER_ADMIN_MANIFEST)
        ids = self._ids(findings)
        self.assertIn("K8S-RBAC-001", ids)

    def test_wildcard_rbac_detected(self):
        findings = self.scanner.scan_string(self._CLUSTER_ADMIN_MANIFEST)
        ids = self._ids(findings)
        self.assertIn("K8S-RBAC-004", ids)

    def test_critical_for_privileged(self):
        findings = self.scanner.scan_string(self._PRIVILEGED_MANIFEST)
        crits = [f for f in findings
                 if (f.severity if hasattr(f,"severity") else f.get("severity")) == "CRITICAL"]
        self.assertGreater(len(crits), 0)

    def test_safe_manifest_no_critical(self):
        findings = self.scanner.scan_string(self._SAFE_MANIFEST)
        crits = [f for f in findings
                 if (f.severity if hasattr(f,"severity") else f.get("severity")) == "CRITICAL"]
        self.assertEqual(len(crits), 0, f"FP CRITICALs: {[f.rule_id for f in crits]}")

    def test_file_scan(self):
        import shutil
        tmpdir = tempfile.mkdtemp()
        try:
            path = os.path.join(tmpdir, "deploy.yaml")
            with open(path, "w") as f:
                f.write(self._PRIVILEGED_MANIFEST)
            from scanners.k8s_scanner.k8s_scanner import K8sSecurityScanner
            result = K8sSecurityScanner().scan(tmpdir, mode="manifest")
            self.assertGreater(result["total"], 0)
            self.assertIn("severity_counts", result)
        finally:
            shutil.rmtree(tmpdir)


# ══════════════════════════════════════════════════════════════════
# 5. REMEDIATION ENGINE
# ══════════════════════════════════════════════════════════════════

class TestRemediationEngine(unittest.TestCase):

    def setUp(self):
        from remediation.remediation_engine import RemediationEngine, PatternFixer, PatchValidator
        self.engine    = RemediationEngine()
        self.fixer     = PatternFixer()
        self.validator = PatchValidator()

    def _finding(self, ftype: str, sev: str = "HIGH", **kw) -> dict:
        return {"type": ftype, "severity": sev, "file": "app.py", "line": 5,
                "message": f"{ftype} detected", **kw}

    # ── Pattern fixer ──────────────────────────────────────────────

    def test_weak_hash_fix(self):
        code  = "digest = hashlib.md5(data).hexdigest()"
        patch = self.fixer.fix(self._finding("weak_hash"), code)
        self.assertIsNotNone(patch)
        self.assertIn("sha256", patch.fixed)
        self.assertNotIn("md5", patch.fixed)

    def test_sha1_fix(self):
        code  = "digest = hashlib.sha1(data).hexdigest()"
        patch = self.fixer.fix(self._finding("weak_hash"), code)
        self.assertIsNotNone(patch)
        self.assertIn("sha256", patch.fixed)

    def test_shell_injection_fix(self):
        code  = "result = subprocess.run(user_input, shell=True)"
        patch = self.fixer.fix(self._finding("shell_injection"), code)
        self.assertIsNotNone(patch)
        self.assertIn("shell=False", patch.fixed)

    def test_debug_mode_fix(self):
        code  = "app.run(host='0.0.0.0', debug=True, port=5000)"
        patch = self.fixer.fix(self._finding("debug_mode"), code)
        self.assertIsNotNone(patch)
        self.assertIn("debug=False", patch.fixed)

    def test_k8s_privileged_fix(self):
        code  = "          privileged: true"
        patch = self.fixer.fix({"type": "k8s_pod_004", "severity": "CRITICAL",
                                 "file": "deploy.yaml", "line": 10}, code)
        self.assertIsNotNone(patch)
        self.assertIn("privileged: false", patch.fixed)

    def test_k8s_latest_tag_fix(self):
        code  = "        image: nginx:latest"
        patch = self.fixer.fix({"type": "k8s_img", "severity": "LOW",
                                 "file": "deploy.yaml", "line": 5}, code)
        self.assertIsNotNone(patch)
        self.assertNotIn(":latest", patch.fixed)

    # ── Diff generation ───────────────────────────────────────────

    def test_patch_has_diff(self):
        code  = "digest = hashlib.md5(data).hexdigest()"
        patch = self.fixer.fix(self._finding("weak_hash"), code)
        self.assertIsNotNone(patch)
        self.assertIn("---", patch.diff)
        self.assertIn("+++", patch.diff)
        self.assertIn("-", patch.diff)
        self.assertIn("+", patch.diff)

    # ── Patch validator ───────────────────────────────────────────

    def test_validator_valid_python(self):
        valid, reason = self.validator._validate_python("x = 1\ny = x + 2\nprint(y)")
        self.assertTrue(valid)

    def test_validator_invalid_python(self):
        valid, reason = self.validator._validate_python("def bad(:\n    pass")
        self.assertFalse(valid)

    def test_validator_valid_yaml(self):
        valid, _ = self.validator._validate_yaml("apiVersion: v1\nkind: Pod")
        self.assertTrue(valid)

    def test_validator_invalid_yaml(self):
        valid, _ = self.validator._validate_yaml("key: [unclosed")
        self.assertFalse(valid)

    # ── Engine integration ────────────────────────────────────────

    def test_engine_generate_pattern(self):
        code  = "digest = hashlib.sha1(secret).hexdigest()"
        patch = self.engine.generate(
            self._finding("weak_hash"), code_context=code, use_llm=False
        )
        self.assertIsNotNone(patch)
        self.assertEqual(patch.method, "pattern")
        self.assertTrue(patch.confidence >= 0.85)

    def test_engine_history(self):
        code  = "subprocess.run(cmd, shell=True)"
        self.engine.generate(self._finding("shell_injection"), code_context=code, use_llm=False)
        history = self.engine.history()
        self.assertGreater(len(history), 0)

    def test_engine_batch(self):
        findings = [
            {"type": "weak_hash",       "severity": "HIGH",   "file": "a.py", "line": 1},
            {"type": "shell_injection",  "severity": "CRITICAL", "file": "b.py", "line": 2},
            {"type": "debug_mode",       "severity": "HIGH",   "file": "c.py", "line": 3},
        ]
        codes = [
            "hashlib.md5(x)",
            "subprocess.run(cmd, shell=True)",
            "app.run(debug=True)",
        ]
        patches = []
        for f, c in zip(findings, codes):
            p = self.engine.generate(f, code_context=c, use_llm=False)
            if p:
                patches.append(p)
        self.assertGreater(len(patches), 0)

    def test_rollback_without_apply(self):
        from remediation.remediation_engine import RemediationPatch
        patch = RemediationPatch(
            "id1", "weak_hash", "app.py", 5,
            "original", "fixed", "diff", "desc", "pattern", 0.9
        )
        success, msg = self.engine.rollback(patch)
        self.assertFalse(success)  # not applied yet


if __name__ == "__main__":
    unittest.main(verbosity=2)
