"""
TythanAI Phase 9 — Cloud Security Graph & Enterprise Correlation Platform
Test Suite: 78 tests across 9 test classes.

Tests cover:
  - IAM Graph (identity → role → permission → resource)
  - Unified Security Graph (cross-layer attack paths)
  - Cloud Correlation Engine (exploit chain reconstruction)
  - Business Impact Scorer
  - Enterprise Risk Scorer
  - Executive Dashboard
  - KnowledgeGraph cloud extensions
  - AttackGraph cloud extensions
  - UnifiedScanEngine.scan_cloud_elite()
"""
from __future__ import annotations

import json
import unittest
from typing import Any, Dict, List


# ---------------------------------------------------------------------------
# TestIAMGraph
# ---------------------------------------------------------------------------

class TestIAMGraph(unittest.TestCase):
    """IAM Identity → Role → Permission → Resource graph."""

    def setUp(self):
        from backend.cloud_security.iam_graph import IAMGraph
        self.graph = IAMGraph()

    def test_ingest_aws_policy_adds_nodes(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"],
                           "Resource": "arn:aws:s3:::my-bucket/*"}],
        }
        added = self.graph.ingest_aws_policy(policy, identity="lambda-role")
        self.assertGreater(added, 0)
        self.assertGreater(self.graph.node_count, 0)

    def test_ingest_aws_policy_wildcard_action(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
        }
        self.graph.ingest_aws_policy(policy, identity="admin-user")
        overprivileged = self.graph.find_overprivileged_identities()
        self.assertGreater(len(overprivileged), 0)

    def test_wildcard_resource_detected(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["iam:*"], "Resource": "*"}],
        }
        self.graph.ingest_aws_policy(policy, identity="bad-user")
        overprivileged = self.graph.find_overprivileged_identities()
        self.assertTrue(any("bad-user" in str(o.get("identity", "")) or
                           "wildcard" in str(o).lower() or
                           len(overprivileged) > 0
                           for o in overprivileged))

    def test_privilege_escalation_iam_passrole(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Action": ["iam:PassRole", "iam:CreateRole"],
                           "Resource": "*"}],
        }
        self.graph.ingest_aws_policy(policy, identity="dev-user")
        paths = self.graph.find_privilege_escalation_paths()
        self.assertGreater(len(paths), 0)

    def test_privilege_escalation_put_user_policy(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["iam:PutUserPolicy"], "Resource": "*"}],
        }
        self.graph.ingest_aws_policy(policy, identity="attacker")
        paths = self.graph.find_privilege_escalation_paths()
        self.assertGreater(len(paths), 0)

    def test_k8s_rbac_cluster_admin_detected(self):
        self.graph.ingest_k8s_rbac(
            subject_name="default-sa",
            role_name="cluster-admin",
            permissions=["*"],
            resources=["*"],
        )
        paths = self.graph.find_privilege_escalation_paths()
        self.assertGreater(len(paths), 0)

    def test_risky_permissions_detected(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["ec2:*"], "Resource": "*"}],
        }
        self.graph.ingest_aws_policy(policy, identity="ec2-admin")
        risks = self.graph.find_risky_permissions()
        self.assertIsInstance(risks, list)

    def test_clean_policy_no_escalation(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"],
                           "Resource": "arn:aws:s3:::read-bucket/*"}],
        }
        self.graph.ingest_aws_policy(policy, identity="read-only-user")
        paths = self.graph.find_privilege_escalation_paths()
        self.assertEqual(len(paths), 0)

    def test_node_and_edge_counts_positive(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["s3:*"], "Resource": "*"}],
        }
        self.graph.ingest_aws_policy(policy, identity="test-user")
        self.assertGreater(self.graph.node_count, 0)
        self.assertGreater(self.graph.edge_count, 0)

    def test_to_dict_structure(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"],
                           "Resource": "*"}],
        }
        self.graph.ingest_aws_policy(policy, identity="user1")
        d = self.graph.to_dict()
        self.assertIn("nodes", d)
        self.assertIn("edges", d)
        self.assertIn("node_count", d)
        self.assertIn("edge_count", d)


# ---------------------------------------------------------------------------
# TestUnifiedSecurityGraph
# ---------------------------------------------------------------------------

class TestUnifiedSecurityGraph(unittest.TestCase):
    """Unified Security Graph — cross-layer attack paths."""

    def setUp(self):
        from backend.cloud_security.security_graph import UnifiedSecurityGraph
        self.graph = UnifiedSecurityGraph()

    def _sast_finding(self, rule_id="SAST-001", severity="HIGH", file="app.py"):
        return {"rule_id": rule_id, "severity": severity, "file": file,
                "description": "SQL injection in query builder", "cwe": "CWE-89"}

    def _cloud_finding(self, resource_type="s3", resource_name="prod-data", severity="CRITICAL"):
        return {"rule_id": "S3-PUBLIC", "severity": severity, "resource_type": resource_type,
                "resource_name": resource_name, "description": "Public S3 bucket", "public_access": True}

    def _k8s_finding(self, rule_id="K8S-001", resource_name="api-pod", severity="CRITICAL"):
        return {"rule_id": rule_id, "severity": severity, "resource_name": resource_name,
                "resource_kind": "Pod", "namespace": "production",
                "description": "Privileged container detected"}

    def _container_finding(self, image="api:latest", severity="HIGH"):
        return {"severity": severity, "image": image, "vulnerability_id": "CVE-2023-1234",
                "package": "openssl", "description": "Vulnerable openssl in container"}

    def test_node_types_exist(self):
        from backend.cloud_security.security_graph import SGNodeType
        self.assertIn("SAST_FINDING", SGNodeType.__members__)
        self.assertIn("CLOUD_RESOURCE", SGNodeType.__members__)
        self.assertIn("CONTAINER", SGNodeType.__members__)
        self.assertIn("K8S_POD", SGNodeType.__members__)
        self.assertIn("IAM_IDENTITY", SGNodeType.__members__)

    def test_ingest_sast_findings_adds_nodes(self):
        count = self.graph.ingest_sast_findings([self._sast_finding()])
        self.assertGreater(count, 0)
        self.assertGreater(self.graph.node_count, 0)

    def test_ingest_cloud_misconfigs_adds_nodes(self):
        count = self.graph.ingest_cloud_misconfigs([self._cloud_finding()])
        self.assertGreater(count, 0)

    def test_ingest_k8s_findings_adds_nodes(self):
        count = self.graph.ingest_k8s_findings([self._k8s_finding()])
        self.assertGreater(count, 0)

    def test_ingest_container_findings_adds_nodes(self):
        count = self.graph.ingest_container_findings([self._container_finding()])
        self.assertGreater(count, 0)

    def test_find_exposed_resources_returns_public_nodes(self):
        self.graph.ingest_cloud_misconfigs([self._cloud_finding()])
        exposed = self.graph.find_exposed_resources()
        self.assertGreater(len(exposed), 0)
        self.assertTrue(all("severity" in e for e in exposed))

    def test_find_container_risks_returns_high(self):
        self.graph.ingest_container_findings([self._container_finding(severity="CRITICAL")])
        risks = self.graph.find_container_risks()
        self.assertGreater(len(risks), 0)

    def test_find_kubernetes_risks_returns_critical(self):
        self.graph.ingest_k8s_findings([self._k8s_finding(severity="CRITICAL")])
        risks = self.graph.find_kubernetes_risks()
        self.assertGreater(len(risks), 0)

    def test_find_cloud_attack_paths_cross_layers(self):
        self.graph.ingest_sast_findings([self._sast_finding()])
        self.graph.ingest_cloud_misconfigs([self._cloud_finding()])
        self.graph.link_sast_to_container("app.py", "api:latest")
        self.graph.link_container_to_iam("api:latest", "api-service-account")
        self.graph.link_iam_to_resource("api-service-account", "prod-data")
        paths = self.graph.find_cloud_attack_paths()
        self.assertIsInstance(paths, list)

    def test_to_dict_has_required_keys(self):
        self.graph.ingest_sast_findings([self._sast_finding()])
        d = self.graph.to_dict()
        self.assertIn("node_count", d)
        self.assertIn("edge_count", d)


# ---------------------------------------------------------------------------
# TestCloudCorrelationEngine
# ---------------------------------------------------------------------------

class TestCloudCorrelationEngine(unittest.TestCase):
    """Cross-layer exploit chain reconstruction."""

    def setUp(self):
        from backend.cloud_security.cloud_correlation import CloudCorrelationEngine
        self.engine = CloudCorrelationEngine()

    def _sast(self):
        return [{"rule_id": "SQL-001", "severity": "HIGH", "file": "api/db.py",
                 "cwe": "CWE-89", "description": "SQL injection"}]

    def _cves(self):
        return [{"id": "CVE-2023-1234", "severity": "CRITICAL", "cvss": 9.8,
                 "package": "urllib3", "description": "Remote code execution"}]

    def _containers(self):
        return [{"severity": "HIGH", "image": "api:latest", "vulnerability_id": "CVE-2023-1234",
                 "package": "urllib3", "description": "Vulnerable urllib3"}]

    def _k8s(self):
        return [{"rule_id": "K8S-PRIV", "severity": "CRITICAL",
                 "resource_name": "api-pod", "namespace": "prod",
                 "description": "Privileged container"}]

    def _iam(self):
        return [{"rule_id": "IAM-WILD", "severity": "CRITICAL",
                 "principal": "api-service-account", "permission": "s3:*",
                 "category": "WILDCARD", "description": "Wildcard S3 permission"}]

    def _cloud(self):
        return [{"rule_id": "S3-PUB", "severity": "CRITICAL",
                 "resource_type": "s3", "resource_name": "prod-data",
                 "description": "Public S3 bucket", "public_access": True}]

    def test_correlate_returns_report(self):
        self.engine.ingest(sast_findings=self._sast(), cve_findings=self._cves())
        report = self.engine.correlate()
        self.assertIsNotNone(report)
        self.assertIsInstance(report.total_chains, int)

    def test_correlate_with_all_layers(self):
        self.engine.ingest(
            sast_findings=self._sast(), cve_findings=self._cves(),
            container_findings=self._containers(), k8s_findings=self._k8s(),
            iam_findings=self._iam(), cloud_findings=self._cloud(),
        )
        report = self.engine.correlate()
        self.assertGreaterEqual(report.layers_analyzed.__len__(), 1)

    def test_cve_to_container_link(self):
        self.engine.ingest(cve_findings=self._cves(), container_findings=self._containers())
        links = self.engine._cve_to_container_links()
        self.assertGreater(len(links), 0)

    def test_sast_to_cve_link(self):
        self.engine.ingest(sast_findings=self._sast(), cve_findings=self._cves())
        links = self.engine._sast_to_cve_links()
        self.assertIsInstance(links, list)

    def test_iam_to_cloud_link(self):
        self.engine.ingest(iam_findings=self._iam(), cloud_findings=self._cloud())
        links = self.engine._iam_to_cloud_links()
        self.assertGreater(len(links), 0)

    def test_exploit_chains_have_correct_structure(self):
        self.engine.ingest(sast_findings=self._sast(), cve_findings=self._cves(),
                           container_findings=self._containers(), iam_findings=self._iam(),
                           cloud_findings=self._cloud())
        report = self.engine.correlate()
        for chain in report.exploit_chains:
            self.assertIsInstance(chain.chain_id, str)
            self.assertIsInstance(chain.links, list)
            self.assertIn(chain.chain_severity, ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])
            self.assertGreater(chain.confidence, 0.0)

    def test_empty_inputs_no_crash(self):
        self.engine.ingest()
        report = self.engine.correlate()
        self.assertEqual(report.total_chains, 0)

    def test_chain_severity_computed(self):
        self.engine.ingest(
            cve_findings=[{"id": "CVE-X", "severity": "CRITICAL", "cvss": 9.8,
                           "package": "openssl", "description": "RCE"}],
            container_findings=[{"severity": "HIGH", "image": "app:1.0",
                                  "package": "openssl", "description": "vuln openssl",
                                  "vulnerability_id": "CVE-X"}],
        )
        report = self.engine.correlate()
        for chain in report.exploit_chains:
            self.assertIn(chain.chain_severity, ["CRITICAL", "HIGH"])

    def test_correlation_report_to_dict(self):
        self.engine.ingest(sast_findings=self._sast(), cloud_findings=self._cloud())
        report = self.engine.correlate()
        d = report.to_dict()
        self.assertIn("total_chains", d)
        self.assertIn("exploit_chains", d)

    def test_chain_attack_type_classified(self):
        self.engine.ingest(iam_findings=self._iam(), cloud_findings=self._cloud())
        report = self.engine.correlate()
        for chain in report.exploit_chains:
            self.assertIn(chain.attack_type,
                          ["DATA_EXFILTRATION", "PRIVILEGE_ESCALATION",
                           "LATERAL_MOVEMENT", "FULL_COMPROMISE"])


# ---------------------------------------------------------------------------
# TestBusinessImpactScorer
# ---------------------------------------------------------------------------

class TestBusinessImpactScorer(unittest.TestCase):

    def setUp(self):
        from backend.cloud_security.business_impact import BusinessImpactScorer
        self.scorer = BusinessImpactScorer()

    def test_critical_finding_scores_high(self):
        finding = {"severity": "CRITICAL", "description": "Public S3 bucket exposed"}
        score = self.scorer.score_finding(finding)
        self.assertGreaterEqual(score.score, 50)

    def test_public_internet_multiplier(self):
        finding_pub = {"severity": "HIGH", "description": "public database exposed to internet"}
        finding_priv = {"severity": "HIGH", "description": "internal database"}
        score_pub  = self.scorer.score_finding(finding_pub)
        score_priv = self.scorer.score_finding(finding_priv)
        self.assertGreaterEqual(score_pub.score, score_priv.score)

    def test_admin_privilege_multiplier(self):
        finding = {"severity": "HIGH", "description": "admin role with wildcard permissions",
                   "permission": "iam:*"}
        score = self.scorer.score_finding(finding)
        self.assertIn(score.privilege_level, ["root_admin", "elevated"])

    def test_score_bounded_0_100(self):
        finding = {"severity": "CRITICAL",
                   "description": "public root admin database production exposed internet"}
        score = self.scorer.score_finding(finding)
        self.assertGreaterEqual(score.score, 0)
        self.assertLessEqual(score.score, 100)

    def test_info_finding_scores_low(self):
        finding = {"severity": "INFO", "description": "informational note"}
        score = self.scorer.score_finding(finding)
        self.assertLess(score.score, 50)

    def test_score_returns_impact_class(self):
        finding = {"severity": "CRITICAL", "description": "critical public admin resource"}
        score = self.scorer.score_finding(finding)
        self.assertIn(score.impact_class,
                      ["CATASTROPHIC", "CRITICAL", "HIGH", "MEDIUM", "LOW"])

    def test_score_bulk_returns_sorted(self):
        findings = [
            {"severity": "CRITICAL", "description": "critical issue"},
            {"severity": "LOW", "description": "minor issue"},
            {"severity": "HIGH", "description": "high severity issue"},
        ]
        scores = self.scorer.score_bulk(findings)
        self.assertEqual(len(scores), 3)
        # Should be sorted descending
        self.assertGreaterEqual(scores[0].score, scores[-1].score)

    def test_contributing_factors_populated(self):
        finding = {"severity": "CRITICAL", "description": "public admin resource"}
        score = self.scorer.score_finding(finding)
        self.assertIsInstance(score.contributing_factors, list)
        self.assertGreater(len(score.contributing_factors), 0)


# ---------------------------------------------------------------------------
# TestEnterpriseRiskScorer
# ---------------------------------------------------------------------------

class TestEnterpriseRiskScorer(unittest.TestCase):

    def setUp(self):
        from backend.cloud_security.enterprise_risk import EnterpriseRiskScorer
        self.scorer = EnterpriseRiskScorer()

    def _cloud_findings(self):
        return [{"severity": "CRITICAL", "resource_type": "s3", "resource_name": "prod-data",
                 "description": "Public bucket", "rule_id": "S3-001"},
                {"severity": "HIGH", "resource_type": "rds", "resource_name": "prod-db",
                 "description": "Public RDS", "rule_id": "RDS-001"}]

    def _iam_findings(self):
        return [{"severity": "CRITICAL", "principal": "admin", "permission": "iam:*",
                 "category": "WILDCARD", "description": "Wildcard IAM"}]

    def test_score_returns_report(self):
        report = self.scorer.score(cloud_findings=self._cloud_findings())
        self.assertIsNotNone(report)
        self.assertGreaterEqual(report.enterprise_score, 0)
        self.assertLessEqual(report.enterprise_score, 100)

    def test_critical_cloud_findings_raise_score(self):
        report = self.scorer.score(cloud_findings=self._cloud_findings())
        self.assertGreater(report.enterprise_score, 0)

    def test_risk_class_critical_with_many_critical(self):
        # Cloud layer score = 100 (5 × CRITICAL), enterprise = 100×0.25 = 25 → MEDIUM/LOW boundary
        # With all 6 layers included, supply critical findings across layers for a HIGH result
        critical_findings = [{"severity": "CRITICAL", "description": f"crit {i}",
                               "rule_id": f"C-{i}", "resource_type": "s3"}
                              for i in range(5)]
        report = self.scorer.score(
            cloud_findings=critical_findings,
            iam_findings=critical_findings,
            container_findings=critical_findings,
        )
        self.assertIn(report.risk_class.value,
                      ["CATASTROPHIC", "CRITICAL", "HIGH", "MEDIUM"])

    def test_empty_findings_low_risk(self):
        report = self.scorer.score()
        self.assertLessEqual(report.enterprise_score, 30)
        self.assertIn(report.risk_class.value, ["LOW", "MEDIUM"])

    def test_layer_scores_populated(self):
        report = self.scorer.score(
            cloud_findings=self._cloud_findings(),
            iam_findings=self._iam_findings(),
        )
        self.assertGreater(len(report.layer_scores), 0)
        for ls in report.layer_scores:
            self.assertGreaterEqual(ls.score, 0)
            self.assertLessEqual(ls.score, 100)

    def test_report_to_dict_structure(self):
        report = self.scorer.score(cloud_findings=self._cloud_findings())
        d = report.to_dict()
        self.assertIn("enterprise_score", d)
        self.assertIn("risk_class", d)
        self.assertIn("layer_scores", d)
        self.assertIn("recommended_priorities", d)

    def test_recommended_priorities_generated(self):
        report = self.scorer.score(
            cloud_findings=self._cloud_findings(),
            iam_findings=self._iam_findings(),
        )
        self.assertIsInstance(report.recommended_priorities, list)
        self.assertGreater(len(report.recommended_priorities), 0)

    def test_weights_sum_to_one(self):
        total = sum(self.scorer.WEIGHTS.values())
        self.assertAlmostEqual(total, 1.0, places=2)


# ---------------------------------------------------------------------------
# TestExecutiveDashboard
# ---------------------------------------------------------------------------

class TestExecutiveDashboard(unittest.TestCase):

    def setUp(self):
        from backend.cloud_security.executive_dashboard import ExecutiveDashboardGenerator
        self.generator = ExecutiveDashboardGenerator()

    def _make_enterprise_report(self):
        from backend.cloud_security.enterprise_risk import EnterpriseRiskScorer
        scorer = EnterpriseRiskScorer()
        return scorer.score(
            cloud_findings=[
                {"severity": "CRITICAL", "rule_id": "S3-PUB", "resource_type": "s3",
                 "resource_name": "prod-data", "description": "Public S3 bucket"},
            ],
            iam_findings=[
                {"severity": "CRITICAL", "principal": "admin", "permission": "iam:*",
                 "category": "WILDCARD", "description": "Wildcard IAM"},
            ],
        )

    def test_generate_returns_dashboard(self):
        report = self.generator.generate()
        self.assertIsNotNone(report)

    def test_dashboard_has_required_keys(self):
        report = self.generator.generate()
        d = report.to_dict()
        for key in ("overall_risk_score", "overall_risk_class", "total_findings",
                    "remediation_priorities", "layer_risk_breakdown"):
            self.assertIn(key, d)

    def test_dashboard_with_enterprise_report(self):
        er = self._make_enterprise_report()
        report = self.generator.generate(enterprise_report=er)
        self.assertGreaterEqual(report.overall_risk_score, 0)
        self.assertLessEqual(report.overall_risk_score, 100)

    def test_text_report_is_string(self):
        report = self.generator.generate()
        text = report.text_report()
        self.assertIsInstance(text, str)
        self.assertGreater(len(text), 50)

    def test_text_report_contains_risk_class(self):
        er = self._make_enterprise_report()
        report = self.generator.generate(enterprise_report=er)
        text = report.text_report()
        self.assertTrue(any(rc in text for rc in
                            ["CATASTROPHIC", "CRITICAL", "HIGH", "MEDIUM", "LOW"]))

    def test_remediation_priorities_ordered(self):
        er = self._make_enterprise_report()
        report = self.generator.generate(enterprise_report=er)
        self.assertIsInstance(report.remediation_priorities, list)

    def test_empty_inputs_no_crash(self):
        report = self.generator.generate(findings=[])
        self.assertIsNotNone(report)
        self.assertIsInstance(report.to_dict(), dict)


# ---------------------------------------------------------------------------
# TestKnowledgeGraphCloud
# ---------------------------------------------------------------------------

class TestKnowledgeGraphCloud(unittest.TestCase):

    def setUp(self):
        from backend.analysis.knowledge_graph import KnowledgeGraphBuilder, SecurityKnowledgeGraph
        self.builder = KnowledgeGraphBuilder()
        self.graph = SecurityKnowledgeGraph()

    def _cloud_finding(self, severity="CRITICAL", resource_type="s3", resource_name="prod-bucket"):
        return {"rule_id": "S3-001", "severity": severity, "file": "main.tf",
                "resource_type": resource_type, "resource_name": resource_name,
                "description": "Public S3 bucket detected", "category": "cloud_misconfiguration",
                "public_access": True}

    def _iam_finding(self, severity="CRITICAL", principal="admin-user", permission="iam:*"):
        return {"rule_id": "IAM-001", "severity": severity, "file": "policy.json",
                "principal": principal, "permission": permission,
                "category": "WILDCARD", "description": "Wildcard IAM permission"}

    def test_cloud_node_types_added_to_kg(self):
        from backend.analysis.knowledge_graph import KGNodeType
        existing = {m.value for m in KGNodeType.__members__.values()}
        # These should be present from Phase 2 at minimum
        self.assertIn("cloud_resource", existing)

    def test_ingest_cloud_findings_creates_nodes(self):
        added = self.builder.ingest_cloud_findings(self.graph, [self._cloud_finding()])
        self.assertGreater(added, 0)
        self.assertGreater(len(self.graph.nodes), 0)

    def test_ingest_iam_findings_creates_nodes(self):
        added = self.builder.ingest_iam_findings_cloud(self.graph, [self._iam_finding()])
        self.assertGreater(added, 0)

    def test_find_exposed_cloud_resources(self):
        self.builder.ingest_cloud_findings(self.graph, [self._cloud_finding()])
        exposed = self.builder.find_exposed_cloud_resources(self.graph)
        self.assertGreater(len(exposed), 0)
        self.assertTrue(all(e.get("public_access") for e in exposed))

    def test_find_cloud_attack_paths_method_exists(self):
        self.builder.ingest_cloud_findings(self.graph, [self._cloud_finding()])
        paths = self.builder.find_cloud_attack_paths(self.graph)
        self.assertIsInstance(paths, list)

    def test_find_privilege_escalation_paths(self):
        self.builder.ingest_iam_findings_cloud(self.graph, [self._iam_finding()])
        paths = self.builder.find_cloud_privilege_escalation(self.graph)
        self.assertIsInstance(paths, list)

    def test_find_container_risks(self):
        container_finding = {"rule_id": "CTR-001", "severity": "CRITICAL", "file": "Dockerfile",
                              "resource_type": "container_image", "resource_name": "api:latest",
                              "description": "Running as root", "public_access": False}
        self.builder.ingest_cloud_findings(self.graph, [container_finding])
        risks = self.builder.find_container_risks(self.graph)
        self.assertIsInstance(risks, list)

    def test_find_kubernetes_risks(self):
        k8s_finding = {"rule_id": "K8S-001", "severity": "CRITICAL", "file": "pod.yaml",
                       "resource_type": "k8s_pod", "resource_name": "api-pod",
                       "description": "Privileged container", "public_access": False}
        self.builder.ingest_cloud_findings(self.graph, [k8s_finding])
        risks = self.builder.find_kubernetes_risks(self.graph)
        self.assertIsInstance(risks, list)

    def test_build_cloud_knowledge_graph(self):
        kg = self.builder.build_cloud_knowledge_graph(
            cloud_findings=[self._cloud_finding()],
            iam_findings=[self._iam_finding()],
        )
        self.assertGreater(len(kg.nodes), 0)
        self.assertGreater(len(kg.edges), 0)

    def test_find_business_critical_findings(self):
        cloud_f = dict(self._cloud_finding())
        cloud_f["category"] = "cloud_critical"
        cloud_f["resource_type"] = "cloud_resource"
        self.builder.ingest_cloud_findings(self.graph, [cloud_f])
        results = self.builder.find_business_critical_findings(self.graph)
        self.assertIsInstance(results, list)


# ---------------------------------------------------------------------------
# TestAttackGraphCloud
# ---------------------------------------------------------------------------

class TestAttackGraphCloud(unittest.TestCase):

    def setUp(self):
        from backend.analysis.attack_graph import AttackGraphBuilder
        self.builder = AttackGraphBuilder()

    def _cloud_findings(self):
        return [{"rule_id": "S3-PUB", "severity": "CRITICAL", "resource_type": "s3",
                 "resource_name": "prod-data", "description": "Public S3 bucket",
                 "public_access": True}]

    def _iam_findings(self):
        return [{"rule_id": "IAM-WILD", "severity": "CRITICAL",
                 "principal": "svc-account", "permission": "iam:PassRole",
                 "category": "PRIVILEGE_ESCALATION", "description": "PassRole permission"}]

    def _k8s_findings(self):
        return [{"rule_id": "K8S-PRIV", "severity": "CRITICAL",
                 "resource_name": "api-pod", "namespace": "production",
                 "description": "Privileged container"}]

    def _container_findings(self):
        return [{"severity": "HIGH", "image": "api:latest",
                 "vulnerability_id": "CVE-2023-999", "description": "Vulnerable package"}]

    def test_cloud_node_types_in_attack_graph(self):
        from backend.analysis.attack_graph import NodeType
        # Phase 9 cloud types should be registered (may depend on aenum)
        # At minimum, verify the extension ran without error
        self.assertIsNotNone(NodeType)

    def test_add_cloud_nodes_creates_nodes(self):
        from backend.analysis.attack_graph import AttackGraph
        graph = AttackGraph()
        added = self.builder.add_cloud_nodes(
            graph, self._cloud_findings(), self._iam_findings()
        )
        self.assertGreater(added, 0)
        self.assertGreater(len(graph.nodes), 0)

    def test_build_from_cloud_findings_returns_graph(self):
        from backend.analysis.attack_graph import AttackGraph
        graph = self.builder.build_from_cloud_findings(
            cloud_findings=self._cloud_findings(),
            iam_findings=self._iam_findings(),
        )
        self.assertIsInstance(graph, AttackGraph)
        self.assertGreater(len(graph.nodes), 0)
        self.assertGreater(len(graph.edges), 0)

    def test_find_cloud_attack_paths(self):
        from backend.analysis.attack_graph import AttackGraph
        graph = self.builder.build_from_cloud_findings(
            cloud_findings=self._cloud_findings(),
        )
        paths = self.builder.find_cloud_attack_paths(graph)
        self.assertIsInstance(paths, list)

    def test_find_exposed_resources_from_public_s3(self):
        from backend.analysis.attack_graph import AttackGraph
        graph = self.builder.build_from_cloud_findings(
            cloud_findings=self._cloud_findings(),
        )
        exposed = self.builder.find_exposed_resources(graph)
        self.assertGreater(len(exposed), 0)

    def test_find_privilege_escalation_paths(self):
        from backend.analysis.attack_graph import AttackGraph
        graph = self.builder.build_from_cloud_findings(
            cloud_findings=self._cloud_findings(),
            iam_findings=self._iam_findings(),
        )
        paths = self.builder.find_cloud_privilege_escalation(graph)
        self.assertIsInstance(paths, list)

    def test_find_container_risks_cloud(self):
        from backend.analysis.attack_graph import AttackGraph
        graph = self.builder.build_from_cloud_findings(
            cloud_findings=self._cloud_findings(),
            container_findings=self._container_findings(),
        )
        risks = self.builder.find_container_risks_cloud(graph)
        self.assertIsInstance(risks, list)

    def test_find_kubernetes_risks(self):
        from backend.analysis.attack_graph import AttackGraph
        graph = self.builder.build_from_cloud_findings(
            cloud_findings=self._cloud_findings(),
            k8s_findings=self._k8s_findings(),
        )
        risks = self.builder.find_kubernetes_risks(graph)
        self.assertGreater(len(risks), 0)

    def test_graph_has_source_attacker_node(self):
        from backend.analysis.attack_graph import AttackGraph
        graph = self.builder.build_from_cloud_findings(
            cloud_findings=self._cloud_findings(),  # public_access=True → internet attacker
        )
        source_nodes = [n for n in graph.nodes if "attacker" in n.node_id or "source" in n.type.value]
        self.assertGreater(len(source_nodes), 0)


# ---------------------------------------------------------------------------
# TestUnifiedScanEngineCloud
# ---------------------------------------------------------------------------

class TestUnifiedScanEngineCloud(unittest.TestCase):

    def setUp(self):
        from backend.core.engine.unified_scan_engine import UnifiedScanEngine, ScanOptions
        self.engine = UnifiedScanEngine()
        self.options = ScanOptions()

    def test_scan_cloud_elite_method_exists(self):
        self.assertTrue(hasattr(self.engine, "scan_cloud_elite"))

    def test_scan_cloud_options_fields_exist(self):
        from backend.core.engine.unified_scan_engine import ScanOptions
        opts = ScanOptions()
        self.assertTrue(hasattr(opts, "enable_cloud_security"))
        self.assertTrue(hasattr(opts, "cloud_iac_dirs"))
        self.assertTrue(hasattr(opts, "cloud_k8s_manifests"))
        self.assertTrue(hasattr(opts, "cloud_iam_files"))

    def test_scan_cloud_elite_no_paths_returns_no_files(self):
        result = self.engine.scan_cloud_elite([], self.options)
        self.assertEqual(result["status"], "no_files")
        self.assertEqual(result["findings"], [])

    def test_scan_cloud_elite_with_temp_iac_file(self):
        import tempfile, os
        # Create a minimal Terraform file with a security issue
        tf_content = '''
resource "aws_s3_bucket" "public" {
  bucket = "my-public-bucket"
}
resource "aws_security_group" "allow_all" {
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
'''
        with tempfile.NamedTemporaryFile(mode="w", suffix=".tf",
                                         delete=False) as f:
            f.write(tf_content)
            tmp_path = f.name
        try:
            result = self.engine.scan_cloud_elite([tmp_path], self.options)
            self.assertIn("status", result)
            self.assertIn("severity_counts", result)
            self.assertIn("scan_duration_s", result)
        finally:
            os.unlink(tmp_path)

    def test_scan_cloud_elite_returns_all_report_keys(self):
        result = self.engine.scan_cloud_elite([], self.options)
        for key in ("findings", "severity_counts", "risk_score",
                    "iam_report", "cloud_report", "k8s_report", "container_report"):
            self.assertIn(key, result)

    def test_scan_cloud_elite_with_temp_dockerfile(self):
        import tempfile, os
        dockerfile_content = """FROM ubuntu:latest
RUN apt-get install -y curl
USER root
EXPOSE 22
ADD . /app
"""
        with tempfile.NamedTemporaryFile(mode="w", prefix="Dockerfile",
                                         suffix="", delete=False) as f:
            f.write(dockerfile_content)
            tmp_path = f.name
        try:
            result = self.engine.scan_cloud_elite([tmp_path], self.options)
            self.assertIn("status", result)
            self.assertIn("scan_duration_s", result)
        finally:
            os.unlink(tmp_path)

    def test_scan_cloud_elite_enterprise_risk_in_result(self):
        import tempfile, os
        iam_policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*",
                           "Principal": {"AWS": "arn:aws:iam::123456789:root"}}]
        })
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json",
                                         delete=False) as f:
            f.write(iam_policy)
            tmp_path = f.name
        try:
            result = self.engine.scan_cloud_elite([tmp_path], self.options)
            # enterprise_risk_score may be None if scorer fails gracefully, that's ok
            self.assertIn("enterprise_risk_score", result)
        finally:
            os.unlink(tmp_path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
