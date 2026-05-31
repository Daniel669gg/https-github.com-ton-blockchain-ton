"""Extended tests for IAM Security Scanner."""
from __future__ import annotations

import json
import textwrap
import sys
import os

# Ensure the project root is on the path
sys.path.insert(0, "/tmp/sentinelops/ghost_security")

import pytest
from backend.scanners.iam_scanner import IAMScanner, IAMFinding


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def scanner() -> IAMScanner:
    return IAMScanner()


# ---------------------------------------------------------------------------
# Test 1: AWS wildcard policy — IAM-AWS-001
# ---------------------------------------------------------------------------

def test_aws_wildcard_policy(scanner: IAMScanner) -> None:
    """Action:* + Resource:* + Allow → IAM-AWS-001 CRITICAL."""
    policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
            }
        ],
    })

    findings = scanner._check_aws_iam_policy("/tmp/test_policy.json", policy)

    rule_ids = [f.rule_id for f in findings]
    assert "IAM-AWS-001" in rule_ids, f"Expected IAM-AWS-001, got: {rule_ids}"

    wildcard_finding = next(f for f in findings if f.rule_id == "IAM-AWS-001")
    assert wildcard_finding.severity == "CRITICAL"
    assert wildcard_finding.category == "WILDCARD"
    assert wildcard_finding.permission == "*"


# ---------------------------------------------------------------------------
# Test 2: GCP owner role — IAM-GCP-001
# ---------------------------------------------------------------------------

def test_gcp_owner_role(scanner: IAMScanner) -> None:
    """roles/owner binding → IAM-GCP-001 CRITICAL."""
    gcp_binding = textwrap.dedent("""
        bindings:
          - role: roles/owner
            members:
              - user:admin@example.com
          - role: roles/viewer
            members:
              - serviceAccount:app@project.iam.gserviceaccount.com
    """)

    findings = scanner._check_gcp_iam("/tmp/iam_policy.yaml", gcp_binding)

    rule_ids = [f.rule_id for f in findings]
    assert "IAM-GCP-001" in rule_ids, f"Expected IAM-GCP-001, got: {rule_ids}"

    owner_finding = next(f for f in findings if f.rule_id == "IAM-GCP-001")
    assert owner_finding.severity == "CRITICAL"
    assert owner_finding.category == "OVERPRIVILEGE"


# ---------------------------------------------------------------------------
# Test 3: Kubernetes ClusterRoleBinding to cluster-admin — IAM-K8S-002
# ---------------------------------------------------------------------------

def test_k8s_cluster_admin_binding(scanner: IAMScanner) -> None:
    """ClusterRoleBinding to cluster-admin → IAM-K8S-002 CRITICAL."""
    manifest = textwrap.dedent("""
        apiVersion: rbac.authorization.k8s.io/v1
        kind: ClusterRoleBinding
        metadata:
          name: superuser-binding
        roleRef:
          apiGroup: rbac.authorization.k8s.io
          kind: ClusterRole
          name: cluster-admin
        subjects:
          - kind: ServiceAccount
            name: my-service-account
            namespace: default
    """)

    findings = scanner._check_k8s_rbac("/tmp/rbac.yaml", manifest)

    rule_ids = [f.rule_id for f in findings]
    assert "IAM-K8S-002" in rule_ids, f"Expected IAM-K8S-002, got: {rule_ids}"

    binding_finding = next(f for f in findings if f.rule_id == "IAM-K8S-002")
    assert binding_finding.severity == "CRITICAL"


# ---------------------------------------------------------------------------
# Test 4: system:unauthenticated in RoleBinding — IAM-K8S-006
# ---------------------------------------------------------------------------

def test_k8s_unauthenticated_binding(scanner: IAMScanner) -> None:
    """system:unauthenticated group → IAM-K8S-006 CRITICAL."""
    manifest = textwrap.dedent("""
        apiVersion: rbac.authorization.k8s.io/v1
        kind: RoleBinding
        metadata:
          name: insecure-binding
          namespace: default
        roleRef:
          apiGroup: rbac.authorization.k8s.io
          kind: Role
          name: pod-reader
        subjects:
          - kind: Group
            name: system:unauthenticated
            apiGroup: rbac.authorization.k8s.io
    """)

    findings = scanner._check_k8s_rbac("/tmp/rbac_insecure.yaml", manifest)

    rule_ids = [f.rule_id for f in findings]
    assert "IAM-K8S-006" in rule_ids, f"Expected IAM-K8S-006, got: {rule_ids}"

    unauth_finding = next(f for f in findings if f.rule_id == "IAM-K8S-006")
    assert unauth_finding.severity == "CRITICAL"
    assert "unauthenticated" in unauth_finding.principal.lower()


# ---------------------------------------------------------------------------
# Test 5: Azure Owner role assignment — IAM-AZ-002
# ---------------------------------------------------------------------------

def test_azure_owner_role(scanner: IAMScanner) -> None:
    """Owner roleDefinitionId in ARM template → IAM-AZ-002 CRITICAL."""
    arm_template = json.dumps({
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "resources": [
            {
                "type": "Microsoft.Authorization/roleAssignments",
                "apiVersion": "2022-04-01",
                "name": "[guid(resourceGroup().id)]",
                "properties": {
                    "roleDefinitionId": "[concat('/subscriptions/', subscription().subscriptionId, '/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635')]",
                    "principalId": "[parameters('principalId')]",
                    "scope": "[concat('/subscriptions/', subscription().subscriptionId)]",
                },
            }
        ],
    })

    findings = scanner._check_azure_rbac("/tmp/arm_template.json", arm_template)

    rule_ids = [f.rule_id for f in findings]
    assert "IAM-AZ-002" in rule_ids, f"Expected IAM-AZ-002, got: {rule_ids}"

    owner_finding = next(f for f in findings if f.rule_id == "IAM-AZ-002")
    assert owner_finding.severity == "CRITICAL"


# ---------------------------------------------------------------------------
# Test 6: Clean K8s RBAC — no CRITICAL findings
# ---------------------------------------------------------------------------

def test_clean_k8s_rbac(scanner: IAMScanner) -> None:
    """Properly scoped ClusterRole → no CRITICAL findings."""
    manifest = textwrap.dedent("""
        apiVersion: rbac.authorization.k8s.io/v1
        kind: ClusterRole
        metadata:
          name: pod-reader
        rules:
          - apiGroups: [""]
            resources: ["pods", "pods/log"]
            verbs: ["get", "list", "watch"]
          - apiGroups: ["apps"]
            resources: ["deployments"]
            verbs: ["get", "list"]
    """)

    findings = scanner._check_k8s_rbac("/tmp/good_rbac.yaml", manifest)

    critical_findings = [f for f in findings if f.severity == "CRITICAL"]
    assert len(critical_findings) == 0, (
        f"Expected no CRITICAL findings, got: {[(f.rule_id, f.severity) for f in critical_findings]}"
    )


# ---------------------------------------------------------------------------
# Additional edge-case tests
# ---------------------------------------------------------------------------

def test_aws_s3_wildcard(scanner: IAMScanner) -> None:
    """s3:* on all resources → IAM-AWS-002."""
    policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "*",
            }
        ],
    })

    findings = scanner._check_aws_iam_policy("/tmp/s3_policy.json", policy)
    rule_ids = [f.rule_id for f in findings]
    assert "IAM-AWS-002" in rule_ids, f"Expected IAM-AWS-002, got: {rule_ids}"
    s3_finding = next(f for f in findings if f.rule_id == "IAM-AWS-002")
    assert s3_finding.severity == "HIGH"


def test_aws_public_principal(scanner: IAMScanner) -> None:
    """Principal:* → IAM-AWS-003 CRITICAL."""
    policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::my-bucket/*",
            }
        ],
    })

    findings = scanner._check_aws_iam_policy("/tmp/bucket_policy.json", policy)
    rule_ids = [f.rule_id for f in findings]
    assert "IAM-AWS-003" in rule_ids, f"Expected IAM-AWS-003, got: {rule_ids}"


def test_terraform_aws_wildcard_actions(scanner: IAMScanner) -> None:
    """Terraform aws_iam_role_policy with actions=["*"] → IAM-TF-001."""
    tf_content = textwrap.dedent("""
        resource "aws_iam_role_policy" "bad_policy" {
          name = "bad-policy"
          role = aws_iam_role.example.id

          policy = jsonencode({
            Version = "2012-10-17"
            Statement = [
              {
                Effect   = "Allow"
                actions  = ["*"]
                Resource = "*"
              }
            ]
          })
        }
    """)

    findings = scanner._check_terraform_iam("/tmp/main.tf", tf_content)
    rule_ids = [f.rule_id for f in findings]
    assert "IAM-TF-001" in rule_ids, f"Expected IAM-TF-001, got: {rule_ids}"


def test_gcp_allusers_binding(scanner: IAMScanner) -> None:
    """allUsers member → IAM-GCP-003 CRITICAL."""
    gcp_binding = textwrap.dedent("""
        bindings:
          - role: roles/storage.objectViewer
            members:
              - allUsers
    """)

    findings = scanner._check_gcp_iam("/tmp/storage_iam.yaml", gcp_binding)
    rule_ids = [f.rule_id for f in findings]
    assert "IAM-GCP-003" in rule_ids, f"Expected IAM-GCP-003, got: {rule_ids}"
    public_finding = next(f for f in findings if f.rule_id == "IAM-GCP-003")
    assert public_finding.severity == "CRITICAL"
    assert public_finding.category == "PUBLIC_ACCESS"


def test_k8s_wildcard_role(scanner: IAMScanner) -> None:
    """ClusterRole with * verbs and * resources → IAM-K8S-001."""
    manifest = textwrap.dedent("""
        apiVersion: rbac.authorization.k8s.io/v1
        kind: ClusterRole
        metadata:
          name: super-role
        rules:
          - apiGroups: ["*"]
            resources: ["*"]
            verbs: ["*"]
    """)

    findings = scanner._check_k8s_rbac("/tmp/super_role.yaml", manifest)
    rule_ids = [f.rule_id for f in findings]
    assert "IAM-K8S-001" in rule_ids, f"Expected IAM-K8S-001, got: {rule_ids}"
    wildcard = next(f for f in findings if f.rule_id == "IAM-K8S-001")
    assert wildcard.severity == "CRITICAL"


def test_iam_finding_model_validation() -> None:
    """IAMFinding validates required fields and defaults."""
    finding = IAMFinding(
        rule_id="IAM-TEST-001",
        file="/tmp/test.yaml",
        line=10,
        severity="HIGH",
        description="Test finding",
        recommendation="Fix it",
    )
    assert finding.rule_id == "IAM-TEST-001"
    assert finding.resource_type == ""
    assert finding.principal == ""
    assert finding.category == ""


def test_scan_directory_skips_git(tmp_path) -> None:
    """scan_directory skips .git directories."""
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    policy_in_git = git_dir / "policy.json"
    policy_in_git.write_text(json.dumps({
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
    }))

    scanner = IAMScanner()
    findings = scanner.scan_directory(str(tmp_path))
    # Should find nothing because .git is skipped
    assert all(
        ".git" not in f.file for f in findings
    ), "scan_directory should skip .git directories"
