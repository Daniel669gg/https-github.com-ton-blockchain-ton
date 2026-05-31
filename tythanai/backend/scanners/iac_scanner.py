"""IaC Security Scanner: Terraform, CloudFormation, Helm, Kubernetes manifests."""
from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

logger = logging.getLogger("tythanai.iac")

try:
    import yaml as _yaml  # type: ignore

    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False
    logger.info("PyYAML not installed; YAML parsing will use regex fallback")


# ─────────────────────────────────────────────────────────────────────────────
# Result model
# ─────────────────────────────────────────────────────────────────────────────


class IaCScanResult(BaseModel):
    file: str
    line: int
    rule_id: str
    severity: str
    description: str
    recommendation: str
    resource: str = ""
    category: str = ""  # NETWORK/IAM/ENCRYPTION/LOGGING/SECRETS/COMPUTE


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

_SKIP_DIRS = {"node_modules", ".git", "vendor", ".terraform"}


def _find_line(content: str, pattern: re.Pattern) -> int:
    """Return the 1-based line number of the first match, or 0."""
    for i, line in enumerate(content.splitlines(), 1):
        if pattern.search(line):
            return i
    return 0


def _find_line_str(content: str, substring: str) -> int:
    """Return the 1-based line number containing substring, or 0."""
    for i, line in enumerate(content.splitlines(), 1):
        if substring in line:
            return i
    return 0


def _res(
    file: str,
    line: int,
    rule_id: str,
    severity: str,
    description: str,
    recommendation: str,
    resource: str = "",
    category: str = "",
) -> IaCScanResult:
    return IaCScanResult(
        file=file,
        line=line,
        rule_id=rule_id,
        severity=severity,
        description=description,
        recommendation=recommendation,
        resource=resource,
        category=category,
    )


def _yaml_load(content: str) -> Optional[Any]:
    if not _YAML_AVAILABLE:
        return None
    try:
        return _yaml.safe_load(content)
    except Exception:
        return None


def _json_load(content: str) -> Optional[Any]:
    try:
        return json.loads(content)
    except Exception:
        return None


def _walk_dict(obj: Any, *keys: str) -> Optional[Any]:
    """Safely walk a nested dict/list structure."""
    for key in keys:
        if isinstance(obj, dict):
            obj = obj.get(key)
        else:
            return None
        if obj is None:
            return None
    return obj


# ─────────────────────────────────────────────────────────────────────────────
# Main scanner
# ─────────────────────────────────────────────────────────────────────────────


class IaCScanner:
    """
    Scans Infrastructure-as-Code files for security misconfigurations.

    Supports: Terraform (.tf), CloudFormation (.yaml/.json with AWSTemplateFormatVersion),
    Helm (values.yaml), and Kubernetes manifests (.yaml with apiVersion/kind).
    """

    # ── Terraform ────────────────────────────────────────────────────────────

    def _check_terraform(self, path: str, content: str) -> List[IaCScanResult]:
        results: List[IaCScanResult] = []
        lines = content.splitlines()

        # Helper: find 1-based line number of first regex match
        def find_re(pat: re.Pattern) -> int:
            for i, ln in enumerate(lines, 1):
                if pat.search(ln):
                    return i
            return 1

        # Helper: find first occurrence of substring
        def find_sub(s: str) -> int:
            for i, ln in enumerate(lines, 1):
                if s in ln:
                    return i
            return 1

        # We parse resource blocks to contextualise checks
        # Build a list of (block_type, resource_type, name, start_line, block_content)
        resource_blocks = _extract_tf_blocks(content)

        # ── IAC-TF-001: S3 bucket missing encryption ─────────────────────────
        for bt, rt, name, start, block in resource_blocks:
            if rt == "aws_s3_bucket":
                # Look for paired aws_s3_bucket_server_side_encryption_configuration
                # or inline server_side_encryption_configuration block
                has_enc_block = bool(re.search(r"server_side_encryption_configuration", block))
                # Also check all content for a separate resource referencing this bucket
                enc_resource_re = re.compile(
                    rf'resource\s+"aws_s3_bucket_server_side_encryption_configuration"[^{{]*{{[^}}]*bucket\s*=\s*aws_s3_bucket\.{re.escape(name)}',
                    re.DOTALL,
                )
                has_enc_resource = bool(enc_resource_re.search(content))
                if not has_enc_block and not has_enc_resource:
                    results.append(
                        _res(
                            path,
                            start,
                            "IAC-TF-001",
                            "HIGH",
                            f"S3 bucket '{name}' missing encryption",
                            "Add server_side_encryption_configuration with AES256 or aws:kms.",
                            resource=f"aws_s3_bucket.{name}",
                            category="ENCRYPTION",
                        )
                    )

        # ── IAC-TF-002: Security group SSH/RDP open to internet ──────────────
        for bt, rt, name, start, block in resource_blocks:
            if rt in ("aws_security_group", "aws_security_group_rule"):
                # Look for ingress blocks with 0.0.0.0/0 and port 22 or 3389
                ingress_blocks = list(re.finditer(r"ingress\s*\{([^}]*)\}", block, re.DOTALL))
                for m in ingress_blocks:
                    ib = m.group(1)
                    if re.search(r'0\.0\.0\.0/0', ib):
                        from_port_m = re.search(r'from_port\s*=\s*(\d+)', ib)
                        to_port_m = re.search(r'to_port\s*=\s*(\d+)', ib)
                        if from_port_m and to_port_m:
                            from_port = int(from_port_m.group(1))
                            to_port = int(to_port_m.group(1))
                            if from_port <= 22 <= to_port or from_port <= 3389 <= to_port:
                                results.append(
                                    _res(
                                        path,
                                        start,
                                        "IAC-TF-002",
                                        "CRITICAL",
                                        f"SSH/RDP open to internet in security group '{name}'",
                                        "Restrict SSH/RDP access to specific trusted CIDR ranges.",
                                        resource=f"{rt}.{name}",
                                        category="NETWORK",
                                    )
                                )
                                break

        # ── IAC-TF-003: All traffic allowed ──────────────────────────────────
        for bt, rt, name, start, block in resource_blocks:
            if rt in ("aws_security_group", "aws_security_group_rule"):
                ingress_blocks = list(re.finditer(r"ingress\s*\{([^}]*)\}", block, re.DOTALL))
                for m in ingress_blocks:
                    ib = m.group(1)
                    if (
                        re.search(r'0\.0\.0\.0/0', ib)
                        and re.search(r'from_port\s*=\s*0\b', ib)
                        and re.search(r'to_port\s*=\s*0\b', ib)
                    ):
                        results.append(
                            _res(
                                path,
                                start,
                                "IAC-TF-003",
                                "CRITICAL",
                                f"All traffic allowed from internet in security group '{name}'",
                                "Restrict ingress rules to only required ports and CIDR ranges.",
                                resource=f"{rt}.{name}",
                                category="NETWORK",
                            )
                        )
                        break

        # ── IAC-TF-004: RDS publicly accessible ──────────────────────────────
        for bt, rt, name, start, block in resource_blocks:
            if rt == "aws_db_instance":
                if re.search(r'publicly_accessible\s*=\s*true', block):
                    results.append(
                        _res(
                            path,
                            start,
                            "IAC-TF-004",
                            "HIGH",
                            f"RDS instance '{name}' is publicly accessible",
                            "Set publicly_accessible = false and use VPC private subnets.",
                            resource=f"aws_db_instance.{name}",
                            category="NETWORK",
                        )
                    )

        # ── IAC-TF-005: RDS storage not encrypted ────────────────────────────
        for bt, rt, name, start, block in resource_blocks:
            if rt == "aws_db_instance":
                if not re.search(r'storage_encrypted\s*=\s*true', block):
                    results.append(
                        _res(
                            path,
                            start,
                            "IAC-TF-005",
                            "HIGH",
                            f"RDS instance '{name}' storage not encrypted",
                            "Set storage_encrypted = true and provide kms_key_id.",
                            resource=f"aws_db_instance.{name}",
                            category="ENCRYPTION",
                        )
                    )

        # ── IAC-TF-006: Overprivileged IAM policy ────────────────────────────
        for bt, rt, name, start, block in resource_blocks:
            if rt == "aws_iam_policy":
                if (
                    re.search(r'"Effect"\s*:\s*"Allow"', block)
                    and re.search(r'"Action"\s*:\s*"\*"', block)
                    and re.search(r'"Resource"\s*:\s*"\*"', block)
                ):
                    results.append(
                        _res(
                            path,
                            start,
                            "IAC-TF-006",
                            "HIGH",
                            f"IAM policy '{name}' grants wildcard actions on all resources",
                            "Apply least-privilege principle; restrict Action and Resource.",
                            resource=f"aws_iam_policy.{name}",
                            category="IAM",
                        )
                    )

        # ── IAC-TF-007: S3 versioning disabled ───────────────────────────────
        for bt, rt, name, start, block in resource_blocks:
            if rt == "aws_s3_bucket":
                has_versioning = bool(re.search(r'versioning\s*\{[^}]*enabled\s*=\s*true', block, re.DOTALL))
                # Also check for separate aws_s3_bucket_versioning resource
                ver_resource_re = re.compile(
                    rf'resource\s+"aws_s3_bucket_versioning"[^{{]*{{[^}}]*bucket\s*=\s*aws_s3_bucket\.{re.escape(name)}',
                    re.DOTALL,
                )
                has_ver_resource = bool(ver_resource_re.search(content))
                if not has_versioning and not has_ver_resource:
                    results.append(
                        _res(
                            path,
                            start,
                            "IAC-TF-007",
                            "MEDIUM",
                            f"S3 bucket '{name}' versioning is disabled",
                            "Enable versioning to protect against accidental deletion.",
                            resource=f"aws_s3_bucket.{name}",
                            category="LOGGING",
                        )
                    )

        # ── IAC-TF-008: Hardcoded credentials ────────────────────────────────
        password_re = re.compile(r'password\s*=\s*"([^"]{6,})"', re.IGNORECASE)
        secret_re = re.compile(r'(?:secret|api_key|access_key|private_key)\s*=\s*"([^"]{6,})"', re.IGNORECASE)
        for pat in (password_re, secret_re):
            for i, line in enumerate(lines, 1):
                m = pat.search(line)
                if m:
                    value = m.group(1)
                    # Skip variable references and empty/placeholder values
                    if value.startswith("var.") or value.startswith("${") or value.lower() in (
                        "changeme", "placeholder", "example", "your-password"
                    ):
                        continue
                    results.append(
                        _res(
                            path,
                            i,
                            "IAC-TF-008",
                            "CRITICAL",
                            "Hardcoded credential detected in Terraform configuration",
                            "Use Terraform variables, AWS Secrets Manager, or Vault for secrets.",
                            category="SECRETS",
                        )
                    )

        # ── IAC-TF-009: EC2 monitoring disabled ──────────────────────────────
        for bt, rt, name, start, block in resource_blocks:
            if rt == "aws_instance":
                if not re.search(r'monitoring\s*=\s*true', block):
                    results.append(
                        _res(
                            path,
                            start,
                            "IAC-TF-009",
                            "LOW",
                            f"EC2 instance '{name}' has detailed monitoring disabled",
                            "Set monitoring = true to enable detailed CloudWatch monitoring.",
                            resource=f"aws_instance.{name}",
                            category="COMPUTE",
                        )
                    )

        # ── IAC-TF-010: CloudTrail logging disabled ───────────────────────────
        for bt, rt, name, start, block in resource_blocks:
            if rt == "aws_cloudtrail":
                if re.search(r'enable_logging\s*=\s*false', block):
                    results.append(
                        _res(
                            path,
                            start,
                            "IAC-TF-010",
                            "HIGH",
                            f"CloudTrail '{name}' logging is disabled",
                            "Set enable_logging = true to ensure audit trail is active.",
                            resource=f"aws_cloudtrail.{name}",
                            category="LOGGING",
                        )
                    )

        return results

    # ── CloudFormation ────────────────────────────────────────────────────────

    def _check_cloudformation(self, path: str, content: str) -> List[IaCScanResult]:
        results: List[IaCScanResult] = []
        lines = content.splitlines()

        # Parse the template
        template: Optional[Dict] = None
        if path.endswith(".json"):
            template = _json_load(content)
        else:
            template = _yaml_load(content)

        if not isinstance(template, dict):
            # Regex fallback for critical checks
            return self._check_cloudformation_regex(path, content)

        resources: Dict = template.get("Resources", {}) or {}
        parameters: Dict = template.get("Parameters", {}) or {}

        def line_for_resource(resource_name: str) -> int:
            for i, ln in enumerate(lines, 1):
                if resource_name in ln:
                    return i
            return 1

        for res_name, res_body in resources.items():
            if not isinstance(res_body, dict):
                continue
            res_type: str = res_body.get("Type", "")
            props: Dict = res_body.get("Properties", {}) or {}
            line_no = line_for_resource(res_name)

            # ── IAC-CF-001: SecurityGroup SSH/RDP open ────────────────────────
            if res_type in ("AWS::EC2::SecurityGroup", "AWS::EC2::SecurityGroupIngress"):
                ingress_rules = props.get("SecurityGroupIngress", []) or []
                if not isinstance(ingress_rules, list):
                    ingress_rules = []
                for rule in ingress_rules:
                    if not isinstance(rule, dict):
                        continue
                    cidr = rule.get("CidrIp", "") or rule.get("CidrIpv6", "")
                    from_port = rule.get("FromPort", -1)
                    to_port = rule.get("ToPort", -1)
                    try:
                        from_port = int(from_port)
                        to_port = int(to_port)
                    except (TypeError, ValueError):
                        continue
                    if cidr in ("0.0.0.0/0", "::/0"):
                        if from_port <= 22 <= to_port or from_port <= 3389 <= to_port:
                            results.append(
                                _res(
                                    path,
                                    line_no,
                                    "IAC-CF-001",
                                    "CRITICAL",
                                    f"SecurityGroup '{res_name}' allows SSH/RDP from internet",
                                    "Restrict CidrIp to trusted IP ranges for port 22/3389.",
                                    resource=res_name,
                                    category="NETWORK",
                                )
                            )
                            break

            # ── IAC-CF-002: S3 Bucket missing encryption ──────────────────────
            if res_type == "AWS::S3::Bucket":
                if not props.get("BucketEncryption"):
                    results.append(
                        _res(
                            path,
                            line_no,
                            "IAC-CF-002",
                            "HIGH",
                            f"S3 bucket '{res_name}' has no BucketEncryption configured",
                            "Add BucketEncryption with ServerSideEncryptionConfiguration.",
                            resource=res_name,
                            category="ENCRYPTION",
                        )
                    )

            # ── IAC-CF-003: RDS PubliclyAccessible ───────────────────────────
            if res_type in ("AWS::RDS::DBInstance", "AWS::RDS::DBCluster"):
                if props.get("PubliclyAccessible") is True:
                    results.append(
                        _res(
                            path,
                            line_no,
                            "IAC-CF-003",
                            "HIGH",
                            f"RDS resource '{res_name}' is publicly accessible",
                            "Set PubliclyAccessible to false.",
                            resource=res_name,
                            category="NETWORK",
                        )
                    )

            # ── IAC-CF-004: IAM wildcard actions/resources ────────────────────
            if res_type in ("AWS::IAM::Role", "AWS::IAM::Policy", "AWS::IAM::ManagedPolicy"):
                policy_doc = props.get("PolicyDocument") or props.get("AssumeRolePolicyDocument") or {}
                if isinstance(policy_doc, dict):
                    statements = policy_doc.get("Statement", []) or []
                    for stmt in statements:
                        if not isinstance(stmt, dict):
                            continue
                        effect = stmt.get("Effect", "")
                        actions = stmt.get("Action", [])
                        resources_val = stmt.get("Resource", [])
                        if isinstance(actions, str):
                            actions = [actions]
                        if isinstance(resources_val, str):
                            resources_val = [resources_val]
                        if effect == "Allow" and "*" in actions and "*" in resources_val:
                            results.append(
                                _res(
                                    path,
                                    line_no,
                                    "IAC-CF-004",
                                    "HIGH",
                                    f"IAM resource '{res_name}' grants wildcard actions on all resources",
                                    "Apply least privilege; restrict Action and Resource fields.",
                                    resource=res_name,
                                    category="IAM",
                                )
                            )
                            break

            # ── IAC-CF-006: Missing DeletionPolicy: Retain ────────────────────
            if res_type in ("AWS::RDS::DBInstance", "AWS::RDS::DBCluster", "AWS::S3::Bucket"):
                deletion_policy = res_body.get("DeletionPolicy", "")
                if deletion_policy != "Retain":
                    results.append(
                        _res(
                            path,
                            line_no,
                            "IAC-CF-006",
                            "LOW",
                            f"Stateful resource '{res_name}' missing DeletionPolicy: Retain",
                            "Set DeletionPolicy: Retain to prevent accidental data loss.",
                            resource=res_name,
                            category="COMPUTE",
                        )
                    )

            # ── IAC-CF-007: Lambda without active tracing ─────────────────────
            if res_type == "AWS::Lambda::Function":
                tracing_config = props.get("TracingConfig", {}) or {}
                mode = tracing_config.get("Mode", "") if isinstance(tracing_config, dict) else ""
                if mode != "Active":
                    results.append(
                        _res(
                            path,
                            line_no,
                            "IAC-CF-007",
                            "LOW",
                            f"Lambda function '{res_name}' does not have active X-Ray tracing",
                            "Set TracingConfig.Mode to Active for observability.",
                            resource=res_name,
                            category="LOGGING",
                        )
                    )

        # ── IAC-CF-005: Parameters with NoEcho: false for secrets ─────────────
        secret_param_re = re.compile(r'(?:password|secret|key|token)', re.IGNORECASE)
        for param_name, param_body in parameters.items():
            if not isinstance(param_body, dict):
                continue
            no_echo = param_body.get("NoEcho", None)
            if secret_param_re.search(param_name):
                if no_echo is False or no_echo == "false":
                    line_no = line_for_resource(param_name)
                    results.append(
                        _res(
                            path,
                            line_no,
                            "IAC-CF-005",
                            "MEDIUM",
                            f"Parameter '{param_name}' looks like a secret but NoEcho is false",
                            "Set NoEcho: true for sensitive parameters to hide values in console.",
                            resource=param_name,
                            category="SECRETS",
                        )
                    )

        return results

    def _check_cloudformation_regex(self, path: str, content: str) -> List[IaCScanResult]:
        """Regex fallback for CloudFormation when YAML parse fails."""
        results: List[IaCScanResult] = []
        lines = content.splitlines()

        if re.search(r'CidrIp\s*:\s*0\.0\.0\.0/0', content) and re.search(r'(?:22|3389)', content):
            ln = _find_line_str(content, "CidrIp")
            results.append(
                _res(path, ln, "IAC-CF-001", "CRITICAL",
                     "SecurityGroup may allow SSH/RDP from internet",
                     "Restrict CidrIp to trusted IP ranges.", category="NETWORK")
            )
        if re.search(r'AWS::S3::Bucket', content) and not re.search(r'BucketEncryption', content):
            ln = _find_line_str(content, "AWS::S3::Bucket")
            results.append(
                _res(path, ln, "IAC-CF-002", "HIGH",
                     "S3 bucket may be missing encryption",
                     "Add BucketEncryption.", category="ENCRYPTION")
            )
        return results

    # ── Helm ─────────────────────────────────────────────────────────────────

    def _check_helm(self, path: str, content: str) -> List[IaCScanResult]:
        results: List[IaCScanResult] = []

        values: Optional[Dict] = _yaml_load(content)
        if not isinstance(values, dict):
            return results

        # ── IAC-HELM-001: securityContext missing or runAsRoot ────────────────
        sc = values.get("securityContext")
        if sc is None:
            results.append(
                _res(
                    path, 1, "IAC-HELM-001", "HIGH",
                    "securityContext is missing from Helm values",
                    "Define securityContext with runAsNonRoot: true and runAsUser > 0.",
                    category="PRIVILEGE",
                )
            )
        elif isinstance(sc, dict):
            run_as_root = sc.get("runAsRoot", False)
            run_as_non_root = sc.get("runAsNonRoot", None)
            run_as_user = sc.get("runAsUser", None)
            is_root = (
                run_as_root is True
                or run_as_non_root is False
                or run_as_user == 0
            )
            if is_root:
                line_no = _find_line_str(content, "securityContext")
                results.append(
                    _res(
                        path, line_no, "IAC-HELM-001", "HIGH",
                        "Helm chart securityContext allows running as root",
                        "Set runAsNonRoot: true and runAsUser to a non-zero UID.",
                        category="PRIVILEGE",
                    )
                )

        # ── IAC-HELM-002: image.pullPolicy not Always ─────────────────────────
        image = values.get("image", {}) or {}
        if isinstance(image, dict):
            pull_policy = image.get("pullPolicy", "")
            if pull_policy != "Always":
                line_no = _find_line_str(content, "pullPolicy") or _find_line_str(content, "image")
                results.append(
                    _res(
                        path, line_no or 1, "IAC-HELM-002", "LOW",
                        f"image.pullPolicy is '{pull_policy}' instead of 'Always'",
                        "Set image.pullPolicy: Always to ensure latest security patches.",
                        category="BUILD",
                    )
                )

        # ── IAC-HELM-003: resources.limits not set ────────────────────────────
        resources_val = values.get("resources", {}) or {}
        if isinstance(resources_val, dict):
            limits = resources_val.get("limits")
            if not limits:
                line_no = _find_line_str(content, "resources") or 1
                results.append(
                    _res(
                        path, line_no, "IAC-HELM-003", "MEDIUM",
                        "resources.limits not configured in Helm values",
                        "Set resources.limits.cpu and resources.limits.memory.",
                        category="COMPUTE",
                    )
                )

        # ── IAC-HELM-004: networkPolicy.enabled: false ────────────────────────
        network_policy = values.get("networkPolicy", {}) or {}
        if isinstance(network_policy, dict):
            enabled = network_policy.get("enabled", None)
            if enabled is False:
                line_no = _find_line_str(content, "networkPolicy")
                results.append(
                    _res(
                        path, line_no or 1, "IAC-HELM-004", "MEDIUM",
                        "NetworkPolicy is explicitly disabled in Helm values",
                        "Set networkPolicy.enabled: true and define ingress/egress rules.",
                        category="NETWORK",
                    )
                )

        # ── IAC-HELM-005: ingress TLS missing with ingress enabled ────────────
        ingress = values.get("ingress", {}) or {}
        if isinstance(ingress, dict):
            ingress_enabled = ingress.get("enabled", False)
            tls = ingress.get("tls", None)
            if ingress_enabled and not tls:
                line_no = _find_line_str(content, "ingress")
                results.append(
                    _res(
                        path, line_no or 1, "IAC-HELM-005", "HIGH",
                        "Ingress is enabled but TLS is not configured",
                        "Set ingress.tls with valid certificate configuration.",
                        category="NETWORK",
                    )
                )

        return results

    # ── Kubernetes ────────────────────────────────────────────────────────────

    def _check_kubernetes(self, path: str, content: str) -> List[IaCScanResult]:
        results: List[IaCScanResult] = []

        manifest: Optional[Any] = _yaml_load(content)
        if not isinstance(manifest, dict):
            return results

        api_version: str = manifest.get("apiVersion", "") or ""
        kind: str = manifest.get("kind", "") or ""
        meta: Dict = manifest.get("metadata", {}) or {}
        resource_name = meta.get("name", "unknown")

        lines = content.splitlines()

        def find_key(key: str) -> int:
            for i, ln in enumerate(lines, 1):
                if re.search(rf'\b{re.escape(key)}\s*:', ln):
                    return i
            return 1

        # Collect pod specs from various resource kinds
        pod_specs = _extract_pod_specs(manifest)

        for pod_spec in pod_specs:
            pod_sc: Dict = pod_spec.get("securityContext", {}) or {}
            containers: List[Dict] = pod_spec.get("containers", []) or []
            init_containers: List[Dict] = pod_spec.get("initContainers", []) or []
            all_containers = containers + init_containers

            # ── IAC-K8S-001: Pod without runAsNonRoot: true ───────────────────
            run_as_non_root = pod_sc.get("runAsNonRoot", None)
            run_as_user = pod_sc.get("runAsUser", None)
            if run_as_non_root is not True and run_as_user != 0:
                # Check if any container overrides
                all_have_non_root = all(
                    c.get("securityContext", {}).get("runAsNonRoot") is True
                    for c in containers
                ) and bool(containers)
                if not all_have_non_root:
                    results.append(
                        _res(
                            path, find_key("securityContext"), "IAC-K8S-001", "HIGH",
                            f"Pod '{resource_name}' does not enforce runAsNonRoot: true",
                            "Set securityContext.runAsNonRoot: true in pod or container spec.",
                            resource=resource_name,
                            category="PRIVILEGE",
                        )
                    )

            # ── IAC-K8S-002: Container without resources.limits ───────────────
            for container in containers:
                cname = container.get("name", "unknown")
                res_limits = _walk_dict(container, "resources", "limits")
                if not res_limits:
                    results.append(
                        _res(
                            path, find_key("resources"), "IAC-K8S-002", "MEDIUM",
                            f"Container '{cname}' in '{resource_name}' has no resource limits",
                            "Define resources.limits.cpu and resources.limits.memory.",
                            resource=resource_name,
                            category="COMPUTE",
                        )
                    )

            # ── IAC-K8S-003: hostNetwork: true ────────────────────────────────
            if pod_spec.get("hostNetwork") is True:
                results.append(
                    _res(
                        path, find_key("hostNetwork"), "IAC-K8S-003", "HIGH",
                        f"Pod '{resource_name}' uses host network namespace",
                        "Set hostNetwork: false or remove the field.",
                        resource=resource_name,
                        category="NETWORK",
                    )
                )

            # ── IAC-K8S-004: hostPID/hostIPC: true ───────────────────────────
            if pod_spec.get("hostPID") is True:
                results.append(
                    _res(
                        path, find_key("hostPID"), "IAC-K8S-004", "HIGH",
                        f"Pod '{resource_name}' shares host PID namespace",
                        "Set hostPID: false.",
                        resource=resource_name,
                        category="PRIVILEGE",
                    )
                )
            if pod_spec.get("hostIPC") is True:
                results.append(
                    _res(
                        path, find_key("hostIPC"), "IAC-K8S-004", "HIGH",
                        f"Pod '{resource_name}' shares host IPC namespace",
                        "Set hostIPC: false.",
                        resource=resource_name,
                        category="PRIVILEGE",
                    )
                )

            # ── IAC-K8S-005/006/007: Per-container security context checks ────
            for container in all_containers:
                cname = container.get("name", "unknown")
                csc: Dict = container.get("securityContext", {}) or {}

                # K8S-005: privileged: true
                if csc.get("privileged") is True:
                    results.append(
                        _res(
                            path, find_key("privileged"), "IAC-K8S-005", "CRITICAL",
                            f"Container '{cname}' in '{resource_name}' runs in privileged mode",
                            "Set securityContext.privileged: false.",
                            resource=resource_name,
                            category="PRIVILEGE",
                        )
                    )

                # K8S-006: allowPrivilegeEscalation: true
                if csc.get("allowPrivilegeEscalation") is True:
                    results.append(
                        _res(
                            path, find_key("allowPrivilegeEscalation"), "IAC-K8S-006", "HIGH",
                            f"Container '{cname}' allows privilege escalation",
                            "Set allowPrivilegeEscalation: false.",
                            resource=resource_name,
                            category="PRIVILEGE",
                        )
                    )

                # K8S-007: readOnlyRootFilesystem missing
                if csc.get("readOnlyRootFilesystem") is not True:
                    results.append(
                        _res(
                            path, find_key("readOnlyRootFilesystem"), "IAC-K8S-007", "MEDIUM",
                            f"Container '{cname}' in '{resource_name}' does not use readOnlyRootFilesystem",
                            "Set securityContext.readOnlyRootFilesystem: true.",
                            resource=resource_name,
                            category="PRIVILEGE",
                        )
                    )

        # ── IAC-K8S-008: ConfigMap with secret-like values ────────────────────
        if kind == "ConfigMap":
            data: Dict = manifest.get("data", {}) or {}
            secret_key_re = re.compile(r'(?:password|token|key|secret|credential)', re.IGNORECASE)
            value_re = re.compile(r'.{8,}')  # Non-trivial value
            for k, v in data.items():
                if secret_key_re.search(k) and isinstance(v, str) and value_re.match(v):
                    line_no = find_key(k)
                    results.append(
                        _res(
                            path, line_no, "IAC-K8S-008", "HIGH",
                            f"ConfigMap '{resource_name}' key '{k}' appears to contain a secret",
                            "Use Kubernetes Secrets or external secret management instead of ConfigMap.",
                            resource=resource_name,
                            category="SECRETS",
                        )
                    )

        # ── IAC-K8S-009: Service exposing sensitive ports ─────────────────────
        _SENSITIVE_PORTS = {22, 3306, 5432}
        if kind == "Service":
            spec: Dict = manifest.get("spec", {}) or {}
            svc_type = spec.get("type", "ClusterIP")
            if svc_type in ("NodePort", "LoadBalancer"):
                ports: List[Dict] = spec.get("ports", []) or []
                for port_def in ports:
                    if not isinstance(port_def, dict):
                        continue
                    port_num = port_def.get("port") or port_def.get("targetPort")
                    try:
                        port_num = int(port_num)
                    except (TypeError, ValueError):
                        continue
                    if port_num in _SENSITIVE_PORTS:
                        results.append(
                            _res(
                                path, find_key("ports"), "IAC-K8S-009", "MEDIUM",
                                f"Service '{resource_name}' exposes sensitive port {port_num} via {svc_type}",
                                "Restrict sensitive service types or use NetworkPolicy to limit access.",
                                resource=resource_name,
                                category="NETWORK",
                            )
                        )
                        break

        # ── IAC-K8S-010: Missing NetworkPolicy (heuristic on namespace) ────────
        if kind == "Namespace":
            # Flag for informational purposes — no NetworkPolicy applied to namespace
            results.append(
                _res(
                    path, 1, "IAC-K8S-010", "LOW",
                    f"Namespace '{resource_name}' has no associated NetworkPolicy defined in this file",
                    "Define a default-deny NetworkPolicy for the namespace.",
                    resource=resource_name,
                    category="NETWORK",
                )
            )

        return results

    # ── File type detection and routing ───────────────────────────────────────

    def scan_file(self, path: str) -> List[IaCScanResult]:
        """Detect file type and route to the appropriate checker."""
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except OSError as exc:
            logger.warning("Cannot read %s: %s", path, exc)
            return []

        try:
            return self._route(path, content)
        except Exception as exc:
            logger.warning("Error scanning %s: %s", path, exc)
            return []

    def _route(self, path: str, content: str) -> List[IaCScanResult]:
        basename = os.path.basename(path).lower()
        ext = os.path.splitext(path)[1].lower()

        # Terraform
        if ext == ".tf":
            return self._check_terraform(path, content)

        # JSON CloudFormation
        if ext == ".json":
            data = _json_load(content)
            if isinstance(data, dict) and (
                "AWSTemplateFormatVersion" in data or (
                    "Resources" in data and isinstance(data["Resources"], dict)
                )
            ):
                return self._check_cloudformation(path, content)
            return []

        # YAML files: determine sub-type
        if ext in (".yaml", ".yml"):
            return self._route_yaml(path, content, basename)

        return []

    def _route_yaml(self, path: str, content: str, basename: str) -> List[IaCScanResult]:
        """Classify a YAML file as CF / K8s / Helm and dispatch."""
        results: List[IaCScanResult] = []

        # CloudFormation: has AWSTemplateFormatVersion or top-level Resources with AWS:: types
        if re.search(r'AWSTemplateFormatVersion', content) or re.search(r'Resources\s*:', content):
            if re.search(r'AWS::', content):
                return self._check_cloudformation(path, content)

        # Kubernetes: has apiVersion and kind at top level
        if re.search(r'^apiVersion\s*:', content, re.MULTILINE) and re.search(r'^kind\s*:', content, re.MULTILINE):
            results.extend(self._check_kubernetes(path, content))
            return results

        # Helm values: values.yaml or in a chart directory
        if basename in ("values.yaml", "values.yml") or re.search(r'Chart\.yaml', path):
            results.extend(self._check_helm(path, content))
            return results

        # Last resort: try both Helm and K8s checks on generic YAML
        parsed = _yaml_load(content)
        if isinstance(parsed, dict):
            if "image" in parsed or "ingress" in parsed or "securityContext" in parsed:
                results.extend(self._check_helm(path, content))

        return results

    def scan_directory(self, directory: str) -> List[IaCScanResult]:
        """Walk directory and scan all IaC files."""
        results: List[IaCScanResult] = []
        for root, dirs, files in os.walk(directory):
            # Prune skip dirs in-place
            dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
            for filename in files:
                ext = os.path.splitext(filename)[1].lower()
                if ext in (".tf", ".yaml", ".yml", ".json"):
                    full_path = os.path.join(root, filename)
                    results.extend(self.scan_file(full_path))
        return results


# ─────────────────────────────────────────────────────────────────────────────
# Terraform block parser
# ─────────────────────────────────────────────────────────────────────────────

_TF_BLOCK_RE = re.compile(
    r'^(resource|data|module)\s+"([^"]+)"\s+"([^"]+)"\s*\{',
    re.MULTILINE,
)


def _extract_tf_blocks(content: str) -> List[Tuple[str, str, str, int, str]]:
    """
    Extract top-level Terraform resource blocks.

    Returns list of (block_type, resource_type, name, start_line, block_content).
    block_content includes everything between the outer braces.
    """
    results = []
    lines = content.splitlines(keepends=True)
    # Build cumulative character offsets per line for line-number lookup
    offsets = []
    total = 0
    for ln in lines:
        offsets.append(total)
        total += len(ln)

    for m in _TF_BLOCK_RE.finditer(content):
        block_type = m.group(1)
        resource_type = m.group(2)
        name = m.group(3)

        # Find start line (1-based)
        start_char = m.start()
        start_line = _char_to_line(offsets, start_char)

        # Extract balanced block content
        brace_start = content.index("{", m.start())
        block_content = _extract_balanced(content, brace_start)

        results.append((block_type, resource_type, name, start_line, block_content))

    return results


def _char_to_line(offsets: List[int], char_pos: int) -> int:
    """Convert character offset to 1-based line number using binary search."""
    lo, hi = 0, len(offsets) - 1
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if offsets[mid] <= char_pos:
            lo = mid
        else:
            hi = mid - 1
    return lo + 1


def _extract_balanced(content: str, start: int) -> str:
    """Extract content of balanced braces starting at `start` (which is '{')."""
    depth = 0
    i = start
    length = len(content)
    while i < length:
        c = content[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return content[start + 1 : i]
        i += 1
    return content[start + 1 :]


# ─────────────────────────────────────────────────────────────────────────────
# Kubernetes pod spec extractor
# ─────────────────────────────────────────────────────────────────────────────


def _extract_pod_specs(manifest: Dict) -> List[Dict]:
    """
    Extract pod spec(s) from a Kubernetes manifest regardless of kind.
    Handles Pod, Deployment, DaemonSet, StatefulSet, ReplicaSet, Job, CronJob.
    """
    kind = manifest.get("kind", "")
    specs: List[Dict] = []

    if kind == "Pod":
        spec = manifest.get("spec", {})
        if isinstance(spec, dict):
            specs.append(spec)
    elif kind in ("Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "Job"):
        pod_spec = _walk_dict(manifest, "spec", "template", "spec")
        if isinstance(pod_spec, dict):
            specs.append(pod_spec)
    elif kind == "CronJob":
        pod_spec = _walk_dict(manifest, "spec", "jobTemplate", "spec", "template", "spec")
        if isinstance(pod_spec, dict):
            specs.append(pod_spec)

    return specs


# ─────────────────────────────────────────────────────────────────────────────
# Module-level convenience function
# ─────────────────────────────────────────────────────────────────────────────


def scan_iac(directory: str) -> List[IaCScanResult]:
    """Scan an entire directory for IaC security issues."""
    return IaCScanner().scan_directory(directory)
