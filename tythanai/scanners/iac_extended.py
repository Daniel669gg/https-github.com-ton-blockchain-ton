"""
TythanAI — Extended IaC Scanner

Covers Ansible playbooks/roles, Helm charts, and AWS CloudFormation templates.
Complements iac_scanner.py which handles Dockerfile/docker-compose/Terraform/GitHub Actions.

Usage:
    from scanners.iac_extended import IaCExtendedScanner
    scanner  = IaCExtendedScanner()
    findings = scanner.scan_directory("/path/to/project")
    findings = scanner.scan_file("/path/to/playbook.yml")
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    import yaml as _yaml
    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False

_SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv",
              "dist", "build", ".terraform"}

_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _load_yaml(text: str):
    """Load YAML with fallback for missing PyYAML."""
    if _YAML_AVAILABLE:
        try:
            return list(_yaml.safe_load_all(text))
        except Exception:
            return []
    return []


def _load_json(text: str):
    try:
        return json.loads(text)
    except Exception:
        return None


def _finding(
    rule_id:  str,
    severity: str,
    cwe:      str,
    file:     str,
    line:     int,
    message:  str,
    desc:     str,
    evidence: str,
    rec:      str,
    source:   str,
    scanner:  str = "iac_extended",
) -> Dict:
    return {
        "type":           "IAC_EXTENDED_ISSUE",
        "id":             rule_id,
        "severity":       severity,
        "cwe":            cwe,
        "file":           file,
        "line":           line,
        "message":        message,
        "description":    desc,
        "evidence":       evidence,
        "recommendation": rec,
        "source":         source,
        "scanner":        scanner,
        "category":       "IaC Security",
        "confidence":     80,
    }


# ── Ansible scanner ────────────────────────────────────────────────────────────

_ANSIBLE_SOURCES = re.compile(
    r"\b(ansible_playbook|hosts|tasks|roles|handlers|vars|defaults)\b"
)

_ANSIBLE_RULES: List[Tuple[str, str, str, str, str, re.Pattern]] = [
    # id, severity, cwe, message, recommendation, pattern
    (
        "ANS-001", "HIGH", "CWE-522",
        "Ansible vault password stored in plaintext",
        "Use ansible-vault to encrypt sensitive variables",
        re.compile(r"vault_password\s*:\s*['\"]?[^'\"\n]{4,}", re.I),
    ),
    (
        "ANS-002", "HIGH", "CWE-798",
        "Hardcoded password in Ansible variable",
        "Move secrets to ansible-vault encrypted vars or environment variables",
        re.compile(r"(password|passwd|secret|api_key|token)\s*:\s*['\"]?.{4,}['\"]?", re.I),
    ),
    (
        "ANS-003", "CRITICAL", "CWE-78",
        "Ansible shell/command task with no_log disabled may expose secrets",
        "Add 'no_log: true' to tasks that handle sensitive data",
        re.compile(r"(shell|command)\s*:\s*.*(password|secret|token|key)", re.I),
    ),
    (
        "ANS-004", "HIGH", "CWE-250",
        "Task runs with become: yes (privilege escalation) without restriction",
        "Restrict become usage to specific tasks; use become_user instead of root",
        re.compile(r"become\s*:\s*(yes|true)", re.I),
    ),
    (
        "ANS-005", "MEDIUM", "CWE-16",
        "SSH host key checking disabled",
        "Do not disable host key checking in production; use known_hosts",
        re.compile(r"host_key_checking\s*[=:]\s*(false|no|0)", re.I),
    ),
    (
        "ANS-006", "MEDIUM", "CWE-319",
        "Ansible connection uses plain HTTP/Telnet",
        "Use SSH or HTTPS for all Ansible connections",
        re.compile(r"ansible_connection\s*:\s*(telnet|http|httpapi.*http://)", re.I),
    ),
    (
        "ANS-007", "HIGH", "CWE-732",
        "File/directory created with world-writable permissions",
        "Use mode 0644 or 0755 instead of 0777/0666",
        re.compile(r"mode\s*:\s*['\"]?0?(777|666|775|664)['\"]?", re.I),
    ),
    (
        "ANS-008", "MEDIUM", "CWE-16",
        "gather_facts disabled — may miss security-relevant host information",
        "Enable gather_facts unless performance is critical and context is known",
        re.compile(r"gather_facts\s*:\s*(false|no)", re.I),
    ),
    (
        "ANS-009", "HIGH", "CWE-295",
        "SSL/TLS verification disabled in Ansible uri/get_url task",
        "Never set validate_certs: false in production",
        re.compile(r"validate_certs\s*:\s*(false|no|0)", re.I),
    ),
    (
        "ANS-010", "MEDIUM", "CWE-312",
        "Task output logged without no_log — may expose credentials",
        "Add 'no_log: true' to tasks handling sensitive output",
        re.compile(r"register\s*:\s*\w+.*\n.*(?:password|secret|token)", re.I | re.MULTILINE),
    ),
]


def _scan_ansible(file_path: str) -> List[Dict]:
    p = Path(file_path)
    try:
        text = p.read_text(errors="replace")
    except Exception:
        return []

    findings: List[Dict] = []
    lines    = text.splitlines()

    for rule_id, sev, cwe, msg, rec, pattern in _ANSIBLE_RULES:
        for i, line in enumerate(lines, 1):
            # Skip comments
            stripped = line.lstrip()
            if stripped.startswith("#"):
                continue
            if pattern.search(line):
                findings.append(_finding(
                    rule_id=rule_id, severity=sev, cwe=cwe,
                    file=file_path, line=i,
                    message=msg,
                    desc=msg,
                    evidence=line.strip()[:120],
                    rec=rec,
                    source="ansible_scanner",
                ))
                break  # one finding per rule per file

    # Check for missing no_log in tasks with sensitive args
    if "no_log" not in text and re.search(r"(password|secret|api_key)", text, re.I):
        findings.append(_finding(
            rule_id="ANS-011", severity="MEDIUM", cwe="CWE-312",
            file=file_path, line=1,
            message="Playbook handles secrets but 'no_log: true' not found",
            desc="Tasks handling sensitive data should set no_log: true to prevent credential logging",
            evidence="no_log directive absent",
            rec="Add 'no_log: true' to all tasks that use or output credentials",
            source="ansible_scanner",
        ))

    return findings


def _is_ansible_file(p: Path) -> bool:
    """Heuristic: YAML file that looks like an Ansible playbook or vars file."""
    name = p.name.lower()
    if name in ("playbook.yml", "playbook.yaml", "site.yml", "site.yaml",
                "main.yml", "main.yaml"):
        return True
    for part in p.parts:
        if part.lower() in ("tasks", "handlers", "vars", "defaults",
                             "group_vars", "host_vars", "roles", "playbooks"):
            return True
    # Check content heuristic
    try:
        head = p.read_text(errors="replace")[:512]
        return bool(re.search(r"\b(hosts|tasks|roles|become|vars|handlers)\b", head))
    except Exception:
        return False


# ── Helm chart scanner ─────────────────────────────────────────────────────────

_HELM_RULES: List[Tuple[str, str, str, str, str, re.Pattern]] = [
    (
        "HELM-001", "HIGH", "CWE-798",
        "Hardcoded secret or password in Helm values",
        "Use Kubernetes Secrets or external secret managers (Vault, AWS Secrets Manager)",
        re.compile(r"(password|secret|api[_-]?key|token|private[_-]?key)\s*:\s*['\"]?\S{4,}", re.I),
    ),
    (
        "HELM-002", "HIGH", "CWE-250",
        "Container runs as root (runAsUser: 0 or missing securityContext)",
        "Set securityContext.runAsNonRoot: true and runAsUser to non-zero UID",
        re.compile(r"runAsUser\s*:\s*0\b"),
    ),
    (
        "HELM-003", "CRITICAL", "CWE-250",
        "privileged: true in Helm security context",
        "Never run containers as privileged unless absolutely necessary",
        re.compile(r"privileged\s*:\s*true", re.I),
    ),
    (
        "HELM-004", "HIGH", "CWE-16",
        "allowPrivilegeEscalation not set to false",
        "Set allowPrivilegeEscalation: false in all container securityContexts",
        re.compile(r"allowPrivilegeEscalation\s*:\s*true", re.I),
    ),
    (
        "HELM-005", "HIGH", "CWE-284",
        "Capabilities added to container (e.g., NET_ADMIN, SYS_ADMIN)",
        "Drop all capabilities and add only those required",
        re.compile(r"add\s*:\s*\[.*(?:NET_ADMIN|SYS_ADMIN|ALL|NET_RAW)", re.I),
    ),
    (
        "HELM-006", "MEDIUM", "CWE-16",
        "readOnlyRootFilesystem not set to true",
        "Set readOnlyRootFilesystem: true; use emptyDir for writable paths",
        re.compile(r"readOnlyRootFilesystem\s*:\s*false", re.I),
    ),
    (
        "HELM-007", "HIGH", "CWE-732",
        "RBAC ClusterRole with wildcard permissions",
        "Grant minimal required permissions; avoid wildcards in RBAC rules",
        re.compile(r'verbs\s*:\s*\[.*"\*"', re.I),
    ),
    (
        "HELM-008", "MEDIUM", "CWE-400",
        "No resource limits defined in container spec",
        "Always define resources.limits.cpu and resources.limits.memory",
        re.compile(r"resources\s*:\s*\{\s*\}", re.I),
    ),
    (
        "HELM-009", "MEDIUM", "CWE-319",
        "Service uses LoadBalancer type exposing port externally",
        "Use ClusterIP with Ingress for external access; restrict with NetworkPolicy",
        re.compile(r"type\s*:\s*LoadBalancer", re.I),
    ),
    (
        "HELM-010", "HIGH", "CWE-295",
        "TLS verification disabled in Helm HTTP configuration",
        "Always verify TLS certificates; do not set insecureSkipVerify: true",
        re.compile(r"insecureSkipVerify\s*:\s*true", re.I),
    ),
    (
        "HELM-011", "MEDIUM", "CWE-16",
        "hostNetwork: true grants container access to host network",
        "Avoid hostNetwork; use ClusterIP services and proper network policies",
        re.compile(r"hostNetwork\s*:\s*true", re.I),
    ),
    (
        "HELM-012", "MEDIUM", "CWE-16",
        "hostPID: true grants container access to host process namespace",
        "Set hostPID: false; only use in specific debugging scenarios",
        re.compile(r"hostPID\s*:\s*true", re.I),
    ),
]


def _scan_helm(file_path: str) -> List[Dict]:
    p = Path(file_path)
    try:
        text = p.read_text(errors="replace")
    except Exception:
        return []

    findings: List[Dict] = []
    lines    = text.splitlines()

    for rule_id, sev, cwe, msg, rec, pattern in _HELM_RULES:
        for i, line in enumerate(lines, 1):
            stripped = line.lstrip()
            if stripped.startswith("#"):
                continue
            if pattern.search(line):
                findings.append(_finding(
                    rule_id=rule_id, severity=sev, cwe=cwe,
                    file=file_path, line=i,
                    message=msg,
                    desc=msg,
                    evidence=line.strip()[:120],
                    rec=rec,
                    source="helm_scanner",
                ))
                break

    # Absence checks on full text
    if p.name in ("values.yaml", "values.yml"):
        if "securityContext" not in text:
            findings.append(_finding(
                rule_id="HELM-013", severity="HIGH", cwe="CWE-250",
                file=file_path, line=1,
                message="No securityContext defined in Helm values",
                desc="Missing securityContext means containers may run as root with full privileges",
                evidence="securityContext key not found",
                rec="Add securityContext with runAsNonRoot: true, readOnlyRootFilesystem: true",
                source="helm_scanner",
            ))

    return findings


def _is_helm_file(p: Path) -> bool:
    """Heuristic: YAML in a chart directory or named values/Chart."""
    name = p.name.lower()
    if name in ("chart.yaml", "chart.yml", "values.yaml", "values.yml"):
        return True
    for part in p.parts:
        if part.lower() in ("templates", "charts"):
            return True
    try:
        head = p.read_text(errors="replace")[:512]
        return bool(re.search(r"\b(apiVersion|kind|metadata|spec|helm\.sh)\b", head))
    except Exception:
        return False


# ── CloudFormation scanner ─────────────────────────────────────────────────────

_CFN_RULES: List[Tuple[str, str, str, str, str]] = [
    # id, severity, cwe, message, recommendation
    # Rules applied as structural checks on parsed JSON/YAML
]

_CFN_REGEX_RULES: List[Tuple[str, str, str, str, str, re.Pattern]] = [
    (
        "CFN-001", "HIGH", "CWE-798",
        "Hardcoded secret/password in CloudFormation template",
        "Use AWS Secrets Manager or SSM Parameter Store with NoEcho: true",
        re.compile(r'"?(Password|Secret|ApiKey|Token)"?\s*:\s*["\']?\S{6,}', re.I),
    ),
    (
        "CFN-002", "HIGH", "CWE-284",
        "S3 bucket has public access (ACL: public-read or public-read-write)",
        "Set BlockPublicAcls, BlockPublicPolicy, IgnorePublicAcls, RestrictPublicBuckets to true",
        re.compile(r'"?AccessControl"?\s*:\s*["\']?(Public|public)', re.I),
    ),
    (
        "CFN-003", "HIGH", "CWE-311",
        "S3 bucket encryption (ServerSideEncryptionConfiguration) not configured",
        "Enable AES-256 or aws:kms encryption on all S3 buckets",
        re.compile(r"AWS::S3::Bucket(?!.*ServerSideEncryptionConfiguration)", re.DOTALL),
    ),
    (
        "CFN-004", "CRITICAL", "CWE-284",
        "Security group allows inbound from 0.0.0.0/0 on sensitive port",
        "Restrict CidrIp to known IP ranges; never use 0.0.0.0/0 for admin ports",
        re.compile(r'"?CidrIp"?\s*:\s*["\']?0\.0\.0\.0/0', re.I),
    ),
    (
        "CFN-005", "HIGH", "CWE-319",
        "RDS instance does not enforce SSL/TLS (StorageEncrypted: false)",
        "Set StorageEncrypted: true and require SSL via parameter group",
        re.compile(r'"?StorageEncrypted"?\s*:\s*(false|no|False)', re.I),
    ),
    (
        "CFN-006", "HIGH", "CWE-284",
        "IAM policy uses wildcard action (*) — overly permissive",
        "Specify exact IAM actions required; avoid Action: '*'",
        re.compile(r'"?Action"?\s*:\s*["\']?\*["\']?', re.I),
    ),
    (
        "CFN-007", "HIGH", "CWE-284",
        "IAM policy uses wildcard resource (*) — overly permissive",
        "Specify exact resource ARNs; avoid Resource: '*'",
        re.compile(r'"?Resource"?\s*:\s*["\']?\*["\']?', re.I),
    ),
    (
        "CFN-008", "HIGH", "CWE-778",
        "CloudTrail logging disabled or not configured",
        "Enable CloudTrail in all regions with log file validation",
        re.compile(r'"?IsLogging"?\s*:\s*(false|False|no)', re.I),
    ),
    (
        "CFN-009", "MEDIUM", "CWE-311",
        "EBS volume not encrypted",
        "Set Encrypted: true on all EBS volumes",
        re.compile(r"AWS::EC2::Volume(?!.*Encrypted\s*:\s*true)", re.DOTALL),
    ),
    (
        "CFN-010", "HIGH", "CWE-312",
        "Lambda function has environment variable with secret-like name",
        "Store secrets in AWS Secrets Manager; reference via {{resolve:secretsmanager:...}}",
        re.compile(r"(PASSWORD|SECRET|API_KEY|TOKEN|PRIVATE_KEY)\s*:", re.I),
    ),
    (
        "CFN-011", "MEDIUM", "CWE-16",
        "DeletionPolicy not set — resource may be accidentally deleted",
        "Add DeletionPolicy: Retain or Snapshot for stateful resources",
        re.compile(r"AWS::(RDS|DynamoDB|S3)::(?!.*DeletionPolicy)", re.DOTALL),
    ),
    (
        "CFN-012", "HIGH", "CWE-295",
        "ElasticSearch/OpenSearch does not enforce HTTPS",
        "Set EnforceHTTPS: true in DomainEndpointOptions",
        re.compile(r"EnforceHTTPS\s*:\s*(false|False|no)", re.I),
    ),
    (
        "CFN-013", "MEDIUM", "CWE-778",
        "VPC Flow Logs not enabled",
        "Enable VPC Flow Logs for network monitoring and incident response",
        re.compile(r"AWS::EC2::VPC(?!.*FlowLog)", re.DOTALL),
    ),
    (
        "CFN-014", "HIGH", "CWE-287",
        "Cognito UserPool MFA not required",
        "Set MfaConfiguration to REQUIRED for Cognito user pools",
        re.compile(r"MfaConfiguration\s*:\s*['\"]?OFF['\"]?", re.I),
    ),
    (
        "CFN-015", "MEDIUM", "CWE-16",
        "CloudFormation stack termination protection not enabled",
        "Enable TerminationProtection on production stacks",
        re.compile(r"EnableTerminationProtection\s*:\s*(false|False)", re.I),
    ),
]


def _scan_cloudformation(file_path: str) -> List[Dict]:
    p = Path(file_path)
    try:
        text = p.read_text(errors="replace")
    except Exception:
        return []

    # Verify it's a CFN template (must have AWSTemplateFormatVersion or Resources)
    if "AWSTemplateFormatVersion" not in text and '"Resources"' not in text and "Resources:" not in text:
        return []

    findings: List[Dict] = []
    lines    = text.splitlines()

    for rule_id, sev, cwe, msg, rec, pattern in _CFN_REGEX_RULES:
        for i, line in enumerate(lines, 1):
            stripped = line.lstrip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue
            if pattern.search(line):
                findings.append(_finding(
                    rule_id=rule_id, severity=sev, cwe=cwe,
                    file=file_path, line=i,
                    message=msg,
                    desc=msg,
                    evidence=line.strip()[:120],
                    rec=rec,
                    source="cloudformation_scanner",
                ))
                break  # one per rule per file

    # Check for NoEcho on parameters with sensitive names
    param_block = re.search(r"Parameters\s*:(.*?)(?=\nResources:|\Z)", text, re.DOTALL)
    if param_block:
        for m in re.finditer(
            r"(\w+)\s*:\s*\n\s+Type\s*:.+\n(?:(?!\n\n).)*",
            param_block.group(1),
            re.DOTALL,
        ):
            param_text = m.group(0)
            param_name = m.group(1)
            if re.search(r"(password|secret|key|token)", param_name, re.I):
                if "NoEcho" not in param_text:
                    line_no = text[:m.start() + param_block.start()].count("\n") + 1
                    findings.append(_finding(
                        rule_id="CFN-016", severity="HIGH", cwe="CWE-312",
                        file=file_path, line=line_no,
                        message=f"Parameter '{param_name}' looks sensitive but lacks NoEcho: true",
                        desc="Sensitive parameters should have NoEcho: true to prevent value display in console",
                        evidence=f"Parameter: {param_name}",
                        rec="Add 'NoEcho: true' to all sensitive CloudFormation parameters",
                        source="cloudformation_scanner",
                    ))

    return findings


def _is_cloudformation_file(p: Path) -> bool:
    name = p.name.lower()
    if name in ("template.json", "template.yaml", "template.yml",
                "cloudformation.json", "cloudformation.yaml", "cloudformation.yml"):
        return True
    if re.search(r"(cfn|cf|cloudformation|stack)", name, re.I):
        return True
    try:
        head = p.read_text(errors="replace")[:512]
        return "AWSTemplateFormatVersion" in head or (
            "Resources" in head and ("AWS::" in head or '"Type"' in head)
        )
    except Exception:
        return False


# ── Main scanner class ─────────────────────────────────────────────────────────

class IaCExtendedScanner:
    """
    Scans Ansible, Helm, and CloudFormation IaC files for security issues.
    Complements the base IaCScanner (Dockerfile/docker-compose/Terraform/GitHub Actions).
    """

    SUPPORTED_FORMATS = ["ansible", "helm", "cloudformation"]

    def scan_file(self, file_path: str) -> List[Dict]:
        """Auto-detect format and scan a single file."""
        p = Path(file_path)
        if not p.exists() or not p.is_file():
            return []

        findings: List[Dict] = []
        suffix = p.suffix.lower()

        if suffix in (".yml", ".yaml", ".json"):
            if _is_cloudformation_file(p):
                findings.extend(_scan_cloudformation(file_path))
            elif _is_helm_file(p):
                findings.extend(_scan_helm(file_path))
            elif _is_ansible_file(p):
                findings.extend(_scan_ansible(file_path))

        findings.sort(key=lambda f: _SEV_ORDER.get(f.get("severity", "LOW"), 4))
        return findings

    def scan_directory(self, directory: str) -> Dict:
        """
        Recursively scan a directory for Ansible, Helm, and CloudFormation files.
        Returns a summary dict with findings list.
        """
        root     = Path(directory)
        findings: List[Dict] = []
        scanned: Dict[str, int] = {"ansible": 0, "helm": 0, "cloudformation": 0}

        for p in root.rglob("*"):
            if not p.is_file():
                continue
            if any(part in _SKIP_DIRS for part in p.parts):
                continue
            suffix = p.suffix.lower()
            if suffix not in (".yml", ".yaml", ".json"):
                continue

            if _is_cloudformation_file(p):
                found = _scan_cloudformation(str(p))
                findings.extend(found)
                scanned["cloudformation"] += 1
            elif _is_helm_file(p):
                found = _scan_helm(str(p))
                findings.extend(found)
                scanned["helm"] += 1
            elif _is_ansible_file(p):
                found = _scan_ansible(str(p))
                findings.extend(found)
                scanned["ansible"] += 1

        findings.sort(key=lambda f: _SEV_ORDER.get(f.get("severity", "LOW"), 4))

        sev_counts: Dict[str, int] = {}
        for f in findings:
            s = f.get("severity", "MEDIUM")
            sev_counts[s] = sev_counts.get(s, 0) + 1

        return {
            "files_scanned":  sum(scanned.values()),
            "breakdown":      scanned,
            "total_findings": len(findings),
            "severity_counts": sev_counts,
            "findings":       findings,
            "scanner":        "iac_extended",
            "formats":        self.SUPPORTED_FORMATS,
        }

    def scan_ansible(self, path: str) -> List[Dict]:
        """Scan a single Ansible playbook/vars file."""
        return _scan_ansible(path) if Path(path).exists() else []

    def scan_helm_chart(self, chart_dir: str) -> List[Dict]:
        """Scan all YAML files in a Helm chart directory."""
        root     = Path(chart_dir)
        findings: List[Dict] = []
        for p in root.rglob("*.yaml"):
            if not any(part in _SKIP_DIRS for part in p.parts):
                findings.extend(_scan_helm(str(p)))
        for p in root.rglob("*.yml"):
            if not any(part in _SKIP_DIRS for part in p.parts):
                findings.extend(_scan_helm(str(p)))
        findings.sort(key=lambda f: _SEV_ORDER.get(f.get("severity", "LOW"), 4))
        return findings

    def scan_cloudformation(self, path: str) -> List[Dict]:
        """Scan a single CloudFormation template (JSON or YAML)."""
        return _scan_cloudformation(path) if Path(path).exists() else []
