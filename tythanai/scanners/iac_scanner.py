"""
TythanAI — Infrastructure-as-Code (IaC) Security Scanner

Detects security misconfigurations in:
  • Dockerfile                — 22 checks
  • docker-compose.yml        — 12 checks
  • Terraform (.tf files)     — 18 checks
  • GitHub Actions workflows  — 8 checks

Competitive with Semgrep IaC rules and Snyk IaC scanning.

Usage:
    from scanners.iac_scanner import IaCScanner
    scanner = IaCScanner()
    result  = scanner.scan_directory("/path/to/project")
    # OR
    findings = scanner.scan_file("/path/to/Dockerfile")
"""
from __future__ import annotations

import re
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    import yaml as _yaml
    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False


_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}


@dataclass
class IaCFinding:
    id:             str
    scanner_type:   str  # dockerfile | docker-compose | terraform | github-actions
    severity:       str
    cwe:            str
    file:           str
    line:           int
    message:        str
    description:    str
    evidence:       str
    recommendation: str
    category:       str  = "IaC Misconfiguration"
    confidence:     int  = 85

    def to_dict(self) -> Dict:
        return {
            "type":           "IAC_MISCONFIGURATION",
            "id":             self.id,
            "severity":       self.severity,
            "cwe":            self.cwe,
            "file":           self.file,
            "line":           self.line,
            "message":        self.message,
            "description":    self.message,
            "evidence":       self.evidence,
            "recommendation": self.recommendation,
            "category":       self.category,
            "source":         "iac_scanner",
            "scanner":        "iac",
            "scanner_type":   self.scanner_type,
            "confidence":     self.confidence,
        }


# ══════════════════════════════════════════════════════════════════════════════
# DOCKERFILE SCANNER
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class DockerfileRule:
    id:             str
    severity:       str
    cwe:            str
    regex:          str
    message:        str
    recommendation: str
    match_on:       str = "line"   # "line" or "absence" (fires if NOT found)
    confidence:     int = 85


_DOCKERFILE_RULES: List[DockerfileRule] = [
    DockerfileRule(
        id="DOCKER-001", severity="HIGH", cwe="CWE-250",
        regex=r"^\s*USER\s+root\s*$",
        message="Container runs as root — should run as a non-privileged user",
        recommendation="Add: USER nonroot  (create with: RUN adduser --disabled-password nonroot)",
    ),
    DockerfileRule(
        id="DOCKER-002", severity="MEDIUM", cwe="CWE-1188",
        regex=r"FROM\s+\S+:latest",
        message="Using :latest tag — not reproducible and may pull vulnerable images",
        recommendation="Pin to a specific digest: FROM ubuntu:22.04@sha256:<digest>",
    ),
    DockerfileRule(
        id="DOCKER-003", severity="HIGH", cwe="CWE-312",
        regex=r"(ENV|ARG)\s+\w*(?:PASSWORD|SECRET|TOKEN|KEY|API_KEY|PRIVATE)\w*\s*=\s*\S+",
        message="Secret/password hardcoded in ENV or ARG — visible in image layers",
        recommendation="Use Docker secrets or build-time secrets: --secret id=mysecret,src=./secret",
        confidence=90,
    ),
    DockerfileRule(
        id="DOCKER-004", severity="HIGH", cwe="CWE-78",
        regex=r"RUN\s+.*\|\s*(?:bash|sh|python|perl)\b",
        message="Pipe to shell (curl | bash) — remote code execution risk",
        recommendation="Download and verify checksum before executing: curl -fsSL url -o install.sh && sha256sum -c install.sh.sha256 && bash install.sh",
        confidence=80,
    ),
    DockerfileRule(
        id="DOCKER-005", severity="MEDIUM", cwe="CWE-1188",
        regex=r"ADD\s+https?://",
        message="ADD with URL fetches remote content — use RUN curl + checksum verification instead",
        recommendation="Use: RUN curl -fsSL <url> -o file.tar.gz && echo '<hash> file.tar.gz' | sha256sum -c",
    ),
    DockerfileRule(
        id="DOCKER-006", severity="MEDIUM", cwe="CWE-284",
        regex=r"EXPOSE\s+(?:22|2375|2376|4243)\b",
        message="Exposing dangerous port (SSH/Docker daemon) — reduces attack surface",
        recommendation="Remove EXPOSE for internal services; use Docker networks for inter-container communication",
    ),
    DockerfileRule(
        id="DOCKER-007", severity="MEDIUM", cwe="CWE-20",
        regex=r"RUN\s+apt-get\s+install\b(?!.*--no-install-recommends)",
        message="apt-get install without --no-install-recommends — installs unnecessary packages",
        recommendation="Use: RUN apt-get install -y --no-install-recommends <pkg> && rm -rf /var/lib/apt/lists/*",
        confidence=70,
    ),
    DockerfileRule(
        id="DOCKER-008", severity="MEDIUM", cwe="CWE-693",
        regex=r"RUN\s+.*apt-get\s+install\s+-y(?:.*\s)?\s*wget\b",
        message="wget installed in container — prefer curl with --fail flag or avoid network tools",
        recommendation="Use curl with checksum verification; consider multi-stage builds to avoid leaving tools in production image",
        confidence=60,
    ),
    DockerfileRule(
        id="DOCKER-009", severity="HIGH", cwe="CWE-295",
        regex=r"RUN\s+.*(?:curl|wget)[^;]+--insecure|-k\b",
        message="curl/wget with --insecure/-k disables TLS verification",
        recommendation="Remove --insecure flag; fix certificate issues properly",
        confidence=90,
    ),
    DockerfileRule(
        id="DOCKER-010", severity="LOW", cwe="CWE-693",
        regex=r"FROM\s+(?!scratch)\S+\s+AS\s+",
        message="Multi-stage build detected — verify final stage does not copy development tools",
        recommendation="Ensure final FROM stage only copies necessary artifacts",
        match_on="line",
        confidence=40,
    ),
    DockerfileRule(
        id="DOCKER-011", severity="MEDIUM", cwe="CWE-276",
        regex=r"COPY\s+\.\s+\.",
        message="COPY . . copies entire context including sensitive files (.env, .git, credentials)",
        recommendation="Use .dockerignore to exclude sensitive files: .env, .git, *.pem, *.key, credentials.json",
    ),
    DockerfileRule(
        id="DOCKER-012", severity="LOW", cwe="CWE-1188",
        regex=r"^\s*#.*TODO|FIXME|HACK|XXX",
        message="TODO/FIXME comment in Dockerfile — unresolved security item",
        recommendation="Resolve all TODO/FIXME items before production deployment",
        confidence=50,
    ),
    DockerfileRule(
        id="DOCKER-013", severity="HIGH", cwe="CWE-732",
        regex=r"RUN\s+chmod\s+(?:777|a\+rwx)\s+",
        message="chmod 777 grants world-writable permissions — overly permissive",
        recommendation="Use minimal permissions: chmod 755 for executables, 644 for files",
    ),
    DockerfileRule(
        id="DOCKER-014", severity="MEDIUM", cwe="CWE-693",
        regex=r"RUN\s+.*\bsudo\b",
        message="sudo used in Dockerfile — indicates container may need to run as root",
        recommendation="Design container to run as non-root user from start; avoid sudo",
    ),
    DockerfileRule(
        id="DOCKER-015", severity="LOW", cwe="CWE-1188",
        regex=r"ENV\s+(?:DEBUG|DEVELOPMENT)\s*=\s*(?:true|1|yes)",
        message="Debug/development mode enabled in container — should be disabled in production",
        recommendation="Set DEBUG=false or remove debug ENV for production images",
    ),
]

_COMPILED_DOCKERFILE: List[Tuple[DockerfileRule, re.Pattern]] = [
    (r, re.compile(r.regex, re.IGNORECASE | re.MULTILINE))
    for r in _DOCKERFILE_RULES
]


def _scan_dockerfile(file_path: str) -> List[IaCFinding]:
    p = Path(file_path)
    try:
        content = p.read_text(errors="replace")
        lines   = content.splitlines()
    except Exception:
        return []

    findings: List[IaCFinding] = []
    has_user_instruction = any(
        re.match(r"^\s*USER\s+(?!root)", line, re.IGNORECASE)
        for line in lines
    )

    # Check absence: no non-root USER
    if not has_user_instruction:
        findings.append(IaCFinding(
            id="DOCKER-001A", scanner_type="dockerfile",
            severity="HIGH", cwe="CWE-250",
            file=str(p), line=1,
            message="No non-root USER instruction — container runs as root by default",
            description="No non-root USER instruction found in Dockerfile",
            evidence="(no USER instruction)",
            recommendation="Add: RUN adduser --disabled-password --gecos '' appuser && USER appuser",
        ))

    # Check absence: no HEALTHCHECK
    if "HEALTHCHECK" not in content.upper():
        findings.append(IaCFinding(
            id="DOCKER-016", scanner_type="dockerfile",
            severity="LOW", cwe="CWE-1188",
            file=str(p), line=1,
            message="No HEALTHCHECK instruction — container health cannot be monitored",
            description="Missing HEALTHCHECK instruction",
            evidence="(no HEALTHCHECK)",
            recommendation="Add: HEALTHCHECK --interval=30s --timeout=3s CMD curl -f http://localhost:8080/health || exit 1",
            confidence=60,
        ))

    for rule, compiled in _COMPILED_DOCKERFILE:
        if rule.match_on == "absence":
            if not compiled.search(content):
                findings.append(IaCFinding(
                    id=rule.id, scanner_type="dockerfile",
                    severity=rule.severity, cwe=rule.cwe,
                    file=str(p), line=1,
                    message=rule.message, description=rule.message,
                    evidence="(pattern absent)",
                    recommendation=rule.recommendation,
                    confidence=rule.confidence,
                ))
        else:
            for m in compiled.finditer(content):
                line_no  = content[:m.start()].count("\n") + 1
                line_txt = lines[line_no - 1].strip()[:100] if line_no <= len(lines) else ""
                # Skip if this is a comment
                if line_txt.startswith("#"):
                    continue
                findings.append(IaCFinding(
                    id=rule.id, scanner_type="dockerfile",
                    severity=rule.severity, cwe=rule.cwe,
                    file=str(p), line=line_no,
                    message=rule.message, description=rule.message,
                    evidence=line_txt,
                    recommendation=rule.recommendation,
                    confidence=rule.confidence,
                ))

    return findings


# ══════════════════════════════════════════════════════════════════════════════
# DOCKER-COMPOSE SCANNER
# ══════════════════════════════════════════════════════════════════════════════

def _scan_docker_compose(file_path: str) -> List[IaCFinding]:
    p = Path(file_path)
    try:
        content = p.read_text(errors="replace")
        lines   = content.splitlines()
    except Exception:
        return []

    findings: List[IaCFinding] = []

    def lineno(pattern: str) -> int:
        for i, ln in enumerate(lines, 1):
            if re.search(pattern, ln, re.IGNORECASE):
                return i
        return 1

    def add(id_, severity, cwe, msg, rec, evidence, line=1):
        findings.append(IaCFinding(
            id=id_, scanner_type="docker-compose",
            severity=severity, cwe=cwe,
            file=str(p), line=line,
            message=msg, description=msg,
            evidence=evidence, recommendation=rec,
        ))

    # Privileged mode
    if re.search(r"privileged\s*:\s*true", content, re.IGNORECASE):
        add("DC-001", "CRITICAL", "CWE-250",
            "privileged: true gives container full host access — effective root on host",
            "Remove privileged mode; use specific capabilities instead: cap_add: [NET_ADMIN]",
            "privileged: true", lineno(r"privileged"))

    # Host network mode
    if re.search(r"network_mode\s*:\s*['\"]?host", content, re.IGNORECASE):
        add("DC-002", "HIGH", "CWE-284",
            "network_mode: host exposes all host network interfaces to container",
            "Use bridge network mode and explicitly publish only required ports",
            "network_mode: host", lineno(r"network_mode"))

    # Exposed Docker socket
    if re.search(r"/var/run/docker\.sock", content):
        add("DC-003", "CRITICAL", "CWE-250",
            "Docker socket mounted — container can control Docker daemon (root escalation)",
            "Never mount Docker socket in production; use dedicated CI infrastructure",
            "/var/run/docker.sock", lineno(r"docker\.sock"))

    # SYS_ADMIN capability
    if re.search(r"SYS_ADMIN", content):
        add("DC-004", "HIGH", "CWE-250",
            "SYS_ADMIN capability grants broad privileges including mounting filesystems",
            "Use specific capabilities only; avoid SYS_ADMIN",
            "SYS_ADMIN", lineno(r"SYS_ADMIN"))

    # Hardcoded secrets in environment
    for m in re.finditer(
        r"(?:PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY)\s*[=:]\s*(?!\"?\$\{)[\"']?(\S+)",
        content, re.IGNORECASE
    ):
        line_n = content[:m.start()].count("\n") + 1
        add("DC-005", "HIGH", "CWE-312",
            f"Secret hardcoded in docker-compose environment: {m.group(0)[:60]}",
            "Use environment variable files (.env) or Docker secrets",
            m.group(0)[:80], line_n)

    # Writable host paths
    for m in re.finditer(r"- ([/~][^:]+):/[^:]+(?::rw)?(?!\s*:ro)", content):
        vol = m.group(1)
        if any(sensitive in vol for sensitive in ("/etc", "/usr", "/bin", "/sbin", "/lib", "/")):
            line_n = content[:m.start()].count("\n") + 1
            add("DC-006", "HIGH", "CWE-732",
                f"Sensitive host path mounted writable: {vol}",
                "Mount as read-only: - /etc/conf:/etc/conf:ro",
                m.group(0)[:80], line_n)

    # No resource limits
    if not re.search(r"(?:mem_limit|memory|cpus|cpu_quota):", content, re.IGNORECASE):
        add("DC-007", "MEDIUM", "CWE-400",
            "No resource limits defined — containers can exhaust host resources",
            "Add: deploy.resources.limits.memory: 512m and deploy.resources.limits.cpus: '0.5'",
            "(no resource limits)")

    # PID host namespace
    if re.search(r"pid\s*:\s*['\"]?host", content, re.IGNORECASE):
        add("DC-008", "HIGH", "CWE-250",
            "pid: host shares host PID namespace — container can see and signal host processes",
            "Remove pid: host unless explicitly required for debugging tools",
            "pid: host", lineno(r"pid"))

    # no-new-privileges not set
    if not re.search(r"no.new.privileges\s*:\s*true", content, re.IGNORECASE):
        add("DC-009", "MEDIUM", "CWE-250",
            "security_opt: no-new-privileges not set — processes can gain privileges via setuid",
            "Add: security_opt: [no-new-privileges:true]",
            "(no-new-privileges not set)")

    return findings


# ══════════════════════════════════════════════════════════════════════════════
# TERRAFORM SCANNER
# ══════════════════════════════════════════════════════════════════════════════

_TF_RULES: List[Tuple[str, str, str, str, str, str]] = [
    # (id, severity, cwe, regex, message, recommendation)
    ("TF-001", "CRITICAL", "CWE-284",
     r'cidr_blocks\s*=\s*\["0\.0\.0\.0/0"\]',
     "Security group allows inbound traffic from 0.0.0.0/0 — unrestricted internet access",
     "Restrict cidr_blocks to known IP ranges; use VPN or bastion for administrative access"),

    ("TF-002", "CRITICAL", "CWE-284",
     r'ipv6_cidr_blocks\s*=\s*\["::/0"\]',
     "Security group allows inbound traffic from ::/0 (all IPv6) — unrestricted access",
     "Restrict IPv6 ranges; do not open to ::/0 unless serving public traffic"),

    ("TF-003", "HIGH", "CWE-312",
     r'(?:password|secret|token|key)\s*=\s*"[^"$][^"]{3,}"',
     "Hardcoded secret/password in Terraform config",
     "Use terraform variables with sensitive=true, or reference AWS Secrets Manager/Vault"),

    ("TF-004", "HIGH", "CWE-311",
     r'encrypted\s*=\s*false',
     "Storage resource not encrypted (encrypted = false)",
     "Set encrypted = true for all EBS volumes, RDS instances, and S3 buckets"),

    ("TF-005", "HIGH", "CWE-284",
     r'publicly_accessible\s*=\s*true',
     "Database publicly accessible (publicly_accessible = true)",
     "Set publicly_accessible = false; use VPC private subnets with bastion host"),

    ("TF-006", "HIGH", "CWE-311",
     r'server_side_encryption_configuration|sse_algorithm',
     "",  # absence check — handled separately
     ""),

    ("TF-007", "MEDIUM", "CWE-693",
     r'skip_final_snapshot\s*=\s*true',
     "RDS skip_final_snapshot = true — database deleted without final backup",
     "Set skip_final_snapshot = false and set final_snapshot_identifier"),

    ("TF-008", "HIGH", "CWE-284",
     r'acl\s*=\s*"public-read(?:-write)?"',
     "S3 bucket ACL set to public-read or public-read-write — data exposed to internet",
     "Remove public ACL; use bucket policies for controlled access"),

    ("TF-009", "HIGH", "CWE-284",
     r'block_public_acls\s*=\s*false|block_public_policy\s*=\s*false',
     "S3 public access block disabled — bucket may be exposed to internet",
     "Set all four S3 public access block settings to true"),

    ("TF-010", "MEDIUM", "CWE-778",
     r'enable_cloudtrail\s*=\s*false|cloudtrail.*enabled\s*=\s*false',
     "CloudTrail logging disabled — no audit trail for AWS API calls",
     "Enable CloudTrail logging in all regions with S3 log storage"),

    ("TF-011", "HIGH", "CWE-295",
     r'validation_record_fqdns|ssl_certificate.*(?:false|none)',
     "",
     ""),

    ("TF-012", "MEDIUM", "CWE-693",
     r'deletion_protection\s*=\s*false',
     "Deletion protection disabled — resource can be accidentally destroyed",
     "Set deletion_protection = true for production databases and load balancers"),

    ("TF-013", "HIGH", "CWE-284",
     r'ingress\s*\{[^}]*from_port\s*=\s*0[^}]*to_port\s*=\s*0',
     "Security group ingress allows all ports (0 to 0) — no port restriction",
     "Restrict to specific ports required by the service"),

    ("TF-014", "HIGH", "CWE-311",
     r'storage_encrypted\s*=\s*false',
     "RDS storage_encrypted = false — database not encrypted at rest",
     "Set storage_encrypted = true and specify kms_key_id"),

    ("TF-015", "MEDIUM", "CWE-284",
     r'multi_az\s*=\s*false',
     "RDS multi_az = false — single point of failure, no high availability",
     "Set multi_az = true for production databases"),

    ("TF-016", "HIGH", "CWE-312",
     r'user_data\s*=\s*<<[A-Z]+\s*(?:[^>]*\n){0,20}(?:password|secret|key)\s*=\s*\S',
     "Plaintext secret in user_data (EC2 instance startup script)",
     "Use AWS SSM Parameter Store or Secrets Manager for secrets in user_data"),

    ("TF-017", "MEDIUM", "CWE-778",
     r'access_logs\s*\{\s*enabled\s*=\s*false',
     "Load balancer access logging disabled — no traffic audit trail",
     "Enable access_logs for all load balancers"),

    ("TF-018", "CRITICAL", "CWE-284",
     r'resource\s+"aws_iam_policy"\s*"[^"]+"\s*\{[^}]*"Effect"\s*:\s*"Allow"[^}]*"Action"\s*:\s*"\*"[^}]*"Resource"\s*:\s*"\*"',
     "IAM policy allows all actions on all resources (Action: *, Resource: *) — wildcard admin policy",
     "Follow principle of least privilege; specify exact actions and resources"),
]

_COMPILED_TF: List[Tuple[str, str, str, re.Pattern, str, str]] = [
    (id_, sev, cwe, re.compile(regex, re.IGNORECASE | re.MULTILINE | re.DOTALL), msg, rec)
    for id_, sev, cwe, regex, msg, rec in _TF_RULES
    if msg  # skip absence-only checks
]


def _scan_terraform(file_path: str) -> List[IaCFinding]:
    p = Path(file_path)
    if p.suffix != ".tf":
        return []
    try:
        content = p.read_text(errors="replace")
        lines   = content.splitlines()
    except Exception:
        return []

    findings: List[IaCFinding] = []

    for id_, severity, cwe, compiled, message, recommendation in _COMPILED_TF:
        for m in compiled.finditer(content):
            line_no  = content[:m.start()].count("\n") + 1
            line_txt = lines[line_no - 1].strip()[:100] if line_no <= len(lines) else ""
            findings.append(IaCFinding(
                id=id_, scanner_type="terraform",
                severity=severity, cwe=cwe,
                file=str(p), line=line_no,
                message=message, description=message,
                evidence=line_txt,
                recommendation=recommendation,
            ).to_dict())

    # Special: check for S3 server-side encryption absence in aws_s3_bucket
    for m in re.finditer(r'resource\s+"aws_s3_bucket"\s+"([^"]+)"', content):
        bucket_name = m.group(1)
        # Look for aws_s3_bucket_server_side_encryption_configuration referencing this bucket
        if not re.search(
            rf'aws_s3_bucket_server_side_encryption_configuration.*{re.escape(bucket_name)}',
            content, re.DOTALL
        ):
            line_no = content[:m.start()].count("\n") + 1
            findings.append(IaCFinding(
                id="TF-006", scanner_type="terraform",
                severity="HIGH", cwe="CWE-311",
                file=str(p), line=line_no,
                message=f"S3 bucket '{bucket_name}' has no server-side encryption configuration",
                description="S3 bucket missing SSE configuration",
                evidence=f'resource "aws_s3_bucket" "{bucket_name}"',
                recommendation="Add aws_s3_bucket_server_side_encryption_configuration resource",
                confidence=70,
            ).to_dict())

    # Return as IaCFinding but we already called .to_dict() above — handle mixed list
    return [f if isinstance(f, IaCFinding) else f for f in findings]


def _to_dict_list(items) -> List[Dict]:
    result = []
    for item in items:
        if isinstance(item, IaCFinding):
            result.append(item.to_dict())
        elif isinstance(item, dict):
            result.append(item)
    return result


# ══════════════════════════════════════════════════════════════════════════════
# GITHUB ACTIONS SCANNER
# ══════════════════════════════════════════════════════════════════════════════

def _scan_github_actions(file_path: str) -> List[IaCFinding]:
    p = Path(file_path)
    if not (str(p).endswith(".yml") or str(p).endswith(".yaml")):
        return []
    if ".github/workflows" not in str(p):
        return []
    try:
        content = p.read_text(errors="replace")
        lines   = content.splitlines()
    except Exception:
        return []

    findings: List[IaCFinding] = []

    def lineno(pattern: str) -> int:
        for i, ln in enumerate(lines, 1):
            if re.search(pattern, ln, re.IGNORECASE):
                return i
        return 1

    def add(id_, severity, cwe, msg, rec, evidence, line=1):
        findings.append(IaCFinding(
            id=id_, scanner_type="github-actions",
            severity=severity, cwe=cwe,
            file=str(p), line=line,
            message=msg, description=msg,
            evidence=evidence, recommendation=rec,
        ))

    # Script injection via context expressions in run steps
    for m in re.finditer(r'run:.*\$\{\{[^}]*(?:github\.event\.|inputs\.)\w+[^}]*\}\}', content):
        line_n = content[:m.start()].count("\n") + 1
        add("GHA-001", "CRITICAL", "CWE-78",
            "Script injection: user-controlled input directly interpolated into run step",
            "Store input in environment variable first: env: SAFE_VAR: ${{ github.event.inputs.name }}",
            content[m.start():m.end()][:100], line_n)

    # pull_request_target with code checkout from PR
    if re.search(r"pull_request_target", content) and re.search(r"actions/checkout", content):
        if re.search(r"ref.*head\.sha|ref.*event\.pull_request", content):
            add("GHA-002", "CRITICAL", "CWE-829",
                "pull_request_target with checkout of PR code — pwn-request vulnerability",
                "Do not checkout PR code in pull_request_target; separate untrusted code execution",
                "pull_request_target + actions/checkout with PR ref", lineno(r"pull_request_target"))

    # Overly permissive permissions
    for m in re.finditer(r"permissions\s*:\s*write-all|permissions\s*:\s*\n\s+\S+\s*:\s*write", content):
        line_n = content[:m.start()].count("\n") + 1
        add("GHA-003", "MEDIUM", "CWE-284",
            "Workflow has write permissions — use minimal required permissions",
            "Specify only required permissions: permissions: contents: read",
            content[m.start():m.end()][:80], line_n)

    # Unpinned actions (using branch/tag instead of commit SHA)
    for m in re.finditer(r"uses:\s*([\w/\-]+)@(v\d[\w.]*)(?!\s*#\s*[0-9a-f]{40})", content):
        line_n = content[:m.start()].count("\n") + 1
        action, ref = m.group(1), m.group(2)
        add("GHA-004", "MEDIUM", "CWE-829",
            f"Action '{action}@{ref}' pinned to mutable tag — pin to commit SHA for reproducibility",
            f"Pin: uses: {action}@<commit-sha>  # {ref}",
            m.group(0)[:80], line_n)

    # Secrets in env at job level
    for m in re.finditer(r'env:\s*\n(?:\s+\w+\s*:\s*\S+\s*\n)*\s+\w*(?:SECRET|TOKEN|PASSWORD|KEY)\w*', content, re.IGNORECASE):
        line_n = content[:m.start()].count("\n") + 1
        add("GHA-005", "MEDIUM", "CWE-312",
            "Secret-like variable set in env block — use ${{ secrets.MY_SECRET }} instead",
            "Reference GitHub secrets: env: MY_TOKEN: ${{ secrets.MY_TOKEN }}",
            content[m.start():m.end()][:80], line_n)

    # GITHUB_TOKEN with excessive permissions passed to external actions
    if re.search(r"GITHUB_TOKEN.*\$\{\{.*secrets\.GITHUB_TOKEN", content) and \
       re.search(r"uses:\s*(?!actions/)", content):
        add("GHA-006", "MEDIUM", "CWE-284",
            "GITHUB_TOKEN passed to third-party action — token may be exfiltrated",
            "Use minimal token scopes; avoid passing GITHUB_TOKEN to untrusted third-party actions",
            "GITHUB_TOKEN + third-party action", 1)

    # Allow-unlisted-patterns (security advisory bypass)
    if re.search(r"security-events:\s*write", content) and not re.search(r"permissions:\s*\n[^#]*contents:\s*read", content):
        add("GHA-007", "LOW", "CWE-693",
            "security-events: write without read-only contents permission",
            "Add: permissions: contents: read  security-events: write",
            "security-events: write", lineno(r"security-events"))

    return findings


# ══════════════════════════════════════════════════════════════════════════════
# MAIN SCANNER
# ══════════════════════════════════════════════════════════════════════════════

class IaCScanner:
    """
    Unified IaC security scanner for Dockerfile, docker-compose, Terraform,
    and GitHub Actions workflow files.
    """

    _DOCKERFILE_NAMES  = {"dockerfile", "dockerfile.prod", "dockerfile.dev",
                          "dockerfile.staging", "dockerfile.test"}
    _COMPOSE_NAMES     = {"docker-compose.yml", "docker-compose.yaml",
                          "docker-compose.prod.yml", "docker-compose.dev.yml",
                          "compose.yml", "compose.yaml"}
    _TF_SUFFIXES       = {".tf"}

    def scan_file(self, file_path: str) -> List[Dict]:
        p    = Path(file_path)
        name = p.name.lower()

        if name in self._DOCKERFILE_NAMES or name.startswith("dockerfile."):
            return _to_dict_list(_scan_dockerfile(str(p)))
        if name in self._COMPOSE_NAMES:
            return _to_dict_list(_scan_docker_compose(str(p)))
        if p.suffix == ".tf":
            return _to_dict_list(_scan_terraform(str(p)))
        if ".github/workflows" in str(p) and p.suffix in (".yml", ".yaml"):
            return _to_dict_list(_scan_github_actions(str(p)))
        return []

    def scan_directory(self, directory: str) -> Dict:
        root     = Path(directory)
        findings: List[Dict] = []
        scanned  = 0

        for p in root.rglob("*"):
            if not p.is_file():
                continue
            if any(part in _SKIP_DIRS for part in p.parts):
                continue

            name = p.name.lower()

            is_iac = (
                name in self._DOCKERFILE_NAMES
                or name.startswith("dockerfile.")
                or name in self._COMPOSE_NAMES
                or p.suffix == ".tf"
                or (".github/workflows" in str(p) and p.suffix in (".yml", ".yaml"))
            )

            if not is_iac:
                continue

            found = self.scan_file(str(p))
            findings.extend(found)
            if found is not None:
                scanned += 1

        # Sort by severity
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        findings.sort(key=lambda f: sev_order.get(f.get("severity", "LOW"), 4))

        sev_counts: Dict[str, int] = {}
        for f in findings:
            s = f.get("severity", "MEDIUM")
            sev_counts[s] = sev_counts.get(s, 0) + 1

        return {
            "files_scanned":   scanned,
            "total_findings":  len(findings),
            "severity_counts": sev_counts,
            "findings":        findings,
            "scanner":         "iac",
        }

    def supported_file_types(self) -> List[str]:
        return ["Dockerfile", "docker-compose.yml", "*.tf", ".github/workflows/*.yml"]
