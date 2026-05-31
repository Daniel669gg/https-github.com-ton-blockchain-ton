"""
backend/scanners/infra_scanner.py — Infrastructure Security Scanner

Scans Dockerfiles, GitHub Actions workflows, and Helm/Kubernetes manifests
for security misconfigurations using regex + PyYAML where applicable.

Graceful fallback to pure regex parsing when PyYAML is unavailable.
"""
from __future__ import annotations

import fnmatch
import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from backend.core.confidence import Finding

logger = logging.getLogger("tythanai.infra")

# ─────────────────────────────────────────────────────────────────────────────
# Optional PyYAML import
# ─────────────────────────────────────────────────────────────────────────────

try:
    import yaml as _yaml  # type: ignore
    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False
    logger.info("PyYAML not installed; YAML checks will use regex fallback")

# ─────────────────────────────────────────────────────────────────────────────
# Severity helpers
# ─────────────────────────────────────────────────────────────────────────────

_SEV_ORDER: Dict[str, int] = {
    "CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0
}

def _downgrade_severity(severity: str) -> str:
    mapping = {"CRITICAL": "HIGH", "HIGH": "MEDIUM", "MEDIUM": "LOW", "LOW": "INFO", "INFO": "INFO"}
    return mapping.get(severity, severity)


# ─────────────────────────────────────────────────────────────────────────────
# False-positive filters
# ─────────────────────────────────────────────────────────────────────────────

_TEMPLATE_GLOBS = ["*example*", "*sample*", "*template*", "*test*"]

_COMMENT_RE = re.compile(r"^\s*#")


def _is_template_path(path: str) -> bool:
    basename = os.path.basename(path).lower()
    return any(fnmatch.fnmatch(basename, g) for g in _TEMPLATE_GLOBS)


def _is_comment_line(line: str) -> bool:
    return bool(_COMMENT_RE.match(line))


def _apply_template_penalty(severity: str, path: str) -> str:
    if _is_template_path(path):
        return _downgrade_severity(severity)
    return severity


def _make_finding(
    rule_id: str,
    filepath: str,
    line: int,
    severity: str,
    cwe_id: str,
    description: str,
    recommendation: str,
    confidence: float = 0.85,
    context_lines: Optional[List[str]] = None,
) -> Finding:
    adjusted_sev = _apply_template_penalty(severity, filepath)
    return Finding(
        rule_id=rule_id,
        file=filepath,
        line=line,
        severity=adjusted_sev,
        confidence=confidence,
        cwe_id=cwe_id,
        description=description,
        recommendation=recommendation,
        sources=[filepath],
        context_lines=context_lines or [],
    )


def _context(lines: List[str], lineno: int, radius: int = 2) -> List[str]:
    start = max(0, lineno - radius - 1)
    end = min(len(lines), lineno + radius)
    return lines[start:end]


# ─────────────────────────────────────────────────────────────────────────────
# Dockerfile scanner
# ─────────────────────────────────────────────────────────────────────────────

# Patterns for secrets in ENV instructions
_DOCKER_ENV_SECRET_RE = re.compile(
    r"""(?i)^ENV\s+(?P<key>[A-Z_][A-Z0-9_]*)[\s=]+(?P<val>[^\s$][^\s]*)""",
    re.MULTILINE,
)
_SECRET_KEY_RE = re.compile(r"(?i)(secret|password|passwd|key|token|api)", re.IGNORECASE)

# Sensitive volume mounts
_SENSITIVE_MOUNTS = {
    "/etc/passwd", "/var/run/docker.sock", "/etc/shadow", "/proc",
    "/etc/ssl", "/root", "/etc/ssh",
}

# Pipe-to-shell patterns
_PIPE_SHELL_RE = re.compile(
    r"""(?i)(wget\s+[^\n]*\|\s*(?:ba)?sh\b|\bcurl\b[^\n]*\|\s*(?:ba)?sh\b|--no-check-certificate)"""
)

# FROM with latest or no digest
_FROM_RE = re.compile(r"""(?i)^FROM\s+(?P<image>[^\s#]+)""")
_PINNED_DIGEST_RE = re.compile(r"""@sha256:[a-f0-9]{64}""")


class DockerfileScanner:
    """Scans Dockerfiles for security misconfigurations."""

    def scan(self, filepath: str) -> List[Finding]:
        try:
            content = Path(filepath).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.warning("Cannot read %s: %s", filepath, exc)
            return []

        lines = content.splitlines()
        findings: List[Finding] = []
        has_user_instruction = False
        user_root = False

        for i, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()

            if _is_comment_line(line):
                continue

            # ── USER instruction ──────────────────────────────────────────────
            if re.match(r"(?i)^USER\s+", line):
                has_user_instruction = True
                if re.match(r"(?i)^USER\s+(root|0)\s*$", line):
                    user_root = True
                    findings.append(_make_finding(
                        rule_id="DOCKER-USER-ROOT",
                        filepath=filepath,
                        line=i,
                        severity="HIGH",
                        cwe_id="CWE-250",
                        description="Container explicitly runs as root (USER root).",
                        recommendation="Set a non-root USER in the Dockerfile: 'USER nobody' or create a dedicated user.",
                        context_lines=_context(lines, i),
                    ))

            # ── privileged: true ─────────────────────────────────────────────
            if re.search(r"(?i)privileged\s*:\s*true", line):
                findings.append(_make_finding(
                    rule_id="DOCKER-PRIVILEGED",
                    filepath=filepath,
                    line=i,
                    severity="CRITICAL",
                    cwe_id="CWE-250",
                    description="Container runs in privileged mode, granting full host access.",
                    recommendation="Remove 'privileged: true'. Use specific capabilities with 'cap_add' instead.",
                    confidence=0.95,
                    context_lines=_context(lines, i),
                ))

            # ── Sensitive volume mounts ───────────────────────────────────────
            if re.match(r"(?i)^(VOLUME|volume)\s+", line) or re.search(r"(?i)\bvolumes?\s*:", line):
                for mount in _SENSITIVE_MOUNTS:
                    if mount in line:
                        findings.append(_make_finding(
                            rule_id="DOCKER-SENSITIVE-MOUNT",
                            filepath=filepath,
                            line=i,
                            severity="HIGH",
                            cwe_id="CWE-732",
                            description=f"Sensitive host path '{mount}' mounted into container.",
                            recommendation=f"Avoid mounting '{mount}'. Use named volumes or Docker secrets.",
                            context_lines=_context(lines, i),
                        ))

            # ── FROM: unpinned or :latest ──────────────────────────────────
            m = _FROM_RE.match(line)
            if m:
                image = m.group("image")
                if "as " in image.lower():
                    image = image.lower().split(" as ")[0]
                if not _PINNED_DIGEST_RE.search(image):
                    tag = image.split(":")[-1] if ":" in image else "latest"
                    if tag.lower() == "latest" or ":" not in image:
                        findings.append(_make_finding(
                            rule_id="DOCKER-UNPINNED-IMAGE",
                            filepath=filepath,
                            line=i,
                            severity="MEDIUM",
                            cwe_id="CWE-1104",
                            description=f"Base image '{image}' uses ':latest' or has no version pin.",
                            recommendation="Pin the base image to a specific SHA digest for reproducible builds.",
                            confidence=0.80,
                            context_lines=_context(lines, i),
                        ))

            # ── Secrets in ENV ────────────────────────────────────────────────
            env_m = _DOCKER_ENV_SECRET_RE.match(raw_line)
            if env_m:
                key = env_m.group("key")
                val = env_m.group("val")
                # Only flag if key name suggests a secret AND value is a literal
                if _SECRET_KEY_RE.search(key):
                    # Skip if value looks like a variable reference or placeholder
                    if not re.match(r"^(\$\{|\$[A-Z_])", val) and val not in ("", '""', "''"):
                        findings.append(_make_finding(
                            rule_id="DOCKER-ENV-SECRET",
                            filepath=filepath,
                            line=i,
                            severity="HIGH",
                            cwe_id="CWE-798",
                            description=f"Secret-like value baked into ENV instruction: {key}.",
                            recommendation="Use Docker secrets (docker secret) or --build-arg at runtime instead of ENV.",
                            context_lines=_context(lines, i),
                        ))

            # ── Pipe-to-shell patterns ────────────────────────────────────────
            if _PIPE_SHELL_RE.search(line):
                findings.append(_make_finding(
                    rule_id="DOCKER-PIPE-SHELL",
                    filepath=filepath,
                    line=i,
                    severity="CRITICAL",
                    cwe_id="CWE-78",
                    description="Dangerous shell pipe pattern: curl/wget piped directly to shell or --no-check-certificate.",
                    recommendation="Download scripts, verify signatures/hashes, then execute. Never pipe remote code directly to shell.",
                    confidence=0.95,
                    context_lines=_context(lines, i),
                ))

        # ── No USER instruction at all ────────────────────────────────────────
        if not has_user_instruction:
            findings.append(_make_finding(
                rule_id="DOCKER-NO-USER",
                filepath=filepath,
                line=0,
                severity="HIGH",
                cwe_id="CWE-250",
                description="Dockerfile does not specify a USER instruction; container defaults to root.",
                recommendation="Add 'USER nonroot' (or a named non-root user) before the final CMD/ENTRYPOINT.",
                confidence=0.85,
            ))

        return findings


# ─────────────────────────────────────────────────────────────────────────────
# GitHub Actions scanner
# ─────────────────────────────────────────────────────────────────────────────

_GH_UNPINNED_ACTION_RE = re.compile(
    r"""uses:\s+(?P<action>[^\s@]+)@(?P<ref>[^\s#]+)"""
)
_SHA_REF_RE = re.compile(r"""[a-f0-9]{40}""")

# Script injection patterns
_GH_INJECT_SOURCES = re.compile(
    r"""\$\{\{\s*github\.event\.(issue\.(body|title)|pull_request\.(title|body)|comment\.body|review\.body|[a-zA-Z_]+\.body)\s*\}\}"""
)

# Hardcoded secret in env (not referencing ${{ secrets.X }})
_GH_HARDCODED_ENV_RE = re.compile(
    r"""(?i)(?P<key>[A-Z_][A-Z0-9_]*(?:SECRET|PASSWORD|TOKEN|KEY|API)[A-Z0-9_]*|(?:SECRET|PASSWORD|TOKEN|KEY|API)[A-Z0-9_]*)\s*:\s*(?P<val>[^\$\n{][^\n]*)"""
)

# GITHUB_TOKEN write permissions
_GH_TOKEN_WRITE_RE = re.compile(
    r"""(?i)permissions\s*:[\s\S]{0,200}?(?:write-all|contents\s*:\s*write|pull-requests\s*:\s*write)"""
)


class GitHubActionsScanner:
    """Scans GitHub Actions workflow files for security issues."""

    def scan(self, filepath: str) -> List[Finding]:
        try:
            content = Path(filepath).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.warning("Cannot read %s: %s", filepath, exc)
            return []

        lines = content.splitlines()
        findings: List[Finding] = []
        in_run_block = False
        run_block_lines: List[Tuple[int, str]] = []

        for i, raw_line in enumerate(lines, start=1):
            line = raw_line

            if _is_comment_line(line):
                continue

            # ── Track 'run:' blocks for injection checks ─────────────────────
            if re.match(r"\s+run:\s*\|?\s*$", line) or re.match(r"\s+run:\s+\S", line):
                in_run_block = True
                run_block_lines = [(i, line)]
                # Check if the run: line itself contains injection (single-line form)
                if _GH_INJECT_SOURCES.search(line):
                    findings.append(_make_finding(
                        rule_id="GHAACTIONS-SCRIPT-INJECTION",
                        filepath=filepath,
                        line=i,
                        severity="HIGH",
                        cwe_id="CWE-78",
                        description=f"GitHub Actions script injection via untrusted event data: {line.strip()[:80]}",
                        recommendation="Never interpolate github.event.* directly in 'run:' scripts. Use an intermediate env var.",
                        context_lines=_context(lines, i),
                    ))
                continue

            if in_run_block:
                # A new key at the same or lower indent level ends the run block
                if re.match(r"\s+\w[^:]*:", line) and not re.match(r"\s{8,}", line):
                    # Check accumulated run block for injection
                    block_text = "\n".join(l for _, l in run_block_lines)
                    first_line = run_block_lines[0][0] if run_block_lines else i
                    inj_matches = _GH_INJECT_SOURCES.findall(block_text)
                    if inj_matches:
                        findings.append(_make_finding(
                            rule_id="GHAACTIONS-SCRIPT-INJECTION",
                            filepath=filepath,
                            line=first_line,
                            severity="HIGH",
                            cwe_id="CWE-78",
                            description=f"GitHub Actions script injection via untrusted event data in 'run:' step: {inj_matches[0]}",
                            recommendation="Never interpolate github.event.* directly in 'run:' scripts. Use an intermediate env var set with `env:` and then reference $VAR_NAME.",
                            context_lines=_context(lines, first_line),
                        ))
                    in_run_block = False
                    run_block_lines = []
                else:
                    run_block_lines.append((i, line))
                    # Also check inline
                    if _GH_INJECT_SOURCES.search(line):
                        findings.append(_make_finding(
                            rule_id="GHAACTIONS-SCRIPT-INJECTION",
                            filepath=filepath,
                            line=i,
                            severity="HIGH",
                            cwe_id="CWE-78",
                            description=f"GitHub Actions script injection via untrusted event data: {line.strip()[:80]}",
                            recommendation="Never interpolate github.event.* directly in 'run:' scripts. Use an intermediate env var.",
                            context_lines=_context(lines, i),
                        ))
                    continue

            # ── Unpinned action (not SHA hash) ────────────────────────────────
            m = _GH_UNPINNED_ACTION_RE.search(line)
            if m:
                ref = m.group("ref")
                if not _SHA_REF_RE.match(ref):
                    findings.append(_make_finding(
                        rule_id="GHAACTIONS-UNPINNED-ACTION",
                        filepath=filepath,
                        line=i,
                        severity="MEDIUM",
                        cwe_id="CWE-1104",
                        description=f"GitHub Action not pinned to SHA hash: uses {m.group('action')}@{ref}",
                        recommendation="Pin actions to a full SHA commit hash instead of a tag (e.g., uses: actions/checkout@a1b2c3d...).",
                        confidence=0.80,
                        context_lines=_context(lines, i),
                    ))

            # ── Hardcoded secrets in env: ─────────────────────────────────────
            env_m = _GH_HARDCODED_ENV_RE.search(line)
            if env_m:
                val = env_m.group("val").strip()
                # Skip if value is a ${{ secrets.X }} reference, env var ref, or empty
                if not re.match(r"""^\$\{\{""", val) and not re.match(r"""^["']?\$""", val) and val:
                    # Skip obvious non-secret values
                    if len(val) > 3 and not re.match(r"""^(true|false|none|null|0|1|\d+)$""", val, re.IGNORECASE):
                        findings.append(_make_finding(
                            rule_id="GHAACTIONS-HARDCODED-SECRET",
                            filepath=filepath,
                            line=i,
                            severity="CRITICAL",
                            cwe_id="CWE-798",
                            description=f"Hardcoded secret in GitHub Actions env: {env_m.group('key')}",
                            recommendation="Use ${{ secrets.MY_SECRET }} to reference repository/organization secrets instead of hardcoding values.",
                            context_lines=_context(lines, i),
                        ))

            # ── Inline script injection check ────────────────────────────────
            if _GH_INJECT_SOURCES.search(line) and "run:" in line:
                findings.append(_make_finding(
                    rule_id="GHAACTIONS-SCRIPT-INJECTION",
                    filepath=filepath,
                    line=i,
                    severity="HIGH",
                    cwe_id="CWE-78",
                    description=f"GitHub Actions script injection via github.event.* in inline run step.",
                    recommendation="Use an intermediate env var: set `env: BODY: ${{ github.event.issue.body }}` then reference $BODY in the run step.",
                    context_lines=_context(lines, i),
                ))

        # ── Flush any remaining open run block at end of file ────────────────
        if in_run_block and run_block_lines:
            block_text = "\n".join(l for _, l in run_block_lines)
            first_line = run_block_lines[0][0]
            inj_matches = _GH_INJECT_SOURCES.findall(block_text)
            if inj_matches:
                findings.append(_make_finding(
                    rule_id="GHAACTIONS-SCRIPT-INJECTION",
                    filepath=filepath,
                    line=first_line,
                    severity="HIGH",
                    cwe_id="CWE-78",
                    description=f"GitHub Actions script injection via untrusted event data in 'run:' step: {inj_matches[0]}",
                    recommendation="Never interpolate github.event.* directly in 'run:' scripts. Use an intermediate env var set with `env:` and then reference $VAR_NAME.",
                    context_lines=_context(lines, first_line),
                ))

        # ── GITHUB_TOKEN with write perms (whole-file check) ──────────────────
        if _GH_TOKEN_WRITE_RE.search(content):
            # Find the line number
            for i, line in enumerate(lines, start=1):
                if re.search(r"(?i)permissions\s*:", line):
                    findings.append(_make_finding(
                        rule_id="GHAACTIONS-TOKEN-WRITE",
                        filepath=filepath,
                        line=i,
                        severity="MEDIUM",
                        cwe_id="CWE-250",
                        description="GITHUB_TOKEN has write permissions; ensure environment protection rules are set.",
                        recommendation="Use the principle of least privilege: only grant write permissions for specific needs and use environment protection rules.",
                        confidence=0.75,
                        context_lines=_context(lines, i),
                    ))
                    break

        return findings


# ─────────────────────────────────────────────────────────────────────────────
# Helm / Kubernetes scanner
# ─────────────────────────────────────────────────────────────────────────────

_K8S_KINDS_WITH_PODS = {
    "Pod", "Deployment", "StatefulSet", "DaemonSet", "Job",
    "CronJob", "ReplicaSet",
}

_RBAC_KINDS = {"ClusterRole", "Role"}


def _load_yaml_safe(content: str) -> Optional[Any]:
    """Parse YAML safely, return None on error."""
    if not _YAML_AVAILABLE:
        return None
    try:
        return _yaml.safe_load(content)
    except Exception as exc:
        logger.debug("YAML parse error: %s", exc)
        return None


def _flatten_containers(spec: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract all container specs from a pod spec."""
    containers: List[Dict[str, Any]] = []
    if not isinstance(spec, dict):
        return containers
    containers.extend(spec.get("containers", []) or [])
    containers.extend(spec.get("initContainers", []) or [])
    containers.extend(spec.get("ephemeralContainers", []) or [])
    return containers


def _get_pod_spec(doc: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Navigate to the pod spec from various resource kinds."""
    kind = doc.get("kind", "")
    if kind == "Pod":
        return doc.get("spec")
    elif kind in {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet"}:
        return (
            doc.get("spec", {})
               .get("template", {})
               .get("spec")
        )
    elif kind == "Job":
        return (
            doc.get("spec", {})
               .get("template", {})
               .get("spec")
        )
    elif kind == "CronJob":
        return (
            doc.get("spec", {})
               .get("jobTemplate", {})
               .get("spec", {})
               .get("template", {})
               .get("spec")
        )
    return None


class KubernetesScanner:
    """Scans Kubernetes/Helm YAML manifests for security misconfigurations."""

    def scan(self, filepath: str) -> List[Finding]:
        try:
            content = Path(filepath).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.warning("Cannot read %s: %s", filepath, exc)
            return []

        lines = content.splitlines()

        # Must have a 'kind:' field to be a Kubernetes manifest
        if not re.search(r"^\s*kind\s*:", content, re.MULTILINE):
            return []

        findings: List[Finding] = []

        # ── YAML parsing path ─────────────────────────────────────────────────
        if _YAML_AVAILABLE:
            try:
                for doc in _yaml.safe_load_all(content):
                    if not isinstance(doc, dict):
                        continue
                    findings.extend(self._check_doc(doc, filepath, lines))
            except Exception as exc:
                logger.debug("YAML multi-doc parse error in %s: %s", filepath, exc)
                # Fall through to regex path
                findings.extend(self._regex_scan(content, filepath, lines))
        else:
            findings.extend(self._regex_scan(content, filepath, lines))

        return findings

    def _check_doc(
        self, doc: Dict[str, Any], filepath: str, lines: List[str]
    ) -> List[Finding]:
        findings: List[Finding] = []
        kind = doc.get("kind", "")

        # ── RBAC wildcard verbs ───────────────────────────────────────────────
        if kind in _RBAC_KINDS:
            for rule in (doc.get("rules") or []):
                verbs = rule.get("verbs", [])
                if "*" in verbs:
                    lineno = self._find_line(lines, "verbs")
                    findings.append(_make_finding(
                        rule_id="K8S-RBAC-WILDCARD",
                        filepath=filepath,
                        line=lineno,
                        severity="HIGH",
                        cwe_id="CWE-269",
                        description=f"RBAC {kind} grants wildcard verbs ('*'), providing excessive permissions.",
                        recommendation="Replace wildcard verbs with explicit verbs (get, list, watch, create, etc.).",
                        context_lines=_context(lines, lineno),
                    ))

        # ── Pod-bearing resources ─────────────────────────────────────────────
        pod_spec = _get_pod_spec(doc)
        if pod_spec is None:
            return findings

        containers = _flatten_containers(pod_spec)

        # ── hostNetwork / hostPID ─────────────────────────────────────────────
        if pod_spec.get("hostNetwork") is True:
            lineno = self._find_line(lines, "hostNetwork")
            findings.append(_make_finding(
                rule_id="K8S-HOST-NETWORK",
                filepath=filepath,
                line=lineno,
                severity="HIGH",
                cwe_id="CWE-668",
                description="Pod uses hostNetwork: true, sharing the host's network namespace.",
                recommendation="Set hostNetwork to false. Use Kubernetes Network Policies to control traffic.",
                context_lines=_context(lines, lineno),
            ))

        if pod_spec.get("hostPID") is True:
            lineno = self._find_line(lines, "hostPID")
            findings.append(_make_finding(
                rule_id="K8S-HOST-PID",
                filepath=filepath,
                line=lineno,
                severity="HIGH",
                cwe_id="CWE-668",
                description="Pod uses hostPID: true, sharing the host's PID namespace.",
                recommendation="Set hostPID to false unless absolutely necessary.",
                context_lines=_context(lines, lineno),
            ))

        # ── Pod-level securityContext missing ────────────────────────────────
        if not pod_spec.get("securityContext"):
            findings.append(_make_finding(
                rule_id="K8S-NO-POD-SECURITY-CONTEXT",
                filepath=filepath,
                line=self._find_line(lines, "spec"),
                severity="MEDIUM",
                cwe_id="CWE-732",
                description=f"Pod spec in '{doc.get('kind', 'resource')}' has no securityContext set.",
                recommendation="Add a securityContext with runAsNonRoot: true, readOnlyRootFilesystem: true, etc.",
                confidence=0.80,
            ))

        # ── Per-container checks ─────────────────────────────────────────────
        for container in containers:
            if not isinstance(container, dict):
                continue
            cname = container.get("name", "<unnamed>")
            sc = container.get("securityContext") or {}

            # No container securityContext
            if not sc:
                lineno = self._find_line(lines, cname)
                findings.append(_make_finding(
                    rule_id="K8S-NO-CONTAINER-SECURITY-CONTEXT",
                    filepath=filepath,
                    line=lineno,
                    severity="MEDIUM",
                    cwe_id="CWE-732",
                    description=f"Container '{cname}' has no securityContext.",
                    recommendation="Add securityContext with allowPrivilegeEscalation: false, readOnlyRootFilesystem: true.",
                    confidence=0.78,
                    context_lines=_context(lines, lineno),
                ))

            # privileged: true in container securityContext
            if sc.get("privileged") is True:
                lineno = self._find_line(lines, "privileged")
                findings.append(_make_finding(
                    rule_id="K8S-PRIVILEGED-CONTAINER",
                    filepath=filepath,
                    line=lineno,
                    severity="CRITICAL",
                    cwe_id="CWE-250",
                    description=f"Container '{cname}' runs in privileged mode.",
                    recommendation="Remove privileged: true. Use specific Linux capabilities with capabilities.add instead.",
                    confidence=0.97,
                    context_lines=_context(lines, lineno),
                ))

            # runAsUser: 0
            if sc.get("runAsUser") == 0:
                lineno = self._find_line(lines, "runAsUser")
                findings.append(_make_finding(
                    rule_id="K8S-RUN-AS-ROOT",
                    filepath=filepath,
                    line=lineno,
                    severity="HIGH",
                    cwe_id="CWE-250",
                    description=f"Container '{cname}' explicitly runs as UID 0 (root).",
                    recommendation="Set runAsUser to a non-zero UID and set runAsNonRoot: true.",
                    context_lines=_context(lines, lineno),
                ))

            # No resource limits
            resources = container.get("resources") or {}
            limits = resources.get("limits")
            if not limits:
                lineno = self._find_line(lines, cname)
                findings.append(_make_finding(
                    rule_id="K8S-NO-RESOURCE-LIMITS",
                    filepath=filepath,
                    line=lineno,
                    severity="LOW",
                    cwe_id="CWE-400",
                    description=f"Container '{cname}' has no resource limits (CPU/memory).",
                    recommendation="Set resources.limits.cpu and resources.limits.memory to prevent resource exhaustion.",
                    confidence=0.85,
                    context_lines=_context(lines, lineno),
                ))

        return findings

    def _regex_scan(self, content: str, filepath: str, lines: List[str]) -> List[Finding]:
        """Regex-only fallback scan when PyYAML is unavailable."""
        findings: List[Finding] = []

        # privileged: true
        for i, line in enumerate(lines, start=1):
            if _is_comment_line(line):
                continue
            if re.search(r"privileged\s*:\s*true", line):
                findings.append(_make_finding(
                    rule_id="K8S-PRIVILEGED-CONTAINER",
                    filepath=filepath,
                    line=i,
                    severity="CRITICAL",
                    cwe_id="CWE-250",
                    description="Container runs in privileged mode.",
                    recommendation="Remove privileged: true.",
                    context_lines=_context(lines, i),
                ))
            if re.search(r"hostNetwork\s*:\s*true", line):
                findings.append(_make_finding(
                    rule_id="K8S-HOST-NETWORK",
                    filepath=filepath,
                    line=i,
                    severity="HIGH",
                    cwe_id="CWE-668",
                    description="Pod uses hostNetwork: true.",
                    recommendation="Set hostNetwork to false.",
                    context_lines=_context(lines, i),
                ))
            if re.search(r"hostPID\s*:\s*true", line):
                findings.append(_make_finding(
                    rule_id="K8S-HOST-PID",
                    filepath=filepath,
                    line=i,
                    severity="HIGH",
                    cwe_id="CWE-668",
                    description="Pod uses hostPID: true.",
                    recommendation="Set hostPID to false.",
                    context_lines=_context(lines, i),
                ))
            if re.search(r"runAsUser\s*:\s*0", line):
                findings.append(_make_finding(
                    rule_id="K8S-RUN-AS-ROOT",
                    filepath=filepath,
                    line=i,
                    severity="HIGH",
                    cwe_id="CWE-250",
                    description="Container explicitly runs as UID 0 (root).",
                    recommendation="Set runAsUser to a non-zero UID.",
                    context_lines=_context(lines, i),
                ))
            # RBAC wildcard
            if re.search(r"""verbs\s*:\s*(?:\[["']?\*["']?\]|- ["']?\*["']?)""", line):
                findings.append(_make_finding(
                    rule_id="K8S-RBAC-WILDCARD",
                    filepath=filepath,
                    line=i,
                    severity="HIGH",
                    cwe_id="CWE-269",
                    description="RBAC grants wildcard verbs ('*').",
                    recommendation="Replace wildcard verbs with specific permissions.",
                    context_lines=_context(lines, i),
                ))

        return findings

    @staticmethod
    def _find_line(lines: List[str], key: str, start: int = 0) -> int:
        """Find the first line number (1-indexed) containing `key`."""
        for i, line in enumerate(lines[start:], start=start + 1):
            if key in line:
                return i
        return 1


# ─────────────────────────────────────────────────────────────────────────────
# Unified infrastructure scanner
# ─────────────────────────────────────────────────────────────────────────────

_SKIP_DIRS: set = {
    ".git", "__pycache__", ".venv", "venv", "node_modules",
    ".mypy_cache", ".pytest_cache", "dist", "build",
}


class InfraScanner:
    """
    Unified infrastructure security scanner.

    Detects issues in:
    - Dockerfiles
    - GitHub Actions workflow YAML files
    - Helm/Kubernetes YAML manifests

    Methods:
        scan_file(path)       → scan a single file
        scan_directory(path)  → scan all infra files in a directory tree
    """

    def __init__(self) -> None:
        self._docker = DockerfileScanner()
        self._gha = GitHubActionsScanner()
        self._k8s = KubernetesScanner()

    def scan_file(self, path: str) -> List[Finding]:
        """Scan a single file, auto-detecting its type."""
        basename = os.path.basename(path).lower()
        if basename.startswith("dockerfile"):
            return self._docker.scan(path)

        if ".github/workflows" in path.replace("\\", "/") and path.endswith((".yml", ".yaml")):
            return self._gha.scan(path)

        if path.endswith((".yml", ".yaml")):
            # Try Kubernetes first (has 'kind:' check), then GitHub Actions
            k8s_findings = self._k8s.scan(path)
            if k8s_findings:
                return k8s_findings
            # If no k8s findings, try GHA (if it has 'on:' or 'jobs:' keys)
            try:
                content = Path(path).read_text(encoding="utf-8", errors="replace")
                if re.search(r"^\s*(?:on|jobs)\s*:", content, re.MULTILINE):
                    return self._gha.scan(path)
            except OSError:
                pass
            # Still return k8s scan result (may be empty)
            return k8s_findings

        return []

    def scan_directory(self, path: str) -> List[Finding]:
        """Scan all infrastructure files in a directory tree."""
        findings: List[Finding] = []
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
            for fname in files:
                fpath = os.path.join(root, fname)
                findings.extend(self.scan_file(fpath))
        return findings
