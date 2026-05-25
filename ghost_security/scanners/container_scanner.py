"""
Ghost Security — Container Image Security Scanner

Scans Docker container images for OS-level CVEs and misconfigurations.
Strategy:
  1. If Trivy is installed → runs `trivy image --format json` (most accurate)
  2. If Grype is installed → runs `grype <image> -o json`
  3. Fallback → static analysis of Dockerfile base images + known vulnerable tags

Usage:
    from scanners.container_scanner import ContainerScanner
    scanner  = ContainerScanner()
    findings = scanner.scan_image("nginx:1.21.0")
    findings = scanner.scan_dockerfile("/path/to/Dockerfile")
    result   = scanner.scan_directory("/path/to/project")   # finds all Dockerfiles
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple

_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv"}

# ── Known vulnerable base image tags (curated, updated quarterly) ─────────────
# Format: "image:tag" → [(CVE, severity, description)]
_KNOWN_VULN_IMAGES: Dict[str, List[Tuple[str, str, str]]] = {
    "ubuntu:18.04": [
        ("CVE-2023-0464", "HIGH", "OpenSSL certificate chain validation flaw"),
        ("CVE-2022-3602", "CRITICAL", "OpenSSL X.509 buffer overflow"),
    ],
    "ubuntu:20.04": [
        ("CVE-2023-0464", "HIGH", "OpenSSL certificate chain validation flaw"),
    ],
    "debian:10": [
        ("CVE-2023-0464", "HIGH", "OpenSSL 1.1.1 chain verification flaw"),
        ("CVE-2023-1255", "MEDIUM", "AES-XTS cipher issue in OpenSSL"),
    ],
    "debian:9": [
        ("CVE-2021-33910", "HIGH", "systemd stack exhaustion via path parsing"),
        ("CVE-2022-3602", "CRITICAL", "OpenSSL X.509 buffer overflow"),
    ],
    "node:14": [
        ("CVE-2023-30581", "HIGH", "Node.js mainModule.__proto__ bypass"),
        ("CVE-2023-30590", "HIGH", "DiffieHellman key generation weakness"),
        ("CVE-2023-32002", "CRITICAL", "Node.js policy mechanism bypass"),
    ],
    "node:16": [
        ("CVE-2023-30581", "HIGH", "Node.js mainModule.__proto__ bypass"),
        ("CVE-2023-38552", "MEDIUM", "Node.js integrity check bypass"),
    ],
    "node:14-alpine": [
        ("CVE-2023-30581", "HIGH", "Node.js mainModule.__proto__ bypass"),
    ],
    "python:3.8": [
        ("CVE-2023-24329", "HIGH", "urllib: blocklist bypass via blank scheme"),
        ("CVE-2022-48566", "MEDIUM", "Timing attack in hmac module"),
    ],
    "python:3.8-slim": [
        ("CVE-2023-24329", "HIGH", "urllib: blocklist bypass via blank scheme"),
    ],
    "python:3.9": [
        ("CVE-2023-24329", "HIGH", "urllib: blocklist bypass via blank scheme"),
    ],
    "nginx:1.20.0": [
        ("CVE-2021-23017", "HIGH", "nginx: off-by-one in resolver"),
    ],
    "nginx:1.20.1": [
        ("CVE-2021-23017", "HIGH", "nginx: off-by-one in resolver"),
    ],
    "nginx:1.21.0": [
        ("CVE-2021-23017", "HIGH", "nginx: off-by-one in resolver"),
    ],
    "alpine:3.15": [
        ("CVE-2022-28391", "HIGH", "BusyBox: heap use-after-free in awk"),
    ],
    "alpine:3.14": [
        ("CVE-2022-28391", "HIGH", "BusyBox: heap use-after-free in awk"),
        ("CVE-2021-42374", "MEDIUM", "BusyBox: out-of-bounds read in unlzma"),
    ],
    "openjdk:11": [
        ("CVE-2023-21930", "HIGH", "Java: JSSE TLS certificate parsing flaw"),
        ("CVE-2023-21937", "MEDIUM", "Java: serialization deserialization issue"),
    ],
    "openjdk:8": [
        ("CVE-2023-21930", "HIGH", "Java: JSSE TLS certificate parsing flaw"),
        ("CVE-2022-21248", "MEDIUM", "Java: serialization flaw in Serializable"),
    ],
    "redis:6.2.0": [
        ("CVE-2022-0543", "CRITICAL", "Redis Lua sandbox escape (Debian builds)"),
    ],
    "redis:6.0.0": [
        ("CVE-2022-0543", "CRITICAL", "Redis Lua sandbox escape"),
        ("CVE-2021-32625", "HIGH", "Redis integer overflow in STRALGO command"),
    ],
    "mysql:5.7": [
        ("CVE-2023-21980", "HIGH", "MySQL client buffer overflow"),
        ("CVE-2022-21592", "MEDIUM", "MySQL Server replication issue"),
    ],
    "postgres:13": [
        ("CVE-2023-2454", "HIGH", "PostgreSQL CREATE SCHEMA allows privilege escalation"),
    ],
    "postgres:12": [
        ("CVE-2023-2454", "HIGH", "PostgreSQL CREATE SCHEMA allows privilege escalation"),
        ("CVE-2022-1552", "HIGH", "PostgreSQL security-restricted operations bypass"),
    ],
}

_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _trivy_available() -> bool:
    try:
        r = subprocess.run(["trivy", "--version"], capture_output=True, timeout=5)
        return r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _grype_available() -> bool:
    try:
        r = subprocess.run(["grype", "version"], capture_output=True, timeout=5)
        return r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _run_trivy(image: str, timeout: int = 120) -> List[Dict]:
    cmd = ["trivy", "image", "--format", "json", "--quiet", image]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        data   = json.loads(result.stdout)
    except Exception:
        return []

    findings: List[Dict] = []
    for target in data.get("Results", []):
        for vuln in target.get("Vulnerabilities") or []:
            sev = vuln.get("Severity", "MEDIUM").upper()
            cve = vuln.get("VulnerabilityID", "")
            pkg = vuln.get("PkgName", "")
            ver = vuln.get("InstalledVersion", "")
            fix = vuln.get("FixedVersion", "")
            findings.append({
                "type":           "CONTAINER_VULNERABILITY",
                "id":             cve,
                "cve":            cve,
                "severity":       sev,
                "file":           image,
                "line":           0,
                "message":        f"{pkg} {ver}: {vuln.get('Title', vuln.get('Description','')[:80])}",
                "description":    vuln.get("Description", "")[:300],
                "evidence":       f"{pkg}=={ver}",
                "recommendation": f"Upgrade {pkg} to {fix}" if fix else "Update base image",
                "cwe":            "CWE-1035",
                "category":       "Container Vulnerability",
                "source":         "trivy",
                "scanner":        "container",
                "package":        pkg,
                "installed_version": ver,
                "fixed_in":       fix,
                "confidence":     90,
            })
    return findings


def _run_grype(image: str, timeout: int = 120) -> List[Dict]:
    cmd = ["grype", image, "-o", "json", "--quiet"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        data   = json.loads(result.stdout)
    except Exception:
        return []

    findings: List[Dict] = []
    for match in data.get("matches", []):
        vuln = match.get("vulnerability", {})
        art  = match.get("artifact", {})
        sev  = vuln.get("severity", "Medium").upper()
        cve  = vuln.get("id", "")
        pkg  = art.get("name", "")
        ver  = art.get("version", "")
        fixes = [f.get("versions", []) for f in vuln.get("fix", {}).get("versions", [])]
        fix   = fixes[0] if fixes else ""
        findings.append({
            "type":           "CONTAINER_VULNERABILITY",
            "id":             cve,
            "cve":            cve,
            "severity":       sev if sev in ("CRITICAL","HIGH","MEDIUM","LOW") else "MEDIUM",
            "file":           image,
            "line":           0,
            "message":        f"{pkg} {ver}: {vuln.get('description','')[:80]}",
            "description":    vuln.get("description", ""),
            "evidence":       f"{pkg}=={ver}",
            "recommendation": f"Upgrade {pkg} to {fix}" if fix else "Update base image",
            "cwe":            "CWE-1035",
            "category":       "Container Vulnerability",
            "source":         "grype",
            "scanner":        "container",
            "package":        pkg,
            "installed_version": ver,
            "fixed_in":       str(fix),
            "confidence":     88,
        })
    return findings


def _parse_from_lines(dockerfile_content: str) -> List[str]:
    """Extract all FROM image references from a Dockerfile."""
    images: List[str] = []
    for line in dockerfile_content.splitlines():
        line = line.strip()
        if line.upper().startswith("FROM "):
            parts = line.split()
            if len(parts) >= 2:
                img = parts[1]
                if img.lower() != "scratch":
                    images.append(img)
    return images


def _static_scan_image(image: str) -> List[Dict]:
    """Static fallback: check image against known-vulnerable tag list."""
    findings: List[Dict] = []

    # Exact match
    vulns = _KNOWN_VULN_IMAGES.get(image, [])

    # Fuzzy: strip digest/sha, match tag prefix
    if not vulns:
        base = image.split("@")[0]
        for known, v in _KNOWN_VULN_IMAGES.items():
            if base == known or base.startswith(known.split(":")[0] + ":"):
                vulns = v
                break

    for cve, sev, desc in vulns:
        findings.append({
            "type":           "CONTAINER_VULNERABILITY",
            "id":             cve,
            "cve":            cve,
            "severity":       sev,
            "file":           image,
            "line":           0,
            "message":        f"{image}: {desc}",
            "description":    desc,
            "evidence":       f"FROM {image}",
            "recommendation": "Update to a newer base image tag or use distroless/minimal base",
            "cwe":            "CWE-1035",
            "category":       "Container Vulnerability (Base Image)",
            "source":         "container_scanner_static",
            "scanner":        "container",
            "confidence":     70,
        })

    # :latest warning
    if image.endswith(":latest") or ":" not in image:
        findings.append({
            "type":           "CONTAINER_MISCONFIGURATION",
            "id":             "CONTAINER-001",
            "severity":       "MEDIUM",
            "cwe":            "CWE-1188",
            "file":           image,
            "line":           0,
            "message":        f"Image '{image}' uses :latest or no tag — not reproducible",
            "description":    "Using :latest or untagged images makes builds non-reproducible and may pull vulnerable versions",
            "evidence":       f"FROM {image}",
            "recommendation": "Pin to exact tag and digest: FROM nginx:1.25.3@sha256:<digest>",
            "source":         "container_scanner_static",
            "scanner":        "container",
            "confidence":     85,
        })

    return findings


class ContainerScanner:
    """
    Scans Docker container images for OS-level CVEs.
    Automatically selects best available scanner: Trivy > Grype > static.
    """

    def __init__(self) -> None:
        self._trivy = _trivy_available()
        self._grype = _grype_available()

    def backend(self) -> str:
        if self._trivy:  return "trivy"
        if self._grype:  return "grype"
        return "static"

    def scan_image(self, image: str, timeout: int = 120) -> List[Dict]:
        """Scan a single Docker image by name/tag."""
        if self._trivy:
            findings = _run_trivy(image, timeout)
            if findings:
                return findings
        if self._grype:
            findings = _run_grype(image, timeout)
            if findings:
                return findings
        return _static_scan_image(image)

    def scan_dockerfile(self, dockerfile_path: str, timeout: int = 60) -> List[Dict]:
        """
        Extract FROM lines from a Dockerfile and scan each base image.
        Uses static analysis when live scanner unavailable.
        """
        p = Path(dockerfile_path)
        if not p.exists():
            return []
        try:
            content = p.read_text(errors="replace")
        except Exception:
            return []

        images   = _parse_from_lines(content)
        findings: List[Dict] = []

        for img in images:
            if self._trivy:
                found = _run_trivy(img, timeout // max(len(images), 1))
            elif self._grype:
                found = _run_grype(img, timeout // max(len(images), 1))
            else:
                found = _static_scan_image(img)

            for f in found:
                f["dockerfile"] = str(p)
            findings.extend(found)

        # Sort by severity
        findings.sort(key=lambda f: _SEV_ORDER.get(f.get("severity", "LOW"), 4))
        return findings

    def scan_directory(self, directory: str) -> Dict:
        """Find all Dockerfiles in a directory and scan their base images."""
        root     = Path(directory)
        findings: List[Dict] = []
        scanned: List[str]   = []

        for p in root.rglob("*"):
            if not p.is_file():
                continue
            if any(part in _SKIP_DIRS for part in p.parts):
                continue
            name = p.name.lower()
            if name == "dockerfile" or name.startswith("dockerfile."):
                found = self.scan_dockerfile(str(p))
                findings.extend(found)
                scanned.append(str(p))

        findings.sort(key=lambda f: _SEV_ORDER.get(f.get("severity", "LOW"), 4))

        sev_counts: Dict[str, int] = {}
        for f in findings:
            s = f.get("severity", "MEDIUM")
            sev_counts[s] = sev_counts.get(s, 0) + 1

        return {
            "dockerfiles_scanned": len(scanned),
            "total_findings":      len(findings),
            "severity_counts":     sev_counts,
            "findings":            findings,
            "backend":             self.backend(),
            "scanner":             "container",
        }

    def status(self) -> Dict:
        return {
            "trivy_available": self._trivy,
            "grype_available": self._grype,
            "active_backend":  self.backend(),
            "note": (
                "Using Trivy (live scan)" if self._trivy else
                "Using Grype (live scan)" if self._grype else
                "Static analysis only — install Trivy for full OS-level CVE scanning: "
                "https://aquasecurity.github.io/trivy/latest/getting-started/installation/"
            ),
        }
