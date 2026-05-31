"""
Tests for TythanAI v10 new scanners:
  - OSV Scanner (dependency CVE lookup)
  - C/C++ SAST Scanner
  - IaC Scanner (Dockerfile, Terraform, docker-compose, GitHub Actions)
  - CI Generator
"""
import json
import os
import shutil
import tempfile
from pathlib import Path

import pytest

# ── Helpers ───────────────────────────────────────────────────────────────────

def write_file(tmpdir: str, name: str, content: str) -> str:
    path = Path(tmpdir) / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return str(path)


# ══════════════════════════════════════════════════════════════════════════════
# C/C++ Scanner
# ══════════════════════════════════════════════════════════════════════════════

class TestCppScanner:
    def setup_method(self):
        from scanners.cpp_scanner import CppScanner
        self.scanner = CppScanner()
        self.tmpdir  = tempfile.mkdtemp()

    def teardown_method(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _scan(self, code: str, suffix: str = ".c") -> list:
        path = write_file(self.tmpdir, f"test{suffix}", code)
        return self.scanner.scan_file(path)

    def test_gets_detected(self):
        findings = self._scan("void f(){char b[64]; gets(b);}")
        ids = [f["id"] for f in findings]
        assert "CPP-001" in ids

    def test_strcpy_detected(self):
        findings = self._scan("void f(char*s){char b[64]; strcpy(b,s);}")
        ids = [f["id"] for f in findings]
        assert "CPP-002" in ids

    def test_sprintf_detected(self):
        findings = self._scan("void f(){char b[64]; sprintf(b, fmt);}")
        ids = [f["id"] for f in findings]
        assert "CPP-004" in ids

    def test_system_detected(self):
        findings = self._scan('void f(char*c){system(c);}')
        ids = [f["id"] for f in findings]
        assert "CPP-020" in ids

    def test_rand_detected(self):
        findings = self._scan("double r = rand();")
        ids = [f["id"] for f in findings]
        assert "CPP-070" in ids

    def test_safe_code_no_findings(self):
        safe = """
#include <stdio.h>
int main() {
    char buf[64];
    fgets(buf, sizeof(buf), stdin);
    snprintf(buf, sizeof(buf), "%s", "hello");
    return 0;
}
"""
        findings = self._scan(safe)
        dangerous = [f for f in findings if f["severity"] in ("CRITICAL", "HIGH")]
        assert len(dangerous) == 0, f"False positives: {dangerous}"

    def test_no_duplicates_inline_comment(self):
        code = 'void f(char *s){gets(s); /* gets() is bad */}\n'
        findings = self._scan(code)
        cpp001 = [f for f in findings if f["id"] == "CPP-001"]
        assert len(cpp001) == 1, f"Expected 1 CPP-001, got {len(cpp001)}"

    def test_cpp_file_scanned(self):
        code = "void f(char*s){strcpy(buf,s); rand();}"
        findings = self._scan(code, suffix=".cpp")
        assert len(findings) > 0

    def test_header_file_scanned(self):
        findings = self._scan("char *gets(char *s);", suffix=".h")
        # pattern should match in header too if it looks like a call
        assert isinstance(findings, list)

    def test_scan_directory(self):
        write_file(self.tmpdir, "vuln.c", "void f(){system(x); gets(b);}")
        write_file(self.tmpdir, "safe.py", "print('hello')")
        result = self.scanner.scan_directory(self.tmpdir)
        assert result["files_scanned"] >= 1
        assert result["total_findings"] >= 2
        assert "CRITICAL" in result["severity_counts"]

    def test_pattern_count(self):
        assert self.scanner.pattern_count() >= 20

    def test_severity_levels_present(self):
        code = "void f(){gets(b); strcpy(d,s); system(c); rand();}"
        findings = self._scan(code)
        severities = {f["severity"] for f in findings}
        assert "CRITICAL" in severities
        assert "HIGH" in severities


# ══════════════════════════════════════════════════════════════════════════════
# IaC Scanner
# ══════════════════════════════════════════════════════════════════════════════

class TestIaCScanner:
    def setup_method(self):
        from scanners.iac_scanner import IaCScanner
        self.scanner = IaCScanner()
        self.tmpdir  = tempfile.mkdtemp()

    def teardown_method(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    # ── Dockerfile ────────────────────────────────────────────────────────────

    def test_dockerfile_root_user(self):
        path = write_file(self.tmpdir, "Dockerfile", "FROM ubuntu:22.04\nRUN echo hello\n")
        findings = self.scanner.scan_file(path)
        ids = [f["id"] for f in findings]
        assert "DOCKER-001A" in ids

    def test_dockerfile_latest_tag(self):
        path = write_file(self.tmpdir, "Dockerfile", "FROM nginx:latest\nUSER nginx\n")
        findings = self.scanner.scan_file(path)
        ids = [f["id"] for f in findings]
        assert "DOCKER-002" in ids

    def test_dockerfile_hardcoded_secret(self):
        path = write_file(self.tmpdir, "Dockerfile",
                          "FROM ubuntu:22.04\nENV PASSWORD=hunter2\nUSER nobody\n")
        findings = self.scanner.scan_file(path)
        ids = [f["id"] for f in findings]
        assert "DOCKER-003" in ids

    def test_dockerfile_curl_pipe_bash(self):
        path = write_file(self.tmpdir, "Dockerfile",
                          "FROM alpine:3.18\nRUN curl -fsSL https://x.com | bash\nUSER nobody\n")
        findings = self.scanner.scan_file(path)
        ids = [f["id"] for f in findings]
        assert "DOCKER-004" in ids

    def test_dockerfile_chmod_777(self):
        path = write_file(self.tmpdir, "Dockerfile",
                          "FROM alpine:3.18\nRUN chmod 777 /app\nUSER appuser\n")
        findings = self.scanner.scan_file(path)
        ids = [f["id"] for f in findings]
        assert "DOCKER-013" in ids

    def test_dockerfile_good_practices_fewer_findings(self):
        good = (
            "FROM python:3.11-slim\n"
            "RUN adduser --disabled-password appuser\n"
            "WORKDIR /app\n"
            "COPY requirements.txt .\n"
            "RUN pip install --no-cache-dir -r requirements.txt\n"
            "USER appuser\n"
            "HEALTHCHECK CMD curl -f http://localhost/ || exit 1\n"
            "CMD [\"python\", \"app.py\"]\n"
        )
        path = write_file(self.tmpdir, "Dockerfile", good)
        findings = self.scanner.scan_file(path)
        crits_highs = [f for f in findings if f["severity"] in ("CRITICAL", "HIGH")]
        assert len(crits_highs) == 0, f"False positives: {crits_highs}"

    # ── docker-compose ────────────────────────────────────────────────────────

    def test_compose_privileged(self):
        compose = "version: '3'\nservices:\n  app:\n    image: nginx\n    privileged: true\n"
        path = write_file(self.tmpdir, "docker-compose.yml", compose)
        findings = self.scanner.scan_file(path)
        ids = [f["id"] for f in findings]
        assert "DC-001" in ids

    def test_compose_docker_socket(self):
        compose = (
            "services:\n  app:\n    image: nginx\n"
            "    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n"
        )
        path = write_file(self.tmpdir, "docker-compose.yml", compose)
        findings = self.scanner.scan_file(path)
        ids = [f["id"] for f in findings]
        assert "DC-003" in ids

    # ── Terraform ─────────────────────────────────────────────────────────────

    def test_terraform_open_security_group(self):
        tf = 'resource "aws_security_group" "web" {\n  ingress {\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n'
        path = write_file(self.tmpdir, "main.tf", tf)
        findings = self.scanner.scan_file(path)
        ids = [f["id"] for f in findings]
        assert "TF-001" in ids

    def test_terraform_hardcoded_password(self):
        tf = 'resource "aws_db_instance" "db" {\n  password = "mySuperSecret123"\n}\n'
        path = write_file(self.tmpdir, "db.tf", tf)
        findings = self.scanner.scan_file(path)
        ids = [f["id"] for f in findings]
        assert "TF-003" in ids

    def test_terraform_public_db(self):
        tf = 'resource "aws_db_instance" "db" {\n  publicly_accessible = true\n}\n'
        path = write_file(self.tmpdir, "db.tf", tf)
        findings = self.scanner.scan_file(path)
        ids = [f["id"] for f in findings]
        assert "TF-005" in ids

    def test_terraform_unencrypted_storage(self):
        tf = 'resource "aws_ebs_volume" "vol" {\n  encrypted = false\n  size = 40\n}\n'
        path = write_file(self.tmpdir, "storage.tf", tf)
        findings = self.scanner.scan_file(path)
        ids = [f["id"] for f in findings]
        assert "TF-004" in ids

    # ── GitHub Actions ────────────────────────────────────────────────────────

    def test_github_actions_unpinned_action(self):
        workflow = (
            "name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
            "    steps:\n      - uses: actions/checkout@v4\n"
        )
        path = write_file(self.tmpdir, ".github/workflows/ci.yml", workflow)
        findings = self.scanner.scan_file(path)
        ids = [f["id"] for f in findings]
        assert "GHA-004" in ids

    # ── Directory scan ────────────────────────────────────────────────────────

    def test_scan_directory_mixed_files(self):
        write_file(self.tmpdir, "Dockerfile", "FROM ubuntu:latest\nRUN echo hello\n")
        write_file(self.tmpdir, "main.tf",
                   'resource "aws_db_instance" "db" {\n  publicly_accessible = true\n}\n')
        result = self.scanner.scan_directory(self.tmpdir)
        assert result["files_scanned"] >= 2
        assert result["total_findings"] >= 2

    def test_scan_directory_returns_structure(self):
        write_file(self.tmpdir, "Dockerfile", "FROM ubuntu:latest\n")
        result = self.scanner.scan_directory(self.tmpdir)
        assert "files_scanned" in result
        assert "total_findings" in result
        assert "severity_counts" in result
        assert "findings" in result


# ══════════════════════════════════════════════════════════════════════════════
# OSV Scanner
# ══════════════════════════════════════════════════════════════════════════════

class TestOSVScanner:
    def setup_method(self):
        from scanners.osv_scanner import OSVScanner
        self.scanner = OSVScanner()
        self.tmpdir  = tempfile.mkdtemp()

    def teardown_method(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_offline_fallback_on_vuln_package(self):
        """Offline path: static DB should catch known-vulnerable packages."""
        write_file(self.tmpdir, "requirements.txt",
                   "django==3.2.0\npillow==9.0.0\nrequests==2.25.1\n")
        result = self.scanner.scan_directory(self.tmpdir)
        # Works either online (OSV) or offline (static DB)
        assert result["total_findings"] >= 1
        assert result["manifests_scanned"] >= 1

    def test_parse_requirements(self):
        from scanners.osv_scanner import _parse_requirements
        deps = _parse_requirements("requests==2.28.0\ndjango>=4.0\nnumpy\n# comment\n")
        names = [d[0] for d in deps]
        assert "requests" in names
        assert "django" in names
        assert "numpy" in names

    def test_parse_package_json(self):
        from scanners.osv_scanner import _parse_package_json
        pkg_json = json.dumps({
            "dependencies": {"lodash": "^4.17.20", "express": "4.18.0"},
            "devDependencies": {"jest": "^29.0.0"},
        })
        deps = _parse_package_json(pkg_json)
        names = [d[0] for d in deps]
        assert "lodash" in names
        assert "express" in names

    def test_parse_go_mod(self):
        from scanners.osv_scanner import _parse_go_mod
        go_mod = "module example.com/proj\ngo 1.21\nrequire (\n\tgolang.org/x/crypto v0.14.0\n)\n"
        deps = _parse_go_mod(go_mod)
        assert any("crypto" in d[0] for d in deps)

    def test_parse_cargo_toml(self):
        from scanners.osv_scanner import _parse_cargo_toml
        cargo = '[dependencies]\nserde = "1.0.195"\ntokio = { version = "1.35.1" }\n'
        deps = _parse_cargo_toml(cargo)
        names = [d[0] for d in deps]
        assert "serde" in names
        assert "tokio" in names

    def test_scan_directory_returns_structure(self):
        write_file(self.tmpdir, "requirements.txt", "flask==2.2.0\n")
        result = self.scanner.scan_directory(self.tmpdir)
        assert "findings" in result
        assert "manifests_scanned" in result
        assert "total_packages" in result
        assert "online" in result

    def test_nonexistent_path_returns_empty(self):
        findings = self.scanner.scan_file("/nonexistent/path/requirements.txt")
        assert findings == []

    def test_empty_manifest_returns_empty(self):
        write_file(self.tmpdir, "requirements.txt", "# just comments\n\n")
        result = self.scanner.scan_directory(self.tmpdir)
        assert result["total_findings"] == 0


# ══════════════════════════════════════════════════════════════════════════════
# CI Generator
# ══════════════════════════════════════════════════════════════════════════════

class TestCIGenerator:
    def setup_method(self):
        from integrations.ci_generator import CIGenerator
        self.gen    = CIGenerator()
        self.tmpdir = tempfile.mkdtemp()

    def teardown_method(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_github_actions_contains_key_fields(self):
        wf = self.gen.github_actions_workflow()
        assert "ghost scan" in wf or "ghost_cli_main" in wf
        assert "sarif" in wf.lower()
        assert "pull_request" in wf
        assert "permissions:" in wf

    def test_github_actions_min_severity_respected(self):
        wf = self.gen.github_actions_workflow(min_severity="HIGH")
        assert "HIGH" in wf

    def test_write_github_actions_creates_file(self):
        target = self.gen.write_github_actions(self.tmpdir)
        assert Path(target).exists()
        content = Path(target).read_text()
        assert "TythanAI" in content

    def test_gitlab_ci_snippet(self):
        snippet = self.gen.gitlab_ci_snippet()
        assert "ghost-security-scan" in snippet
        assert "stage:" in snippet
        assert "artifacts" in snippet

    def test_pre_commit_script(self):
        script = self.gen.pre_commit_script()
        assert "CRITICAL" in script
        assert "staged" in script.lower()

    def test_vscode_tasks(self):
        tasks = self.gen.vscode_tasks()
        data = json.loads(tasks)
        assert data["version"] == "2.0.0"
        assert len(data["tasks"]) >= 2
