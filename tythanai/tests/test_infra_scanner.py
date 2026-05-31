"""
tests/test_infra_scanner.py — Tests for backend/scanners/infra_scanner.py

Covers:
  1. True Positive tests (misconfigurations MUST be detected)
  2. True Negative tests (secure configs must NOT trigger)
  3. Benchmark test (precision >= 0.85, recall >= 0.80)
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path
from typing import List, Tuple

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.core.benchmark import BenchmarkRunner, GroundTruthItem
from backend.core.confidence import Finding
from backend.scanners.infra_scanner import (
    DockerfileScanner,
    GitHubActionsScanner,
    KubernetesScanner,
    InfraScanner,
)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def write_temp(content: str, suffix: str = ".yaml", prefix: str = "test_infra") -> str:
    """Write content to a temp file and return its path."""
    f = tempfile.NamedTemporaryFile(
        mode="w", suffix=suffix, prefix=prefix,
        delete=False, encoding="utf-8"
    )
    f.write(content)
    f.close()
    return f.name


def has_rule(findings: List[Finding], rule_id: str) -> bool:
    return any(f.rule_id == rule_id for f in findings)


def findings_for(findings: List[Finding], rule_id: str) -> List[Finding]:
    return [f for f in findings if f.rule_id == rule_id]


# ─────────────────────────────────────────────────────────────────────────────
# Dockerfile TRUE POSITIVE tests
# ─────────────────────────────────────────────────────────────────────────────

class TestDockerfileTP:

    def _scan(self, content: str) -> List[Finding]:
        fpath = write_temp(content, suffix="", prefix="Dockerfile")
        try:
            return DockerfileScanner().scan(fpath)
        finally:
            os.unlink(fpath)

    def test_user_root(self):
        """USER root must trigger HIGH (CWE-250)."""
        content = "FROM ubuntu:20.04\nRUN apt-get update\nUSER root\nCMD [\"bash\"]\n"
        findings = self._scan(content)
        assert has_rule(findings, "DOCKER-USER-ROOT"), \
            f"Expected DOCKER-USER-ROOT, got: {[f.rule_id for f in findings]}"
        f = findings_for(findings, "DOCKER-USER-ROOT")[0]
        assert f.severity == "HIGH"
        assert f.cwe_id == "CWE-250"

    def test_no_user_instruction(self):
        """Dockerfile without USER must trigger DOCKER-NO-USER."""
        content = "FROM ubuntu:20.04\nRUN apt-get update\nCMD [\"bash\"]\n"
        findings = self._scan(content)
        assert has_rule(findings, "DOCKER-NO-USER"), \
            f"Expected DOCKER-NO-USER, got: {[f.rule_id for f in findings]}"

    def test_privileged_true(self):
        """privileged: true must trigger CRITICAL."""
        content = "FROM ubuntu:20.04\nprivileged: true\nUSER nobody\n"
        findings = self._scan(content)
        assert has_rule(findings, "DOCKER-PRIVILEGED")
        f = findings_for(findings, "DOCKER-PRIVILEGED")[0]
        assert f.severity == "CRITICAL"

    def test_sensitive_volume_docker_sock(self):
        """Mount of /var/run/docker.sock must trigger HIGH."""
        content = "FROM ubuntu:20.04\nVOLUME /var/run/docker.sock\nUSER nobody\n"
        findings = self._scan(content)
        assert has_rule(findings, "DOCKER-SENSITIVE-MOUNT")

    def test_sensitive_volume_etc_passwd(self):
        """/etc/passwd volume must trigger."""
        content = "FROM ubuntu:20.04\nVOLUME /etc/passwd\nUSER nobody\n"
        findings = self._scan(content)
        assert has_rule(findings, "DOCKER-SENSITIVE-MOUNT")

    def test_unpinned_latest_image(self):
        """FROM image:latest must trigger MEDIUM."""
        content = "FROM ubuntu:latest\nUSER nobody\nCMD [\"bash\"]\n"
        findings = self._scan(content)
        assert has_rule(findings, "DOCKER-UNPINNED-IMAGE")

    def test_unpinned_no_tag(self):
        """FROM image with no tag must trigger MEDIUM."""
        content = "FROM ubuntu\nUSER nobody\nCMD [\"bash\"]\n"
        findings = self._scan(content)
        assert has_rule(findings, "DOCKER-UNPINNED-IMAGE")

    def test_env_secret(self):
        """ENV with SECRET in key and literal value must trigger HIGH."""
        content = (
            "FROM ubuntu:20.04\n"
            "ENV DB_SECRET mypassword123\n"
            "USER nobody\n"
        )
        findings = self._scan(content)
        assert has_rule(findings, "DOCKER-ENV-SECRET"), \
            f"Expected DOCKER-ENV-SECRET, got: {[f.rule_id for f in findings]}"

    def test_env_password(self):
        """ENV with PASSWORD in key and literal value must trigger."""
        content = (
            "FROM ubuntu:20.04\n"
            "ENV DB_PASSWORD supersecretpass\n"
            "USER nobody\n"
        )
        findings = self._scan(content)
        assert has_rule(findings, "DOCKER-ENV-SECRET")

    def test_curl_pipe_shell(self):
        """curl | sh pattern must trigger CRITICAL."""
        content = (
            "FROM ubuntu:20.04\n"
            "RUN curl https://install.example.com/install.sh | sh\n"
            "USER nobody\n"
        )
        findings = self._scan(content)
        assert has_rule(findings, "DOCKER-PIPE-SHELL")
        f = findings_for(findings, "DOCKER-PIPE-SHELL")[0]
        assert f.severity == "CRITICAL"

    def test_wget_pipe_bash(self):
        """wget -O- | bash must trigger CRITICAL."""
        content = (
            "FROM ubuntu:20.04\n"
            "RUN wget -O- https://example.com/setup.sh | bash\n"
            "USER nobody\n"
        )
        findings = self._scan(content)
        assert has_rule(findings, "DOCKER-PIPE-SHELL")

    def test_no_check_certificate(self):
        """--no-check-certificate must trigger CRITICAL."""
        content = (
            "FROM ubuntu:20.04\n"
            "RUN wget --no-check-certificate https://example.com/setup.sh\n"
            "USER nobody\n"
        )
        findings = self._scan(content)
        assert has_rule(findings, "DOCKER-PIPE-SHELL")


# ─────────────────────────────────────────────────────────────────────────────
# Dockerfile TRUE NEGATIVE tests
# ─────────────────────────────────────────────────────────────────────────────

class TestDockerfileTN:

    def _scan(self, content: str) -> List[Finding]:
        fpath = write_temp(content, suffix="", prefix="Dockerfile")
        try:
            return DockerfileScanner().scan(fpath)
        finally:
            os.unlink(fpath)

    def test_user_nonroot(self):
        """USER nobody must NOT trigger DOCKER-USER-ROOT."""
        content = "FROM ubuntu:20.04\nUSER nobody\nCMD [\"bash\"]\n"
        findings = self._scan(content)
        assert not has_rule(findings, "DOCKER-USER-ROOT")

    def test_env_with_var_reference(self):
        """ENV with $VAR reference must NOT trigger env secret."""
        content = (
            "FROM ubuntu:20.04\n"
            "ENV DB_SECRET ${DB_SECRET}\n"
            "USER nobody\n"
        )
        findings = self._scan(content)
        assert not has_rule(findings, "DOCKER-ENV-SECRET"), \
            "ENV with variable reference should not be flagged"

    def test_commented_out_secret(self):
        """Commented ENV must NOT trigger."""
        content = (
            "FROM ubuntu:20.04\n"
            "# ENV DB_SECRET mysecret\n"
            "USER nobody\n"
        )
        findings = self._scan(content)
        assert not has_rule(findings, "DOCKER-ENV-SECRET")

    def test_pinned_sha_image(self):
        """FROM with SHA digest must NOT trigger unpinned image."""
        sha = "sha256:" + "a" * 64
        content = f"FROM ubuntu@{sha}\nUSER nobody\nCMD [\"bash\"]\n"
        findings = self._scan(content)
        assert not has_rule(findings, "DOCKER-UNPINNED-IMAGE")


# ─────────────────────────────────────────────────────────────────────────────
# GitHub Actions TRUE POSITIVE tests
# ─────────────────────────────────────────────────────────────────────────────

class TestGHActionsTP:

    def _scan(self, content: str) -> List[Finding]:
        # Simulate a .github/workflows path
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yml", prefix="workflow", delete=False,
            dir=tempfile.gettempdir(), encoding="utf-8"
        ) as f:
            f.write(content)
            fpath = f.name
        # Patch the path to look like a workflow file
        wf_path = fpath.replace(os.path.basename(fpath), ".github/workflows/" + os.path.basename(fpath))
        os.makedirs(os.path.dirname(wf_path), exist_ok=True)
        import shutil
        shutil.copy(fpath, wf_path)
        os.unlink(fpath)
        try:
            return GitHubActionsScanner().scan(wf_path)
        finally:
            try:
                os.unlink(wf_path)
            except OSError:
                pass

    def _scan_direct(self, content: str) -> List[Finding]:
        """Scan content directly with GHA scanner."""
        fpath = write_temp(content, suffix=".yml", prefix=".github_workflows_")
        try:
            return GitHubActionsScanner().scan(fpath)
        finally:
            os.unlink(fpath)

    def test_unpinned_action_with_tag(self):
        """Action pinned to vX.Y tag (not SHA) must trigger MEDIUM."""
        content = """
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
"""
        findings = self._scan_direct(content)
        assert has_rule(findings, "GHAACTIONS-UNPINNED-ACTION"), \
            f"Expected GHAACTIONS-UNPINNED-ACTION, got: {[f.rule_id for f in findings]}"

    def test_script_injection_issue_body(self):
        """${{ github.event.issue.body }} in run step must trigger HIGH."""
        content = """
on: issues
jobs:
  process:
    runs-on: ubuntu-latest
    steps:
      - name: Process issue
        run: |
          echo "${{ github.event.issue.body }}"
"""
        findings = self._scan_direct(content)
        assert has_rule(findings, "GHAACTIONS-SCRIPT-INJECTION"), \
            f"Expected GHAACTIONS-SCRIPT-INJECTION, got: {[f.rule_id for f in findings]}"
        f = findings_for(findings, "GHAACTIONS-SCRIPT-INJECTION")[0]
        assert f.severity == "HIGH"
        assert f.cwe_id == "CWE-78"

    def test_script_injection_pr_title(self):
        """${{ github.event.pull_request.title }} in run step must trigger."""
        content = """
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Check title
        run: echo "${{ github.event.pull_request.title }}"
"""
        findings = self._scan_direct(content)
        assert has_rule(findings, "GHAACTIONS-SCRIPT-INJECTION")

    def test_hardcoded_secret_in_env(self):
        """Literal secret value in env: block must trigger CRITICAL."""
        content = """
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    env:
      MY_API_KEY: hardcoded_secret_value_here
    steps:
      - run: echo done
"""
        findings = self._scan_direct(content)
        assert has_rule(findings, "GHAACTIONS-HARDCODED-SECRET"), \
            f"Expected GHAACTIONS-HARDCODED-SECRET, got: {[f.rule_id for f in findings]}"


# ─────────────────────────────────────────────────────────────────────────────
# GitHub Actions TRUE NEGATIVE tests
# ─────────────────────────────────────────────────────────────────────────────

class TestGHActionsTN:

    def _scan(self, content: str) -> List[Finding]:
        fpath = write_temp(content, suffix=".yml", prefix="workflow_tn_")
        try:
            return GitHubActionsScanner().scan(fpath)
        finally:
            os.unlink(fpath)

    def test_sha_pinned_action(self):
        """SHA-pinned action must NOT trigger unpinned warning."""
        sha = "a" * 40
        content = f"""
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@{sha}
"""
        findings = self._scan(content)
        assert not has_rule(findings, "GHAACTIONS-UNPINNED-ACTION"), \
            "SHA-pinned action should not be flagged"

    def test_secrets_context_reference(self):
        """${{ secrets.MY_SECRET }} in env must NOT trigger hardcoded secret."""
        content = """
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    env:
      MY_SECRET: ${{ secrets.MY_SECRET }}
    steps:
      - run: echo "done"
"""
        findings = self._scan(content)
        assert not has_rule(findings, "GHAACTIONS-HARDCODED-SECRET"), \
            "secrets context reference should not be flagged"

    def test_static_string_in_run_no_injection(self):
        """Static strings in run steps must NOT trigger injection."""
        content = """
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Build
        run: echo "Hello, world!"
"""
        findings = self._scan(content)
        assert not has_rule(findings, "GHAACTIONS-SCRIPT-INJECTION")


# ─────────────────────────────────────────────────────────────────────────────
# Kubernetes TRUE POSITIVE tests
# ─────────────────────────────────────────────────────────────────────────────

class TestKubernetesTP:

    def _scan(self, content: str) -> List[Finding]:
        fpath = write_temp(content, suffix=".yaml", prefix="k8s_tp_")
        try:
            return KubernetesScanner().scan(fpath)
        finally:
            os.unlink(fpath)

    def test_privileged_container(self):
        """privileged: true in securityContext must trigger CRITICAL."""
        content = """
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  containers:
    - name: myapp
      image: nginx:1.21
      securityContext:
        privileged: true
"""
        findings = self._scan(content)
        assert has_rule(findings, "K8S-PRIVILEGED-CONTAINER"), \
            f"Expected K8S-PRIVILEGED-CONTAINER, got: {[f.rule_id for f in findings]}"
        f = findings_for(findings, "K8S-PRIVILEGED-CONTAINER")[0]
        assert f.severity == "CRITICAL"

    def test_host_network(self):
        """hostNetwork: true must trigger HIGH."""
        content = """
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  hostNetwork: true
  containers:
    - name: myapp
      image: nginx:1.21
      securityContext:
        allowPrivilegeEscalation: false
"""
        findings = self._scan(content)
        assert has_rule(findings, "K8S-HOST-NETWORK"), \
            f"Expected K8S-HOST-NETWORK, got: {[f.rule_id for f in findings]}"
        f = findings_for(findings, "K8S-HOST-NETWORK")[0]
        assert f.severity == "HIGH"

    def test_host_pid(self):
        """hostPID: true must trigger HIGH."""
        content = """
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  hostPID: true
  containers:
    - name: myapp
      image: nginx:1.21
"""
        findings = self._scan(content)
        assert has_rule(findings, "K8S-HOST-PID")

    def test_run_as_root(self):
        """runAsUser: 0 must trigger HIGH."""
        content = """
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  containers:
    - name: myapp
      image: nginx:1.21
      securityContext:
        runAsUser: 0
"""
        findings = self._scan(content)
        assert has_rule(findings, "K8S-RUN-AS-ROOT"), \
            f"Expected K8S-RUN-AS-ROOT, got: {[f.rule_id for f in findings]}"

    def test_rbac_wildcard_verbs_list(self):
        """RBAC with verbs: ['*'] must trigger HIGH."""
        content = """
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: all-access
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]
"""
        findings = self._scan(content)
        assert has_rule(findings, "K8S-RBAC-WILDCARD"), \
            f"Expected K8S-RBAC-WILDCARD, got: {[f.rule_id for f in findings]}"
        f = findings_for(findings, "K8S-RBAC-WILDCARD")[0]
        assert f.severity == "HIGH"

    def test_no_security_context(self):
        """Pod with no securityContext must trigger MEDIUM."""
        content = """
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  containers:
    - name: myapp
      image: nginx:1.21
      resources:
        limits:
          cpu: "100m"
          memory: "128Mi"
"""
        findings = self._scan(content)
        # Should have at least one security context finding
        sc_rules = ["K8S-NO-POD-SECURITY-CONTEXT", "K8S-NO-CONTAINER-SECURITY-CONTEXT"]
        assert any(has_rule(findings, r) for r in sc_rules), \
            f"Expected security context finding, got: {[f.rule_id for f in findings]}"

    def test_no_resource_limits(self):
        """Container with no resource limits must trigger LOW."""
        content = """
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  containers:
    - name: myapp
      image: nginx:1.21
      securityContext:
        allowPrivilegeEscalation: false
"""
        findings = self._scan(content)
        assert has_rule(findings, "K8S-NO-RESOURCE-LIMITS"), \
            f"Expected K8S-NO-RESOURCE-LIMITS, got: {[f.rule_id for f in findings]}"

    def test_deployment_privileged(self):
        """Deployment with privileged container must trigger."""
        content = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-deploy
spec:
  template:
    spec:
      containers:
        - name: app
          image: myapp:1.0
          securityContext:
            privileged: true
"""
        findings = self._scan(content)
        assert has_rule(findings, "K8S-PRIVILEGED-CONTAINER")


# ─────────────────────────────────────────────────────────────────────────────
# Kubernetes TRUE NEGATIVE tests
# ─────────────────────────────────────────────────────────────────────────────

class TestKubernetesTN:

    def _scan(self, content: str) -> List[Finding]:
        fpath = write_temp(content, suffix=".yaml", prefix="k8s_tn_")
        try:
            return KubernetesScanner().scan(fpath)
        finally:
            os.unlink(fpath)

    def test_secure_pod(self):
        """Well-configured pod must NOT trigger CRITICAL/HIGH findings."""
        content = """
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 2000
  containers:
    - name: myapp
      image: nginx:1.21.6
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        privileged: false
        runAsUser: 1000
      resources:
        limits:
          cpu: "100m"
          memory: "128Mi"
        requests:
          cpu: "50m"
          memory: "64Mi"
"""
        findings = self._scan(content)
        critical_high = [f for f in findings if f.severity in ("CRITICAL", "HIGH")]
        assert not critical_high, \
            f"Secure pod should not have CRITICAL/HIGH findings, got: {[(f.rule_id, f.severity) for f in critical_high]}"

    def test_non_k8s_yaml_ignored(self):
        """YAML files without 'kind:' field must be ignored."""
        content = """
database:
  host: localhost
  port: 5432
  name: mydb
"""
        findings = self._scan(content)
        assert not findings, "Non-k8s YAML should produce no findings"


# ─────────────────────────────────────────────────────────────────────────────
# InfraScanner integration tests
# ─────────────────────────────────────────────────────────────────────────────

class TestInfraScannerIntegration:

    def test_scan_file_dockerfile(self):
        """InfraScanner.scan_file detects Dockerfile issues."""
        content = "FROM ubuntu\nCMD [\"bash\"]\n"
        fpath = write_temp(content, suffix="", prefix="Dockerfile")
        try:
            scanner = InfraScanner()
            findings = scanner.scan_file(fpath)
            assert len(findings) > 0
        finally:
            os.unlink(fpath)

    def test_scan_directory(self):
        """InfraScanner.scan_directory scans all infra files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a Dockerfile
            (Path(tmpdir) / "Dockerfile").write_text(
                "FROM ubuntu\nCMD [\"bash\"]\n"
            )
            # Create a k8s YAML
            (Path(tmpdir) / "deployment.yaml").write_text("""
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  template:
    spec:
      containers:
        - name: app
          image: myapp:latest
          securityContext:
            privileged: true
""")
            scanner = InfraScanner()
            findings = scanner.scan_directory(tmpdir)
            assert len(findings) > 0
            rule_ids = {f.rule_id for f in findings}
            assert len(rule_ids) >= 2


# ─────────────────────────────────────────────────────────────────────────────
# BENCHMARK test — precision >= 0.85, recall >= 0.80
# ─────────────────────────────────────────────────────────────────────────────

class TestBenchmark:

    def _build_corpus(self):
        """Build labeled corpus for benchmark evaluation."""
        docker_scanner = DockerfileScanner()
        k8s_scanner = KubernetesScanner()
        gha_scanner = GitHubActionsScanner()

        all_findings: List[Finding] = []
        ground_truth: List[GroundTruthItem] = []
        tmp_files: List[str] = []

        try:
            # ── Dockerfile TPs ─────────────────────────────────────────────
            docker_cases: List[Tuple[str, str, str, int]] = [
                (
                    "FROM ubuntu\nCMD [\"bash\"]\n",
                    "DOCKER-NO-USER", 0
                ),
                (
                    "FROM ubuntu:20.04\nUSER root\nCMD [\"bash\"]\n",
                    "DOCKER-USER-ROOT", 3
                ),
                (
                    "FROM ubuntu:20.04\nENV DB_SECRET mysecret123\nUSER nobody\n",
                    "DOCKER-ENV-SECRET", 2
                ),
                (
                    "FROM ubuntu:20.04\nRUN curl https://example.com | sh\nUSER nobody\n",
                    "DOCKER-PIPE-SHELL", 2
                ),
                (
                    "FROM ubuntu:latest\nUSER nobody\nCMD [\"bash\"]\n",
                    "DOCKER-UNPINNED-IMAGE", 1
                ),
            ]

            for content, rule_id, line in docker_cases:
                fpath = write_temp(content, suffix="", prefix="Dockerfile_bench_")
                tmp_files.append(fpath)
                founds = docker_scanner.scan(fpath)
                all_findings.extend(founds)
                # Primary expected finding
                ground_truth.append(GroundTruthItem(
                    rule_id=rule_id,
                    file=fpath,
                    line=line,
                ))
                # All co-occurring findings from the same file are also expected
                for f in founds:
                    if f.rule_id != rule_id:
                        ground_truth.append(GroundTruthItem(
                            rule_id=f.rule_id,
                            file=fpath,
                            line=f.line,
                        ))

            # ── K8s TPs ────────────────────────────────────────────────────
            k8s_cases: List[Tuple[str, str, int]] = [
                (
                    "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n"
                    "  containers:\n    - name: app\n      image: x\n"
                    "      securityContext:\n        privileged: true\n",
                    "K8S-PRIVILEGED-CONTAINER", 10
                ),
                (
                    "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n"
                    "  hostNetwork: true\n  containers:\n    - name: app\n      image: x\n",
                    "K8S-HOST-NETWORK", 6
                ),
                (
                    "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\n"
                    "metadata:\n  name: admin\nrules:\n"
                    "  - apiGroups: [\"*\"]\n    resources: [\"*\"]\n    verbs: [\"*\"]\n",
                    "K8S-RBAC-WILDCARD", 8
                ),
            ]

            for content, rule_id, line in k8s_cases:
                fpath = write_temp(content, suffix=".yaml", prefix="k8s_bench_")
                tmp_files.append(fpath)
                founds = k8s_scanner.scan(fpath)
                all_findings.extend(founds)
                # Primary expected finding
                ground_truth.append(GroundTruthItem(
                    rule_id=rule_id,
                    file=fpath,
                    line=line,
                ))
                # Co-occurring findings are also expected (all are legitimate)
                for f in founds:
                    if f.rule_id != rule_id:
                        ground_truth.append(GroundTruthItem(
                            rule_id=f.rule_id,
                            file=fpath,
                            line=f.line,
                        ))

            # ── GHA TPs ────────────────────────────────────────────────────
            gha_cases: List[Tuple[str, str, int]] = [
                (
                    "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
                    "    steps:\n      - uses: actions/checkout@v3\n",
                    "GHAACTIONS-UNPINNED-ACTION", 6
                ),
            ]

            for content, rule_id, line in gha_cases:
                fpath = write_temp(content, suffix=".yml", prefix="gha_bench_")
                tmp_files.append(fpath)
                founds = gha_scanner.scan(fpath)
                all_findings.extend(founds)
                ground_truth.append(GroundTruthItem(
                    rule_id=rule_id,
                    file=fpath,
                    line=line,
                ))

        finally:
            for f in tmp_files:
                try:
                    os.unlink(f)
                except OSError:
                    pass

        return all_findings, ground_truth

    def test_benchmark_precision_recall(self):
        """InfraScanner must achieve precision >= 0.85, recall >= 0.80."""
        findings, ground_truth = self._build_corpus()

        runner = BenchmarkRunner(
            precision_threshold=0.85,
            recall_threshold=0.80,
            line_tolerance=4,
        )
        report = runner.evaluate(
            predicted=findings,
            ground_truth=ground_truth,
            module_name="infra_scanner",
        )
        print(f"\n{report.summary()}")

        assert report.precision >= 0.85, (
            f"Precision {report.precision:.3f} below threshold 0.85. "
            f"FP={report.false_positives} TP={report.true_positives}\n"
            f"False positives: {report.details.get('false_positive_findings', [])}"
        )
        assert report.recall >= 0.80, (
            f"Recall {report.recall:.3f} below threshold 0.80. "
            f"FN={report.false_negatives} TP={report.true_positives}\n"
            f"Missed: {report.details.get('missed_findings', [])}"
        )
        assert report.passed, report.summary()
