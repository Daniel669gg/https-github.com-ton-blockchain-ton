"""
Tests for IaCScanner (iac_scanner.py) and ContainerScanner (container_scanner.py).

Covers all 12 required test cases using pytest + tmp_path fixtures.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import List

import pytest

# Ensure the project root is on the path
PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.scanners.iac_scanner import IaCScanner, IaCScanResult
from backend.scanners.container_scanner import ContainerScanner, ContainerFinding


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _write(tmp_path: Path, filename: str, content: str) -> Path:
    """Write content to a file and return its path."""
    p = tmp_path / filename
    p.write_text(content, encoding="utf-8")
    return p


def _rule_ids(results: list) -> list:
    return [r.rule_id for r in results]


def _severities(results: list) -> list:
    return [r.severity for r in results]


# ─────────────────────────────────────────────────────────────────────────────
# Test 1 — TF S3 missing encryption → IAC-TF-001
# ─────────────────────────────────────────────────────────────────────────────

TF_S3_NO_ENCRYPTION = '''\
resource "aws_s3_bucket" "my_bucket" {
  bucket = "my-app-bucket"
  acl    = "private"
}
'''


def test_tf_s3_missing_encryption(tmp_path: Path) -> None:
    """S3 bucket without server_side_encryption_configuration triggers IAC-TF-001."""
    p = _write(tmp_path, "main.tf", TF_S3_NO_ENCRYPTION)
    scanner = IaCScanner()
    results = scanner.scan_file(str(p))
    rule_ids = _rule_ids(results)
    assert "IAC-TF-001" in rule_ids, f"Expected IAC-TF-001 in {rule_ids}"
    enc_findings = [r for r in results if r.rule_id == "IAC-TF-001"]
    assert enc_findings[0].severity == "HIGH"
    assert enc_findings[0].category == "ENCRYPTION"


# ─────────────────────────────────────────────────────────────────────────────
# Test 2 — TF security group SSH open to internet → IAC-TF-002
# ─────────────────────────────────────────────────────────────────────────────

TF_SG_SSH_OPEN = '''\
resource "aws_security_group" "open_ssh" {
  name = "allow_ssh"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
'''


def test_tf_sg_ssh_open(tmp_path: Path) -> None:
    """Security group with SSH open to 0.0.0.0/0 triggers IAC-TF-002."""
    p = _write(tmp_path, "sg.tf", TF_SG_SSH_OPEN)
    scanner = IaCScanner()
    results = scanner.scan_file(str(p))
    rule_ids = _rule_ids(results)
    assert "IAC-TF-002" in rule_ids, f"Expected IAC-TF-002 in {rule_ids}"
    ssh_findings = [r for r in results if r.rule_id == "IAC-TF-002"]
    assert ssh_findings[0].severity == "CRITICAL"
    assert ssh_findings[0].category == "NETWORK"


# ─────────────────────────────────────────────────────────────────────────────
# Test 3 — TF hardcoded password → IAC-TF-008
# ─────────────────────────────────────────────────────────────────────────────

TF_HARDCODED_PASSWORD = '''\
resource "aws_db_instance" "default" {
  engine         = "mysql"
  instance_class = "db.t3.micro"
  username       = "admin"
  password       = "SuperSecret123!"
  storage_encrypted = true
}
'''


def test_tf_hardcoded_password(tmp_path: Path) -> None:
    """Hardcoded password in Terraform file triggers IAC-TF-008."""
    p = _write(tmp_path, "db.tf", TF_HARDCODED_PASSWORD)
    scanner = IaCScanner()
    results = scanner.scan_file(str(p))
    rule_ids = _rule_ids(results)
    assert "IAC-TF-008" in rule_ids, f"Expected IAC-TF-008 in {rule_ids}"
    cred_findings = [r for r in results if r.rule_id == "IAC-TF-008"]
    assert cred_findings[0].severity == "CRITICAL"
    assert cred_findings[0].category == "SECRETS"


# ─────────────────────────────────────────────────────────────────────────────
# Test 4 — TF clean file → no findings
# ─────────────────────────────────────────────────────────────────────────────

TF_CLEAN = '''\
resource "aws_s3_bucket" "secure_bucket" {
  bucket = "secure-app-bucket"
  acl    = "private"

  versioning {
    enabled = true
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}

resource "aws_instance" "web" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.micro"
  monitoring    = true
}
'''


def test_tf_clean_no_findings(tmp_path: Path) -> None:
    """A well-configured Terraform file produces no HIGH/CRITICAL findings."""
    p = _write(tmp_path, "clean.tf", TF_CLEAN)
    scanner = IaCScanner()
    results = scanner.scan_file(str(p))
    critical_high = [r for r in results if r.severity in ("CRITICAL", "HIGH")]
    assert not critical_high, (
        f"Expected no CRITICAL/HIGH findings, got: {[(r.rule_id, r.severity) for r in critical_high]}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Test 5 — CF open security group → IAC-CF-001
# ─────────────────────────────────────────────────────────────────────────────

CF_OPEN_SG = '''\
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  WebServerSG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Web server security group
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: 0.0.0.0/0
'''


def test_cf_open_security_group(tmp_path: Path) -> None:
    """CloudFormation SecurityGroup with SSH open to 0.0.0.0/0 triggers IAC-CF-001."""
    p = _write(tmp_path, "template.yaml", CF_OPEN_SG)
    scanner = IaCScanner()
    results = scanner.scan_file(str(p))
    rule_ids = _rule_ids(results)
    assert "IAC-CF-001" in rule_ids, f"Expected IAC-CF-001 in {rule_ids}"
    sg_findings = [r for r in results if r.rule_id == "IAC-CF-001"]
    assert sg_findings[0].severity == "CRITICAL"


# ─────────────────────────────────────────────────────────────────────────────
# Test 6 — K8s privileged container → IAC-K8S-005
# ─────────────────────────────────────────────────────────────────────────────

K8S_PRIVILEGED = '''\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vulnerable-app
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: vulnerable
  template:
    metadata:
      labels:
        app: vulnerable
    spec:
      containers:
        - name: app
          image: nginx:1.25
          securityContext:
            privileged: true
          resources:
            limits:
              cpu: "500m"
              memory: "128Mi"
'''


def test_k8s_privileged_container(tmp_path: Path) -> None:
    """K8s deployment with privileged: true triggers IAC-K8S-005."""
    p = _write(tmp_path, "deployment.yaml", K8S_PRIVILEGED)
    scanner = IaCScanner()
    results = scanner.scan_file(str(p))
    rule_ids = _rule_ids(results)
    assert "IAC-K8S-005" in rule_ids, f"Expected IAC-K8S-005 in {rule_ids}"
    priv_findings = [r for r in results if r.rule_id == "IAC-K8S-005"]
    assert priv_findings[0].severity == "CRITICAL"
    assert priv_findings[0].category == "PRIVILEGE"


# ─────────────────────────────────────────────────────────────────────────────
# Test 7 — K8s clean deployment → no CRITICAL findings
# ─────────────────────────────────────────────────────────────────────────────

K8S_CLEAN = '''\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secure-app
  namespace: default
spec:
  replicas: 2
  selector:
    matchLabels:
      app: secure
  template:
    metadata:
      labels:
        app: secure
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 2000
      containers:
        - name: app
          image: nginx:1.25.3
          securityContext:
            privileged: false
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
          resources:
            limits:
              cpu: "500m"
              memory: "128Mi"
            requests:
              cpu: "250m"
              memory: "64Mi"
'''


def test_k8s_clean_no_critical(tmp_path: Path) -> None:
    """A well-configured K8s deployment produces no CRITICAL findings."""
    p = _write(tmp_path, "secure_deployment.yaml", K8S_CLEAN)
    scanner = IaCScanner()
    results = scanner.scan_file(str(p))
    critical = [r for r in results if r.severity == "CRITICAL"]
    assert not critical, (
        f"Expected no CRITICAL findings, got: {[(r.rule_id, r.description) for r in critical]}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Test 8 — Dockerfile latest tag → CONT-001
# ─────────────────────────────────────────────────────────────────────────────

DOCKERFILE_LATEST = '''\
FROM python:latest

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .

USER 1000
HEALTHCHECK CMD curl -f http://localhost:8000/health || exit 1
CMD ["python", "app.py"]
'''


def test_dockerfile_latest_tag(tmp_path: Path) -> None:
    """Dockerfile with FROM python:latest triggers CONT-001."""
    p = _write(tmp_path, "Dockerfile", DOCKERFILE_LATEST)
    scanner = ContainerScanner()
    results = scanner.scan_dockerfile(str(p))
    rule_ids = _rule_ids(results)
    assert "CONT-001" in rule_ids, f"Expected CONT-001 in {rule_ids}"
    latest_findings = [r for r in results if r.rule_id == "CONT-001"]
    assert latest_findings[0].severity == "MEDIUM"
    assert latest_findings[0].category == "BASE_IMAGE"


# ─────────────────────────────────────────────────────────────────────────────
# Test 9 — Dockerfile no USER → CONT-002
# ─────────────────────────────────────────────────────────────────────────────

DOCKERFILE_NO_USER = '''\
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

HEALTHCHECK CMD curl -f http://localhost:8080/ || exit 1
CMD ["./server"]
'''


def test_dockerfile_no_user(tmp_path: Path) -> None:
    """Dockerfile without USER directive triggers CONT-002."""
    p = _write(tmp_path, "Dockerfile", DOCKERFILE_NO_USER)
    scanner = ContainerScanner()
    results = scanner.scan_dockerfile(str(p))
    rule_ids = _rule_ids(results)
    assert "CONT-002" in rule_ids, f"Expected CONT-002 in {rule_ids}"
    user_findings = [r for r in results if r.rule_id == "CONT-002"]
    assert user_findings[0].severity == "HIGH"
    assert user_findings[0].category == "PRIVILEGE"


# ─────────────────────────────────────────────────────────────────────────────
# Test 10 — Dockerfile pipe-to-shell → CONT-003
# ─────────────────────────────────────────────────────────────────────────────

DOCKERFILE_PIPE_SHELL = '''\
FROM ubuntu:22.04

RUN curl -sSL https://install.example.com/script.sh | bash

USER 1000
HEALTHCHECK CMD echo "ok"
CMD ["bash"]
'''


def test_dockerfile_pipe_to_shell(tmp_path: Path) -> None:
    """Dockerfile with curl | bash triggers CONT-003."""
    p = _write(tmp_path, "Dockerfile", DOCKERFILE_PIPE_SHELL)
    scanner = ContainerScanner()
    results = scanner.scan_dockerfile(str(p))
    rule_ids = _rule_ids(results)
    assert "CONT-003" in rule_ids, f"Expected CONT-003 in {rule_ids}"
    pipe_findings = [r for r in results if r.rule_id == "CONT-003"]
    assert pipe_findings[0].severity == "CRITICAL"
    assert pipe_findings[0].category == "BUILD"


# ─────────────────────────────────────────────────────────────────────────────
# Test 11 — Docker compose privileged service → CONT-C-001
# ─────────────────────────────────────────────────────────────────────────────

COMPOSE_PRIVILEGED = '''\
version: "3.9"
services:
  agent:
    image: myapp:1.0.0
    privileged: true
    environment:
      - APP_ENV=production
'''


def test_compose_privileged(tmp_path: Path) -> None:
    """docker-compose service with privileged: true triggers CONT-C-001."""
    p = _write(tmp_path, "docker-compose.yml", COMPOSE_PRIVILEGED)
    scanner = ContainerScanner()
    results = scanner.scan_compose(str(p))
    rule_ids = _rule_ids(results)
    assert "CONT-C-001" in rule_ids, f"Expected CONT-C-001 in {rule_ids}"
    priv_findings = [r for r in results if r.rule_id == "CONT-C-001"]
    assert priv_findings[0].severity == "CRITICAL"
    assert priv_findings[0].category == "PRIVILEGE"


# ─────────────────────────────────────────────────────────────────────────────
# Test 12 — Docker compose docker.sock mount → CONT-C-004
# ─────────────────────────────────────────────────────────────────────────────

COMPOSE_DOCKER_SOCK = '''\
version: "3.9"
services:
  ci-runner:
    image: ci-runner:2.0.1
    mem_limit: 512m
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    environment:
      - CI_TOKEN=dummy
'''


def test_compose_docker_sock_mount(tmp_path: Path) -> None:
    """docker-compose service mounting /var/run/docker.sock triggers CONT-C-004."""
    p = _write(tmp_path, "docker-compose.yml", COMPOSE_DOCKER_SOCK)
    scanner = ContainerScanner()
    results = scanner.scan_compose(str(p))
    rule_ids = _rule_ids(results)
    assert "CONT-C-004" in rule_ids, f"Expected CONT-C-004 in {rule_ids}"
    sock_findings = [r for r in results if r.rule_id == "CONT-C-004"]
    assert sock_findings[0].severity == "CRITICAL"
    assert sock_findings[0].category == "PRIVILEGE"
    assert "docker.sock" in sock_findings[0].description
