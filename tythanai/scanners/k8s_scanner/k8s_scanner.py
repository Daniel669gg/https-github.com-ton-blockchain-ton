"""
TythanAI Platform — Kubernetes Security Scanner
Defensive static + live analysis of Kubernetes clusters.

Checks (CIS Kubernetes Benchmark + OWASP K8s Top 10):
  RBAC          — избыточные права, wildcard permissions, cluster-admin binding
  Pod Security  — privileged containers, hostPID/hostNetwork, root user
  Secrets       — secrets in env vars, unencrypted etcd
  Network       — отсутствие NetworkPolicy, разрешённый ingress *:*
  Resources     — нет limits/requests (DoS риск)
  Images        — latest tag, no digest pinning
  Manifests     — статический анализ YAML без живого кластера
"""
from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


# ══════════════════════════════════════════════════════════════════════════════
# FINDING MODEL
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class K8sFinding:
    rule_id:     str
    severity:    str         # CRITICAL / HIGH / MEDIUM / LOW / INFO
    category:    str
    resource:    str         # e.g. "Deployment/frontend"
    namespace:   str
    message:     str
    description: str
    recommendation: str
    cis_id:      str = ""    # CIS benchmark ID
    cwe:         str = ""
    evidence:    str = ""
    source:      str = "k8s_scanner"

    def to_dict(self) -> dict:
        return {
            "rule_id":        self.rule_id,
            "severity":       self.severity,
            "category":       self.category,
            "resource":       self.resource,
            "namespace":      self.namespace,
            "message":        self.message,
            "description":    self.description,
            "recommendation": self.recommendation,
            "cis_id":         self.cis_id,
            "cwe":            self.cwe,
            "evidence":       self.evidence,
            "source":         self.source,
            "type":           "K8S_MISCONFIGURATION",
        }


# ══════════════════════════════════════════════════════════════════════════════
# KUBECTL CLIENT (live cluster)
# ══════════════════════════════════════════════════════════════════════════════

class KubectlClient:
    """Wrapper вокруг kubectl для получения данных из живого кластера."""

    def __init__(self, kubeconfig: str = "", context: str = "") -> None:
        self._base = ["kubectl"]
        if kubeconfig:
            self._base += ["--kubeconfig", kubeconfig]
        if context:
            self._base += ["--context", context]
        self._available: Optional[bool] = None

    def is_available(self) -> bool:
        if self._available is not None:
            return self._available
        try:
            r = subprocess.run(
                self._base + ["version", "--client", "--output=json"],
                capture_output=True, timeout=5,
            )
            self._available = r.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            self._available = False
        return self._available

    def get(self, resource: str, namespace: str = "", output: str = "json") -> dict:
        cmd = self._base + ["get", resource, f"--output={output}"]
        if namespace:
            cmd += ["-n", namespace]
        else:
            cmd += ["--all-namespaces"]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if r.returncode != 0:
                return {}
            return json.loads(r.stdout) if output == "json" else {"raw": r.stdout}
        except Exception:
            return {}

    def namespaces(self) -> List[str]:
        data = self.get("namespaces")
        return [item["metadata"]["name"] for item in data.get("items", [])]


# ══════════════════════════════════════════════════════════════════════════════
# RBAC AUDITOR
# ══════════════════════════════════════════════════════════════════════════════

class RBACAuditor:
    """Аудит RBAC: wildcard permissions, cluster-admin bindings, избыточные права."""

    _DANGEROUS_VERBS  = {"*", "delete", "deletecollection", "patch", "update", "create"}
    _SENSITIVE_RESOURCES = {
        "secrets", "pods", "nodes", "persistentvolumes",
        "clusterroles", "clusterrolebindings", "serviceaccounts",
    }

    def audit_from_kubectl(self, kubectl: KubectlClient) -> List[K8sFinding]:
        findings = []
        # ClusterRoleBindings
        crb = kubectl.get("clusterrolebindings")
        for item in crb.get("items", []):
            findings += self._check_crb(item)
        # RoleBindings in all namespaces
        rb = kubectl.get("rolebindings")
        for item in rb.get("items", []):
            findings += self._check_rb(item)
        # ClusterRoles
        cr = kubectl.get("clusterroles")
        for item in cr.get("items", []):
            findings += self._check_clusterrole(item)
        return findings

    def audit_from_yaml(self, resources: List[dict]) -> List[K8sFinding]:
        findings = []
        for res in resources:
            kind = res.get("kind", "")
            if kind == "ClusterRoleBinding":
                findings += self._check_crb(res)
            elif kind == "RoleBinding":
                findings += self._check_rb(res)
            elif kind == "ClusterRole":
                findings += self._check_clusterrole(res)
        return findings

    def _check_crb(self, crb: dict) -> List[K8sFinding]:
        findings = []
        meta  = crb.get("metadata", {})
        name  = meta.get("name", "")
        ref   = crb.get("roleRef", {})
        role  = ref.get("name", "")
        subjs = crb.get("subjects", [])

        # cluster-admin binding to non-system subject
        if role == "cluster-admin":
            for s in subjs:
                sname = s.get("name", "")
                sns   = s.get("namespace", "")
                if not sname.startswith("system:"):
                    findings.append(K8sFinding(
                        rule_id="K8S-RBAC-001",
                        severity="CRITICAL",
                        category="RBAC",
                        resource=f"ClusterRoleBinding/{name}",
                        namespace="",
                        message=f"cluster-admin bound to non-system subject: {s.get('kind')}/{sname}",
                        description=(
                            f"ClusterRoleBinding '{name}' grants cluster-admin to "
                            f"'{sname}' (ns: {sns or 'cluster-wide'}). "
                            "cluster-admin has full unrestricted access to every resource."
                        ),
                        recommendation="Grant only the minimum required permissions; use namespace-scoped roles",
                        cis_id="CIS 5.1.1",
                        evidence=f"subjects: {json.dumps(s)}",
                    ))
        # Default service account with cluster-wide binding
        for s in subjs:
            if s.get("name") == "default" and s.get("kind") == "ServiceAccount":
                findings.append(K8sFinding(
                    rule_id="K8S-RBAC-002",
                    severity="HIGH",
                    category="RBAC",
                    resource=f"ClusterRoleBinding/{name}",
                    namespace=s.get("namespace", ""),
                    message="default ServiceAccount bound to ClusterRole",
                    description="The default service account should never have cluster-wide permissions",
                    recommendation="Create a dedicated service account with minimal permissions",
                    cis_id="CIS 5.1.5",
                ))
        return findings

    def _check_rb(self, rb: dict) -> List[K8sFinding]:
        findings = []
        meta  = rb.get("metadata", {})
        name  = meta.get("name", "")
        ns    = meta.get("namespace", "")
        ref   = rb.get("roleRef", {})
        for s in rb.get("subjects", []):
            if s.get("name") == "default" and s.get("kind") == "ServiceAccount":
                findings.append(K8sFinding(
                    rule_id="K8S-RBAC-003",
                    severity="MEDIUM",
                    category="RBAC",
                    resource=f"RoleBinding/{name}",
                    namespace=ns,
                    message=f"default ServiceAccount bound to Role '{ref.get('name')}'",
                    description="Default service account should not have explicit role bindings",
                    recommendation="Create dedicated service account for each workload",
                    cis_id="CIS 5.1.5",
                ))
        return findings

    def _check_clusterrole(self, cr: dict) -> List[K8sFinding]:
        findings = []
        meta  = cr.get("metadata", {})
        name  = meta.get("name", "")
        if name.startswith("system:"):
            return []  # skip built-in roles

        for rule in cr.get("rules", []):
            verbs     = set(rule.get("verbs", []))
            resources = set(rule.get("resources", []))
            api_groups = rule.get("apiGroups", [])

            # Wildcard resources
            if "*" in resources and "*" in verbs:
                findings.append(K8sFinding(
                    rule_id="K8S-RBAC-004",
                    severity="CRITICAL",
                    category="RBAC",
                    resource=f"ClusterRole/{name}",
                    namespace="",
                    message="ClusterRole grants wildcard permissions on all resources",
                    description=f"ClusterRole '{name}' has rules: verbs=[*] resources=[*] — equivalent to cluster-admin",
                    recommendation="Enumerate specific resources and verbs needed; never use * on both",
                    cis_id="CIS 5.1.3",
                    evidence=f"verbs={list(verbs)}, resources={list(resources)}",
                ))

            # Secrets access
            if "secrets" in resources and verbs & {"get", "list", "watch", "*"}:
                findings.append(K8sFinding(
                    rule_id="K8S-RBAC-005",
                    severity="HIGH",
                    category="RBAC",
                    resource=f"ClusterRole/{name}",
                    namespace="",
                    message="ClusterRole can read Secrets cluster-wide",
                    description="Cluster-wide secret read access exposes all credentials and tokens",
                    recommendation="Restrict to namespace-scoped Role; grant only to specific service accounts that need it",
                    cis_id="CIS 5.1.2",
                ))
        return findings


# ══════════════════════════════════════════════════════════════════════════════
# POD SECURITY AUDITOR
# ══════════════════════════════════════════════════════════════════════════════

class PodSecurityAuditor:
    """Проверяет pod/container spec на небезопасные конфигурации."""

    def audit_from_kubectl(self, kubectl: KubectlClient) -> List[K8sFinding]:
        findings = []
        for kind in ("pods", "deployments", "statefulsets", "daemonsets"):
            data = kubectl.get(kind)
            for item in data.get("items", []):
                findings += self._check_workload(item)
        return findings

    def audit_from_yaml(self, resources: List[dict]) -> List[K8sFinding]:
        findings = []
        pod_kinds = {"Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob"}
        for res in resources:
            if res.get("kind") in pod_kinds:
                findings += self._check_workload(res)
        return findings

    def _check_workload(self, obj: dict) -> List[K8sFinding]:
        meta   = obj.get("metadata", {})
        name   = meta.get("name", "")
        ns     = meta.get("namespace", "default")
        kind   = obj.get("kind", "Workload")
        spec   = obj.get("spec", {})
        # Handle nested pod spec for Deployment/DaemonSet etc.
        pod_spec = spec.get("template", {}).get("spec", spec)
        resource = f"{kind}/{name}"
        findings = []

        # Host namespace checks
        for flag in ("hostPID", "hostIPC", "hostNetwork"):
            if pod_spec.get(flag):
                sev = "CRITICAL" if flag in ("hostPID", "hostNetwork") else "HIGH"
                findings.append(K8sFinding(
                    rule_id="K8S-POD-" + {"hostPID":"001","hostIPC":"002","hostNetwork":"003"}.get(flag,"000"),
                    severity=sev,
                    category="Pod Security",
                    resource=resource, namespace=ns,
                    message=f"{flag}: true — pod shares host namespace",
                    description=f"Pod '{name}' has {flag}=true, giving it access to host-level resources",
                    recommendation=f"Set {flag}: false unless absolutely required; use PSP/PSA to enforce",
                    cis_id="CIS 5.2.2",
                ))

        # Container checks
        for container in pod_spec.get("containers", []) + pod_spec.get("initContainers", []):
            cname = container.get("name", "")
            findings += self._check_container(container, resource, ns, cname)

        return findings

    def _check_container(
        self, c: dict, workload: str, ns: str, cname: str
    ) -> List[K8sFinding]:
        findings = []
        sc   = c.get("securityContext", {})
        res  = c.get("resources", {})
        img  = c.get("image", "")

        # Privileged container
        if sc.get("privileged"):
            findings.append(K8sFinding(
                rule_id="K8S-POD-004",
                severity="CRITICAL",
                category="Pod Security",
                resource=f"{workload}/container:{cname}",
                namespace=ns,
                message="Container runs in privileged mode",
                description="Privileged containers have full host capabilities — equivalent to root on the node",
                recommendation="Remove privileged: true; drop capabilities explicitly; use seccompProfile",
                cis_id="CIS 5.2.1",
                cwe="CWE-250",
            ))

        # Running as root
        run_as_non_root = sc.get("runAsNonRoot")
        run_as_user     = sc.get("runAsUser", -1)
        if run_as_non_root is False or run_as_user == 0:
            findings.append(K8sFinding(
                rule_id="K8S-POD-005",
                severity="HIGH",
                category="Pod Security",
                resource=f"{workload}/container:{cname}",
                namespace=ns,
                message="Container runs as root (UID 0)",
                description="Running as root increases blast radius of any container escape",
                recommendation="Set runAsNonRoot: true and runAsUser: >=1000",
                cis_id="CIS 5.2.6",
                cwe="CWE-250",
            ))

        # allowPrivilegeEscalation
        if sc.get("allowPrivilegeEscalation") is not False:
            findings.append(K8sFinding(
                rule_id="K8S-POD-006",
                severity="MEDIUM",
                category="Pod Security",
                resource=f"{workload}/container:{cname}",
                namespace=ns,
                message="allowPrivilegeEscalation not explicitly set to false",
                description="Without allowPrivilegeEscalation: false, processes can gain more privileges via setuid binaries",
                recommendation="Add securityContext.allowPrivilegeEscalation: false",
                cis_id="CIS 5.2.5",
            ))

        # Resource limits
        limits = res.get("limits", {})
        if not limits.get("memory") or not limits.get("cpu"):
            findings.append(K8sFinding(
                rule_id="K8S-RES-001",
                severity="MEDIUM",
                category="Resource Management",
                resource=f"{workload}/container:{cname}",
                namespace=ns,
                message="Container has no CPU/memory limits — DoS risk",
                description="Without resource limits, a single container can exhaust node resources",
                recommendation="Set resources.limits.cpu and resources.limits.memory",
                cis_id="CIS 5.6.3",
                cwe="CWE-400",
            ))

        # Image tag :latest
        if img.endswith(":latest") or (":" not in img and "@" not in img):
            findings.append(K8sFinding(
                rule_id="K8S-IMG-001",
                severity="LOW",
                category="Image Security",
                resource=f"{workload}/container:{cname}",
                namespace=ns,
                message=f"Image uses ':latest' tag or no digest pin: {img}",
                description="Using :latest prevents reproducible deployments and may pull untested images",
                recommendation="Pin to specific version tag or SHA digest: image: app@sha256:...",
                evidence=f"image: {img}",
            ))

        # Secrets in env vars
        for env in c.get("env", []):
            ename = env.get("name", "").lower()
            val   = env.get("value", "")
            if any(s in ename for s in ("password","secret","token","key","api_key","credential")):
                if val and not env.get("valueFrom"):
                    findings.append(K8sFinding(
                        rule_id="K8S-SEC-001",
                        severity="HIGH",
                        category="Secrets",
                        resource=f"{workload}/container:{cname}",
                        namespace=ns,
                        message=f"Plaintext secret in env var: {env.get('name')}",
                        description="Secrets in env vars are visible in pod descriptions and logs",
                        recommendation="Use secretKeyRef: or Vault/External Secrets Operator",
                        cis_id="CIS 5.4.1",
                        cwe="CWE-312",
                        evidence=f"env name: {env.get('name')}",
                    ))
        return findings


# ══════════════════════════════════════════════════════════════════════════════
# NETWORK POLICY AUDITOR
# ══════════════════════════════════════════════════════════════════════════════

class NetworkAuditor:
    """Проверяет NetworkPolicy: отсутствие политик, wildcard ingress/egress."""

    def audit_from_kubectl(self, kubectl: KubectlClient) -> List[K8sFinding]:
        findings = []
        ns_list  = kubectl.namespaces()
        netpols  = kubectl.get("networkpolicies")
        covered  = {
            item["metadata"]["namespace"]
            for item in netpols.get("items", [])
        }
        for ns in ns_list:
            if ns in ("kube-system", "kube-public", "kube-node-lease"):
                continue
            if ns not in covered:
                findings.append(K8sFinding(
                    rule_id="K8S-NET-001",
                    severity="MEDIUM",
                    category="Network Policy",
                    resource=f"Namespace/{ns}",
                    namespace=ns,
                    message=f"Namespace '{ns}' has no NetworkPolicy — all traffic allowed",
                    description="Without NetworkPolicy, any pod can communicate with any other pod in the cluster",
                    recommendation="Apply default-deny ingress/egress NetworkPolicy, then allow only needed flows",
                    cis_id="CIS 5.3.2",
                    cwe="CWE-284",
                ))
        return findings

    def audit_from_yaml(self, resources: List[dict]) -> List[K8sFinding]:
        findings = []
        for res in resources:
            if res.get("kind") != "NetworkPolicy":
                continue
            spec = res.get("spec", {})
            meta = res.get("metadata", {})
            name = meta.get("name", "")
            ns   = meta.get("namespace", "")
            # Wildcard ingress (allow from all)
            for rule in spec.get("ingress", []):
                frm = rule.get("from", [])
                if not frm:  # empty from = allow all
                    findings.append(K8sFinding(
                        rule_id="K8S-NET-002",
                        severity="MEDIUM",
                        category="Network Policy",
                        resource=f"NetworkPolicy/{name}",
                        namespace=ns,
                        message="NetworkPolicy ingress rule allows traffic from all sources",
                        description="Empty 'from' selector allows ingress from any pod/namespace/IP",
                        recommendation="Specify explicit podSelector or namespaceSelector for ingress rules",
                    ))
        return findings


# ══════════════════════════════════════════════════════════════════════════════
# MANIFEST SCANNER (static YAML analysis)
# ══════════════════════════════════════════════════════════════════════════════

class ManifestScanner:
    """Статический анализ Kubernetes YAML манифестов без живого кластера."""

    def scan_directory(self, path: str) -> List[K8sFinding]:
        root = Path(path)
        files = (
            list(root.rglob("*.yaml")) + list(root.rglob("*.yml"))
            if root.is_dir() else [root]
        )
        resources = []
        for f in files:
            resources += self._parse_yaml(f)
        return self._audit_resources(resources)

    def scan_string(self, yaml_content: str) -> List[K8sFinding]:
        import io
        resources = self._parse_yaml_string(yaml_content)
        return self._audit_resources(resources)

    def _audit_resources(self, resources: List[dict]) -> List[K8sFinding]:
        pod_aud  = PodSecurityAuditor()
        rbac_aud = RBACAuditor()
        net_aud  = NetworkAuditor()
        findings = []
        findings += pod_aud.audit_from_yaml(resources)
        findings += rbac_aud.audit_from_yaml(resources)
        findings += net_aud.audit_from_yaml(resources)
        return findings

    @staticmethod
    def _parse_yaml(filepath: Path) -> List[dict]:
        try:
            import yaml
            with open(filepath) as f:
                docs = list(yaml.safe_load_all(f.read()))
            return [d for d in docs if isinstance(d, dict) and d.get("kind")]
        except Exception:
            return []

    @staticmethod
    def _parse_yaml_string(content: str) -> List[dict]:
        try:
            import yaml
            docs = list(yaml.safe_load_all(content))
            return [d for d in docs if isinstance(d, dict) and d.get("kind")]
        except Exception:
            return []


# ══════════════════════════════════════════════════════════════════════════════
# MAIN K8S SCANNER
# ══════════════════════════════════════════════════════════════════════════════

class K8sSecurityScanner:
    """
    Единый entry point для всех K8s проверок.
    Режимы:
      live     — подключается к kubectl, сканирует живой кластер
      manifest — статически анализирует YAML файлы/директории
      auto     — пробует live, при неудаче — manifest
    """

    def __init__(self, kubeconfig: str = "", context: str = "") -> None:
        self._kubectl   = KubectlClient(kubeconfig, context)
        self._manifests = ManifestScanner()

    def scan(self, path: str = "", mode: str = "auto") -> dict:
        if mode == "live" or (mode == "auto" and self._kubectl.is_available()):
            return self._scan_live()
        return self._scan_manifests(path)

    def _scan_live(self) -> dict:
        if not self._kubectl.is_available():
            return {"error": "kubectl not available", "findings": []}
        findings: List[K8sFinding] = []
        findings += RBACAuditor().audit_from_kubectl(self._kubectl)
        findings += PodSecurityAuditor().audit_from_kubectl(self._kubectl)
        findings += NetworkAuditor().audit_from_kubectl(self._kubectl)
        return self._package(findings, mode="live")

    def _scan_manifests(self, path: str) -> dict:
        if not path:
            return {"error": "path required for manifest mode", "findings": []}
        findings = self._manifests.scan_directory(path)
        return self._package(findings, mode="manifest")

    def _package(self, findings: List[K8sFinding], mode: str) -> dict:
        dicts = [f.to_dict() for f in findings]
        counts: Dict[str, int] = {}
        for f in dicts:
            s = f["severity"]
            counts[s] = counts.get(s, 0) + 1
        return {
            "findings":        dicts,
            "total":           len(dicts),
            "severity_counts": counts,
            "mode":            mode,
            "kubectl_available": self._kubectl.is_available(),
            "categories": list({f["category"] for f in dicts}),
        }

    def status(self) -> dict:
        return {
            "kubectl_available": self._kubectl.is_available(),
            "checks": ["RBAC", "Pod Security", "Network Policy",
                       "Resource Limits", "Image Security", "Secrets"],
            "standards": ["CIS Kubernetes Benchmark", "OWASP K8s Top 10"],
        }
