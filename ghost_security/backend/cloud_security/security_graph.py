"""Unified Security Graph — connects code → dependency → runtime → cloud → identity → resource.

Builds on IAMGraph and adds cross-layer attack paths for a holistic view of the
attack surface.  Deliberately does NOT import AttackGraph to avoid circular deps.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set

from backend.cloud_security.iam_graph import IAMGraph


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class SGNodeType(str, Enum):
    # Code layer
    SAST_FINDING     = "sast_finding"
    DEPENDENCY_CVE   = "dependency_cve"
    # Runtime layer
    CONTAINER        = "container"
    CONTAINER_IMAGE  = "container_image"
    # Orchestration layer
    K8S_POD          = "k8s_pod"
    K8S_NAMESPACE    = "k8s_namespace"
    K8S_SERVICE      = "k8s_service"
    # Identity layer
    IAM_IDENTITY     = "iam_identity"
    IAM_ROLE         = "iam_role"
    IAM_PERMISSION   = "iam_permission"
    # Cloud layer
    CLOUD_ACCOUNT    = "cloud_account"
    CLOUD_RESOURCE   = "cloud_resource"
    CLOUD_STORAGE    = "cloud_storage"
    CLOUD_DATABASE   = "cloud_database"
    CLOUD_NETWORK    = "cloud_network"
    # Business layer
    BUSINESS_ASSET   = "business_asset"


# Severity ordering used when computing "highest severity in path"
_SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def _higher_severity(a: str, b: str) -> str:
    return a if _SEV_ORDER.get(a, 0) >= _SEV_ORDER.get(b, 0) else b


# Layer membership maps for cross-layer path detection
_LAYER_OF: Dict[str, str] = {
    SGNodeType.SAST_FINDING:    "code",
    SGNodeType.DEPENDENCY_CVE:  "code",
    SGNodeType.CONTAINER:       "runtime",
    SGNodeType.CONTAINER_IMAGE: "runtime",
    SGNodeType.K8S_POD:         "runtime",
    SGNodeType.K8S_NAMESPACE:   "runtime",
    SGNodeType.K8S_SERVICE:     "runtime",
    SGNodeType.IAM_IDENTITY:    "identity",
    SGNodeType.IAM_ROLE:        "identity",
    SGNodeType.IAM_PERMISSION:  "identity",
    SGNodeType.CLOUD_ACCOUNT:   "cloud",
    SGNodeType.CLOUD_RESOURCE:  "cloud",
    SGNodeType.CLOUD_STORAGE:   "cloud",
    SGNodeType.CLOUD_DATABASE:  "cloud",
    SGNodeType.CLOUD_NETWORK:   "cloud",
    SGNodeType.BUSINESS_ASSET:  "business",
}

# Node types that are valid BFS targets for cloud attack paths
_CLOUD_TARGET_TYPES: Set[str] = {
    SGNodeType.CLOUD_RESOURCE,
    SGNodeType.CLOUD_STORAGE,
    SGNodeType.CLOUD_DATABASE,
    SGNodeType.BUSINESS_ASSET,
}

# Node types that are valid BFS start points for cloud attack paths
_CODE_SOURCE_TYPES: Set[str] = {
    SGNodeType.SAST_FINDING,
    SGNodeType.DEPENDENCY_CVE,
}

# IAM node type mappings from IAMGraph node_type strings
_IAM_NODE_TYPE_MAP: Dict[str, SGNodeType] = {
    "IDENTITY":        SGNodeType.IAM_IDENTITY,
    "ROLE":            SGNodeType.IAM_ROLE,
    "POLICY":          SGNodeType.IAM_ROLE,          # policies act like roles in the SG
    "PERMISSION":      SGNodeType.IAM_PERMISSION,
    "RESOURCE":        SGNodeType.CLOUD_RESOURCE,
    "CLUSTER_ROLE":    SGNodeType.IAM_ROLE,
    "SERVICE_ACCOUNT": SGNodeType.IAM_IDENTITY,
}

# IAM edge relation mappings
_IAM_EDGE_MAP: Dict[str, str] = {
    "HAS_ROLE":      "BOUND_TO",
    "GRANTS":        "GRANTS",
    "APPLIES_TO":    "ACCESSES",
    "ASSUMES":       "BOUND_TO",
    "BOUND_TO":      "BOUND_TO",
    "ESCALATES_TO":  "ESCALATES_TO",
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class SGNode:
    node_id: str
    node_type: SGNodeType
    label: str
    severity: str = "INFO"            # CRITICAL | HIGH | MEDIUM | LOW | INFO
    layer: str = "unknown"            # code | runtime | identity | cloud | business
    properties: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "node_type": self.node_type.value,
            "label": self.label,
            "severity": self.severity,
            "layer": self.layer,
            "properties": self.properties,
        }


@dataclass
class SGEdge:
    from_id: str
    to_id: str
    relation: str   # REACHES | RUNS_ON | BOUND_TO | ACCESSES | CONTROLS | EXPOSES | ESCALATES_TO | GRANTS
    weight: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "from_id": self.from_id,
            "to_id": self.to_id,
            "relation": self.relation,
            "weight": self.weight,
        }


@dataclass
class AttackPath:
    path_id: str
    nodes: List[str]           # ordered node_ids
    node_labels: List[str]     # human-readable labels
    layers: List[str]          # layers traversed (de-duplicated, ordered)
    severity: str              # highest severity across all nodes in path
    attack_type: str           # CLOUD_ATTACK | PRIVILEGE_ESCALATION | LATERAL_MOVEMENT | DATA_EXFILTRATION
    description: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path_id": self.path_id,
            "nodes": self.nodes,
            "node_labels": self.node_labels,
            "layers": self.layers,
            "severity": self.severity,
            "attack_type": self.attack_type,
            "description": self.description,
        }


# ---------------------------------------------------------------------------
# Unified Security Graph
# ---------------------------------------------------------------------------


class UnifiedSecurityGraph:
    """Connects code findings → dependencies → runtime → cloud → identity → resources
    into a single directed graph and finds cross-layer attack paths.
    """

    def __init__(self) -> None:
        self._nodes: Dict[str, SGNode] = {}
        self._edges: List[SGEdge] = []
        # Adjacency list (node_id → list of neighbour node_ids), updated on every _add_edge call
        self._adj: Dict[str, List[str]] = {}
        self._path_counter: int = 0

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _make_node_id(self, node_type: SGNodeType, label: str) -> str:
        """Generate a stable node ID from type + label."""
        safe = label.lower().replace(" ", "_").replace("/", "_").replace(":", "_")
        return f"{node_type.value}:{safe}"

    def _add_node(
        self,
        node_id: str,
        node_type: SGNodeType,
        label: str,
        severity: str = "INFO",
        **props: Any,
    ) -> SGNode:
        """Add node or return existing; updates severity to highest seen."""
        if node_id not in self._nodes:
            layer = _LAYER_OF.get(node_type.value, "unknown")
            self._nodes[node_id] = SGNode(
                node_id=node_id,
                node_type=node_type,
                label=label,
                severity=severity,
                layer=layer,
                properties=dict(props),
            )
            self._adj.setdefault(node_id, [])
        else:
            # Escalate severity if the new evidence is more severe
            existing = self._nodes[node_id]
            if _SEV_ORDER.get(severity, 0) > _SEV_ORDER.get(existing.severity, 0):
                existing.severity = severity
            # Merge properties
            existing.properties.update(props)
        return self._nodes[node_id]

    def _add_edge(
        self,
        from_id: str,
        to_id: str,
        relation: str,
        weight: float = 1.0,
    ) -> SGEdge:
        """Add directed edge; deduplicates by (from_id, to_id, relation)."""
        for existing in self._edges:
            if existing.from_id == from_id and existing.to_id == to_id and existing.relation == relation:
                return existing
        edge = SGEdge(from_id=from_id, to_id=to_id, relation=relation, weight=weight)
        self._edges.append(edge)
        self._adj.setdefault(from_id, [])
        self._adj.setdefault(to_id, [])
        if to_id not in self._adj[from_id]:
            self._adj[from_id].append(to_id)
        return edge

    def _next_path_id(self) -> str:
        self._path_counter += 1
        return f"path_{self._path_counter:04d}"

    # ------------------------------------------------------------------
    # Ingestion — SAST findings
    # ------------------------------------------------------------------

    def ingest_sast_findings(self, findings: List[Dict[str, Any]]) -> int:
        """Ingest SAST findings.

        Each finding dict must contain: rule_id, severity, file, description.
        Optional: cwe.

        Creates a SAST_FINDING node per finding.
        Returns the count of new nodes added.
        """
        before = len(self._nodes)
        for f in findings:
            rule_id = str(f.get("rule_id", "UNKNOWN"))
            severity = str(f.get("severity", "MEDIUM")).upper()
            file_path = str(f.get("file", ""))
            description = str(f.get("description", ""))
            cwe = str(f.get("cwe", ""))

            # Node label: combine rule_id with file basename for readability
            import os as _os
            basename = _os.path.basename(file_path) if file_path else "unknown"
            label = f"{rule_id}@{basename}"
            node_id = self._make_node_id(SGNodeType.SAST_FINDING, label)

            self._add_node(
                node_id,
                SGNodeType.SAST_FINDING,
                label,
                severity=severity,
                rule_id=rule_id,
                file=file_path,
                description=description,
                cwe=cwe,
            )

        return len(self._nodes) - before

    # ------------------------------------------------------------------
    # Ingestion — CVE / dependency findings
    # ------------------------------------------------------------------

    def ingest_cve_findings(self, findings: List[Dict[str, Any]]) -> int:
        """Ingest CVE / dependency findings.

        Each finding dict: cve_id (or id), cvss, severity, package, description.
        Creates a DEPENDENCY_CVE node.
        Adds a REACHES edge from any SAST_FINDING that has a matching CWE.

        Returns the count of new nodes added.
        """
        before = len(self._nodes)

        # Build CWE → SAST_FINDING node map for heuristic linking
        cwe_to_sast: Dict[str, List[str]] = {}
        for nid, n in self._nodes.items():
            if n.node_type == SGNodeType.SAST_FINDING:
                cwe = n.properties.get("cwe", "")
                if cwe:
                    cwe_to_sast.setdefault(cwe, []).append(nid)

        for f in findings:
            cve_id = str(f.get("cve_id") or f.get("id", "CVE-UNKNOWN"))
            cvss = float(f.get("cvss", 0.0))
            severity = str(f.get("severity", "MEDIUM")).upper()
            package = str(f.get("package", "unknown"))
            description = str(f.get("description", ""))

            label = f"{cve_id}:{package}"
            node_id = self._make_node_id(SGNodeType.DEPENDENCY_CVE, label)

            self._add_node(
                node_id,
                SGNodeType.DEPENDENCY_CVE,
                label,
                severity=severity,
                cve_id=cve_id,
                cvss=cvss,
                package=package,
                description=description,
            )

            # Heuristic: link CVEs to SAST findings via CWE
            # CVE-related CWEs are commonly mapped by NIST; we check if any SAST
            # finding references a CWE that often corresponds to memory/injection
            # vulnerabilities matching the CVE package context.
            for cwe, sast_ids in cwe_to_sast.items():
                # CWE-79 (XSS), CWE-89 (SQLi), CWE-119 (buffer overflow), etc.
                # Simple heuristic: if the package name appears in any SAST finding's file
                for sast_id in sast_ids:
                    sast_node = self._nodes.get(sast_id)
                    if sast_node:
                        sast_file = sast_node.properties.get("file", "")
                        if package and package.lower() in sast_file.lower():
                            self._add_edge(sast_id, node_id, "REACHES", weight=0.6)

        return len(self._nodes) - before

    # ------------------------------------------------------------------
    # Ingestion — IAMGraph
    # ------------------------------------------------------------------

    def ingest_iam_graph(self, iam_graph: "IAMGraph") -> int:
        """Import IAM graph nodes and edges into the unified security graph.

        IAM node types are mapped to SGNodeType:
          IDENTITY / SERVICE_ACCOUNT → IAM_IDENTITY
          ROLE / POLICY / CLUSTER_ROLE → IAM_ROLE
          PERMISSION → IAM_PERMISSION
          RESOURCE → CLOUD_RESOURCE

        IAM edge relations are mapped to SG relations.

        Returns the count of new nodes added.
        """
        before = len(self._nodes)

        # Import nodes
        for iam_node in iam_graph._nodes.values():
            sg_type = _IAM_NODE_TYPE_MAP.get(iam_node.node_type, SGNodeType.CLOUD_RESOURCE)
            # Derive severity from properties if available
            severity = iam_node.properties.get("severity", "INFO")
            if not severity or severity not in _SEV_ORDER:
                severity = "INFO"

            sg_node_id = f"iam:{iam_node.node_id}"
            self._add_node(
                sg_node_id,
                sg_type,
                iam_node.label,
                severity=severity,
                iam_node_id=iam_node.node_id,
                cloud_provider=iam_node.cloud_provider,
                **{k: v for k, v in iam_node.properties.items() if k not in ("severity",)},
            )

        # Import edges
        for iam_edge in iam_graph._edges:
            from_sg_id = f"iam:{iam_edge.from_id}"
            to_sg_id = f"iam:{iam_edge.to_id}"
            relation = _IAM_EDGE_MAP.get(iam_edge.relation, iam_edge.relation)
            # Only add edge if both endpoints were imported
            if from_sg_id in self._nodes and to_sg_id in self._nodes:
                self._add_edge(from_sg_id, to_sg_id, relation)

        return len(self._nodes) - before

    # ------------------------------------------------------------------
    # Ingestion — Kubernetes findings
    # ------------------------------------------------------------------

    def ingest_k8s_findings(self, findings: List[Dict[str, Any]]) -> int:
        """Ingest Kubernetes security findings.

        Each finding: rule_id, severity, resource_kind, resource_name, namespace, description.
        Creates K8S_POD/K8S_NAMESPACE nodes.

        Returns the count of new nodes added.
        """
        before = len(self._nodes)

        for f in findings:
            severity = str(f.get("severity", "MEDIUM")).upper()
            resource_kind = str(f.get("resource_kind", "Pod"))
            resource_name = str(f.get("resource_name", "unknown"))
            namespace = str(f.get("namespace", "default"))
            description = str(f.get("description", ""))
            rule_id = str(f.get("rule_id", "K8S-UNKNOWN"))

            # Namespace node (one per namespace)
            ns_label = f"ns:{namespace}"
            ns_id = self._make_node_id(SGNodeType.K8S_NAMESPACE, ns_label)
            self._add_node(ns_id, SGNodeType.K8S_NAMESPACE, ns_label, severity="INFO", namespace=namespace)

            # Pod / workload node
            kind_lower = resource_kind.lower()
            if kind_lower in ("service", "ingress"):
                pod_type = SGNodeType.K8S_SERVICE
            else:
                pod_type = SGNodeType.K8S_POD

            pod_label = f"{resource_kind}/{resource_name}"
            pod_id = self._make_node_id(pod_type, f"{namespace}:{resource_name}")
            self._add_node(
                pod_id,
                pod_type,
                pod_label,
                severity=severity,
                rule_id=rule_id,
                namespace=namespace,
                resource_kind=resource_kind,
                resource_name=resource_name,
                description=description,
            )

            # Pod runs inside namespace
            self._add_edge(pod_id, ns_id, "RUNS_ON")

            # Link to container node if one exists with matching name
            container_id = self._make_node_id(SGNodeType.CONTAINER, resource_name)
            if container_id in self._nodes:
                self._add_edge(container_id, pod_id, "RUNS_ON")

        return len(self._nodes) - before

    # ------------------------------------------------------------------
    # Ingestion — container findings
    # ------------------------------------------------------------------

    def ingest_container_findings(self, findings: List[Dict[str, Any]]) -> int:
        """Ingest container/image vulnerability findings.

        Each finding: severity, image, vulnerability_id, package, description.
        Creates CONTAINER_IMAGE nodes.
        Links DEPENDENCY_CVE → RUNS_ON → CONTAINER if CVE ID matches.

        Returns the count of new nodes added.
        """
        before = len(self._nodes)

        # Build CVE-id → DEPENDENCY_CVE node id map
        cve_id_to_node: Dict[str, str] = {}
        for nid, n in self._nodes.items():
            if n.node_type == SGNodeType.DEPENDENCY_CVE:
                cve_id = n.properties.get("cve_id", "")
                if cve_id:
                    cve_id_to_node[cve_id] = nid

        for f in findings:
            severity = str(f.get("severity", "MEDIUM")).upper()
            image = str(f.get("image", "unknown-image"))
            vuln_id = str(f.get("vulnerability_id", ""))
            package = str(f.get("package", ""))
            description = str(f.get("description", ""))

            # Container image node
            img_label = image
            img_id = self._make_node_id(SGNodeType.CONTAINER_IMAGE, image)
            self._add_node(
                img_id,
                SGNodeType.CONTAINER_IMAGE,
                img_label,
                severity=severity,
                image=image,
                vulnerability_id=vuln_id,
                package=package,
                description=description,
            )

            # Container runtime node (logical container using this image)
            container_label = f"container:{image}"
            container_id = self._make_node_id(SGNodeType.CONTAINER, image)
            self._add_node(
                container_id,
                SGNodeType.CONTAINER,
                container_label,
                severity=severity,
                image=image,
            )
            # Container uses this image
            self._add_edge(container_id, img_id, "RUNS_ON")

            # Link CVE → container if the vuln_id matches an existing CVE node
            if vuln_id and vuln_id in cve_id_to_node:
                self._add_edge(cve_id_to_node[vuln_id], container_id, "RUNS_ON")

        return len(self._nodes) - before

    # ------------------------------------------------------------------
    # Ingestion — cloud misconfigurations
    # ------------------------------------------------------------------

    def ingest_cloud_misconfigs(self, findings: List[Dict[str, Any]]) -> int:
        """Ingest cloud misconfiguration findings.

        Each finding: rule_id, severity, resource_type, resource_name, description.
        Optional: public_access (bool).

        Creates CLOUD_RESOURCE / CLOUD_STORAGE / CLOUD_DATABASE nodes.
        Adds EXPOSES edge (from node to itself / from identity to resource) if public_access=True.

        Returns the count of new nodes added.
        """
        before = len(self._nodes)

        _resource_type_map = {
            "s3":         SGNodeType.CLOUD_STORAGE,
            "bucket":     SGNodeType.CLOUD_STORAGE,
            "storage":    SGNodeType.CLOUD_STORAGE,
            "gcs":        SGNodeType.CLOUD_STORAGE,
            "blob":       SGNodeType.CLOUD_STORAGE,
            "rds":        SGNodeType.CLOUD_DATABASE,
            "database":   SGNodeType.CLOUD_DATABASE,
            "db":         SGNodeType.CLOUD_DATABASE,
            "dynamodb":   SGNodeType.CLOUD_DATABASE,
            "sql":        SGNodeType.CLOUD_DATABASE,
            "vpc":        SGNodeType.CLOUD_NETWORK,
            "network":    SGNodeType.CLOUD_NETWORK,
            "subnet":     SGNodeType.CLOUD_NETWORK,
            "sg":         SGNodeType.CLOUD_NETWORK,
            "security_group": SGNodeType.CLOUD_NETWORK,
        }

        for f in findings:
            severity = str(f.get("severity", "MEDIUM")).upper()
            resource_type = str(f.get("resource_type", "resource")).lower()
            resource_name = str(f.get("resource_name", "unknown"))
            description = str(f.get("description", ""))
            rule_id = str(f.get("rule_id", "CLOUD-UNKNOWN"))
            public_access = bool(f.get("public_access", False))

            # Determine node type from resource_type string
            sg_type = SGNodeType.CLOUD_RESOURCE
            for keyword, mapped_type in _resource_type_map.items():
                if keyword in resource_type:
                    sg_type = mapped_type
                    break

            label = f"{resource_type}:{resource_name}"
            node_id = self._make_node_id(sg_type, label)
            self._add_node(
                node_id,
                sg_type,
                label,
                severity=severity,
                rule_id=rule_id,
                resource_type=resource_type,
                resource_name=resource_name,
                description=description,
                public_access=public_access,
            )

            if public_access:
                # Represent public exposure as a self-loop EXPOSES edge (pattern used for queries)
                self._add_edge(node_id, node_id, "EXPOSES", weight=2.0)

        return len(self._nodes) - before

    # ------------------------------------------------------------------
    # Manual link helpers
    # ------------------------------------------------------------------

    def link_sast_to_container(self, sast_file: str, container_name: str) -> None:
        """Add a REACHES edge from a SAST_FINDING node for sast_file to a CONTAINER node."""
        # Find SAST_FINDING nodes with matching file
        for nid, n in self._nodes.items():
            if n.node_type == SGNodeType.SAST_FINDING and n.properties.get("file", "") == sast_file:
                container_id = self._make_node_id(SGNodeType.CONTAINER, container_name)
                if container_id not in self._nodes:
                    self._add_node(container_id, SGNodeType.CONTAINER, f"container:{container_name}", container=container_name)
                self._add_edge(nid, container_id, "REACHES")
                return

    def link_container_to_iam(self, container_name: str, iam_identity: str) -> None:
        """Add a BOUND_TO edge from a CONTAINER node to an IAM_IDENTITY node."""
        container_id = self._make_node_id(SGNodeType.CONTAINER, container_name)
        if container_id not in self._nodes:
            self._add_node(container_id, SGNodeType.CONTAINER, f"container:{container_name}", container=container_name)

        # Try to find an IAM_IDENTITY node with matching label
        iam_id: Optional[str] = None
        for nid, n in self._nodes.items():
            if n.node_type == SGNodeType.IAM_IDENTITY and n.label.lower() == iam_identity.lower():
                iam_id = nid
                break

        if iam_id is None:
            # Create a placeholder IAM identity node
            iam_id = self._make_node_id(SGNodeType.IAM_IDENTITY, iam_identity)
            self._add_node(iam_id, SGNodeType.IAM_IDENTITY, iam_identity, severity="INFO")

        self._add_edge(container_id, iam_id, "BOUND_TO")

    def link_iam_to_resource(self, iam_identity: str, resource_name: str) -> None:
        """Add an ACCESSES edge from an IAM_IDENTITY node to a CLOUD_RESOURCE node."""
        # Find or create IAM_IDENTITY
        iam_id: Optional[str] = None
        for nid, n in self._nodes.items():
            if n.node_type == SGNodeType.IAM_IDENTITY and n.label.lower() == iam_identity.lower():
                iam_id = nid
                break
        if iam_id is None:
            iam_id = self._make_node_id(SGNodeType.IAM_IDENTITY, iam_identity)
            self._add_node(iam_id, SGNodeType.IAM_IDENTITY, iam_identity)

        # Find or create CLOUD_RESOURCE
        resource_id: Optional[str] = None
        for nid, n in self._nodes.items():
            if n.node_type in (
                SGNodeType.CLOUD_RESOURCE, SGNodeType.CLOUD_STORAGE, SGNodeType.CLOUD_DATABASE
            ) and n.label.lower() == resource_name.lower():
                resource_id = nid
                break
        if resource_id is None:
            resource_id = self._make_node_id(SGNodeType.CLOUD_RESOURCE, resource_name)
            self._add_node(resource_id, SGNodeType.CLOUD_RESOURCE, resource_name)

        self._add_edge(iam_id, resource_id, "ACCESSES")

    # ------------------------------------------------------------------
    # Analysis — cloud attack paths (BFS)
    # ------------------------------------------------------------------

    def find_cloud_attack_paths(self) -> List[AttackPath]:
        """BFS from SAST_FINDING/DEPENDENCY_CVE nodes towards CLOUD/BUSINESS targets.

        Rules:
        - Start nodes: SAST_FINDING, DEPENDENCY_CVE
        - Target nodes: CLOUD_RESOURCE, CLOUD_STORAGE, CLOUD_DATABASE, BUSINESS_ASSET
        - Max BFS depth: 8
        - A path is kept only if it crosses ≥ 2 distinct layers
        - Deduplicate by (start_node_id, end_node_id)

        Returns a list of AttackPath objects.
        """
        results: List[AttackPath] = []
        seen_pairs: Set[tuple] = set()

        source_ids = [
            nid for nid, n in self._nodes.items()
            if n.node_type.value in _CODE_SOURCE_TYPES
        ]

        for start_id in source_ids:
            # BFS: queue entries = (current_node_id, path_node_ids_list)
            queue: deque = deque()
            queue.append((start_id, [start_id]))
            visited_from_start: Set[str] = set()

            while queue:
                current_id, path_so_far = queue.popleft()

                if len(path_so_far) > 8:
                    continue

                current_node = self._nodes.get(current_id)
                if current_node is None:
                    continue

                # Check if we reached a target
                if current_node.node_type.value in _CLOUD_TARGET_TYPES and len(path_so_far) > 1:
                    pair = (start_id, current_id)
                    if pair not in seen_pairs:
                        seen_pairs.add(pair)

                        # Collect layers traversed
                        path_layers_ordered: List[str] = []
                        seen_layers: Set[str] = set()
                        path_sev = "INFO"
                        node_labels: List[str] = []
                        for nid in path_so_far:
                            n = self._nodes.get(nid)
                            if n is None:
                                continue
                            node_labels.append(n.label)
                            path_sev = _higher_severity(path_sev, n.severity)
                            layer = _LAYER_OF.get(n.node_type.value, "unknown")
                            if layer not in seen_layers:
                                seen_layers.add(layer)
                                path_layers_ordered.append(layer)

                        # Only keep paths crossing ≥ 2 layers
                        if len(path_layers_ordered) >= 2:
                            # Classify attack type
                            if "identity" in path_layers_ordered:
                                attack_type = "PRIVILEGE_ESCALATION"
                            elif "runtime" in path_layers_ordered:
                                attack_type = "LATERAL_MOVEMENT"
                            elif current_node.node_type in (SGNodeType.CLOUD_STORAGE, SGNodeType.CLOUD_DATABASE):
                                attack_type = "DATA_EXFILTRATION"
                            else:
                                attack_type = "CLOUD_ATTACK"

                            start_node = self._nodes[start_id]
                            end_node = current_node
                            description = (
                                f"Attack path from {start_node.node_type.value} "
                                f"'{start_node.label}' through {len(path_so_far)} nodes "
                                f"(layers: {' → '.join(path_layers_ordered)}) "
                                f"to {end_node.node_type.value} '{end_node.label}'."
                            )

                            results.append(
                                AttackPath(
                                    path_id=self._next_path_id(),
                                    nodes=list(path_so_far),
                                    node_labels=node_labels,
                                    layers=path_layers_ordered,
                                    severity=path_sev,
                                    attack_type=attack_type,
                                    description=description,
                                )
                            )
                    # Don't explore deeper from target nodes
                    continue

                # Expand neighbours
                if current_id in visited_from_start:
                    continue
                visited_from_start.add(current_id)

                for neighbour_id in self._adj.get(current_id, []):
                    if neighbour_id not in path_so_far:  # avoid cycles
                        queue.append((neighbour_id, path_so_far + [neighbour_id]))

        # Sort by severity descending
        results.sort(key=lambda p: _SEV_ORDER.get(p.severity, 0), reverse=True)
        return results

    # ------------------------------------------------------------------
    # Analysis — exposed resources
    # ------------------------------------------------------------------

    def find_exposed_resources(self) -> List[Dict[str, Any]]:
        """Find cloud resources that are publicly exposed or critically/highly vulnerable.

        A resource is flagged if:
        - It has an EXPOSES self-loop (public_access=True during ingestion)
        - Its severity is CRITICAL or HIGH

        Returns list of {"resource_id", "label", "resource_type", "severity", "reason"}.
        """
        results: List[Dict[str, Any]] = []
        cloud_types = {
            SGNodeType.CLOUD_RESOURCE, SGNodeType.CLOUD_STORAGE,
            SGNodeType.CLOUD_DATABASE, SGNodeType.CLOUD_NETWORK,
        }

        # Collect nodes that have EXPOSES self-loop
        exposed_ids: Set[str] = set()
        for edge in self._edges:
            if edge.relation == "EXPOSES":
                exposed_ids.add(edge.from_id)

        for nid, n in self._nodes.items():
            if n.node_type not in cloud_types:
                continue

            reasons: List[str] = []
            if nid in exposed_ids or n.properties.get("public_access"):
                reasons.append("publicly accessible (public_access=True)")
            if n.severity in ("CRITICAL", "HIGH"):
                reasons.append(f"severity={n.severity}")

            if reasons:
                results.append({
                    "resource_id": nid,
                    "label": n.label,
                    "resource_type": n.node_type.value,
                    "severity": n.severity,
                    "reason": "; ".join(reasons),
                })

        results.sort(key=lambda r: _SEV_ORDER.get(r["severity"], 0), reverse=True)
        return results

    # ------------------------------------------------------------------
    # Analysis — privilege escalation paths
    # ------------------------------------------------------------------

    def find_privilege_escalation_paths(self) -> List[AttackPath]:
        """Find paths: IAM_IDENTITY → ESCALATES_TO → IAM_ROLE → ACCESSES → CLOUD_RESOURCE.

        Returns a list of AttackPath objects for privilege escalation chains.
        """
        results: List[AttackPath] = []

        # Find all ESCALATES_TO edges
        for edge in self._edges:
            if edge.relation != "ESCALATES_TO":
                continue

            identity_id = edge.from_id
            role_id = edge.to_id

            identity_node = self._nodes.get(identity_id)
            role_node = self._nodes.get(role_id)
            if identity_node is None or role_node is None:
                continue

            # Find ACCESSES edges from the role to cloud resources
            for edge2 in self._edges:
                if edge2.from_id != role_id or edge2.relation not in ("ACCESSES", "GRANTS", "BOUND_TO"):
                    continue

                target_node = self._nodes.get(edge2.to_id)
                if target_node is None:
                    continue
                if target_node.node_type not in (
                    SGNodeType.CLOUD_RESOURCE, SGNodeType.CLOUD_STORAGE,
                    SGNodeType.CLOUD_DATABASE, SGNodeType.IAM_PERMISSION,
                ):
                    continue

                path_nodes = [identity_id, role_id, edge2.to_id]
                path_labels = [identity_node.label, role_node.label, target_node.label]
                path_sev = _higher_severity(
                    _higher_severity(identity_node.severity, role_node.severity),
                    target_node.severity,
                )

                layers = []
                for nid in path_nodes:
                    n = self._nodes[nid]
                    layer = _LAYER_OF.get(n.node_type.value, "unknown")
                    if not layers or layers[-1] != layer:
                        layers.append(layer)

                description = (
                    f"Privilege escalation: identity '{identity_node.label}' "
                    f"escalates to role '{role_node.label}' and gains access to "
                    f"'{target_node.label}'."
                )

                results.append(
                    AttackPath(
                        path_id=self._next_path_id(),
                        nodes=path_nodes,
                        node_labels=path_labels,
                        layers=layers,
                        severity=path_sev,
                        attack_type="PRIVILEGE_ESCALATION",
                        description=description,
                    )
                )

        results.sort(key=lambda p: _SEV_ORDER.get(p.severity, 0), reverse=True)
        return results

    # ------------------------------------------------------------------
    # Analysis — reachable cloud assets from code
    # ------------------------------------------------------------------

    def find_reachable_cloud_assets(self) -> List[Dict[str, Any]]:
        """Find all CLOUD_* nodes reachable from any SAST_FINDING via graph traversal.

        Returns list of {"node_id", "label", "node_type", "reachable_from", "path_length"}.
        """
        cloud_types = {
            SGNodeType.CLOUD_RESOURCE, SGNodeType.CLOUD_STORAGE,
            SGNodeType.CLOUD_DATABASE, SGNodeType.CLOUD_NETWORK,
            SGNodeType.BUSINESS_ASSET,
        }

        results: List[Dict[str, Any]] = []
        seen_pairs: Set[tuple] = set()

        source_ids = [
            nid for nid, n in self._nodes.items()
            if n.node_type == SGNodeType.SAST_FINDING
        ]

        for start_id in source_ids:
            start_node = self._nodes[start_id]
            # BFS with depth tracking
            queue: deque = deque([(start_id, 0)])
            visited: Set[str] = {start_id}

            while queue:
                current_id, depth = queue.popleft()
                if depth > 10:
                    continue

                current_node = self._nodes.get(current_id)
                if current_node is None:
                    continue

                if current_node.node_type in cloud_types and current_id != start_id:
                    pair = (start_id, current_id)
                    if pair not in seen_pairs:
                        seen_pairs.add(pair)
                        results.append({
                            "node_id": current_id,
                            "label": current_node.label,
                            "node_type": current_node.node_type.value,
                            "reachable_from": start_node.label,
                            "path_length": depth,
                        })

                for neighbour_id in self._adj.get(current_id, []):
                    if neighbour_id not in visited:
                        visited.add(neighbour_id)
                        queue.append((neighbour_id, depth + 1))

        results.sort(key=lambda r: r["path_length"])
        return results

    # ------------------------------------------------------------------
    # Analysis — container risks
    # ------------------------------------------------------------------

    def find_container_risks(self) -> List[Dict[str, Any]]:
        """Find CONTAINER and CONTAINER_IMAGE nodes with HIGH or CRITICAL severity.

        Returns list of {"node_id", "label", "node_type", "severity", "properties"}.
        """
        results: List[Dict[str, Any]] = []
        for nid, n in self._nodes.items():
            if n.node_type not in (SGNodeType.CONTAINER, SGNodeType.CONTAINER_IMAGE):
                continue
            if n.severity not in ("HIGH", "CRITICAL"):
                continue
            results.append({
                "node_id": nid,
                "label": n.label,
                "node_type": n.node_type.value,
                "severity": n.severity,
                "properties": n.properties,
            })
        results.sort(key=lambda r: _SEV_ORDER.get(r["severity"], 0), reverse=True)
        return results

    # ------------------------------------------------------------------
    # Analysis — Kubernetes risks
    # ------------------------------------------------------------------

    def find_kubernetes_risks(self) -> List[Dict[str, Any]]:
        """Find K8S_POD and K8S_NAMESPACE nodes with HIGH or CRITICAL severity.

        Returns list of {"node_id", "label", "node_type", "severity", "properties"}.
        """
        results: List[Dict[str, Any]] = []
        for nid, n in self._nodes.items():
            if n.node_type not in (SGNodeType.K8S_POD, SGNodeType.K8S_NAMESPACE, SGNodeType.K8S_SERVICE):
                continue
            if n.severity not in ("HIGH", "CRITICAL"):
                continue
            results.append({
                "node_id": nid,
                "label": n.label,
                "node_type": n.node_type.value,
                "severity": n.severity,
                "properties": n.properties,
            })
        results.sort(key=lambda r: _SEV_ORDER.get(r["severity"], 0), reverse=True)
        return results

    # ------------------------------------------------------------------
    # Analysis — business critical findings
    # ------------------------------------------------------------------

    def find_business_critical_findings(self) -> List[Dict[str, Any]]:
        """Find paths that reach BUSINESS_ASSET nodes.

        Returns list of {"business_asset_id", "label", "severity",
                          "reachable_from_count", "reaching_paths"}.
        """
        business_nodes = {
            nid: n for nid, n in self._nodes.items()
            if n.node_type == SGNodeType.BUSINESS_ASSET
        }

        if not business_nodes:
            return []

        # Reverse adjacency: for each business asset, find what can reach it
        # Build reverse adj list
        rev_adj: Dict[str, List[str]] = {nid: [] for nid in self._nodes}
        for edge in self._edges:
            rev_adj.setdefault(edge.to_id, []).append(edge.from_id)

        results: List[Dict[str, Any]] = []

        for ba_id, ba_node in business_nodes.items():
            # BFS backwards from business asset
            reaching_ids: Set[str] = set()
            queue: deque = deque([ba_id])
            visited: Set[str] = {ba_id}

            while queue:
                current = queue.popleft()
                for predecessor in rev_adj.get(current, []):
                    if predecessor not in visited:
                        visited.add(predecessor)
                        reaching_ids.add(predecessor)
                        queue.append(predecessor)

            reaching_paths: List[Dict[str, Any]] = []
            for rid in reaching_ids:
                n = self._nodes.get(rid)
                if n and n.severity in ("CRITICAL", "HIGH"):
                    reaching_paths.append({
                        "node_id": rid,
                        "label": n.label,
                        "node_type": n.node_type.value,
                        "severity": n.severity,
                    })

            results.append({
                "business_asset_id": ba_id,
                "label": ba_node.label,
                "severity": ba_node.severity,
                "reachable_from_count": len(reaching_ids),
                "reaching_paths": reaching_paths,
            })

        results.sort(key=lambda r: len(r["reaching_paths"]), reverse=True)
        return results

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def node_count(self) -> int:
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        return len(self._edges)

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        """Return a complete dict representation of the unified security graph."""
        cloud_attack_paths = self.find_cloud_attack_paths()
        priv_esc_paths = self.find_privilege_escalation_paths()
        return {
            "node_count": self.node_count,
            "edge_count": self.edge_count,
            "nodes": [n.to_dict() for n in self._nodes.values()],
            "edges": [e.to_dict() for e in self._edges],
            "cloud_attack_paths": [p.to_dict() for p in cloud_attack_paths],
            "privilege_escalation_paths": [p.to_dict() for p in priv_esc_paths],
            "exposed_resources": self.find_exposed_resources(),
            "reachable_cloud_assets": self.find_reachable_cloud_assets(),
            "container_risks": self.find_container_risks(),
            "kubernetes_risks": self.find_kubernetes_risks(),
            "business_critical_findings": self.find_business_critical_findings(),
        }
