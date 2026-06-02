"""IAM Identity Graph — builds an IAM identity/role/permission/resource graph from
IAMFinding objects and raw AWS IAM policy documents, then detects privilege
escalation paths and overprivileged identities.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Set

from backend.scanners.iam_scanner import IAMFinding

# ---------------------------------------------------------------------------
# Dangerous permission combos that enable privilege escalation
# ---------------------------------------------------------------------------

DANGEROUS_COMBOS: Dict[str, List[str]] = {
    "create_role_and_attach_policy": ["iam:PassRole", "iam:CreateRole"],
    "attach_policy_via_pass_role": ["iam:PassRole", "iam:AttachRolePolicy"],
    "direct_policy_injection": ["iam:PutUserPolicy"],
    "role_policy_injection": ["iam:PutRolePolicy"],
    "create_console_profile": ["iam:CreateLoginProfile"],
    "lambda_execution_with_role": ["iam:PassRole", "lambda:CreateFunction"],
    "update_assume_role_policy": ["iam:UpdateAssumeRolePolicy"],
}

# Admin-level permission prefixes / exact patterns
_ADMIN_PATTERNS: Set[str] = {
    "*",
    "iam:*",
    "s3:*",
    "ec2:*",
    "lambda:*",
    "sts:*",
    "cloudformation:*",
    "organizations:*",
    "kms:*",
    "secretsmanager:*",
}

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class IAMNode:
    node_id: str
    node_type: str  # IDENTITY | ROLE | PERMISSION | RESOURCE | POLICY | CLUSTER_ROLE | SERVICE_ACCOUNT
    label: str
    cloud_provider: str  # aws | gcp | azure | k8s
    properties: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "node_type": self.node_type,
            "label": self.label,
            "cloud_provider": self.cloud_provider,
            "properties": self.properties,
        }


@dataclass
class IAMEdge:
    from_id: str
    to_id: str
    relation: str  # HAS_ROLE | GRANTS | APPLIES_TO | ASSUMES | BOUND_TO | ESCALATES_TO
    properties: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "from_id": self.from_id,
            "to_id": self.to_id,
            "relation": self.relation,
            "properties": self.properties,
        }


# ---------------------------------------------------------------------------
# Core graph
# ---------------------------------------------------------------------------


class IAMGraph:
    """Builds and analyses an IAM graph from findings and raw policy documents."""

    def __init__(self) -> None:
        self._nodes: Dict[str, IAMNode] = {}
        self._edges: List[IAMEdge] = []

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _make_node_id(self, cloud_provider: str, node_type: str, label: str) -> str:
        """Generate a stable, deterministic node ID."""
        safe_label = label.lower().replace(" ", "_").replace("/", "_").replace(":", "_")
        return f"{cloud_provider}:{node_type.lower()}:{safe_label}"

    def _add_node(
        self,
        node_id: str,
        node_type: str,
        label: str,
        cloud_provider: str,
        **props: Any,
    ) -> IAMNode:
        """Add a node (or return existing one if node_id already registered)."""
        if node_id not in self._nodes:
            self._nodes[node_id] = IAMNode(
                node_id=node_id,
                node_type=node_type,
                label=label,
                cloud_provider=cloud_provider,
                properties=dict(props),
            )
        return self._nodes[node_id]

    def _add_edge(
        self,
        from_id: str,
        to_id: str,
        relation: str,
        **props: Any,
    ) -> IAMEdge:
        """Add a directed edge.  Duplicate (from, to, relation) triples are
        collapsed so the graph stays clean even when the same policy is
        ingested multiple times."""
        for existing in self._edges:
            if (
                existing.from_id == from_id
                and existing.to_id == to_id
                and existing.relation == relation
            ):
                return existing
        edge = IAMEdge(from_id=from_id, to_id=to_id, relation=relation, properties=dict(props))
        self._edges.append(edge)
        return edge

    # ------------------------------------------------------------------
    # Ingestion — IAMFinding objects
    # ------------------------------------------------------------------

    def ingest_findings(self, findings: List[IAMFinding]) -> int:
        """Ingest IAMFinding objects.

        For each finding that carries a non-empty *principal* and *permission*
        we build:

          IDENTITY --(HAS_ROLE)--> POLICY --(GRANTS)--> PERMISSION

        If the finding also specifies a resource_type we add a RESOURCE node
        and a APPLIES_TO edge.

        Returns the count of *new* nodes added.
        """
        before = len(self._nodes)

        # Determine cloud provider from rule_id prefix
        def _provider_from_rule(rule_id: str) -> str:
            prefix = rule_id.upper()
            if "AWS" in prefix:
                return "aws"
            if "GCP" in prefix:
                return "gcp"
            if "AZ" in prefix:
                return "azure"
            if "K8S" in prefix or "TF" in prefix.replace("IAM-TF", "K8S"):
                return "k8s"
            return "aws"

        for finding in findings:
            principal = (finding.principal or "").strip()
            permission = (finding.permission or "").strip()

            # Skip findings without enough data to build meaningful graph nodes
            if not principal and not permission:
                continue

            provider = _provider_from_rule(finding.rule_id)

            # Determine category-based node types
            resource_type_raw = (finding.resource_type or "identity").lower()
            node_type_map = {
                "role": "ROLE",
                "policy": "POLICY",
                "user": "IDENTITY",
                "group": "IDENTITY",
                "service_account": "SERVICE_ACCOUNT",
            }
            principal_node_type = node_type_map.get(resource_type_raw, "IDENTITY")

            # --- Principal node ---
            if principal:
                principal_id = self._make_node_id(provider, principal_node_type, principal)
                self._add_node(
                    principal_id,
                    principal_node_type,
                    principal,
                    provider,
                    severity=finding.severity,
                    category=finding.category,
                    source_rule=finding.rule_id,
                    source_file=finding.file,
                )

                # --- Permission node ---
                if permission:
                    perm_id = self._make_node_id(provider, "PERMISSION", permission)
                    self._add_node(
                        perm_id,
                        "PERMISSION",
                        permission,
                        provider,
                        category=finding.category,
                        severity=finding.severity,
                    )

                    # Link principal → permission
                    # If category implies escalation use ESCALATES_TO, else GRANTS
                    relation = (
                        "ESCALATES_TO"
                        if finding.category in ("OVERPRIVILEGE", "WILDCARD")
                        else "GRANTS"
                    )
                    self._add_edge(principal_id, perm_id, relation, rule_id=finding.rule_id)

        return len(self._nodes) - before

    # ------------------------------------------------------------------
    # Ingestion — raw AWS policy document
    # ------------------------------------------------------------------

    def ingest_aws_policy(
        self,
        policy_doc: Dict[str, Any],
        identity: str = "unknown",
    ) -> int:
        """Parse an AWS IAM policy document and build the graph.

        Graph shape per Statement::

            IDENTITY --(HAS_ROLE)--> POLICY
                                        |
                                     (GRANTS)
                                        v
                                   PERMISSION --(APPLIES_TO)--> RESOURCE

        Returns the number of new nodes added.
        """
        before = len(self._nodes)

        # Identity node
        identity_id = self._make_node_id("aws", "IDENTITY", identity)
        self._add_node(identity_id, "IDENTITY", identity, "aws")

        # Policy node — keyed by a synthetic name derived from the identity
        policy_label = f"{identity}_policy"
        policy_id = self._make_node_id("aws", "POLICY", policy_label)
        self._add_node(policy_id, "POLICY", policy_label, "aws")
        self._add_edge(identity_id, policy_id, "HAS_ROLE")

        statements = policy_doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
        if not isinstance(statements, list):
            statements = []

        for stmt_idx, stmt in enumerate(statements):
            effect = stmt.get("Effect", "Allow")
            if effect != "Allow":
                # Deny statements do not contribute positive permissions to the graph
                continue

            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            if not isinstance(actions, list):
                actions = []

            resources = stmt.get("Resource", ["*"])
            if isinstance(resources, str):
                resources = [resources]
            if not isinstance(resources, list):
                resources = []

            # Check for wildcard principal (public access)
            principal = stmt.get("Principal")
            is_public = False
            if principal == "*" or (
                isinstance(principal, dict)
                and (principal.get("AWS") == "*" or principal.get("Service") == "*")
            ):
                is_public = True

            for action in actions:
                action_str = str(action)
                perm_id = self._make_node_id("aws", "PERMISSION", action_str)
                self._add_node(
                    perm_id,
                    "PERMISSION",
                    action_str,
                    "aws",
                    is_wildcard=("*" in action_str),
                    public_access=is_public,
                )
                self._add_edge(policy_id, perm_id, "GRANTS")

                for resource in resources:
                    resource_str = str(resource)
                    res_id = self._make_node_id("aws", "RESOURCE", resource_str)
                    self._add_node(
                        res_id,
                        "RESOURCE",
                        resource_str,
                        "aws",
                        public_access=is_public,
                        is_wildcard=(resource_str == "*"),
                    )
                    self._add_edge(perm_id, res_id, "APPLIES_TO")

        return len(self._nodes) - before

    # ------------------------------------------------------------------
    # Ingestion — Kubernetes RBAC
    # ------------------------------------------------------------------

    def ingest_k8s_rbac(
        self,
        subject_name: str,
        role_name: str,
        permissions: List[str],
        resources: List[str],
    ) -> int:
        """Build a K8s RBAC sub-graph.

        Graph shape::

            SERVICE_ACCOUNT --(BOUND_TO)--> CLUSTER_ROLE
                                                  |
                                               (GRANTS)
                                                  v
                                            PERMISSION --(APPLIES_TO)--> RESOURCE

        Returns the number of new nodes added.
        """
        before = len(self._nodes)

        # Service account node
        sa_id = self._make_node_id("k8s", "SERVICE_ACCOUNT", subject_name)
        self._add_node(sa_id, "SERVICE_ACCOUNT", subject_name, "k8s")

        # Cluster role node
        cr_id = self._make_node_id("k8s", "CLUSTER_ROLE", role_name)
        self._add_node(
            cr_id,
            "CLUSTER_ROLE",
            role_name,
            "k8s",
            is_admin=(role_name.lower() == "cluster-admin"),
        )
        self._add_edge(sa_id, cr_id, "BOUND_TO")

        for perm in permissions:
            perm_id = self._make_node_id("k8s", "PERMISSION", perm)
            self._add_node(
                perm_id,
                "PERMISSION",
                perm,
                "k8s",
                is_wildcard=(perm == "*"),
            )
            self._add_edge(cr_id, perm_id, "GRANTS")

            for res in resources:
                res_id = self._make_node_id("k8s", "RESOURCE", res)
                self._add_node(
                    res_id,
                    "RESOURCE",
                    res,
                    "k8s",
                    is_wildcard=(res == "*"),
                )
                self._add_edge(perm_id, res_id, "APPLIES_TO")

        return len(self._nodes) - before

    # ------------------------------------------------------------------
    # Analysis — privilege escalation
    # ------------------------------------------------------------------

    def find_privilege_escalation_paths(self) -> List[Dict[str, Any]]:
        """Detect privilege escalation patterns across all identities in the graph.

        Patterns detected:

        * DANGEROUS_COMBOS — multi-permission combinations that enable escalation
        * K8s wildcard verbs / cluster-admin bindings

        Returns a list of finding dicts with keys:
            identity, permissions, escalation_type, severity, description
        """
        # Build a map: identity_node_id -> set of permissions it holds
        identity_perms: Dict[str, Set[str]] = {}

        # Walk edges: IDENTITY/SERVICE_ACCOUNT --(*)-> PERMISSION (direct or via POLICY/ROLE/CLUSTER_ROLE)
        # We do a two-hop BFS for each identity node.

        def _reachable_permissions(start_id: str) -> Set[str]:
            """BFS up to 3 hops to collect PERMISSION node labels reachable from start_id."""
            visited: Set[str] = set()
            queue: List[str] = [start_id]
            perms: Set[str] = set()
            while queue:
                nid = queue.pop()
                if nid in visited:
                    continue
                visited.add(nid)
                for edge in self._edges:
                    if edge.from_id != nid:
                        continue
                    target = self._nodes.get(edge.to_id)
                    if target is None:
                        continue
                    if target.node_type == "PERMISSION":
                        perms.add(target.label)
                    elif target.node_type in ("POLICY", "ROLE", "CLUSTER_ROLE"):
                        queue.append(target.node_id)
            return perms

        identity_types = {"IDENTITY", "SERVICE_ACCOUNT"}
        for node in self._nodes.values():
            if node.node_type in identity_types:
                identity_perms[node.node_id] = _reachable_permissions(node.node_id)

        results: List[Dict[str, Any]] = []

        for identity_id, perms in identity_perms.items():
            identity_label = self._nodes[identity_id].label
            provider = self._nodes[identity_id].cloud_provider
            # Normalise to lowercase for matching
            perms_lower = {p.lower() for p in perms}

            # --- AWS/GCP/Azure dangerous combos ---
            for combo_name, required in DANGEROUS_COMBOS.items():
                required_lower = [r.lower() for r in required]
                if all(
                    any(req == p or p.endswith(req.split(":")[-1].lower()) for p in perms_lower)
                    for req in required_lower
                ):
                    results.append(
                        {
                            "identity": identity_label,
                            "identity_id": identity_id,
                            "permissions": list(required),
                            "escalation_type": combo_name,
                            "severity": "CRITICAL",
                            "description": (
                                f"Identity '{identity_label}' holds the permission combination "
                                f"{required} enabling privilege escalation via '{combo_name}'."
                            ),
                        }
                    )

            # --- K8s: cluster-admin binding ---
            if provider == "k8s":
                for edge in self._edges:
                    if edge.from_id != identity_id or edge.relation != "BOUND_TO":
                        continue
                    cr_node = self._nodes.get(edge.to_id)
                    if cr_node and cr_node.node_type == "CLUSTER_ROLE":
                        if cr_node.properties.get("is_admin") or "cluster-admin" in cr_node.label.lower():
                            results.append(
                                {
                                    "identity": identity_label,
                                    "identity_id": identity_id,
                                    "permissions": ["cluster-admin"],
                                    "escalation_type": "k8s_cluster_admin_binding",
                                    "severity": "CRITICAL",
                                    "description": (
                                        f"K8s ServiceAccount '{identity_label}' is bound to "
                                        f"cluster-admin ClusterRole, granting full cluster control."
                                    ),
                                }
                            )

            # --- K8s: wildcard verbs ---
            if provider == "k8s" and ("*" in perms or "*" in perms_lower):
                results.append(
                    {
                        "identity": identity_label,
                        "identity_id": identity_id,
                        "permissions": ["*"],
                        "escalation_type": "k8s_wildcard_verbs",
                        "severity": "CRITICAL",
                        "description": (
                            f"K8s identity '{identity_label}' has wildcard verbs, "
                            f"enabling arbitrary operations on cluster resources."
                        ),
                    }
                )

        return results

    # ------------------------------------------------------------------
    # Analysis — overprivileged identities
    # ------------------------------------------------------------------

    def find_overprivileged_identities(self) -> List[Dict[str, Any]]:
        """Find identities that hold wildcard actions, admin-level permissions, or
        cluster-admin ClusterRoleBindings.

        Returns a list of dicts with keys:
            identity, permission_count, wildcard_actions, severity, reason
        """
        results: List[Dict[str, Any]] = []
        identity_types = {"IDENTITY", "SERVICE_ACCOUNT"}

        for node in self._nodes.values():
            if node.node_type not in identity_types:
                continue

            # Collect all reachable PERMISSION node IDs
            visited: Set[str] = set()
            queue: List[str] = [node.node_id]
            perm_nodes: List[IAMNode] = []

            while queue:
                nid = queue.pop()
                if nid in visited:
                    continue
                visited.add(nid)
                for edge in self._edges:
                    if edge.from_id != nid:
                        continue
                    target = self._nodes.get(edge.to_id)
                    if target is None:
                        continue
                    if target.node_type == "PERMISSION":
                        perm_nodes.append(target)
                    elif target.node_type in ("POLICY", "ROLE", "CLUSTER_ROLE"):
                        queue.append(target.node_id)

            permission_labels = [p.label for p in perm_nodes]
            wildcard_actions = [
                p
                for p in permission_labels
                if p == "*" or p.endswith(":*") or p.endswith("/*")
            ]
            admin_actions = [
                p
                for p in permission_labels
                if p.lower() in _ADMIN_PATTERNS
            ]

            # K8s cluster-admin check
            is_cluster_admin = False
            for edge in self._edges:
                if edge.from_id == node.node_id and edge.relation == "BOUND_TO":
                    cr = self._nodes.get(edge.to_id)
                    if cr and cr.node_type == "CLUSTER_ROLE" and (
                        cr.properties.get("is_admin") or "cluster-admin" in cr.label.lower()
                    ):
                        is_cluster_admin = True
                        break

            severity = "INFO"
            reason_parts: List[str] = []

            if wildcard_actions:
                severity = "CRITICAL"
                reason_parts.append(f"wildcard actions: {wildcard_actions[:5]}")
            if admin_actions:
                severity = "CRITICAL"
                reason_parts.append(f"admin-level permissions: {admin_actions[:5]}")
            if is_cluster_admin:
                severity = "CRITICAL"
                reason_parts.append("bound to cluster-admin ClusterRole")

            # Mark HIGH if many permissions even without wildcards
            if not reason_parts and len(permission_labels) > 20:
                severity = "HIGH"
                reason_parts.append(f"excessive permission count: {len(permission_labels)}")

            if reason_parts:
                results.append(
                    {
                        "identity": node.label,
                        "identity_id": node.node_id,
                        "permission_count": len(permission_labels),
                        "wildcard_actions": wildcard_actions,
                        "admin_actions": admin_actions,
                        "severity": severity,
                        "reason": "; ".join(reason_parts),
                    }
                )

        return results

    # ------------------------------------------------------------------
    # Analysis — risky permissions
    # ------------------------------------------------------------------

    def find_risky_permissions(self) -> List[Dict[str, Any]]:
        """Find dangerous permission patterns in the graph regardless of identity.

        Rules:
        - s3:PutObject + s3:GetObject + s3:DeleteObject on wildcard resource = full S3
        - ec2:* = full EC2 control
        - lambda:InvokeFunction + iam:PassRole = lateral movement
        - iam:CreateLoginProfile = account takeover vector
        - sts:AssumeRole on wildcard resource
        - Wildcard action (*) on any resource

        Returns list of {"permission", "risk", "severity"}.
        """
        all_perm_labels = {
            n.label.lower(): n
            for n in self._nodes.values()
            if n.node_type == "PERMISSION"
        }
        results: List[Dict[str, Any]] = []
        seen: Set[str] = set()

        def _add(perm: str, risk: str, sev: str) -> None:
            key = f"{perm}:{risk}"
            if key not in seen:
                seen.add(key)
                results.append({"permission": perm, "risk": risk, "severity": sev})

        # Single-permission risks
        for label_lower, node in all_perm_labels.items():
            if label_lower == "*":
                _add(node.label, "Full admin access — all actions on all resources", "CRITICAL")
            elif label_lower == "ec2:*":
                _add(node.label, "Full EC2 control including instance launch/terminate", "HIGH")
            elif label_lower == "iam:*":
                _add(node.label, "Full IAM control — can create/modify any identity or policy", "CRITICAL")
            elif label_lower == "s3:*":
                _add(node.label, "Full S3 access — read/write/delete all buckets and objects", "HIGH")
            elif label_lower in ("iam:createloginprofile",):
                _add(node.label, "Can create console login for any IAM user (account takeover)", "HIGH")
            elif label_lower in ("sts:assumerole",):
                # Check if any APPLIES_TO resource is wildcard
                for edge in self._edges:
                    if edge.from_id == node.node_id and edge.relation == "APPLIES_TO":
                        res_node = self._nodes.get(edge.to_id)
                        if res_node and res_node.properties.get("is_wildcard"):
                            _add(
                                node.label,
                                "Unrestricted AssumeRole — can assume any role in any account",
                                "HIGH",
                            )
                            break
            elif label_lower.endswith(":*"):
                service = label_lower.split(":")[0].upper()
                _add(node.label, f"Full {service} service control via wildcard action", "HIGH")

        # Multi-permission risks (check at resource level)
        s3_full = {"s3:putobject", "s3:getobject", "s3:deleteobject"}
        present_s3 = s3_full.intersection(all_perm_labels.keys())
        if present_s3 == s3_full:
            # Check if any of them applies to wildcard resource
            for label_lower, node in all_perm_labels.items():
                if label_lower in s3_full:
                    for edge in self._edges:
                        if edge.from_id == node.node_id and edge.relation == "APPLIES_TO":
                            res_node = self._nodes.get(edge.to_id)
                            if res_node and res_node.properties.get("is_wildcard"):
                                _add(
                                    "s3:PutObject+GetObject+DeleteObject/*",
                                    "Full S3 read/write/delete on all buckets",
                                    "HIGH",
                                )
                                break

        if "lambda:invokefunction" in all_perm_labels and "iam:passrole" in all_perm_labels:
            _add(
                "lambda:InvokeFunction + iam:PassRole",
                "Lateral movement — invoke Lambda with arbitrary IAM role",
                "HIGH",
            )

        return results

    # ------------------------------------------------------------------
    # Analysis — public access identities
    # ------------------------------------------------------------------

    def find_public_access_identities(self) -> List[Dict[str, Any]]:
        """Find identities/policies/resources that are publicly accessible.

        A node is considered public if:
        - Its label is "*" (wildcard principal)
        - Its properties carry public_access=True
        - A PERMISSION node with public_access=True applies to a RESOURCE

        Returns list of {"resource", "principal", "permission", "severity"}.
        """
        results: List[Dict[str, Any]] = []
        seen: Set[str] = set()

        def _add(resource: str, principal: str, permission: str, sev: str) -> None:
            key = f"{resource}:{principal}:{permission}"
            if key not in seen:
                seen.add(key)
                results.append(
                    {
                        "resource": resource,
                        "principal": principal,
                        "permission": permission,
                        "severity": sev,
                    }
                )

        for node in self._nodes.values():
            # Wildcard IDENTITY principal
            if node.node_type == "IDENTITY" and node.label == "*":
                # Find permissions it grants
                for edge in self._edges:
                    if edge.from_id == node.node_id:
                        perm_node = self._nodes.get(edge.to_id)
                        if perm_node and perm_node.node_type == "PERMISSION":
                            # Find resources
                            for e2 in self._edges:
                                if e2.from_id == perm_node.node_id and e2.relation == "APPLIES_TO":
                                    res_node = self._nodes.get(e2.to_id)
                                    if res_node:
                                        _add(res_node.label, "*", perm_node.label, "CRITICAL")

            # Nodes with public_access flag
            if node.properties.get("public_access"):
                if node.node_type == "PERMISSION":
                    # Find the resource it applies to
                    for edge in self._edges:
                        if edge.from_id == node.node_id and edge.relation == "APPLIES_TO":
                            res_node = self._nodes.get(edge.to_id)
                            if res_node:
                                _add(res_node.label, "*", node.label, "CRITICAL")
                elif node.node_type == "RESOURCE":
                    _add(node.label, "*", "unknown", "HIGH")

            # IDENTITY nodes from findings with PUBLIC_ACCESS category
            if (
                node.node_type in ("IDENTITY", "SERVICE_ACCOUNT")
                and node.properties.get("category") == "PUBLIC_ACCESS"
            ):
                _add(node.label, node.label, node.properties.get("permission", "unknown"), "CRITICAL")

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
        """Return a complete dict representation of the graph including analyses."""
        return {
            "nodes": [n.to_dict() for n in self._nodes.values()],
            "edges": [e.to_dict() for e in self._edges],
            "node_count": self.node_count,
            "edge_count": self.edge_count,
            "privilege_escalation_paths": self.find_privilege_escalation_paths(),
            "overprivileged_identities": self.find_overprivileged_identities(),
        }
