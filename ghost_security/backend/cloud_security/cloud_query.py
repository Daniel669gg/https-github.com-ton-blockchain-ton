"""
TythanAI Phase 9 — Cloud Security Query Extensions

Monkey-patches cloud-specific query methods onto:
  - SecurityKnowledgeGraph / KnowledgeGraphBuilder
  - AttackGraph / AttackGraphBuilder
  - CPGQueryLanguage (query language)

New queries:
  find_cloud_attack_paths(graph)
  find_exposed_resources(graph)
  find_privilege_escalation_paths(graph)
  find_reachable_cloud_assets(graph)
  find_container_risks(graph)
  find_kubernetes_risks(graph)
  find_business_critical_findings(graph)
"""
from __future__ import annotations

from collections import deque
from typing import Any, Dict, List, Optional, Set


# ---------------------------------------------------------------------------
# Node type groupings (string-based so we don't depend on a running KGNodeType
# import — the KGNodeType enum values are all lowercase strings anyway).
# ---------------------------------------------------------------------------

_APP_TYPES: Set[str] = {
    "code_unit", "finding", "dependency", "cve", "endpoint",
    "source", "sink", "dataflow", "runtime_finding", "cwe_node",
    "function", "method", "class", "module", "package", "api_route",
}

_CLOUD_TYPES: Set[str] = {
    "cloud_resource", "cloud_storage", "cloud_database",
    "cloud_network", "cloud_account", "cloud_function",
}

_IDENTITY_TYPES: Set[str] = {
    "iam_identity", "iam_role", "iam_permission",
    # The IAMGraph nodes use these string constants
    "identity", "role", "permission", "service_account",
    "cluster_role", "policy",
}

_CONTAINER_TYPES: Set[str] = {
    "container", "container_image", "k8s_pod", "cluster",
    "k8s_namespace",
}

_HIGH_SEVERITY: Set[str] = {"HIGH", "CRITICAL"}
_CRITICAL_SEVERITY: Set[str] = {"CRITICAL"}

_SEVERITY_RANK: Dict[str, int] = {
    "CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1,
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _node_type_value(node: Any) -> str:
    """Return a normalised node type string from a KGNode or dict."""
    if isinstance(node, dict):
        ntype = node.get("type", "")
    else:
        ntype = getattr(node, "type", "")
    return (ntype.value if hasattr(ntype, "value") else str(ntype)).lower()


def _node_id(node: Any) -> str:
    if isinstance(node, dict):
        return str(node.get("node_id", node.get("id", "")))
    return str(getattr(node, "node_id", getattr(node, "id", "")))


def _node_label(node: Any) -> str:
    if isinstance(node, dict):
        return str(node.get("label", ""))
    return str(getattr(node, "label", ""))


def _node_properties(node: Any) -> Dict[str, Any]:
    if isinstance(node, dict):
        return node.get("properties", {}) or {}
    return getattr(node, "properties", {}) or {}


def _node_severity(node: Any) -> str:
    props = _node_properties(node)
    sev = str(props.get("severity", "INFO")).upper()
    return sev


def _build_adjacency(graph: Any) -> Dict[str, List[str]]:
    """Return {from_id: [to_id, ...]} forward adjacency from graph edges."""
    adj: Dict[str, List[str]] = {}
    edges = getattr(graph, "edges", []) or []
    for edge in edges:
        if isinstance(edge, dict):
            from_id = str(edge.get("from_id", ""))
            to_id = str(edge.get("to_id", ""))
            rel = str(edge.get("relation", edge.get("label", "")))
        else:
            from_id = str(getattr(edge, "from_id", ""))
            to_id = str(getattr(edge, "to_id", ""))
            rel = str(getattr(edge, "relation", getattr(edge, "label", "")))
        if from_id and to_id:
            adj.setdefault(from_id, []).append(to_id)
    return adj


def _build_adjacency_with_relations(
    graph: Any,
) -> Dict[str, List[tuple]]:
    """Return {from_id: [(to_id, relation), ...]}."""
    adj: Dict[str, List[tuple]] = {}
    edges = getattr(graph, "edges", []) or []
    for edge in edges:
        if isinstance(edge, dict):
            from_id = str(edge.get("from_id", ""))
            to_id = str(edge.get("to_id", ""))
            rel = str(edge.get("relation", edge.get("label", "")))
        else:
            from_id = str(getattr(edge, "from_id", ""))
            to_id = str(getattr(edge, "to_id", ""))
            rel = str(getattr(edge, "relation", getattr(edge, "label", "")))
        if from_id and to_id:
            adj.setdefault(from_id, []).append((to_id, rel))
    return adj


def _build_node_map(graph: Any) -> Dict[str, Any]:
    """Return {node_id: node} from graph.nodes."""
    raw_nodes = getattr(graph, "nodes", []) or []
    if isinstance(raw_nodes, dict):
        return {str(k): v for k, v in raw_nodes.items()}
    return {_node_id(n): n for n in raw_nodes if _node_id(n)}


def _infer_layers_from_path(
    path_ids: List[str],
    node_map: Dict[str, Any],
) -> List[str]:
    """Return unique layers present along a node-id path."""
    from backend.cloud_security.executive_dashboard import _layer_for_node_type
    layers: List[str] = []
    for nid in path_ids:
        node = node_map.get(nid)
        if node is None:
            continue
        ntype_val = _node_type_value(node)
        layer = _layer_for_node_type(ntype_val)
        if layer not in layers:
            layers.append(layer)
    return layers


# ---------------------------------------------------------------------------
# KnowledgeGraph query functions
# ---------------------------------------------------------------------------


def find_cloud_attack_paths(graph: "SecurityKnowledgeGraph") -> List[Dict[str, Any]]:
    """
    Find attack paths crossing from the app/code layer to the cloud layer.

    Returns paths where at least one app_type node leads (via directed BFS)
    to at least one cloud_type node, spanning at least 2 different node type
    groups.

    Returns list of:
      {
        "path_id":    str,
        "start_node": str,
        "end_node":   str,
        "node_count": int,
        "severity":   str,
        "layers":     List[str],
      }
    """
    node_map = _build_node_map(graph)
    adj = _build_adjacency(graph)

    # Identify start nodes (app_types) and goal nodes (cloud_types)
    start_ids: Set[str] = {
        nid for nid, node in node_map.items()
        if _node_type_value(node) in _APP_TYPES
    }
    goal_ids: Set[str] = {
        nid for nid, node in node_map.items()
        if _node_type_value(node) in _CLOUD_TYPES
    }

    if not start_ids or not goal_ids:
        return []

    results: List[Dict[str, Any]] = []
    seen_path_signatures: Set[tuple] = set()

    # BFS from each start node, bounded to avoid combinatorial explosion
    MAX_PATH_LEN = 8
    MAX_RESULTS = 50

    for start_id in start_ids:
        if len(results) >= MAX_RESULTS:
            break
        queue: deque = deque([(start_id, [start_id], {start_id})])
        while queue and len(results) < MAX_RESULTS:
            current, path, visited = queue.popleft()
            if len(path) > MAX_PATH_LEN:
                continue
            if current in goal_ids and len(path) > 1:
                sig = (path[0], path[-1], len(path))
                if sig not in seen_path_signatures:
                    seen_path_signatures.add(sig)
                    # Compute max severity along path
                    max_sev = "LOW"
                    for nid in path:
                        n = node_map.get(nid)
                        if n:
                            sev = _node_severity(n)
                            if _SEVERITY_RANK.get(sev, 0) > _SEVERITY_RANK.get(max_sev, 0):
                                max_sev = sev

                    layers = _infer_layers_from_path(path, node_map)

                    results.append({
                        "path_id": f"cloud_path_{len(results) + 1}",
                        "start_node": start_id,
                        "end_node": current,
                        "node_count": len(path),
                        "severity": max_sev,
                        "layers": layers,
                        "node_ids": path,
                    })
                # Do not extend beyond a found goal to keep paths distinct
                continue

            for neighbor in adj.get(current, []):
                if neighbor not in visited:
                    queue.append((neighbor, path + [neighbor], visited | {neighbor}))

    # Sort: CRITICAL paths first
    results.sort(
        key=lambda r: (_SEVERITY_RANK.get(r["severity"], 0), -r["node_count"]),
        reverse=True,
    )
    return results


def find_exposed_resources(graph: "SecurityKnowledgeGraph") -> List[Dict[str, Any]]:
    """
    Find CLOUD_RESOURCE / CLOUD_STORAGE / CLOUD_DATABASE nodes that are
    publicly exposed.

    "Exposed" means the node has:
    - property public_access=True, OR
    - an incoming or outgoing edge with relation "EXPOSES" / "EXPOSED_BY", OR
    - property label/type containing "public"
    """
    node_map = _build_node_map(graph)
    exposed_node_ids: Set[str] = set()
    cloud_node_ids: Set[str] = {
        nid for nid, node in node_map.items()
        if _node_type_value(node) in _CLOUD_TYPES
    }

    # Find via EXPOSES / EXPOSED_BY / PUBLIC edges
    edges = getattr(graph, "edges", []) or []
    exposes_relations: Set[str] = {"EXPOSES", "EXPOSED_BY", "PUBLIC_ACCESS", "PUBLIC"}
    for edge in edges:
        if isinstance(edge, dict):
            from_id = str(edge.get("from_id", ""))
            to_id = str(edge.get("to_id", ""))
            rel = str(edge.get("relation", edge.get("label", ""))).upper()
        else:
            from_id = str(getattr(edge, "from_id", ""))
            to_id = str(getattr(edge, "to_id", ""))
            rel = str(getattr(edge, "relation", getattr(edge, "label", ""))).upper()

        if rel in exposes_relations:
            if to_id in cloud_node_ids:
                exposed_node_ids.add(to_id)
            if from_id in cloud_node_ids:
                exposed_node_ids.add(from_id)

    # Find via node property public_access=True
    for nid in cloud_node_ids:
        node = node_map[nid]
        props = _node_properties(node)
        if (
            props.get("public_access")
            or props.get("publicly_accessible")
            or "public" in str(props.get("acl", "")).lower()
            or "public" in _node_label(node).lower()
        ):
            exposed_node_ids.add(nid)

    results: List[Dict[str, Any]] = []
    for nid in exposed_node_ids:
        node = node_map.get(nid)
        if node is None:
            continue
        props = _node_properties(node)
        results.append({
            "node_id": nid,
            "label": _node_label(node),
            "node_type": _node_type_value(node),
            "cloud_provider": props.get("cloud_provider", props.get("provider", "unknown")),
            "region": props.get("region", ""),
            "public_access": True,
            "severity": props.get("severity", "HIGH"),
        })

    # Stable ordering: databases first, then by severity
    def _expose_sort_key(r: Dict[str, Any]) -> tuple:
        is_db = 1 if "database" in r.get("node_type", "") else 0
        sev_rank = _SEVERITY_RANK.get(str(r.get("severity", "INFO")).upper(), 0)
        return (-is_db, -sev_rank)

    results.sort(key=_expose_sort_key)
    return results


def find_privilege_escalation_paths(
    graph: "SecurityKnowledgeGraph",
) -> List[Dict[str, Any]]:
    """
    Find privilege escalation paths in the knowledge graph.

    Patterns detected:
      1. IAM_IDENTITY → ESCALATES_TO → IAM_ROLE → ACCESSES → CLOUD_RESOURCE
      2. CONTAINER → BOUND_TO → IAM_IDENTITY with admin permissions
      3. Any path from identity_type node to cloud_type with ESCALATES_TO edge
    """
    node_map = _build_node_map(graph)
    adj_with_rel = _build_adjacency_with_relations(graph)

    identity_nodes: Set[str] = {
        nid for nid, node in node_map.items()
        if _node_type_value(node) in _IDENTITY_TYPES
    }
    cloud_nodes: Set[str] = {
        nid for nid, node in node_map.items()
        if _node_type_value(node) in _CLOUD_TYPES
    }
    container_nodes: Set[str] = {
        nid for nid, node in node_map.items()
        if _node_type_value(node) in _CONTAINER_TYPES
    }

    escalation_rels: Set[str] = {
        "ESCALATES_TO", "ESCALATES", "ESCALATE_TO",
        "ASSUMES", "IMPERSONATES",
    }
    accesses_rels: Set[str] = {
        "ACCESSES", "HAS_ACCESS", "GRANTS", "APPLIES_TO",
        "CONTAINS", "EXPOSES", "EXPOSED_THROUGH",
    }
    bound_rels: Set[str] = {"BOUND_TO", "BOUND", "RUNS_AS", "SERVICE_ACCOUNT"}

    results: List[Dict[str, Any]] = []

    # Pattern 1: IDENTITY --ESCALATES_TO--> ROLE --ACCESSES--> CLOUD_RESOURCE
    for identity_id in identity_nodes:
        for (next_id, rel) in adj_with_rel.get(identity_id, []):
            if rel.upper() not in escalation_rels:
                continue
            role_node = node_map.get(next_id)
            if role_node is None:
                continue
            role_props = _node_properties(role_node)

            for (cloud_id, rel2) in adj_with_rel.get(next_id, []):
                if rel2.upper() not in accesses_rels:
                    continue
                if cloud_id not in cloud_nodes:
                    continue
                cloud_node = node_map.get(cloud_id)
                cloud_props = _node_properties(cloud_node) if cloud_node else {}

                identity_node = node_map.get(identity_id)
                identity_label = _node_label(identity_node) if identity_node else identity_id
                role_label = _node_label(role_node)
                cloud_label = _node_label(cloud_node) if cloud_node else cloud_id

                results.append({
                    "path_type": "identity_escalation",
                    "identity_id": identity_id,
                    "identity_label": identity_label,
                    "escalation_step": next_id,
                    "escalation_label": role_label,
                    "target_resource_id": cloud_id,
                    "target_resource_label": cloud_label,
                    "severity": "CRITICAL",
                    "path": [identity_id, next_id, cloud_id],
                    "description": (
                        f"Identity '{identity_label}' escalates via '{rel}' to "
                        f"'{role_label}', then accesses cloud resource '{cloud_label}'"
                    ),
                })

    # Pattern 2: CONTAINER --BOUND_TO--> IAM_IDENTITY (with wildcard/admin perms)
    for container_id in container_nodes:
        for (bound_target_id, rel) in adj_with_rel.get(container_id, []):
            if rel.upper() not in bound_rels:
                continue
            if bound_target_id not in identity_nodes:
                continue
            identity_node = node_map.get(bound_target_id)
            identity_props = _node_properties(identity_node) if identity_node else {}

            # Consider it an escalation if the identity has admin/wildcard indicators
            is_admin = (
                identity_props.get("is_admin")
                or identity_props.get("is_wildcard")
                or any(
                    kw in str(identity_props.get("label", "")).lower()
                    or kw in str(identity_props.get("permission", "")).lower()
                    for kw in ("admin", "*", "cluster-admin", "poweruser")
                )
            )
            if is_admin:
                container_node = node_map.get(container_id)
                container_label = _node_label(container_node) if container_node else container_id
                identity_label = _node_label(identity_node) if identity_node else bound_target_id

                results.append({
                    "path_type": "container_identity_binding",
                    "identity_id": container_id,
                    "identity_label": container_label,
                    "escalation_step": bound_target_id,
                    "escalation_label": identity_label,
                    "target_resource_id": bound_target_id,
                    "target_resource_label": identity_label,
                    "severity": "CRITICAL",
                    "path": [container_id, bound_target_id],
                    "description": (
                        f"Container '{container_label}' is bound to IAM identity "
                        f"'{identity_label}' which has admin/wildcard permissions"
                    ),
                })

    # Deduplicate by (identity_id, target_resource_id)
    seen: Set[tuple] = set()
    unique: List[Dict[str, Any]] = []
    for r in results:
        key = (r["identity_id"], r["target_resource_id"])
        if key not in seen:
            seen.add(key)
            unique.append(r)

    return unique


def find_reachable_cloud_assets(
    graph: "SecurityKnowledgeGraph",
) -> List[Dict[str, Any]]:
    """
    Find all cloud assets (CLOUD_* nodes) reachable from any FINDING node.

    Returns:
      [{"asset_id", "label", "asset_type", "reachable_from", "path_length"}, ...]
    """
    node_map = _build_node_map(graph)
    adj = _build_adjacency(graph)

    finding_ids: List[str] = [
        nid for nid, node in node_map.items()
        if _node_type_value(node) in {"finding", "runtime_finding", "sink"}
    ]
    cloud_ids: Set[str] = {
        nid for nid, node in node_map.items()
        if _node_type_value(node) in _CLOUD_TYPES
    }

    if not finding_ids or not cloud_ids:
        return []

    # BFS from all FINDING nodes simultaneously to find shortest path to each cloud asset
    # queue: (node_id, origin_finding_id, depth)
    reachable: Dict[str, Dict[str, Any]] = {}  # cloud_asset_id → result dict

    queue: deque = deque()
    visited_from: Dict[str, Set[str]] = {}  # node_id → set of origin finding_ids that reached it

    for fid in finding_ids:
        queue.append((fid, fid, 0))
        visited_from.setdefault(fid, set()).add(fid)

    MAX_DEPTH = 8

    while queue:
        current_id, origin_fid, depth = queue.popleft()
        if depth > MAX_DEPTH:
            continue

        if current_id in cloud_ids and current_id not in reachable:
            node = node_map.get(current_id)
            reachable[current_id] = {
                "asset_id": current_id,
                "label": _node_label(node) if node else current_id,
                "asset_type": _node_type_value(node) if node else "cloud_resource",
                "reachable_from": origin_fid,
                "path_length": depth,
            }

        for neighbor in adj.get(current_id, []):
            if origin_fid not in visited_from.get(neighbor, set()):
                visited_from.setdefault(neighbor, set()).add(origin_fid)
                if neighbor not in reachable:  # only traverse unexplored
                    queue.append((neighbor, origin_fid, depth + 1))

    return sorted(reachable.values(), key=lambda r: r["path_length"])


def find_container_risks(
    graph: "SecurityKnowledgeGraph",
) -> List[Dict[str, Any]]:
    """
    Find CONTAINER / CONTAINER_IMAGE nodes with HIGH or CRITICAL severity,
    or FINDING nodes related to container vulnerabilities.
    """
    node_map = _build_node_map(graph)
    results: List[Dict[str, Any]] = []

    container_types = {"container", "container_image"}

    for nid, node in node_map.items():
        ntype_val = _node_type_value(node)
        props = _node_properties(node)
        sev = str(props.get("severity", "INFO")).upper()

        # Direct container/image nodes with high+ severity
        if ntype_val in container_types and sev in _HIGH_SEVERITY:
            results.append({
                "node_id": nid,
                "label": _node_label(node),
                "node_type": ntype_val,
                "severity": sev,
                "image": props.get("image", props.get("image_name", "")),
                "cve": props.get("cve", props.get("cve_id", "")),
                "description": props.get("description", ""),
            })
            continue

        # FINDING nodes with container-related rule_ids or descriptions
        if ntype_val in {"finding", "runtime_finding", "sink"} and sev in _HIGH_SEVERITY:
            rule_id = str(props.get("rule_id", "")).upper()
            description = str(props.get("description", "")).lower()
            if any(
                kw in rule_id or kw in description
                for kw in (
                    "CONTAINER", "DOCKER", "IMAGE", "PRIVILEGED",
                    "SECCOMP", "APPARMOR", "ROOTFS", "CAPABILITY",
                    "container", "docker", "image",
                )
            ):
                results.append({
                    "node_id": nid,
                    "label": _node_label(node),
                    "node_type": ntype_val,
                    "severity": sev,
                    "image": "",
                    "cve": props.get("cve_id", ""),
                    "description": props.get("description", ""),
                    "rule_id": props.get("rule_id", ""),
                })

    # Sort: CRITICAL first
    results.sort(
        key=lambda r: _SEVERITY_RANK.get(r["severity"], 0),
        reverse=True,
    )
    return results


def find_kubernetes_risks(
    graph: "SecurityKnowledgeGraph",
) -> List[Dict[str, Any]]:
    """
    Find K8S_POD / CLUSTER / K8S_NAMESPACE nodes with HIGH or CRITICAL severity,
    or FINDING nodes related to Kubernetes misconfigurations.
    """
    node_map = _build_node_map(graph)
    results: List[Dict[str, Any]] = []

    k8s_types = {"k8s_pod", "cluster", "k8s_namespace"}
    k8s_keywords = {
        "K8S", "KUBERNETES", "KUBECTL", "KUBE", "RBAC",
        "SERVICEACCOUNT", "CLUSTERROLE", "PODSECURITYPOLICY",
        "NETWORKPOLICY", "PRIVILEGED", "HOSTPID", "HOSTIPC",
    }

    for nid, node in node_map.items():
        ntype_val = _node_type_value(node)
        props = _node_properties(node)
        sev = str(props.get("severity", "INFO")).upper()

        # Native K8s node types with high+ severity
        if ntype_val in k8s_types and sev in _HIGH_SEVERITY:
            results.append({
                "node_id": nid,
                "label": _node_label(node),
                "node_type": ntype_val,
                "severity": sev,
                "namespace": props.get("namespace", ""),
                "cluster": props.get("cluster", ""),
                "description": props.get("description", ""),
            })
            continue

        # FINDING nodes with K8s-related rule_ids or descriptions
        if ntype_val in {"finding", "runtime_finding", "sink"} and sev in _HIGH_SEVERITY:
            rule_id = str(props.get("rule_id", "")).upper()
            description = str(props.get("description", "")).lower()
            rule_tokens = set(rule_id.replace("-", "_").split("_"))
            if (
                rule_tokens & k8s_keywords
                or any(kw.lower() in description for kw in k8s_keywords)
            ):
                results.append({
                    "node_id": nid,
                    "label": _node_label(node),
                    "node_type": ntype_val,
                    "severity": sev,
                    "namespace": "",
                    "cluster": "",
                    "description": props.get("description", ""),
                    "rule_id": props.get("rule_id", ""),
                })

    results.sort(
        key=lambda r: _SEVERITY_RANK.get(r["severity"], 0),
        reverse=True,
    )
    return results


def find_business_critical_findings(
    graph: "SecurityKnowledgeGraph",
) -> List[Dict[str, Any]]:
    """
    Find CRITICAL severity findings that:
      (a) have a path to a BUSINESS_ASSET node, OR
      (b) are in the cloud, iam, or container layer.

    Returns list of {node_id, label, severity, layer, has_business_asset_path, description}.
    """
    node_map = _build_node_map(graph)
    adj = _build_adjacency(graph)

    # Business asset node types
    business_asset_types: Set[str] = {
        "asset", "business_asset",
        # Also treat high-value cloud assets as business-critical
        "cloud_database", "cloud_storage", "cloud_account",
    }
    business_asset_ids: Set[str] = {
        nid for nid, node in node_map.items()
        if _node_type_value(node) in business_asset_types
    }

    finding_types = {"finding", "runtime_finding", "sink"}
    cloud_iam_container_types = _CLOUD_TYPES | _IDENTITY_TYPES | _CONTAINER_TYPES

    results: List[Dict[str, Any]] = []

    for nid, node in node_map.items():
        ntype_val = _node_type_value(node)
        props = _node_properties(node)
        sev = str(props.get("severity", "INFO")).upper()

        if sev not in _CRITICAL_SEVERITY:
            continue

        if ntype_val not in finding_types:
            continue

        # Check layer
        from backend.cloud_security.executive_dashboard import _layer_for_node_type
        layer = _layer_for_node_type(ntype_val)

        is_cloud_iam_container = ntype_val in cloud_iam_container_types
        rule_id = str(props.get("rule_id", "")).upper()
        desc = str(props.get("description", "")).lower()
        if any(kw in rule_id or kw in desc for kw in (
            "cloud", "iam", "s3", "ec2", "rds", "container", "k8s", "docker"
        )):
            is_cloud_iam_container = True

        # BFS to find if any business asset is reachable
        has_path = False
        if business_asset_ids:
            visited: Set[str] = {nid}
            queue: deque = deque([nid])
            depth = 0
            while queue and depth < 6:
                next_queue: deque = deque()
                while queue:
                    curr = queue.popleft()
                    for neighbor in adj.get(curr, []):
                        if neighbor in business_asset_ids:
                            has_path = True
                            break
                        if neighbor not in visited:
                            visited.add(neighbor)
                            next_queue.append(neighbor)
                    if has_path:
                        break
                if has_path:
                    break
                queue = next_queue
                depth += 1

        if has_path or is_cloud_iam_container:
            results.append({
                "node_id": nid,
                "label": _node_label(node),
                "severity": sev,
                "layer": layer,
                "has_business_asset_path": has_path,
                "description": props.get("description", ""),
                "rule_id": props.get("rule_id", ""),
                "cwe_id": props.get("cwe_id", props.get("cwe", "")),
            })

    # Sort: findings with business_asset paths first, then by label
    results.sort(key=lambda r: (0 if r["has_business_asset_path"] else 1, r["label"]))
    return results


# ---------------------------------------------------------------------------
# AttackGraph query functions
# ---------------------------------------------------------------------------

def find_cloud_attack_paths_ag(graph: "AttackGraph") -> List[Dict[str, Any]]:
    """
    Find attack paths in the AttackGraph that reach CLOUD_RESOURCE or CLOUD_ACCOUNT nodes.

    Uses BFS from SOURCE / VULNERABILITY nodes through the directed edge set.
    """
    raw_nodes = getattr(graph, "nodes", {}) or {}
    if isinstance(raw_nodes, list):
        node_map = {_node_id(n): n for n in raw_nodes if _node_id(n)}
    else:
        node_map = {str(k): v for k, v in raw_nodes.items()}

    adj = _build_adjacency(graph)

    cloud_node_types = _CLOUD_TYPES | {"cloud_resource", "cloud_account", "asset"}
    cloud_keywords = {"cloud", "s3", "ec2", "rds", "gcs", "azure", "bucket", "storage"}

    def _is_cloud_target(node: Any) -> bool:
        ntype_val = _node_type_value(node)
        if ntype_val in cloud_node_types:
            return True
        label_lower = _node_label(node).lower()
        props = _node_properties(node)
        desc_lower = str(props.get("description", "")).lower()
        return any(kw in label_lower or kw in desc_lower for kw in cloud_keywords)

    # Source and vulnerability start nodes
    start_types = {"source", "vulnerability", "vuln", "runtime_finding", "finding"}
    start_ids: List[str] = [
        nid for nid, node in node_map.items()
        if _node_type_value(node) in start_types
    ]
    cloud_target_ids: Set[str] = {
        nid for nid, node in node_map.items()
        if _is_cloud_target(node)
    }

    if not start_ids or not cloud_target_ids:
        return []

    results: List[Dict[str, Any]] = []
    seen_sigs: Set[tuple] = set()
    MAX_DEPTH = 7

    for start_id in start_ids[:30]:  # bound the outer loop
        queue: deque = deque([(start_id, [start_id], {start_id})])
        while queue and len(results) < 100:
            current, path, visited = queue.popleft()
            if len(path) > MAX_DEPTH:
                continue
            if current in cloud_target_ids and len(path) > 1:
                sig = (path[0], current)
                if sig not in seen_sigs:
                    seen_sigs.add(sig)
                    start_node = node_map.get(start_id)
                    end_node = node_map.get(current)
                    results.append({
                        "path_id": f"ag_cloud_path_{len(results) + 1}",
                        "start_node_id": start_id,
                        "start_label": _node_label(start_node) if start_node else start_id,
                        "end_node_id": current,
                        "end_label": _node_label(end_node) if end_node else current,
                        "path_length": len(path),
                        "node_ids": path,
                    })
                continue
            for neighbor in adj.get(current, []):
                if neighbor not in visited:
                    queue.append((neighbor, path + [neighbor], visited | {neighbor}))

    return results


def find_exposed_resources_ag(graph: "AttackGraph") -> List[Dict[str, Any]]:
    """Find CLOUD_RESOURCE nodes in AttackGraph that are marked as exposed."""
    raw_nodes = getattr(graph, "nodes", {}) or {}
    if isinstance(raw_nodes, list):
        node_iter = raw_nodes
    else:
        node_iter = list(raw_nodes.values())

    exposed_edges: Set[str] = set()
    edges = getattr(graph, "edges", []) or []
    expose_labels = {"exposed_by", "exposes", "public", "public_access"}
    for edge in edges:
        if isinstance(edge, dict):
            to_id = str(edge.get("to_id", ""))
            from_id = str(edge.get("from_id", ""))
            label = str(edge.get("label", edge.get("relation", ""))).lower()
        else:
            to_id = str(getattr(edge, "to_id", ""))
            from_id = str(getattr(edge, "from_id", ""))
            label = str(getattr(edge, "label", getattr(edge, "relation", ""))).lower()
        if label in expose_labels or any(kw in label for kw in expose_labels):
            exposed_edges.add(to_id)
            exposed_edges.add(from_id)

    results: List[Dict[str, Any]] = []
    cloud_keywords = {"cloud", "s3", "ec2", "rds", "bucket", "storage", "database", "gcs", "azure"}

    for node in node_iter:
        nid = _node_id(node)
        ntype_val = _node_type_value(node)
        label_lower = _node_label(node).lower()
        props = _node_properties(node)

        is_cloud = (
            ntype_val in _CLOUD_TYPES
            or any(kw in label_lower for kw in cloud_keywords)
            or ntype_val == "asset"
        )
        is_exposed = (
            nid in exposed_edges
            or props.get("public_access")
            or props.get("exposed")
            or props.get("risk_level") in ("CRITICAL", "HIGH")
        )

        if is_cloud and is_exposed:
            results.append({
                "node_id": nid,
                "label": _node_label(node),
                "node_type": ntype_val,
                "risk_level": props.get("risk_level", "HIGH"),
                "auth_required": props.get("auth_required"),
                "url": props.get("url", ""),
            })

    return results


def find_privilege_escalation_ag(graph: "AttackGraph") -> List[List[str]]:
    """
    Find privilege escalation paths in AttackGraph.

    Looks for paths where a SOURCE or VULNERABILITY node leads to an ASSET node
    via edges labelled with escalation keywords, or paths through nodes labelled
    with iam/role/priv keywords.
    """
    raw_nodes = getattr(graph, "nodes", {}) or {}
    if isinstance(raw_nodes, list):
        node_map = {_node_id(n): n for n in raw_nodes if _node_id(n)}
    else:
        node_map = {str(k): v for k, v in raw_nodes.items()}

    edges = getattr(graph, "edges", []) or []

    # Build adjacency with labels
    adj_with_label: Dict[str, List[tuple]] = {}
    for edge in edges:
        if isinstance(edge, dict):
            fid = str(edge.get("from_id", ""))
            tid = str(edge.get("to_id", ""))
            lbl = str(edge.get("label", edge.get("relation", ""))).lower()
        else:
            fid = str(getattr(edge, "from_id", ""))
            tid = str(getattr(edge, "to_id", ""))
            lbl = str(getattr(edge, "label", getattr(edge, "relation", ""))).lower()
        if fid and tid:
            adj_with_label.setdefault(fid, []).append((tid, lbl))

    escalation_edge_keywords = {
        "escalat", "priv", "admin", "assume", "impersonat", "bypass", "controls"
    }
    iam_node_keywords = {
        "iam", "role", "admin", "privilege", "permission",
        "policy", "identity", "service_account", "cluster-admin",
    }

    # Find nodes that are escalation-related
    def _is_escalation_node(nid: str) -> bool:
        node = node_map.get(nid)
        if node is None:
            return False
        label_lower = _node_label(node).lower()
        ntype_val = _node_type_value(node)
        return (
            ntype_val in _IDENTITY_TYPES
            or any(kw in label_lower for kw in iam_node_keywords)
        )

    # Find asset (target) nodes
    asset_ids: Set[str] = {
        nid for nid, node in node_map.items()
        if _node_type_value(node) in {"asset"}
        or any(kw in _node_label(node).lower() for kw in {"database", "data", "credential", "secret"})
    }

    start_ids: Set[str] = {
        nid for nid, node in node_map.items()
        if _node_type_value(node) in {"source", "vulnerability", "vuln"}
    }

    paths: List[List[str]] = []
    seen: Set[tuple] = set()
    MAX_DEPTH = 6

    for start_id in start_ids:
        queue: deque = deque([(start_id, [start_id], {start_id}, False)])
        while queue:
            current, path, visited, has_priv_edge = queue.popleft()
            if len(path) > MAX_DEPTH:
                continue

            if current in asset_ids and has_priv_edge and len(path) > 1:
                sig = (path[0], current, len(path))
                if sig not in seen:
                    seen.add(sig)
                    paths.append(list(path))
                continue

            for (neighbor, edge_lbl) in adj_with_label.get(current, []):
                if neighbor in visited:
                    continue
                edge_has_priv = any(kw in edge_lbl for kw in escalation_edge_keywords)
                node_is_priv = _is_escalation_node(neighbor)
                new_has_priv = has_priv_edge or edge_has_priv or node_is_priv
                queue.append((neighbor, path + [neighbor], visited | {neighbor}, new_has_priv))

    return paths


def find_container_risks_ag(graph: "AttackGraph") -> List[Dict[str, Any]]:
    """Find CONTAINER nodes in AttackGraph with critical/high risk."""
    raw_nodes = getattr(graph, "nodes", {}) or {}
    if isinstance(raw_nodes, list):
        node_iter = raw_nodes
    else:
        node_iter = list(raw_nodes.values())

    container_keywords = {
        "container", "docker", "image", "pod", "k8s", "kubernetes",
        "helm", "registry", "privileged",
    }
    results: List[Dict[str, Any]] = []

    for node in node_iter:
        nid = _node_id(node)
        ntype_val = _node_type_value(node)
        label_lower = _node_label(node).lower()
        props = _node_properties(node)

        sev = str(props.get("severity", "INFO")).upper()
        risk_level = str(props.get("risk_level", "")).upper()

        is_container = (
            ntype_val in _CONTAINER_TYPES
            or any(kw in label_lower for kw in container_keywords)
            or any(
                kw in str(props.get("rule_id", "")).upper()
                or kw in str(props.get("description", "")).lower()
                for kw in container_keywords
            )
        )

        if not is_container:
            continue

        effective_sev = sev if sev in _HIGH_SEVERITY else risk_level
        if effective_sev not in _HIGH_SEVERITY:
            continue

        results.append({
            "node_id": nid,
            "label": _node_label(node),
            "node_type": ntype_val,
            "severity": effective_sev,
            "image": props.get("image", props.get("image_name", "")),
            "description": props.get("description", ""),
        })

    results.sort(
        key=lambda r: _SEVERITY_RANK.get(r["severity"], 0),
        reverse=True,
    )
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Monkey-patch onto existing graph builders
# ─────────────────────────────────────────────────────────────────────────────

def _install_cloud_queries() -> None:
    """Install cloud query methods on existing graph classes."""
    try:
        from backend.analysis.knowledge_graph import KnowledgeGraphBuilder, SecurityKnowledgeGraph

        # Patch as staticmethods that accept the graph as their only argument
        KnowledgeGraphBuilder.find_cloud_attack_paths = staticmethod(find_cloud_attack_paths)          # type: ignore[attr-defined]
        KnowledgeGraphBuilder.find_exposed_resources = staticmethod(find_exposed_resources)            # type: ignore[attr-defined]
        KnowledgeGraphBuilder.find_privilege_escalation_paths = staticmethod(find_privilege_escalation_paths)  # type: ignore[attr-defined]
        KnowledgeGraphBuilder.find_reachable_cloud_assets = staticmethod(find_reachable_cloud_assets)  # type: ignore[attr-defined]
        KnowledgeGraphBuilder.find_container_risks = staticmethod(find_container_risks)                # type: ignore[attr-defined]
        KnowledgeGraphBuilder.find_kubernetes_risks = staticmethod(find_kubernetes_risks)              # type: ignore[attr-defined]
        KnowledgeGraphBuilder.find_business_critical_findings = staticmethod(find_business_critical_findings)  # type: ignore[attr-defined]
    except ImportError:
        pass

    try:
        from backend.analysis.attack_graph import AttackGraph

        # For AttackGraph, patch as regular methods (first arg is self=graph instance)
        AttackGraph.find_cloud_attack_paths = find_cloud_attack_paths_ag   # type: ignore[attr-defined]
        AttackGraph.find_exposed_resources = find_exposed_resources_ag      # type: ignore[attr-defined]
        AttackGraph.find_privilege_escalation = find_privilege_escalation_ag  # type: ignore[attr-defined]
        AttackGraph.find_container_risks = find_container_risks_ag          # type: ignore[attr-defined]
    except ImportError:
        pass


_install_cloud_queries()
