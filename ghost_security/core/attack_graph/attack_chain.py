"""
Ghost Security Platform — Attack Chain Visualizer

Generates Mermaid.js flowcharts and DOT/Graphviz attack graphs showing how
vulnerabilities chain together from entry point to impact.

Node types:
  Entry       — external input (user-controlled data, network request, file upload)
  Vuln        — a concrete vulnerability finding
  Propagation — how the attacker moves between systems/contexts
  Impact      — final outcome (DataLeak, RCE, PrivEsc, FundsDrain, etc.)

Kill chain detection:
  SQLi → DataLeak
  XSS  → SessionHijack
  RCE  → PrivEsc
  Reentrancy → FundsDrain

Usage:
    from core.attack_graph import AttackChainBuilder
    builder = AttackChainBuilder()
    graph   = builder.build(findings)
    print(builder.to_mermaid(graph))
    print(builder.to_dot(graph))
    report  = builder.generate_report(findings)
"""
from __future__ import annotations

import hashlib
import json
import os
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


# ─────────────────────────────────────────────────────────────────────────────
# Data model
# ─────────────────────────────────────────────────────────────────────────────

NODE_ENTRY       = "Entry"
NODE_VULN        = "Vuln"
NODE_PROPAGATION = "Propagation"
NODE_IMPACT      = "Impact"

# Map vuln type keywords → canonical type key used in kill-chain rules
_TYPE_ALIASES: Dict[str, str] = {
    "sql_injection":    "sqli",
    "sqli":             "sqli",
    "xss":              "xss",
    "cross_site_scripting": "xss",
    "rce":              "rce",
    "remote_code_execution": "rce",
    "shell_injection":  "rce",
    "command_injection": "rce",
    "reentrancy":       "reentrancy",
    "reentrancy_vulnerability": "reentrancy",
    "path_traversal":   "path_traversal",
    "ssrf":             "ssrf",
    "server_side_request_forgery": "ssrf",
    "hardcoded_secret": "hardcoded_secret",
    "hardcoded_credential": "hardcoded_secret",
    "secret_exposure":  "hardcoded_secret",
    "insecure_deserialization": "deserialization",
    "deserialization":  "deserialization",
    "open_redirect":    "open_redirect",
    "privilege_escalation": "privesc",
    "privesc":          "privesc",
    "missing_auth":     "missing_auth",
    "broken_access_control": "missing_auth",
    "csrf":             "csrf",
    "xxe":              "xxe",
    "xml_external_entity": "xxe",
    "ton_fund":         "ton_fund",
    "ton_replay":       "ton_replay",
    "ton_access":       "ton_access",
    "ton_upgrade":      "ton_upgrade",
}

# CWE → canonical type mapping (partial, covers most common)
_CWE_TO_TYPE: Dict[str, str] = {
    "CWE-89":  "sqli",
    "CWE-79":  "xss",
    "CWE-78":  "rce",
    "CWE-77":  "rce",
    "CWE-502": "deserialization",
    "CWE-22":  "path_traversal",
    "CWE-918": "ssrf",
    "CWE-798": "hardcoded_secret",
    "CWE-321": "hardcoded_secret",
    "CWE-601": "open_redirect",
    "CWE-352": "csrf",
    "CWE-611": "xxe",
    "CWE-287": "missing_auth",
    "CWE-306": "missing_auth",
    "CWE-269": "privesc",
}

# OWASP category → canonical type
_OWASP_TO_TYPE: Dict[str, str] = {
    "A03:2021": "sqli",
    "A07:2021": "xss",
    "A01:2021": "missing_auth",
}

# Kill-chain definitions: (from_type, to_type) → (propagation_label, impact_label, impact_level)
_KILL_CHAINS: List[Tuple[str, str, str, str, str]] = [
    # (from, to, propagation, impact_label, impact_severity)
    ("sqli",            "hardcoded_secret", "Database credential dump",       "DataLeak",      "CRITICAL"),
    ("sqli",            "missing_auth",     "Authentication bypass via SQLi",  "AuthBypass",    "CRITICAL"),
    ("sqli",            "rce",              "SQLi to OS command via xp_cmdshell", "RCE",        "CRITICAL"),
    ("xss",             "hardcoded_secret", "Token exfiltration from DOM",    "SessionHijack", "HIGH"),
    ("xss",             "csrf",             "CSRF protection bypass via XSS", "SessionHijack", "HIGH"),
    ("xss",             "open_redirect",    "Phishing via XSS redirect",      "SessionHijack", "HIGH"),
    ("rce",             "privesc",          "Shell access → privilege escalation", "PrivEsc",   "CRITICAL"),
    ("rce",             "hardcoded_secret", "Read secrets from disk/env",     "DataLeak",      "CRITICAL"),
    ("reentrancy",      "ton_fund",         "Re-enter before balance update", "FundsDrain",    "CRITICAL"),
    ("reentrancy",      "ton_access",       "Reentrancy bypasses access guard", "FundsDrain",  "CRITICAL"),
    ("ton_fund",        "ton_replay",       "Repeated replay drains funds",   "FundsDrain",    "CRITICAL"),
    ("ton_upgrade",     "ton_access",       "Unauthenticated upgrade",        "ContractTakeover", "CRITICAL"),
    ("ssrf",            "hardcoded_secret", "Cloud metadata endpoint access", "DataLeak",      "CRITICAL"),
    ("ssrf",            "missing_auth",     "Pivot to internal unauthenticated service", "AuthBypass", "HIGH"),
    ("path_traversal",  "hardcoded_secret", "Read config/env files",         "DataLeak",      "CRITICAL"),
    ("deserialization", "rce",              "Gadget chain execution",         "RCE",           "CRITICAL"),
    ("hardcoded_secret","missing_auth",     "Use credential to bypass auth",  "AuthBypass",    "CRITICAL"),
    ("xxe",             "ssrf",             "XXE with external entity fetch", "DataLeak",      "HIGH"),
    ("open_redirect",   "xss",             "Redirect to attacker page with XSS", "SessionHijack", "MEDIUM"),
]

# Entry points: these finding types are treated as entry nodes
_ENTRY_TYPES: Set[str] = {
    "sqli", "xss", "rce", "ssrf", "path_traversal",
    "deserialization", "xxe", "open_redirect", "csrf",
    "ton_fund", "reentrancy",
}

# Severity → numeric weight for graph scoring
_SEV_WEIGHT: Dict[str, int] = {
    "CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 2, "INFO": 1,
}


@dataclass
class AttackNode:
    node_id:     str
    node_type:   str          # Entry | Vuln | Propagation | Impact
    label:       str
    severity:    str = "MEDIUM"
    finding_ref: Optional[dict] = None   # originating finding dict
    canonical:   str = ""                # canonical type key


@dataclass
class AttackEdge:
    src: str
    dst: str
    label: str = ""
    weight: int = 1


@dataclass
class AttackGraph:
    nodes:      Dict[str, AttackNode] = field(default_factory=dict)
    edges:      List[AttackEdge]      = field(default_factory=list)
    kill_chains: List[List[str]]      = field(default_factory=list)  # lists of node_ids


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _short_id(text: str) -> str:
    """Stable short ID from arbitrary string."""
    return hashlib.md5(text.encode()).hexdigest()[:8]


def _canonical_type(finding: dict) -> str:
    """Map a finding to one of the canonical type keys."""
    # Try vuln_type / type field first
    for key in ("vuln_type", "type", "check_id", "rule_id"):
        raw = str(finding.get(key, "")).lower().replace("-", "_").replace(" ", "_")
        if raw in _TYPE_ALIASES:
            return _TYPE_ALIASES[raw]
        for alias, canon in _TYPE_ALIASES.items():
            if alias in raw:
                return canon

    # Try CWE
    cwe = finding.get("cwe") or finding.get("CWE", "")
    if isinstance(cwe, list):
        cwe = cwe[0] if cwe else ""
    cwe = str(cwe).upper().strip()
    if cwe in _CWE_TO_TYPE:
        return _CWE_TO_TYPE[cwe]

    # Try OWASP
    owasp = str(finding.get("owasp", "")).upper().strip()
    for key, canon in _OWASP_TO_TYPE.items():
        if key in owasp:
            return canon

    # Fallback: description keywords
    desc = str(finding.get("description", "") + " " + finding.get("title", "")).lower()
    for alias, canon in _TYPE_ALIASES.items():
        if alias.replace("_", " ") in desc or alias in desc:
            return canon

    return "unknown"


def _node_label(finding: dict, canon: str) -> str:
    title = finding.get("title") or finding.get("check_id") or finding.get("rule_id") or canon
    path  = finding.get("file", "")
    if path:
        path = os.path.basename(path)
        return f"{title} [{path}]"
    return str(title)


def _severity(finding: dict) -> str:
    return str(finding.get("severity", finding.get("sev", "MEDIUM"))).upper()


# ─────────────────────────────────────────────────────────────────────────────
# AttackChainBuilder
# ─────────────────────────────────────────────────────────────────────────────

class AttackChainBuilder:
    """
    Builds attack graphs from security findings and exports them in multiple
    formats (Mermaid, DOT/Graphviz, JSON adjacency list).
    """

    # ── Build ──────────────────────────────────────────────────────────────────

    def build(self, findings: list) -> AttackGraph:
        """Build an AttackGraph from a list of finding dicts."""
        graph = AttackGraph()

        # 1. Create Vuln nodes for each finding
        vuln_nodes: Dict[str, str] = {}   # finding index → node_id
        canon_to_nodes: Dict[str, List[str]] = defaultdict(list)

        for idx, f in enumerate(findings):
            canon = _canonical_type(f)
            label = _node_label(f, canon)
            nid   = f"v_{_short_id(f'{idx}_{label}')}"
            sev   = _severity(f)

            node_type = NODE_ENTRY if canon in _ENTRY_TYPES else NODE_VULN
            graph.nodes[nid] = AttackNode(
                node_id=nid, node_type=node_type, label=label,
                severity=sev, finding_ref=f, canonical=canon,
            )
            vuln_nodes[idx] = nid
            canon_to_nodes[canon].append(nid)

        # 2. Connect same-file findings (proximity edges)
        file_groups: Dict[str, List[int]] = defaultdict(list)
        for idx, f in enumerate(findings):
            fp = f.get("file", "")
            if fp:
                file_groups[fp].append(idx)

        for fp, idxs in file_groups.items():
            if len(idxs) < 2:
                continue
            for i in range(len(idxs) - 1):
                src = vuln_nodes[idxs[i]]
                dst = vuln_nodes[idxs[i + 1]]
                graph.edges.append(AttackEdge(src=src, dst=dst, label="same file"))

        # 3. Apply kill-chain rules to wire Propagation + Impact nodes
        for (from_canon, to_canon, prop_label, impact_label, impact_sev) in _KILL_CHAINS:
            src_nodes = canon_to_nodes.get(from_canon, [])
            dst_nodes = canon_to_nodes.get(to_canon, [])
            if not src_nodes:
                continue

            # Create propagation node
            prop_nid = f"p_{_short_id(from_canon + to_canon + prop_label)}"
            if prop_nid not in graph.nodes:
                graph.nodes[prop_nid] = AttackNode(
                    node_id=prop_nid, node_type=NODE_PROPAGATION,
                    label=prop_label, severity=impact_sev, canonical="propagation",
                )

            # Create impact node
            imp_nid = f"i_{_short_id(impact_label + impact_sev)}"
            if imp_nid not in graph.nodes:
                graph.nodes[imp_nid] = AttackNode(
                    node_id=imp_nid, node_type=NODE_IMPACT,
                    label=impact_label, severity=impact_sev, canonical="impact",
                )

            for src_nid in src_nodes:
                graph.edges.append(AttackEdge(src=src_nid, dst=prop_nid,
                                              label="enables",
                                              weight=_SEV_WEIGHT.get(impact_sev, 1)))

            if dst_nodes:
                for dst_nid in dst_nodes:
                    graph.edges.append(AttackEdge(src=dst_nid, dst=prop_nid,
                                                  label="contributes",
                                                  weight=_SEV_WEIGHT.get(impact_sev, 1)))

            graph.edges.append(AttackEdge(src=prop_nid, dst=imp_nid,
                                          label="leads to",
                                          weight=_SEV_WEIGHT.get(impact_sev, 1)))

        # 4. Detect kill-chain paths (entry → ... → CRITICAL impact)
        graph.kill_chains = self.find_critical_paths(graph)
        return graph

    # ── Exports ────────────────────────────────────────────────────────────────

    def to_mermaid(self, graph: AttackGraph) -> str:
        """Return a Mermaid.js flowchart string."""
        lines = ["flowchart TD"]

        shape_open  = {"Entry": "([", "Vuln": "[",  "Propagation": ">",  "Impact": "(("}
        shape_close = {"Entry": "])", "Vuln": "]",  "Propagation": "]",  "Impact": "))"}
        style_class = {"Entry": "entry", "Vuln": "vuln", "Propagation": "prop", "Impact": "impact"}

        for nid, node in graph.nodes.items():
            o = shape_open.get(node.node_type, "[")
            c = shape_close.get(node.node_type, "]")
            safe_label = node.label.replace('"', "'").replace("\n", " ")
            lines.append(f'    {nid}{o}"{safe_label}"{c}')

        for edge in graph.edges:
            if edge.src not in graph.nodes or edge.dst not in graph.nodes:
                continue
            arrow = f"-->|{edge.label}|" if edge.label else "-->"
            lines.append(f"    {edge.src} {arrow} {edge.dst}")

        # Styles
        lines.append("    classDef entry fill:#4CAF50,stroke:#388E3C,color:#fff")
        lines.append("    classDef vuln  fill:#FF9800,stroke:#F57C00,color:#fff")
        lines.append("    classDef prop  fill:#2196F3,stroke:#1565C0,color:#fff")
        lines.append("    classDef impact fill:#f44336,stroke:#B71C1C,color:#fff")

        for nid, node in graph.nodes.items():
            cls = style_class.get(node.node_type, "vuln")
            lines.append(f"    class {nid} {cls}")

        return "\n".join(lines)

    def to_dot(self, graph: AttackGraph) -> str:
        """Return a Graphviz DOT format string."""
        dot_color = {
            "Entry":       '#4CAF50',
            "Vuln":        '#FF9800',
            "Propagation": '#2196F3',
            "Impact":      '#f44336',
        }
        dot_shape = {
            "Entry":       "ellipse",
            "Vuln":        "box",
            "Propagation": "diamond",
            "Impact":      "doubleoctagon",
        }

        lines = ['digraph AttackGraph {', '    rankdir=LR;',
                 '    node [fontname="Helvetica", fontsize=11];']

        for nid, node in graph.nodes.items():
            color = dot_color.get(node.node_type, "#999999")
            shape = dot_shape.get(node.node_type, "box")
            safe  = node.label.replace('"', '\\"')
            sev   = f"\\n[{node.severity}]" if node.severity else ""
            lines.append(
                f'    {nid} [label="{safe}{sev}", shape={shape}, '
                f'style=filled, fillcolor="{color}", fontcolor=white];'
            )

        for edge in graph.edges:
            if edge.src not in graph.nodes or edge.dst not in graph.nodes:
                continue
            lbl = f' [label="{edge.label}"]' if edge.label else ""
            lines.append(f"    {edge.src} -> {edge.dst}{lbl};")

        lines.append("}")
        return "\n".join(lines)

    def to_json(self, graph: AttackGraph) -> dict:
        """Return a JSON-serialisable adjacency list."""
        adjacency: Dict[str, List[str]] = defaultdict(list)
        for edge in graph.edges:
            if edge.src in graph.nodes and edge.dst in graph.nodes:
                adjacency[edge.src].append(edge.dst)

        return {
            "nodes": [
                {
                    "id":        n.node_id,
                    "type":      n.node_type,
                    "label":     n.label,
                    "severity":  n.severity,
                    "canonical": n.canonical,
                }
                for n in graph.nodes.values()
            ],
            "edges": [
                {"src": e.src, "dst": e.dst, "label": e.label, "weight": e.weight}
                for e in graph.edges
                if e.src in graph.nodes and e.dst in graph.nodes
            ],
            "adjacency": dict(adjacency),
            "kill_chain_paths": graph.kill_chains,
        }

    # ── Analysis ───────────────────────────────────────────────────────────────

    def find_critical_paths(self, graph: AttackGraph) -> List[List[str]]:
        """
        BFS from every Entry/Vuln node; collect all paths that reach an
        Impact node with severity CRITICAL.
        """
        critical_impacts: Set[str] = {
            nid for nid, n in graph.nodes.items()
            if n.node_type == NODE_IMPACT and n.severity == "CRITICAL"
        }
        if not critical_impacts:
            return []

        # Build adjacency list
        adj: Dict[str, List[str]] = defaultdict(list)
        for edge in graph.edges:
            if edge.src in graph.nodes and edge.dst in graph.nodes:
                adj[edge.src].append(edge.dst)

        # BFS to find paths
        entry_nodes = [
            nid for nid, n in graph.nodes.items()
            if n.node_type in (NODE_ENTRY, NODE_VULN) and n.canonical in _ENTRY_TYPES
        ]

        paths: List[List[str]] = []
        for start in entry_nodes:
            queue: deque = deque([[start]])
            seen_paths: Set[Tuple[str, ...]] = set()
            while queue:
                path = queue.popleft()
                current = path[-1]

                if current in critical_impacts:
                    key = tuple(path)
                    if key not in seen_paths:
                        seen_paths.add(key)
                        paths.append(path)
                    continue

                for neighbor in adj.get(current, []):
                    if neighbor not in path:   # avoid cycles
                        queue.append(path + [neighbor])

        # Deduplicate and sort by path length (longest = most complex chain)
        unique = {tuple(p): p for p in paths}
        return sorted(unique.values(), key=lambda p: len(p), reverse=True)

    # ── Report generation ──────────────────────────────────────────────────────

    def generate_report(self, findings: list) -> str:
        """
        Generate a full Markdown report with embedded Mermaid diagram,
        critical paths, and per-chain narrative.
        """
        graph = self.build(findings)
        mermaid = self.to_mermaid(graph)
        paths   = graph.kill_chains

        vuln_count  = sum(1 for n in graph.nodes.values() if n.node_type in (NODE_ENTRY, NODE_VULN))
        impact_count = sum(1 for n in graph.nodes.values() if n.node_type == NODE_IMPACT)

        lines: List[str] = [
            "# Attack Chain Analysis Report",
            "",
            f"**Vulnerabilities mapped:** {vuln_count}  ",
            f"**Potential impact nodes:** {impact_count}  ",
            f"**Critical kill-chain paths found:** {len(paths)}",
            "",
            "---",
            "",
            "## Attack Flow Diagram",
            "",
            "```mermaid",
            mermaid,
            "```",
            "",
            "---",
            "",
            "## Critical Attack Paths",
            "",
        ]

        if not paths:
            lines.append("_No critical end-to-end attack paths detected._")
        else:
            for i, path in enumerate(paths, 1):
                node_labels = []
                for nid in path:
                    n = graph.nodes.get(nid)
                    if n:
                        node_labels.append(f"**{n.label}** `[{n.node_type}]`")
                chain_str = " → ".join(node_labels)
                lines.append(f"### Path {i}: {len(path)}-step chain")
                lines.append("")
                lines.append(chain_str)
                lines.append("")

        lines += [
            "---",
            "",
            "## Node Inventory",
            "",
            "| ID | Type | Label | Severity |",
            "|----|------|-------|----------|",
        ]
        for nid, node in sorted(graph.nodes.items(), key=lambda x: x[1].node_type):
            lines.append(f"| `{nid}` | {node.node_type} | {node.label} | {node.severity} |")

        lines += [
            "",
            "---",
            "",
            "## Raw Data (JSON)",
            "",
            "```json",
            json.dumps(self.to_json(graph), indent=2),
            "```",
        ]

        return "\n".join(lines)
