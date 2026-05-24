"""
Ghost Security Platform — Attack Path Graph
Связывает отдельные findings в многошаговые цепочки атак.
Показывает как атакующий может пройти от входной точки до критичного ресурса.

Модель графа:
  Узел = finding (уязвимость)
  Ребро = "если эксплуатировать A, открывается возможность B"

Правила цепочек (attack chain rules):
  XSS → session_hijack → auth_bypass → privilege_escalation
  SSRF → internal_access → credential_theft → full_compromise
  SQLi → data_exfil → credential_crack → lateral_movement
  hardcoded_secret → direct_api_access → data_breach
  ...и т.д.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


# ══════════════════════════════════════════════════════════════════════════════
# ATTACK CHAIN RULES
# Формат: (trigger_type, requires_type) → chain_description, impact_boost
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class ChainRule:
    from_type:   str          # тип finding-источника
    to_type:     str          # тип finding-цели
    chain_name:  str          # название цепочки
    description: str          # как именно связаны
    severity:    str          # итоговая severity цепочки
    impact:      str          # описание итогового воздействия
    mitre_tactic: str = ""    # MITRE ATT&CK tactic


_CHAIN_RULES: List[ChainRule] = [
    # XSS chains
    ChainRule("xss", "hardcoded_secret",
              "XSS → Secret Exfiltration",
              "XSS can exfiltrate API keys or tokens visible in page source",
              "CRITICAL", "Full API compromise via stolen credentials", "TA0006"),
    ChainRule("xss", "csrf",
              "XSS + CSRF Bypass",
              "XSS can be used to forge state-changing requests bypassing CSRF protection",
              "HIGH", "Account takeover, unauthorized state changes", "TA0001"),
    ChainRule("xss", "open_redirect",
              "XSS → Phishing via Open Redirect",
              "XSS combined with open redirect enables convincing phishing attacks",
              "HIGH", "Credential phishing, account takeover", "TA0001"),

    # SQL Injection chains
    ChainRule("sql_injection", "hardcoded_secret",
              "SQLi → Credential Dump",
              "SQL injection allows dumping user table with hashed passwords; hardcoded secret accelerates crack",
              "CRITICAL", "Full database compromise + credential theft", "TA0006"),
    ChainRule("sql_injection", "weak_hash",
              "SQLi → Weak Hash Crack",
              "SQL injection dumps password hashes; weak hash (MD5/SHA1) enables offline cracking",
              "CRITICAL", "Mass account compromise", "TA0006"),
    ChainRule("sql_injection", "missing_auth",
              "SQLi → Auth Bypass",
              "SQL injection in login query enables authentication bypass",
              "CRITICAL", "Admin account takeover", "TA0001"),

    # SSRF chains
    ChainRule("ssrf", "hardcoded_secret",
              "SSRF → Cloud Metadata Theft",
              "SSRF can reach cloud metadata endpoint (169.254.169.254) to steal IAM credentials",
              "CRITICAL", "Cloud infrastructure compromise", "TA0006"),
    ChainRule("ssrf", "internal_network",
              "SSRF → Internal Network Pivot",
              "SSRF allows probing internal services not exposed to internet",
              "HIGH", "Internal service access, lateral movement", "TA0007"),

    # Hardcoded secret chains
    ChainRule("hardcoded_secret", "missing_auth",
              "Credential + Auth Bypass",
              "Hardcoded credential combined with missing auth check allows unauthenticated API access",
              "CRITICAL", "Direct API access without authentication", "TA0001"),
    ChainRule("hardcoded_secret", "sql_injection",
              "DB Credential + SQLi",
              "Hardcoded DB credentials combined with SQL injection enables direct database access",
              "CRITICAL", "Complete database takeover", "TA0005"),

    # Path traversal chains
    ChainRule("path_traversal", "hardcoded_secret",
              "Path Traversal → Config File Read",
              "Path traversal can read config files containing hardcoded secrets",
              "CRITICAL", "Credential theft via file system traversal", "TA0006"),
    ChainRule("path_traversal", "weak_hash",
              "Path Traversal → Shadow File",
              "Path traversal may read /etc/shadow; weak hashes enable offline cracking",
              "CRITICAL", "System credential compromise", "TA0006"),

    # Command injection
    ChainRule("shell_injection", "missing_auth",
              "RCE + No Auth",
              "Command injection with no authentication = unauthenticated remote code execution",
              "CRITICAL", "Complete server compromise", "TA0002"),
    ChainRule("command_injection", "missing_auth",
              "RCE + No Auth",
              "Command injection with no authentication = unauthenticated remote code execution",
              "CRITICAL", "Complete server compromise", "TA0002"),

    # TON-specific chains
    ChainRule("ton_fund", "ton_replay",
              "Fund Drain + Replay",
              "Mode-128 drain combined with replay attack enables repeated fund extraction",
              "CRITICAL", "Complete contract fund theft via repeated replay", "TA0010"),
    ChainRule("ton_upgrade", "ton_access",
              "Unauthorized Upgrade + No Auth",
              "Unauthenticated upgrade function allows attacker to replace contract code",
              "CRITICAL", "Full contract takeover via code replacement", "TA0010"),
    ChainRule("ton_fund", "ton_access",
              "Fund Drain + Auth Bypass",
              "Missing access control on fund-draining function enables direct theft",
              "CRITICAL", "Direct contract fund theft", "TA0010"),

    # K8s chains
    ChainRule("k8s_privileged", "k8s_rbac",
              "Privileged Pod + Cluster-Admin RBAC",
              "Privileged container combined with cluster-admin RBAC = full cluster escape",
              "CRITICAL", "Complete Kubernetes cluster compromise", "TA0004"),
    ChainRule("k8s_secret", "k8s_rbac",
              "Secret Exposure + RBAC Escalation",
              "Exposed K8s secrets combined with excessive RBAC enables privilege escalation",
              "CRITICAL", "Cluster-wide credential compromise", "TA0006"),
]


# ── Keyword матчинг ──────────────────────────────────────────────────────────

_TYPE_KEYWORDS: Dict[str, List[str]] = {
    "xss":              ["xss", "cross_site", "cross-site", "CWE-79"],
    "sql_injection":    ["sql", "sqli", "CWE-89"],
    "ssrf":             ["ssrf", "server_side_request", "CWE-918"],
    "hardcoded_secret": ["secret", "hardcoded", "credential", "api_key", "CWE-798", "CWE-312"],
    "weak_hash":        ["md5", "sha1", "weak_hash", "CWE-327"],
    "path_traversal":   ["path_traversal", "directory_traversal", "CWE-22"],
    "shell_injection":  ["shell_injection", "command_injection", "shell=True", "CWE-78"],
    "command_injection":["command_injection", "os_command", "CWE-78"],
    "csrf":             ["csrf", "CWE-352"],
    "open_redirect":    ["open_redirect", "redirect", "CWE-601"],
    "missing_auth":     ["missing_auth", "no_auth", "authentication", "CWE-306", "CWE-862"],
    "internal_network": ["internal", "localhost", "127.0.0.1", "169.254"],
    "ton_fund":         ["TON-FUND", "mode.*128", "drain"],
    "ton_replay":       ["TON-REPLAY", "replay", "seqno"],
    "ton_upgrade":      ["TON-UPG", "set_code", "upgrade"],
    "ton_access":       ["TON-AC", "TON-GAS", "accept_message", "access_control"],
    "k8s_privileged":   ["K8S-POD-004", "privileged"],
    "k8s_rbac":         ["K8S-RBAC", "cluster-admin", "wildcard"],
    "k8s_secret":       ["K8S-SEC", "plaintext_secret"],
}


def _classify_finding(finding: dict) -> str:
    """Определяет тип finding для матчинга цепочек."""
    text = " ".join([
        str(finding.get("type", "")),
        str(finding.get("rule_id", "")),
        str(finding.get("id", "")),
        str(finding.get("cwe", "")),
        str(finding.get("message", "")),
    ]).lower()

    for ftype, keywords in _TYPE_KEYWORDS.items():
        if any(kw.lower() in text for kw in keywords):
            return ftype
    return "unknown"


# ══════════════════════════════════════════════════════════════════════════════
# GRAPH MODEL
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class AttackNode:
    node_id:  str
    finding:  dict
    ftype:    str
    severity: str

    def label(self) -> str:
        msg = (self.finding.get("message") or self.finding.get("description") or self.ftype)[:50]
        loc = f"{Path(self.finding.get('file','')).name}:{self.finding.get('line','')}"
        return f"{self.ftype}\n{msg}\n{loc}"


@dataclass
class AttackEdge:
    from_id:     str
    to_id:       str
    chain_name:  str
    description: str
    severity:    str

    def to_dict(self) -> dict:
        return {
            "from":        self.from_id,
            "to":          self.to_id,
            "chain":       self.chain_name,
            "description": self.description,
            "severity":    self.severity,
        }


@dataclass
class AttackPath:
    """Один полный путь атаки (цепочка узлов)."""
    path_id:    str
    nodes:      List[AttackNode]
    edges:      List[AttackEdge]
    severity:   str   # максимальная severity в цепочке
    impact:     str
    chain_name: str

    @property
    def length(self) -> int:
        return len(self.nodes)

    def to_dict(self) -> dict:
        return {
            "path_id":   self.path_id,
            "chain":     self.chain_name,
            "severity":  self.severity,
            "impact":    self.impact,
            "steps":     self.length,
            "nodes":     [{"id": n.node_id, "type": n.ftype,
                           "file": n.finding.get("file",""),
                           "line": n.finding.get("line",0),
                           "message": (n.finding.get("message","") or "")[:80]} for n in self.nodes],
            "edges":     [e.to_dict() for e in self.edges],
        }


# ══════════════════════════════════════════════════════════════════════════════
# ATTACK PATH ANALYZER
# ══════════════════════════════════════════════════════════════════════════════

import hashlib
from pathlib import Path


class AttackPathAnalyzer:
    """
    Строит граф атаки из списка findings.
    Находит все возможные цепочки (attack paths).
    """

    def analyze(self, findings: List[dict]) -> dict:
        """
        Основной метод. Принимает список findings, возвращает:
          - nodes: все узлы графа
          - edges: все рёбра (цепочки)
          - paths: конкретные attack paths
          - risk_score: суммарный risk с учётом цепочек
        """
        if not findings:
            return {"nodes": [], "edges": [], "paths": [], "risk_score": 0}

        # Классифицируем findings
        nodes: List[AttackNode] = []
        for i, f in enumerate(findings):
            ftype = _classify_finding(f)
            nid   = hashlib.sha1(
                f"{f.get('file','')}:{f.get('line',0)}:{f.get('rule_id',i)}".encode()
            ).hexdigest()[:10]
            nodes.append(AttackNode(
                node_id  = nid,
                finding  = f,
                ftype    = ftype,
                severity = f.get("severity", "MEDIUM"),
            ))

        # Строим рёбра по правилам
        edges: List[AttackEdge] = []
        type_to_nodes: Dict[str, List[AttackNode]] = {}
        for node in nodes:
            type_to_nodes.setdefault(node.ftype, []).append(node)

        for rule in _CHAIN_RULES:
            from_nodes = type_to_nodes.get(rule.from_type, [])
            to_nodes   = type_to_nodes.get(rule.to_type, [])
            for fn in from_nodes:
                for tn in to_nodes:
                    if fn.node_id != tn.node_id:
                        edges.append(AttackEdge(
                            from_id     = fn.node_id,
                            to_id       = tn.node_id,
                            chain_name  = rule.chain_name,
                            description = rule.description,
                            severity    = rule.severity,
                        ))

        # Найти attack paths (простые пути длиной 2–4)
        paths = self._find_paths(nodes, edges)

        # Рассчитать risk_score с учётом цепочек
        base_score  = self._base_risk(findings)
        chain_bonus = len([p for p in paths if p.severity == "CRITICAL"]) * 15
        risk_score  = min(100, base_score + chain_bonus)

        return {
            "nodes": [{"id": n.node_id, "type": n.ftype, "severity": n.severity,
                       "file": n.finding.get("file",""), "line": n.finding.get("line",0),
                       "message": (n.finding.get("message","") or "")[:80]}
                      for n in nodes if n.ftype != "unknown"],
            "edges":       [e.to_dict() for e in edges],
            "paths":       [p.to_dict() for p in paths],
            "risk_score":  risk_score,
            "chain_count": len(paths),
            "critical_chains": len([p for p in paths if p.severity == "CRITICAL"]),
            "stats": {
                "total_nodes":      len(nodes),
                "classified_nodes": len([n for n in nodes if n.ftype != "unknown"]),
                "edges":            len(edges),
                "attack_paths":     len(paths),
            },
        }

    def _find_paths(
        self,
        nodes: List[AttackNode],
        edges: List[AttackEdge],
        max_depth: int = 3,
    ) -> List[AttackPath]:
        """BFS для поиска attack paths длиной 2–max_depth."""
        node_map  = {n.node_id: n for n in nodes}
        adj: Dict[str, List[AttackEdge]] = {}
        for e in edges:
            adj.setdefault(e.from_id, []).append(e)

        paths: List[AttackPath] = []
        seen_paths: Set[str] = set()

        for start in nodes:
            if start.ftype == "unknown":
                continue
            # BFS
            queue = [([start], [])]  # (node_path, edge_path)
            while queue:
                node_path, edge_path = queue.pop(0)
                current = node_path[-1]

                if len(node_path) >= 2:
                    # Valid path — record it
                    path_key = "→".join(n.node_id for n in node_path)
                    if path_key not in seen_paths:
                        seen_paths.add(path_key)
                        sev = max(
                            (e.severity for e in edge_path),
                            key=lambda s: ["INFO","LOW","MEDIUM","HIGH","CRITICAL"].index(s),
                            default="MEDIUM",
                        )
                        # Find the rule for this path
                        impact = edge_path[-1].description if edge_path else ""
                        chain  = " → ".join(edge_path[-1].chain_name.split("→")[0:1]) if edge_path else ""
                        paths.append(AttackPath(
                            path_id    = path_key[:20],
                            nodes      = list(node_path),
                            edges      = list(edge_path),
                            severity   = sev,
                            impact     = impact,
                            chain_name = chain or edge_path[-1].chain_name if edge_path else "",
                        ))

                if len(node_path) >= max_depth + 1:
                    continue

                for edge in adj.get(current.node_id, []):
                    next_node = node_map.get(edge.to_id)
                    if next_node and next_node not in node_path:
                        queue.append((node_path + [next_node], edge_path + [edge]))

        # Sort by severity desc, path length desc
        sev_order = {"CRITICAL":4,"HIGH":3,"MEDIUM":2,"LOW":1,"INFO":0}
        paths.sort(key=lambda p: (-sev_order.get(p.severity,0), -p.length))
        return paths[:20]  # top 20 paths

    @staticmethod
    def _base_risk(findings: List[dict]) -> float:
        weights = {"CRITICAL":25,"HIGH":15,"MEDIUM":8,"LOW":3,"INFO":0.5}
        return min(100, sum(weights.get(f.get("severity","MEDIUM"),0) for f in findings))

    def mermaid(self, graph: dict) -> str:
        """Export attack graph as Mermaid diagram."""
        lines = ["graph LR"]
        for node in graph["nodes"][:15]:  # limit for readability
            label = f"{node['type']}\\n{node.get('file','')[:20]}:{node.get('line','')}"
            style = {"CRITICAL":"fill:#f00,color:#fff","HIGH":"fill:#f80","MEDIUM":"fill:#ff0"}.get(
                node["severity"], "")
            nid = node["id"]
            lines.append(f'  {nid}["{label}"]')
            if style:
                lines.append(f'  style {nid} {style}')
        for edge in graph["edges"][:20]:
            lines.append(f'  {edge["from"]} -->|"{edge["chain"][:20]}"| {edge["to"]}')
        return "\n".join(lines)

    def narrative(self, graph: dict) -> str:
        """Human-readable attack narrative."""
        paths = graph.get("paths", [])
        if not paths:
            return "No attack chains identified."

        lines = [f"# Attack Path Analysis\n{graph['chain_count']} attack chains identified.\n"]
        for i, p in enumerate(paths[:5], 1):
            lines.append(f"## Chain {i}: {p['chain']} [{p['severity']}]")
            lines.append(f"**Impact:** {p['impact']}\n")
            for j, step in enumerate(p["nodes"], 1):
                lines.append(f"  Step {j}: `{step['type']}` in `{step.get('file','')}:{step.get('line','')}`")
            lines.append("")
        return "\n".join(lines)
