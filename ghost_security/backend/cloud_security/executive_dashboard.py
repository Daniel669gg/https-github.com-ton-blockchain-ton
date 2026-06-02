"""
TythanAI Phase 9 — Executive Security Dashboard

Aggregates all security signals (SAST, CVE, DAST, Cloud, IAM, K8s, Container)
into a unified executive dashboard report.

Displays:
- Top Attack Paths (with business impact)
- Top Exploitable Risks
- Business Impact Summary
- Cloud Exposure Summary
- Verified Findings Summary
- Layer Risk Breakdown
- Remediation Priorities
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class AttackPathSummary:
    rank: int
    path_description: str    # "SQL Injection → CVE-2023-1234 → api-container → s3-admin-role → prod-data-bucket"
    layers: List[str]        # ["code", "container", "iam", "cloud"]
    severity: str
    business_impact_score: int
    attack_type: str


@dataclass
class CloudExposureSummary:
    public_resources: int
    open_ports: int
    public_databases: int
    overprivileged_identities: int
    privilege_escalation_paths: int
    exposed_secrets: int


@dataclass
class ExecutiveDashboardReport:
    generated_at: str                    # ISO timestamp
    overall_risk_score: int              # 0–100
    overall_risk_class: str              # CATASTROPHIC/CRITICAL/HIGH/MEDIUM/LOW

    # Top findings
    top_attack_paths: List[AttackPathSummary]      # top 5
    top_exploitable_risks: List[Dict[str, Any]]    # top 5 by impact

    # Summaries
    business_impact_summary: Dict[str, Any]
    cloud_exposure_summary: CloudExposureSummary
    verified_findings_count: int

    # Layer breakdown
    layer_risk_breakdown: Dict[str, int]   # layer_name → score (0-100)
    critical_findings_by_layer: Dict[str, int]

    # Remediation
    remediation_priorities: List[str]      # ordered list

    # Stats
    total_findings: int
    critical_chains: int
    layers_with_critical: List[str]

    def text_report(self) -> str:
        """Generate human-readable executive report."""
        lines: List[str] = []
        w = 55  # separator width

        sep = "═" * w
        thin = "─" * w

        lines.append(sep)
        lines.append("  TYTHANAI EXECUTIVE SECURITY DASHBOARD")
        lines.append(f"  Generated: {self.generated_at}")
        lines.append(sep)
        lines.append("")
        lines.append(
            f"  OVERALL RISK: {self.overall_risk_class}"
            f"  (Score: {self.overall_risk_score}/100)"
        )
        lines.append("")

        # --- Top attack paths ---
        lines.append(thin)
        lines.append("  TOP ATTACK PATHS:")
        lines.append(thin)
        if self.top_attack_paths:
            for ap in self.top_attack_paths:
                layer_str = " → ".join(ap.layers) if ap.layers else "n/a"
                lines.append(f"  {ap.rank}. [{ap.severity}] {ap.path_description}")
                lines.append(f"     Type: {ap.attack_type}")
                lines.append(f"     Layers: {layer_str}")
                lines.append(f"     Business Impact: {ap.business_impact_score}/100")
                lines.append("")
        else:
            lines.append("  No attack paths identified.")
            lines.append("")

        # --- Top exploitable risks ---
        lines.append(thin)
        lines.append("  TOP EXPLOITABLE RISKS:")
        lines.append(thin)
        if self.top_exploitable_risks:
            for i, risk in enumerate(self.top_exploitable_risks, start=1):
                title = risk.get("title", risk.get("rule_id", "Unknown"))
                severity = risk.get("severity", "UNKNOWN")
                impact = risk.get("impact_score", risk.get("risk_score", 0))
                lines.append(f"  {i}. [{severity}] {title}  (Impact: {impact})")
        else:
            lines.append("  No exploitable risks identified.")
        lines.append("")

        # --- Business impact summary ---
        lines.append(thin)
        lines.append("  BUSINESS IMPACT SUMMARY:")
        lines.append(thin)
        bi = self.business_impact_summary
        lines.append(f"  Total Assets at Risk:       {bi.get('total_at_risk', 0)}")
        lines.append(f"  Critical Business Impact:   {bi.get('critical_impact', 0)}")
        lines.append(f"  High Business Impact:       {bi.get('high_impact', 0)}")
        lines.append(f"  Average Impact Score:       {bi.get('average_score', 0.0):.1f}")
        lines.append(f"  Est. Economic Exposure:     {bi.get('estimated_economic_exposure', 'N/A')}")
        lines.append("")

        # --- Cloud exposure ---
        lines.append(thin)
        lines.append("  CLOUD EXPOSURE SUMMARY:")
        lines.append(thin)
        ce = self.cloud_exposure_summary
        lines.append(f"  Public Resources:           {ce.public_resources}")
        lines.append(f"  Open Ports (exposed):       {ce.open_ports}")
        lines.append(f"  Public Databases:           {ce.public_databases}")
        lines.append(f"  Overprivileged Identities:  {ce.overprivileged_identities}")
        lines.append(f"  Privilege Escalation Paths: {ce.privilege_escalation_paths}")
        lines.append(f"  Exposed Secrets:            {ce.exposed_secrets}")
        lines.append("")

        # --- Verified findings ---
        lines.append(thin)
        lines.append("  VERIFIED FINDINGS SUMMARY:")
        lines.append(thin)
        lines.append(f"  Verified Exploitable:       {self.verified_findings_count}")
        lines.append(f"  Total Findings:             {self.total_findings}")
        lines.append(f"  Critical Attack Chains:     {self.critical_chains}")
        lines.append("")

        # --- Layer risk breakdown ---
        lines.append(thin)
        lines.append("  LAYER RISK BREAKDOWN:")
        lines.append(thin)
        if self.layer_risk_breakdown:
            for layer, score in sorted(
                self.layer_risk_breakdown.items(), key=lambda x: -x[1]
            ):
                critical_n = self.critical_findings_by_layer.get(layer, 0)
                bar = _risk_bar(score)
                lines.append(
                    f"  {layer:<20} {bar}  {score:>3}/100"
                    f"  (critical: {critical_n})"
                )
        else:
            lines.append("  No layer data available.")
        lines.append("")

        # --- Remediation priorities ---
        lines.append(thin)
        lines.append("  REMEDIATION PRIORITIES:")
        lines.append(thin)
        if self.remediation_priorities:
            for i, priority in enumerate(self.remediation_priorities, start=1):
                lines.append(f"  {i:>2}. {priority}")
        else:
            lines.append("  No remediation priorities generated.")
        lines.append("")
        lines.append(sep)

        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize report to a plain dict."""
        return {
            "generated_at": self.generated_at,
            "overall_risk_score": self.overall_risk_score,
            "overall_risk_class": self.overall_risk_class,
            "top_attack_paths": [
                {
                    "rank": ap.rank,
                    "path_description": ap.path_description,
                    "layers": ap.layers,
                    "severity": ap.severity,
                    "business_impact_score": ap.business_impact_score,
                    "attack_type": ap.attack_type,
                }
                for ap in self.top_attack_paths
            ],
            "top_exploitable_risks": self.top_exploitable_risks,
            "business_impact_summary": self.business_impact_summary,
            "cloud_exposure_summary": {
                "public_resources": self.cloud_exposure_summary.public_resources,
                "open_ports": self.cloud_exposure_summary.open_ports,
                "public_databases": self.cloud_exposure_summary.public_databases,
                "overprivileged_identities": self.cloud_exposure_summary.overprivileged_identities,
                "privilege_escalation_paths": self.cloud_exposure_summary.privilege_escalation_paths,
                "exposed_secrets": self.cloud_exposure_summary.exposed_secrets,
            },
            "verified_findings_count": self.verified_findings_count,
            "layer_risk_breakdown": self.layer_risk_breakdown,
            "critical_findings_by_layer": self.critical_findings_by_layer,
            "remediation_priorities": self.remediation_priorities,
            "total_findings": self.total_findings,
            "critical_chains": self.critical_chains,
            "layers_with_critical": self.layers_with_critical,
        }


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _risk_bar(score: int, width: int = 10) -> str:
    """Return a simple ASCII progress bar for a 0-100 score."""
    filled = int(round(score / 100 * width))
    return "[" + "█" * filled + "░" * (width - filled) + "]"


def _risk_class_from_score(score: int) -> str:
    """Map a 0-100 integer risk score to a risk class label."""
    if score >= 90:
        return "CATASTROPHIC"
    if score >= 70:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def _severity_rank(severity: str) -> int:
    """Numeric rank for sorting (higher = more severe)."""
    return {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}.get(
        str(severity).upper(), 0
    )


def _layer_for_node_type(node_type_value: str) -> str:
    """Map a KGNodeType value string to a security layer name."""
    _map: Dict[str, str] = {
        "code_unit": "code",
        "function": "code",
        "method": "code",
        "source": "code",
        "sink": "code",
        "dataflow": "code",
        "finding": "code",
        "runtime_finding": "code",
        "dependency": "dependencies",
        "cve": "dependencies",
        "endpoint": "api",
        "api_route": "api",
        "cloud_resource": "cloud",
        "cloud_storage": "cloud",
        "cloud_database": "cloud",
        "cloud_network": "cloud",
        "cloud_account": "cloud",
        "cloud_function": "cloud",
        "iam_identity": "iam",
        "iam_role": "iam",
        "iam_permission": "iam",
        "container": "container",
        "container_image": "container",
        "k8s_pod": "kubernetes",
        "k8s_namespace": "kubernetes",
        "cluster": "kubernetes",
        "smart_contract": "blockchain",
    }
    return _map.get(str(node_type_value).lower(), "other")


def _estimate_economic_exposure(critical_count: int, high_count: int) -> str:
    """Return a rough economic exposure bracket as a string."""
    total_weighted = critical_count * 5_000_000 + high_count * 500_000
    if total_weighted == 0:
        return "$0"
    if total_weighted >= 50_000_000:
        return f">${total_weighted // 1_000_000}M (estimated)"
    if total_weighted >= 1_000_000:
        return f"~${total_weighted // 1_000_000}M (estimated)"
    return f"~${total_weighted // 1_000}K (estimated)"


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------


class ExecutiveDashboardGenerator:
    """
    Generates ExecutiveDashboardReport from enterprise risk report and security graph.

    All inputs are optional. The generator gracefully degrades when individual
    data sources are absent, producing a best-effort report from whatever is
    available.
    """

    def generate(
        self,
        enterprise_report: Optional[Any] = None,     # EnterpriseRiskReport
        security_graph: Optional[Any] = None,         # UnifiedSecurityGraph / SecurityKnowledgeGraph
        iam_graph: Optional[Any] = None,              # IAMGraph
        correlation_report: Optional[Any] = None,     # CorrelationReport
        business_impacts: Optional[List[Any]] = None, # List[BusinessImpactScore]
        findings: Optional[List[Dict]] = None,        # raw findings for fallback
    ) -> ExecutiveDashboardReport:
        """
        Build the complete executive dashboard report from available inputs.

        Priority order for each data element:
          1. Dedicated structured source (enterprise_report, iam_graph, etc.)
          2. Graph traversal (security_graph)
          3. Raw findings list fallback
          4. Empty / zero defaults
        """
        findings = findings or []

        # ----- core scores -----
        overall_risk_score = self._compute_overall_risk(
            enterprise_report, security_graph, findings
        )
        overall_risk_class = _risk_class_from_score(overall_risk_score)

        # ----- top attack paths -----
        top_attack_paths = self._extract_top_attack_paths(
            security_graph, correlation_report
        )

        # ----- top exploitable risks -----
        top_exploitable_risks = self._extract_top_risks(enterprise_report, business_impacts)

        # ----- cloud exposure -----
        cloud_exposure_summary = self._build_cloud_exposure_summary(
            security_graph, iam_graph
        )

        # ----- business impact -----
        business_impact_summary = self._build_business_impact_summary(
            business_impacts, enterprise_report
        )

        # ----- verified findings -----
        verified_findings_count = self._count_verified_findings(
            security_graph, findings
        )

        # ----- layer breakdown -----
        layer_risk_breakdown = self._extract_layer_breakdown(
            enterprise_report, security_graph, findings
        )
        critical_findings_by_layer = self._count_critical_by_layer(
            security_graph, findings
        )

        # ----- total findings / chains -----
        total_findings = self._count_total_findings(
            enterprise_report, security_graph, findings
        )
        critical_chains = self._count_critical_chains(enterprise_report, security_graph)

        # ----- layers with critical severity -----
        layers_with_critical = [
            layer
            for layer, cnt in critical_findings_by_layer.items()
            if cnt > 0
        ]

        # ----- remediation priorities -----
        remediation_priorities = self._build_remediation_priorities(
            top_attack_paths,
            cloud_exposure_summary,
            layer_risk_breakdown,
            critical_findings_by_layer,
        )

        return ExecutiveDashboardReport(
            generated_at=datetime.now(timezone.utc).isoformat(),
            overall_risk_score=overall_risk_score,
            overall_risk_class=overall_risk_class,
            top_attack_paths=top_attack_paths,
            top_exploitable_risks=top_exploitable_risks,
            business_impact_summary=business_impact_summary,
            cloud_exposure_summary=cloud_exposure_summary,
            verified_findings_count=verified_findings_count,
            layer_risk_breakdown=layer_risk_breakdown,
            critical_findings_by_layer=critical_findings_by_layer,
            remediation_priorities=remediation_priorities,
            total_findings=total_findings,
            critical_chains=critical_chains,
            layers_with_critical=layers_with_critical,
        )

    # ------------------------------------------------------------------
    # Internal: overall risk
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_overall_risk(
        enterprise_report: Optional[Any],
        security_graph: Optional[Any],
        findings: List[Dict],
    ) -> int:
        """Derive a 0-100 integer overall risk score from the best available source."""
        # 1. enterprise_report.overall_risk_score (int or float)
        if enterprise_report is not None:
            for attr in ("overall_risk_score", "risk_score", "score"):
                val = getattr(enterprise_report, attr, None)
                if val is not None:
                    return max(0, min(100, int(round(float(val)))))

        # 2. security_graph risk_score
        if security_graph is not None:
            for attr in ("risk_score", "overall_risk_score"):
                val = getattr(security_graph, attr, None)
                if val is not None:
                    raw = float(val)
                    # attack_graph risk_score is 0-100 already; normalise if < 1.0
                    if raw <= 1.0:
                        raw = raw * 100.0
                    return max(0, min(100, int(round(raw))))

        # 3. Derive from raw findings severity distribution
        if findings:
            _w = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 8, "LOW": 3, "INFO": 1}
            total = sum(
                _w.get(str(f.get("severity", "INFO")).upper(), 1) for f in findings
            )
            normalised = min(100, int(total / max(len(findings), 1)))
            return normalised

        return 0

    # ------------------------------------------------------------------
    # Internal: top attack paths
    # ------------------------------------------------------------------

    def _extract_top_attack_paths(
        self,
        security_graph: Optional[Any],
        correlation_report: Optional[Any],
    ) -> List[AttackPathSummary]:
        """
        Extract up to 5 top attack paths ranked by severity then business impact.

        Sources tried in order:
          1. security_graph.critical_paths (AttackGraph / SecurityKnowledgeGraph)
          2. correlation_report chains / attack_paths
          3. Empty list
        """
        paths: List[AttackPathSummary] = []

        # --- Source 1: AttackGraph.critical_paths ---
        if security_graph is not None:
            node_map: Dict[str, Any] = {}
            # Handle both AttackGraph (nodes=List[GraphNode]) and
            # SecurityKnowledgeGraph (nodes=List[KGNode])
            raw_nodes = getattr(security_graph, "nodes", []) or []
            if isinstance(raw_nodes, dict):
                # AttackGraph nodes may be stored as {id: dict} in some variants
                for nid, ndata in raw_nodes.items():
                    node_map[nid] = ndata
            else:
                for n in raw_nodes:
                    nid = getattr(n, "node_id", None) or n.get("node_id", "")
                    if nid:
                        node_map[nid] = n

            critical_paths = getattr(security_graph, "critical_paths", []) or []
            for path_nodes_ids in critical_paths[:20]:
                path_summary = self._path_ids_to_summary(path_nodes_ids, node_map)
                if path_summary is not None:
                    paths.append(path_summary)

        # --- Source 2: correlation_report ---
        if correlation_report is not None:
            corr_chains = (
                getattr(correlation_report, "attack_paths", None)
                or getattr(correlation_report, "chains", None)
                or getattr(correlation_report, "critical_chains", None)
                or []
            )
            for chain in corr_chains[:20]:
                path_summary = self._chain_to_summary(chain)
                if path_summary is not None:
                    paths.append(path_summary)

        # Rank: CRITICAL first, then by business_impact_score desc
        paths.sort(
            key=lambda p: (_severity_rank(p.severity), p.business_impact_score),
            reverse=True,
        )

        # Re-number and return top 5
        result: List[AttackPathSummary] = []
        for rank, ap in enumerate(paths[:5], start=1):
            ap.rank = rank
            result.append(ap)
        return result

    def _path_ids_to_summary(
        self,
        path_ids: List[str],
        node_map: Dict[str, Any],
    ) -> Optional[AttackPathSummary]:
        """Convert a list of node IDs into an AttackPathSummary."""
        if not path_ids:
            return None

        labels: List[str] = []
        layers_set: List[str] = []
        max_severity = "LOW"
        attack_type = "multi-layer"

        for nid in path_ids:
            node = node_map.get(nid)
            if node is None:
                labels.append(nid.split(":")[-1][:30])
                continue

            # Label
            lbl = (
                getattr(node, "label", None)
                or (node.get("label") if isinstance(node, dict) else None)
                or nid.split(":")[-1][:30]
            )
            labels.append(str(lbl).split("\n")[0][:40])

            # Severity
            props = (
                getattr(node, "properties", {})
                or (node.get("properties", {}) if isinstance(node, dict) else {})
            )
            sev = props.get("severity", "")
            if _severity_rank(sev) > _severity_rank(max_severity):
                max_severity = sev.upper() if sev else max_severity

            # Layer
            ntype = (
                getattr(node, "type", None)
                or (node.get("type") if isinstance(node, dict) else None)
                or ""
            )
            ntype_val = ntype.value if hasattr(ntype, "value") else str(ntype)
            layer = _layer_for_node_type(ntype_val)
            if layer not in layers_set:
                layers_set.append(layer)

            # Attack type hint from CWE
            cwe = props.get("cwe_id", props.get("cwe", ""))
            if cwe:
                attack_type = _attack_type_from_cwe(cwe)

        if not labels:
            return None

        path_description = " → ".join(labels[:7])
        impact_score = _severity_rank(max_severity) * 20

        return AttackPathSummary(
            rank=0,
            path_description=path_description,
            layers=layers_set,
            severity=max_severity,
            business_impact_score=min(100, impact_score),
            attack_type=attack_type,
        )

    def _chain_to_summary(self, chain: Any) -> Optional[AttackPathSummary]:
        """Convert a correlation chain / ChainResult object into an AttackPathSummary."""
        if chain is None:
            return None

        description = (
            getattr(chain, "narrative", None)
            or getattr(chain, "description", None)
            or getattr(chain, "title", None)
            or str(chain)
        )
        severity = str(
            getattr(chain, "severity", None)
            or getattr(chain, "impact", "MEDIUM")
        ).upper()
        chain_type = str(getattr(chain, "chain_type", "unknown"))
        impact_score = _severity_rank(severity) * 20

        layers: List[str] = []
        for step in getattr(chain, "steps", []):
            step_type = str(getattr(step, "step_type", "")).lower()
            if "cloud" in step_type:
                if "cloud" not in layers:
                    layers.append("cloud")
            elif "iam" in step_type or "priv" in step_type:
                if "iam" not in layers:
                    layers.append("iam")
            elif "container" in step_type or "k8s" in step_type:
                if "container" not in layers:
                    layers.append("container")
            else:
                if "code" not in layers:
                    layers.append("code")

        if not layers:
            layers = ["code"]

        return AttackPathSummary(
            rank=0,
            path_description=str(description)[:120],
            layers=layers,
            severity=severity,
            business_impact_score=min(100, impact_score),
            attack_type=_attack_type_from_chain_type(chain_type),
        )

    # ------------------------------------------------------------------
    # Internal: top risks
    # ------------------------------------------------------------------

    def _extract_top_risks(
        self,
        enterprise_report: Optional[Any],
        business_impacts: Optional[List[Any]],
    ) -> List[Dict[str, Any]]:
        """
        Return up to 5 top exploitable risks.

        Sources tried in order:
          1. business_impacts list (BusinessImpactScore objects or dicts)
          2. enterprise_report.top_risks
        """
        risks: List[Dict[str, Any]] = []

        # --- Source 1: business_impacts ---
        if business_impacts:
            for bi in business_impacts:
                if isinstance(bi, dict):
                    risks.append(bi)
                else:
                    risks.append({
                        "title": (
                            getattr(bi, "title", None)
                            or getattr(bi, "rule_id", None)
                            or getattr(bi, "name", "Unknown Risk")
                        ),
                        "severity": str(
                            getattr(bi, "severity", "MEDIUM")
                        ).upper(),
                        "impact_score": float(
                            getattr(bi, "impact_score", None)
                            or getattr(bi, "score", None)
                            or getattr(bi, "risk_score", 0)
                        ),
                        "description": str(getattr(bi, "description", "")),
                        "layer": str(getattr(bi, "layer", "unknown")),
                        "recommendation": str(getattr(bi, "recommendation", "")),
                    })

        # --- Source 2: enterprise_report.top_risks ---
        if not risks and enterprise_report is not None:
            top_risks_raw = (
                getattr(enterprise_report, "top_risks", None)
                or getattr(enterprise_report, "critical_findings", None)
                or []
            )
            for r in top_risks_raw:
                if isinstance(r, dict):
                    risks.append(r)
                elif isinstance(r, str):
                    risks.append({"title": r, "severity": "HIGH", "impact_score": 70})
                else:
                    risks.append({
                        "title": str(getattr(r, "title", getattr(r, "rule_id", str(r)))),
                        "severity": str(getattr(r, "severity", "HIGH")).upper(),
                        "impact_score": float(getattr(r, "risk_score", 70)),
                    })

        # Sort by impact_score descending, return top 5
        risks.sort(key=lambda x: float(x.get("impact_score", x.get("risk_score", 0))), reverse=True)
        return risks[:5]

    # ------------------------------------------------------------------
    # Internal: cloud exposure
    # ------------------------------------------------------------------

    def _build_cloud_exposure_summary(
        self,
        security_graph: Optional[Any],
        iam_graph: Optional[Any],
    ) -> CloudExposureSummary:
        """
        Build CloudExposureSummary by querying graph objects.

        security_graph: may have find_exposed_resources() / find_cloud_attack_paths()
        iam_graph:      has find_overprivileged_identities() / find_privilege_escalation_paths()
        """
        public_resources = 0
        open_ports = 0
        public_databases = 0
        overprivileged_identities = 0
        privilege_escalation_paths = 0
        exposed_secrets = 0

        # --- From security_graph ---
        if security_graph is not None:
            # Try graph-level query methods (monkey-patched in cloud_query.py)
            for method_name in ("find_exposed_resources",):
                method = getattr(security_graph, method_name, None)
                if callable(method):
                    try:
                        exposed = method() if not _takes_graph_arg(method) else method(security_graph)
                        if exposed:
                            public_resources += len(exposed)
                            public_databases += sum(
                                1 for r in exposed
                                if _is_database_resource(r)
                            )
                    except Exception:
                        pass

            # Fallback: scan nodes directly
            raw_nodes = getattr(security_graph, "nodes", []) or []
            if isinstance(raw_nodes, list):
                cloud_types = {
                    "cloud_resource", "cloud_storage", "cloud_database",
                    "cloud_network", "cloud_account", "cloud_function",
                }
                for node in raw_nodes:
                    ntype = getattr(node, "type", None)
                    ntype_val = (ntype.value if hasattr(ntype, "value") else str(ntype)).lower()
                    props = getattr(node, "properties", {}) or {}
                    if ntype_val in cloud_types and props.get("public_access"):
                        public_resources += 1
                        if "database" in ntype_val or "db" in str(props.get("label", "")).lower():
                            public_databases += 1
                    # Count exposed port findings
                    if "port" in str(props.get("description", "")).lower() and props.get("public_access"):
                        open_ports += 1
                    # Secrets in properties
                    if (
                        ntype_val == "finding"
                        and any(
                            kw in str(props.get("rule_id", "")).lower()
                            or kw in str(props.get("description", "")).lower()
                            for kw in ("secret", "credential", "token", "key", "password")
                        )
                    ):
                        exposed_secrets += 1

        # --- From iam_graph ---
        if iam_graph is not None:
            try:
                overprivileged = iam_graph.find_overprivileged_identities()
                overprivileged_identities = len(overprivileged) if overprivileged else 0
            except Exception:
                overprivileged_identities = 0

            try:
                esc_paths = iam_graph.find_privilege_escalation_paths()
                privilege_escalation_paths = len(esc_paths) if esc_paths else 0
            except Exception:
                privilege_escalation_paths = 0

        return CloudExposureSummary(
            public_resources=public_resources,
            open_ports=open_ports,
            public_databases=public_databases,
            overprivileged_identities=overprivileged_identities,
            privilege_escalation_paths=privilege_escalation_paths,
            exposed_secrets=exposed_secrets,
        )

    # ------------------------------------------------------------------
    # Internal: business impact summary
    # ------------------------------------------------------------------

    def _build_business_impact_summary(
        self,
        business_impacts: Optional[List[Any]],
        enterprise_report: Optional[Any],
    ) -> Dict[str, Any]:
        """
        Build a dict summary of business impact data.

        Returns:
          {
            "total_at_risk":              int,
            "critical_impact":            int,
            "high_impact":                int,
            "average_score":              float,
            "estimated_economic_exposure": str,
          }
        """
        total_at_risk = 0
        critical_impact = 0
        high_impact = 0
        scores: List[float] = []

        if business_impacts:
            for bi in business_impacts:
                if isinstance(bi, dict):
                    sev = str(bi.get("severity", "MEDIUM")).upper()
                    score_val = float(bi.get("impact_score", bi.get("score", bi.get("risk_score", 0))))
                else:
                    sev = str(getattr(bi, "severity", "MEDIUM")).upper()
                    score_val = float(
                        getattr(bi, "impact_score", None)
                        or getattr(bi, "score", None)
                        or getattr(bi, "risk_score", 0)
                    )
                total_at_risk += 1
                if sev == "CRITICAL":
                    critical_impact += 1
                elif sev == "HIGH":
                    high_impact += 1
                scores.append(score_val)

        elif enterprise_report is not None:
            # Pull from enterprise_report if available
            for attr in ("total_findings", "finding_count"):
                val = getattr(enterprise_report, attr, None)
                if val is not None:
                    total_at_risk = int(val)
                    break
            critical_impact = getattr(enterprise_report, "critical_count", 0) or 0
            high_impact = getattr(enterprise_report, "high_count", 0) or 0

        average_score = sum(scores) / len(scores) if scores else 0.0

        return {
            "total_at_risk": total_at_risk,
            "critical_impact": critical_impact,
            "high_impact": high_impact,
            "average_score": round(average_score, 1),
            "estimated_economic_exposure": _estimate_economic_exposure(critical_impact, high_impact),
        }

    # ------------------------------------------------------------------
    # Internal: layer breakdown
    # ------------------------------------------------------------------

    def _extract_layer_breakdown(
        self,
        enterprise_report: Optional[Any],
        security_graph: Optional[Any],
        findings: List[Dict],
    ) -> Dict[str, int]:
        """
        Return {layer: risk_score (0-100)} from enterprise_report.layer_scores
        or by scanning the security_graph node types.
        """
        # 1. enterprise_report.layer_scores
        if enterprise_report is not None:
            for attr in ("layer_scores", "layer_risk_breakdown", "layer_risk"):
                layer_scores = getattr(enterprise_report, attr, None)
                if layer_scores and isinstance(layer_scores, dict):
                    # Ensure values are ints 0-100
                    return {
                        k: max(0, min(100, int(round(float(v)))))
                        for k, v in layer_scores.items()
                    }

        # 2. Derive from security_graph
        if security_graph is not None:
            return self._derive_layer_scores_from_graph(security_graph)

        # 3. Derive from raw findings
        if findings:
            return self._derive_layer_scores_from_findings(findings)

        return {}

    @staticmethod
    def _derive_layer_scores_from_graph(security_graph: Any) -> Dict[str, int]:
        """Scan KG nodes and accumulate severity-weighted scores per layer."""
        _w = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 8, "LOW": 3, "INFO": 1}
        layer_raw: Dict[str, float] = {}
        layer_max: Dict[str, float] = {}

        raw_nodes = getattr(security_graph, "nodes", []) or []
        if isinstance(raw_nodes, dict):
            raw_nodes = list(raw_nodes.values())

        for node in raw_nodes:
            ntype = getattr(node, "type", None)
            ntype_val = (ntype.value if hasattr(ntype, "value") else str(ntype)).lower()
            layer = _layer_for_node_type(ntype_val)
            props = getattr(node, "properties", {}) or {}
            sev = str(props.get("severity", "INFO")).upper()
            weight = _w.get(sev, 1)
            layer_raw[layer] = layer_raw.get(layer, 0.0) + weight
            layer_max[layer] = layer_max.get(layer, 0.0) + _w["CRITICAL"]

        result: Dict[str, int] = {}
        for layer, raw in layer_raw.items():
            mx = layer_max.get(layer, _w["CRITICAL"])
            result[layer] = max(0, min(100, int(round(raw / mx * 100))))

        return result

    @staticmethod
    def _derive_layer_scores_from_findings(findings: List[Dict]) -> Dict[str, int]:
        """Derive layer risk scores from raw findings list."""
        _w = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 8, "LOW": 3, "INFO": 1}
        layer_raw: Dict[str, float] = {}

        for f in findings:
            # Infer layer from rule_id or file path
            rule_id = str(f.get("rule_id", "")).upper()
            file_path = str(f.get("file", "")).lower()
            sev = str(f.get("severity", "INFO")).upper()
            weight = _w.get(sev, 1)

            if any(x in rule_id for x in ("CLOUD", "S3", "EC2", "IAC", "RDS")):
                layer = "cloud"
            elif any(x in rule_id for x in ("IAM", "ROLE", "PRIV", "POLICY")):
                layer = "iam"
            elif any(x in rule_id for x in ("CONTAINER", "DOCKER", "K8S", "HELM")):
                layer = "container"
            elif any(x in rule_id for x in ("CVE", "DEPENDENCY", "SUPPLY")):
                layer = "dependencies"
            else:
                layer = "code"

            layer_raw[layer] = layer_raw.get(layer, 0.0) + weight

        if not layer_raw:
            return {}

        max_raw = max(layer_raw.values(), default=1.0)
        return {
            layer: max(0, min(100, int(round(raw / max_raw * 100))))
            for layer, raw in layer_raw.items()
        }

    # ------------------------------------------------------------------
    # Internal: critical findings by layer
    # ------------------------------------------------------------------

    @staticmethod
    def _count_critical_by_layer(
        security_graph: Optional[Any],
        findings: List[Dict],
    ) -> Dict[str, int]:
        """Return {layer: count_of_critical_findings}."""
        counts: Dict[str, int] = {}

        if security_graph is not None:
            raw_nodes = getattr(security_graph, "nodes", []) or []
            if isinstance(raw_nodes, dict):
                raw_nodes = list(raw_nodes.values())
            for node in raw_nodes:
                props = getattr(node, "properties", {}) or {}
                sev = str(props.get("severity", "INFO")).upper()
                if sev == "CRITICAL":
                    ntype = getattr(node, "type", None)
                    ntype_val = (ntype.value if hasattr(ntype, "value") else str(ntype)).lower()
                    layer = _layer_for_node_type(ntype_val)
                    counts[layer] = counts.get(layer, 0) + 1

        elif findings:
            for f in findings:
                sev = str(f.get("severity", "INFO")).upper()
                if sev == "CRITICAL":
                    rule_id = str(f.get("rule_id", "")).upper()
                    if any(x in rule_id for x in ("CLOUD", "S3", "EC2", "IAC", "RDS")):
                        layer = "cloud"
                    elif any(x in rule_id for x in ("IAM", "ROLE", "PRIV")):
                        layer = "iam"
                    elif any(x in rule_id for x in ("CONTAINER", "DOCKER", "K8S")):
                        layer = "container"
                    elif any(x in rule_id for x in ("CVE", "DEPENDENCY")):
                        layer = "dependencies"
                    else:
                        layer = "code"
                    counts[layer] = counts.get(layer, 0) + 1

        return counts

    # ------------------------------------------------------------------
    # Internal: verified findings
    # ------------------------------------------------------------------

    @staticmethod
    def _count_verified_findings(
        security_graph: Optional[Any],
        findings: List[Dict],
    ) -> int:
        """Count RUNTIME_FINDING nodes with verification_status = verified."""
        if security_graph is not None:
            raw_nodes = getattr(security_graph, "nodes", []) or []
            if isinstance(raw_nodes, dict):
                raw_nodes = list(raw_nodes.values())
            count = 0
            for node in raw_nodes:
                ntype = getattr(node, "type", None)
                ntype_val = (ntype.value if hasattr(ntype, "value") else str(ntype)).lower()
                if "runtime_finding" in ntype_val:
                    props = getattr(node, "properties", {}) or {}
                    if props.get("verification_status") == "verified":
                        count += 1
            return count

        # Fallback: raw findings with verification marker
        return sum(
            1 for f in findings
            if str(f.get("verification_status", "")).lower() == "verified"
        )

    # ------------------------------------------------------------------
    # Internal: total findings
    # ------------------------------------------------------------------

    @staticmethod
    def _count_total_findings(
        enterprise_report: Optional[Any],
        security_graph: Optional[Any],
        findings: List[Dict],
    ) -> int:
        if enterprise_report is not None:
            for attr in ("total_findings", "finding_count", "total"):
                val = getattr(enterprise_report, attr, None)
                if val is not None:
                    return int(val)

        if security_graph is not None:
            raw_nodes = getattr(security_graph, "nodes", []) or []
            count = 0
            for node in raw_nodes:
                ntype = getattr(node, "type", None)
                ntype_val = (ntype.value if hasattr(ntype, "value") else str(ntype)).lower()
                if "finding" in ntype_val:
                    count += 1
            return count if count > 0 else len(getattr(security_graph, "nodes", [])) or 0

        return len(findings)

    # ------------------------------------------------------------------
    # Internal: critical chains
    # ------------------------------------------------------------------

    @staticmethod
    def _count_critical_chains(
        enterprise_report: Optional[Any],
        security_graph: Optional[Any],
    ) -> int:
        if enterprise_report is not None:
            for attr in ("critical_chains", "critical_chain_count"):
                val = getattr(enterprise_report, attr, None)
                if val is not None:
                    return int(val)

        if security_graph is not None:
            critical_paths = getattr(security_graph, "critical_paths", []) or []
            return len(critical_paths)

        return 0

    # ------------------------------------------------------------------
    # Internal: remediation priorities
    # ------------------------------------------------------------------

    @staticmethod
    def _build_remediation_priorities(
        top_attack_paths: List[AttackPathSummary],
        cloud_exposure: CloudExposureSummary,
        layer_risk_breakdown: Dict[str, int],
        critical_by_layer: Dict[str, int],
    ) -> List[str]:
        """
        Derive an ordered remediation priority list from the dashboard data.

        Logic:
          1. Any critical attack path starting with a code-level entry → patch first
          2. Privilege escalation paths → remediate IAM
          3. Public cloud resources → tighten network controls
          4. Overprivileged identities → apply least-privilege
          5. High-risk layers → address by descending score
          6. Container / K8s vulnerabilities
          7. Dependency CVEs
        """
        priorities: List[str] = []
        added: set = set()

        def _add(msg: str) -> None:
            if msg not in added:
                added.add(msg)
                priorities.append(msg)

        # 1. Critical attack paths
        for ap in top_attack_paths:
            if ap.severity == "CRITICAL":
                _add(
                    f"IMMEDIATE: Remediate critical attack path — {ap.attack_type} "
                    f"across layers: {' → '.join(ap.layers)}"
                )

        # 2. Privilege escalation
        if cloud_exposure.privilege_escalation_paths > 0:
            _add(
                f"HIGH: Eliminate {cloud_exposure.privilege_escalation_paths} "
                f"IAM privilege escalation path(s) — review iam:PassRole and "
                f"dangerous permission combinations"
            )

        # 3. Public cloud resources
        if cloud_exposure.public_resources > 0:
            _add(
                f"HIGH: Restrict public access on {cloud_exposure.public_resources} "
                f"cloud resource(s) — audit S3 bucket policies and security groups"
            )
        if cloud_exposure.public_databases > 0:
            _add(
                f"CRITICAL: Immediately disable public access on "
                f"{cloud_exposure.public_databases} publicly-exposed database(s)"
            )

        # 4. Overprivileged identities
        if cloud_exposure.overprivileged_identities > 0:
            _add(
                f"HIGH: Apply least-privilege to {cloud_exposure.overprivileged_identities} "
                f"overprivileged IAM identit(ies) — remove wildcard actions"
            )

        # 5. Exposed secrets
        if cloud_exposure.exposed_secrets > 0:
            _add(
                f"CRITICAL: Rotate {cloud_exposure.exposed_secrets} "
                f"exposed secret(s)/credential(s) immediately"
            )

        # 6. High-risk layers by score
        sorted_layers = sorted(
            layer_risk_breakdown.items(), key=lambda x: -x[1]
        )
        for layer, score in sorted_layers:
            if score >= 70:
                crit_n = critical_by_layer.get(layer, 0)
                _add(
                    f"HIGH: Address {layer} layer findings (risk score {score}/100, "
                    f"{crit_n} critical)"
                )

        # 7. Container layer
        if "container" in layer_risk_breakdown or "kubernetes" in layer_risk_breakdown:
            k8s_score = layer_risk_breakdown.get("kubernetes", 0)
            container_score = layer_risk_breakdown.get("container", 0)
            if max(k8s_score, container_score) >= 40:
                _add(
                    "MEDIUM: Patch container/Kubernetes vulnerabilities — update base "
                    "images and review pod security policies"
                )

        # 8. Dependency CVEs
        if "dependencies" in layer_risk_breakdown:
            dep_score = layer_risk_breakdown["dependencies"]
            if dep_score >= 30:
                _add(
                    "MEDIUM: Update vulnerable dependencies — run SCA scan and apply "
                    "vendor security patches"
                )

        # Default if nothing flagged
        if not priorities:
            priorities.append(
                "LOW: Continue routine vulnerability management and monitoring"
            )

        return priorities


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def _attack_type_from_cwe(cwe: str) -> str:
    """Map a CWE ID to a human-readable attack type."""
    _map: Dict[str, str] = {
        "CWE-89":  "SQL Injection",
        "CWE-79":  "Cross-Site Scripting (XSS)",
        "CWE-78":  "Command Injection",
        "CWE-22":  "Path Traversal",
        "CWE-918": "SSRF",
        "CWE-502": "Deserialization",
        "CWE-798": "Hardcoded Credential",
        "CWE-306": "Authentication Bypass",
        "CWE-862": "Authorization Bypass",
        "CWE-284": "Privilege Escalation",
        "CWE-200": "Information Disclosure",
    }
    return _map.get(cwe.upper(), f"Vulnerability ({cwe})")


def _attack_type_from_chain_type(chain_type: str) -> str:
    """Map a chain_type string to a human-readable attack type."""
    chain_type = chain_type.lower()
    if "inject" in chain_type:
        return "Injection Attack"
    if "auth" in chain_type:
        return "Authentication Bypass"
    if "secret" in chain_type or "credential" in chain_type:
        return "Credential Exposure"
    if "priv" in chain_type or "escalat" in chain_type:
        return "Privilege Escalation"
    if "cloud" in chain_type:
        return "Cloud Lateral Movement"
    if "iam" in chain_type:
        return "IAM Abuse"
    return "Multi-Stage Attack"


def _is_database_resource(node: Any) -> bool:
    """Return True if a node appears to represent a database resource."""
    if isinstance(node, dict):
        ntype = str(node.get("type", "")).lower()
        label = str(node.get("label", "")).lower()
    else:
        ntype = str(getattr(node, "type", "")).lower()
        label = str(getattr(node, "label", "")).lower()
    return "database" in ntype or "db" in label or "rds" in label


def _takes_graph_arg(method: Any) -> bool:
    """Heuristic: does this callable accept a graph positional argument?"""
    import inspect
    try:
        sig = inspect.signature(method)
        params = list(sig.parameters.values())
        # If it's a bound method with only `self`, it takes no extra args.
        return len(params) > 0
    except (ValueError, TypeError):
        return False
