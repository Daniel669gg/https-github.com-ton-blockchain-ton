"""
TythanAI Phase 9 — Cloud Security Cross-Layer Correlation Engine

Correlates findings across security layers to reconstruct end-to-end exploit chains:
  Code Vulnerability → Reachable CVE → Vulnerable Container →
  IAM Permission → Cloud Resource → Business Asset

No actual cloud API calls. Correlation is based on:
  - Severity cross-correlation (CRITICAL+CRITICAL = confirmed chain)
  - Package names matching container contents
  - Service/container names matching IAM principal names
  - Namespace + service account matching K8s RBAC
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Severity ordering
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
_SEVERITY_NAMES = {v: k for k, v in _SEVERITY_ORDER.items()}

# ---------------------------------------------------------------------------
# Attack type labels
# ---------------------------------------------------------------------------

_ATTACK_DATA_EXFIL = "DATA_EXFILTRATION"
_ATTACK_PRIV_ESC = "PRIVILEGE_ESCALATION"
_ATTACK_LATERAL = "LATERAL_MOVEMENT"
_ATTACK_FULL = "FULL_COMPROMISE"

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class ChainLink:
    layer: str          # code | dependency | container | k8s | iam | cloud
    finding_id: str
    severity: str
    label: str
    resource: str       # file path, image name, resource ARN, etc.


@dataclass
class ExploitChain:
    chain_id: str
    links: List[ChainLink]
    chain_severity: str      # highest severity across links
    attack_type: str         # DATA_EXFILTRATION | PRIVILEGE_ESCALATION | LATERAL_MOVEMENT | FULL_COMPROMISE
    description: str
    confidence: float        # 0.0–1.0 based on correlation strength

    def layers_count(self) -> int:
        return len({l.layer for l in self.links})

    def to_dict(self) -> Dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "links": [
                {
                    "layer": lnk.layer,
                    "finding_id": lnk.finding_id,
                    "severity": lnk.severity,
                    "label": lnk.label,
                    "resource": lnk.resource,
                }
                for lnk in self.links
            ],
            "chain_severity": self.chain_severity,
            "attack_type": self.attack_type,
            "description": self.description,
            "confidence": round(self.confidence, 3),
            "layers_count": self.layers_count(),
        }


@dataclass
class CorrelationReport:
    total_chains: int
    critical_chains: int
    exploit_chains: List[ExploitChain]
    layers_analyzed: List[str]
    cross_layer_findings: int   # total findings that appear in ≥2 layers

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_chains": self.total_chains,
            "critical_chains": self.critical_chains,
            "exploit_chains": [c.to_dict() for c in self.exploit_chains],
            "layers_analyzed": self.layers_analyzed,
            "cross_layer_findings": self.cross_layer_findings,
        }


# ---------------------------------------------------------------------------
# Helper: normalise a finding to a guaranteed dict with standard keys
# ---------------------------------------------------------------------------

def _normalise(finding: Any, layer: str) -> Dict[str, Any]:
    """Return a copy of *finding* guaranteed to have the keys we need."""
    if not isinstance(finding, dict):
        return {}
    out = dict(finding)
    out.setdefault("id", str(uuid.uuid4()))
    out.setdefault("severity", "LOW")
    out.setdefault("description", "")
    out.setdefault("label", out.get("title", out.get("rule_id", out.get("name", layer))))
    out.setdefault("resource", out.get("file", out.get("image", out.get("arn", out.get("resource_id", "")))))
    out.setdefault("package", out.get("package_name", out.get("affected_package", "")))
    out.setdefault("cwe", out.get("cwe_id", ""))
    out.setdefault("service_account", out.get("sa", out.get("subject", "")))
    out.setdefault("namespace", out.get("ns", ""))
    out.setdefault("principal", out.get("identity", out.get("role", "")))
    out.setdefault("permission", "")
    out.setdefault("resource_type", "")
    out["_layer"] = layer
    return out


# ---------------------------------------------------------------------------
# Core engine
# ---------------------------------------------------------------------------


class CloudCorrelationEngine:
    """
    Correlates security findings across layers to build end-to-end exploit chains.
    Uses structural heuristics, severity matching, and name-based correlation.
    """

    def __init__(self) -> None:
        self._sast: List[Dict] = []
        self._cves: List[Dict] = []
        self._containers: List[Dict] = []
        self._k8s: List[Dict] = []
        self._iam: List[Dict] = []
        self._cloud: List[Dict] = []

    # ------------------------------------------------------------------
    # Ingestion
    # ------------------------------------------------------------------

    def ingest(
        self,
        sast_findings: Optional[List[Dict]] = None,
        cve_findings: Optional[List[Dict]] = None,
        container_findings: Optional[List[Dict]] = None,
        k8s_findings: Optional[List[Dict]] = None,
        iam_findings: Optional[List[Dict]] = None,
        cloud_findings: Optional[List[Dict]] = None,
    ) -> "CloudCorrelationEngine":
        """Store findings in each layer bucket. Returns *self* for chaining."""
        if sast_findings:
            self._sast = [_normalise(f, "code") for f in sast_findings]
        if cve_findings:
            self._cves = [_normalise(f, "dependency") for f in cve_findings]
        if container_findings:
            self._containers = [_normalise(f, "container") for f in container_findings]
        if k8s_findings:
            self._k8s = [_normalise(f, "k8s") for f in k8s_findings]
        if iam_findings:
            self._iam = [_normalise(f, "iam") for f in iam_findings]
        if cloud_findings:
            self._cloud = [_normalise(f, "cloud") for f in cloud_findings]
        return self

    # ------------------------------------------------------------------
    # Main correlation entry point
    # ------------------------------------------------------------------

    def correlate(self) -> CorrelationReport:
        """Build all exploit chains and return a CorrelationReport."""

        # ---- collect per-layer pairwise links ----
        sast_cve_pairs = self._sast_to_cve_links()
        cve_cont_pairs = self._cve_to_container_links()
        cont_k8s_pairs = self._container_to_k8s_links()
        k8s_iam_pairs = self._k8s_to_iam_links()
        iam_cloud_pairs = self._iam_to_cloud_links()

        # Build adjacency maps: finding_id -> list of (finding, confidence)
        # from_layer → to_layer maps
        sast_to_cve: Dict[str, List[Tuple[Dict, float]]] = {}
        for s, c, conf in sast_cve_pairs:
            sast_to_cve.setdefault(s["id"], []).append((c, conf))

        cve_to_cont: Dict[str, List[Tuple[Dict, float]]] = {}
        for c, cn, conf in cve_cont_pairs:
            cve_to_cont.setdefault(c["id"], []).append((cn, conf))

        cont_to_k8s: Dict[str, List[Tuple[Dict, float]]] = {}
        for cn, k, conf in cont_k8s_pairs:
            cont_to_k8s.setdefault(cn["id"], []).append((k, conf))

        k8s_to_iam: Dict[str, List[Tuple[Dict, float]]] = {}
        for k, i, conf in k8s_iam_pairs:
            k8s_to_iam.setdefault(k["id"], []).append((i, conf))

        iam_to_cloud: Dict[str, List[Tuple[Dict, float]]] = {}
        for i, cl, conf in iam_cloud_pairs:
            iam_to_cloud.setdefault(i["id"], []).append((cl, conf))

        # ---- assemble full chains via DFS through the adjacency maps ----
        chains: List[ExploitChain] = []
        seen_signatures: Set[str] = set()

        def _finding_to_link(f: Dict) -> ChainLink:
            return ChainLink(
                layer=f["_layer"],
                finding_id=f["id"],
                severity=f.get("severity", "LOW").upper(),
                label=f.get("label", ""),
                resource=f.get("resource", ""),
            )

        def _build_chains_from_sast(sast_f: Dict) -> None:
            """Walk the full chain tree depth-first and emit every path that
            crosses at least two distinct layers."""
            # Each state: (accumulated_links, accumulated_raw_confidence, last_finding)
            # We keep a stack of partial paths and expand layer by layer.

            initial_link = _finding_to_link(sast_f)
            # Stack entries: (links_so_far, conf_accumulator, last_finding)
            stack: List[Tuple[List[ChainLink], float, Dict]] = [
                ([initial_link], 1.0, sast_f)
            ]

            while stack:
                links, conf_acc, last_f = stack.pop()
                layer = last_f["_layer"]
                expanded = False

                next_map: Optional[Dict[str, List[Tuple[Dict, float]]]] = None
                if layer == "code":
                    next_map = sast_to_cve
                elif layer == "dependency":
                    next_map = cve_to_cont
                elif layer == "container":
                    next_map = cont_to_k8s
                elif layer == "k8s":
                    next_map = k8s_to_iam
                elif layer == "iam":
                    next_map = iam_to_cloud

                if next_map:
                    for next_f, edge_conf in next_map.get(last_f["id"], []):
                        next_link = _finding_to_link(next_f)
                        new_links = links + [next_link]
                        new_conf = conf_acc * edge_conf
                        stack.append((new_links, new_conf, next_f))
                        expanded = True

                # Emit a chain if we have ≥2 layers (even a partial chain is valuable)
                if len({lnk.layer for lnk in links}) >= 2:
                    sig = ":".join(sorted(lnk.finding_id for lnk in links))
                    if sig not in seen_signatures:
                        seen_signatures.add(sig)
                        chain = self._assemble_chain(links, conf_acc)
                        chains.append(chain)

        for sast_f in self._sast:
            _build_chains_from_sast(sast_f)

        # Also build chains that START at CVE level (when no SAST available)
        def _build_chains_from_cve(cve_f: Dict) -> None:
            initial_link = _finding_to_link(cve_f)
            stack: List[Tuple[List[ChainLink], float, Dict]] = [
                ([initial_link], 1.0, cve_f)
            ]
            while stack:
                links, conf_acc, last_f = stack.pop()
                layer = last_f["_layer"]
                next_map = None
                if layer == "dependency":
                    next_map = cve_to_cont
                elif layer == "container":
                    next_map = cont_to_k8s
                elif layer == "k8s":
                    next_map = k8s_to_iam
                elif layer == "iam":
                    next_map = iam_to_cloud

                if next_map:
                    for next_f, edge_conf in next_map.get(last_f["id"], []):
                        stack.append((links + [_finding_to_link(next_f)], conf_acc * edge_conf, next_f))

                if len({lnk.layer for lnk in links}) >= 2:
                    sig = ":".join(sorted(lnk.finding_id for lnk in links))
                    if sig not in seen_signatures:
                        seen_signatures.add(sig)
                        chains.append(self._assemble_chain(links, conf_acc))

        if not self._sast:
            for cve_f in self._cves:
                _build_chains_from_cve(cve_f)

        # Build IAM→Cloud only chains when upper layers absent
        for iam_f, cloud_f, conf in iam_cloud_pairs:
            sig = ":".join(sorted([iam_f["id"], cloud_f["id"]]))
            if sig not in seen_signatures:
                seen_signatures.add(sig)
                links = [_finding_to_link(iam_f), _finding_to_link(cloud_f)]
                chains.append(self._assemble_chain(links, conf))

        # ---- compute cross_layer_findings ----
        finding_to_layers: Dict[str, Set[str]] = {}
        all_pairs_flat = (
            [(s, c) for s, c, _ in sast_cve_pairs]
            + [(c, cn) for c, cn, _ in cve_cont_pairs]
            + [(cn, k) for cn, k, _ in cont_k8s_pairs]
            + [(k, i) for k, i, _ in k8s_iam_pairs]
            + [(i, cl) for i, cl, _ in iam_cloud_pairs]
        )
        for a, b in all_pairs_flat:
            finding_to_layers.setdefault(a["id"], set()).add(a["_layer"])
            finding_to_layers.setdefault(b["id"], set()).add(b["_layer"])
        cross_layer = sum(1 for layers in finding_to_layers.values() if len(layers) >= 2)

        # ---- gather layers analyzed ----
        layers_analyzed: List[str] = []
        for bucket, name in [
            (self._sast, "code"),
            (self._cves, "dependency"),
            (self._containers, "container"),
            (self._k8s, "k8s"),
            (self._iam, "iam"),
            (self._cloud, "cloud"),
        ]:
            if bucket:
                layers_analyzed.append(name)

        critical_chains = sum(
            1 for c in chains if c.chain_severity == "CRITICAL"
        )

        return CorrelationReport(
            total_chains=len(chains),
            critical_chains=critical_chains,
            exploit_chains=sorted(chains, key=lambda c: _SEVERITY_ORDER.get(c.chain_severity, 0), reverse=True),
            layers_analyzed=layers_analyzed,
            cross_layer_findings=cross_layer,
        )

    # ------------------------------------------------------------------
    # Chain assembly helper
    # ------------------------------------------------------------------

    def _assemble_chain(self, links: List[ChainLink], raw_confidence: float) -> ExploitChain:
        """Build an ExploitChain from a list of ChainLinks."""
        sev = self._chain_severity(links)
        attack = self._classify_attack(links)
        conf = self._compute_confidence(links, raw_confidence)

        layer_labels = " → ".join(
            f"[{lnk.layer.upper()}] {lnk.label or lnk.resource or lnk.finding_id}"
            for lnk in links
        )
        description = f"{attack} chain spanning {len({lnk.layer for lnk in links})} layers: {layer_labels}"

        return ExploitChain(
            chain_id=str(uuid.uuid4()),
            links=links,
            chain_severity=sev,
            attack_type=attack,
            description=description,
            confidence=conf,
        )

    # ------------------------------------------------------------------
    # Layer-to-layer link builders
    # ------------------------------------------------------------------

    def _sast_to_cve_links(self) -> List[Tuple[Dict, Dict, float]]:
        """Link SAST findings to CVE findings. Returns (sast, cve, confidence) triples."""
        results: List[Tuple[Dict, Dict, float]] = []
        for sast in self._sast:
            sast_cwe = str(sast.get("cwe", "")).strip().lower()
            sast_pkg = str(sast.get("package", "")).strip().lower()
            sast_desc = str(sast.get("description", "")).lower()
            sast_sev = sast.get("severity", "LOW").upper()

            for cve in self._cves:
                cve_cwe = str(cve.get("cwe", "")).strip().lower()
                cve_pkg = str(cve.get("package", "")).strip().lower()
                cve_desc = str(cve.get("description", "")).lower()
                cve_sev = cve.get("severity", "LOW").upper()

                confidence = 0.0

                # CWE match
                if sast_cwe and cve_cwe and sast_cwe == cve_cwe:
                    confidence = max(confidence, 0.8)

                # Package name mentioned in SAST file path or description
                if cve_pkg and (cve_pkg in sast_desc or cve_pkg in sast.get("resource", "").lower()):
                    confidence = max(confidence, 0.6)

                # SAST package matches CVE package exactly
                if sast_pkg and cve_pkg and sast_pkg == cve_pkg:
                    confidence = max(confidence, 0.75)

                # CVE package in SAST description or vice-versa
                if cve_pkg and sast_pkg and (cve_pkg in sast_pkg or sast_pkg in cve_pkg):
                    confidence = max(confidence, 0.55)

                if confidence == 0.0:
                    continue

                # Severity bonus
                if sast_sev == "CRITICAL" and cve_sev == "CRITICAL":
                    confidence = min(1.0, confidence + 0.1)

                results.append((sast, cve, confidence))

        return results

    def _cve_to_container_links(self) -> List[Tuple[Dict, Dict, float]]:
        """Link CVE findings to container findings. Returns (cve, container, confidence) triples."""
        results: List[Tuple[Dict, Dict, float]] = []
        for cve in self._cves:
            cve_pkg = str(cve.get("package", "")).strip().lower()
            cve_sev = cve.get("severity", "LOW").upper()

            for container in self._containers:
                cont_desc = str(container.get("description", "")).lower()
                cont_image = str(container.get("resource", "")).lower()
                cont_label = str(container.get("label", "")).lower()
                cont_sev = container.get("severity", "LOW").upper()

                confidence = 0.0

                # CVE package name appears in container image name or description
                if cve_pkg and (cve_pkg in cont_desc or cve_pkg in cont_image or cve_pkg in cont_label):
                    confidence = max(confidence, 0.9)

                # Same severity level
                if cve_sev == cont_sev and cve_sev in ("CRITICAL", "HIGH"):
                    confidence = max(confidence, 0.7)
                elif cve_sev == cont_sev:
                    confidence = max(confidence, 0.5)

                if confidence == 0.0:
                    continue

                results.append((cve, container, confidence))

        return results

    def _container_to_k8s_links(self) -> List[Tuple[Dict, Dict, float]]:
        """Link container findings to K8s findings. Returns (container, k8s, confidence) triples."""
        results: List[Tuple[Dict, Dict, float]] = []
        for container in self._containers:
            cont_image = str(container.get("resource", "")).lower()
            cont_label = str(container.get("label", "")).lower()
            cont_ns = str(container.get("namespace", "")).strip().lower()

            for k8s in self._k8s:
                k8s_desc = str(k8s.get("description", "")).lower()
                k8s_label = str(k8s.get("label", "")).lower()
                k8s_resource = str(k8s.get("resource", "")).lower()
                k8s_ns = str(k8s.get("namespace", "")).strip().lower()

                confidence = 0.0

                # Container name/image appears in K8s pod/deployment name or description
                # Check both directions: container label in k8s, or k8s resource in container
                img_base = cont_image.split("/")[-1].split(":")[0] if cont_image else ""
                label_base = cont_label.split(":")[0] if cont_label else ""

                for needle in filter(None, [img_base, label_base, cont_label]):
                    if len(needle) >= 3 and (needle in k8s_desc or needle in k8s_resource or needle in k8s_label):
                        confidence = max(confidence, 0.8)

                # Same namespace
                if cont_ns and k8s_ns and cont_ns == k8s_ns:
                    confidence = max(confidence, 0.7)

                if confidence == 0.0:
                    continue

                results.append((container, k8s, confidence))

        return results

    def _k8s_to_iam_links(self) -> List[Tuple[Dict, Dict, float]]:
        """Link K8s service accounts to IAM findings. Returns (k8s, iam, confidence) triples."""
        results: List[Tuple[Dict, Dict, float]] = []
        for k8s in self._k8s:
            k8s_sa = str(k8s.get("service_account", "")).strip().lower()
            k8s_label = str(k8s.get("label", "")).strip().lower()
            k8s_desc = str(k8s.get("description", "")).lower()
            k8s_category = str(k8s.get("category", "")).upper()

            for iam in self._iam:
                iam_principal = str(iam.get("principal", "")).strip().lower()
                iam_label = str(iam.get("label", "")).strip().lower()
                iam_desc = str(iam.get("description", "")).lower()
                iam_category = str(iam.get("category", "")).upper()

                confidence = 0.0

                # Service account name matches IAM principal
                if k8s_sa and iam_principal and (k8s_sa == iam_principal or k8s_sa in iam_principal or iam_principal in k8s_sa):
                    confidence = max(confidence, 0.9)

                # K8s label matches IAM label
                if k8s_label and iam_label and (k8s_label in iam_label or iam_label in k8s_label):
                    confidence = max(confidence, 0.7)

                # Both have RBAC/privilege findings
                rbac_keywords = {"rbac", "privilege", "escalat", "admin", "cluster-admin"}
                k8s_has_rbac = any(kw in k8s_desc for kw in rbac_keywords) or "RBAC" in k8s_category or "PRIV" in k8s_category
                iam_has_similar = any(kw in iam_desc for kw in rbac_keywords) or "PRIV" in iam_category or "OVER" in iam_category

                if k8s_has_rbac and iam_has_similar:
                    confidence = max(confidence, 0.6)

                if confidence == 0.0:
                    continue

                results.append((k8s, iam, confidence))

        return results

    def _iam_to_cloud_links(self) -> List[Tuple[Dict, Dict, float]]:
        """Link IAM findings to cloud resource findings. Returns (iam, cloud, confidence) triples."""

        # Service-type mapping: IAM permission prefix → cloud resource types
        _SERVICE_MAP: Dict[str, List[str]] = {
            "s3": ["storage", "bucket", "s3", "blob"],
            "rds": ["database", "rds", "sql", "db", "aurora"],
            "ec2": ["compute", "instance", "vm", "ec2"],
            "lambda": ["function", "lambda", "serverless"],
            "kms": ["kms", "encryption", "key"],
            "secretsmanager": ["secret", "vault"],
            "iam": ["iam", "identity", "role", "policy"],
            "cloudformation": ["stack", "cloudformation", "template"],
            "eks": ["eks", "kubernetes", "cluster", "k8s"],
        }

        results: List[Tuple[Dict, Dict, float]] = []
        for iam in self._iam:
            iam_permission = str(iam.get("permission", "")).lower()
            iam_principal = str(iam.get("principal", "")).lower()
            iam_desc = str(iam.get("description", "")).lower()
            iam_sev = iam.get("severity", "LOW").upper()

            # Extract service prefix from permission (e.g. "s3:GetObject" → "s3")
            service_prefix = iam_permission.split(":")[0] if ":" in iam_permission else ""
            # Also try rule_id
            if not service_prefix:
                rule = str(iam.get("rule_id", "")).lower()
                for svc in _SERVICE_MAP:
                    if svc in rule:
                        service_prefix = svc
                        break

            for cloud in self._cloud:
                cloud_rtype = str(cloud.get("resource_type", "")).lower()
                cloud_resource = str(cloud.get("resource", "")).lower()
                cloud_desc = str(cloud.get("description", "")).lower()
                cloud_label = str(cloud.get("label", "")).lower()
                cloud_sev = cloud.get("severity", "LOW").upper()

                confidence = 0.0

                # IAM permission service prefix matches cloud resource type keywords
                if service_prefix:
                    matching_keywords = _SERVICE_MAP.get(service_prefix, [service_prefix])
                    combined_cloud_text = f"{cloud_rtype} {cloud_resource} {cloud_desc} {cloud_label}"
                    if any(kw in combined_cloud_text for kw in matching_keywords):
                        confidence = max(confidence, 0.8)

                # Both CRITICAL or HIGH → strong signal
                if iam_sev in ("CRITICAL", "HIGH") and cloud_sev in ("CRITICAL", "HIGH"):
                    confidence = max(confidence, 0.9)
                elif iam_sev == cloud_sev:
                    confidence = max(confidence, 0.6)

                # Principal/identity name appears in cloud resource ARN or name
                if iam_principal and len(iam_principal) >= 3:
                    if iam_principal in cloud_resource or iam_principal in cloud_desc:
                        confidence = max(confidence, 0.75)

                if confidence == 0.0:
                    continue

                results.append((iam, cloud, confidence))

        return results

    # ------------------------------------------------------------------
    # Scoring helpers
    # ------------------------------------------------------------------

    def _severity_score(self, severity: str) -> int:
        return _SEVERITY_ORDER.get(severity.upper(), 0)

    def _chain_severity(self, links: List[ChainLink]) -> str:
        max_score = max((_SEVERITY_ORDER.get(lnk.severity.upper(), 0) for lnk in links), default=0)
        return _SEVERITY_NAMES.get(max_score, "LOW")

    def _classify_attack(self, links: List[ChainLink]) -> str:
        layers = {lnk.layer for lnk in links}
        labels_lower = " ".join(lnk.label.lower() + " " + lnk.resource.lower() for lnk in links)

        # FULL_COMPROMISE: spans 4+ distinct layers
        if len(layers) >= 4:
            return _ATTACK_FULL

        # DATA_EXFILTRATION: has cloud storage + iam layer
        storage_keywords = {"s3", "storage", "bucket", "blob", "rds", "database", "secret"}
        has_storage = any(kw in labels_lower for kw in storage_keywords)
        if "iam" in layers and "cloud" in layers and has_storage:
            return _ATTACK_DATA_EXFIL

        # PRIVILEGE_ESCALATION: IAM escalation indicators
        priv_keywords = {"privilege", "escalat", "admin", "root", "cluster-admin", "passrole", "wildcard"}
        has_priv = any(kw in labels_lower for kw in priv_keywords)
        if has_priv and "iam" in layers:
            return _ATTACK_PRIV_ESC

        # IAM only chain with cloud
        if "iam" in layers and "cloud" in layers:
            return _ATTACK_DATA_EXFIL

        # Default
        return _ATTACK_LATERAL

    def _compute_confidence(self, links: List[ChainLink], raw_confidence: float) -> float:
        """Adjust raw edge-product confidence based on chain quality signals."""
        n_layers = len({lnk.layer for lnk in links})

        # Layer span bonus: each additional layer beyond 2 adds 5%
        layer_bonus = 0.05 * max(0, n_layers - 2)

        # Severity bonus: CRITICAL links each add 3%
        critical_count = sum(1 for lnk in links if lnk.severity.upper() == "CRITICAL")
        sev_bonus = 0.03 * critical_count

        adjusted = raw_confidence + layer_bonus + sev_bonus
        return min(1.0, adjusted)
