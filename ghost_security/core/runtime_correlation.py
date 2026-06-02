"""
TythanAI Phase 7 — SAST↔DAST Runtime Correlation Engine

Correlates static analysis findings with dynamic test results to:
  1. Confirm reachability via runtime evidence
  2. Compute combined confidence scores (static + runtime)
  3. Assign verification statuses: detected → reachable → exploitable → verified
  4. Build correlated finding records with full audit trails

Core algorithm:
  - For each SAST finding, locate the source endpoint via Attack Surface map
  - Match DAST findings by CWE + URL + parameter heuristics
  - Score correlation by field overlap (CWE, URL path, method, param name)
  - Emit CorrelatedFinding with both evidence types and a unified risk score
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


# ── Verification statuses ────────────────────────────────────────────────────

class VerificationStatus:
    DETECTED    = "detected"     # found by SAST only
    REACHABLE   = "reachable"    # SAST finding is on a reachable endpoint
    EXPLOITABLE = "exploitable"  # DAST confirmed exploitable (200/injection success)
    VERIFIED    = "verified"     # Both SAST + DAST + EPSS/reachability agree


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class StaticEvidence:
    rule_id:       str
    file:          str
    line:          int
    description:   str
    cwe:           str
    severity:      str
    confidence:    int            # 0-100
    handler:       str = ""       # function name from SAST
    source_scanner: str = "sast"


@dataclass
class RuntimeEvidence:
    rule_id:       str
    url:           str
    method:        str
    description:   str
    cwe:           str
    severity:      str
    confidence:    int            # 0-100
    evidence_text: str = ""
    source_scanner: str = "dast"
    zap_plugin_id: str = ""


@dataclass
class CorrelatedFinding:
    correlation_id:      str
    title:               str
    cwe:                 str
    severity:            str              # unified severity (max of static/runtime)
    owasp_category:      str
    verification_status: str             # VerificationStatus.*
    static_evidence:     Optional[StaticEvidence]
    runtime_evidence:    Optional[RuntimeEvidence]
    endpoint_url:        str
    endpoint_method:     str
    endpoint_path:       str
    handler:             str
    static_confidence:   int             # 0-100
    runtime_confidence:  int             # 0-100
    combined_confidence: int             # 0-100 (weighted blend)
    risk_score:          float           # 0.0 – 10.0
    exploit_path:        List[str] = field(default_factory=list)
    recommendations:     List[str] = field(default_factory=list)
    tags:                List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "correlation_id":      self.correlation_id,
            "title":               self.title,
            "cwe":                 self.cwe,
            "severity":            self.severity,
            "owasp_category":      self.owasp_category,
            "verification_status": self.verification_status,
            "endpoint":            {
                "url":     self.endpoint_url,
                "method":  self.endpoint_method,
                "path":    self.endpoint_path,
                "handler": self.handler,
            },
            "static_evidence": {
                "rule_id":     self.static_evidence.rule_id if self.static_evidence else "",
                "file":        self.static_evidence.file if self.static_evidence else "",
                "line":        self.static_evidence.line if self.static_evidence else 0,
                "description": self.static_evidence.description if self.static_evidence else "",
                "confidence":  self.static_confidence,
            },
            "runtime_evidence": {
                "rule_id":   self.runtime_evidence.rule_id if self.runtime_evidence else "",
                "url":       self.runtime_evidence.url if self.runtime_evidence else "",
                "method":    self.runtime_evidence.method if self.runtime_evidence else "",
                "evidence":  self.runtime_evidence.evidence_text if self.runtime_evidence else "",
                "confidence": self.runtime_confidence,
            },
            "combined_confidence": self.combined_confidence,
            "risk_score":          self.risk_score,
            "exploit_path":        self.exploit_path,
            "recommendations":     self.recommendations,
            "tags":                self.tags,
        }


@dataclass
class CorrelationReport:
    generated_at:         str
    total_correlated:     int
    verified_findings:    int
    exploitable_findings: int
    reachable_findings:   int
    detected_only:        int
    correlated_findings:  List[CorrelatedFinding]
    sast_only_count:      int
    dast_only_count:      int
    false_positive_candidates: int   # SAST findings with no reachable endpoint
    noise_reduction_pct:  float      # % SAST findings promoted to higher confidence

    def to_dict(self) -> dict:
        return {
            "generated_at":              self.generated_at,
            "total_correlated":          self.total_correlated,
            "verified_findings":         self.verified_findings,
            "exploitable_findings":      self.exploitable_findings,
            "reachable_findings":        self.reachable_findings,
            "detected_only":             self.detected_only,
            "sast_only_count":           self.sast_only_count,
            "dast_only_count":           self.dast_only_count,
            "false_positive_candidates": self.false_positive_candidates,
            "noise_reduction_pct":       round(self.noise_reduction_pct, 1),
            "findings": [f.to_dict() for f in self.correlated_findings],
        }


# ── CWE normalization helpers ─────────────────────────────────────────────────

def _normalize_cwe(raw: str) -> str:
    """Return 'CWE-NNN' or empty string."""
    if not raw:
        return ""
    m = re.search(r"(\d+)", raw)
    return f"CWE-{m.group(1)}" if m else raw.upper()


def _cwe_family(cwe: str) -> str:
    """Group CWEs into vulnerability families for broader matching."""
    n = re.search(r"(\d+)", cwe)
    if not n:
        return ""
    num = int(n.group(1))
    # Injection family
    if num in (89, 78, 77, 88, 94, 95, 80, 116, 643, 917):
        return "injection"
    # Auth/access control
    if num in (306, 307, 284, 285, 639, 862, 863, 522, 613, 307):
        return "auth"
    # Crypto / TLS
    if num in (295, 311, 312, 319, 326, 327, 330, 338):
        return "crypto"
    # XSS / output encoding
    if num in (79, 80, 81, 83, 87, 116):
        return "xss"
    # SSRF / info disclosure
    if num in (918, 200, 598):
        return "ssrf_disclosure"
    # Deserialization
    if num in (502, 400, 502):
        return "deserialization"
    # Header / config
    if num in (16, 693, 1004, 614, 352, 1021, 430):
        return "config"
    return "other"


def _severity_rank(sev: str) -> int:
    return {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}.get(
        sev.upper(), 0
    )


def _max_severity(a: str, b: str) -> str:
    return a if _severity_rank(a) >= _severity_rank(b) else b


# ── Endpoint matcher ──────────────────────────────────────────────────────────

def _path_to_pattern(path: str) -> re.Pattern:
    """
    Convert a URL path template (/users/{id}/posts) to a regex that matches
    concrete paths (/users/42/posts) and template paths (/users/1/posts).
    """
    escaped = re.escape(path)
    # Replace \{word\} with a numeric-or-word group
    escaped = re.sub(r"\\\{[^}]+\\\}", r"[^/]+", escaped)
    return re.compile(f"^{escaped}$")


def _url_path(url: str) -> str:
    """Extract /path from a full URL or path template."""
    from urllib.parse import urlparse
    p = urlparse(url)
    return p.path or url


def _match_endpoint(sast_file: str, sast_handler: str,
                    endpoint_source_file: str, endpoint_handler: str,
                    endpoint_path: str, dast_url: str) -> Tuple[bool, int]:
    """
    Returns (matched, confidence_bonus).
    Heuristic: match by handler name, source file, or URL path overlap.
    """
    score = 0

    # Handler name match (strongest signal)
    if sast_handler and endpoint_handler and sast_handler == endpoint_handler:
        score += 40

    # Source file match
    if sast_file and endpoint_source_file:
        sast_stem = re.sub(r"[/\\]", "/", sast_file).split("/")[-1]
        ep_stem   = re.sub(r"[/\\]", "/", endpoint_source_file).split("/")[-1]
        if sast_stem == ep_stem:
            score += 25
        elif sast_stem.replace(".py", "") in ep_stem or \
                ep_stem.replace(".py", "") in sast_stem:
            score += 10

    # URL path ↔ source file heuristic (views.py → /api/views/*)
    if sast_file:
        sast_stem = re.sub(r"[/\\]", "/", sast_file).split("/")[-1].replace(".py", "")
        if sast_stem in endpoint_path.lower():
            score += 15

    # DAST URL path matches endpoint path template
    if dast_url and endpoint_path:
        dast_path  = _url_path(dast_url)
        ep_pattern = _path_to_pattern(endpoint_path)
        if ep_pattern.search(dast_path) or dast_path == endpoint_path:
            score += 30

    return score >= 25, score


# ── CWE ↔ rule_id matching ────────────────────────────────────────────────────

def _cwe_matches(sast_cwe: str, dast_cwe: str, dast_rule: str) -> Tuple[bool, int]:
    """
    Returns (matched, score).
    Direct CWE match = 50 pts; same family = 20 pts.
    ZAP rule-ID heuristics supplement when CWE is missing.
    """
    s_cwe = _normalize_cwe(sast_cwe)
    d_cwe = _normalize_cwe(dast_cwe)

    if s_cwe and d_cwe:
        if s_cwe == d_cwe:
            return True, 50
        if _cwe_family(s_cwe) == _cwe_family(d_cwe) and _cwe_family(s_cwe) != "other":
            return True, 20

    # Fallback: ZAP plugin-level heuristics
    _ZAP_RULE_FAMILIES: Dict[str, str] = {
        "40018": "injection",   # SQL injection
        "90020": "injection",   # Command injection
        "10202": "xss",
        "40012": "xss",
        "10098": "config",      # CORS
        "10036": "config",      # CSP
        "10010": "config",      # X-Frame-Options
        "10035": "crypto",      # HSTS
        "10040": "crypto",      # Mixed content
        "40003": "auth",        # CSRF
        "10054": "auth",        # Cookie without secure
    }
    dast_family = _ZAP_RULE_FAMILIES.get(dast_rule, "")
    if s_cwe and dast_family and _cwe_family(s_cwe) == dast_family:
        return True, 15

    return False, 0


# ── Combined confidence ───────────────────────────────────────────────────────

def _combined_confidence(static_conf: int, runtime_conf: int,
                          has_both: bool) -> int:
    """
    Bayesian-inspired combination:
      - If both sources agree, confidence is boosted beyond simple average.
      - If only one source, confidence stays at that source's level.
    """
    if not has_both:
        return static_conf if static_conf > runtime_conf else runtime_conf

    # Both signals present — P(both wrong) = (1 - p_s) * (1 - p_r)
    p_s = static_conf  / 100.0
    p_r = runtime_conf / 100.0
    p_combined = 1.0 - (1.0 - p_s) * (1.0 - p_r)
    return min(100, int(p_combined * 100))


def _risk_score(severity: str, combined_conf: int, verification_status: str) -> float:
    """Numeric risk score 0.0-10.0 for priority ranking."""
    base = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.5, "INFO": 0.5}.get(
        severity.upper(), 2.5
    )
    conf_mult = combined_conf / 100.0
    status_mult = {
        VerificationStatus.VERIFIED:    1.0,
        VerificationStatus.EXPLOITABLE: 0.9,
        VerificationStatus.REACHABLE:   0.7,
        VerificationStatus.DETECTED:    0.5,
    }.get(verification_status, 0.5)
    return round(min(10.0, base * conf_mult * status_mult), 2)


# ── Main correlator ───────────────────────────────────────────────────────────

class RuntimeCorrelator:
    """
    Correlates SAST findings with DAST findings via endpoint mapping.

    Usage:
        correlator = RuntimeCorrelator(attack_surface, sast_findings, dast_findings)
        report = correlator.correlate()
    """

    def __init__(
        self,
        attack_surface_endpoints: List[dict],   # from AttackSurfaceMapper.to_attack_graph_nodes()
        sast_findings:  List[dict],
        dast_findings:  List[dict],
        reachability_results: Optional[List[dict]] = None,
    ):
        self._endpoints   = attack_surface_endpoints
        self._sast        = sast_findings
        self._dast        = dast_findings
        self._reachability = {
            r.get("file", ""): r
            for r in (reachability_results or [])
            if r.get("file")
        }

    def correlate(self) -> CorrelationReport:
        correlated: List[CorrelatedFinding] = []
        matched_sast: Set[int] = set()
        matched_dast: Set[int] = set()

        # Build a DAST index by CWE family and URL path for fast lookup
        dast_by_family: Dict[str, List[Tuple[int, dict]]] = {}
        for i, df in enumerate(self._dast):
            cwe    = _normalize_cwe(df.get("cwe", "") or df.get("cwe_id", ""))
            family = _cwe_family(cwe)
            dast_by_family.setdefault(family, []).append((i, df))
            dast_by_family.setdefault("all", []).append((i, df))

        # For each SAST finding, try to find a correlated DAST finding + endpoint
        for si, sf in enumerate(self._sast):
            sast_cwe     = _normalize_cwe(sf.get("cwe", "") or sf.get("cwe_id", ""))
            sast_file    = sf.get("file", "") or sf.get("file_path", "")
            sast_handler = sf.get("handler", "") or sf.get("function", "")
            sast_sev     = sf.get("severity", "MEDIUM")
            sast_conf    = int(sf.get("confidence", 70))
            sast_family  = _cwe_family(sast_cwe)

            static_ev = StaticEvidence(
                rule_id=sf.get("rule_id", sf.get("id", "")),
                file=sast_file,
                line=int(sf.get("line", 0)),
                description=sf.get("description", sf.get("message", "")),
                cwe=sast_cwe,
                severity=sast_sev,
                confidence=sast_conf,
                handler=sast_handler,
                source_scanner=sf.get("source", "sast"),
            )

            # Find best matching endpoint
            best_ep: Optional[dict] = None
            best_ep_score = 0
            for ep in self._endpoints:
                _, ep_score = _match_endpoint(
                    sast_file, sast_handler,
                    ep.get("source_file", ""), ep.get("handler", ""),
                    ep.get("path", ""), "",
                )
                if ep_score > best_ep_score:
                    best_ep_score = ep_score
                    best_ep = ep

            ep_url    = best_ep.get("url", "") if best_ep else ""
            ep_method = best_ep.get("method", "") if best_ep else ""
            ep_path   = best_ep.get("path", ep_url) if best_ep else ""
            ep_handler = best_ep.get("handler", sast_handler) if best_ep else sast_handler

            # Find best matching DAST finding
            best_dast: Optional[dict] = None
            best_dast_idx = -1
            best_dast_score = 0

            candidates = dast_by_family.get(sast_family, []) + \
                         dast_by_family.get("all", [])
            seen_di: Set[int] = set()
            for di, df in candidates:
                if di in seen_di:
                    continue
                seen_di.add(di)
                dast_cwe   = _normalize_cwe(df.get("cwe", "") or df.get("cwe_id", ""))
                dast_url   = df.get("url", "")
                dast_rule  = df.get("rule_id", "").replace("ZAP-", "")

                cwe_ok, cwe_score = _cwe_matches(sast_cwe, dast_cwe, dast_rule)
                if not cwe_ok:
                    continue

                ep_ok, ep_score = _match_endpoint(
                    sast_file, sast_handler,
                    best_ep.get("source_file", "") if best_ep else "",
                    best_ep.get("handler", "") if best_ep else "",
                    ep_path, dast_url,
                )
                total_score = cwe_score + (ep_score if ep_ok else 0)
                if total_score > best_dast_score:
                    best_dast_score = total_score
                    best_dast_idx   = di
                    best_dast       = df

            runtime_ev: Optional[RuntimeEvidence] = None
            runtime_conf = 0
            if best_dast is not None:
                matched_dast.add(best_dast_idx)
                dast_conf = int(best_dast.get("confidence", 65))
                runtime_ev = RuntimeEvidence(
                    rule_id=best_dast.get("rule_id", ""),
                    url=best_dast.get("url", ""),
                    method=best_dast.get("method", "GET"),
                    description=best_dast.get("description", ""),
                    cwe=_normalize_cwe(best_dast.get("cwe", "")),
                    severity=best_dast.get("severity", "MEDIUM"),
                    confidence=dast_conf,
                    evidence_text=best_dast.get("evidence", ""),
                    source_scanner=best_dast.get("source", "dast"),
                    zap_plugin_id=best_dast.get("rule_id", "").replace("ZAP-", ""),
                )
                runtime_conf = dast_conf
                matched_sast.add(si)

            # Reachability check
            reach_result = self._reachability.get(sast_file, {})
            reachable    = reach_result.get("reachability_status", "") == "REACHABLE"

            # Determine verification status
            if runtime_ev is not None and reachable:
                status = VerificationStatus.VERIFIED
            elif runtime_ev is not None:
                status = VerificationStatus.EXPLOITABLE
            elif reachable or best_ep is not None:
                status = VerificationStatus.REACHABLE
                matched_sast.add(si)
            else:
                status = VerificationStatus.DETECTED

            has_both      = runtime_ev is not None
            combined_conf = _combined_confidence(sast_conf, runtime_conf, has_both)
            unified_sev   = (
                _max_severity(sast_sev, runtime_ev.severity)
                if runtime_ev else sast_sev
            )

            corr_id = f"CORR-{si:04d}-{int(time.time()) % 100000}"
            title   = (
                sf.get("title", sf.get("description", "Security Finding"))[:80]
            )

            owasp = (
                sf.get("owasp_category", "")
                or (best_dast.get("owasp_category", "") if best_dast else "")
                or _cwe_to_owasp(sast_cwe)
            )

            exploit_path = self._build_exploit_path(
                static_ev, runtime_ev, best_ep
            )
            recommendations = self._collect_recommendations(sf, best_dast)

            correlated.append(CorrelatedFinding(
                correlation_id=corr_id,
                title=title,
                cwe=sast_cwe or (runtime_ev.cwe if runtime_ev else ""),
                severity=unified_sev,
                owasp_category=owasp,
                verification_status=status,
                static_evidence=static_ev,
                runtime_evidence=runtime_ev,
                endpoint_url=ep_url,
                endpoint_method=ep_method,
                endpoint_path=ep_path,
                handler=ep_handler,
                static_confidence=sast_conf,
                runtime_confidence=runtime_conf,
                combined_confidence=combined_conf,
                risk_score=_risk_score(unified_sev, combined_conf, status),
                exploit_path=exploit_path,
                recommendations=recommendations,
                tags=self._tags(status, unified_sev, sast_cwe),
            ))

        # DAST-only findings (not matched to any SAST)
        for di, df in enumerate(self._dast):
            if di in matched_dast:
                continue
            dast_cwe  = _normalize_cwe(df.get("cwe", "") or df.get("cwe_id", ""))
            dast_sev  = df.get("severity", "MEDIUM")
            dast_conf = int(df.get("confidence", 65))
            dast_url  = df.get("url", "")

            runtime_ev = RuntimeEvidence(
                rule_id=df.get("rule_id", ""),
                url=dast_url,
                method=df.get("method", "GET"),
                description=df.get("description", ""),
                cwe=dast_cwe,
                severity=dast_sev,
                confidence=dast_conf,
                evidence_text=df.get("evidence", ""),
                source_scanner=df.get("source", "dast"),
            )

            owasp = df.get("owasp_category", "") or _cwe_to_owasp(dast_cwe)
            path  = _url_path(dast_url)

            correlated.append(CorrelatedFinding(
                correlation_id=f"CORR-DAST-{di:04d}",
                title=df.get("title", df.get("description", "DAST Finding"))[:80],
                cwe=dast_cwe,
                severity=dast_sev,
                owasp_category=owasp,
                verification_status=VerificationStatus.EXPLOITABLE,
                static_evidence=None,
                runtime_evidence=runtime_ev,
                endpoint_url=dast_url,
                endpoint_method=df.get("method", "GET"),
                endpoint_path=path,
                handler="",
                static_confidence=0,
                runtime_confidence=dast_conf,
                combined_confidence=dast_conf,
                risk_score=_risk_score(dast_sev, dast_conf,
                                       VerificationStatus.EXPLOITABLE),
                recommendations=[df.get("recommendation", "")],
                tags=["dast-only"] + self._tags(
                    VerificationStatus.EXPLOITABLE, dast_sev, dast_cwe
                ),
            ))

        # Sort by risk score descending
        correlated.sort(key=lambda c: -c.risk_score)

        total_sast = len(self._sast)
        fp_candidates = total_sast - len(matched_sast)
        noise_reduction = (
            (len(matched_sast) / total_sast * 100) if total_sast > 0 else 0.0
        )

        return CorrelationReport(
            generated_at=_iso_now(),
            total_correlated=len(correlated),
            verified_findings=sum(
                1 for c in correlated
                if c.verification_status == VerificationStatus.VERIFIED
            ),
            exploitable_findings=sum(
                1 for c in correlated
                if c.verification_status == VerificationStatus.EXPLOITABLE
            ),
            reachable_findings=sum(
                1 for c in correlated
                if c.verification_status == VerificationStatus.REACHABLE
            ),
            detected_only=sum(
                1 for c in correlated
                if c.verification_status == VerificationStatus.DETECTED
            ),
            correlated_findings=correlated,
            sast_only_count=fp_candidates,
            dast_only_count=len(self._dast) - len(matched_dast),
            false_positive_candidates=fp_candidates,
            noise_reduction_pct=noise_reduction,
        )

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _build_exploit_path(static_ev: StaticEvidence,
                             runtime_ev: Optional[RuntimeEvidence],
                             endpoint: Optional[dict]) -> List[str]:
        path: List[str] = []
        if endpoint:
            path.append(f"Endpoint: {endpoint.get('method', 'GET')} {endpoint.get('path', '')}")
        if static_ev:
            path.append(f"Source: {static_ev.file}:{static_ev.line} — {static_ev.handler}")
        if runtime_ev:
            path.append(f"Runtime: {runtime_ev.method} {runtime_ev.url}")
            if runtime_ev.evidence_text:
                path.append(f"Evidence: {runtime_ev.evidence_text[:120]}")
        return path

    @staticmethod
    def _collect_recommendations(sast_f: dict,
                                  dast_f: Optional[dict]) -> List[str]:
        recs: List[str] = []
        for f in (sast_f, dast_f):
            if f is None:
                continue
            for key in ("recommendation", "solution", "fix", "description"):
                val = f.get(key, "")
                if val and val not in recs:
                    recs.append(val[:200])
                    break
        return recs[:3]

    @staticmethod
    def _tags(status: str, severity: str, cwe: str) -> List[str]:
        tags = [status, severity.lower()]
        family = _cwe_family(cwe)
        if family != "other":
            tags.append(family)
        if cwe:
            tags.append(cwe.lower())
        return tags


# ── Utility ───────────────────────────────────────────────────────────────────

_CWE_OWASP: Dict[str, str] = {
    "CWE-89":  "A03:2021 – Injection",
    "CWE-78":  "A03:2021 – Injection",
    "CWE-79":  "A03:2021 – Injection",
    "CWE-502": "A08:2021 – Software and Data Integrity Failures",
    "CWE-312": "A02:2021 – Cryptographic Failures",
    "CWE-319": "A02:2021 – Cryptographic Failures",
    "CWE-327": "A02:2021 – Cryptographic Failures",
    "CWE-306": "A07:2021 – Identification and Authentication Failures",
    "CWE-307": "A07:2021 – Identification and Authentication Failures",
    "CWE-284": "A01:2021 – Broken Access Control",
    "CWE-639": "A01:2021 – Broken Access Control",
    "CWE-862": "A01:2021 – Broken Access Control",
    "CWE-918": "A10:2021 – SSRF",
    "CWE-200": "A05:2021 – Security Misconfiguration",
    "CWE-16":  "A05:2021 – Security Misconfiguration",
    "CWE-352": "A01:2021 – Broken Access Control",
    "CWE-942": "A05:2021 – Security Misconfiguration",
}


def _cwe_to_owasp(cwe: str) -> str:
    normalized = _normalize_cwe(cwe)
    return _CWE_OWASP.get(normalized, "")


def _iso_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
