"""
TythanAI Platform — CVE / CWE / OWASP Enrichment Layer
Correlates findings with:
  • CWE weakness database (embedded subset)
  • OWASP Top 10 2021 mapping
  • CVE lookup (via OSV.dev API — no key required)
  • Historical scan correlation
"""
from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional


# ── Embedded CWE reference (top 30 most common) ───────────────────────────────
_CWE_DB: Dict[str, dict] = {
    "CWE-79":  {"name": "Cross-Site Scripting (XSS)",
                "category": "Injection", "owasp": "A03:2021"},
    "CWE-89":  {"name": "SQL Injection",
                "category": "Injection", "owasp": "A03:2021"},
    "CWE-78":  {"name": "OS Command Injection",
                "category": "Injection", "owasp": "A03:2021"},
    "CWE-94":  {"name": "Code Injection",
                "category": "Injection", "owasp": "A03:2021"},
    "CWE-22":  {"name": "Path Traversal",
                "category": "Access Control", "owasp": "A01:2021"},
    "CWE-502": {"name": "Deserialization of Untrusted Data",
                "category": "Injection", "owasp": "A08:2021"},
    "CWE-20":  {"name": "Improper Input Validation",
                "category": "Validation", "owasp": "A03:2021"},
    "CWE-125": {"name": "Out-of-bounds Read",
                "category": "Memory", "owasp": "A06:2021"},
    "CWE-787": {"name": "Out-of-bounds Write",
                "category": "Memory", "owasp": "A06:2021"},
    "CWE-416": {"name": "Use After Free",
                "category": "Memory", "owasp": "A06:2021"},
    "CWE-476": {"name": "NULL Pointer Dereference",
                "category": "Memory", "owasp": "A06:2021"},
    "CWE-190": {"name": "Integer Overflow",
                "category": "Numeric", "owasp": "A06:2021"},
    "CWE-134": {"name": "Format String Vulnerability",
                "category": "Injection", "owasp": "A03:2021"},
    "CWE-259": {"name": "Hard-coded Password",
                "category": "Credentials", "owasp": "A02:2021"},
    "CWE-798": {"name": "Hard-coded Credentials",
                "category": "Credentials", "owasp": "A02:2021"},
    "CWE-321": {"name": "Hard-coded Cryptographic Key",
                "category": "Cryptography", "owasp": "A02:2021"},
    "CWE-327": {"name": "Broken Cryptographic Algorithm",
                "category": "Cryptography", "owasp": "A02:2021"},
    "CWE-330": {"name": "Insufficient Randomness",
                "category": "Cryptography", "owasp": "A02:2021"},
    "CWE-918": {"name": "Server-Side Request Forgery (SSRF)",
                "category": "SSRF", "owasp": "A10:2021"},
    "CWE-601": {"name": "Open Redirect",
                "category": "Redirect", "owasp": "A01:2021"},
    "CWE-352": {"name": "Cross-Site Request Forgery (CSRF)",
                "category": "Access Control", "owasp": "A01:2021"},
    "CWE-862": {"name": "Missing Authorization",
                "category": "Access Control", "owasp": "A01:2021"},
    "CWE-863": {"name": "Incorrect Authorization",
                "category": "Access Control", "owasp": "A01:2021"},
    "CWE-306": {"name": "Missing Authentication",
                "category": "Authentication", "owasp": "A07:2021"},
    "CWE-384": {"name": "Session Fixation",
                "category": "Authentication", "owasp": "A07:2021"},
    "CWE-611": {"name": "XML External Entity (XXE)",
                "category": "Injection", "owasp": "A05:2021"},
    "CWE-400": {"name": "Uncontrolled Resource Consumption",
                "category": "DoS", "owasp": "A05:2021"},
    "CWE-732": {"name": "Incorrect Permission Assignment",
                "category": "Access Control", "owasp": "A01:2021"},
    "CWE-377": {"name": "Insecure Temporary File",
                "category": "File", "owasp": "A05:2021"},
    "CWE-703": {"name": "Improper Error Handling",
                "category": "Error Handling", "owasp": "A09:2021"},
}

# ── OWASP Top 10 2021 descriptions ────────────────────────────────────────────
_OWASP_MAP: Dict[str, dict] = {
    "A01:2021": {"title": "Broken Access Control",    "url": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"},
    "A02:2021": {"title": "Cryptographic Failures",   "url": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"},
    "A03:2021": {"title": "Injection",                "url": "https://owasp.org/Top10/A03_2021-Injection/"},
    "A04:2021": {"title": "Insecure Design",          "url": "https://owasp.org/Top10/A04_2021-Insecure_Design/"},
    "A05:2021": {"title": "Security Misconfiguration","url": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"},
    "A06:2021": {"title": "Vulnerable Components",   "url": "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"},
    "A07:2021": {"title": "Authentication Failures",  "url": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"},
    "A08:2021": {"title": "Software & Data Integrity","url": "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/"},
    "A09:2021": {"title": "Security Logging Failures","url": "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/"},
    "A10:2021": {"title": "Server-Side Request Forgery","url": "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery/"},
}

# ── Rule-ID → CWE heuristic mapping ───────────────────────────────────────────
_RULE_CWE_MAP: Dict[str, str] = {
    "sql": "CWE-89", "sqli": "CWE-89",
    "xss": "CWE-79", "cross_site": "CWE-79",
    "ssrf": "CWE-918", "request_forgery": "CWE-918",
    "csrf": "CWE-352",
    "path_traversal": "CWE-22", "path-traversal": "CWE-22", "directory": "CWE-22",
    "command_injection": "CWE-78", "shell_injection": "CWE-78",
    "hardcoded_secret": "CWE-798", "hardcoded_password": "CWE-259",
    "hardcoded_key": "CWE-321",
    "weak_hash": "CWE-327", "md5": "CWE-327", "sha1": "CWE-327",
    "insecure_random": "CWE-330", "weak_random": "CWE-330",
    "deserialization": "CWE-502",
    "xxe": "CWE-611",
    "integer_overflow": "CWE-190",
    "null_deref": "CWE-476",
    "use_after_free": "CWE-416",
    "open_redirect": "CWE-601",
    "missing_auth": "CWE-306",
    "broken_access": "CWE-862",
    "eval": "CWE-94", "code_injection": "CWE-94",
    "uncontrolled_resource": "CWE-400",
}


def _guess_cwe(finding: dict) -> Optional[str]:
    """Infer CWE ID from rule ID / type / message."""
    sources = [
        str(finding.get("type") or ""),
        str(finding.get("id") or ""),
        str(finding.get("rule_id") or ""),
        str(finding.get("message") or ""),
    ]
    text = " ".join(sources).lower().replace("-", "_").replace(" ", "_")
    for keyword, cwe_id in _RULE_CWE_MAP.items():
        if keyword in text:
            return cwe_id
    # Try direct CWE mention
    m = re.search(r"cwe[-_]?(\d+)", text)
    if m:
        return f"CWE-{m.group(1)}"
    return None


# ── OSV.dev CVE lookup (no API key needed) ─────────────────────────────────────

def _osv_query(package: str, version: str, ecosystem: str = "PyPI") -> List[dict]:
    """Query osv.dev for known vulnerabilities. Returns list of CVE dicts."""
    payload = json.dumps({
        "version": version,
        "package": {"name": package, "ecosystem": ecosystem}
    }).encode()
    req = urllib.request.Request(
        "https://api.osv.dev/v1/query",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
        vulns = data.get("vulns", [])
        result = []
        for v in vulns[:5]:  # cap at 5 per package
            aliases = v.get("aliases", [])
            cve_id  = next((a for a in aliases if a.startswith("CVE-")), v.get("id", ""))
            result.append({
                "id":       cve_id or v.get("id"),
                "summary":  v.get("summary", ""),
                "severity": _osv_severity(v),
                "published": v.get("published", ""),
                "source":   "osv.dev",
            })
        return result
    except Exception:
        return []


def _osv_severity(vuln: dict) -> str:
    for sev in vuln.get("severity", []):
        score_text = sev.get("score", "")
        # CVSS v3 text score
        m = re.search(r"(\d+\.\d+)", str(score_text))
        if m:
            score = float(m.group(1))
            if score >= 9.0: return "CRITICAL"
            if score >= 7.0: return "HIGH"
            if score >= 4.0: return "MEDIUM"
            return "LOW"
    return "UNKNOWN"


# ── Enricher ───────────────────────────────────────────────────────────────────

class CVEEnricher:
    """
    Enrich security findings with CWE, OWASP, and CVE metadata.
    Works on both static-analysis findings and dependency findings.
    """

    def __init__(self, online: bool = True) -> None:
        """
        online=True → attempt CVE lookup via osv.dev (requires network).
        online=False → offline mode using embedded DB only.
        """
        self._online   = online
        self._cve_cache: Dict[str, List[dict]] = {}

    # ── Public API ────────────────────────────────────────────────────────────

    def enrich(self, findings: List[dict]) -> List[dict]:
        """Enrich a list of findings in-place (returns enriched list)."""
        enriched = []
        for raw in findings:
            f = dict(raw)
            self._enrich_one(f)
            enriched.append(f)
        return enriched

    def enrich_deps(self, dep_findings: List[dict]) -> List[dict]:
        """
        Specialised enrichment for dependency CVE findings.
        Each finding should have 'package' and 'version' fields.
        """
        enriched = []
        for raw in dep_findings:
            f = dict(raw)
            pkg = f.get("package") or f.get("name") or ""
            ver = f.get("version") or f.get("installed_version") or ""
            if pkg and ver and self._online:
                cache_key = f"{pkg}@{ver}"
                if cache_key not in self._cve_cache:
                    self._cve_cache[cache_key] = _osv_query(pkg, ver)
                f["cves"] = self._cve_cache[cache_key]
                if f["cves"] and not f.get("cve_id"):
                    f["cve_id"] = f["cves"][0]["id"]
            enriched.append(f)
        return enriched

    def cwe_info(self, cwe_id: str) -> dict:
        return _CWE_DB.get(cwe_id, {"name": "Unknown", "category": "Unknown", "owasp": None})

    def owasp_info(self, owasp_id: str) -> dict:
        return _OWASP_MAP.get(owasp_id, {"title": "Unknown", "url": ""})

    def summary(self, findings: List[dict]) -> dict:
        """Aggregate enrichment stats for a list of findings."""
        cwes: dict = {}
        owasp_cats: dict = {}
        for f in findings:
            cwe = f.get("cwe") or ""
            if cwe:
                cwes[cwe] = cwes.get(cwe, 0) + 1
            owasp = f.get("owasp") or ""
            if owasp:
                owasp_cats[owasp] = owasp_cats.get(owasp, 0) + 1
        top_cwes   = sorted(cwes.items(),       key=lambda x: -x[1])[:10]
        top_owasp  = sorted(owasp_cats.items(), key=lambda x: -x[1])[:10]
        return {
            "total_enriched": len(findings),
            "top_cwes":  [{"id": k, "count": v, "name": _CWE_DB.get(k, {}).get("name")} for k, v in top_cwes],
            "top_owasp": [{"id": k, "count": v, "title": _OWASP_MAP.get(k, {}).get("title")} for k, v in top_owasp],
        }

    # ── Internal ──────────────────────────────────────────────────────────────

    def _enrich_one(self, finding: dict) -> None:
        # 1. Guess CWE if not present
        if not finding.get("cwe"):
            cwe = _guess_cwe(finding)
            if cwe:
                finding["cwe"] = cwe

        # 2. Expand CWE info
        cwe_id = finding.get("cwe") or ""
        if cwe_id:
            info = _CWE_DB.get(cwe_id, {})
            finding.setdefault("cwe_name",  info.get("name", ""))
            finding.setdefault("cwe_category", info.get("category", ""))
            owasp_id = info.get("owasp")
            if owasp_id:
                finding.setdefault("owasp", owasp_id)

        # 3. Expand OWASP info
        owasp_id = finding.get("owasp") or finding.get("owasp_category") or ""
        if owasp_id and owasp_id in _OWASP_MAP:
            finding.setdefault("owasp_title", _OWASP_MAP[owasp_id]["title"])
            finding.setdefault("owasp_url",   _OWASP_MAP[owasp_id]["url"])

        # 4. Normalise severity
        sev = (finding.get("severity") or "MEDIUM").upper()
        finding["severity"] = sev if sev in _SEV_WEIGHT else "MEDIUM"


_SEV_WEIGHT = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1, "INFO": 0}

# Module-level singleton
ENRICHER = CVEEnricher(online=True)
