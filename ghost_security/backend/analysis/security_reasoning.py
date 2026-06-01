"""
backend/analysis/security_reasoning.py — Automatic security reasoning for findings.

For each finding, automatically generates:
- Why this is a vulnerability (source of data, flow, exploit point)
- Reachability assessment
- Verification status
- Impact analysis
- Recommended fix

Does NOT duplicate any analysis logic — reads from existing components.
"""
from __future__ import annotations

import re
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("tythanai.security_reasoning")

# ---------------------------------------------------------------------------
# Try to import Finding; fall back to duck-typed Any
# ---------------------------------------------------------------------------
try:
    from backend.core.confidence import Finding as _Finding  # noqa: F401
    _FINDING_TYPE = _Finding
except ImportError:  # pragma: no cover
    _FINDING_TYPE = None  # type: ignore[assignment]

# ---------------------------------------------------------------------------
# CWE metadata
# ---------------------------------------------------------------------------

_CWE_DESCRIPTIONS: Dict[str, str] = {
    "CWE-89":  "SQL Injection: user-controlled data is embedded directly into a SQL query, "
               "allowing an attacker to manipulate the query's logic.",
    "CWE-79":  "Cross-Site Scripting (XSS): user-supplied content is reflected in an HTTP "
               "response without escaping, enabling script injection into other users' browsers.",
    "CWE-78":  "OS Command Injection: user input is passed to a shell command without "
               "sanitisation, allowing arbitrary command execution on the server.",
    "CWE-22":  "Path Traversal: a user-controlled file path is used to access the filesystem "
               "without adequate normalisation, enabling reads or writes outside the intended directory.",
    "CWE-798": "Hard-coded Credentials: credentials are embedded directly in source code or "
               "configuration, making them trivially extractable by anyone with repository access.",
    "CWE-94":  "Code Injection / SSTI: user input is evaluated as code or as a template "
               "expression, enabling remote code execution.",
    "CWE-502": "Insecure Deserialization: untrusted data is passed to a deserializer (e.g. pickle) "
               "that can execute arbitrary code during the deserialization process.",
    "CWE-918": "Server-Side Request Forgery (SSRF): the server fetches a URL constructed from "
               "user input, enabling access to internal services and cloud metadata endpoints.",
    "CWE-611": "XML External Entity (XXE): the XML parser resolves external entities from "
               "user-controlled XML, enabling file reads and SSRF.",
    "CWE-306": "Missing Authentication: a sensitive operation or resource is accessible without "
               "requiring the caller to authenticate.",
    "CWE-862": "Missing Authorisation: the application does not verify that the caller has "
               "permission to perform the requested operation.",
}

_CWE_AFFECTED_ASSETS: Dict[str, List[str]] = {
    "CWE-89":  ["database", "user_records"],
    "CWE-79":  ["browser_session", "user_cookies"],
    "CWE-78":  ["operating_system", "server_filesystem"],
    "CWE-22":  ["filesystem", "configuration_files", "secrets_files"],
    "CWE-798": ["credentials", "secrets"],
    "CWE-94":  ["server_process", "application_secrets"],
    "CWE-502": ["server_process", "application_data"],
    "CWE-918": ["internal_network", "cloud_metadata", "IAM_credentials"],
    "CWE-611": ["filesystem", "internal_services"],
    "CWE-306": ["protected_resources"],
    "CWE-862": ["protected_resources", "other_users_data"],
}

_CWE_EXPLOITATION_TECHNIQUES: Dict[str, str] = {
    "CWE-89":  "SQL injection via string concatenation / format strings",
    "CWE-79":  "Reflected or stored XSS via unescaped HTML output",
    "CWE-78":  "Shell metacharacter injection (e.g. ; | && ` $())",
    "CWE-22":  "Directory traversal with ../ sequences or absolute paths",
    "CWE-798": "Credential extraction from source code or version history",
    "CWE-94":  "Template expression injection ({{7*7}}) or eval() on user input",
    "CWE-502": "Malicious pickle/YAML payload triggering __reduce__ / !!python/object",
    "CWE-918": "Crafted URL parameter targeting 169.254.169.254 or internal IPs",
    "CWE-611": "DOCTYPE ENTITY referencing file:// or http:// URIs",
    "CWE-306": "Direct access to protected endpoint without credentials",
    "CWE-862": "Horizontal / vertical privilege escalation via predictable IDs",
}

# Patterns that look like source data origins in Python/JS source
_SOURCE_PATTERNS: List[re.Pattern] = [
    re.compile(r"request\.(args|form|json|data|params|get_json)\b"),
    re.compile(r"request\.get\("),
    re.compile(r'\binput\s*\('),
    re.compile(r'\bos\.environ\b'),
    re.compile(r'\bsys\.argv\b'),
    re.compile(r'\bgetenv\s*\('),
    re.compile(r'\breadline\s*\('),
    re.compile(r'\bparams\['),
    re.compile(r'\bquery_params\b'),
    re.compile(r'\bbody\b.*='),
]

_CONTEXT_WINDOW = 5  # lines around finding.line to scan for source patterns


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class ReasoningReport:
    finding_id: str
    cwe_id: str
    severity: str

    # The "why is this a problem" explanation
    why_vulnerable: str

    # Data source
    data_source: str            # e.g. "HTTP request parameter 'user_id'"
    source_file: str
    source_line: int

    # Propagation path
    propagation_path: List[str] = field(default_factory=list)
    # ["request.args.get('id')", "user_id", "cursor.execute(...)"]
    propagation_summary: str = ""   # Human-readable 1-sentence summary

    # Exploitation point
    exploitation_point: str = ""    # e.g. "SQL query construction at line 42"
    exploitation_technique: str = ""  # e.g. "SQL injection via string concatenation"

    # Reachability
    is_reachable: bool = False
    reachability_score: float = 0.0
    reachability_path: str = ""     # e.g. "GET /api/users → get_user() → line 42"

    # Verification
    verification_status: str = "Potential"   # "Potential" / "Reproduced" / "Verified"
    verification_evidence: str = ""          # What evidence exists

    # Impact
    affected_assets: List[str] = field(default_factory=list)
    impact_description: str = ""
    cvss_estimate: float = 0.0

    # Fix
    fix_summary: str = ""           # 1-sentence fix
    fix_code_example: str = ""      # Optional code snippet showing the fix


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class SecurityReasoningEngine:
    """Generates human-readable security reasoning for each finding."""

    # CWE → fix templates (hardcoded, no network)
    _FIX_TEMPLATES: Dict[str, tuple] = {
        "CWE-89": (
            "Use parameterized queries or ORM",
            'cursor.execute("SELECT * FROM t WHERE id=%s", (user_id,))',
        ),
        "CWE-79": (
            "Escape output or use safe templating",
            "html.escape(user_input)",
        ),
        "CWE-78": (
            "Use subprocess with list args, never shell=True",
            'subprocess.run(["cmd", arg], shell=False)',
        ),
        "CWE-22": (
            "Validate and normalize paths with os.path.realpath",
            'safe = os.path.realpath(os.path.join(base_dir, user_path))\nassert safe.startswith(base_dir)',
        ),
        "CWE-798": (
            "Store credentials in environment variables or secrets manager",
            'password = os.environ["DB_PASSWORD"]',
        ),
        "CWE-94": (
            "Avoid eval/exec on user input; use AST literal_eval for data",
            "ast.literal_eval(user_input)  # only for literals",
        ),
        "CWE-502": (
            "Use safe deserializers (json.loads instead of pickle)",
            "data = json.loads(user_input)",
        ),
        "CWE-918": (
            "Validate and whitelist allowed URLs/IPs",
            "if not url.startswith(ALLOWED_BASE): raise ValueError",
        ),
        "CWE-611": (
            "Disable external entity processing in XML parser",
            "parser = etree.XMLParser(resolve_entities=False)",
        ),
    }

    # Severity → CVSS estimate mapping
    _SEVERITY_CVSS: Dict[str, float] = {
        "CRITICAL": 9.0,
        "HIGH": 7.5,
        "MEDIUM": 5.0,
        "LOW": 3.0,
        "INFO": 1.0,
    }

    # ------------------------------------------------------------------ public

    def reason(self, finding: Any, source_code: str = "") -> ReasoningReport:
        """Generate full reasoning report for a single finding."""
        cwe = getattr(finding, "cwe_id", "") or ""
        severity = (getattr(finding, "severity", "MEDIUM") or "MEDIUM").upper()
        rule_id = getattr(finding, "rule_id", "UNKNOWN") or "UNKNOWN"
        src_file = getattr(finding, "file", "") or ""
        src_line = int(getattr(finding, "line", 0) or 0)
        confidence = float(getattr(finding, "confidence", 0.8) or 0.8)
        description = getattr(finding, "description", "") or ""

        finding_id = f"{rule_id}:{src_file}:{src_line}"

        # ── Why vulnerable ────────────────────────────────────────────────────
        base_desc = _CWE_DESCRIPTIONS.get(cwe, f"{cwe} vulnerability detected")
        why_vulnerable = (
            f"{base_desc} "
            f"Found in {src_file} at line {src_line}."
        )
        if description:
            why_vulnerable = f"{why_vulnerable} Detail: {description}"

        # ── Data source ───────────────────────────────────────────────────────
        data_source = self._infer_data_source(source_code, src_line, cwe)

        # ── Propagation path ──────────────────────────────────────────────────
        propagation_path = self._build_propagation_path(
            source_code, src_line, cwe, data_source
        )
        propagation_summary = self._summarize_propagation(
            propagation_path, cwe, src_file, src_line
        )

        # ── Exploitation point ────────────────────────────────────────────────
        exploitation_point = f"{cwe} exploitation at {src_file}:{src_line}"
        exploitation_technique = _CWE_EXPLOITATION_TECHNIQUES.get(
            cwe, "Exploitation via unsanitised user input"
        )

        # ── Reachability ──────────────────────────────────────────────────────
        reachability_score = self._estimate_reachability(finding, confidence)
        is_reachable = severity in ("CRITICAL", "HIGH") or reachability_score > 0.5
        reachability_path = self._build_reachability_path(finding)

        # ── Verification ──────────────────────────────────────────────────────
        verification_status, verification_evidence = self._assess_verification(finding)

        # ── Impact ────────────────────────────────────────────────────────────
        affected_assets = list(_CWE_AFFECTED_ASSETS.get(cwe, ["application"]))
        impact_description = self._build_impact_description(cwe, severity, affected_assets)
        cvss_estimate = self._SEVERITY_CVSS.get(severity, 5.0)

        # ── Fix ───────────────────────────────────────────────────────────────
        fix_summary, fix_code_example = self._FIX_TEMPLATES.get(
            cwe,
            (
                f"Sanitise all user-controlled input before using it in {cwe} context",
                "# Consult the CWE description for language-specific guidance",
            ),
        )

        return ReasoningReport(
            finding_id=finding_id,
            cwe_id=cwe,
            severity=severity,
            why_vulnerable=why_vulnerable,
            data_source=data_source,
            source_file=src_file,
            source_line=src_line,
            propagation_path=propagation_path,
            propagation_summary=propagation_summary,
            exploitation_point=exploitation_point,
            exploitation_technique=exploitation_technique,
            is_reachable=is_reachable,
            reachability_score=reachability_score,
            reachability_path=reachability_path,
            verification_status=verification_status,
            verification_evidence=verification_evidence,
            affected_assets=affected_assets,
            impact_description=impact_description,
            cvss_estimate=cvss_estimate,
            fix_summary=fix_summary,
            fix_code_example=fix_code_example,
        )

    def reason_batch(
        self,
        findings: List[Any],
        source_code: str = "",
    ) -> List[ReasoningReport]:
        """Generate reasoning for all findings. Returns sorted by severity."""
        _SEV_ORDER: Dict[str, int] = {
            "CRITICAL": 0,
            "HIGH": 1,
            "MEDIUM": 2,
            "LOW": 3,
            "INFO": 4,
        }
        reports = [self.reason(f, source_code) for f in findings]
        reports.sort(key=lambda r: _SEV_ORDER.get(r.severity, 99))
        return reports

    def format_markdown(self, report: ReasoningReport) -> str:
        """Format reasoning report as markdown text."""
        lines = [
            f"## Security Finding: {report.finding_id}",
            "",
            f"**Severity**: {report.severity}  |  **CWE**: {report.cwe_id}  "
            f"|  **CVSS Estimate**: {report.cvss_estimate}",
            "",
            "### Why This Is Vulnerable",
            report.why_vulnerable,
            "",
            "### Data Source",
            f"- **Source**: {report.data_source}",
            f"- **File**: `{report.source_file}` line {report.source_line}",
            "",
        ]

        if report.propagation_path:
            lines += [
                "### Data Propagation Path",
                " → ".join(f"`{step}`" for step in report.propagation_path),
                "",
                f"*{report.propagation_summary}*",
                "",
            ]

        lines += [
            "### Exploitation",
            f"- **Point**: {report.exploitation_point}",
            f"- **Technique**: {report.exploitation_technique}",
            "",
            "### Reachability",
            f"- **Reachable**: {'Yes' if report.is_reachable else 'No'}  "
            f"(score: {report.reachability_score:.2f})",
        ]
        if report.reachability_path:
            lines.append(f"- **Path**: `{report.reachability_path}`")
        lines.append("")

        lines += [
            "### Verification",
            f"- **Status**: {report.verification_status}",
        ]
        if report.verification_evidence:
            lines.append(f"- **Evidence**: {report.verification_evidence}")
        lines.append("")

        lines += [
            "### Impact",
            f"- **Affected Assets**: {', '.join(report.affected_assets)}",
            f"- **Description**: {report.impact_description}",
            "",
            "### Recommended Fix",
            f"**{report.fix_summary}**",
            "",
        ]
        if report.fix_code_example:
            lines += [
                "```python",
                report.fix_code_example,
                "```",
                "",
            ]

        return "\n".join(lines)

    def format_brief(self, report: ReasoningReport) -> str:
        """One-paragraph plain-text summary of the finding's risk."""
        reach = "reachable from the internet" if report.is_reachable else "internally reachable"
        return (
            f"[{report.severity}] {report.cwe_id} in {report.source_file}:{report.source_line} — "
            f"{report.why_vulnerable.split('.')[0]}. "
            f"The vulnerability is {reach} (score {report.reachability_score:.2f}) and is "
            f"{report.verification_status.lower()}. "
            f"It could affect: {', '.join(report.affected_assets)}. "
            f"Fix: {report.fix_summary}."
        )

    # ------------------------------------------------------------------ helpers

    def _infer_data_source(
        self, source_code: str, line: int, cwe: str
    ) -> str:
        """Scan source_code for common source patterns near finding.line."""
        if not source_code:
            return self._default_data_source(cwe)

        code_lines = source_code.splitlines()
        start = max(0, line - _CONTEXT_WINDOW - 1)
        end = min(len(code_lines), line + _CONTEXT_WINDOW)
        window = "\n".join(code_lines[start:end])

        for pattern in _SOURCE_PATTERNS:
            m = pattern.search(window)
            if m:
                return f"User-controlled input via `{m.group(0).strip()}`"

        return self._default_data_source(cwe)

    @staticmethod
    def _default_data_source(cwe: str) -> str:
        """Return a generic data-source description when code is unavailable."""
        defaults: Dict[str, str] = {
            "CWE-89":  "HTTP request parameter (query string or POST body)",
            "CWE-79":  "HTTP request parameter rendered in HTML response",
            "CWE-78":  "User-controlled input passed to OS command",
            "CWE-22":  "User-supplied file path parameter",
            "CWE-798": "Hard-coded literal in source code",
            "CWE-94":  "User input evaluated by template engine or exec/eval",
            "CWE-502": "Untrusted serialised data (network or file)",
            "CWE-918": "User-controlled URL parameter",
            "CWE-611": "User-supplied XML payload",
        }
        return defaults.get(cwe, "User-controlled input")

    def _build_propagation_path(
        self,
        source_code: str,
        line: int,
        cwe: str,
        data_source: str,
    ) -> List[str]:
        """Build a representative propagation path for the finding."""
        # Generic chains per CWE when full taint analysis is not available
        generic_chains: Dict[str, List[str]] = {
            "CWE-89": [
                data_source,
                "user_id (variable)",
                'cursor.execute("... " + user_id)',
            ],
            "CWE-79": [
                data_source,
                "user_content (variable)",
                "render_template(user_content)",
            ],
            "CWE-78": [
                data_source,
                "cmd_arg (variable)",
                'os.system("cmd " + cmd_arg)',
            ],
            "CWE-22": [
                data_source,
                "filepath (variable)",
                'open(os.path.join(base, filepath))',
            ],
            "CWE-94": [
                data_source,
                "template_str (variable)",
                "eval(template_str) / Template(template_str).render()",
            ],
            "CWE-502": [
                data_source,
                "serialised_bytes",
                "pickle.loads(serialised_bytes)",
            ],
            "CWE-918": [
                data_source,
                "target_url (variable)",
                "requests.get(target_url)",
            ],
            "CWE-611": [
                data_source,
                "xml_payload",
                "etree.fromstring(xml_payload)",
            ],
        }
        if source_code:
            # Try to extract a compact representation from code context
            code_lines = source_code.splitlines()
            if 0 < line <= len(code_lines):
                sink_line = code_lines[line - 1].strip()
                chain = generic_chains.get(cwe, [data_source, f"line {line}: {sink_line}"])
                # Replace last step with actual code line if available
                if chain and sink_line:
                    return chain[:-1] + [sink_line]
        return generic_chains.get(cwe, [data_source, f"sink at line {line}"])

    @staticmethod
    def _summarize_propagation(
        path: List[str], cwe: str, src_file: str, src_line: int
    ) -> str:
        """Return a one-sentence summary of the propagation path."""
        if not path:
            return f"User input flows to a {cwe} sink in {src_file} at line {src_line}."
        src = path[0]
        sink = path[-1]
        return (
            f"Data originating from '{src}' flows through {len(path) - 1} "
            f"transformation step(s) to reach the {cwe} sink '{sink}' "
            f"in {src_file} at line {src_line}."
        )

    @staticmethod
    def _estimate_reachability(finding: Any, confidence: float) -> float:
        """Estimate reachability score from finding attributes."""
        # Use an explicit reachability_score property if present
        explicit = getattr(finding, "reachability_score", None)
        if explicit is not None:
            try:
                return float(explicit)
            except (TypeError, ValueError):
                pass

        # Use confidence as a proxy, adjusted by severity
        severity = (getattr(finding, "severity", "MEDIUM") or "MEDIUM").upper()
        _sev_boost: Dict[str, float] = {
            "CRITICAL": 0.2,
            "HIGH": 0.1,
            "MEDIUM": 0.0,
            "LOW": -0.1,
            "INFO": -0.2,
        }
        raw = confidence + _sev_boost.get(severity, 0.0)
        return round(max(0.0, min(1.0, raw)), 4)

    @staticmethod
    def _build_reachability_path(finding: Any) -> str:
        """Build a human-readable reachability path from finding metadata."""
        src_file = getattr(finding, "file", "") or ""
        src_line = getattr(finding, "line", 0)
        rule_id = getattr(finding, "rule_id", "") or ""

        # Use sources list if available
        sources: List[str] = list(getattr(finding, "sources", None) or [])
        if sources:
            chain = sources + [f"{src_file}:{src_line}"]
            return " → ".join(chain)

        if src_file:
            return f"entry point → {src_file}:{src_line} ({rule_id})"
        return ""

    @staticmethod
    def _assess_verification(finding: Any) -> tuple:
        """Return (verification_status, verification_evidence) from finding."""
        description = (getattr(finding, "description", "") or "").lower()
        context_lines = list(getattr(finding, "context_lines", None) or [])

        # Check for explicit verified/reproduced markers
        if any(tok in description for tok in ("verified", "confirmed", "exploited")):
            return (
                "Verified",
                "Finding description contains verification marker.",
            )
        if any(tok in description for tok in ("reproduced", "poc available", "proof of concept")):
            return (
                "Reproduced",
                "Finding description indicates a proof-of-concept exists.",
            )

        # Context lines presence increases confidence but doesn't confirm
        if context_lines:
            return (
                "Potential",
                f"Static analysis match with {len(context_lines)} context line(s) available.",
            )

        return (
            "Potential",
            "No reproduction evidence found; assessment based on static analysis.",
        )

    @staticmethod
    def _build_impact_description(
        cwe: str, severity: str, affected_assets: List[str]
    ) -> str:
        """Construct a concise impact description."""
        asset_str = ", ".join(affected_assets) if affected_assets else "application assets"
        impact_templates: Dict[str, str] = {
            "CWE-89":  f"Successful exploitation could allow full read/write access to the database, "
                       f"exposing all {asset_str}.",
            "CWE-79":  f"Successful exploitation enables script execution in victims' browsers, "
                       f"compromising {asset_str}.",
            "CWE-78":  f"Successful exploitation provides arbitrary command execution on the host, "
                       f"compromising {asset_str}.",
            "CWE-22":  f"Successful exploitation allows reading or writing arbitrary files, "
                       f"including {asset_str}.",
            "CWE-798": f"Exposed credentials allow direct access to the associated service "
                       f"({asset_str}).",
            "CWE-94":  f"Successful exploitation achieves remote code execution, "
                       f"fully compromising {asset_str}.",
            "CWE-502": f"Malicious payloads can achieve remote code execution, "
                       f"compromising {asset_str}.",
            "CWE-918": f"Successful exploitation exposes internal services and may lead to "
                       f"credential theft from {asset_str}.",
            "CWE-611": f"Successful exploitation allows file reads and SSRF, "
                       f"exposing {asset_str}.",
        }
        return impact_templates.get(
            cwe,
            f"{severity} severity {cwe} finding could compromise {asset_str}.",
        )
