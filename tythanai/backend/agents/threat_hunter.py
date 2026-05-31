"""
TythanAI — Threat Hunter Agent
Hypothesis-driven threat hunting based on security findings.
Distinct from threat_hunting.py (which has SIEM queries); this is an autonomous agent
that reasons about code findings and generates/tests hypotheses.
"""
from __future__ import annotations

import importlib.util
import json
import logging
import os
import pathlib
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("ghost.threat_hunter")

# ─────────────────────────────────────────────────────────────────────────────
# Resolve Finding import — works in-tree or standalone
# ─────────────────────────────────────────────────────────────────────────────

try:
    from backend.core.confidence import Finding
except ModuleNotFoundError:
    _root = pathlib.Path(__file__).resolve().parents[2]
    _spec = importlib.util.spec_from_file_location(
        "confidence", _root / "backend" / "core" / "confidence.py"
    )
    _mod = importlib.util.module_from_spec(_spec)  # type: ignore[arg-type]
    _spec.loader.exec_module(_mod)  # type: ignore[union-attr]
    Finding = _mod.Finding  # type: ignore[misc]

# Resolve SkillsLoader
try:
    from backend.agents.skills_loader import SkillsLoader
except ModuleNotFoundError:
    _agents_dir = pathlib.Path(__file__).resolve().parent
    _sl_spec = importlib.util.spec_from_file_location(
        "skills_loader", _agents_dir / "skills_loader.py"
    )
    _sl_mod = importlib.util.module_from_spec(_sl_spec)  # type: ignore[arg-type]
    _sl_spec.loader.exec_module(_sl_mod)  # type: ignore[union-attr]
    SkillsLoader = _sl_mod.SkillsLoader  # type: ignore[misc]


# ─────────────────────────────────────────────────────────────────────────────
# Data models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Hypothesis:
    id: str
    description: str
    source_finding_rule: str
    attck_technique: str
    checks: List[str]         # concrete search patterns to apply to code
    confidence: float         # 0.0-1.0


@dataclass
class HypothesisResult:
    hypothesis: Hypothesis
    confirmed: bool
    evidence: List[str]       # lines/patterns that confirmed it
    false_positive_indicators: List[str]


@dataclass
class HuntingReport:
    scan_id: str
    hypotheses_generated: int
    hypotheses_confirmed: int
    results: List[HypothesisResult]
    lotl_patterns: List[str]    # Living off the Land patterns found
    sigma_rules: List[str]      # generated Sigma rule YAML strings
    report_path: Optional[str]


# ─────────────────────────────────────────────────────────────────────────────
# Hypothesis Templates
# ATT&CK technique → list of hypothesis template dicts
# ─────────────────────────────────────────────────────────────────────────────

_HYPOTHESIS_TEMPLATES: Dict[str, List[dict]] = {
    # T1055 — Process Injection
    "T1055": [
        {
            "description": (
                "Subprocess combined with ctypes may indicate in-process shellcode injection "
                "or foreign function invocation for process injection."
            ),
            "checks": [
                r"\bsubprocess\b",
                r"\bctypes\b",
                r"(LoadLibrary|WinDLL|CDLL|cdll)",
            ],
            "confidence": 0.75,
        },
        {
            "description": (
                "mmap() with PROT_EXEC permissions followed by callable cast suggests "
                "runtime shellcode execution / process injection via memory-mapped payload."
            ),
            "checks": [
                r"\bmmap\b",
                r"(PROT_EXEC|mprotect.*EXEC|MAP_EXECUTABLE)",
                r"(ctypes\.cast|cast\(.*CFUNCTYPE)",
            ],
            "confidence": 0.85,
        },
        {
            "description": (
                "ptrace() syscall usage outside of a debugger context may indicate "
                "process injection or memory manipulation via debug API abuse."
            ),
            "checks": [
                r"\bptrace\b",
                r"(PTRACE_POKEDATA|PTRACE_ATTACH|PTRACE_SETREGS)",
            ],
            "confidence": 0.80,
        },
    ],
    # T1059 — Command and Scripting Interpreter
    "T1059": [
        {
            "description": (
                "subprocess.call or os.system invoked with user-controlled input creates "
                "a command injection vector that attackers can leverage for arbitrary code execution."
            ),
            "checks": [
                r"(subprocess\.call|subprocess\.run|subprocess\.Popen)",
                r"(request\.(args|form|data|json)|input\(|sys\.argv)",
            ],
            "confidence": 0.80,
        },
        {
            "description": (
                "os.system() with dynamic string construction from external inputs "
                "enables shell injection attacks."
            ),
            "checks": [
                r"\bos\.system\s*\(",
                r"(f['\"]|%\s*['\"]|\.format\s*\(|str\s*\()",
            ],
            "confidence": 0.78,
        },
        {
            "description": (
                "eval() or exec() with non-literal arguments is a critical code injection "
                "risk allowing arbitrary Python execution from attacker-controlled input."
            ),
            "checks": [
                r"\b(eval|exec)\s*\(",
                r"(request\.|input\(|os\.environ|sys\.argv|open\()",
            ],
            "confidence": 0.90,
        },
    ],
    # T1078 — Valid Accounts (hardcoded credentials)
    "T1078": [
        {
            "description": (
                "Hardcoded password or secret strings in source code allow attackers "
                "who gain repository access to immediately use valid credentials."
            ),
            "checks": [
                r"(password|passwd|secret|api_key|apikey|token)\s*=\s*['\"][^'\"]{6,}['\"]",
                r"(?i)(password|secret|api.?key)\s*[:=]\s*['\"][^'\"]+['\"]",
            ],
            "confidence": 0.85,
        },
        {
            "description": (
                "Default or well-known credential strings (admin, root, password123, changeme) "
                "suggest hardcoded defaults that are easily guessed by automated scanners."
            ),
            "checks": [
                r"(?i)(admin|root|changeme|password123|default|test123|letmein|qwerty)",
                r"(password|passwd|secret|token|auth)\s*=",
            ],
            "confidence": 0.70,
        },
    ],
    # T1027 — Obfuscated Files or Information
    "T1027": [
        {
            "description": (
                "base64-decoded content passed directly to exec() or eval() is a "
                "common malware obfuscation technique to bypass static analysis."
            ),
            "checks": [
                r"\b(base64\.b64decode|b64decode|base64_decode)\b",
                r"\b(exec|eval|compile|__import__)\s*\(",
            ],
            "confidence": 0.88,
        },
        {
            "description": (
                "chr() concatenation to build strings character-by-character is an "
                "obfuscation technique used to evade static string detection."
            ),
            "checks": [
                r"\bchr\s*\(\s*\d+\s*\)",
                r"(chr\s*\(\s*\d+\s*\)\s*\+\s*){3,}",
            ],
            "confidence": 0.72,
        },
        {
            "description": (
                "ROT13 or XOR encoding of embedded strings followed by execution "
                "indicates runtime payload deobfuscation before code execution."
            ),
            "checks": [
                r"(codecs\.decode|rot_13|rot13)",
                r"\b(exec|eval)\s*\(",
            ],
            "confidence": 0.80,
        },
    ],
    # T1003 — OS Credential Dumping
    "T1003": [
        {
            "description": (
                "Reading /etc/passwd or /etc/shadow from application code may indicate "
                "credential harvesting attempt or information disclosure vulnerability."
            ),
            "checks": [
                r"open\s*\(['\"]/?etc/(passwd|shadow|sudoers)['\"]",
                r"(open|read|load)\s*.*/(etc|passwd|shadow)",
            ],
            "confidence": 0.82,
        },
        {
            "description": (
                "Keyring or OS credential store access by web application code "
                "may indicate malicious credential harvesting from service accounts."
            ),
            "checks": [
                r"\b(keyring|secretstorage|gnomekeyring|keyczar)\b",
                r"\b(get_password|get_credential|get_secret)\b",
            ],
            "confidence": 0.70,
        },
    ],
    # T1190 — Exploit Public-Facing Application
    "T1190": [
        {
            "description": (
                "SQL string concatenation with external input creates SQL injection "
                "vulnerability allowing database compromise via public-facing application."
            ),
            "checks": [
                r"(execute|cursor\.execute|query|raw_query)\s*\(",
                r"(f['\"].*SELECT|['\"].*\+.*SELECT|format.*SELECT)",
            ],
            "confidence": 0.85,
        },
        {
            "description": (
                "HTTP request made with URL built from user input without validation "
                "creates SSRF vulnerability exploitable through the public-facing interface."
            ),
            "checks": [
                r"(requests\.get|requests\.post|urllib\.request|httpx\.get)\s*\(",
                r"(request\.(args|form|data|json)|input\(|os\.environ)",
            ],
            "confidence": 0.80,
        },
        {
            "description": (
                "XML parsing of user-supplied data without disabling external entity "
                "resolution creates XXE vulnerability in public-facing application."
            ),
            "checks": [
                r"(etree\.parse|minidom\.parse|lxml\.etree|xml\.dom)",
                r"(request\.(data|body|stream)|open\(|file_upload)",
            ],
            "confidence": 0.78,
        },
        {
            "description": (
                "Deserialization of user-supplied data (pickle, marshal, yaml.load) "
                "can lead to remote code execution through a public-facing interface."
            ),
            "checks": [
                r"\b(pickle\.loads|marshal\.loads|yaml\.load\s*\((?!.*Loader))",
                r"(request\.(data|body|json)|input\(|open\(.*['\"]rb['\"])",
            ],
            "confidence": 0.90,
        },
    ],
    # T1071 — Application Layer Protocol (C2)
    "T1071": [
        {
            "description": (
                "socket.connect() to a hardcoded IP address from application code "
                "may indicate C2 callback channel embedded in malicious or backdoored code."
            ),
            "checks": [
                r"socket\.connect\s*\(",
                r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
            ],
            "confidence": 0.75,
        },
        {
            "description": (
                "DNS resolution of a hardcoded non-local hostname from application code "
                "may indicate domain generation algorithm (DGA) based C2 communication."
            ),
            "checks": [
                r"(socket\.gethostbyname|dns\.resolver\.resolve|getaddrinfo)\s*\(",
                r"['\"][a-z0-9]{8,}\.(xyz|club|top|pw|cc|tk|ml|ga|cf)['\"]",
            ],
            "confidence": 0.72,
        },
        {
            "description": (
                "HTTP beacon with fixed User-Agent or regular timing intervals "
                "is a pattern used by C2 frameworks for persistent implant communication."
            ),
            "checks": [
                r"(requests\.get|requests\.post|urllib\.request\.urlopen)",
                r"(time\.sleep|asyncio\.sleep)\s*\(\s*\d+",
            ],
            "confidence": 0.65,
        },
    ],
    # T1005 — Data from Local System
    "T1005": [
        {
            "description": (
                "Reading sensitive files (SSH keys, certificates, .env files) in "
                "application code may indicate unauthorized data collection attempt."
            ),
            "checks": [
                r"open\s*\(['\"].*\.(pem|key|pfx|p12|env|secrets)['\"]",
                r"(~|/home/|/root/)\.ssh",
            ],
            "confidence": 0.78,
        },
        {
            "description": (
                "Bulk collection of environment variables with os.environ or reading "
                "all process environment data may indicate credential/secret harvesting."
            ),
            "checks": [
                r"\bos\.environ\b",
                r"(dict\(os\.environ\)|list\(os\.environ\)|os\.environ\.copy\(\))",
            ],
            "confidence": 0.65,
        },
    ],
    # T1552 — Unsecured Credentials
    "T1552": [
        {
            "description": (
                "Config file parsing with fallback to hardcoded credential string "
                "indicates unsecured credentials that persist even without config files."
            ),
            "checks": [
                r"(configparser|yaml\.safe_load|json\.load|toml\.load)\s*\(",
                r"(password|secret|api_key)\s*=\s*['\"][^'\"]{6,}['\"]",
            ],
            "confidence": 0.75,
        },
    ],
    # T1611 — Escape to Host (container)
    "T1611": [
        {
            "description": (
                "nsenter or unshare syscalls from within container code may indicate "
                "container escape attempt exploiting namespace isolation weaknesses."
            ),
            "checks": [
                r"\b(nsenter|unshare|setns)\b",
                r"(subprocess|os\.system|os\.popen)",
            ],
            "confidence": 0.90,
        },
        {
            "description": (
                "Docker socket access from application code can allow full host compromise "
                "by spawning privileged containers or executing host commands."
            ),
            "checks": [
                r"(/var/run/docker\.sock|docker_socket|DockerClient)",
                r"(privileged|host.*network|pid.*mode|cap_add)",
            ],
            "confidence": 0.88,
        },
    ],
}

# ─────────────────────────────────────────────────────────────────────────────
# Rule_id / CWE → ATT&CK technique mapping
# ─────────────────────────────────────────────────────────────────────────────

_RULE_TO_TECHNIQUE: List[Tuple[str, str]] = [
    ("sqli", "T1190"),
    ("sql_inj", "T1190"),
    ("xss", "T1059"),
    ("ssrf", "T1190"),
    ("rce", "T1059"),
    ("cmd_inj", "T1059"),
    ("exec", "T1059"),
    ("eval", "T1059"),
    ("deser", "T1190"),
    ("xxe", "T1190"),
    ("secret", "T1078"),
    ("hardcod", "T1078"),
    ("cred", "T1003"),
    ("passwd", "T1003"),
    ("shadow", "T1003"),
    ("obfusc", "T1027"),
    ("base64", "T1027"),
    ("encode", "T1027"),
    ("container", "T1611"),
    ("docker", "T1611"),
    ("k8s", "T1611"),
    ("lateral", "T1021"),
    ("c2", "T1071"),
    ("beacon", "T1071"),
    ("exfil", "T1041"),
    ("persist", "T1547"),
    ("inject", "T1055"),
    ("proc_inj", "T1055"),
    ("data_collect", "T1005"),
    ("env_var", "T1005"),
]

_CWE_TO_TECHNIQUE: Dict[str, str] = {
    "CWE-89": "T1190",
    "CWE-79": "T1059",
    "CWE-78": "T1059",
    "CWE-918": "T1190",
    "CWE-502": "T1190",
    "CWE-611": "T1190",
    "CWE-798": "T1078",
    "CWE-522": "T1003",
    "CWE-327": "T1027",
    "CWE-326": "T1027",
    "CWE-94": "T1059",
    "CWE-77": "T1059",
    "CWE-287": "T1078",
    "CWE-269": "T1055",
}

# ─────────────────────────────────────────────────────────────────────────────
# Living off the Land (LotL) patterns
# ─────────────────────────────────────────────────────────────────────────────

_LOTL_PATTERNS: List[str] = [
    r"\bcurl\b.*(-d|--data|--upload|-T|--request|-X)",
    r"\bwget\b.*(-O|-P|--output-document|--post-data|--quiet)",
    r"\bnc\b.*(-e|--exec|-c|--sh-exec|-l)",
    r"\bncat\b.*(-e|--exec|-c|--sh-exec|-l)",
    r"\bnetcat\b",
    r"python\s+-c\s+['\"]",
    r"python3?\s+-c\s+['\"]",
    r"perl\s+-e\s+['\"]",
    r"ruby\s+-e\s+['\"]",
    r"bash\s+-i\s*(>&|>)",
    r"sh\s+-i\s*(>&|>)",
    r"/bin/bash\s+-i",
    r"/bin/sh\s+-i",
    r"\bmkfifo\b.*&&.*\bnc\b",
    r"\bsocat\b.*(TCP|EXEC|PTY)",
    r"\btelnet\b.*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
    r"0<&\d+-;(exec|bash|sh)\s",
    r"exec\s+\d+<>/dev/tcp/",
    r"/dev/tcp/\d{1,3}\.\d{1,3}",
    r"\bawk\b.*'BEGIN.*system\s*\(",
    r"sed\s+-n\s+'[0-9]+",
    r"\bpython.*import\s+pty",
    r"pty\.spawn\s*\(\s*['\"]/(bin|usr/bin)/(bash|sh)",
    r"\bchmod\s+\+s\b",
    r"\bchown\s+root\b.*&&.*chmod",
    r"(wget|curl).*\|\s*(sh|bash|python|perl)",
    r"\benv\s+x=.*\(\s*\)",
    r"dd\s+if=/dev/urandom",
    r"\bcrontab\s+-l\b.*\|",
    r"echo\s+.*>>\s*/etc/cron",
]

# ─────────────────────────────────────────────────────────────────────────────
# Source file extensions to scan
# ─────────────────────────────────────────────────────────────────────────────

_SCANNABLE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".java", ".rb", ".php",
    ".sh", ".bash", ".ps1", ".c", ".cpp", ".h", ".cs", ".rs", ".kt",
    ".yml", ".yaml", ".tf", ".json", ".conf", ".cfg", ".ini", ".env",
    ".dockerfile", ".Dockerfile",
}


# ─────────────────────────────────────────────────────────────────────────────
# ThreatHunterAgent
# ─────────────────────────────────────────────────────────────────────────────

class ThreatHunterAgent:
    """
    Autonomous threat hunting agent that generates and tests hypotheses about
    malicious code patterns based on security findings.
    """

    def __init__(self) -> None:
        self._loader = SkillsLoader()
        # Pre-load threat-hunting domain skills
        self._hunting_skills = self._loader.search_by_domain("threat-hunting")

    def hunt(
        self,
        findings: List[Finding],
        project_root: Optional[pathlib.Path] = None,
    ) -> HuntingReport:
        """
        Main entry point: generate hypotheses for high/critical findings,
        run code checks if project_root provided, detect LotL patterns,
        and generate Sigma rules for confirmed hypotheses.
        """
        scan_id = f"HUNT-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6].upper()}"

        all_results: List[HypothesisResult] = []
        lotl_found: List[str] = []
        sigma_rules: List[str] = []

        # Focus on HIGH and CRITICAL findings
        priority_findings = [
            f for f in findings
            if f.severity.upper() in ("HIGH", "CRITICAL")
        ]

        # Generate and test hypotheses for each priority finding
        for finding in priority_findings:
            hypotheses = self._generate_hypotheses(finding)
            for hyp in hypotheses:
                evidence: List[str] = []
                fp_indicators: List[str] = []

                if project_root and project_root.is_dir():
                    for check in hyp.checks:
                        matches = self._run_code_check(check, project_root)
                        evidence.extend(matches)

                    # Check for LotL patterns in discovered evidence files
                    for ev_line in evidence:
                        for lotl_re in _LOTL_PATTERNS:
                            if re.search(lotl_re, ev_line, re.IGNORECASE):
                                pattern_match = f"LotL pattern '{lotl_re}' matched: {ev_line[:100]}"
                                if pattern_match not in lotl_found:
                                    lotl_found.append(pattern_match)

                confirmed = len(evidence) >= len(hyp.checks) * 0.5 and len(evidence) > 0

                # Add false-positive context
                if not confirmed and evidence:
                    fp_indicators.append("Pattern present but insufficient corroborating evidence")
                if finding.is_test_file if hasattr(finding, 'is_test_file') else False:
                    fp_indicators.append("Finding is in a test file — likely test code or fixture")

                result = HypothesisResult(
                    hypothesis=hyp,
                    confirmed=confirmed,
                    evidence=evidence[:20],
                    false_positive_indicators=fp_indicators,
                )
                all_results.append(result)

                if confirmed:
                    sigma_rules.append(self._generate_sigma_rule(hyp, evidence))

        # If no project_root, run hypothesis generation only (no confirmation)
        if not project_root:
            all_results = [
                HypothesisResult(
                    hypothesis=hyp,
                    confirmed=False,
                    evidence=[],
                    false_positive_indicators=["No project_root provided; static hypothesis only"],
                )
                for finding in priority_findings
                for hyp in self._generate_hypotheses(finding)
            ]

        # Scan entire project for LotL if project_root available
        if project_root and project_root.is_dir():
            additional_lotl = self._scan_lotl(project_root)
            for item in additional_lotl:
                if item not in lotl_found:
                    lotl_found.append(item)

        confirmed_count = sum(1 for r in all_results if r.confirmed)

        # Persist report
        report_path: Optional[str] = None
        try:
            report_dir = pathlib.Path("/tmp/reports/threat_hunting")
            report_dir.mkdir(parents=True, exist_ok=True)
            report_file = report_dir / f"{scan_id}.json"
            payload = {
                "scan_id": scan_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "hypotheses_generated": len(all_results),
                "hypotheses_confirmed": confirmed_count,
                "lotl_patterns": lotl_found[:50],
                "sigma_rules_count": len(sigma_rules),
                "results": [
                    {
                        "hypothesis_id": r.hypothesis.id,
                        "description": r.hypothesis.description,
                        "attck_technique": r.hypothesis.attck_technique,
                        "source_finding_rule": r.hypothesis.source_finding_rule,
                        "confirmed": r.confirmed,
                        "evidence_count": len(r.evidence),
                        "confidence": r.hypothesis.confidence,
                    }
                    for r in all_results
                ],
            }
            report_file.write_text(json.dumps(payload, indent=2))
            report_path = str(report_file)
        except OSError as exc:
            logger.warning("Could not save hunt report: %s", exc)

        return HuntingReport(
            scan_id=scan_id,
            hypotheses_generated=len(all_results),
            hypotheses_confirmed=confirmed_count,
            results=all_results,
            lotl_patterns=lotl_found[:50],
            sigma_rules=sigma_rules,
            report_path=report_path,
        )

    def _generate_hypotheses(self, finding: Finding) -> List[Hypothesis]:
        """
        Generate hypotheses for a single finding based on rule_id and cwe_id.
        Always returns at least 2 hypotheses for HIGH+ severity findings.
        """
        technique = self._resolve_technique(finding)
        templates = _HYPOTHESIS_TEMPLATES.get(technique, [])

        hypotheses: List[Hypothesis] = []

        for tmpl in templates:
            hyp_id = f"HYP-{finding.rule_id.upper()[:8]}-{uuid.uuid4().hex[:6].upper()}"
            hypotheses.append(Hypothesis(
                id=hyp_id,
                description=tmpl["description"],
                source_finding_rule=finding.rule_id,
                attck_technique=technique,
                checks=list(tmpl["checks"]),
                confidence=tmpl["confidence"],
            ))

        # Guarantee at least 2 hypotheses for HIGH/CRITICAL findings
        severity_upper = finding.severity.upper()
        if severity_upper in ("HIGH", "CRITICAL") and len(hypotheses) < 2:
            fallback_techs = self._get_fallback_techniques(finding, exclude=technique)
            for extra_tech in fallback_techs:
                extra_templates = _HYPOTHESIS_TEMPLATES.get(extra_tech, [])
                for tmpl in extra_templates:
                    if len(hypotheses) >= 2:
                        break
                    hyp_id = f"HYP-{finding.rule_id.upper()[:8]}-{uuid.uuid4().hex[:6].upper()}"
                    hypotheses.append(Hypothesis(
                        id=hyp_id,
                        description=tmpl["description"],
                        source_finding_rule=finding.rule_id,
                        attck_technique=extra_tech,
                        checks=list(tmpl["checks"]),
                        confidence=tmpl["confidence"] * 0.85,  # slightly lower for fallback
                    ))
                if len(hypotheses) >= 2:
                    break

            # Final safety net: synthesize generic hypotheses if still < 2
            while len(hypotheses) < 2:
                idx = len(hypotheses)
                generic_checks = self._get_generic_checks(finding, idx)
                generic_tech = fallback_techs[idx] if idx < len(fallback_techs) else "T1059"
                hyp_id = f"HYP-{finding.rule_id.upper()[:8]}-GEN{idx}"
                hypotheses.append(Hypothesis(
                    id=hyp_id,
                    description=(
                        f"Generic hypothesis #{idx + 1} for {finding.rule_id}: "
                        f"Investigate {generic_tech} indicators in the affected code area."
                    ),
                    source_finding_rule=finding.rule_id,
                    attck_technique=generic_tech,
                    checks=generic_checks,
                    confidence=0.55,
                ))

        return hypotheses

    def _resolve_technique(self, finding: Finding) -> str:
        """Map finding rule_id / cwe_id to an ATT&CK technique ID."""
        rule_lower = finding.rule_id.lower()

        # Rule-id keyword match
        for keyword, technique in _RULE_TO_TECHNIQUE:
            if keyword in rule_lower:
                return technique

        # CWE-based fallback
        if finding.cwe_id:
            cwe_upper = finding.cwe_id.upper().strip()
            if cwe_upper in _CWE_TO_TECHNIQUE:
                return _CWE_TO_TECHNIQUE[cwe_upper]

        # Skills-based lookup
        skill_results = self._loader.scan_all(finding.rule_id + " " + finding.description, top_n=1)
        if skill_results:
            mitre_ids = skill_results[0].mitre_ids
            if mitre_ids:
                return mitre_ids[0]

        # Default to T1190 for web findings, T1059 otherwise
        web_keywords = ("xss", "inject", "ssrf", "sqli", "deser", "xxe", "rce")
        if any(k in rule_lower for k in web_keywords):
            return "T1190"
        return "T1059"

    def _get_fallback_techniques(self, finding: Finding, exclude: str) -> List[str]:
        """Return additional techniques to generate hypotheses from."""
        rule_lower = finding.rule_id.lower()
        candidates: List[str] = []

        # Build a candidate set from all matching rule mappings
        for keyword, technique in _RULE_TO_TECHNIQUE:
            if keyword in rule_lower and technique != exclude:
                if technique not in candidates:
                    candidates.append(technique)

        # Always include some broad techniques as safety net
        defaults = ["T1059", "T1078", "T1027", "T1005", "T1190", "T1003"]
        for t in defaults:
            if t != exclude and t not in candidates:
                candidates.append(t)

        return candidates

    def _get_generic_checks(self, finding: Finding, idx: int) -> List[str]:
        """Return generic code search patterns for a finding."""
        rule_lower = finding.rule_id.lower()
        if "web" in rule_lower or "http" in rule_lower or "request" in rule_lower:
            patterns = [
                [r"(request\.|flask\.request|django\.request)", r"(sql|query|execute)"],
                [r"(render|template|response\.write)", r"(user|input|param)"],
            ]
        elif "cred" in rule_lower or "pass" in rule_lower or "auth" in rule_lower:
            patterns = [
                [r"(password|passwd|secret)\s*=\s*['\"]", r"['\"][A-Za-z0-9!@#$%]{6,}['\"]"],
                [r"(login|authenticate|verify_password)", r"(hardcod|literal|const)"],
            ]
        else:
            patterns = [
                [r"\b(subprocess|os\.system|eval|exec)\b", r"(import|from)"],
                [r"\b(open|read|write)\s*\(", r"['\"]/(etc|tmp|var)/"],
            ]
        return patterns[idx] if idx < len(patterns) else [r"\b(security|auth|token)\b"]

    def _run_code_check(self, check_pattern: str, project_root: pathlib.Path) -> List[str]:
        """
        Grep-like search: scan all scannable files under project_root for the
        given regex pattern. Returns matched line strings (capped at 50).
        """
        compiled: re.Pattern
        try:
            compiled = re.compile(check_pattern, re.IGNORECASE)
        except re.error as exc:
            logger.debug("Invalid regex pattern '%s': %s", check_pattern, exc)
            return []

        matches: List[str] = []
        try:
            for file_path in project_root.rglob("*"):
                if not file_path.is_file():
                    continue
                if file_path.suffix.lower() not in _SCANNABLE_EXTENSIONS:
                    # Also match files named 'Dockerfile' without extension
                    if file_path.name not in ("Dockerfile", ".env", ".envrc"):
                        continue
                # Skip very large files (>500 KB)
                try:
                    if file_path.stat().st_size > 512_000:
                        continue
                    text = file_path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue

                for lineno, line in enumerate(text.splitlines(), 1):
                    if compiled.search(line):
                        rel_path = file_path.relative_to(project_root)
                        matches.append(f"{rel_path}:{lineno}: {line.strip()[:120]}")
                        if len(matches) >= 50:
                            return matches
        except OSError as exc:
            logger.debug("Error scanning project root: %s", exc)

        return matches

    def _scan_lotl(self, project_root: pathlib.Path) -> List[str]:
        """Scan all code files in project_root for Living off the Land patterns."""
        compiled_patterns = []
        for pattern in _LOTL_PATTERNS:
            try:
                compiled_patterns.append((pattern, re.compile(pattern, re.IGNORECASE)))
            except re.error:
                continue

        found: List[str] = []
        try:
            for file_path in project_root.rglob("*"):
                if not file_path.is_file():
                    continue
                if file_path.suffix.lower() not in _SCANNABLE_EXTENSIONS:
                    if file_path.name not in ("Dockerfile", ".env"):
                        continue
                try:
                    if file_path.stat().st_size > 512_000:
                        continue
                    text = file_path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue

                for lineno, line in enumerate(text.splitlines(), 1):
                    for pat_str, pat_re in compiled_patterns:
                        if pat_re.search(line):
                            rel = file_path.relative_to(project_root)
                            found.append(
                                f"LotL[{pat_str[:40]}] {rel}:{lineno}: {line.strip()[:100]}"
                            )
                            if len(found) >= 100:
                                return found
        except OSError as exc:
            logger.debug("LotL scan error: %s", exc)

        return found

    def _generate_sigma_rule(self, hyp: Hypothesis, evidence: List[str]) -> str:
        """
        Generate a minimal valid Sigma YAML rule from a confirmed hypothesis.
        """
        technique = hyp.attck_technique
        # Determine best logsource category from technique
        logsource_category = "process_creation"
        logsource_product = "linux"
        if technique in ("T1190", "T1059.007"):
            logsource_category = "webserver"
            logsource_product = ""
        elif technique in ("T1003", "T1005"):
            logsource_category = "process_creation"
            logsource_product = "linux"
        elif technique in ("T1071", "T1041"):
            logsource_category = "network_connection"
            logsource_product = "linux"
        elif technique in ("T1078", "T1552"):
            logsource_category = "application"
            logsource_product = ""

        # Build detection keywords from checks
        keywords: List[str] = []
        for check in hyp.checks[:3]:
            # Strip regex metacharacters to get human-readable keywords
            kw = re.sub(r"[\\\(\)\[\]\{\}\|\?\+\*\^]", "", check)
            kw = re.sub(r"\s+", " ", kw).strip()
            if kw and len(kw) > 2:
                keywords.append(kw[:60])

        # Build evidence-based false positive context
        fp_note = "Review in context; legitimate security tooling may trigger this rule"
        if evidence:
            fp_note = f"Confirmed in {len(evidence)} locations; verify business justification"

        # Sanitize description for YAML
        description = hyp.description[:200].replace("\n", " ").replace('"', "'")
        rule_name = f"TythanAI Hunt — {technique} — {hyp.source_finding_rule.replace('_', ' ').title()}"

        logsource_block = f"  category: {logsource_category}"
        if logsource_product:
            logsource_block += f"\n  product: {logsource_product}"

        keywords_yaml = "\n".join(f"      - '{kw}'" for kw in keywords) if keywords else "      - ''"

        sigma_yaml = f"""title: '{rule_name}'
id: {uuid.uuid4()}
status: experimental
description: '{description}'
author: TythanAI ThreatHunterAgent
date: {datetime.now(timezone.utc).strftime('%Y/%m/%d')}
references:
  - https://attack.mitre.org/techniques/{technique.replace('.', '/').rstrip('/')}
logsource:
{logsource_block}
detection:
  keywords:
{keywords_yaml}
  condition: keywords
falsepositives:
  - {fp_note}
level: {'critical' if hyp.confidence >= 0.85 else 'high' if hyp.confidence >= 0.70 else 'medium'}
tags:
  - attack.{technique.lower().replace('.', '_')}
  - attack.{'initial_access' if technique == 'T1190' else 'execution' if 'T1059' in technique else 'defense_evasion' if technique == 'T1027' else 'credential_access' if technique in ('T1003', 'T1078', 'T1552') else 'command_and_control' if technique in ('T1071', 'T1041') else 'collection' if technique == 'T1005' else 'privilege_escalation'}
"""
        return sigma_yaml
