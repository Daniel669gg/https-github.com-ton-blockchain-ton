"""Threat Hunting Engine — behavioral detection patterns and hunting queries."""
from __future__ import annotations

import re
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class HuntingQuery(BaseModel):
    query_id: str          # "HUNT-001"
    name: str
    description: str
    platform: str          # "splunk" | "elastic" | "chronicle" | "kql" | "yara"
    query: str             # actual query string
    mitre_technique: str   # "T1059.001"
    severity: str
    tags: List[str] = Field(default_factory=list)
    hypothesis: str = ""   # threat hypothesis being tested
    false_positive_notes: str = ""


class HuntingResult(BaseModel):
    query: HuntingQuery
    matched_patterns: List[str]   # patterns found in code/logs
    matched_lines: List[int]
    confidence: float
    evidence: List[str]           # snippets of matching code


# ---------------------------------------------------------------------------
# Built-in hunting queries
# ---------------------------------------------------------------------------

HUNTING_QUERIES: List[HuntingQuery] = [
    # ── Splunk queries ──────────────────────────────────────────────────────
    HuntingQuery(
        query_id="HUNT-001",
        name="Reverse Shell Pattern in Python Code",
        description="Detects reverse shell patterns in Python application logs involving subprocess or os.system with pipe/redirect operators.",
        platform="splunk",
        query=(
            'index=app_logs sourcetype=python command IN ("*subprocess*", "*os.system*") '
            '| search command="*&*" OR command="*|nc*"'
        ),
        mitre_technique="T1059.006",
        severity="CRITICAL",
        tags=["execution", "reverse-shell", "python"],
        hypothesis="Attacker gained code execution and is attempting to spawn a reverse shell.",
        false_positive_notes="CI/CD pipelines running subprocess for build tasks; verify destination IP.",
    ),
    HuntingQuery(
        query_id="HUNT-002",
        name="Base64-Encoded Command Execution",
        description="Detects base64-encoded payloads being decoded and executed, a common obfuscation technique.",
        platform="splunk",
        query=(
            'index=app_logs | eval decoded=base64decode(field) '
            '| search decoded="*exec*" OR decoded="*import*"'
        ),
        mitre_technique="T1027",
        severity="HIGH",
        tags=["obfuscation", "base64", "execution"],
        hypothesis="Attacker is using base64 encoding to bypass input validation and execute arbitrary code.",
        false_positive_notes="Legitimate base64 data transmission; check for presence of exec/eval after decode.",
    ),
    HuntingQuery(
        query_id="HUNT-003",
        name="Unusual Outbound Connections on Known C2 Ports",
        description="Detects outbound network connections to ports commonly used by C2 frameworks (Metasploit, Cobalt Strike).",
        platform="splunk",
        query="index=network sourcetype=firewall dest_port IN (4444, 1337, 9001, 31337)",
        mitre_technique="T1571",
        severity="CRITICAL",
        tags=["c2", "network", "exfiltration"],
        hypothesis="Compromised host is beaconing to attacker-controlled C2 infrastructure.",
        false_positive_notes="Some dev tools use port 4444; validate destination IP reputation.",
    ),
    HuntingQuery(
        query_id="HUNT-004",
        name="Credential Stuffing High-Volume Auth",
        description="Detects IPs generating more than 100 authentication attempts, indicative of credential stuffing.",
        platform="splunk",
        query=(
            "index=auth sourcetype=access_log "
            "| stats count by src_ip | where count > 100"
        ),
        mitre_technique="T1110.004",
        severity="HIGH",
        tags=["credential-stuffing", "brute-force", "authentication"],
        hypothesis="Attacker is attempting credential stuffing using a list of breached credentials.",
        false_positive_notes="Load balancers and monitoring tools may appear as high-volume IPs; whitelist known infra.",
    ),
    HuntingQuery(
        query_id="HUNT-005",
        name="Web Shell Upload Indicators",
        description="Detects web shell upload attempts via PHP files accessed with command execution parameters.",
        platform="splunk",
        query='index=web_logs | search (uri="*.php*" AND (uri="*cmd*" OR uri="*exec*"))',
        mitre_technique="T1505.003",
        severity="CRITICAL",
        tags=["webshell", "persistence", "initial-access"],
        hypothesis="Attacker has uploaded a PHP web shell to maintain persistent access.",
        false_positive_notes="Legitimate PHP admin panels; cross-reference with file upload events.",
    ),
    HuntingQuery(
        query_id="HUNT-006",
        name="SSRF Indicators in Application Logs",
        description="Detects Server-Side Request Forgery attempts targeting internal metadata services and private IP ranges.",
        platform="splunk",
        query=(
            'index=app_logs | search url IN '
            '("*169.254*", "*127.0*", "*192.168*", "*10.*")'
        ),
        mitre_technique="T1552.005",
        severity="HIGH",
        tags=["ssrf", "cloud", "metadata"],
        hypothesis="Attacker is attempting SSRF to access cloud metadata service or internal resources.",
        false_positive_notes="Internal health checks and service mesh calls may appear; check user-controlled input.",
    ),
    HuntingQuery(
        query_id="HUNT-007",
        name="SQL Injection in Web Logs",
        description="Detects SQL injection attack patterns in web access logs.",
        platform="splunk",
        query=(
            'index=web_logs | search (url="*UNION*SELECT*" OR '
            "url=\"*' OR '1'='1*\" OR url=\"*;DROP*\")"
        ),
        mitre_technique="T1190",
        severity="CRITICAL",
        tags=["sqli", "web", "initial-access"],
        hypothesis="Attacker is attempting SQL injection to extract database contents or bypass authentication.",
        false_positive_notes="Security scanners during pen-tests; correlate with login and error events.",
    ),
    HuntingQuery(
        query_id="HUNT-008",
        name="JWT Algorithm Confusion Attack",
        description="Detects JWT tokens using 'none' algorithm, indicative of algorithm confusion attack bypassing signature verification.",
        platform="splunk",
        query=(
            'index=app_logs | search token="eyJ*" '
            '| eval alg=json_extract(base64decode(split(token, ".")[0]), "alg") '
            '| search alg="none"'
        ),
        mitre_technique="T1550.001",
        severity="CRITICAL",
        tags=["jwt", "authentication", "bypass"],
        hypothesis="Attacker is crafting JWT tokens with alg:none to bypass signature validation.",
        false_positive_notes="Rarely a false positive; any alg:none in production is a finding.",
    ),
    HuntingQuery(
        query_id="HUNT-009",
        name="Path Traversal in URLs",
        description="Detects path traversal attack attempts using ../ sequences or URL-encoded equivalents.",
        platform="splunk",
        query='index=web_logs | search uri="*../*" OR uri="*%2e%2e%2f*"',
        mitre_technique="T1083",
        severity="HIGH",
        tags=["path-traversal", "web", "lfi"],
        hypothesis="Attacker is attempting to read files outside the web root using path traversal.",
        false_positive_notes="Some CDN redirect URLs contain ../ ; verify response status codes.",
    ),
    HuntingQuery(
        query_id="HUNT-010",
        name="Prototype Pollution / Mass Assignment Attack",
        description="Detects prototype pollution attempts via __proto__ or constructor in request bodies.",
        platform="splunk",
        query='index=app_logs | search body="*__proto__*" OR body="*constructor*"',
        mitre_technique="T1134",
        severity="HIGH",
        tags=["prototype-pollution", "mass-assignment", "web"],
        hypothesis="Attacker is attempting prototype pollution to escalate privileges or inject properties.",
        false_positive_notes="Serialized objects in legitimate APIs may contain 'constructor'; review in context.",
    ),
    # ── KQL (Microsoft Defender / Chronicle) queries ────────────────────────
    HuntingQuery(
        query_id="HUNT-011",
        name="Suspicious PowerShell Encoded Commands",
        description="Detects PowerShell invocations with encoded commands or IEX, used for fileless malware and LOLBins.",
        platform="kql",
        query=(
            'DeviceProcessEvents '
            '| where FileName == "powershell.exe" '
            '| where ProcessCommandLine contains "-EncodedCommand" '
            'or ProcessCommandLine contains "IEX"'
        ),
        mitre_technique="T1059.001",
        severity="HIGH",
        tags=["powershell", "execution", "lolbin"],
        hypothesis="Attacker is using encoded PowerShell to evade script-block logging.",
        false_positive_notes="SCCM and management tooling use encoded commands; check parent process.",
    ),
    HuntingQuery(
        query_id="HUNT-012",
        name="Lateral Movement via Network Logons",
        description="Detects accounts generating excessive network logons, indicative of lateral movement.",
        platform="kql",
        query=(
            "IdentityLogonEvents "
            '| where LogonType == "Network" '
            "| summarize count() by AccountName "
            "| where count_ > 50"
        ),
        mitre_technique="T1021",
        severity="HIGH",
        tags=["lateral-movement", "credential-use", "network"],
        hypothesis="Attacker is using valid credentials to move laterally across systems.",
        false_positive_notes="Service accounts performing scheduled tasks; review account purpose.",
    ),
    HuntingQuery(
        query_id="HUNT-013",
        name="Privilege Escalation Attempt",
        description="Detects privilege escalation attempts flagged by Microsoft Defender.",
        platform="kql",
        query='DeviceEvents | where ActionType == "PrivilegeEscalationAttempt"',
        mitre_technique="T1068",
        severity="CRITICAL",
        tags=["privilege-escalation", "exploit"],
        hypothesis="Attacker is exploiting a local vulnerability to gain elevated privileges.",
        false_positive_notes="Security testing tools; correlate with change window.",
    ),
    HuntingQuery(
        query_id="HUNT-014",
        name="Data Exfiltration via Web Clients",
        description="Detects data exfiltration attempts using curl, wget, or Python over HTTPS.",
        platform="kql",
        query=(
            "DeviceNetworkEvents "
            "| where RemotePort == 443 "
            '| where InitiatingProcessFileName in ("curl", "wget", "python")'
        ),
        mitre_technique="T1048.002",
        severity="HIGH",
        tags=["exfiltration", "network", "https"],
        hypothesis="Attacker is exfiltrating data over encrypted HTTPS to bypass DLP controls.",
        false_positive_notes="Update mechanisms and package managers use these tools; check destination.",
    ),
    HuntingQuery(
        query_id="HUNT-015",
        name="Persistence via Registry Run Keys",
        description="Detects persistence established by writing to Windows registry Run keys.",
        platform="kql",
        query=(
            "DeviceRegistryEvents "
            r'| where RegistryKey has @"CurrentVersion\Run"'
        ),
        mitre_technique="T1547.001",
        severity="HIGH",
        tags=["persistence", "registry", "windows"],
        hypothesis="Attacker is establishing persistence via registry autorun keys.",
        false_positive_notes="Legitimate software installers modify Run keys; check registry value content.",
    ),
    HuntingQuery(
        query_id="HUNT-016",
        name="C2 Beaconing Pattern Detection",
        description="Detects regular beaconing patterns by identifying hosts with high connection frequency to the same external IP.",
        platform="kql",
        query=(
            "DeviceNetworkEvents "
            "| summarize count(), dcount(RemoteIP) by DeviceName, bin(Timestamp, 1h) "
            "| where count_ > 100"
        ),
        mitre_technique="T1071.001",
        severity="CRITICAL",
        tags=["c2", "beaconing", "network"],
        hypothesis="Compromised endpoint is beaconing to C2 at regular intervals.",
        false_positive_notes="CDN-heavy applications generate high connection counts; check connection regularity.",
    ),
    HuntingQuery(
        query_id="HUNT-017",
        name="Credential Dumping via LSASS",
        description="Detects credential dumping tool execution including Mimikatz and LSASS memory access.",
        platform="kql",
        query=(
            "DeviceProcessEvents "
            '| where ProcessCommandLine has_any ("lsass", "mimikatz", "sekurlsa")'
        ),
        mitre_technique="T1003.001",
        severity="CRITICAL",
        tags=["credential-dumping", "lsass", "mimikatz"],
        hypothesis="Attacker is dumping credentials from LSASS memory for lateral movement.",
        false_positive_notes="EDR tools may access LSASS for monitoring; verify process origin.",
    ),
    HuntingQuery(
        query_id="HUNT-018",
        name="Container Escape via nsenter",
        description="Detects container escape attempts using nsenter from the container runtime process.",
        platform="kql",
        query=(
            "DeviceProcessEvents "
            '| where InitiatingProcessFileName == "runc" '
            '| where ProcessCommandLine contains "nsenter"'
        ),
        mitre_technique="T1611",
        severity="CRITICAL",
        tags=["container-escape", "kubernetes", "privilege-escalation"],
        hypothesis="Attacker inside a container is attempting to escape to the host via namespace manipulation.",
        false_positive_notes="Extremely rare false positives; any nsenter from runc is highly suspicious.",
    ),
    HuntingQuery(
        query_id="HUNT-019",
        name="Audit Log Cleared",
        description="Detects Windows Security audit log clearing (Event ID 1102), a common anti-forensics technique.",
        platform="kql",
        query="SecurityEvent | where EventID == 1102",
        mitre_technique="T1070.001",
        severity="CRITICAL",
        tags=["defense-evasion", "log-clearing", "anti-forensics"],
        hypothesis="Attacker is clearing audit logs to cover tracks after compromise.",
        false_positive_notes="Legitimate log rotation policies may generate this event; verify with change tickets.",
    ),
    HuntingQuery(
        query_id="HUNT-020",
        name="Suspicious npm Registry Access",
        description="Detects non-npm processes accessing the npm registry, possibly indicating supply chain attack or dependency confusion.",
        platform="kql",
        query=(
            "DeviceNetworkEvents "
            r'| where RemoteUrl matches regex @".*\.npmjs\.org.*" '
            '| where InitiatingProcessFileName != "npm"'
        ),
        mitre_technique="T1195.001",
        severity="HIGH",
        tags=["supply-chain", "npm", "dependency-confusion"],
        hypothesis="Malicious package or compromised process is communicating with npm registry.",
        false_positive_notes="Yarn, pnpm, and other package managers also access npmjs.org; check process legitimacy.",
    ),
    # ── Elastic/OpenSearch DSL queries ──────────────────────────────────────
    HuntingQuery(
        query_id="HUNT-021",
        name="Web Shell Upload via Elastic",
        description="Detects web shell file creation events on web-accessible directories using Elastic file integrity monitoring.",
        platform="elastic",
        query=(
            '{"query": {"bool": {"must": ['
            '{"term": {"event.category": "file"}}, '
            '{"wildcard": {"file.path": {"value": "*/www*"}}}, '
            '{"terms": {"file.extension": ["php", "jsp", "aspx", "ashx"]}},'
            '{"term": {"event.action": "creation"}}'
            ']}}}'
        ),
        mitre_technique="T1505.003",
        severity="CRITICAL",
        tags=["webshell", "file-creation", "persistence"],
        hypothesis="Attacker uploaded a web shell to the web root for persistent access.",
        false_positive_notes="Legitimate deployments; correlate with deployment events.",
    ),
    HuntingQuery(
        query_id="HUNT-022",
        name="Encoded Payload in Process Arguments",
        description="Detects base64 or hex-encoded payloads in process command-line arguments.",
        platform="elastic",
        query=(
            '{"query": {"bool": {"should": ['
            '{"regexp": {"process.args": ".*[A-Za-z0-9+/]{40,}={0,2}.*"}}, '
            '{"regexp": {"process.args": ".*\\\\x[0-9a-fA-F]{2}.*"}}'
            '], "minimum_should_match": 1}}}'
        ),
        mitre_technique="T1027",
        severity="HIGH",
        tags=["obfuscation", "encoded-payload", "execution"],
        hypothesis="Attacker is using encoded payloads to bypass command-line logging and EDR.",
        false_positive_notes="Certificates and keys in arguments may appear as base64; check process context.",
    ),
    HuntingQuery(
        query_id="HUNT-023",
        name="DNS Tunneling Detection",
        description="Detects DNS tunneling by identifying unusually long or high-entropy DNS query names.",
        platform="elastic",
        query=(
            '{"query": {"bool": {"must": ['
            '{"term": {"event.category": "network"}}, '
            '{"term": {"network.protocol": "dns"}},'
            '{"range": {"dns.question.name.length": {"gt": 50}}}'
            ']}}}'
        ),
        mitre_technique="T1071.004",
        severity="HIGH",
        tags=["dns-tunneling", "exfiltration", "c2"],
        hypothesis="Attacker is using DNS tunneling for C2 communication or data exfiltration.",
        false_positive_notes="CDNs with long subdomain names; check query frequency and entropy.",
    ),
    HuntingQuery(
        query_id="HUNT-024",
        name="Crypto Mining Process Detection",
        description="Detects known cryptocurrency mining processes (xmrig, minerd, cpuminer) on host systems.",
        platform="elastic",
        query=(
            '{"query": {"bool": {"should": ['
            '{"terms": {"process.name": ["xmrig", "minerd", "cpuminer", "ethminer", "cgminer", "bfgminer"]}}, '
            '{"regexp": {"process.args": ".*stratum\\\\+tcp.*"}}'
            '], "minimum_should_match": 1}}}'
        ),
        mitre_technique="T1496",
        severity="HIGH",
        tags=["cryptomining", "resource-hijacking"],
        hypothesis="Host has been compromised and is running cryptocurrency mining software.",
        false_positive_notes="Internal research or mining operations; verify business justification.",
    ),
    HuntingQuery(
        query_id="HUNT-025",
        name="Memory Injection via Process Hollowing",
        description="Detects process hollowing indicators by identifying suspended process creation followed by memory writes.",
        platform="elastic",
        query=(
            '{"query": {"bool": {"must": ['
            '{"term": {"event.category": "process"}}, '
            '{"term": {"process.parent.name": "explorer.exe"}},'
            '{"terms": {"event.action": ["process_hollowing", "virtual_alloc_remote", "write_process_memory"]}}'
            ']}}}'
        ),
        mitre_technique="T1055.012",
        severity="CRITICAL",
        tags=["process-injection", "defense-evasion", "memory"],
        hypothesis="Attacker is using process hollowing to inject malicious code into legitimate processes.",
        false_positive_notes="Security products use similar techniques; verify process ancestry.",
    ),
    HuntingQuery(
        query_id="HUNT-026",
        name="Unusual Child Process Spawning",
        description="Detects unusual child processes spawned from web server processes (Apache, IIS, nginx), indicative of web shell execution.",
        platform="elastic",
        query=(
            '{"query": {"bool": {"must": ['
            '{"terms": {"process.parent.name": ["apache2", "httpd", "nginx", "w3wp.exe", "tomcat"]}}, '
            '{"terms": {"process.name": ["cmd.exe", "powershell.exe", "sh", "bash", "python", "perl"]}}'
            ']}}}'
        ),
        mitre_technique="T1059",
        severity="CRITICAL",
        tags=["web-shell", "process-spawn", "execution"],
        hypothesis="Web server has spawned a shell process, indicating web shell execution.",
        false_positive_notes="CGI scripts may spawn shells legitimately; verify parent-child chain.",
    ),
    HuntingQuery(
        query_id="HUNT-027",
        name="Timestomping / File Time Modification",
        description="Detects file timestamp modification used to hide malware implants and evade forensic analysis.",
        platform="elastic",
        query=(
            '{"query": {"bool": {"must": ['
            '{"term": {"event.category": "file"}}, '
            '{"term": {"event.action": "attribute_change"}},'
            '{"exists": {"field": "file.mtime"}}'
            ']}}}'
        ),
        mitre_technique="T1070.006",
        severity="MEDIUM",
        tags=["timestomping", "anti-forensics", "defense-evasion"],
        hypothesis="Attacker is modifying file timestamps to hide malware implant creation time.",
        false_positive_notes="Backup and restore operations modify timestamps; check file path and process.",
    ),
    HuntingQuery(
        query_id="HUNT-028",
        name="DLL Hijacking Indicators",
        description="Detects DLL hijacking by identifying DLL loads from unusual paths (temp, user directories).",
        platform="elastic",
        query=(
            '{"query": {"bool": {"must": ['
            '{"term": {"event.category": "library"}}, '
            '{"bool": {"should": ['
            '{"wildcard": {"dll.path": "*/Temp/*"}}, '
            '{"wildcard": {"dll.path": "*/AppData/*"}}, '
            '{"wildcard": {"dll.path": "*/Downloads/*"}}'
            ']}}'
            ']}}}'
        ),
        mitre_technique="T1574.001",
        severity="HIGH",
        tags=["dll-hijacking", "persistence", "privilege-escalation"],
        hypothesis="Attacker is loading malicious DLL from user-writable path to hijack legitimate application.",
        false_positive_notes="Some legitimate apps load DLLs from AppData; correlate with process reputation.",
    ),
    HuntingQuery(
        query_id="HUNT-029",
        name="Scheduled Task Creation for Persistence",
        description="Detects scheduled task creation as a persistence mechanism.",
        platform="elastic",
        query=(
            '{"query": {"bool": {"should": ['
            '{"term": {"event.category": "process"}}, '
            '{"terms": {"process.name": ["schtasks.exe", "at.exe", "cron"]}}, '
            '{"regexp": {"process.args": ".*(create|add|register).*"}}'
            '], "minimum_should_match": 2}}}'
        ),
        mitre_technique="T1053.005",
        severity="MEDIUM",
        tags=["scheduled-task", "persistence", "execution"],
        hypothesis="Attacker is creating scheduled tasks for persistent code execution.",
        false_positive_notes="Legitimate software installers create scheduled tasks; check task action command.",
    ),
    HuntingQuery(
        query_id="HUNT-030",
        name="Unusual SUID/SGID Binary Execution",
        description="Detects execution of SUID/SGID binaries from unusual paths, potentially indicating privilege escalation via misconfigured permissions.",
        platform="elastic",
        query=(
            '{"query": {"bool": {"must": ['
            '{"term": {"event.category": "process"}}, '
            '{"term": {"process.is_setuid": true}}, '
            '{"bool": {"must_not": ['
            '{"terms": {"process.executable": '
            '["/usr/bin/sudo", "/usr/bin/passwd", "/bin/su", "/usr/bin/newgrp"]}}'
            ']}}'
            ']}}}'
        ),
        mitre_technique="T1548.001",
        severity="HIGH",
        tags=["suid", "privilege-escalation", "linux"],
        hypothesis="Attacker is exploiting misconfigured SUID binary to escalate privileges.",
        false_positive_notes="Custom SUID binaries for legitimate purposes; maintain allowlist of expected SUID binaries.",
    ),
]


# ---------------------------------------------------------------------------
# Static code pattern mapping for hunt_in_code
# ---------------------------------------------------------------------------

# Maps query_id → list of (pattern_description, compiled_regex) tuples.
# For a result to be returned, ALL patterns in the list must match.
_CODE_DETECTION_PATTERNS: Dict[str, List[Tuple[str, re.Pattern]]] = {
    "HUNT-001": [
        ("subprocess/os.system usage", re.compile(r"\b(subprocess|os\.system|os\.popen)\b")),
        ("pipe/redirect indicator", re.compile(r"(\|\s*nc\b|/dev/tcp|>&\s*/dev/)")),
    ],
    "HUNT-002": [
        ("base64 decode", re.compile(r"\b(base64\.b64decode|b64decode|base64_decode)\b")),
        ("code execution", re.compile(r"\b(exec|eval|compile|__import__)\s*\(")),
    ],
    "HUNT-003": [
        ("known C2 port", re.compile(r"\b(4444|1337|9001|31337|6666|5555)\b")),
        ("socket/connect", re.compile(r"\b(socket|connect|bind|listen)\b")),
    ],
    "HUNT-004": [
        ("high-volume auth", re.compile(r"\b(login|authenticate|auth)\b", re.IGNORECASE)),
        ("loop/counter", re.compile(r"\b(for|while|range|count|attempts)\b")),
    ],
    "HUNT-005": [
        ("file upload", re.compile(r"\b(upload|write|save|open)\b", re.IGNORECASE)),
        ("php/jsp web shell extension", re.compile(r"\.(php|jsp|aspx|ashx|phtml)\b", re.IGNORECASE)),
    ],
    "HUNT-006": [
        ("SSRF target", re.compile(r"(169\.254\.|127\.0\.|192\.168\.|10\.\d+\.\d+)")),
        ("HTTP request", re.compile(r"\b(requests\.|urllib|httpx|aiohttp|fetch)\b")),
    ],
    "HUNT-007": [
        ("SQL injection payload", re.compile(r"(?i)(union\s+select|select\s+\*|drop\s+table|1=1|' OR |;--)")),
    ],
    "HUNT-008": [
        ("JWT token", re.compile(r'(eyJ[A-Za-z0-9+/]+)')),
        ('none algorithm', re.compile(r'"alg"\s*:\s*"none"', re.IGNORECASE)),
    ],
    "HUNT-009": [
        ("path traversal", re.compile(r"(\.\.\/|%2e%2e%2f|\.\.\\\\)", re.IGNORECASE)),
    ],
    "HUNT-010": [
        ("prototype pollution", re.compile(r"(__proto__|constructor\s*\[|prototype\s*\[)")),
    ],
    "HUNT-011": [
        ("encoded command", re.compile(r"(-EncodedCommand|-enc\s+[A-Za-z0-9+/]|IEX\s*\(|Invoke-Expression)", re.IGNORECASE)),
        ("powershell", re.compile(r"(powershell|pwsh)", re.IGNORECASE)),
    ],
    "HUNT-017": [
        ("credential dumping tool", re.compile(r"\b(mimikatz|sekurlsa|lsass|procdump|wce\.exe)\b", re.IGNORECASE)),
    ],
    "HUNT-018": [
        ("container escape", re.compile(r"\b(nsenter|unshare|setns)\b")),
        ("namespace", re.compile(r"\b(--mount|--pid|--net|--ipc|--uts)\b")),
    ],
    "HUNT-024": [
        ("crypto miner", re.compile(r"\b(xmrig|minerd|cpuminer|ethminer|cgminer|stratum\+tcp)\b", re.IGNORECASE)),
    ],
    "HUNT-025": [
        ("process injection", re.compile(r"\b(VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|NtUnmapViewOfSection)\b", re.IGNORECASE)),
    ],
    "HUNT-028": [
        ("dll hijacking", re.compile(r"\b(LoadLibrary|LoadLibraryEx|DllMain)\b", re.IGNORECASE)),
        ("suspicious path", re.compile(r"(Temp\\\\|AppData\\\\|Downloads\\\\|%TEMP%)", re.IGNORECASE)),
    ],
    "HUNT-030": [
        ("suid execution", re.compile(r"\b(setuid|setgid|os\.setuid|os\.setgid|prctl)\b")),
    ],
}


# ---------------------------------------------------------------------------
# Threat Hunting Engine
# ---------------------------------------------------------------------------

class ThreatHuntingEngine:
    """Static analysis and query management for threat hunting."""

    def get_queries_for_technique(self, technique: str) -> List[HuntingQuery]:
        """Return queries matching the given ATT&CK technique (prefix match supported).

        E.g. "T1059" returns all T1059.* queries.
        """
        technique = technique.strip()
        return [
            q for q in HUNTING_QUERIES
            if q.mitre_technique == technique or q.mitre_technique.startswith(technique + ".")
        ]

    def hunt_in_code(self, source_code: str, filename: str) -> List[HuntingResult]:
        """Perform static analysis on source_code using hunting query patterns.

        Converts Splunk/KQL/Elastic query keywords into regex patterns and
        scans the source code for matches. Returns a HuntingResult for each
        query that produces at least one match.
        """
        if not source_code.strip():
            return []

        lines = source_code.splitlines()
        results: List[HuntingResult] = []

        for query in HUNTING_QUERIES:
            patterns = _CODE_DETECTION_PATTERNS.get(query.query_id)
            if not patterns:
                # Generate simple keyword patterns from query text
                patterns = self._derive_patterns_from_query(query)
                if not patterns:
                    continue

            # All patterns must match somewhere in the file
            all_matched = True
            matched_pattern_names: List[str] = []
            matched_lines_all: List[int] = []
            evidence_snippets: List[str] = []

            for pattern_name, regex in patterns:
                pattern_lines: List[int] = []
                for lineno, line in enumerate(lines, 1):
                    if regex.search(line):
                        pattern_lines.append(lineno)
                        evidence_snippets.append(f"L{lineno}: {line.strip()[:120]}")

                if pattern_lines:
                    matched_pattern_names.append(pattern_name)
                    matched_lines_all.extend(pattern_lines)
                else:
                    all_matched = False
                    break

            if not all_matched:
                continue

            # Deduplicate line numbers
            unique_lines = sorted(set(matched_lines_all))
            # Deduplicate evidence (preserve order)
            seen: set = set()
            unique_evidence: List[str] = []
            for ev in evidence_snippets:
                if ev not in seen:
                    seen.add(ev)
                    unique_evidence.append(ev)

            # Confidence based on number of pattern matches and match density
            match_density = len(unique_lines) / max(len(lines), 1)
            base_confidence = 0.6
            density_boost = min(0.3, match_density * 10)
            confidence = round(min(0.95, base_confidence + density_boost), 3)

            results.append(HuntingResult(
                query=query,
                matched_patterns=matched_pattern_names,
                matched_lines=unique_lines[:50],  # cap at 50
                confidence=confidence,
                evidence=unique_evidence[:20],     # cap at 20
            ))

        return results

    def _derive_patterns_from_query(
        self, query: HuntingQuery
    ) -> List[Tuple[str, re.Pattern]]:
        """Derive simple keyword patterns from the query text as a fallback."""
        # Extract quoted strings from query text as keywords
        keywords = re.findall(r'"([^"]{3,30})"', query.query)
        # Filter to those that look like code/log patterns
        code_keywords = [k for k in keywords if re.search(r"[a-z_\.\*]", k, re.IGNORECASE)]
        if not code_keywords:
            return []
        # Use first keyword only to avoid overly restrictive matching
        kw = re.escape(code_keywords[0])
        try:
            return [(code_keywords[0], re.compile(kw, re.IGNORECASE))]
        except re.error:
            return []

    def generate_threat_brief(self, results: List[HuntingResult]) -> str:
        """Generate a Markdown threat brief grouped by MITRE ATT&CK technique."""
        if not results:
            return "# Threat Hunting Brief\n\nNo threats detected.\n"

        # Group by technique
        by_technique: Dict[str, List[HuntingResult]] = defaultdict(list)
        for r in results:
            by_technique[r.query.mitre_technique].append(r)

        lines: List[str] = [
            "# Threat Hunting Brief",
            "",
            f"**Total findings:** {len(results)}",
            f"**Techniques covered:** {len(by_technique)}",
            "",
            "---",
            "",
        ]

        for technique in sorted(by_technique.keys()):
            technique_results = by_technique[technique]
            lines.append(f"## MITRE ATT&CK Technique: {technique}")
            lines.append("")

            for res in technique_results:
                severity_badge = f"[{res.query.severity}]"
                lines.append(f"### {res.query.query_id} — {res.query.name} {severity_badge}")
                lines.append("")
                lines.append(f"**Platform:** `{res.query.platform}`")
                lines.append(f"**Confidence:** {res.confidence:.0%}")
                lines.append(f"**Hypothesis:** {res.query.hypothesis or res.query.description}")
                lines.append("")
                if res.matched_patterns:
                    lines.append("**Matched patterns:**")
                    for p in res.matched_patterns:
                        lines.append(f"- {p}")
                    lines.append("")
                if res.matched_lines:
                    lines.append(f"**Matched lines:** {', '.join(str(ln) for ln in res.matched_lines[:10])}")
                    lines.append("")
                if res.evidence:
                    lines.append("**Evidence:**")
                    lines.append("```")
                    for ev in res.evidence[:5]:
                        lines.append(ev)
                    lines.append("```")
                    lines.append("")
                if res.query.false_positive_notes:
                    lines.append(f"**False positive notes:** {res.query.false_positive_notes}")
                    lines.append("")
                lines.append("---")
                lines.append("")

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def hunt_code_threats(source_code: str, filename: str) -> List[HuntingResult]:
    """Scan source code for threat patterns using all hunting queries."""
    return ThreatHuntingEngine().hunt_in_code(source_code, filename)


def get_hunting_queries(platform: Optional[str] = None) -> List[HuntingQuery]:
    """Return hunting queries, optionally filtered by platform."""
    if platform:
        return [q for q in HUNTING_QUERIES if q.platform == platform]
    return HUNTING_QUERIES
