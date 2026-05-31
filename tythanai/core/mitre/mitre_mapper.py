"""
TythanAI Platform — MITRE ATT&CK Mapper

Maps security findings to MITRE ATT&CK techniques across three matrices:
  • Enterprise (https://attack.mitre.org/matrices/enterprise/)
  • ICS         (https://attack.mitre.org/matrices/ics/)
  • Mobile      (https://attack.mitre.org/matrices/mobile/)

Enrichment adds the following fields to each finding:
  technique_id     — e.g. "T1190"
  technique_name   — human-readable name
  tactic           — e.g. "Initial Access"
  tactic_id        — e.g. "TA0001"
  kill_chain_phase — lowercased kebab form used in STIX kill-chain
  mitre_url        — direct link to the technique page
  matrix           — "enterprise" | "ics" | "mobile"

Usage:
    from core.mitre.mitre_mapper import MITREMapper

    mapper   = MITREMapper()
    findings = mapper.enrich(findings)
    print(mapper.report(findings))
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional


# ══════════════════════════════════════════════════════════════════════════════
# TECHNIQUE CATALOGUE
# Each entry: technique_id, name, tactic, tactic_id, matrix
# ══════════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class Technique:
    technique_id:     str
    name:             str
    tactic:           str
    tactic_id:        str
    matrix:           str = "enterprise"

    @property
    def kill_chain_phase(self) -> str:
        return self.tactic.lower().replace(" ", "-")

    @property
    def mitre_url(self) -> str:
        base = {
            "enterprise": "https://attack.mitre.org/techniques/",
            "ics":        "https://attack.mitre.org/techniques/",
            "mobile":     "https://attack.mitre.org/techniques/",
        }[self.matrix]
        return f"{base}{self.technique_id}/"

    def to_dict(self) -> dict:
        return {
            "technique_id":     self.technique_id,
            "technique_name":   self.name,
            "tactic":           self.tactic,
            "tactic_id":        self.tactic_id,
            "kill_chain_phase": self.kill_chain_phase,
            "mitre_url":        self.mitre_url,
            "matrix":           self.matrix,
        }


# ── Technique registry ────────────────────────────────────────────────────────

_TECHNIQUES: Dict[str, Technique] = {}


def _t(tid: str, name: str, tactic: str, tactic_id: str, matrix: str = "enterprise") -> Technique:
    tech = Technique(tid, name, tactic, tactic_id, matrix)
    _TECHNIQUES[tid] = tech
    return tech


# Enterprise — Initial Access
T1190 = _t("T1190", "Exploit Public-Facing Application",   "Initial Access",       "TA0001")
T1133 = _t("T1133", "External Remote Services",            "Initial Access",       "TA0001")
T1078 = _t("T1078", "Valid Accounts",                      "Initial Access",       "TA0001")
T1566 = _t("T1566", "Phishing",                            "Initial Access",       "TA0001")
T1195 = _t("T1195", "Supply Chain Compromise",             "Initial Access",       "TA0001")
T1189 = _t("T1189", "Drive-by Compromise",                 "Initial Access",       "TA0001")

# Enterprise — Execution
T1059 = _t("T1059", "Command and Scripting Interpreter",   "Execution",            "TA0002")
T1203 = _t("T1203", "Exploitation for Client Execution",   "Execution",            "TA0002")
T1072 = _t("T1072", "Software Deployment Tools",           "Execution",            "TA0002")
T1569 = _t("T1569", "System Services",                     "Execution",            "TA0002")

# Enterprise — Persistence
T1546 = _t("T1546", "Event Triggered Execution",           "Persistence",          "TA0003")
T1543 = _t("T1543", "Create or Modify System Process",     "Persistence",          "TA0003")
T1574 = _t("T1574", "Hijack Execution Flow",               "Persistence",          "TA0003")

# Enterprise — Privilege Escalation
T1068 = _t("T1068", "Exploitation for Privilege Escalation","Privilege Escalation","TA0004")
T1548 = _t("T1548", "Abuse Elevation Control Mechanism",   "Privilege Escalation", "TA0004")
T1134 = _t("T1134", "Access Token Manipulation",           "Privilege Escalation", "TA0004")

# Enterprise — Defense Evasion
T1027 = _t("T1027", "Obfuscated Files or Information",     "Defense Evasion",      "TA0005")
T1562 = _t("T1562", "Impair Defenses",                     "Defense Evasion",      "TA0005")
T1070 = _t("T1070", "Indicator Removal",                   "Defense Evasion",      "TA0005")
T1036 = _t("T1036", "Masquerading",                        "Defense Evasion",      "TA0005")

# Enterprise — Credential Access
T1552 = _t("T1552", "Unsecured Credentials",               "Credential Access",    "TA0006")
T1555 = _t("T1555", "Credentials from Password Stores",    "Credential Access",    "TA0006")
T1110 = _t("T1110", "Brute Force",                         "Credential Access",    "TA0006")
T1212 = _t("T1212", "Exploitation for Credential Access",  "Credential Access",    "TA0006")
T1539 = _t("T1539", "Steal Web Session Cookie",            "Credential Access",    "TA0006")
T1606 = _t("T1606", "Forge Web Credentials",               "Credential Access",    "TA0006")

# Enterprise — Discovery
T1082 = _t("T1082", "System Information Discovery",        "Discovery",            "TA0007")
T1083 = _t("T1083", "File and Directory Discovery",        "Discovery",            "TA0007")
T1046 = _t("T1046", "Network Service Discovery",           "Discovery",            "TA0007")
T1057 = _t("T1057", "Process Discovery",                   "Discovery",            "TA0007")

# Enterprise — Lateral Movement
T1210 = _t("T1210", "Exploitation of Remote Services",     "Lateral Movement",     "TA0008")
T1550 = _t("T1550", "Use Alternate Authentication Material","Lateral Movement",    "TA0008")

# Enterprise — Collection
T1005 = _t("T1005", "Data from Local System",              "Collection",           "TA0009")
T1213 = _t("T1213", "Data from Information Repositories",  "Collection",           "TA0009")
T1530 = _t("T1530", "Data from Cloud Storage",             "Collection",           "TA0009")

# Enterprise — Exfiltration
T1041 = _t("T1041", "Exfiltration Over C2 Channel",        "Exfiltration",         "TA0010")
T1048 = _t("T1048", "Exfiltration Over Alternative Protocol","Exfiltration",       "TA0010")

# Enterprise — Impact
T1499 = _t("T1499", "Endpoint Denial of Service",          "Impact",               "TA0040")
T1496 = _t("T1496", "Resource Hijacking",                  "Impact",               "TA0040")
T1485 = _t("T1485", "Data Destruction",                    "Impact",               "TA0040")
T1486 = _t("T1486", "Data Encrypted for Impact",           "Impact",               "TA0040")
T1565 = _t("T1565", "Data Manipulation",                   "Impact",               "TA0040")

# Enterprise — Command and Control
T1071 = _t("T1071", "Application Layer Protocol",          "Command and Control",  "TA0011")
T1090 = _t("T1090", "Proxy",                               "Command and Control",  "TA0011")

# ICS techniques
T0817 = _t("T0817", "Drive-by Compromise",                 "Initial Access",       "TA0108", "ics")
T0816 = _t("T0816", "Device Restart/Shutdown",             "Inhibit Response Function","TA0107", "ics")
T0831 = _t("T0831", "Manipulation of Control",             "Impair Process Control","TA0106", "ics")

# Mobile techniques
MT1417 = _t("T1417", "Input Capture",                      "Collection",           "TA0035", "mobile")
MT1404 = _t("T1404", "Exploit OS Vulnerability",           "Privilege Escalation", "TA0029", "mobile")


# ══════════════════════════════════════════════════════════════════════════════
# CWE → ATT&CK TECHNIQUE MAPPINGS (50+ entries)
# Format: "CWE-NNN" → technique_id
# ══════════════════════════════════════════════════════════════════════════════

_CWE_TO_TECHNIQUE: Dict[str, str] = {
    # Injection
    "CWE-89":   "T1190",   # SQL Injection → Exploit Public-Facing Application
    "CWE-78":   "T1059",   # OS Command Injection → Command and Scripting Interpreter
    "CWE-77":   "T1059",   # Command Injection (general)
    "CWE-79":   "T1189",   # XSS → Drive-by Compromise
    "CWE-94":   "T1059",   # Code Injection → Command and Scripting Interpreter
    "CWE-917":  "T1059",   # Expression Language Injection
    "CWE-1336": "T1059",   # Template Injection
    "CWE-643":  "T1190",   # XPath Injection
    "CWE-90":   "T1190",   # LDAP Injection
    "CWE-91":   "T1190",   # XML Injection
    "CWE-918":  "T1190",   # SSRF → Exploit Public-Facing Application

    # Authentication & Credentials
    "CWE-287":  "T1078",   # Improper Authentication → Valid Accounts
    "CWE-306":  "T1078",   # Missing Authentication
    "CWE-307":  "T1110",   # Improper Restriction of Auth Attempts → Brute Force
    "CWE-308":  "T1078",   # Use of Single-Factor Auth
    "CWE-798":  "T1552",   # Hardcoded Credentials → Unsecured Credentials
    "CWE-259":  "T1552",   # Hardcoded Password
    "CWE-321":  "T1552",   # Hardcoded Cryptographic Key
    "CWE-522":  "T1552",   # Insufficiently Protected Credentials
    "CWE-256":  "T1552",   # Plaintext Storage of Password
    "CWE-312":  "T1552",   # Cleartext Storage of Sensitive Info
    "CWE-315":  "T1539",   # Cleartext Storage in Cookie → Steal Web Session Cookie
    "CWE-614":  "T1539",   # Sensitive Cookie Without Secure Flag

    # Access Control / Authorization
    "CWE-284":  "T1068",   # Improper Access Control → Exploitation for Privilege Escalation
    "CWE-285":  "T1548",   # Improper Authorization → Abuse Elevation Control
    "CWE-269":  "T1548",   # Improper Privilege Management
    "CWE-250":  "T1548",   # Execution with Unnecessary Privileges
    "CWE-266":  "T1548",   # Incorrect Privilege Assignment
    "CWE-862":  "T1548",   # Missing Authorization
    "CWE-863":  "T1548",   # Incorrect Authorization
    "CWE-732":  "T1083",   # Incorrect Permission Assignment → File and Directory Discovery

    # Cryptographic Failures
    "CWE-327":  "T1486",   # Use of Broken Crypto → Data Encrypted for Impact
    "CWE-326":  "T1486",   # Inadequate Encryption Strength
    "CWE-330":  "T1606",   # Use of Insufficiently Random Values → Forge Web Credentials
    "CWE-331":  "T1606",   # Insufficient Entropy
    "CWE-338":  "T1606",   # Use of Cryptographically Weak PRNG
    "CWE-347":  "T1606",   # Improper Verification of Cryptographic Signature

    # Path Traversal & File Issues
    "CWE-22":   "T1083",   # Path Traversal → File and Directory Discovery
    "CWE-23":   "T1083",   # Relative Path Traversal
    "CWE-36":   "T1083",   # Absolute Path Traversal
    "CWE-73":   "T1005",   # External Control of File Name → Data from Local System

    # Supply Chain
    "CWE-1035": "T1195",   # Using Vulnerable Third-Party Component → Supply Chain Compromise
    "CWE-1104": "T1195",   # Use of Unmaintained Third Party Components
    "CWE-494":  "T1195",   # Download of Code Without Integrity Check

    # Logging & Monitoring
    "CWE-778":  "T1070",   # Insufficient Logging → Indicator Removal
    "CWE-117":  "T1070",   # Improper Output Neutralization for Logs
    "CWE-223":  "T1070",   # Omission of Security-relevant Information

    # Memory Safety
    "CWE-120":  "T1203",   # Buffer Copy without Checking Size → Exploitation for Client Execution
    "CWE-122":  "T1203",   # Heap-based Buffer Overflow
    "CWE-125":  "T1005",   # Out-of-bounds Read → Data from Local System
    "CWE-190":  "T1499",   # Integer Overflow → Denial of Service
    "CWE-416":  "T1203",   # Use After Free
    "CWE-476":  "T1499",   # NULL Pointer Dereference

    # Resource & DoS
    "CWE-400":  "T1499",   # Uncontrolled Resource Consumption → Denial of Service
    "CWE-770":  "T1499",   # Allocation Without Limits
    "CWE-664":  "T1499",   # Improper Control of Resource Lifetime

    # Information Disclosure
    "CWE-200":  "T1082",   # Exposure of Sensitive Information → System Information Discovery
    "CWE-209":  "T1082",   # Generation of Error Message with Sensitive Info
    "CWE-213":  "T1082",   # Exposure of Sensitive Info Due to Incompatible Policies
    "CWE-532":  "T1552",   # Insertion of Sensitive Info into Log File

    # Serialization
    "CWE-502":  "T1059",   # Deserialization of Untrusted Data → Command Execution
    "CWE-915":  "T1565",   # Improperly Controlled Modification → Data Manipulation

    # Configuration
    "CWE-16":   "T1562",   # Configuration → Impair Defenses
    "CWE-311":  "T1486",   # Missing Encryption of Sensitive Data
    "CWE-319":  "T1048",   # Cleartext Transmission → Exfiltration Over Alt Protocol
    "CWE-295":  "T1550",   # Improper Certificate Validation → Use Alternate Auth Material
}


# ══════════════════════════════════════════════════════════════════════════════
# OWASP CATEGORY → ATT&CK TECHNIQUE MAPPINGS
# ══════════════════════════════════════════════════════════════════════════════

_OWASP_TO_TECHNIQUE: Dict[str, str] = {
    # OWASP Top 10 2021
    "A01:2021": "T1548",   # Broken Access Control
    "A02:2021": "T1486",   # Cryptographic Failures
    "A03:2021": "T1190",   # Injection
    "A04:2021": "T1190",   # Insecure Design
    "A05:2021": "T1562",   # Security Misconfiguration
    "A06:2021": "T1195",   # Vulnerable and Outdated Components
    "A07:2021": "T1078",   # Identification and Authentication Failures
    "A08:2021": "T1565",   # Software and Data Integrity Failures
    "A09:2021": "T1070",   # Security Logging and Monitoring Failures
    "A10:2021": "T1190",   # Server-Side Request Forgery

    # OWASP Top 10 2017 (legacy rules may reference these)
    "A1:2017":  "T1190",   # Injection
    "A2:2017":  "T1078",   # Broken Authentication
    "A3:2017":  "T1552",   # Sensitive Data Exposure
    "A4:2017":  "T1190",   # XXE
    "A5:2017":  "T1548",   # Broken Access Control
    "A6:2017":  "T1562",   # Security Misconfiguration
    "A7:2017":  "T1189",   # XSS
    "A8:2017":  "T1059",   # Insecure Deserialization
    "A9:2017":  "T1195",   # Using Components with Known Vulnerabilities
    "A10:2017": "T1070",   # Insufficient Logging & Monitoring

    # OWASP Mobile Top 10
    "M1:2016":  "T1552",   # Improper Platform Usage
    "M2:2016":  "T1552",   # Insecure Data Storage
    "M3:2016":  "T1048",   # Insecure Communication
    "M4:2016":  "T1078",   # Insecure Authentication
    "M5:2016":  "T1486",   # Insufficient Cryptography

    # OWASP Smart Contract Top 10
    "SC01":     "T1190",   # Reentrancy
    "SC02":     "T1548",   # Integer Overflow
    "SC03":     "T1552",   # Timestamp Dependence
    "SC04":     "T1548",   # Access Control Issues
    "SC05":     "T1059",   # Front-Running
}


# ══════════════════════════════════════════════════════════════════════════════
# RULE ID PATTERN → ATT&CK TECHNIQUE MAPPINGS
# Covers TythanAI internal rule namespaces
# ══════════════════════════════════════════════════════════════════════════════

_RULE_PATTERNS: List[tuple] = [
    # Pattern (regex)                  → technique_id
    (r"GHOST-EVM-REEN",                "T1190"),   # EVM Reentrancy
    (r"GHOST-EVM-INT",                 "T1499"),   # EVM Integer Issues → DoS
    (r"GHOST-EVM-ACCESS",              "T1548"),   # EVM Access Control
    (r"GHOST-EVM-PRIV",                "T1548"),   # EVM Privilege
    (r"GHOST-EVM-RAND",                "T1606"),   # EVM Randomness → Forge Credentials
    (r"GHOST-EVM-FLASH",               "T1565"),   # EVM Flash Loan → Data Manipulation
    (r"GHOST-EVM-DELEG",               "T1574"),   # EVM Delegatecall → Hijack Execution
    (r"GHOST-EVM-SELFD",               "T1485"),   # EVM Selfdestruct → Data Destruction
    (r"GHOST-EVM-",                    "T1190"),   # EVM general
    (r"TON-FUND|TON-DRAIN",            "T1565"),   # TON Fund Drain → Data Manipulation
    (r"TON-REPLAY",                    "T1606"),   # TON Replay → Forge Credentials
    (r"TON-UPG",                       "T1574"),   # TON Upgrade → Hijack Execution Flow
    (r"TON-AC|TON-GAS",                "T1548"),   # TON Access Control
    (r"TON-",                          "T1190"),   # TON general
    (r"GHOST-PY-SQL|GHOST-JS-SQL",     "T1190"),   # SQL Injection
    (r"GHOST-PY-CMD|GHOST-JS-CMD",     "T1059"),   # Command Injection
    (r"GHOST-PY-XSS|GHOST-JS-XSS",    "T1189"),   # XSS
    (r"GHOST-PY-SSRF|GHOST-JS-SSRF",  "T1190"),   # SSRF
    (r"GHOST-PY-SECRET|GHOST-JS-SECRET","T1552"),  # Secrets in code
    (r"GHOST-PY-PATH|GHOST-JS-PATH",   "T1083"),   # Path traversal
    (r"GHOST-PY-DESER|GHOST-JS-DESER", "T1059"),   # Deserialization
    (r"GHOST-PY-CRYPTO|GHOST-JS-CRYPTO","T1486"),  # Weak crypto
    (r"GHOST-PY-HASH",                 "T1606"),   # Weak hash
    (r"GHOST-PY-",                     "T1190"),   # Python general
    (r"GHOST-JS-",                     "T1190"),   # JS general
    (r"K8S-POD-PRIV",                  "T1548"),   # K8s privileged container
    (r"K8S-RBAC",                      "T1548"),   # K8s RBAC escalation
    (r"K8S-SECRET",                    "T1552"),   # K8s secrets
    (r"K8S-NET",                       "T1046"),   # K8s network exposure
    (r"K8S-",                          "T1562"),   # K8s misconfiguration
    (r"DOCKER-ROOT|DOCKER-PRIV",       "T1548"),   # Docker privilege escalation
    (r"DOCKER-",                       "T1562"),   # Docker misconfiguration
    (r"TF-|CDK-|PULUMI-",             "T1562"),   # IaC misconfiguration
    (r"SBOM-VULN|SBOM-CVE",           "T1195"),   # Supply chain vulnerability
    (r"SBOM-",                         "T1195"),   # Supply chain general
    (r"SECRET-|CRED-|API-KEY",         "T1552"),   # Secret/credential exposure
    (r"HARDCODED",                     "T1552"),   # Hardcoded credentials
    (r"SQLI|SQL_INJ",                  "T1190"),   # SQL injection (alt naming)
    (r"CMDI|CMD_INJ|OS_CMD",           "T1059"),   # Command injection (alt naming)
    (r"XSS|CROSS.SITE",                "T1189"),   # XSS (alt naming)
    (r"PATH.TRAV",                     "T1083"),   # Path traversal (alt naming)
    (r"SSRF|SERVER.SIDE.REQ",          "T1190"),   # SSRF (alt naming)
    (r"REPLAY",                        "T1606"),   # Replay attacks
    (r"PRIVESC|PRIV.ESC",              "T1548"),   # Privilege escalation
    (r"RCE|REMOTE.CODE",               "T1059"),   # Remote code execution
    (r"LOG.INJECT|LOG.FORGE",          "T1070"),   # Log injection
    (r"WEAK.RAND|INSEC.RAND",          "T1606"),   # Weak randomness
    (r"RESOURCE.EXHAUST|UNBOUND",      "T1499"),   # Resource exhaustion / DoS
    (r"DELEG|DELEGATE",                "T1574"),   # Delegatecall / Hijack
]


# ══════════════════════════════════════════════════════════════════════════════
# MAPPER CLASS
# ══════════════════════════════════════════════════════════════════════════════

class MITREMapper:
    """
    Enriches TythanAI findings with MITRE ATT&CK context.

    Resolution order (first match wins):
      1. rule_id   pattern match
      2. CWE       exact match
      3. OWASP     prefix match
      4. keyword   heuristic on message/type fields
    """

    _FALLBACK_TECHNIQUE = "T1190"   # Exploit Public-Facing Application

    # Keywords in finding message/type → technique
    _KEYWORD_MAP: Dict[str, str] = {
        "sql":          "T1190",
        "injection":    "T1190",
        "xss":          "T1189",
        "ssrf":         "T1190",
        "command":      "T1059",
        "shell":        "T1059",
        "exec":         "T1059",
        "rce":          "T1059",
        "secret":       "T1552",
        "credential":   "T1552",
        "hardcoded":    "T1552",
        "api_key":      "T1552",
        "password":     "T1552",
        "token":        "T1539",
        "cookie":       "T1539",
        "session":      "T1539",
        "overflow":     "T1499",
        "dos":          "T1499",
        "denial":       "T1499",
        "resource":     "T1499",
        "path":         "T1083",
        "traversal":    "T1083",
        "directory":    "T1083",
        "crypto":       "T1486",
        "encrypt":      "T1486",
        "cipher":       "T1486",
        "hash":         "T1606",
        "random":       "T1606",
        "entropy":      "T1606",
        "privilege":    "T1548",
        "escalat":      "T1548",
        "access":       "T1548",
        "permission":   "T1548",
        "supply":       "T1195",
        "dependency":   "T1195",
        "vulnerable":   "T1195",
        "log":          "T1070",
        "audit":        "T1070",
        "deleg":        "T1574",
        "hijack":       "T1574",
        "replay":       "T1606",
        "reentrancy":   "T1190",
        "selfdestruct": "T1485",
        "destroy":      "T1485",
        "drain":        "T1565",
        "manipulat":    "T1565",
        "deseri":       "T1059",
        "unsafe":       "T1203",
    }

    # ── Public API ─────────────────────────────────────────────────────────────

    def enrich(self, findings: List[dict]) -> List[dict]:
        """
        Enrich each finding dict in-place with MITRE ATT&CK fields.

        Added keys:
            technique_id, technique_name, tactic, tactic_id,
            kill_chain_phase, mitre_url, matrix
        """
        for finding in findings:
            tech = self._resolve(finding)
            finding.update(tech.to_dict())
        return findings

    def map_cwe(self, cwe_str: str) -> dict:
        """
        Resolve a CWE identifier to a MITRE ATT&CK technique dict.

        Accepts both "CWE-89" and "89" formats.
        Returns empty dict if no mapping found.
        """
        if not cwe_str:
            return {}
        normalised = self._normalise_cwe(cwe_str)
        tid = _CWE_TO_TECHNIQUE.get(normalised)
        if not tid:
            return {}
        tech = _TECHNIQUES.get(tid)
        return tech.to_dict() if tech else {}

    def map_rule(self, rule_id: str) -> dict:
        """
        Resolve a TythanAI rule_id to a MITRE ATT&CK technique dict.

        Iterates compiled patterns and returns the first match.
        Returns empty dict if no pattern matches.
        """
        if not rule_id:
            return {}
        for pattern, tid in _RULE_PATTERNS:
            if re.search(pattern, rule_id, re.IGNORECASE):
                tech = _TECHNIQUES.get(tid)
                if tech:
                    return tech.to_dict()
        return {}

    def report(self, findings: List[dict]) -> str:
        """
        Generate a Markdown MITRE ATT&CK coverage report from enriched findings.

        The report includes:
          - Summary table by tactic
          - Top techniques by frequency
          - Per-finding technique listing
        """
        if not findings:
            return "# MITRE ATT&CK Report\n\nNo findings to report.\n"

        enriched = [f for f in findings if f.get("technique_id")]
        if not enriched:
            enriched = self.enrich([dict(f) for f in findings])

        # Aggregate by tactic
        tactic_counts: Dict[str, int] = {}
        technique_counts: Dict[str, Dict] = {}

        for f in enriched:
            tactic = f.get("tactic", "Unknown")
            tid    = f.get("technique_id", "?")
            tname  = f.get("technique_name", "?")
            tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1
            if tid not in technique_counts:
                technique_counts[tid] = {
                    "name":    tname,
                    "tactic":  tactic,
                    "url":     f.get("mitre_url", ""),
                    "count":   0,
                    "severities": [],
                }
            technique_counts[tid]["count"] += 1
            sev = f.get("severity", "MEDIUM")
            technique_counts[tid]["severities"].append(sev)

        _sev_weight = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        top_techniques = sorted(
            technique_counts.items(),
            key=lambda kv: (-kv[1]["count"], -_sev_weight.get(
                max(kv[1]["severities"], key=lambda s: _sev_weight.get(s, 0), default="INFO"), 0
            )),
        )

        lines: List[str] = ["# MITRE ATT&CK Report\n"]
        lines.append(f"> **Total Findings:** {len(enriched)}  ")
        lines.append(f"> **Techniques Covered:** {len(technique_counts)}  ")
        lines.append(f"> **Tactics Covered:** {len(tactic_counts)}\n")

        # Tactic summary table
        lines.append("## Tactic Coverage\n")
        lines.append("| Tactic | Findings |")
        lines.append("|--------|----------|")
        for tactic, count in sorted(tactic_counts.items(), key=lambda x: -x[1]):
            lines.append(f"| {tactic} | {count} |")
        lines.append("")

        # Top techniques
        lines.append("## Top Techniques\n")
        lines.append("| Technique | Name | Tactic | Count | Link |")
        lines.append("|-----------|------|--------|-------|------|")
        for tid, info in top_techniques[:20]:
            url = info["url"]
            lines.append(
                f"| `{tid}` | {info['name']} | {info['tactic']} | {info['count']} "
                f"| [MITRE]({url}) |"
            )
        lines.append("")

        # Per-finding detail
        lines.append("## Findings Detail\n")
        lines.append("| Severity | Rule | Technique | Tactic | File |")
        lines.append("|----------|------|-----------|--------|------|")
        for f in sorted(enriched,
                        key=lambda x: -_sev_weight.get(x.get("severity", "MEDIUM"), 2)):
            sev    = f.get("severity", "?")
            rule   = f.get("rule_id", f.get("id", "?"))
            tid    = f.get("technique_id", "?")
            tactic = f.get("tactic", "?")
            fname  = f.get("file", "?")
            line   = f.get("line", "")
            loc    = f"{fname}:{line}" if line else fname
            lines.append(f"| {sev} | `{rule}` | `{tid}` | {tactic} | `{loc}` |")

        return "\n".join(lines) + "\n"

    # ── Internal helpers ───────────────────────────────────────────────────────

    def _resolve(self, finding: dict) -> Technique:
        """Resolve the best-matching MITRE technique for a finding."""
        # 1. rule_id pattern
        rule_id = finding.get("rule_id", "")
        if rule_id:
            for pattern, tid in _RULE_PATTERNS:
                if re.search(pattern, rule_id, re.IGNORECASE):
                    tech = _TECHNIQUES.get(tid)
                    if tech:
                        return tech

        # 2. CWE exact match
        cwe = finding.get("cwe", "")
        if cwe:
            normalised = self._normalise_cwe(cwe)
            tid = _CWE_TO_TECHNIQUE.get(normalised)
            if tid:
                tech = _TECHNIQUES.get(tid)
                if tech:
                    return tech

        # 3. OWASP prefix match
        owasp = finding.get("owasp", "")
        if owasp:
            # Try exact, then prefix (e.g. "A03:2021-Injection" → "A03:2021")
            tid = _OWASP_TO_TECHNIQUE.get(owasp)
            if not tid:
                for key, val in _OWASP_TO_TECHNIQUE.items():
                    if owasp.startswith(key):
                        tid = val
                        break
            if tid:
                tech = _TECHNIQUES.get(tid)
                if tech:
                    return tech

        # 4. Keyword heuristic on message + type + tags
        text = " ".join([
            str(finding.get("message", "")),
            str(finding.get("description", "")),
            str(finding.get("type", "")),
            " ".join(finding.get("tags", [])),
        ]).lower()

        for keyword, tid in self._KEYWORD_MAP.items():
            if keyword in text:
                tech = _TECHNIQUES.get(tid)
                if tech:
                    return tech

        # 5. Fallback
        return _TECHNIQUES[self._FALLBACK_TECHNIQUE]

    @staticmethod
    def _normalise_cwe(cwe_str: str) -> str:
        """Normalise CWE input to 'CWE-NNN' format."""
        cwe_str = str(cwe_str).strip()
        if re.match(r"^\d+$", cwe_str):
            return f"CWE-{cwe_str}"
        if re.match(r"^CWE-\d+$", cwe_str, re.IGNORECASE):
            return cwe_str.upper()
        # Handle "CWE-89: SQL Injection" style
        m = re.match(r"^(CWE-\d+)", cwe_str, re.IGNORECASE)
        if m:
            return m.group(1).upper()
        return cwe_str
