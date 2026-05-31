"""Compliance Mapper — maps findings to MITRE ATT&CK, NIST CSF 2.0, D3FEND, OWASP Top 10."""

from __future__ import annotations

import json
import pathlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Resolve Finding import — works whether run in-tree or as standalone
# ---------------------------------------------------------------------------
try:
    from backend.core.confidence import Finding
except ModuleNotFoundError:
    import importlib.util

    _root = pathlib.Path(__file__).resolve().parents[2]
    _spec = importlib.util.spec_from_file_location(
        "confidence", _root / "backend" / "core" / "confidence.py"
    )
    _mod = importlib.util.module_from_spec(_spec)  # type: ignore[arg-type]
    _spec.loader.exec_module(_mod)  # type: ignore[union-attr]
    Finding = _mod.Finding


# ---------------------------------------------------------------------------
# MITRE ATT&CK technique catalogue (40+ entries)
# ---------------------------------------------------------------------------

ATTACK_TECHNIQUES: Dict[str, Dict[str, Any]] = {
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": (
            "Adversaries may exploit weaknesses in internet-facing systems "
            "to gain initial access."
        ),
        "url": "https://attack.mitre.org/techniques/T1190/",
        "mitigations": ["M1048", "M1050"],
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": (
            "Adversaries may abuse command and script interpreters to execute "
            "commands, scripts, or binaries."
        ),
        "url": "https://attack.mitre.org/techniques/T1059/",
        "mitigations": ["M1038", "M1045"],
    },
    "T1059.001": {
        "name": "Command and Scripting Interpreter: PowerShell",
        "tactic": "Execution",
        "description": "Adversaries may abuse PowerShell to execute malicious commands.",
        "url": "https://attack.mitre.org/techniques/T1059/001/",
        "mitigations": ["M1038", "M1045"],
    },
    "T1059.004": {
        "name": "Command and Scripting Interpreter: Unix Shell",
        "tactic": "Execution",
        "description": (
            "Adversaries may abuse Unix shell commands to execute code on a system."
        ),
        "url": "https://attack.mitre.org/techniques/T1059/004/",
        "mitigations": ["M1038"],
    },
    "T1059.007": {
        "name": "Command and Scripting Interpreter: JavaScript",
        "tactic": "Execution",
        "description": (
            "Adversaries may abuse JavaScript/JScript to execute malicious code "
            "including in web browsers."
        ),
        "url": "https://attack.mitre.org/techniques/T1059/007/",
        "mitigations": ["M1038", "M1021"],
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Defense Evasion",
        "description": (
            "Adversaries may obtain and abuse credentials of existing accounts to "
            "maintain persistence and evade defences."
        ),
        "url": "https://attack.mitre.org/techniques/T1078/",
        "mitigations": ["M1026", "M1032", "M1017"],
    },
    "T1083": {
        "name": "File and Directory Discovery",
        "tactic": "Discovery",
        "description": (
            "Adversaries may enumerate files and directories to find information "
            "of interest."
        ),
        "url": "https://attack.mitre.org/techniques/T1083/",
        "mitigations": ["M1022"],
    },
    "T1185": {
        "name": "Browser Session Hijacking",
        "tactic": "Collection",
        "description": (
            "Adversaries may take advantage of security vulnerabilities and "
            "inherent functionality in browser software to hijack sessions."
        ),
        "url": "https://attack.mitre.org/techniques/T1185/",
        "mitigations": ["M1054"],
    },
    "T1195": {
        "name": "Supply Chain Compromise",
        "tactic": "Initial Access",
        "description": (
            "Adversaries may manipulate products or delivery mechanisms prior to "
            "receipt by a final consumer."
        ),
        "url": "https://attack.mitre.org/techniques/T1195/",
        "mitigations": ["M1051", "M1016"],
    },
    "T1195.001": {
        "name": "Supply Chain Compromise: Compromise Software Dependencies",
        "tactic": "Initial Access",
        "description": (
            "Adversaries may manipulate software dependencies and development tools "
            "prior to receipt by a final consumer."
        ),
        "url": "https://attack.mitre.org/techniques/T1195/001/",
        "mitigations": ["M1051", "M1016"],
    },
    "T1204": {
        "name": "User Execution",
        "tactic": "Execution",
        "description": (
            "An adversary may rely upon specific actions by a user in order to gain "
            "execution."
        ),
        "url": "https://attack.mitre.org/techniques/T1204/",
        "mitigations": ["M1017", "M1038"],
    },
    "T1548": {
        "name": "Abuse Elevation Control Mechanism",
        "tactic": "Privilege Escalation",
        "description": (
            "Adversaries may circumvent mechanisms designed to control elevated "
            "privileges to gain higher-level permissions."
        ),
        "url": "https://attack.mitre.org/techniques/T1548/",
        "mitigations": ["M1026", "M1028"],
    },
    "T1550": {
        "name": "Use Alternate Authentication Material",
        "tactic": "Lateral Movement",
        "description": (
            "Adversaries may use alternate authentication material, such as password "
            "hashes or access tokens, to move laterally."
        ),
        "url": "https://attack.mitre.org/techniques/T1550/",
        "mitigations": ["M1026", "M1054"],
    },
    "T1552": {
        "name": "Unsecured Credentials",
        "tactic": "Credential Access",
        "description": (
            "Adversaries may search for insecurely stored credentials to obtain "
            "legitimate access."
        ),
        "url": "https://attack.mitre.org/techniques/T1552/",
        "mitigations": ["M1026", "M1022", "M1047"],
    },
    "T1552.001": {
        "name": "Unsecured Credentials: Credentials In Files",
        "tactic": "Credential Access",
        "description": (
            "Adversaries may search files on local and remote systems for "
            "credential material such as passwords in cleartext or configuration files."
        ),
        "url": "https://attack.mitre.org/techniques/T1552/001/",
        "mitigations": ["M1022", "M1026"],
    },
    "T1555": {
        "name": "Credentials from Password Stores",
        "tactic": "Credential Access",
        "description": (
            "Adversaries may search for common password storage locations to obtain "
            "user credentials."
        ),
        "url": "https://attack.mitre.org/techniques/T1555/",
        "mitigations": ["M1026", "M1027"],
    },
    "T1565": {
        "name": "Data Manipulation",
        "tactic": "Impact",
        "description": (
            "Adversaries may insert, delete, or manipulate data in order to influence "
            "external outcomes or hide activity."
        ),
        "url": "https://attack.mitre.org/techniques/T1565/",
        "mitigations": ["M1041", "M1029"],
    },
    "T1600": {
        "name": "Weaken Encryption",
        "tactic": "Defense Evasion",
        "description": (
            "Adversaries may compromise a network device's encryption capability "
            "or configurations to facilitate data exfiltration."
        ),
        "url": "https://attack.mitre.org/techniques/T1600/",
        "mitigations": ["M1041", "M1026"],
    },
    "T1005": {
        "name": "Data from Local System",
        "tactic": "Collection",
        "description": (
            "Adversaries may search local system sources to find files of interest "
            "and sensitive data prior to exfiltration."
        ),
        "url": "https://attack.mitre.org/techniques/T1005/",
        "mitigations": ["M1022", "M1057"],
    },
    "T1040": {
        "name": "Network Sniffing",
        "tactic": "Credential Access",
        "description": (
            "Adversaries may passively sniff network traffic to capture information "
            "about an environment."
        ),
        "url": "https://attack.mitre.org/techniques/T1040/",
        "mitigations": ["M1041"],
    },
    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "description": (
            "Adversaries may steal data by exfiltrating it over an existing command "
            "and control channel."
        ),
        "url": "https://attack.mitre.org/techniques/T1041/",
        "mitigations": ["M1031", "M1037"],
    },
    "T1046": {
        "name": "Network Service Scanning",
        "tactic": "Discovery",
        "description": (
            "Adversaries may attempt to get a listing of services running on remote "
            "hosts and local network infrastructure devices."
        ),
        "url": "https://attack.mitre.org/techniques/T1046/",
        "mitigations": ["M1042"],
    },
    "T1068": {
        "name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
        "description": (
            "Adversaries may exploit software vulnerabilities in an attempt to "
            "collect elevated credentials."
        ),
        "url": "https://attack.mitre.org/techniques/T1068/",
        "mitigations": ["M1048", "M1050"],
    },
    "T1072": {
        "name": "Software Deployment Tools",
        "tactic": "Execution",
        "description": (
            "Adversaries may gain access to and use centralized software suites to "
            "execute commands and move laterally through enterprise environment."
        ),
        "url": "https://attack.mitre.org/techniques/T1072/",
        "mitigations": ["M1026", "M1018"],
    },
    "T1098": {
        "name": "Account Manipulation",
        "tactic": "Persistence",
        "description": (
            "Adversaries may manipulate accounts to maintain access to victim systems."
        ),
        "url": "https://attack.mitre.org/techniques/T1098/",
        "mitigations": ["M1026", "M1032"],
    },
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": (
            "Adversaries may use brute force techniques to gain access to accounts "
            "when passwords are unknown or when password hashes are obtained."
        ),
        "url": "https://attack.mitre.org/techniques/T1110/",
        "mitigations": ["M1036", "M1032"],
    },
    "T1133": {
        "name": "External Remote Services",
        "tactic": "Initial Access",
        "description": (
            "Adversaries may leverage external-facing remote services to initially "
            "access and/or persist within a network."
        ),
        "url": "https://attack.mitre.org/techniques/T1133/",
        "mitigations": ["M1030", "M1042"],
    },
    "T1134": {
        "name": "Access Token Manipulation",
        "tactic": "Defense Evasion",
        "description": (
            "Adversaries may modify access tokens to operate under a different user "
            "or system security context to perform actions."
        ),
        "url": "https://attack.mitre.org/techniques/T1134/",
        "mitigations": ["M1026", "M1018"],
    },
    "T1210": {
        "name": "Exploitation of Remote Services",
        "tactic": "Lateral Movement",
        "description": (
            "Adversaries may exploit remote services to gain unauthorized access to "
            "internal systems once inside a network."
        ),
        "url": "https://attack.mitre.org/techniques/T1210/",
        "mitigations": ["M1048", "M1050"],
    },
    "T1211": {
        "name": "Exploitation for Defense Evasion",
        "tactic": "Defense Evasion",
        "description": (
            "Adversaries may exploit a system or application vulnerability to bypass "
            "security features."
        ),
        "url": "https://attack.mitre.org/techniques/T1211/",
        "mitigations": ["M1050", "M1048"],
    },
    "T1212": {
        "name": "Exploitation for Credential Access",
        "tactic": "Credential Access",
        "description": (
            "Adversaries may exploit software vulnerabilities in an attempt to "
            "collect credentials."
        ),
        "url": "https://attack.mitre.org/techniques/T1212/",
        "mitigations": ["M1048", "M1050"],
    },
    "T1485": {
        "name": "Data Destruction",
        "tactic": "Impact",
        "description": (
            "Adversaries may destroy data and files on specific systems or in large "
            "numbers on a network to interrupt availability."
        ),
        "url": "https://attack.mitre.org/techniques/T1485/",
        "mitigations": ["M1053"],
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "description": (
            "Adversaries may encrypt data on target systems to interrupt availability "
            "to system and network resources."
        ),
        "url": "https://attack.mitre.org/techniques/T1486/",
        "mitigations": ["M1053", "M1040"],
    },
    "T1496": {
        "name": "Resource Hijacking",
        "tactic": "Impact",
        "description": (
            "Adversaries may leverage the resources of co-opted systems to solve "
            "resource-intensive problems, such as cryptocurrency mining."
        ),
        "url": "https://attack.mitre.org/techniques/T1496/",
        "mitigations": ["M1018"],
    },
    "T1499": {
        "name": "Endpoint Denial of Service",
        "tactic": "Impact",
        "description": (
            "Adversaries may perform Endpoint Denial of Service attacks to degrade "
            "or block the availability of services."
        ),
        "url": "https://attack.mitre.org/techniques/T1499/",
        "mitigations": ["M1037"],
    },
    "T1505": {
        "name": "Server Software Component",
        "tactic": "Persistence",
        "description": (
            "Adversaries may abuse legitimate extensible development features of "
            "server applications to establish persistent access."
        ),
        "url": "https://attack.mitre.org/techniques/T1505/",
        "mitigations": ["M1047", "M1042"],
    },
    "T1505.003": {
        "name": "Server Software Component: Web Shell",
        "tactic": "Persistence",
        "description": (
            "Adversaries may backdoor web servers with web shells to establish "
            "persistent access to systems."
        ),
        "url": "https://attack.mitre.org/techniques/T1505/003/",
        "mitigations": ["M1042"],
    },
    "T1530": {
        "name": "Data from Cloud Storage",
        "tactic": "Collection",
        "description": (
            "Adversaries may access data objects from improperly secured cloud "
            "storage."
        ),
        "url": "https://attack.mitre.org/techniques/T1530/",
        "mitigations": ["M1022", "M1041"],
    },
    "T1543": {
        "name": "Create or Modify System Process",
        "tactic": "Persistence",
        "description": (
            "Adversaries may create or modify system-level processes to repeatedly "
            "execute malicious payloads as part of persistence."
        ),
        "url": "https://attack.mitre.org/techniques/T1543/",
        "mitigations": ["M1018", "M1022"],
    },
    "T1562": {
        "name": "Impair Defenses",
        "tactic": "Defense Evasion",
        "description": (
            "Adversaries may maliciously modify components of a victim environment "
            "in order to hinder or disable defensive mechanisms."
        ),
        "url": "https://attack.mitre.org/techniques/T1562/",
        "mitigations": ["M1022", "M1024"],
    },
    "T1566": {
        "name": "Phishing",
        "tactic": "Initial Access",
        "description": (
            "Adversaries may send phishing messages to gain access to victim systems."
        ),
        "url": "https://attack.mitre.org/techniques/T1566/",
        "mitigations": ["M1049", "M1017"],
    },
    "T1574": {
        "name": "Hijack Execution Flow",
        "tactic": "Defense Evasion",
        "description": (
            "Adversaries may execute their own malicious payloads by hijacking the "
            "way operating systems run programs."
        ),
        "url": "https://attack.mitre.org/techniques/T1574/",
        "mitigations": ["M1038", "M1044"],
    },
}


# ---------------------------------------------------------------------------
# NIST CSF 2.0 controls catalogue (15+ entries)
# ---------------------------------------------------------------------------

NIST_CSF_CONTROLS: Dict[str, str] = {
    # Govern
    "GV.OC-01": "Organizational mission and objectives establish cybersecurity risk context",
    "GV.RM-01": "Risk management objectives are established and agreed to by stakeholders",
    # Identify
    "ID.AM-1": "Physical devices and systems within the organization are inventoried",
    "ID.AM-2": "Software platforms and applications within the organization are inventoried",
    "ID.RA-1": "Asset vulnerabilities are identified and documented",
    "ID.RA-2": "Cyber threat intelligence is received from information sharing forums",
    # Protect
    "PR.AC-1": "Identities and credentials are issued, managed, verified, revoked",
    "PR.AC-3": "Remote access is managed",
    "PR.AC-4": "Access permissions and authorizations are managed",
    "PR.DS-1": "Data-at-rest is protected",
    "PR.DS-2": "Data-in-transit is protected",
    "PR.DS-5": "Protections against data leaks are implemented",
    "PR.IP-1": "A baseline configuration of IT/OT is created and maintained",
    "PR.IP-3": "Configuration change control processes are in place",
    # Detect
    "DE.AE-1": "A baseline of network operations and expected data flows is established",
    "DE.AE-2": "Detected events are analyzed to understand attack targets and methods",
    "DE.CM-1": "The network is monitored to detect potential cybersecurity events",
    "DE.CM-4": "Malicious code is detected",
    # Respond
    "RS.RP-1": "Response plan is executed during or after a cybersecurity incident",
    "RS.CO-2": "Incidents are reported consistent with established criteria",
    "RS.AN-1": "Notifications from detection systems are investigated",
    "RS.MI-1": "Incidents are contained",
    "RS.MI-2": "Incidents are mitigated",
    # Recover
    "RC.RP-1": "Recovery plan is executed during or after a cybersecurity incident",
    "RC.IM-1": "Recovery plans incorporate lessons learned",
}


# ---------------------------------------------------------------------------
# CWE → multi-framework compliance mapping (20+ entries)
# ---------------------------------------------------------------------------

CWE_COMPLIANCE_MAP: Dict[str, Dict[str, Any]] = {
    "CWE-89": {
        "name": "SQL Injection",
        "owasp_top10": ["A03:2021 - Injection"],
        "attack_techniques": ["T1190", "T1059.004"],
        "nist_csf": ["PR.DS-1", "PR.IP-1", "DE.CM-1"],
        "d3fend": ["D3-SQLCA", "D3-INOUTVAL"],
        "pci_dss": ["6.2.4", "6.3.2"],
        "iso27001": ["A.14.2.5"],
        "severity_weight": 9,
    },
    "CWE-79": {
        "name": "Cross-site Scripting",
        "owasp_top10": ["A03:2021 - Injection"],
        "attack_techniques": ["T1059.007", "T1185"],
        "nist_csf": ["PR.DS-1", "PR.DS-2"],
        "d3fend": ["D3-INOUTVAL", "D3-CSPP"],
        "pci_dss": ["6.2.4"],
        "iso27001": ["A.14.2.5"],
        "severity_weight": 7,
    },
    "CWE-22": {
        "name": "Path Traversal",
        "owasp_top10": ["A01:2021 - Broken Access Control"],
        "attack_techniques": ["T1083", "T1190"],
        "nist_csf": ["PR.AC-4", "PR.DS-1", "DE.CM-1"],
        "d3fend": ["D3-INOUTVAL", "D3-FA"],
        "pci_dss": ["6.2.4", "6.3.2"],
        "iso27001": ["A.9.4.1"],
        "severity_weight": 8,
    },
    "CWE-94": {
        "name": "Code Injection",
        "owasp_top10": ["A03:2021 - Injection"],
        "attack_techniques": ["T1059", "T1190", "T1505.003"],
        "nist_csf": ["PR.IP-1", "DE.CM-4", "RS.MI-1"],
        "d3fend": ["D3-INOUTVAL", "D3-EI"],
        "pci_dss": ["6.2.4"],
        "iso27001": ["A.14.2.5"],
        "severity_weight": 10,
    },
    "CWE-78": {
        "name": "OS Command Injection",
        "owasp_top10": ["A03:2021 - Injection"],
        "attack_techniques": ["T1059.004", "T1190"],
        "nist_csf": ["PR.IP-1", "DE.CM-4"],
        "d3fend": ["D3-INOUTVAL", "D3-EI"],
        "pci_dss": ["6.2.4"],
        "iso27001": ["A.14.2.5"],
        "severity_weight": 10,
    },
    "CWE-798": {
        "name": "Use of Hard-coded Credentials",
        "owasp_top10": ["A07:2021 - Identification and Authentication Failures"],
        "attack_techniques": ["T1552", "T1552.001", "T1078"],
        "nist_csf": ["PR.AC-1", "PR.AC-4", "ID.AM-2"],
        "d3fend": ["D3-SCM", "D3-ORA"],
        "pci_dss": ["8.3.1", "8.6.1"],
        "iso27001": ["A.9.2.1", "A.9.4.3"],
        "severity_weight": 9,
    },
    "CWE-502": {
        "name": "Deserialization of Untrusted Data",
        "owasp_top10": ["A08:2021 - Software and Data Integrity Failures"],
        "attack_techniques": ["T1059", "T1190"],
        "nist_csf": ["PR.IP-1", "DE.CM-4"],
        "d3fend": ["D3-INOUTVAL"],
        "pci_dss": ["6.2.4"],
        "iso27001": ["A.14.2.5"],
        "severity_weight": 9,
    },
    "CWE-327": {
        "name": "Use of a Broken or Risky Cryptographic Algorithm",
        "owasp_top10": ["A02:2021 - Cryptographic Failures"],
        "attack_techniques": ["T1600", "T1040"],
        "nist_csf": ["PR.DS-1", "PR.DS-2"],
        "d3fend": ["D3-ESTO"],
        "pci_dss": ["4.2.1", "3.5.1"],
        "iso27001": ["A.10.1.1"],
        "severity_weight": 7,
    },
    "CWE-326": {
        "name": "Inadequate Encryption Strength",
        "owasp_top10": ["A02:2021 - Cryptographic Failures"],
        "attack_techniques": ["T1600", "T1040"],
        "nist_csf": ["PR.DS-1", "PR.DS-2"],
        "d3fend": ["D3-ESTO"],
        "pci_dss": ["4.2.1"],
        "iso27001": ["A.10.1.1"],
        "severity_weight": 7,
    },
    "CWE-328": {
        "name": "Use of Weak Hash",
        "owasp_top10": ["A02:2021 - Cryptographic Failures"],
        "attack_techniques": ["T1600"],
        "nist_csf": ["PR.DS-1"],
        "d3fend": ["D3-ESTO"],
        "pci_dss": ["3.5.1"],
        "iso27001": ["A.10.1.1"],
        "severity_weight": 6,
    },
    "CWE-287": {
        "name": "Improper Authentication",
        "owasp_top10": ["A07:2021 - Identification and Authentication Failures"],
        "attack_techniques": ["T1078", "T1550"],
        "nist_csf": ["PR.AC-1", "PR.AC-3", "PR.AC-4"],
        "d3fend": ["D3-MFA", "D3-ORA"],
        "pci_dss": ["8.2.1", "8.3.1"],
        "iso27001": ["A.9.4.2"],
        "severity_weight": 8,
    },
    "CWE-306": {
        "name": "Missing Authentication for Critical Function",
        "owasp_top10": ["A07:2021 - Identification and Authentication Failures"],
        "attack_techniques": ["T1078", "T1190"],
        "nist_csf": ["PR.AC-1", "PR.AC-4"],
        "d3fend": ["D3-MFA"],
        "pci_dss": ["8.2.1"],
        "iso27001": ["A.9.4.2"],
        "severity_weight": 9,
    },
    "CWE-384": {
        "name": "Session Fixation",
        "owasp_top10": ["A07:2021 - Identification and Authentication Failures"],
        "attack_techniques": ["T1550", "T1185"],
        "nist_csf": ["PR.AC-1", "PR.AC-3"],
        "d3fend": ["D3-SCM"],
        "pci_dss": ["8.3.1"],
        "iso27001": ["A.9.4.2"],
        "severity_weight": 7,
    },
    "CWE-918": {
        "name": "Server-Side Request Forgery (SSRF)",
        "owasp_top10": ["A10:2021 - Server-Side Request Forgery"],
        "attack_techniques": ["T1190", "T1083", "T1005"],
        "nist_csf": ["PR.AC-4", "DE.CM-1"],
        "d3fend": ["D3-INOUTVAL"],
        "pci_dss": ["6.2.4"],
        "iso27001": ["A.13.1.1"],
        "severity_weight": 8,
    },
    "CWE-611": {
        "name": "XML External Entity (XXE)",
        "owasp_top10": ["A05:2021 - Security Misconfiguration"],
        "attack_techniques": ["T1190", "T1083"],
        "nist_csf": ["PR.IP-1", "DE.CM-4"],
        "d3fend": ["D3-INOUTVAL"],
        "pci_dss": ["6.2.4"],
        "iso27001": ["A.14.2.5"],
        "severity_weight": 8,
    },
    "CWE-434": {
        "name": "Unrestricted File Upload",
        "owasp_top10": ["A04:2021 - Insecure Design"],
        "attack_techniques": ["T1190", "T1505.003"],
        "nist_csf": ["PR.IP-1", "DE.CM-4"],
        "d3fend": ["D3-INOUTVAL"],
        "pci_dss": ["6.2.4"],
        "iso27001": ["A.14.2.5"],
        "severity_weight": 8,
    },
    "CWE-352": {
        "name": "Cross-Site Request Forgery (CSRF)",
        "owasp_top10": ["A01:2021 - Broken Access Control"],
        "attack_techniques": ["T1185", "T1204"],
        "nist_csf": ["PR.DS-1"],
        "d3fend": ["D3-CSPP"],
        "pci_dss": ["6.2.4"],
        "iso27001": ["A.14.2.5"],
        "severity_weight": 6,
    },
    "CWE-200": {
        "name": "Exposure of Sensitive Information",
        "owasp_top10": ["A02:2021 - Cryptographic Failures"],
        "attack_techniques": ["T1005", "T1530"],
        "nist_csf": ["PR.DS-1", "PR.DS-5"],
        "d3fend": ["D3-DNSTRM"],
        "pci_dss": ["3.3.1", "6.2.4"],
        "iso27001": ["A.13.2.1"],
        "severity_weight": 5,
    },
    "CWE-285": {
        "name": "Improper Authorization",
        "owasp_top10": ["A01:2021 - Broken Access Control"],
        "attack_techniques": ["T1078", "T1548"],
        "nist_csf": ["PR.AC-4"],
        "d3fend": ["D3-ORA"],
        "pci_dss": ["7.2.1"],
        "iso27001": ["A.9.4.1"],
        "severity_weight": 7,
    },
    "CWE-259": {
        "name": "Use of Hard-coded Password",
        "owasp_top10": ["A07:2021 - Identification and Authentication Failures"],
        "attack_techniques": ["T1552.001", "T1078"],
        "nist_csf": ["PR.AC-1"],
        "d3fend": ["D3-ORA"],
        "pci_dss": ["8.3.1"],
        "iso27001": ["A.9.2.4"],
        "severity_weight": 9,
    },
    "CWE-190": {
        "name": "Integer Overflow or Wraparound",
        "owasp_top10": ["A04:2021 - Insecure Design"],
        "attack_techniques": ["T1068"],
        "nist_csf": ["PR.IP-1"],
        "d3fend": [],
        "pci_dss": ["6.2.4"],
        "iso27001": ["A.14.2.5"],
        "severity_weight": 6,
    },
    "CWE-400": {
        "name": "Uncontrolled Resource Consumption",
        "owasp_top10": ["A04:2021 - Insecure Design"],
        "attack_techniques": ["T1499"],
        "nist_csf": ["DE.CM-1", "RS.MI-1"],
        "d3fend": [],
        "pci_dss": ["6.2.4"],
        "iso27001": ["A.12.6.1"],
        "severity_weight": 5,
    },
    "CWE-601": {
        "name": "URL Redirection to Untrusted Site ('Open Redirect')",
        "owasp_top10": ["A01:2021 - Broken Access Control"],
        "attack_techniques": ["T1566", "T1185"],
        "nist_csf": ["PR.DS-1"],
        "d3fend": ["D3-INOUTVAL"],
        "pci_dss": ["6.2.4"],
        "iso27001": ["A.14.2.5"],
        "severity_weight": 5,
    },
    "CWE-476": {
        "name": "NULL Pointer Dereference",
        "owasp_top10": ["A04:2021 - Insecure Design"],
        "attack_techniques": ["T1499"],
        "nist_csf": ["PR.IP-1"],
        "d3fend": [],
        "pci_dss": ["6.2.4"],
        "iso27001": ["A.14.2.5"],
        "severity_weight": 4,
    },
}

# ---------------------------------------------------------------------------
# OWASP Top 10 2021 — full category list
# ---------------------------------------------------------------------------

OWASP_CATEGORIES = [
    "A01:2021 - Broken Access Control",
    "A02:2021 - Cryptographic Failures",
    "A03:2021 - Injection",
    "A04:2021 - Insecure Design",
    "A05:2021 - Security Misconfiguration",
    "A06:2021 - Vulnerable and Outdated Components",
    "A07:2021 - Identification and Authentication Failures",
    "A08:2021 - Software and Data Integrity Failures",
    "A09:2021 - Security Logging and Monitoring Failures",
    "A10:2021 - Server-Side Request Forgery",
]


# ---------------------------------------------------------------------------
# Severity weights for compliance score
# ---------------------------------------------------------------------------

_SEVERITY_WEIGHT: Dict[str, float] = {
    "CRITICAL": 10.0,
    "HIGH": 7.0,
    "MEDIUM": 4.0,
    "LOW": 1.5,
    "INFO": 0.5,
}


def _finding_weight(finding: "Finding") -> float:  # type: ignore[name-defined]
    return _SEVERITY_WEIGHT.get(finding.severity.upper(), 4.0)


# ---------------------------------------------------------------------------
# ComplianceMapper
# ---------------------------------------------------------------------------


class ComplianceMapper:
    """Maps security findings to multiple compliance and threat intelligence frameworks."""

    # ── Single finding ───────────────────────────────────────────────────────

    def map_finding(self, finding: "Finding") -> Dict[str, Any]:  # type: ignore[name-defined]
        """Return all compliance framework mappings for a single finding."""
        cwe = finding.cwe_id
        entry = CWE_COMPLIANCE_MAP.get(cwe, {})

        # Enrich ATT&CK references
        enriched_techniques: List[Dict[str, Any]] = []
        for tid in entry.get("attack_techniques", []):
            tech = ATTACK_TECHNIQUES.get(tid, {})
            enriched_techniques.append(
                {
                    "technique_id": tid,
                    "name": tech.get("name", "Unknown"),
                    "tactic": tech.get("tactic", "Unknown"),
                    "url": tech.get("url", f"https://attack.mitre.org/techniques/{tid}/"),
                }
            )

        # Enrich NIST CSF references
        enriched_nist: List[Dict[str, str]] = []
        for ctrl_id in entry.get("nist_csf", []):
            enriched_nist.append(
                {
                    "control_id": ctrl_id,
                    "description": NIST_CSF_CONTROLS.get(ctrl_id, ""),
                }
            )

        return {
            "rule_id": finding.rule_id,
            "cwe_id": cwe,
            "cwe_name": entry.get("name", "Unknown CWE"),
            "severity": finding.severity,
            "file": finding.file,
            "line": finding.line,
            "owasp_top10": entry.get("owasp_top10", []),
            "mitre_attack": enriched_techniques,
            "nist_csf": enriched_nist,
            "d3fend": entry.get("d3fend", []),
            "pci_dss": entry.get("pci_dss", []),
            "iso27001": entry.get("iso27001", []),
            "severity_weight": entry.get("severity_weight", 5),
            "mapped": bool(entry),
        }

    # ── Batch mapping ─────────────────────────────────────────────────────────

    def map_findings_batch(
        self, findings: List["Finding"]  # type: ignore[name-defined]
    ) -> Dict[str, Any]:
        """Map all findings and aggregate framework coverage."""
        per_finding = [self.map_finding(f) for f in findings]

        # Aggregate unique framework hits
        owasp_hits: Dict[str, List[str]] = {}      # category → rule_ids
        attack_hits: Dict[str, List[str]] = {}     # technique_id → rule_ids
        nist_hits: Dict[str, List[str]] = {}       # control_id → rule_ids
        d3fend_hits: Dict[str, List[str]] = {}
        pci_dss_hits: Dict[str, List[str]] = {}
        iso27001_hits: Dict[str, List[str]] = {}

        for fm in per_finding:
            rid = fm["rule_id"]
            for cat in fm["owasp_top10"]:
                owasp_hits.setdefault(cat, []).append(rid)
            for tech in fm["mitre_attack"]:
                attack_hits.setdefault(tech["technique_id"], []).append(rid)
            for ctrl in fm["nist_csf"]:
                nist_hits.setdefault(ctrl["control_id"], []).append(rid)
            for tag in fm["d3fend"]:
                d3fend_hits.setdefault(tag, []).append(rid)
            for ctrl in fm["pci_dss"]:
                pci_dss_hits.setdefault(ctrl, []).append(rid)
            for ctrl in fm["iso27001"]:
                iso27001_hits.setdefault(ctrl, []).append(rid)

        return {
            "total_findings": len(findings),
            "findings": per_finding,
            "aggregated": {
                "owasp_top10": owasp_hits,
                "mitre_attack_techniques": attack_hits,
                "nist_csf_controls": nist_hits,
                "d3fend_tactics": d3fend_hits,
                "pci_dss_requirements": pci_dss_hits,
                "iso27001_controls": iso27001_hits,
            },
            "unique_cwe_ids": sorted({fm["cwe_id"] for fm in per_finding if fm["cwe_id"]}),
            "unique_owasp_categories": sorted(owasp_hits.keys()),
            "unique_attack_techniques": sorted(attack_hits.keys()),
            "unique_nist_controls": sorted(nist_hits.keys()),
        }

    # ── Full compliance report ───────────────────────────────────────────────

    def generate_compliance_report(
        self,
        findings: List["Finding"],  # type: ignore[name-defined]
        standards: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Generate a compliance posture report for the given findings.

        Standards filter: ["OWASP", "NIST_CSF", "MITRE_ATTACK", "PCI_DSS",
                           "ISO27001", "D3FEND"]
        """
        all_standards = ["OWASP", "NIST_CSF", "MITRE_ATTACK", "PCI_DSS", "ISO27001", "D3FEND"]
        active_standards = standards if standards else all_standards

        batch = self.map_findings_batch(findings)
        agg = batch["aggregated"]

        # ── OWASP Top 10 section ─────────────────────────────────────────────
        owasp_report: Dict[str, Any] = {}
        if "OWASP" in active_standards:
            for cat, rule_ids in agg["owasp_top10"].items():
                # Determine highest severity for this category
                related = [f for f in findings if f.rule_id in rule_ids]
                sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
                max_sev = max(
                    (f.severity.upper() for f in related),
                    key=lambda s: sev_order.get(s, 0),
                    default="MEDIUM",
                )
                owasp_report[cat] = {
                    "findings": rule_ids,
                    "count": len(rule_ids),
                    "severity": max_sev,
                }

        # ── MITRE ATT&CK section — group by tactic ───────────────────────────
        mitre_report: Dict[str, List[str]] = {}
        if "MITRE_ATTACK" in active_standards:
            for tid in agg["mitre_attack_techniques"]:
                tactic = ATTACK_TECHNIQUES.get(tid, {}).get("tactic", "Unknown")
                mitre_report.setdefault(tactic, []).append(tid)

        # ── NIST CSF gaps (controls where we have findings) ──────────────────
        nist_gaps = sorted(agg["nist_csf_controls"].keys()) if "NIST_CSF" in active_standards else []

        # ── PCI DSS section ──────────────────────────────────────────────────
        pci_report: Dict[str, int] = {}
        if "PCI_DSS" in active_standards:
            pci_report = {req: len(rids) for req, rids in agg["pci_dss_requirements"].items()}

        # ── ISO 27001 section ────────────────────────────────────────────────
        iso_report: Dict[str, int] = {}
        if "ISO27001" in active_standards:
            iso_report = {ctrl: len(rids) for ctrl, rids in agg["iso27001_controls"].items()}

        # ── D3FEND gaps ──────────────────────────────────────────────────────
        d3fend_gaps = sorted(agg["d3fend_tactics"].keys()) if "D3FEND" in active_standards else []

        # ── Compliance score ─────────────────────────────────────────────────
        # Score = 100 − (sum of weighted finding contributions / maximum possible weight) × 100
        # Capped to [0, 100]
        total_weight = sum(_finding_weight(f) for f in findings)
        # Normalise: assume maximum credible total weight is 100 for the formula
        # We use a logarithmic penalty approach for realistic scores
        if findings:
            max_weight_per_finding = _SEVERITY_WEIGHT["CRITICAL"]
            worst_case_weight = max_weight_per_finding * len(findings)
            raw_score = max(0.0, 100.0 - (total_weight / worst_case_weight) * 100.0)
            # Apply non-linearity: even a few high-severity findings should tank the score
            high_critical = sum(
                1 for f in findings if f.severity.upper() in ("CRITICAL", "HIGH")
            )
            penalty = min(40.0, high_critical * 5.0)
            compliance_score = round(max(0.0, raw_score - penalty), 1)
        else:
            compliance_score = 100.0

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_findings": len(findings),
            "active_standards": active_standards,
            "owasp_top10": owasp_report,
            "mitre_attack": mitre_report,
            "nist_csf_gaps": nist_gaps,
            "pci_dss": pci_report,
            "iso27001": iso_report,
            "d3fend_gaps": d3fend_gaps,
            "compliance_score": compliance_score,
            "unique_cwe_ids": batch["unique_cwe_ids"],
        }

    # ── Markdown report ──────────────────────────────────────────────────────

    def to_markdown(self, report: Dict[str, Any]) -> str:
        """Convert a compliance report dict to a Markdown document."""
        lines: List[str] = []
        ts = report.get("generated_at", "")
        score = report.get("compliance_score", 0)

        lines.append("# TythanAI — Compliance Report")
        lines.append("")
        lines.append(f"**Generated**: {ts}  ")
        lines.append(f"**Total Findings**: {report.get('total_findings', 0)}  ")
        lines.append(f"**Compliance Score**: {score} / 100")
        lines.append("")

        # OWASP
        if "owasp_top10" in report and report["owasp_top10"]:
            lines.append("## OWASP Top 10 (2021)")
            lines.append("")
            lines.append("| Category | Findings | Max Severity |")
            lines.append("|----------|----------|--------------|")
            for cat, data in sorted(report["owasp_top10"].items()):
                lines.append(f"| {cat} | {data['count']} | {data['severity']} |")
            lines.append("")

        # MITRE ATT&CK
        if "mitre_attack" in report and report["mitre_attack"]:
            lines.append("## MITRE ATT&CK Coverage")
            lines.append("")
            for tactic, techniques in sorted(report["mitre_attack"].items()):
                tech_list = ", ".join(f"`{t}`" for t in techniques)
                lines.append(f"- **{tactic}**: {tech_list}")
            lines.append("")

        # NIST CSF gaps
        if "nist_csf_gaps" in report and report["nist_csf_gaps"]:
            lines.append("## NIST CSF 2.0 — Control Gaps")
            lines.append("")
            lines.append("| Control ID | Description |")
            lines.append("|------------|-------------|")
            for ctrl_id in report["nist_csf_gaps"]:
                desc = NIST_CSF_CONTROLS.get(ctrl_id, "")
                lines.append(f"| `{ctrl_id}` | {desc} |")
            lines.append("")

        # PCI DSS
        if "pci_dss" in report and report["pci_dss"]:
            lines.append("## PCI DSS Requirements")
            lines.append("")
            lines.append("| Requirement | Finding Count |")
            lines.append("|-------------|---------------|")
            for req, count in sorted(report["pci_dss"].items()):
                lines.append(f"| {req} | {count} |")
            lines.append("")

        # ISO 27001
        if "iso27001" in report and report["iso27001"]:
            lines.append("## ISO 27001 Controls")
            lines.append("")
            lines.append("| Control | Finding Count |")
            lines.append("|---------|---------------|")
            for ctrl, count in sorted(report["iso27001"].items()):
                lines.append(f"| {ctrl} | {count} |")
            lines.append("")

        # D3FEND
        if "d3fend_gaps" in report and report["d3fend_gaps"]:
            lines.append("## D3FEND Defensive Technique Gaps")
            lines.append("")
            for tag in report["d3fend_gaps"]:
                lines.append(f"- `{tag}`")
            lines.append("")

        return "\n".join(lines)

    # ── SARIF 2.1 export ─────────────────────────────────────────────────────

    def to_sarif_enriched(
        self, findings: List["Finding"]  # type: ignore[name-defined]
    ) -> Dict[str, Any]:
        """
        Return a SARIF 2.1.0 document enriched with CWE, OWASP, and MITRE ATT&CK taxa.

        Compatible with GitHub Advanced Security, VS Code SARIF Viewer, and CI/CD tools.
        """
        # Build rule catalogue from unique rule_ids
        rules_seen: Dict[str, Dict[str, Any]] = {}
        for f in findings:
            if f.rule_id not in rules_seen:
                cwe_entry = CWE_COMPLIANCE_MAP.get(f.cwe_id, {})
                rule: Dict[str, Any] = {
                    "id": f.rule_id,
                    "name": f.rule_id,
                    "shortDescription": {"text": f.description or f.rule_id},
                    "fullDescription": {
                        "text": f.description or f.recommendation or f.rule_id
                    },
                    "defaultConfiguration": {"level": _sarif_level(f.severity)},
                    "properties": {
                        "precision": "high" if f.confidence >= 0.85 else "medium",
                        "problem.severity": f.severity.lower(),
                    },
                    "relationships": [],
                }

                # CWE relationship
                if f.cwe_id:
                    cwe_num = f.cwe_id.replace("CWE-", "")
                    rule["relationships"].append(
                        {
                            "target": {
                                "id": cwe_num,
                                "toolComponent": {"name": "CWE"},
                            },
                            "kinds": ["relevant"],
                        }
                    )

                # OWASP relationships
                for owasp_cat in cwe_entry.get("owasp_top10", []):
                    rule["relationships"].append(
                        {
                            "target": {
                                "id": owasp_cat,
                                "toolComponent": {"name": "OWASP"},
                            },
                            "kinds": ["relevant"],
                        }
                    )

                # MITRE ATT&CK relationships
                for tid in cwe_entry.get("attack_techniques", []):
                    rule["relationships"].append(
                        {
                            "target": {
                                "id": tid,
                                "toolComponent": {"name": "MITRE ATT&CK"},
                            },
                            "kinds": ["relevant"],
                        }
                    )

                rules_seen[f.rule_id] = rule

        # Build results array
        results: List[Dict[str, Any]] = []
        for f in findings:
            result: Dict[str, Any] = {
                "ruleId": f.rule_id,
                "level": _sarif_level(f.severity),
                "message": {"text": f.description or f"Issue detected by rule {f.rule_id}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.file, "uriBaseId": "%SRCROOT%"},
                            "region": {"startLine": max(1, f.line)},
                        }
                    }
                ],
                "fingerprints": {"primaryLocationLineHash": f.fingerprint()},
                "properties": {
                    "confidence": f.confidence,
                    "cwe": f.cwe_id,
                    "recommendation": f.recommendation,
                },
            }
            results.append(result)

        # CWE taxonomy
        cwe_taxa = []
        seen_cwes = {fm.cwe_id for fm in findings if fm.cwe_id}
        for cwe_id in sorted(seen_cwes):
            cwe_num = cwe_id.replace("CWE-", "")
            entry = CWE_COMPLIANCE_MAP.get(cwe_id, {})
            cwe_taxa.append(
                {
                    "id": cwe_num,
                    "name": entry.get("name", cwe_id),
                    "shortDescription": {"text": entry.get("name", cwe_id)},
                    "helpUri": f"https://cwe.mitre.org/data/definitions/{cwe_num}.html",
                    "properties": {"severity_weight": entry.get("severity_weight", 5)},
                }
            )

        # OWASP taxonomy
        owasp_taxa = []
        seen_owasp: set = set()
        for f in findings:
            entry = CWE_COMPLIANCE_MAP.get(f.cwe_id, {})
            for cat in entry.get("owasp_top10", []):
                if cat not in seen_owasp:
                    seen_owasp.add(cat)
                    owasp_taxa.append(
                        {
                            "id": cat,
                            "name": cat,
                            "shortDescription": {"text": cat},
                            "helpUri": "https://owasp.org/Top10/",
                        }
                    )

        # ATT&CK taxonomy
        attack_taxa = []
        seen_attack: set = set()
        for f in findings:
            entry = CWE_COMPLIANCE_MAP.get(f.cwe_id, {})
            for tid in entry.get("attack_techniques", []):
                if tid not in seen_attack:
                    seen_attack.add(tid)
                    tech = ATTACK_TECHNIQUES.get(tid, {})
                    attack_taxa.append(
                        {
                            "id": tid,
                            "name": tech.get("name", tid),
                            "shortDescription": {
                                "text": f"{tech.get('tactic', 'Unknown')} — {tech.get('name', tid)}"
                            },
                            "helpUri": tech.get(
                                "url", f"https://attack.mitre.org/techniques/{tid}/"
                            ),
                        }
                    )

        sarif: Dict[str, Any] = {
            "$schema": (
                "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json"
            ),
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "TythanAI",
                            "version": "3.0",
                            "informationUri": "https://ghost.security",
                            "rules": list(rules_seen.values()),
                            "supportedTaxonomies": [
                                {"name": "CWE", "version": "4.12"},
                                {"name": "OWASP", "version": "2021"},
                                {"name": "MITRE ATT&CK", "version": "14.0"},
                            ],
                        }
                    },
                    "results": results,
                    "taxonomies": [
                        {
                            "name": "CWE",
                            "version": "4.12",
                            "organization": "MITRE",
                            "shortDescription": {
                                "text": "Common Weakness Enumeration"
                            },
                            "informationUri": "https://cwe.mitre.org/",
                            "taxa": cwe_taxa,
                        },
                        {
                            "name": "OWASP",
                            "version": "2021",
                            "organization": "OWASP Foundation",
                            "shortDescription": {"text": "OWASP Top 10 2021"},
                            "informationUri": "https://owasp.org/Top10/",
                            "taxa": owasp_taxa,
                        },
                        {
                            "name": "MITRE ATT&CK",
                            "version": "14.0",
                            "organization": "MITRE",
                            "shortDescription": {
                                "text": "MITRE ATT&CK Framework"
                            },
                            "informationUri": "https://attack.mitre.org/",
                            "taxa": attack_taxa,
                        },
                    ],
                }
            ],
        }
        return sarif


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _sarif_level(severity: str) -> str:
    """Map a TythanAI severity to a SARIF level."""
    mapping = {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
        "INFO": "note",
    }
    return mapping.get(severity.upper(), "warning")


# ---------------------------------------------------------------------------
# Module-level convenience API
# ---------------------------------------------------------------------------


def map_to_compliance(
    findings: List["Finding"],  # type: ignore[name-defined]
) -> Dict[str, Any]:
    """Map findings to all compliance frameworks and return the batch result."""
    return ComplianceMapper().map_findings_batch(findings)


def export_sarif(
    findings: List["Finding"],  # type: ignore[name-defined]
) -> str:
    """Export findings as a SARIF 2.1.0 JSON string."""
    mapper = ComplianceMapper()
    return json.dumps(mapper.to_sarif_enriched(findings), indent=2)
