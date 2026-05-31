"""
TythanAI — Skills Loader
Loads cybersecurity skills from embedded registry (no external dependencies).
Supports: domain search, framework search (ATT&CK/D3FEND/NIST/ATLAS), semantic scan_all.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional


# ─────────────────────────────────────────────────────────────────────────────
# Data models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class SkillMeta:
    skill_id: str
    name: str
    description: str
    domain: str          # e.g. "web-application-security", "threat-hunting"
    tags: List[str]
    mitre_ids: List[str]    # ["T1190", "T1059"]
    d3fend_ids: List[str]   # ["D3-DA", "D3-NTA"]
    nist_ids: List[str]     # ["DE.CM", "PR.DS-1"]
    atlas_ids: List[str]    # ["AML.T0047"]
    severity_focus: str     # "critical","high","medium"


@dataclass
class SkillContent:
    meta: SkillMeta
    prerequisites: List[str]
    workflow_steps: List[str]
    verification_steps: List[str]
    remediation: List[str]
    sigma_queries: List[str]   # Sigma-compatible detection queries
    kql_queries: List[str]


# ─────────────────────────────────────────────────────────────────────────────
# Embedded skills registry  (exactly 40 skills)
# ─────────────────────────────────────────────────────────────────────────────

_EMBEDDED_SKILLS: List[SkillMeta] = [
    # ── web-application-security (5 skills) ──────────────────────────────────
    SkillMeta(
        skill_id="sql-injection-hunting",
        name="SQL Injection Detection & Hunting",
        description=(
            "Detect and hunt SQL injection vulnerabilities including error-based, "
            "blind, time-based, and UNION-based SQLi in web application code and logs."
        ),
        domain="web-application-security",
        tags=["sqli", "sql", "injection", "database", "owasp", "web", "cwe-89"],
        mitre_ids=["T1190", "T1059.007"],
        d3fend_ids=["D3-DA", "D3-DENCR"],
        nist_ids=["DE.CM-1", "PR.DS-2"],
        atlas_ids=[],
        severity_focus="critical",
    ),
    SkillMeta(
        skill_id="xss-detection",
        name="Cross-Site Scripting (XSS) Detection",
        description=(
            "Identify reflected, stored, and DOM-based XSS vulnerabilities in "
            "web applications. Covers content security policy bypass and sink analysis."
        ),
        domain="web-application-security",
        tags=["xss", "cross-site-scripting", "dom", "reflected", "stored", "csp", "owasp", "cwe-79"],
        mitre_ids=["T1059.007", "T1185"],
        d3fend_ids=["D3-DA", "D3-OE"],
        nist_ids=["PR.DS-2", "DE.CM-4"],
        atlas_ids=[],
        severity_focus="high",
    ),
    SkillMeta(
        skill_id="ssrf-detection",
        name="Server-Side Request Forgery (SSRF) Detection",
        description=(
            "Detect SSRF vulnerabilities where an attacker can cause the server to "
            "make requests to internal resources, cloud metadata APIs, or arbitrary URLs."
        ),
        domain="web-application-security",
        tags=["ssrf", "request-forgery", "cloud-metadata", "internal-network", "cwe-918"],
        mitre_ids=["T1552.005", "T1190"],
        d3fend_ids=["D3-NTA", "D3-DA"],
        nist_ids=["PR.AC-3", "DE.CM-1"],
        atlas_ids=[],
        severity_focus="high",
    ),
    SkillMeta(
        skill_id="idor-detection",
        name="Insecure Direct Object Reference (IDOR) Detection",
        description=(
            "Identify IDOR vulnerabilities where object identifiers are not properly "
            "authorization-checked, allowing horizontal or vertical privilege escalation."
        ),
        domain="web-application-security",
        tags=["idor", "broken-access-control", "authorization", "owasp", "cwe-639"],
        mitre_ids=["T1078", "T1212"],
        d3fend_ids=["D3-HBPI", "D3-UAM"],
        nist_ids=["PR.AC-4", "DE.CM-3"],
        atlas_ids=[],
        severity_focus="high",
    ),
    SkillMeta(
        skill_id="cors-misconfiguration",
        name="CORS Misconfiguration Detection",
        description=(
            "Detect permissive or wildcard CORS configurations that allow unauthorized "
            "cross-origin requests to authenticated endpoints, leading to CSRF and data theft."
        ),
        domain="web-application-security",
        tags=["cors", "cross-origin", "misconfiguration", "http-headers", "cwe-346"],
        mitre_ids=["T1185", "T1190"],
        d3fend_ids=["D3-OE", "D3-DA"],
        nist_ids=["PR.DS-2", "PR.AC-3"],
        atlas_ids=[],
        severity_focus="medium",
    ),
    # ── threat-hunting (5 skills) ─────────────────────────────────────────────
    SkillMeta(
        skill_id="lateral-movement-hunt",
        name="Lateral Movement Detection Hunt",
        description=(
            "Hunt for lateral movement techniques including pass-the-hash, pass-the-ticket, "
            "WMI execution, and SMB-based movement across network segments."
        ),
        domain="threat-hunting",
        tags=["lateral-movement", "pass-the-hash", "wmi", "smb", "credential-reuse"],
        mitre_ids=["T1021", "T1550.002", "T1047"],
        d3fend_ids=["D3-NTA", "D3-UAM"],
        nist_ids=["DE.CM-1", "DE.AE-3"],
        atlas_ids=[],
        severity_focus="critical",
    ),
    SkillMeta(
        skill_id="c2-beaconing-hunt",
        name="Command & Control Beaconing Detection",
        description=(
            "Identify C2 beaconing patterns using periodic network traffic analysis, "
            "JA3 fingerprints, and DNS-based C2 detection across SIEM data."
        ),
        domain="threat-hunting",
        tags=["c2", "beaconing", "command-control", "dns-tunneling", "ja3", "cobalt-strike"],
        mitre_ids=["T1071", "T1071.001", "T1071.004", "T1132"],
        d3fend_ids=["D3-NTA", "D3-DNSTA"],
        nist_ids=["DE.CM-1", "DE.AE-2"],
        atlas_ids=[],
        severity_focus="critical",
    ),
    SkillMeta(
        skill_id="credential-dumping-hunt",
        name="Credential Dumping Hunt",
        description=(
            "Detect credential harvesting operations including LSASS memory dumps, "
            "NTDS.dit extraction, SAM hive access, and keylogger artifacts."
        ),
        domain="threat-hunting",
        tags=["credential-dumping", "lsass", "mimikatz", "ntds", "sam", "keylogger", "cwe-522"],
        mitre_ids=["T1003", "T1003.001", "T1003.002", "T1003.003"],
        d3fend_ids=["D3-CRED", "D3-UAM"],
        nist_ids=["DE.CM-1", "PR.AC-1"],
        atlas_ids=[],
        severity_focus="critical",
    ),
    SkillMeta(
        skill_id="data-exfiltration-hunt",
        name="Data Exfiltration Pattern Hunt",
        description=(
            "Hunt for data exfiltration using DNS tunneling, HTTPS to unusual destinations, "
            "staged zip archives, and cloud storage uploads by unusual processes."
        ),
        domain="threat-hunting",
        tags=["exfiltration", "dns-tunnel", "staging", "cloud-exfil", "data-theft"],
        mitre_ids=["T1041", "T1048", "T1048.002", "T1567"],
        d3fend_ids=["D3-NTA", "D3-DNSTA", "D3-DA"],
        nist_ids=["DE.CM-1", "PR.DS-5"],
        atlas_ids=[],
        severity_focus="high",
    ),
    SkillMeta(
        skill_id="persistence-mechanisms-hunt",
        name="Persistence Mechanisms Hunt",
        description=(
            "Identify attacker persistence via registry run keys, scheduled tasks, "
            "cron jobs, SUID binaries, SSH authorized_keys modification, and web shells."
        ),
        domain="threat-hunting",
        tags=["persistence", "registry", "scheduled-task", "cron", "suid", "web-shell"],
        mitre_ids=["T1053", "T1547", "T1505", "T1078"],
        d3fend_ids=["D3-FCSAM", "D3-UAM"],
        nist_ids=["DE.CM-3", "DE.AE-2"],
        atlas_ids=[],
        severity_focus="high",
    ),
    # ── cryptography (4 skills) ───────────────────────────────────────────────
    SkillMeta(
        skill_id="weak-key-detection",
        name="Weak Cryptographic Key Detection",
        description=(
            "Detect use of weak or insufficient key sizes in RSA (<2048 bits), "
            "DSA (<2048 bits), EC (<224 bits), and hardcoded symmetric keys in source code."
        ),
        domain="cryptography",
        tags=["weak-keys", "rsa", "dsa", "ecc", "key-size", "cwe-326", "crypto"],
        mitre_ids=["T1600", "T1553"],
        d3fend_ids=["D3-ECES", "D3-DENCR"],
        nist_ids=["PR.DS-2", "PR.DS-5"],
        atlas_ids=[],
        severity_focus="high",
    ),
    SkillMeta(
        skill_id="weak-hash-detection",
        name="Weak Hashing Algorithm Detection",
        description=(
            "Identify use of deprecated or broken hash algorithms: MD5, SHA-1, "
            "and their HMAC variants for security-sensitive operations like password storage."
        ),
        domain="cryptography",
        tags=["md5", "sha1", "weak-hash", "password-storage", "cwe-327", "bcrypt"],
        mitre_ids=["T1600.002", "T1110"],
        d3fend_ids=["D3-DENCR", "D3-CRED"],
        nist_ids=["PR.DS-2", "PR.AC-1"],
        atlas_ids=[],
        severity_focus="medium",
    ),
    SkillMeta(
        skill_id="padding-oracle-detection",
        name="Padding Oracle Vulnerability Detection",
        description=(
            "Detect CBC mode decryption without proper MAC verification, enabling "
            "padding oracle attacks (POODLE, BEAST, Lucky13) against encrypted communications."
        ),
        domain="cryptography",
        tags=["padding-oracle", "cbc", "poodle", "beast", "lucky13", "tls", "cwe-649"],
        mitre_ids=["T1600", "T1557"],
        d3fend_ids=["D3-ECES", "D3-NTA"],
        nist_ids=["PR.DS-2"],
        atlas_ids=[],
        severity_focus="high",
    ),
    # ── identity-access-management (4 skills) ─────────────────────────────────
    SkillMeta(
        skill_id="broken-auth-detection",
        name="Broken Authentication Detection",
        description=(
            "Detect broken authentication patterns: hardcoded credentials, missing "
            "brute-force protection, insecure password reset flows, and JWT weaknesses."
        ),
        domain="identity-access-management",
        tags=["broken-auth", "authentication", "jwt", "password", "brute-force", "cwe-287"],
        mitre_ids=["T1078", "T1110", "T1550.001"],
        d3fend_ids=["D3-MFA", "D3-UAM", "D3-CRED"],
        nist_ids=["PR.AC-1", "PR.AC-7", "DE.CM-3"],
        atlas_ids=[],
        severity_focus="critical",
    ),
    SkillMeta(
        skill_id="session-management-audit",
        name="Session Management Security Audit",
        description=(
            "Identify session fixation, insecure cookie flags (missing Secure/HttpOnly/SameSite), "
            "overly long session lifetimes, and missing CSRF protection."
        ),
        domain="identity-access-management",
        tags=["session", "cookie", "csrf", "session-fixation", "httponly", "samesite", "cwe-384"],
        mitre_ids=["T1185", "T1539"],
        d3fend_ids=["D3-UAM", "D3-OE"],
        nist_ids=["PR.AC-7", "DE.CM-3"],
        atlas_ids=[],
        severity_focus="high",
    ),
    SkillMeta(
        skill_id="rbac-misconfiguration",
        name="RBAC Misconfiguration Detection",
        description=(
            "Identify overly permissive role assignments, privilege escalation paths "
            "through role chaining, missing permission checks, and RBAC bypass via parameter tampering."
        ),
        domain="identity-access-management",
        tags=["rbac", "authorization", "privilege-escalation", "access-control", "cwe-269"],
        mitre_ids=["T1078", "T1134", "T1548"],
        d3fend_ids=["D3-UAM", "D3-HBPI"],
        nist_ids=["PR.AC-4", "PR.AC-6", "DE.CM-3"],
        atlas_ids=[],
        severity_focus="high",
    ),
    # ── incident-response (3 skills) ─────────────────────────────────────────
    SkillMeta(
        skill_id="incident-triage",
        name="Incident Triage & Initial Assessment",
        description=(
            "Systematic initial triage of security incidents: severity classification, "
            "scope determination, immediate containment triggers, and stakeholder notification."
        ),
        domain="incident-response",
        tags=["triage", "incident", "classification", "scope", "containment", "ir"],
        mitre_ids=["T1078", "T1190"],
        d3fend_ids=["D3-DA", "D3-NTA"],
        nist_ids=["RS.AN-1", "RS.CO-2", "RS.MI-1"],
        atlas_ids=[],
        severity_focus="critical",
    ),
    SkillMeta(
        skill_id="incident-containment",
        name="Incident Containment Procedures",
        description=(
            "Execute containment actions for active incidents: network isolation, "
            "account disabling, endpoint quarantine, and preventing lateral spread."
        ),
        domain="incident-response",
        tags=["containment", "isolation", "quarantine", "network-block", "ir"],
        mitre_ids=["T1021", "T1071"],
        d3fend_ids=["D3-ITF", "D3-NTA"],
        nist_ids=["RS.MI-1", "RS.MI-2"],
        atlas_ids=[],
        severity_focus="critical",
    ),
    SkillMeta(
        skill_id="incident-eradication",
        name="Incident Eradication & Recovery",
        description=(
            "Remove attacker footholds, eradicate malware, rotate compromised credentials, "
            "patch exploited vulnerabilities, and restore systems from clean backups."
        ),
        domain="incident-response",
        tags=["eradication", "remediation", "recovery", "malware-removal", "credential-rotation"],
        mitre_ids=["T1078", "T1505"],
        d3fend_ids=["D3-FCSAM", "D3-UAM"],
        nist_ids=["RS.MI-3", "RC.RP-1"],
        atlas_ids=[],
        severity_focus="high",
    ),
    # ── digital-forensics (3 skills) ─────────────────────────────────────────
    SkillMeta(
        skill_id="memory-forensics",
        name="Memory Forensics Analysis",
        description=(
            "Acquire and analyze system memory for injected code, hidden processes, "
            "network connections, encryption keys, and malware artifacts using Volatility."
        ),
        domain="digital-forensics",
        tags=["memory-forensics", "volatility", "ram", "process-injection", "artifacts"],
        mitre_ids=["T1055", "T1003.001"],
        d3fend_ids=["D3-DA", "D3-FCSAM"],
        nist_ids=["DE.CM-1", "RS.AN-1"],
        atlas_ids=[],
        severity_focus="critical",
    ),
    SkillMeta(
        skill_id="disk-forensics",
        name="Disk & File System Forensics",
        description=(
            "Forensic analysis of disk images including MFT parsing, deleted file recovery, "
            "timeline analysis, browser artifacts, and prefetch/LNK file examination."
        ),
        domain="digital-forensics",
        tags=["disk-forensics", "mft", "deleted-files", "timeline", "artifacts", "prefetch"],
        mitre_ids=["T1005", "T1070"],
        d3fend_ids=["D3-FCSAM", "D3-DA"],
        nist_ids=["DE.CM-1", "RS.AN-1"],
        atlas_ids=[],
        severity_focus="high",
    ),
    SkillMeta(
        skill_id="log-analysis-forensics",
        name="Security Log Analysis & Forensics",
        description=(
            "Structured analysis of security logs (SIEM, syslog, Windows Event, web access) "
            "to reconstruct attack timelines and identify indicators of compromise."
        ),
        domain="digital-forensics",
        tags=["log-analysis", "siem", "windows-event", "ioc", "timeline", "forensics"],
        mitre_ids=["T1070.001", "T1562"],
        d3fend_ids=["D3-DA", "D3-NTA"],
        nist_ids=["DE.CM-1", "RS.AN-3"],
        atlas_ids=[],
        severity_focus="medium",
    ),
    # ── devsecops (4 skills) ──────────────────────────────────────────────────
    SkillMeta(
        skill_id="secrets-in-code",
        name="Secrets & Credential Detection in Source Code",
        description=(
            "Detect hardcoded API keys, passwords, tokens, and private keys in "
            "source code repositories using entropy analysis and pattern matching."
        ),
        domain="devsecops",
        tags=["secrets", "hardcoded", "api-key", "password", "token", "entropy", "cwe-798"],
        mitre_ids=["T1552", "T1552.001"],
        d3fend_ids=["D3-CRED", "D3-DA"],
        nist_ids=["PR.DS-5", "PR.AC-1"],
        atlas_ids=[],
        severity_focus="critical",
    ),
    SkillMeta(
        skill_id="supply-chain-integrity",
        name="Software Supply Chain Integrity Verification",
        description=(
            "Verify integrity of third-party dependencies using checksums, SBOM generation, "
            "provenance attestation, and detection of dependency confusion/typosquatting attacks."
        ),
        domain="devsecops",
        tags=["supply-chain", "sbom", "dependency", "provenance", "typosquatting", "cwe-494"],
        mitre_ids=["T1195.001", "T1195.002", "T1554"],
        d3fend_ids=["D3-SBOM", "D3-DA"],
        nist_ids=["ID.SC-4", "PR.DS-6"],
        atlas_ids=[],
        severity_focus="high",
    ),
    SkillMeta(
        skill_id="sast-pipeline-integration",
        name="SAST Pipeline Integration & Tuning",
        description=(
            "Integrate static application security testing into CI/CD pipelines with "
            "rule customization, false-positive reduction, and developer feedback loops."
        ),
        domain="devsecops",
        tags=["sast", "ci-cd", "pipeline", "false-positive", "semgrep", "codeql"],
        mitre_ids=["T1554", "T1195"],
        d3fend_ids=["D3-DA", "D3-SBOM"],
        nist_ids=["ID.SC-2", "PR.IP-2"],
        atlas_ids=[],
        severity_focus="medium",
    ),
    # ── container-security (3 skills) ────────────────────────────────────────
    SkillMeta(
        skill_id="docker-escape-detection",
        name="Container Escape Vulnerability Detection",
        description=(
            "Detect container escape paths including privileged containers, dangerous "
            "capabilities (SYS_ADMIN, SYS_PTRACE), mounted docker socket, and kernel exploits."
        ),
        domain="container-security",
        tags=["docker", "container-escape", "privileged", "capabilities", "nsenter", "cgroup"],
        mitre_ids=["T1611", "T1548.001"],
        d3fend_ids=["D3-ITF", "D3-NTA"],
        nist_ids=["PR.AC-3", "DE.CM-1"],
        atlas_ids=[],
        severity_focus="critical",
    ),
    SkillMeta(
        skill_id="k8s-rbac-audit",
        name="Kubernetes RBAC Security Audit",
        description=(
            "Audit Kubernetes RBAC configurations for overly permissive cluster-admin "
            "bindings, wildcard permissions, insecure service account token mounts."
        ),
        domain="container-security",
        tags=["kubernetes", "k8s", "rbac", "cluster-admin", "service-account", "wildcard"],
        mitre_ids=["T1078", "T1548"],
        d3fend_ids=["D3-UAM", "D3-HBPI"],
        nist_ids=["PR.AC-4", "DE.CM-3"],
        atlas_ids=[],
        severity_focus="high",
    ),
    SkillMeta(
        skill_id="container-image-scanning",
        name="Container Image Vulnerability Scanning",
        description=(
            "Scan container images for OS package CVEs, misconfigured Dockerfiles, "
            "exposed secrets in layers, and running as root in production containers."
        ),
        domain="container-security",
        tags=["image-scanning", "dockerfile", "os-cve", "root-container", "layers", "trivy"],
        mitre_ids=["T1195", "T1078"],
        d3fend_ids=["D3-SBOM", "D3-DA"],
        nist_ids=["ID.SC-4", "PR.IP-1"],
        atlas_ids=[],
        severity_focus="high",
    ),
    # ── cloud-security (3 skills) ─────────────────────────────────────────────
    SkillMeta(
        skill_id="iam-misconfiguration",
        name="Cloud IAM Misconfiguration Detection",
        description=(
            "Identify overly permissive IAM roles and policies in AWS/GCP/Azure: "
            "wildcard actions, cross-account trust misuse, and privilege escalation paths."
        ),
        domain="cloud-security",
        tags=["iam", "cloud", "aws", "gcp", "azure", "privilege-escalation", "policy"],
        mitre_ids=["T1078.004", "T1548", "T1537"],
        d3fend_ids=["D3-UAM", "D3-HBPI"],
        nist_ids=["PR.AC-4", "DE.CM-3"],
        atlas_ids=[],
        severity_focus="critical",
    ),
    SkillMeta(
        skill_id="s3-public-exposure",
        name="Cloud Object Storage Public Exposure Detection",
        description=(
            "Detect publicly exposed S3 buckets, GCS buckets, and Azure Blob containers "
            "through misconfigured ACLs, bucket policies, or missing block public access settings."
        ),
        domain="cloud-security",
        tags=["s3", "gcs", "blob", "public-bucket", "data-exposure", "acl", "cwe-732"],
        mitre_ids=["T1530", "T1213"],
        d3fend_ids=["D3-DA", "D3-DENCR"],
        nist_ids=["PR.DS-5", "DE.CM-1"],
        atlas_ids=[],
        severity_focus="critical",
    ),
    SkillMeta(
        skill_id="lambda-security-audit",
        name="Serverless/Lambda Security Audit",
        description=(
            "Audit serverless functions for overprivileged execution roles, "
            "environment variable secrets, insecure event triggers, and injection via event data."
        ),
        domain="cloud-security",
        tags=["lambda", "serverless", "function", "execution-role", "event-trigger", "env-vars"],
        mitre_ids=["T1078.004", "T1552.005", "T1190"],
        d3fend_ids=["D3-UAM", "D3-DA"],
        nist_ids=["PR.AC-4", "PR.DS-5"],
        atlas_ids=[],
        severity_focus="high",
    ),
    # ── malware-analysis (3 skills) ───────────────────────────────────────────
    SkillMeta(
        skill_id="static-malware-analysis",
        name="Static Malware Analysis",
        description=(
            "Perform static analysis of malware samples using disassembly, import table "
            "inspection, PE header analysis, string extraction, and YARA rule matching."
        ),
        domain="malware-analysis",
        tags=["static-analysis", "yara", "pe-header", "disassembly", "strings", "ioc"],
        mitre_ids=["T1027", "T1036", "T1204"],
        d3fend_ids=["D3-DA", "D3-FCSAM"],
        nist_ids=["DE.CM-4", "RS.AN-2"],
        atlas_ids=["AML.T0047"],
        severity_focus="critical",
    ),
    SkillMeta(
        skill_id="behavioral-malware-analysis",
        name="Behavioral Malware Analysis",
        description=(
            "Dynamic analysis of malware in sandbox environments: API call tracing, "
            "network communication capture, registry changes, and persistence mechanisms."
        ),
        domain="malware-analysis",
        tags=["behavioral-analysis", "sandbox", "api-calls", "network-capture", "registry"],
        mitre_ids=["T1055", "T1071", "T1547"],
        d3fend_ids=["D3-DA", "D3-NTA"],
        nist_ids=["DE.CM-4", "RS.AN-2"],
        atlas_ids=["AML.T0047"],
        severity_focus="critical",
    ),
    SkillMeta(
        skill_id="yara-rule-development",
        name="YARA Rule Development for Malware Detection",
        description=(
            "Develop effective YARA rules for malware family detection using byte sequences, "
            "PE characteristics, string patterns, and behavioral indicators."
        ),
        domain="malware-analysis",
        tags=["yara", "signatures", "malware-family", "byte-sequence", "detection"],
        mitre_ids=["T1027", "T1036"],
        d3fend_ids=["D3-DA", "D3-FCSAM"],
        nist_ids=["DE.CM-4", "DE.AE-2"],
        atlas_ids=[],
        severity_focus="high",
    ),
    # ── api-security (3 skills) ───────────────────────────────────────────────
    SkillMeta(
        skill_id="broken-object-level-auth",
        name="Broken Object-Level Authorization (BOLA) Detection",
        description=(
            "Detect BOLA/IDOR in REST APIs where object IDs in requests are not "
            "validated against the authenticated user's permissions. OWASP API Top 1."
        ),
        domain="api-security",
        tags=["bola", "api", "idor", "authorization", "rest", "owasp-api", "cwe-639"],
        mitre_ids=["T1078", "T1212"],
        d3fend_ids=["D3-HBPI", "D3-UAM"],
        nist_ids=["PR.AC-4", "DE.CM-3"],
        atlas_ids=[],
        severity_focus="critical",
    ),
    SkillMeta(
        skill_id="mass-assignment-detection",
        name="Mass Assignment / Parameter Tampering Detection",
        description=(
            "Detect mass assignment vulnerabilities where ORM/framework auto-binds request "
            "parameters to model objects, allowing modification of sensitive fields."
        ),
        domain="api-security",
        tags=["mass-assignment", "parameter-tampering", "orm", "api", "cwe-915"],
        mitre_ids=["T1190", "T1134"],
        d3fend_ids=["D3-DA", "D3-HBPI"],
        nist_ids=["PR.DS-2", "DE.CM-4"],
        atlas_ids=[],
        severity_focus="high",
    ),
    SkillMeta(
        skill_id="api-rate-limiting-audit",
        name="API Rate Limiting & Abuse Prevention Audit",
        description=(
            "Audit API endpoints for missing or bypassable rate limiting that enables "
            "credential stuffing, scraping, resource exhaustion, and enumeration attacks."
        ),
        domain="api-security",
        tags=["rate-limiting", "api", "dos", "credential-stuffing", "enumeration"],
        mitre_ids=["T1110", "T1499"],
        d3fend_ids=["D3-NTA", "D3-DA"],
        nist_ids=["PR.DS-4", "DE.CM-1"],
        atlas_ids=[],
        severity_focus="medium",
    ),
    # ── zero-trust-architecture (3 skills) ───────────────────────────────────
    SkillMeta(
        skill_id="network-segmentation-audit",
        name="Network Segmentation & Micro-Segmentation Audit",
        description=(
            "Validate network segmentation controls, verify east-west traffic policies, "
            "identify flat network segments, and assess software-defined perimeter implementations."
        ),
        domain="zero-trust-architecture",
        tags=["segmentation", "micro-segmentation", "east-west", "sdp", "network-policy"],
        mitre_ids=["T1021", "T1041"],
        d3fend_ids=["D3-NTA", "D3-ITF"],
        nist_ids=["PR.AC-3", "PR.AC-5"],
        atlas_ids=[],
        severity_focus="high",
    ),
    SkillMeta(
        skill_id="pep-enforcement",
        name="Policy Enforcement Point (PEP) Validation",
        description=(
            "Validate Zero Trust Policy Enforcement Points for continuous verification, "
            "device posture assessment, just-in-time access, and per-request authorization."
        ),
        domain="zero-trust-architecture",
        tags=["pep", "zero-trust", "continuous-verification", "jit-access", "device-posture"],
        mitre_ids=["T1078", "T1134"],
        d3fend_ids=["D3-UAM", "D3-HBPI"],
        nist_ids=["PR.AC-4", "PR.AC-6", "PR.AC-7"],
        atlas_ids=[],
        severity_focus="high",
    ),
    SkillMeta(
        skill_id="microsegmentation-implementation",
        name="Microsegmentation Deployment & Verification",
        description=(
            "Implement and verify microsegmentation using service mesh (Istio/Linkerd), "
            "Kubernetes NetworkPolicies, and host-based firewall rules for workload isolation."
        ),
        domain="zero-trust-architecture",
        tags=["microsegmentation", "istio", "service-mesh", "network-policy", "workload-isolation"],
        mitre_ids=["T1021", "T1046"],
        d3fend_ids=["D3-NTA", "D3-ITF"],
        nist_ids=["PR.AC-5", "PR.AC-3"],
        atlas_ids=[],
        severity_focus="medium",
    ),
]


# ─────────────────────────────────────────────────────────────────────────────
# Full SkillContent definitions for 5 key skills
# ─────────────────────────────────────────────────────────────────────────────

def _make_skill_content_sql_injection() -> SkillContent:
    meta = next(s for s in _EMBEDDED_SKILLS if s.skill_id == "sql-injection-hunting")
    return SkillContent(
        meta=meta,
        prerequisites=[
            "Access to web application source code or deployed application",
            "Database schema knowledge (if available)",
            "Web application firewall (WAF) logs and database audit logs",
            "SIEM access for query correlation",
        ],
        workflow_steps=[
            "1. Identify all database query entry points: ORM calls, raw SQL, stored procedures",
            "2. Map user-controlled inputs that flow into query construction (taint analysis)",
            "3. Check for parameterized queries / prepared statements usage",
            "4. Review ORM configurations for raw() or extra() calls with unsanitized input",
            "5. Scan web/application logs for UNION SELECT, OR 1=1, comment sequences (--/;--)",
            "6. Test identified endpoints with basic payloads: single quote, comment injection",
            "7. Attempt blind SQLi using boolean-based (AND 1=1 vs AND 1=2) and time-based (SLEEP/WAITFOR)",
            "8. Check error messages for database stack traces revealing table/column names",
            "9. Correlate findings with HUNT-007 Splunk/SIEM queries for evidence in logs",
            "10. Document exploitability chain from user input to unauthorized data access",
        ],
        verification_steps=[
            "Confirm parameterized queries are used for all dynamic SQL construction",
            "Verify ORM layer does not accept raw SQL from user input",
            "Validate WAF rules block common SQLi payloads and test bypass techniques",
            "Check that error messages do not expose database internals in production",
            "Review database user privileges: application account should use least privilege",
            "Test with sqlmap using safe mode to confirm exploitability without data extraction",
            "Verify database audit logging captures all failed query attempts",
        ],
        remediation=[
            "Replace string concatenation SQL with parameterized queries or ORM methods",
            "Apply allow-list input validation on all user-supplied values",
            "Enforce least-privilege database accounts (SELECT-only where applicable)",
            "Deploy WAF rules with OWASP CRS SQLi ruleset",
            "Enable database query logging and alert on suspicious patterns",
            "Conduct code review training on secure query patterns for the development team",
        ],
        sigma_queries=[
            """title: SQL Injection Attempt in Web Logs
status: experimental
logsource:
  category: webserver
detection:
  selection:
    cs-uri-query|contains:
      - "' OR '"
      - "UNION SELECT"
      - ";DROP"
      - "1=1"
      - "--"
      - "/*"
  condition: selection
falsepositives:
  - Security scanner activity
  - Penetration testing
level: high
tags:
  - attack.initial_access
  - attack.t1190""",
        ],
        kql_queries=[
            """DeviceNetworkEvents
| where RemoteUrl contains "UNION" and RemoteUrl contains "SELECT"
    or RemoteUrl contains "' OR '" or RemoteUrl contains "--"
| project Timestamp, DeviceName, RemoteUrl, InitiatingProcessFileName
| order by Timestamp desc""",
        ],
    )


def _make_skill_content_credential_dumping() -> SkillContent:
    meta = next(s for s in _EMBEDDED_SKILLS if s.skill_id == "credential-dumping-hunt")
    return SkillContent(
        meta=meta,
        prerequisites=[
            "EDR/AV telemetry covering target endpoints",
            "Windows Event Log access (Security, System logs)",
            "SIEM with process creation events (Sysmon Event IDs 1, 10)",
            "Memory analysis capability (Volatility) for offline analysis",
        ],
        workflow_steps=[
            "1. Query Sysmon Event ID 10 (ProcessAccess) for lsass.exe as target process",
            "2. Search for known credential dumping tool names: mimikatz, procdump, wce, pwdump",
            "3. Hunt for suspicious LSASS memory read patterns: OpenProcess with PROCESS_VM_READ",
            "4. Check for NTDS.dit access patterns: vssadmin create shadow, ntdsutil",
            "5. Examine SAM hive access via reg save HKLM\\SAM or esentutl",
            "6. Review PowerShell transcripts for Invoke-Mimikatz, sekurlsa, Get-GPPPassword",
            "7. Detect comsvcs.dll MiniDump calls: rundll32 comsvcs.dll MiniDump <lsass_pid>",
            "8. Look for Task Manager creating lsass.DMP in unusual directories",
            "9. Correlate with subsequent lateral movement activity (new logon events from different hosts)",
            "10. Check for credential use within 30 minutes of suspected dump activity",
        ],
        verification_steps=[
            "Confirm LSASS process access came from non-security product processes",
            "Verify Credential Guard / Protected Users group settings on affected systems",
            "Check if Sysmon is deployed with Rule 10 (ProcessAccess) targeting lsass",
            "Validate Windows Defender Credential Guard enrollment on domain controllers",
            "Review security event 4624/4625 for anomalous authentication patterns post-hunt",
            "Confirm no scheduled tasks or services were created using harvested credentials",
        ],
        remediation=[
            "Enable Windows Defender Credential Guard on all eligible systems",
            "Add LSASS to Protected Process Light (PPL) via registry or Group Policy",
            "Deploy Sysmon with ProcessAccess rules targeting lsass.exe",
            "Remove debug privilege from non-administrative accounts",
            "Enable ASR (Attack Surface Reduction) rule blocking LSASS credential theft",
            "Enforce tiered administration model to limit credential exposure",
            "Rotate all credentials for accounts with confirmed access from compromised hosts",
        ],
        sigma_queries=[
            """title: LSASS Memory Access by Suspicious Process
status: stable
logsource:
  product: windows
  category: process_access
detection:
  selection:
    TargetImage|endswith: '\\lsass.exe'
    GrantedAccess|contains:
      - '0x1010'
      - '0x1410'
      - '0x147a'
      - '0x143a'
  filter_legit:
    SourceImage|contains:
      - '\\Windows\\System32\\'
      - '\\Windows\\SysWOW64\\'
  condition: selection and not filter_legit
falsepositives:
  - EDR/AV products
  - Monitoring tools with legitimate LSASS access
level: critical
tags:
  - attack.credential_access
  - attack.t1003.001""",
        ],
        kql_queries=[
            """DeviceProcessEvents
| where FileName =~ "mimikatz.exe" or ProcessCommandLine has_any ("sekurlsa", "lsadump", "MiniDump")
    or (ProcessCommandLine has "lsass" and ProcessCommandLine has "procdump")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc""",
        ],
    )


def _make_skill_content_xss() -> SkillContent:
    meta = next(s for s in _EMBEDDED_SKILLS if s.skill_id == "xss-detection")
    return SkillContent(
        meta=meta,
        prerequisites=[
            "Access to web application source code for static analysis",
            "Running web application instance for dynamic testing",
            "Browser developer tools for DOM-based XSS analysis",
            "Web proxy (Burp Suite/ZAP) for intercepting requests",
        ],
        workflow_steps=[
            "1. Enumerate all input reflection points: URL parameters, form fields, HTTP headers, JSON fields",
            "2. Identify HTML sinks: innerHTML, document.write, eval, setTimeout with string arg",
            "3. Check output encoding functions applied to user data before HTML rendering",
            "4. Test reflected XSS: inject <script>alert(1)</script> in all reflected parameters",
            "5. Probe stored XSS in all persistent data fields rendered to other users",
            "6. Analyze JavaScript sources for DOM-based sinks: location.hash, document.URL, postMessage",
            "7. Evaluate Content Security Policy headers for bypass opportunities (unsafe-inline, data:)",
            "8. Test CSP bypass with JSONP endpoints, Angular template injection, or trusted domains",
            "9. Check httpOnly and Secure cookie flags on session tokens",
            "10. Assess impact: can the XSS access session cookies, escalate to CSRF, or access sensitive DOM data",
        ],
        verification_steps=[
            "Confirm output encoding is applied in all rendering contexts (HTML, JS, URL, CSS)",
            "Verify Content Security Policy denies inline scripts and untrusted sources",
            "Check that X-XSS-Protection header is set (legacy browsers)",
            "Validate template engine auto-escaping is enabled and not disabled locally",
            "Ensure DOM manipulation uses textContent / setAttribute instead of innerHTML for user data",
            "Test that CSP report-uri receives violation reports in staging environment",
        ],
        remediation=[
            "Apply context-aware output encoding using libraries (e.g., OWASP Java Encoder, DOMPurify)",
            "Implement strict Content Security Policy: default-src 'self'; script-src 'self'",
            "Enable template engine auto-escaping globally; explicitly mark trusted content",
            "Replace innerHTML assignments with textContent or createElement for user data",
            "Set HttpOnly and Secure flags on all session cookies",
            "Deploy WAF rules blocking common XSS payloads as defense-in-depth",
        ],
        sigma_queries=[
            """title: XSS Payload in Web Request
status: experimental
logsource:
  category: webserver
detection:
  selection:
    cs-uri-query|contains:
      - '<script>'
      - 'javascript:'
      - 'onerror='
      - 'onload='
      - 'alert('
  condition: selection
level: medium
tags:
  - attack.t1059.007""",
        ],
        kql_queries=[
            """DeviceNetworkEvents
| where RemoteUrl matches regex @".*(<script>|javascript:|onerror=|onload=).*"
| project Timestamp, DeviceName, RemoteUrl
| order by Timestamp desc""",
        ],
    )


def _make_skill_content_supply_chain() -> SkillContent:
    meta = next(s for s in _EMBEDDED_SKILLS if s.skill_id == "supply-chain-integrity")
    return SkillContent(
        meta=meta,
        prerequisites=[
            "Access to project dependency manifests (package.json, requirements.txt, pom.xml, go.mod)",
            "SBOM generation tooling (Syft, CycloneDX CLI, or OSV-Scanner)",
            "Access to internal package registry or artifact manager",
            "VCS access for dependency commit history review",
        ],
        workflow_steps=[
            "1. Generate comprehensive SBOM for the project in CycloneDX JSON format",
            "2. Cross-reference all dependencies against OSV (Open Source Vulnerabilities) database",
            "3. Check for dependency confusion: verify internal package names do not exist on public registries",
            "4. Audit transitive dependencies for unexpected new maintainers or ownership changes",
            "5. Verify package checksums/hashes match published registry values (lock file integrity)",
            "6. Check for typosquatting: scan dependency names for common substitution patterns",
            "7. Review packages with high permissions (install scripts, postinstall hooks)",
            "8. Verify build artifact provenance using SLSA attestation if available",
            "9. Audit CI/CD pipeline for pinned action versions vs mutable tags (@v3 vs @sha256)",
            "10. Check for direct GitHub source dependencies bypassing registry security controls",
        ],
        verification_steps=[
            "Confirm lock files are committed to version control and not gitignored",
            "Verify package registry allows only approved, verified packages (private mirror)",
            "Check that CI/CD enforces checksum verification before installing dependencies",
            "Validate SBOM completeness: all direct and transitive deps are listed",
            "Confirm GitHub Actions use pinned SHA hashes for third-party actions",
            "Review npm/PyPI publishing tokens have MFA enabled",
        ],
        remediation=[
            "Pin all dependencies to exact versions with checksum verification in lock files",
            "Use a private package mirror (Artifactory, Nexus) with upstream sync and scanning",
            "Implement dependency allow-list policies in CI/CD pipelines",
            "Generate and publish SBOM as part of every release for customer transparency",
            "Enable Dependabot or Renovate for automated dependency update PRs",
            "Sign release artifacts with Sigstore/cosign and publish SLSA provenance",
        ],
        sigma_queries=[
            """title: Suspicious npm Registry Access from Non-Standard Process
status: experimental
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith: '.npmjs.org'
  filter_npm:
    Image|endswith:
      - '\\node.exe'
      - '\\npm.cmd'
      - '\\yarn.js'
  condition: selection and not filter_npm
level: medium
tags:
  - attack.t1195.001""",
        ],
        kql_queries=[
            """DeviceNetworkEvents
| where RemoteUrl contains "npmjs.org" or RemoteUrl contains "pypi.org"
| where InitiatingProcessFileName !in~ ("node.exe", "python.exe", "pip.exe", "yarn")
| project Timestamp, DeviceName, RemoteUrl, InitiatingProcessFileName
| order by Timestamp desc""",
        ],
    )


def _make_skill_content_incident_triage() -> SkillContent:
    meta = next(s for s in _EMBEDDED_SKILLS if s.skill_id == "incident-triage")
    return SkillContent(
        meta=meta,
        prerequisites=[
            "Incident response policy and escalation matrix",
            "SIEM access with normalized log data",
            "Asset inventory with criticality ratings",
            "On-call security team availability",
            "Documented runbooks for common incident types",
        ],
        workflow_steps=[
            "1. Receive alert/report and assign an incident tracking ID (INC-YYYYMMDD-NNN)",
            "2. Classify initial severity using CVSS base score + asset criticality matrix (P1-P4)",
            "3. Identify affected assets: hostname, IP, user account, application, business unit",
            "4. Preserve initial evidence: capture log snapshots, memory if appropriate, network flows",
            "5. Determine incident type: malware, data breach, unauthorized access, DDoS, insider threat",
            "6. Notify required stakeholders per escalation matrix within SLA window",
            "7. Establish incident Slack/Teams channel and assign IR lead",
            "8. Query SIEM for initial IOCs: source IP, hash, domain, user account across 72hr window",
            "9. Assess scope: number of systems affected, data potentially exposed, business impact",
            "10. Decide on immediate containment triggers: isolate endpoint, block IP, disable account",
            "11. Document all findings in ticketing system (JIRA/ServiceNow) with timestamps",
            "12. Determine if external reporting obligations apply (GDPR 72hr, PCI, SOX, HIPAA)",
        ],
        verification_steps=[
            "Confirm incident severity classification is consistent with classification matrix",
            "Verify all affected systems and user accounts have been identified",
            "Check that evidence preservation steps did not modify original artifacts",
            "Confirm stakeholder notifications were sent within required SLA timeframes",
            "Validate that containment actions did not disrupt critical business processes",
            "Verify external reporting deadlines have been identified and calendared",
        ],
        remediation=[
            "Complete post-incident review within 5 business days using lessons-learned template",
            "Update detection rules based on TTPs observed during incident",
            "Document gaps in visibility identified during investigation",
            "Review and update incident response playbooks based on findings",
            "Conduct tabletop exercises for similar incident scenarios with stakeholders",
        ],
        sigma_queries=[
            """title: Multiple Failed Logins Followed by Success (Credential Stuffing)
status: stable
logsource:
  product: windows
  service: security
detection:
  selection_failure:
    EventID: 4625
  selection_success:
    EventID: 4624
  timeframe: 5m
  condition: selection_failure | count(IpAddress) by IpAddress > 10
falsepositives:
  - Legitimate user after lockout
level: high
tags:
  - attack.t1110""",
        ],
        kql_queries=[
            """IdentityLogonEvents
| where ActionType == "LogonFailed"
| summarize FailCount=count() by AccountUpn, IPAddress, bin(Timestamp, 10m)
| where FailCount > 10
| join kind=inner (
    IdentityLogonEvents | where ActionType == "LogonSuccess"
  ) on AccountUpn
| project Timestamp, AccountUpn, IPAddress, FailCount
| order by Timestamp desc""",
        ],
    )


# ─────────────────────────────────────────────────────────────────────────────
# Generic SkillContent builder for remaining skills
# ─────────────────────────────────────────────────────────────────────────────

_GENERIC_CONTENT_MAP: Dict[str, SkillContent] = {}


def _build_generic_skill_content(meta: SkillMeta) -> SkillContent:
    """Build a real (non-placeholder) SkillContent for skills without a full definition."""
    domain = meta.domain
    sid = meta.skill_id

    # Domain-aware workflow templates
    _workflow_templates: Dict[str, List[str]] = {
        "web-application-security": [
            f"1. Enumerate application entry points relevant to {meta.name}",
            "2. Identify user-controlled input fields and request parameters",
            "3. Review source code for insecure patterns using SAST tooling",
            "4. Perform dynamic testing against staging environment",
            "5. Document exploitation scenarios with proof-of-concept payloads",
            "6. Assess data sensitivity and business impact of exploitation",
            "7. Correlate with related vulnerabilities for attack chain analysis",
        ],
        "threat-hunting": [
            f"1. Define threat hypothesis for {meta.name}",
            "2. Collect and normalize relevant log sources in SIEM",
            "3. Apply detection queries across 30-day baseline period",
            "4. Triage results, separating true positives from benign activity",
            "5. Pivot on confirmed findings to expand scope of investigation",
            "6. Document confirmed TTPs with ATT&CK framework mapping",
            "7. Tune detection rules to reduce false positive rate below 5%",
        ],
        "cryptography": [
            f"1. Inventory all cryptographic operations relevant to {meta.name}",
            "2. Identify cryptographic algorithm, key size, and mode of operation",
            "3. Verify compliance with organization cryptographic standards",
            "4. Test for implementation weaknesses using cryptographic analysis tools",
            "5. Check for known CVEs affecting the cryptographic library in use",
            "6. Assess data sensitivity protected by the cryptographic control",
            "7. Document remediation path with migration timeline",
        ],
        "identity-access-management": [
            f"1. Map all authentication and authorization flows for {meta.name}",
            "2. Review identity provider configuration and federation settings",
            "3. Audit user and service account privileges against need-to-know",
            "4. Test authentication bypass scenarios and privilege escalation paths",
            "5. Review session management implementation and token security",
            "6. Verify MFA enforcement coverage and bypass resistance",
            "7. Document gaps against identity security framework requirements",
        ],
        "incident-response": [
            f"1. Activate incident response procedures for {meta.name}",
            "2. Establish communication channels and assign team roles",
            "3. Collect and preserve digital evidence per chain of custody",
            "4. Perform root cause analysis and timeline reconstruction",
            "5. Execute containment, eradication, and recovery actions",
            "6. Validate remediation effectiveness through re-testing",
            "7. Produce incident report and lessons-learned documentation",
        ],
        "digital-forensics": [
            f"1. Acquire forensic images/artifacts relevant to {meta.name}",
            "2. Verify acquisition integrity using cryptographic hashes",
            "3. Mount artifacts in read-only forensic environment",
            "4. Extract and parse relevant forensic artifacts",
            "5. Build event timeline from multiple data sources",
            "6. Identify and document indicators of compromise",
            "7. Produce forensic report with findings and methodology",
        ],
        "devsecops": [
            f"1. Integrate {meta.name} checks into CI/CD pipeline",
            "2. Configure scanning tools with project-specific rule sets",
            "3. Establish baseline of existing findings for prioritization",
            "4. Define quality gates: block on critical/high severity findings",
            "5. Triage existing findings and assign remediation owners",
            "6. Track remediation progress in security backlog",
            "7. Report metrics: mean time to remediate by severity",
        ],
        "container-security": [
            f"1. Enumerate container images and running workloads for {meta.name}",
            "2. Scan images for OS and application CVEs",
            "3. Review Dockerfile and Kubernetes manifests for misconfigurations",
            "4. Audit RBAC bindings and service account permissions",
            "5. Check for overly permissive capabilities and host path mounts",
            "6. Validate network policies restrict inter-pod communication",
            "7. Verify container runtime security profiles (seccomp, AppArmor)",
        ],
        "cloud-security": [
            f"1. Enumerate cloud resources and configurations for {meta.name}",
            "2. Run cloud security posture management (CSPM) scan",
            "3. Review IAM policies for wildcard permissions and privilege escalation",
            "4. Check for public exposure of storage, databases, and compute",
            "5. Audit logging configuration: CloudTrail, VPC Flow Logs, Security Hub",
            "6. Assess network security groups and firewall rules",
            "7. Validate encryption at rest and in transit configurations",
        ],
        "malware-analysis": [
            f"1. Receive and document sample metadata for {meta.name}",
            "2. Calculate cryptographic hashes and check threat intel platforms",
            "3. Perform static analysis: strings, imports, PE headers, packing",
            "4. Execute in isolated sandbox environment with full monitoring",
            "5. Analyze behavioral indicators: files, registry, network, processes",
            "6. Develop YARA rules from unique indicators",
            "7. Produce analysis report with IOCs and ATT&CK TTP mapping",
        ],
        "api-security": [
            f"1. Enumerate all API endpoints from OpenAPI spec or crawling for {meta.name}",
            "2. Review authentication and authorization implementation per endpoint",
            "3. Test object-level authorization with cross-user object access",
            "4. Check input validation and schema enforcement",
            "5. Test rate limiting effectiveness and bypass techniques",
            "6. Review sensitive data exposure in responses",
            "7. Validate error responses do not leak internal implementation details",
        ],
        "zero-trust-architecture": [
            f"1. Map current network topology and trust boundaries for {meta.name}",
            "2. Identify implicit trust relationships to be eliminated",
            "3. Define workload identities and microsegmentation policies",
            "4. Implement continuous verification for all access requests",
            "5. Deploy mutual TLS for service-to-service communication",
            "6. Validate policy enforcement with authorized and unauthorized traffic tests",
            "7. Monitor and refine policies based on access pattern analytics",
        ],
    }

    _verification_templates: Dict[str, List[str]] = {
        "web-application-security": [
            f"Confirm all {meta.name.lower()} attack vectors are addressed",
            "Verify secure coding practices are documented and followed",
            "Validate WAF rules cover identified attack patterns",
            "Check security headers are correctly configured",
            "Confirm developer security training covers identified weakness class",
        ],
        "threat-hunting": [
            "Confirm detection coverage for identified TTPs",
            "Verify alert fidelity: false positive rate below acceptable threshold",
            "Validate SIEM log sources are complete and normalized",
            "Check that analyst runbooks cover confirmed threat scenarios",
            "Confirm detection gaps are documented in risk register",
        ],
        "cryptography": [
            "Confirm migration from deprecated algorithms is complete",
            "Verify new cryptographic implementation passes known-answer tests",
            "Validate key management procedures meet compliance requirements",
            "Check cryptographic agility is maintained for future migrations",
        ],
        "identity-access-management": [
            "Confirm access review has been completed for affected accounts",
            "Verify MFA enrollment meets coverage targets",
            "Validate privileged access management controls are operational",
            "Check identity governance policies are enforced",
        ],
        "incident-response": [
            "Confirm all IOCs are blocked across detection layers",
            "Verify system integrity after recovery actions",
            "Validate monitoring coverage prevents recurrence",
            "Check post-incident report is complete and distributed",
        ],
        "digital-forensics": [
            "Verify chain of custody documentation is complete",
            "Confirm forensic artifacts are preserved and hashed",
            "Validate timeline reconstruction is corroborated by multiple sources",
            "Check that all identified IOCs are communicated to security operations",
        ],
        "devsecops": [
            "Confirm CI/CD quality gates are blocking on policy violations",
            "Verify developer feedback is actionable within the IDE",
            "Validate scan coverage includes all code repositories",
            "Check metrics dashboards are updated and reviewed weekly",
        ],
        "container-security": [
            "Confirm no privileged containers are running in production",
            "Verify image scanning is integrated into build pipeline",
            "Validate network policies deny traffic by default",
            "Check runtime security monitoring is active on all nodes",
        ],
        "cloud-security": [
            "Confirm no resources have public access without explicit business justification",
            "Verify logging and monitoring configuration is complete",
            "Validate IAM policies follow least privilege principle",
            "Check compliance findings are tracked in remediation backlog",
        ],
        "malware-analysis": [
            "Confirm all IOCs from analysis are deployed to detection tools",
            "Verify YARA rules have acceptable false positive rate in production",
            "Validate malware family classification against threat intel",
            "Check sandbox analysis completeness with known-malware samples",
        ],
        "api-security": [
            "Confirm all API endpoints require authentication",
            "Verify authorization checks are present for every resource operation",
            "Validate rate limiting thresholds are appropriate and enforced",
            "Check API security headers are correctly configured",
        ],
        "zero-trust-architecture": [
            "Confirm implicit trust relationships have been eliminated",
            "Verify microsegmentation policies are enforced correctly",
            "Validate continuous verification is operational for all access",
            "Check device posture assessment is included in access decisions",
        ],
    }

    # Default sigma query template based on domain
    _sigma_template = f"""title: {meta.name} Detection
status: experimental
logsource:
  category: {'webserver' if 'web' in domain else 'process_creation' if 'threat' in domain or 'malware' in domain else 'application'}
detection:
  selection:
    EventID|contains: '{meta.skill_id}'
  condition: selection
falsepositives:
  - Security testing
level: {'critical' if meta.severity_focus == 'critical' else 'high' if meta.severity_focus == 'high' else 'medium'}
tags:
  - {'attack.' + meta.mitre_ids[0].lower().replace('-', '_') if meta.mitre_ids else 'attack.execution'}"""

    _kql_template = f"""// {meta.name} KQL Hunt Query
// Technique: {', '.join(meta.mitre_ids) if meta.mitre_ids else 'N/A'}
DeviceEvents
| where ActionType contains "{meta.skill_id.split('-')[0]}"
| project Timestamp, DeviceName, AccountName, AdditionalFields
| order by Timestamp desc
| take 1000"""

    workflow = _workflow_templates.get(domain, [
        f"1. Assess scope of {meta.name} engagement",
        "2. Collect relevant data sources and artifacts",
        "3. Apply automated and manual analysis techniques",
        "4. Document and prioritize findings by risk",
        "5. Develop and validate remediation recommendations",
        "6. Report findings to stakeholders with evidence",
        "7. Verify remediation effectiveness after implementation",
    ])

    verification = _verification_templates.get(domain, [
        f"Confirm {meta.name} objectives have been fully addressed",
        "Verify findings documentation is complete and accurate",
        "Validate remediation actions are implemented correctly",
        "Check that monitoring covers identified risk areas",
    ])

    return SkillContent(
        meta=meta,
        prerequisites=[
            f"Appropriate access permissions for {domain.replace('-', ' ')} assessment",
            "Relevant tooling and environment access",
            "Knowledge of target system architecture and technology stack",
        ],
        workflow_steps=workflow,
        verification_steps=verification,
        remediation=[
            f"Address identified {meta.severity_focus}-severity findings within SLA",
            "Apply security controls aligned with identified NIST controls: " + ", ".join(meta.nist_ids),
            "Reference ATT&CK mitigations for: " + ", ".join(meta.mitre_ids),
            "Update security monitoring to cover identified gaps",
            "Conduct lessons-learned review and update policies accordingly",
        ],
        sigma_queries=[_sigma_template],
        kql_queries=[_kql_template],
    )


# ─────────────────────────────────────────────────────────────────────────────
# SkillsLoader
# ─────────────────────────────────────────────────────────────────────────────

class SkillsLoader:
    """
    Offline skills registry providing search, lookup, and framework-based queries
    over an embedded set of 40 cybersecurity skills.
    """

    def __init__(self) -> None:
        self._skills: List[SkillMeta] = _EMBEDDED_SKILLS

        # Build full SkillContent for all 5 detailed skills
        _detailed = {
            "sql-injection-hunting": _make_skill_content_sql_injection(),
            "credential-dumping-hunt": _make_skill_content_credential_dumping(),
            "xss-detection": _make_skill_content_xss(),
            "supply-chain-integrity": _make_skill_content_supply_chain(),
            "incident-triage": _make_skill_content_incident_triage(),
        }

        self._content_cache: Dict[str, SkillContent] = dict(_detailed)

        # Pre-build generic content for the remaining skills
        for meta in self._skills:
            if meta.skill_id not in self._content_cache:
                self._content_cache[meta.skill_id] = _build_generic_skill_content(meta)

        # Inverted indexes
        self._by_domain: Dict[str, List[SkillMeta]] = {}
        self._by_attck: Dict[str, List[SkillMeta]] = {}
        self._by_d3fend: Dict[str, List[SkillMeta]] = {}
        self._by_nist: Dict[str, List[SkillMeta]] = {}
        self._by_atlas: Dict[str, List[SkillMeta]] = {}

        for skill in self._skills:
            self._by_domain.setdefault(skill.domain, []).append(skill)
            for tid in skill.mitre_ids:
                self._by_attck.setdefault(tid.upper(), []).append(skill)
            for did in skill.d3fend_ids:
                self._by_d3fend.setdefault(did.upper(), []).append(skill)
            for nid in skill.nist_ids:
                self._by_nist.setdefault(nid.upper(), []).append(skill)
            for aid in skill.atlas_ids:
                self._by_atlas.setdefault(aid.upper(), []).append(skill)

    # ── public API ────────────────────────────────────────────────────────────

    def scan_all(self, query: str, top_n: int = 5) -> List[SkillMeta]:
        """
        Tokenize query and score each skill by keyword matches across
        description, tags, and name.  Returns top_n skills by score.
        """
        # Empty query returns all skills up to top_n
        if not query.strip():
            return list(self._skills[:top_n])

        tokens = set(re.findall(r"[a-zA-Z0-9]+", query.lower()))
        if not tokens:
            return list(self._skills[:top_n])

        scored: List[tuple] = []
        for skill in self._skills:
            searchable = (
                skill.name.lower()
                + " "
                + skill.description.lower()
                + " "
                + " ".join(skill.tags)
                + " "
                + skill.domain.lower()
                + " "
                + " ".join(skill.mitre_ids).lower()
            )
            score = sum(1 for tok in tokens if tok in searchable)
            if score > 0:
                scored.append((score, skill))

        # Fall back to returning all skills if no match
        if not scored:
            return list(self._skills[:top_n])

        scored.sort(key=lambda x: x[0], reverse=True)
        return [s for _, s in scored[:top_n]]

    def load_skill(self, skill_name: str) -> Optional[SkillContent]:
        """
        Find a skill by name or skill_id (case-insensitive) and return
        its full SkillContent.
        """
        key = skill_name.strip().lower()
        for skill in self._skills:
            if skill.skill_id.lower() == key or skill.name.lower() == key:
                return self._content_cache.get(skill.skill_id)
        return None

    def search_by_framework(self, framework: str, id: str) -> List[SkillMeta]:
        """
        Return skills tagged with a specific framework identifier.

        framework: "ATT&CK" | "D3FEND" | "NIST" | "ATLAS"
        id: e.g. "T1190", "D3-DA", "PR.DS-1", "AML.T0047"
        """
        fw = framework.upper().replace("&", "").replace("ATTCK", "ATT&CK")
        lookup_id = id.strip().upper()

        if "ATT" in fw or "ATTCK" in fw.replace("&", "") or fw == "ATT&CK":
            index = self._by_attck
        elif "D3FEND" in fw or "D3" in fw:
            index = self._by_d3fend
        elif "NIST" in fw:
            index = self._by_nist
        elif "ATLAS" in fw:
            index = self._by_atlas
        else:
            return []

        # Exact match first
        results = index.get(lookup_id, [])
        if results:
            return list(results)

        # Prefix match (e.g. "T1059" matches "T1059.001")
        results = []
        for key, skills in index.items():
            if key.startswith(lookup_id) or lookup_id.startswith(key):
                for skill in skills:
                    if skill not in results:
                        results.append(skill)
        return results

    def search_by_domain(self, domain: str) -> List[SkillMeta]:
        """
        Return skills matching domain (exact or partial, case-insensitive).
        """
        domain_lower = domain.strip().lower()
        # Exact match
        for key, skills in self._by_domain.items():
            if key.lower() == domain_lower:
                return list(skills)
        # Partial match
        results = []
        for key, skills in self._by_domain.items():
            if domain_lower in key.lower() or key.lower() in domain_lower:
                for skill in skills:
                    if skill not in results:
                        results.append(skill)
        return results

    # ── convenience ───────────────────────────────────────────────────────────

    def list_domains(self) -> List[str]:
        """Return all unique domains in the registry."""
        return sorted(self._by_domain.keys())

    def list_all(self) -> List[SkillMeta]:
        """Return all skills in the registry."""
        return list(self._skills)
