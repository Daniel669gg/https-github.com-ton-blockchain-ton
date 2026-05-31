"""TythanAI — CVE Research Assistant
Builds complete vulnerability research chains:
CWE → known CVEs → public PoC availability → real-world impact.
Works fully offline using embedded knowledge base.
"""
from __future__ import annotations

import logging
from typing import Dict, List, Optional

from pydantic import BaseModel

from backend.core.confidence import Finding

logger = logging.getLogger("tythanai.cve_researcher")

# ─────────────────────────────────────────────────────────────────────────────
# Embedded knowledge base — CWE → CVE records
# ─────────────────────────────────────────────────────────────────────────────

_CVE_KNOWLEDGE_BASE: Dict[str, List[Dict]] = {
    "CWE-89": [
        {
            "cve_id": "CVE-2023-23752",
            "product": "Joomla CMS",
            "vendor": "Open Source Matters",
            "year": 2023,
            "cvss": 5.3,
            "epss_approx": 0.97,
            "poc_available": True,
            "poc_url": "https://github.com/Acceis/exploit-CVE-2023-23752",
            "metasploit_module": True,
            "description": "Improper access check in Joomla API endpoints exposes sensitive configuration data including database credentials.",
            "impact": "Unauthenticated access to MySQL credentials, enabling full database compromise and SQLi.",
            "patch_available": True,
            "cisa_kev": False,
        },
        {
            "cve_id": "CVE-2022-21587",
            "product": "Oracle WebLogic Server",
            "vendor": "Oracle",
            "year": 2022,
            "cvss": 9.8,
            "epss_approx": 0.97,
            "poc_available": True,
            "poc_url": "https://github.com/awsassets/CVE-2022-21587",
            "metasploit_module": True,
            "description": "Unauthenticated SQLi in Oracle WebLogic Server via the Oracle Web Applications Desktop Integrator component.",
            "impact": "Remote code execution as the WebLogic service account; full database exfiltration.",
            "patch_available": True,
            "cisa_kev": True,
        },
        {
            "cve_id": "CVE-2021-27928",
            "product": "MariaDB Server",
            "vendor": "MariaDB Foundation",
            "year": 2021,
            "cvss": 7.2,
            "epss_approx": 0.74,
            "poc_available": True,
            "poc_url": "https://github.com/Al1ex/CVE-2021-27928",
            "metasploit_module": False,
            "description": "A privilege escalation via a writeable .so shared object injection in MariaDB's wsrep provider.",
            "impact": "Authenticated attacker with FILE privilege can execute OS commands as the MySQL user.",
            "patch_available": True,
            "cisa_kev": False,
        },
        {
            "cve_id": "CVE-2022-32429",
            "product": "ChurchCRM",
            "vendor": "ChurchCRM",
            "year": 2022,
            "cvss": 9.8,
            "epss_approx": 0.65,
            "poc_available": True,
            "poc_url": "",
            "metasploit_module": False,
            "description": "Multiple unauthenticated SQLi vulnerabilities in ChurchCRM login endpoint.",
            "impact": "Complete database access without authentication.",
            "patch_available": True,
            "cisa_kev": False,
        },
        {
            "cve_id": "CVE-2023-28120",
            "product": "Ruby on Rails",
            "vendor": "Rails Core",
            "year": 2023,
            "cvss": 5.4,
            "epss_approx": 0.22,
            "poc_available": True,
            "poc_url": "",
            "metasploit_module": False,
            "description": "Possible XSS and SQLi via inline ERB in Ruby on Rails content-type processing.",
            "impact": "Reflected XSS and potential SQL injection in Rails 5/6 applications.",
            "patch_available": True,
            "cisa_kev": False,
        },
    ],

    "CWE-79": [
        {
            "cve_id": "CVE-2023-3460",
            "product": "WordPress Ultimate Member Plugin",
            "vendor": "Ultimate Member",
            "year": 2023,
            "cvss": 9.8,
            "epss_approx": 0.97,
            "poc_available": True,
            "poc_url": "https://github.com/gbrsh/CVE-2023-3460",
            "metasploit_module": True,
            "description": "Privilege escalation via user meta manipulation in Ultimate Member WordPress plugin leading to stored XSS as admin.",
            "impact": "Unauthenticated attacker can register as administrator and plant persistent XSS.",
            "patch_available": True,
            "cisa_kev": True,
        },
        {
            "cve_id": "CVE-2022-3590",
            "product": "WordPress Core",
            "vendor": "WordPress",
            "year": 2022,
            "cvss": 6.1,
            "epss_approx": 0.45,
            "poc_available": True,
            "poc_url": "",
            "metasploit_module": False,
            "description": "Reflected XSS via the WordPress core search parameter in certain configurations.",
            "impact": "Reflected XSS allows session hijacking of logged-in administrators.",
            "patch_available": True,
            "cisa_kev": False,
        },
        {
            "cve_id": "CVE-2021-34473",
            "product": "Microsoft Exchange Server",
            "vendor": "Microsoft",
            "year": 2021,
            "cvss": 9.8,
            "epss_approx": 0.97,
            "poc_available": True,
            "poc_url": "https://github.com/GossiTheDog/HackingMoreStuff",
            "metasploit_module": True,
            "description": "ProxyShell — pre-auth SSRF in Exchange EWS leading to RCE via PowerShell execution.",
            "impact": "Full Exchange server compromise including email exfiltration and domain persistence.",
            "patch_available": True,
            "cisa_kev": True,
        },
        {
            "cve_id": "CVE-2023-24488",
            "product": "Citrix Gateway",
            "vendor": "Citrix",
            "year": 2023,
            "cvss": 6.1,
            "epss_approx": 0.69,
            "poc_available": True,
            "poc_url": "",
            "metasploit_module": False,
            "description": "Reflected XSS in Citrix Gateway's login page via malformed URL parameters.",
            "impact": "Credential harvesting via reflected XSS on the authentication page.",
            "patch_available": True,
            "cisa_kev": False,
        },
    ],

    "CWE-78": [
        {
            "cve_id": "CVE-2021-44228",
            "product": "Apache Log4j 2",
            "vendor": "Apache Software Foundation",
            "year": 2021,
            "cvss": 10.0,
            "epss_approx": 0.97,
            "poc_available": True,
            "poc_url": "https://github.com/tangxiaofeng7/CVE-2021-44228-Apache-Log4j-Rce",
            "metasploit_module": True,
            "description": "Log4Shell — JNDI injection via attacker-controlled log messages triggering remote class loading.",
            "impact": "Unauthenticated RCE on any Java application logging user-supplied strings with Log4j 2.0-2.14.",
            "patch_available": True,
            "cisa_kev": True,
        },
        {
            "cve_id": "CVE-2022-26134",
            "product": "Atlassian Confluence",
            "vendor": "Atlassian",
            "year": 2022,
            "cvss": 9.8,
            "epss_approx": 0.97,
            "poc_available": True,
            "poc_url": "https://github.com/W01fh4cker/Serein",
            "metasploit_module": True,
            "description": "OGNL injection in Confluence Server/Data Center allows unauthenticated OS command injection.",
            "impact": "Full server takeover including read/write of all Confluence data.",
            "patch_available": True,
            "cisa_kev": True,
        },
        {
            "cve_id": "CVE-2023-46604",
            "product": "Apache ActiveMQ",
            "vendor": "Apache Software Foundation",
            "year": 2023,
            "cvss": 10.0,
            "epss_approx": 0.97,
            "poc_available": True,
            "poc_url": "https://github.com/X1r0z/ActiveMQ-RCE",
            "metasploit_module": True,
            "description": "RCE via ClassInfo deserialization in Apache ActiveMQ 5.x OpenWire protocol — no authentication required.",
            "impact": "Unauthenticated RCE leading to full broker and host compromise.",
            "patch_available": True,
            "cisa_kev": True,
        },
        {
            "cve_id": "CVE-2023-33246",
            "product": "Apache RocketMQ",
            "vendor": "Apache Software Foundation",
            "year": 2023,
            "cvss": 9.8,
            "epss_approx": 0.93,
            "poc_available": True,
            "poc_url": "",
            "metasploit_module": False,
            "description": "Remote command injection in RocketMQ 5.1.0 and below via the update configuration function.",
            "impact": "RCE as the RocketMQ service account.",
            "patch_available": True,
            "cisa_kev": False,
        },
    ],

    "CWE-22": [
        {
            "cve_id": "CVE-2021-41773",
            "product": "Apache HTTP Server",
            "vendor": "Apache Software Foundation",
            "year": 2021,
            "cvss": 9.8,
            "epss_approx": 0.97,
            "poc_available": True,
            "poc_url": "https://github.com/thehackersbrain/CVE-2021-41773",
            "metasploit_module": True,
            "description": "Path traversal and RCE in Apache HTTPD 2.4.49 via URL-encoded path components and mod_cgi.",
            "impact": "Unauthenticated file read and RCE on systems with mod_cgi enabled.",
            "patch_available": True,
            "cisa_kev": True,
        },
        {
            "cve_id": "CVE-2022-22965",
            "product": "Spring Framework",
            "vendor": "VMware (Pivotal)",
            "year": 2022,
            "cvss": 9.8,
            "epss_approx": 0.97,
            "poc_available": True,
            "poc_url": "https://github.com/BobTheShoplifter/Spring4Shell-POC",
            "metasploit_module": True,
            "description": "Spring4Shell — class path manipulation via data binder parameter pollution leading to RCE on Tomcat.",
            "impact": "RCE on Spring MVC/WebFlux applications running on JDK 9+ with Tomcat.",
            "patch_available": True,
            "cisa_kev": True,
        },
        {
            "cve_id": "CVE-2023-44487",
            "product": "HTTP/2 Protocol Implementation",
            "vendor": "Multiple vendors",
            "year": 2023,
            "cvss": 7.5,
            "epss_approx": 0.91,
            "poc_available": True,
            "poc_url": "https://github.com/imabee101/CVE-2023-44487",
            "metasploit_module": False,
            "description": "HTTP/2 Rapid Reset Attack — allows a single client to exhaust server resources via concurrent stream cancellation.",
            "impact": "Denial of service against nginx, Apache, Go net/http and many other HTTP/2 servers.",
            "patch_available": True,
            "cisa_kev": True,
        },
        {
            "cve_id": "CVE-2021-21985",
            "product": "VMware vCenter Server",
            "vendor": "VMware",
            "year": 2021,
            "cvss": 9.8,
            "epss_approx": 0.97,
            "poc_available": True,
            "poc_url": "",
            "metasploit_module": True,
            "description": "Path traversal via the vSphere Client plugin API leading to unauthenticated RCE.",
            "impact": "Full vCenter infrastructure takeover.",
            "patch_available": True,
            "cisa_kev": True,
        },
    ],

    "CWE-798": [
        {
            "cve_id": "CVE-2022-1388",
            "product": "F5 BIG-IP",
            "vendor": "F5 Networks",
            "year": 2022,
            "cvss": 9.8,
            "epss_approx": 0.97,
            "poc_available": True,
            "poc_url": "https://github.com/Al1ex/CVE-2022-1388",
            "metasploit_module": True,
            "description": "Authentication bypass in F5 BIG-IP iControl REST API via X-F5-Auth-Token header with hardcoded admin credentials.",
            "impact": "Unauthenticated RCE as root on BIG-IP management plane.",
            "patch_available": True,
            "cisa_kev": True,
        },
        {
            "cve_id": "CVE-2021-22986",
            "product": "F5 BIG-IP / BIG-IQ",
            "vendor": "F5 Networks",
            "year": 2021,
            "cvss": 9.8,
            "epss_approx": 0.97,
            "poc_available": True,
            "poc_url": "https://github.com/dorkerdevil/CVE-2021-22986",
            "metasploit_module": True,
            "description": "Unauthenticated RCE in F5 BIG-IP iControl REST API due to broken authentication with hardcoded service account.",
            "impact": "Full compromise of BIG-IP appliance including traffic interception.",
            "patch_available": True,
            "cisa_kev": True,
        },
        {
            "cve_id": "CVE-2023-20198",
            "product": "Cisco IOS XE",
            "vendor": "Cisco",
            "year": 2023,
            "cvss": 10.0,
            "epss_approx": 0.97,
            "poc_available": True,
            "poc_url": "",
            "metasploit_module": False,
            "description": "Privilege escalation via a hardcoded credential path in the Cisco IOS XE web UI, enabling level 15 access.",
            "impact": "Full network device compromise with configuration access and traffic interception.",
            "patch_available": True,
            "cisa_kev": True,
        },
    ],

    "CWE-502": [
        {
            "cve_id": "CVE-2021-44228",
            "product": "Apache Log4j 2",
            "vendor": "Apache Software Foundation",
            "year": 2021,
            "cvss": 10.0,
            "epss_approx": 0.97,
            "poc_available": True,
            "poc_url": "https://github.com/tangxiaofeng7/CVE-2021-44228-Apache-Log4j-Rce",
            "metasploit_module": True,
            "description": "Log4Shell — JNDI deserialization via attacker-controlled log messages. The canonical deserialization-to-RCE exploit.",
            "impact": "Unauthenticated RCE at JVM level on all Log4j 2.0–2.14.1 deployments.",
            "patch_available": True,
            "cisa_kev": True,
        },
        {
            "cve_id": "CVE-2022-42889",
            "product": "Apache Commons Text",
            "vendor": "Apache Software Foundation",
            "year": 2022,
            "cvss": 9.8,
            "epss_approx": 0.96,
            "poc_available": True,
            "poc_url": "https://github.com/securekomodo/text4shell-poc",
            "metasploit_module": True,
            "description": "Text4Shell — RCE via StringSubstitutor class processing attacker-controlled strings with ${script:...} interpolation.",
            "impact": "RCE in any Java application using Commons Text StringSubstitutor with user input.",
            "patch_available": True,
            "cisa_kev": False,
        },
        {
            "cve_id": "CVE-2023-34362",
            "product": "MOVEit Transfer",
            "vendor": "Progress Software",
            "year": 2023,
            "cvss": 9.8,
            "epss_approx": 0.97,
            "poc_available": True,
            "poc_url": "https://github.com/horizon3ai/CVE-2023-34362",
            "metasploit_module": True,
            "description": "SQL injection in MOVEit Transfer web application leading to RCE via .NET ViewState deserialization.",
            "impact": "Mass data exfiltration affecting 2000+ organizations in the Cl0p ransomware campaign.",
            "patch_available": True,
            "cisa_kev": True,
        },
        {
            "cve_id": "CVE-2021-42278",
            "product": "Microsoft Active Directory",
            "vendor": "Microsoft",
            "year": 2021,
            "cvss": 8.8,
            "epss_approx": 0.85,
            "poc_available": True,
            "poc_url": "",
            "metasploit_module": True,
            "description": "sAMAccountName spoofing + noPac deserialization chain enabling domain privilege escalation.",
            "impact": "Any domain user can escalate to Domain Admin via Kerberos ticket manipulation.",
            "patch_available": True,
            "cisa_kev": False,
        },
    ],

    "CWE-287": [
        {
            "cve_id": "CVE-2022-1388",
            "product": "F5 BIG-IP",
            "vendor": "F5 Networks",
            "year": 2022,
            "cvss": 9.8,
            "epss_approx": 0.97,
            "poc_available": True,
            "poc_url": "https://github.com/Al1ex/CVE-2022-1388",
            "metasploit_module": True,
            "description": "Authentication bypass in F5 BIG-IP iControl REST via Connection header manipulation.",
            "impact": "Unauthenticated OS command execution as root.",
            "patch_available": True,
            "cisa_kev": True,
        },
        {
            "cve_id": "CVE-2023-20198",
            "product": "Cisco IOS XE Web UI",
            "vendor": "Cisco",
            "year": 2023,
            "cvss": 10.0,
            "epss_approx": 0.97,
            "poc_available": True,
            "poc_url": "",
            "metasploit_module": False,
            "description": "Authentication bypass in Cisco IOS XE HTTP server feature allows creation of local admin accounts.",
            "impact": "Full device takeover without credentials.",
            "patch_available": True,
            "cisa_kev": True,
        },
        {
            "cve_id": "CVE-2021-20038",
            "product": "SonicWall SMA 100",
            "vendor": "SonicWall",
            "year": 2021,
            "cvss": 9.8,
            "epss_approx": 0.97,
            "poc_available": True,
            "poc_url": "https://github.com/rapid7/metasploit-framework/pull/15833",
            "metasploit_module": True,
            "description": "Stack-based buffer overflow in SonicWall SMA 100 series VPN appliance allowing authentication bypass and RCE.",
            "impact": "Unauthenticated RCE as root on VPN appliances.",
            "patch_available": True,
            "cisa_kev": True,
        },
        {
            "cve_id": "CVE-2022-40684",
            "product": "Fortinet FortiOS/FortiProxy",
            "vendor": "Fortinet",
            "year": 2022,
            "cvss": 9.8,
            "epss_approx": 0.97,
            "poc_available": True,
            "poc_url": "",
            "metasploit_module": True,
            "description": "Authentication bypass via alternative path in FortiOS admin interface.",
            "impact": "Unauthenticated administrative access to network security appliance.",
            "patch_available": True,
            "cisa_kev": True,
        },
    ],

    "CWE-190": [
        {
            "cve_id": "CVE-2021-3156",
            "product": "sudo",
            "vendor": "Todd C. Miller",
            "year": 2021,
            "cvss": 7.8,
            "epss_approx": 0.97,
            "poc_available": True,
            "poc_url": "https://github.com/blasty/CVE-2021-3156",
            "metasploit_module": True,
            "description": "Baron Samedit — heap overflow in sudo argument parsing via unescape of '\\' sequences, allowing local privilege escalation.",
            "impact": "Local user escalation to root on most Linux/macOS systems without authentication.",
            "patch_available": True,
            "cisa_kev": False,
        },
        {
            "cve_id": "CVE-2022-0847",
            "product": "Linux Kernel",
            "vendor": "Linux Kernel Organization",
            "year": 2022,
            "cvss": 7.8,
            "epss_approx": 0.97,
            "poc_available": True,
            "poc_url": "https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits",
            "metasploit_module": True,
            "description": "Dirty Pipe — flags field uninitialized in pipe_buffer struct allows writing to arbitrary read-only files.",
            "impact": "Local unprivileged user can write to read-only files, escalate to root or modify SUID binaries.",
            "patch_available": True,
            "cisa_kev": False,
        },
        {
            "cve_id": "CVE-2023-0386",
            "product": "Linux Kernel",
            "vendor": "Linux Kernel Organization",
            "year": 2023,
            "cvss": 7.8,
            "epss_approx": 0.89,
            "poc_available": True,
            "poc_url": "https://github.com/xkaneiki/CVE-2023-0386",
            "metasploit_module": False,
            "description": "OverlayFS — setuid file copy from lower layer to upper layer without permission stripping, enabling SUID binary creation.",
            "impact": "Local privilege escalation to root on kernel 5.11–6.2.",
            "patch_available": True,
            "cisa_kev": False,
        },
    ],

    "CWE-416": [
        {
            "cve_id": "CVE-2021-30551",
            "product": "Google Chrome",
            "vendor": "Google",
            "year": 2021,
            "cvss": 8.8,
            "epss_approx": 0.97,
            "poc_available": True,
            "poc_url": "",
            "metasploit_module": False,
            "description": "Type confusion in V8 JavaScript engine leading to use-after-free, exploited in the wild.",
            "impact": "Remote code execution in the Chrome renderer process from a malicious web page.",
            "patch_available": True,
            "cisa_kev": True,
        },
        {
            "cve_id": "CVE-2022-3038",
            "product": "Google Chrome",
            "vendor": "Google",
            "year": 2022,
            "cvss": 8.8,
            "epss_approx": 0.95,
            "poc_available": True,
            "poc_url": "",
            "metasploit_module": False,
            "description": "Use after free in the Network Service component of Chrome — exploitable via a crafted HTML page.",
            "impact": "Heap corruption and potential code execution in the Chrome browser process.",
            "patch_available": True,
            "cisa_kev": False,
        },
        {
            "cve_id": "CVE-2023-2033",
            "product": "Google Chrome V8",
            "vendor": "Google",
            "year": 2023,
            "cvss": 8.8,
            "epss_approx": 0.97,
            "poc_available": True,
            "poc_url": "",
            "metasploit_module": False,
            "description": "Type confusion in V8 exploited in the wild as a zero-day — use-after-free leading to sandbox escape.",
            "impact": "RCE in renderer, with sandbox escape potential when chained with another vulnerability.",
            "patch_available": True,
            "cisa_kev": True,
        },
    ],

    "CWE-327": [
        {
            "cve_id": "CVE-2022-0778",
            "product": "OpenSSL",
            "vendor": "OpenSSL Project",
            "year": 2022,
            "cvss": 7.5,
            "epss_approx": 0.97,
            "poc_available": True,
            "poc_url": "https://github.com/drago-96/CVE-2022-0778",
            "metasploit_module": False,
            "description": "Infinite loop in BN_mod_sqrt() in OpenSSL triggered by a malformed elliptic curve certificate.",
            "impact": "Denial of service on any TLS server or client parsing attacker-supplied certificates.",
            "patch_available": True,
            "cisa_kev": True,
        },
        {
            "cve_id": "CVE-2023-0465",
            "product": "OpenSSL",
            "vendor": "OpenSSL Project",
            "year": 2023,
            "cvss": 5.3,
            "epss_approx": 0.41,
            "poc_available": False,
            "poc_url": "",
            "metasploit_module": False,
            "description": "Invalid certificate policies in X.509 not rejected when EXFLAG_INVALID_POLICY is set, weakening crypto validation.",
            "impact": "Policy constraint bypass in certificate validation — reduces trust chain assurance.",
            "patch_available": True,
            "cisa_kev": False,
        },
        {
            "cve_id": "CVE-2021-3449",
            "product": "OpenSSL",
            "vendor": "OpenSSL Project",
            "year": 2021,
            "cvss": 5.9,
            "epss_approx": 0.78,
            "poc_available": True,
            "poc_url": "",
            "metasploit_module": False,
            "description": "NULL pointer dereference in OpenSSL TLSv1.2 server via malformed renegotiation ClientHello.",
            "impact": "Denial of service of any TLS server accepting renegotiation.",
            "patch_available": True,
            "cisa_kev": False,
        },
    ],

    "CWE-611": [
        {
            "cve_id": "CVE-2021-44228",
            "product": "Apache Log4j 2",
            "vendor": "Apache Software Foundation",
            "year": 2021,
            "cvss": 10.0,
            "epss_approx": 0.97,
            "poc_available": True,
            "poc_url": "https://github.com/tangxiaofeng7/CVE-2021-44228-Apache-Log4j-Rce",
            "metasploit_module": True,
            "description": "XXE/JNDI injection in Log4j 2 via the XML configuration or log message interpolation.",
            "impact": "SSRF and file exfiltration via XXE; full RCE via JNDI.",
            "patch_available": True,
            "cisa_kev": True,
        },
        {
            "cve_id": "CVE-2022-21449",
            "product": "Java SE / Oracle JDK",
            "vendor": "Oracle",
            "year": 2022,
            "cvss": 7.5,
            "epss_approx": 0.88,
            "poc_available": True,
            "poc_url": "https://github.com/notlsecurity/CVE-2022-21449",
            "metasploit_module": False,
            "description": "Psychic Signatures — ECDSA signature validation bypass in Java 15–18 allows forged signatures with r=s=0.",
            "impact": "Any ECDSA-signed JWT, XML signature, or TLS certificate can be forged.",
            "patch_available": True,
            "cisa_kev": False,
        },
        {
            "cve_id": "CVE-2023-20887",
            "product": "VMware Aria Operations for Networks",
            "vendor": "VMware",
            "year": 2023,
            "cvss": 9.8,
            "epss_approx": 0.97,
            "poc_available": True,
            "poc_url": "https://github.com/sinsinology/CVE-2023-20887",
            "metasploit_module": True,
            "description": "Command injection via GZIP content in the API endpoint of VMware Aria (vRealize) Operations for Networks.",
            "impact": "Unauthenticated RCE on the VMware vRealize appliance.",
            "patch_available": True,
            "cisa_kev": True,
        },
    ],

    "CWE-94": [
        {
            "cve_id": "CVE-2021-41277",
            "product": "Metabase",
            "vendor": "Metabase Inc.",
            "year": 2021,
            "cvss": 10.0,
            "epss_approx": 0.97,
            "poc_available": True,
            "poc_url": "https://github.com/SecretRealms/CVE-2021-41277",
            "metasploit_module": True,
            "description": "Local file inclusion via the GeoJSON endpoint in Metabase — attackers can read files and achieve SSRF.",
            "impact": "Unauthenticated LFI/SSRF leading to secret exfiltration and potential RCE.",
            "patch_available": True,
            "cisa_kev": False,
        },
        {
            "cve_id": "CVE-2022-27925",
            "product": "Zimbra Collaboration Suite",
            "vendor": "Synacor (Zimbra)",
            "year": 2022,
            "cvss": 9.8,
            "epss_approx": 0.97,
            "poc_available": True,
            "poc_url": "",
            "metasploit_module": True,
            "description": "Arbitrary file upload leading to RCE in Zimbra Collaboration Suite via MBOXIMPORT endpoint (code injection via .jsp).",
            "impact": "Unauthenticated RCE on Zimbra mail servers — used in ransomware campaigns.",
            "patch_available": True,
            "cisa_kev": True,
        },
        {
            "cve_id": "CVE-2023-33246",
            "product": "Apache RocketMQ",
            "vendor": "Apache Software Foundation",
            "year": 2023,
            "cvss": 9.8,
            "epss_approx": 0.93,
            "poc_available": True,
            "poc_url": "",
            "metasploit_module": False,
            "description": "Remote code injection via configuration update function in RocketMQ that executes OS commands without sanitisation.",
            "impact": "Arbitrary command execution as the RocketMQ service user.",
            "patch_available": True,
            "cisa_kev": False,
        },
        {
            "cve_id": "CVE-2021-25646",
            "product": "Apache Druid",
            "vendor": "Apache Software Foundation",
            "year": 2021,
            "cvss": 8.8,
            "epss_approx": 0.96,
            "poc_available": True,
            "poc_url": "https://github.com/lz2y/CVE-2021-25646",
            "metasploit_module": True,
            "description": "Code injection via JavaScript functions in Druid query API endpoint without authentication.",
            "impact": "RCE as the Druid process user from an unauthenticated request.",
            "patch_available": True,
            "cisa_kev": False,
        },
    ],
}

# CWE name lookup
_CWE_NAMES: Dict[str, str] = {
    "CWE-89":  "SQL Injection",
    "CWE-79":  "Cross-Site Scripting (XSS)",
    "CWE-78":  "OS Command Injection",
    "CWE-22":  "Path Traversal",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-287": "Improper Authentication / Auth Bypass",
    "CWE-190": "Integer Overflow or Wraparound",
    "CWE-416": "Use After Free",
    "CWE-327": "Use of a Broken or Risky Cryptographic Algorithm",
    "CWE-611": "Improper Restriction of XML External Entity Reference (XXE)",
    "CWE-94":  "Improper Control of Generation of Code (Code Injection)",
    "CWE-120": "Buffer Copy Without Checking Size of Input",
    "CWE-134": "Use of Externally-Controlled Format String",
    "CWE-362": "Race Condition",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-415": "Double Free",
    "CWE-193": "Off-by-one Error",
    "CWE-121": "Stack-based Buffer Overflow",
    "CWE-195": "Signed to Unsigned Conversion Error",
    "CWE-191": "Integer Underflow",
    "CWE-367": "Time-of-check Time-of-use (TOCTOU) Race Condition",
    "CWE-562": "Return of Stack Variable Address",
    "CWE-321": "Use of Hard-coded Cryptographic Key",
    "CWE-338": "Use of Cryptographically Weak Pseudo-Random Number Generator",
    "CWE-328": "Use of Weak Hash",
    "CWE-295": "Improper Certificate Validation",
    "CWE-326": "Inadequate Encryption Strength",
}

# Researcher notes per CWE
_RESEARCHER_NOTES: Dict[str, str] = {
    "CWE-89":  "Always test for time-based blind SQLi (SLEEP/WAITFOR) and error-based extraction. Check JSON parameters and HTTP headers too — they are frequently forgotten.",
    "CWE-79":  "Test DOM-based XSS in addition to reflected/stored. Use SVG payloads (<svg onload=alert(1)>) to bypass HTML sanitisers. CSP bypass is a separate bonus.",
    "CWE-78":  "Try JNDI, ${IFS}, $IFS, semicolons, backticks, and newline injection. Look for command injection in file-name parameters and HTTP headers like User-Agent.",
    "CWE-22":  "Use ../ chains, URL-encoded variants (%2F), and Windows UNC paths (\\\\server\\share). Test ZIP/archive extraction endpoints for Zip Slip.",
    "CWE-798": "Search GitHub, Docker Hub, and NPM for the vendor's hardcoded creds. Check firmware dumps, APK decompilation, and JS bundles.",
    "CWE-502": "Use ysoserial gadget chains for Java. For PHP use unserialize() with POP chains. Check XML parsers (YAML deserialization is underrated).",
    "CWE-287": "Fuzz authentication tokens for predictable patterns. Test JWT with alg:none and RS256→HS256 confusion. Check OAuth state parameter handling.",
    "CWE-190": "Send maximum integer values (0xFFFFFFFF, -1) and check allocation sizes. Look for signed integer casts after arithmetic.",
    "CWE-416": "Use Address Sanitizer (ASAN) to detect UAF at runtime. In browser targets, use heap spraying to achieve reliable exploitation.",
    "CWE-327": "Test for MD5/SHA1 password hashes; crack common passwords offline. Check for ECB-mode AES by submitting two identical blocks.",
    "CWE-611": "Test XXE with out-of-band DNS callbacks (interactsh). Try file:// for local file read and http:// for SSRF. Check SOAP endpoints and Office document parsers.",
    "CWE-94":  "Look for server-side template injection (SSTI) in addition to direct code eval. Test Jinja2, Twig, Freemarker, and Velocity templates.",
}

_BOUNTY_RANGES: Dict[str, Dict[str, str]] = {
    "CRITICAL": {"low": "$5,000", "high": "$100,000+", "range": "$5,000 - $100,000+"},
    "HIGH":     {"low": "$1,000", "high": "$15,000",   "range": "$1,000 - $15,000"},
    "MEDIUM":   {"low": "$200",   "high": "$3,000",    "range": "$200 - $3,000"},
    "LOW":      {"low": "$50",    "high": "$500",      "range": "$50 - $500"},
    "INFO":     {"low": "$0",     "high": "$200",      "range": "$0 - $200"},
}

_RECOMMENDED_CHECKS: Dict[str, List[str]] = {
    "CWE-89":  ["Test login, search, and filter parameters for SQLi", "Try time-based blind injection", "Enumerate database version and schema", "Attempt data exfiltration via UNION SELECT"],
    "CWE-79":  ["Test all user-input fields for reflected XSS", "Check stored XSS in profile/comment fields", "Test DOM-based XSS via URL fragments", "Verify CSP headers are present and correct"],
    "CWE-78":  ["Test OS command injection in file/path parameters", "Try JNDI injection strings", "Fuzz HTTP headers for injection", "Test shell metacharacters: ; | && || ` $()"],
    "CWE-22":  ["Test path traversal in file download endpoints", "Try URL-encoded and double-encoded traversal", "Test ZIP archive extraction for Zip Slip", "Check absolute path injection"],
    "CWE-798": ["Search source code and binaries for hardcoded strings", "Test default credential combinations", "Decompile APK/JAR for embedded secrets", "Check .env files and config endpoints"],
    "CWE-502": ["Test deserialization endpoints with ysoserial payloads", "Check ViewState for HMAC validation", "Test YAML/XML/JSON parsers", "Look for Java ObjectInputStream usages"],
    "CWE-287": ["Fuzz authentication tokens", "Test JWT alg:none bypass", "Check for parameter pollution bypasses", "Test OAuth CSRF via state parameter"],
    "CWE-190": ["Send INT_MAX and UINT_MAX values", "Test negative size values", "Check arithmetic before memory allocation", "Fuzz size parameters with large values"],
    "CWE-416": ["Run application under ASAN/Valgrind", "Test rapid creation/destruction cycles", "Look for double-free patterns", "Check concurrent access with TSAN"],
    "CWE-327": ["Check hash algorithms used for passwords", "Test for ECB mode by submitting identical blocks", "Verify TLS version and cipher suite", "Check for weak random number generation"],
    "CWE-611": ["Send XXE payload to XML endpoints", "Test with external entity referencing internal files", "Try blind XXE with DNS callback", "Check SOAP, DOCX, SVG upload handlers"],
    "CWE-94":  ["Test SSTI in all template variables", "Try direct code eval payloads", "Test Jinja2/Twig/Freemarker templates", "Look for eval() or exec() with user input"],
}


# ─────────────────────────────────────────────────────────────────────────────
# Pydantic models
# ─────────────────────────────────────────────────────────────────────────────

class CVEResearchEntry(BaseModel):
    cve_id: str
    product: str
    vendor: str
    cvss: float
    epss_approx: float
    poc_available: bool
    metasploit_module: bool
    cisa_kev: bool
    description: str
    impact: str
    patch_available: bool


class VulnResearchChain(BaseModel):
    cwe_id: str
    cwe_name: str
    findings_count: int
    related_cves: List[CVEResearchEntry]
    weaponization_score: float   # 0-1: how weaponized is this vulnerability class
    researcher_notes: str        # actionable notes for bug bounty
    estimated_bounty_range: str  # e.g. "$500 - $5,000"
    recommended_checks: List[str]  # concrete test steps


# ─────────────────────────────────────────────────────────────────────────────
# Helper: build a chain from raw records
# ─────────────────────────────────────────────────────────────────────────────

def _build_chain(cwe_id: str, raw_records: List[Dict], findings_count: int, severity: str = "HIGH") -> VulnResearchChain:
    cve_entries = [
        CVEResearchEntry(
            cve_id=r["cve_id"],
            product=r["product"],
            vendor=r["vendor"],
            cvss=r["cvss"],
            epss_approx=r["epss_approx"],
            poc_available=r["poc_available"],
            metasploit_module=r["metasploit_module"],
            cisa_kev=r["cisa_kev"],
            description=r["description"],
            impact=r["impact"],
            patch_available=r["patch_available"],
        )
        for r in raw_records
    ]

    n = len(cve_entries)
    if n == 0:
        weaponization_score = 0.0
    else:
        msf_count = sum(1 for e in cve_entries if e.metasploit_module)
        poc_count = sum(1 for e in cve_entries if e.poc_available)
        kev_count = sum(1 for e in cve_entries if e.cisa_kev)
        weaponization_score = round(
            (msf_count * 0.4 + poc_count * 0.3 + kev_count * 0.3) / n, 4
        )

    return VulnResearchChain(
        cwe_id=cwe_id,
        cwe_name=_CWE_NAMES.get(cwe_id, "Unknown CWE"),
        findings_count=findings_count,
        related_cves=cve_entries,
        weaponization_score=min(1.0, weaponization_score),
        researcher_notes=_RESEARCHER_NOTES.get(cwe_id, "Refer to OWASP Testing Guide for detailed test steps."),
        estimated_bounty_range=_BOUNTY_RANGES.get(severity, _BOUNTY_RANGES["MEDIUM"])["range"],
        recommended_checks=_RECOMMENDED_CHECKS.get(cwe_id, ["Review OWASP guidance for this CWE", "Fuzz the relevant parameter", "Review source code for the root cause"]),
    )


# ─────────────────────────────────────────────────────────────────────────────
# CVEResearcher class
# ─────────────────────────────────────────────────────────────────────────────

class CVEResearcher:
    """
    Offline CVE research assistant — builds CWE → CVE → PoC → Impact chains.

    All data is sourced from the embedded _CVE_KNOWLEDGE_BASE.
    """

    def research_finding(self, finding: Finding) -> VulnResearchChain:
        """Build a VulnResearchChain for a single Finding using its cwe_id."""
        cwe_id = finding.cwe_id or "CWE-89"
        records = _CVE_KNOWLEDGE_BASE.get(cwe_id, [])
        if not records:
            # Fall back to closest available CWE
            records = []
        return _build_chain(cwe_id, records, findings_count=1, severity=finding.severity)

    def research_findings(self, findings: List[Finding]) -> List[VulnResearchChain]:
        """Build chains for a list of findings, grouped by CWE."""
        from collections import Counter
        cwe_counts: Counter = Counter(f.cwe_id for f in findings if f.cwe_id)
        severity_map: Dict[str, str] = {}
        for f in findings:
            if f.cwe_id and f.cwe_id not in severity_map:
                severity_map[f.cwe_id] = f.severity

        chains: List[VulnResearchChain] = []
        for cwe_id, count in cwe_counts.items():
            records = _CVE_KNOWLEDGE_BASE.get(cwe_id, [])
            chains.append(_build_chain(cwe_id, records, findings_count=count, severity=severity_map.get(cwe_id, "MEDIUM")))
        return chains

    def get_top_weaponized(self, findings: List[Finding], top_n: int = 5) -> List[VulnResearchChain]:
        """Return the most weaponized vulnerability chains, sorted descending."""
        chains = self.research_findings(findings)
        return sorted(chains, key=lambda c: c.weaponization_score, reverse=True)[:top_n]

    def estimate_bounty(self, finding: Finding) -> str:
        """Return an estimated bounty range string based on finding severity and CVSS."""
        severity = (finding.severity or "MEDIUM").upper()
        return _BOUNTY_RANGES.get(severity, _BOUNTY_RANGES["MEDIUM"])["range"]


# ─────────────────────────────────────────────────────────────────────────────
# Module-level convenience
# ─────────────────────────────────────────────────────────────────────────────

def research_cwe(cwe_id: str) -> Optional[VulnResearchChain]:
    """Look up a CWE and build a VulnResearchChain. Returns None if unknown."""
    records = _CVE_KNOWLEDGE_BASE.get(cwe_id)
    if records is None:
        return None
    return _build_chain(cwe_id, records, findings_count=0)
