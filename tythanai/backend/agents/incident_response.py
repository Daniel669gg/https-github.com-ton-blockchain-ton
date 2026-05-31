"""Incident Response Automation — playbooks, triage, and response actions."""

from __future__ import annotations

import json
import random
import sys
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Resolve Finding import — works whether run in-tree or as standalone
# ---------------------------------------------------------------------------
try:
    from backend.core.confidence import Finding
except ModuleNotFoundError:
    import importlib.util, pathlib

    _root = pathlib.Path(__file__).resolve().parents[2]
    _spec = importlib.util.spec_from_file_location(
        "confidence", _root / "backend" / "core" / "confidence.py"
    )
    _mod = importlib.util.module_from_spec(_spec)  # type: ignore[arg-type]
    _spec.loader.exec_module(_mod)  # type: ignore[union-attr]
    Finding = _mod.Finding


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class IncidentSeverity(str, Enum):
    P1 = "P1"  # Critical — breach / active attack
    P2 = "P2"  # High — likely compromise
    P3 = "P3"  # Medium — suspicious activity
    P4 = "P4"  # Low — informational


class PlaybookStepStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    SKIPPED = "skipped"
    FAILED = "failed"


# ---------------------------------------------------------------------------
# Core models
# ---------------------------------------------------------------------------


class PlaybookStep(BaseModel):
    """A single, atomic step in an incident response playbook."""

    step_id: str
    name: str
    description: str
    action_type: str  # investigate | contain | eradicate | recover | document
    automated: bool = False
    command_hint: str = ""
    expected_output: str = ""
    status: PlaybookStepStatus = PlaybookStepStatus.PENDING
    notes: str = ""
    duration_minutes: int = 0


class Playbook(BaseModel):
    """A structured set of response procedures for a class of security incident."""

    playbook_id: str
    name: str
    description: str
    trigger_cwe: List[str] = Field(default_factory=list)
    trigger_rule_ids: List[str] = Field(default_factory=list)
    severity: IncidentSeverity
    phases: List[str] = Field(default_factory=list)
    steps: List[PlaybookStep]
    estimated_duration_minutes: int = 0
    references: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)


class IncidentTicket(BaseModel):
    """Tracks the full lifecycle of a security incident from creation to resolution."""

    ticket_id: str  # IR-2026-XXXX
    created_at: str
    severity: IncidentSeverity
    title: str
    affected_files: List[str]
    findings: List[str]  # Finding rule_ids
    assigned_playbook: str = ""
    playbook_steps: List[PlaybookStep] = Field(default_factory=list)
    status: str = "open"  # open | investigating | contained | resolved
    timeline: List[Dict[str, str]] = Field(default_factory=list)
    resolution_notes: str = ""


# ---------------------------------------------------------------------------
# Built-in playbooks
# ---------------------------------------------------------------------------

BUILTIN_PLAYBOOKS: List[Playbook] = [
    # ── 1. SQL Injection ────────────────────────────────────────────────────
    Playbook(
        playbook_id="PB-001",
        name="SQL Injection Response",
        description=(
            "Response procedures for SQL injection vulnerabilities that may allow "
            "attackers to read, modify, or delete database contents."
        ),
        trigger_cwe=["CWE-89"],
        severity=IncidentSeverity.P2,
        phases=["Triage", "Contain", "Eradicate", "Recover", "Verify"],
        estimated_duration_minutes=180,
        references=[
            "https://owasp.org/www-community/attacks/SQL_Injection",
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        ],
        mitre_techniques=["T1190", "T1059.004"],
        steps=[
            PlaybookStep(
                step_id="PB001-TRIAGE-001",
                name="Identify Affected Endpoints",
                description=(
                    "Enumerate all HTTP endpoints, stored procedures, and DB queries "
                    "that interact with user-supplied input without parameterisation."
                ),
                action_type="investigate",
                automated=False,
                command_hint=(
                    "grep -rn --include='*.py' --include='*.js' --include='*.java' "
                    r"'execute\|cursor\.execute\|query(' . | grep -v '#'"
                ),
                expected_output="List of files and line numbers with raw query construction.",
                duration_minutes=30,
            ),
            PlaybookStep(
                step_id="PB001-CONTAIN-001",
                name="Disable Vulnerable Endpoint / Add WAF Rule",
                description=(
                    "Immediately block access to the affected endpoint via WAF rule or "
                    "feature flag while a permanent fix is prepared."
                ),
                action_type="contain",
                automated=False,
                command_hint=(
                    "# AWS WAF example — add IP-set deny rule for the endpoint path\n"
                    "aws wafv2 create-ip-set --name block-sqli-temp --scope REGIONAL "
                    "--ip-address-version IPV4 --addresses 0.0.0.0/0"
                ),
                expected_output="WAF rule active; endpoint returns 403 or feature flag disabled.",
                duration_minutes=15,
            ),
            PlaybookStep(
                step_id="PB001-INVESTIGATE-001",
                name="Review DB Logs for Exfiltration",
                description=(
                    "Inspect database query logs and slow-query logs for anomalous "
                    "UNION / ORDER BY payloads and bulk data reads."
                ),
                action_type="investigate",
                automated=False,
                command_hint=(
                    "# PostgreSQL — last 1000 statements with duration\n"
                    "psql -c \"SELECT query, calls, total_exec_time FROM "
                    "pg_stat_statements ORDER BY total_exec_time DESC LIMIT 1000;\""
                ),
                expected_output="Timeline of suspicious queries; rows read vs baseline.",
                duration_minutes=45,
            ),
            PlaybookStep(
                step_id="PB001-ERADICATE-001",
                name="Fix with Parameterised Queries",
                description=(
                    "Replace all string-concatenated SQL with prepared statements / "
                    "ORM parameterised equivalents and add input-validation middleware."
                ),
                action_type="eradicate",
                automated=False,
                command_hint=(
                    "# Python example — replace unsafe construction\n"
                    "# BEFORE: cursor.execute(f\"SELECT * FROM users WHERE id={uid}\")\n"
                    "# AFTER:  cursor.execute('SELECT * FROM users WHERE id=%s', (uid,))"
                ),
                expected_output="All query construction uses bind parameters; code review approved.",
                duration_minutes=60,
            ),
            PlaybookStep(
                step_id="PB001-VERIFY-001",
                name="Retest with SQLMap",
                description=(
                    "Run automated and manual SQLi probes against the repaired endpoint "
                    "to confirm no injection vectors remain."
                ),
                action_type="investigate",
                automated=True,
                command_hint=(
                    "sqlmap -u 'https://TARGET/endpoint?param=1' --level=5 --risk=3 "
                    "--batch --forms --output-dir=/tmp/sqlmap_results"
                ),
                expected_output="sqlmap reports 'no injectable parameters found'.",
                duration_minutes=30,
            ),
        ],
    ),
    # ── 2. Remote Code Execution ────────────────────────────────────────────
    Playbook(
        playbook_id="PB-002",
        name="Remote Code Execution Response",
        description=(
            "Containment and eradication procedures for vulnerabilities that allow "
            "unauthenticated or low-privilege remote code execution."
        ),
        trigger_cwe=["CWE-94", "CWE-78"],
        severity=IncidentSeverity.P1,
        phases=["Triage", "Contain", "Investigate", "Eradicate", "Recover"],
        estimated_duration_minutes=240,
        references=[
            "https://owasp.org/www-community/attacks/Code_Injection",
            "https://attack.mitre.org/techniques/T1059/",
        ],
        mitre_techniques=["T1059", "T1190", "T1543"],
        steps=[
            PlaybookStep(
                step_id="PB002-TRIAGE-001",
                name="Determine if Actively Exploited in Production",
                description=(
                    "Check application and OS logs for shell spawns, unexpected child "
                    "processes, or outbound connections from the app process."
                ),
                action_type="investigate",
                automated=False,
                command_hint=(
                    "# Check recent process tree anomalies\n"
                    "ps -auxf | grep -E '(python|java|node|ruby)' | head -50\n"
                    "# Check for reverse shells\n"
                    "ss -tlnp | grep -v LISTEN | grep ESTABLISHED"
                ),
                expected_output="No unexpected child processes; no outbound shell connections.",
                duration_minutes=20,
            ),
            PlaybookStep(
                step_id="PB002-CONTAIN-001",
                name="Isolate Affected Service",
                description=(
                    "Immediately remove the compromised service from the load balancer, "
                    "apply network-level isolation, and preserve its state for forensics."
                ),
                action_type="contain",
                automated=False,
                command_hint=(
                    "# Kubernetes — cordon node and delete pod replicas from LB\n"
                    "kubectl cordon <node-name>\n"
                    "kubectl delete pod <pod-name> --grace-period=0\n"
                    "# Capture memory image first if forensics required\n"
                    "# sudo avml /tmp/memory.lime"
                ),
                expected_output="Service removed from traffic; no new connections accepted.",
                duration_minutes=15,
            ),
            PlaybookStep(
                step_id="PB002-INVESTIGATE-001",
                name="Inspect Process Trees and Audit Logs",
                description=(
                    "Collect and analyse process genealogy, loaded modules, open file "
                    "descriptors, and OS audit logs for the time window of exploitation."
                ),
                action_type="investigate",
                automated=False,
                command_hint=(
                    "# Linux audit logs for exec calls\n"
                    "ausearch -ts recent -k exec -i | head -200\n"
                    "# Bash history for suspicious commands\n"
                    "find /home /root -name '.bash_history' -exec cat {} \\;"
                ),
                expected_output="Full command timeline; list of files created or modified.",
                duration_minutes=60,
            ),
            PlaybookStep(
                step_id="PB002-ERADICATE-001",
                name="Patch Vulnerability and Redeploy",
                description=(
                    "Apply code fix (disable eval/exec on user input, sandbox template "
                    "rendering), pass code review, rebuild container image from scratch."
                ),
                action_type="eradicate",
                automated=False,
                command_hint=(
                    "# Rebuild container without cache to ensure clean base\n"
                    "docker build --no-cache -t app:patched .\n"
                    "docker push registry/app:patched\n"
                    "kubectl set image deployment/app app=registry/app:patched"
                ),
                expected_output="New image deployed; old pods terminated; vulnerability absent in SAST rescan.",
                duration_minutes=90,
            ),
            PlaybookStep(
                step_id="PB002-RECOVER-001",
                name="Restore Service and Monitor",
                description=(
                    "Re-admit patched service to load balancer; enable enhanced logging "
                    "and alerting for the next 72 hours."
                ),
                action_type="recover",
                automated=False,
                command_hint=(
                    "kubectl uncordon <node-name>\n"
                    "kubectl scale deployment app --replicas=3\n"
                    "# Enable verbose access logging in your WAF/SIEM for 72 h"
                ),
                expected_output="Service healthy; 72-h monitoring window active.",
                duration_minutes=20,
            ),
        ],
    ),
    # ── 3. Hardcoded Credentials ────────────────────────────────────────────
    Playbook(
        playbook_id="PB-003",
        name="Hardcoded Credentials Exposure Response",
        description=(
            "Urgent response for credentials, API keys, or secrets committed to "
            "source control or embedded in application binaries."
        ),
        trigger_cwe=["CWE-798"],
        severity=IncidentSeverity.P1,
        phases=["Triage", "Contain", "Investigate", "Eradicate", "Recover"],
        estimated_duration_minutes=120,
        references=[
            "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
            "https://docs.github.com/en/code-security/secret-scanning",
        ],
        mitre_techniques=["T1552", "T1078"],
        steps=[
            PlaybookStep(
                step_id="PB003-TRIAGE-001",
                name="Determine If Credentials Are Still Valid",
                description=(
                    "Test each discovered credential against its target service to "
                    "determine if it grants active access."
                ),
                action_type="investigate",
                automated=False,
                command_hint=(
                    "# AWS — test key validity\n"
                    "AWS_ACCESS_KEY_ID=<key> AWS_SECRET_ACCESS_KEY=<secret> "
                    "aws sts get-caller-identity\n"
                    "# Generic HTTP API key test\n"
                    "curl -H 'Authorization: Bearer <token>' https://api.example.com/me"
                ),
                expected_output="List of credentials: valid / revoked / expired.",
                duration_minutes=15,
            ),
            PlaybookStep(
                step_id="PB003-CONTAIN-001",
                name="Rotate All Exposed Credentials Immediately",
                description=(
                    "Invalidate every exposed credential before any further "
                    "investigation. Rotation takes priority over root-cause analysis."
                ),
                action_type="contain",
                automated=False,
                command_hint=(
                    "# AWS — delete and recreate IAM access key\n"
                    "aws iam delete-access-key --access-key-id <key-id>\n"
                    "aws iam create-access-key --user-name <username>\n"
                    "# Update secret in secrets manager\n"
                    "aws secretsmanager put-secret-value --secret-id <name> "
                    "--secret-string '{\"key\":\"<new-value>\"}'"
                ),
                expected_output="All old credentials revoked; new credentials stored in secrets manager.",
                duration_minutes=20,
            ),
            PlaybookStep(
                step_id="PB003-INVESTIGATE-001",
                name="Audit Access Logs for Unauthorised Use",
                description=(
                    "Search SIEM, CloudTrail, and access logs for any API calls or "
                    "logins made with the exposed credentials."
                ),
                action_type="investigate",
                automated=False,
                command_hint=(
                    "# AWS CloudTrail — look for calls made by the key\n"
                    "aws cloudtrail lookup-events "
                    "--lookup-attributes AttributeKey=AccessKeyId,AttributeValue=<key-id> "
                    "--max-items 500\n"
                    "# Git history to see who committed the secret\n"
                    "git log --all -p -S 'SECRET_TOKEN' | head -100"
                ),
                expected_output="Timeline of all API calls; determine blast radius.",
                duration_minutes=45,
            ),
            PlaybookStep(
                step_id="PB003-ERADICATE-001",
                name="Remove Credentials from Code and Git History",
                description=(
                    "Purge the secret from all branches and tags, force-push cleaned "
                    "history, and invalidate GitHub/GitLab caches."
                ),
                action_type="eradicate",
                automated=False,
                command_hint=(
                    "# Using git-filter-repo (preferred over BFG)\n"
                    "git filter-repo --path-glob '*.env' --invert-paths\n"
                    "# Or replace specific string across all commits\n"
                    "git filter-repo --replace-text <(echo 'OLDTOKEN==>REDACTED')\n"
                    "git push --force --all origin"
                ),
                expected_output=(
                    "Secret absent from all branches; GitHub secret scanning shows no active alerts."
                ),
                duration_minutes=30,
            ),
            PlaybookStep(
                step_id="PB003-ERADICATE-002",
                name="Migrate to Secrets Manager / Vault",
                description=(
                    "Replace all plaintext secret usage in code with runtime lookups "
                    "from a secrets manager (AWS Secrets Manager, HashiCorp Vault, etc.)."
                ),
                action_type="eradicate",
                automated=False,
                command_hint=(
                    "# Example: fetch secret at runtime in Python\n"
                    "import boto3\n"
                    "client = boto3.client('secretsmanager')\n"
                    "secret = client.get_secret_value(SecretId='prod/app/db')['SecretString']"
                ),
                expected_output="No hardcoded secrets in codebase; pre-commit hook blocks future commits.",
                duration_minutes=60,
            ),
        ],
    ),
    # ── 4. Path Traversal ───────────────────────────────────────────────────
    Playbook(
        playbook_id="PB-004",
        name="Path Traversal Response",
        description=(
            "Response for directory-traversal vulnerabilities that allow an attacker "
            "to read or write arbitrary files outside the intended scope."
        ),
        trigger_cwe=["CWE-22"],
        severity=IncidentSeverity.P2,
        phases=["Triage", "Contain", "Investigate", "Eradicate"],
        estimated_duration_minutes=120,
        references=[
            "https://owasp.org/www-community/attacks/Path_Traversal",
            "https://portswigger.net/web-security/file-path-traversal",
        ],
        mitre_techniques=["T1083", "T1190"],
        steps=[
            PlaybookStep(
                step_id="PB004-TRIAGE-001",
                name="Identify Accessible Paths",
                description=(
                    "Map the paths reachable via traversal and assess which sensitive "
                    "files (credentials, private keys, /etc/passwd) could be read."
                ),
                action_type="investigate",
                automated=True,
                command_hint=(
                    "# Probe with common traversal payloads\n"
                    "ffuf -u 'https://TARGET/file?name=FUZZ' "
                    "-w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt "
                    "-mc 200 -o /tmp/traversal_results.json"
                ),
                expected_output="List of files successfully read; presence of sensitive data confirmed or denied.",
                duration_minutes=20,
            ),
            PlaybookStep(
                step_id="PB004-CONTAIN-001",
                name="Add Chroot / Realpath Validation",
                description=(
                    "Apply an immediate server-side guard that resolves and validates "
                    "every file path against an allow-list of safe directories before I/O."
                ),
                action_type="contain",
                automated=False,
                command_hint=(
                    "# Python — safe path resolution\n"
                    "import os, pathlib\n"
                    "BASE = pathlib.Path('/var/www/uploads').resolve()\n"
                    "def safe_open(user_path: str):\n"
                    "    target = (BASE / user_path).resolve()\n"
                    "    if not str(target).startswith(str(BASE)):\n"
                    "        raise PermissionError('Path traversal blocked')\n"
                    "    return open(target)"
                ),
                expected_output="Path traversal probes return 403/400; no directory listing outside BASE.",
                duration_minutes=30,
            ),
            PlaybookStep(
                step_id="PB004-INVESTIGATE-001",
                name="Check File Access Logs for Exfiltration",
                description=(
                    "Search web server access logs and OS file-access audit events for "
                    "traversal attempts and successful file reads."
                ),
                action_type="investigate",
                automated=False,
                command_hint=(
                    "# nginx — find traversal attempts in access log\n"
                    "grep -E '(\\.\\./|%2e%2e|%252e)' /var/log/nginx/access.log | "
                    "awk '{print $1, $7, $9}' | sort | uniq -c | sort -rn | head -50"
                ),
                expected_output="Earliest traversal attempt timestamp; IP addresses involved.",
                duration_minutes=30,
            ),
            PlaybookStep(
                step_id="PB004-ERADICATE-001",
                name="Implement Centralised Path Sanitisation",
                description=(
                    "Refactor all file-serving code to use a single validated helper; "
                    "add unit tests; update SAST rules to flag raw path concatenation."
                ),
                action_type="eradicate",
                automated=False,
                command_hint=(
                    "# Add pre-commit hook to catch path concat patterns\n"
                    "grep -rn 'open(.*+' . --include='*.py' | grep -v '#'"
                ),
                expected_output="No raw path concatenation in codebase; SAST clean.",
                duration_minutes=60,
            ),
        ],
    ),
    # ── 5. Insecure Deserialization ─────────────────────────────────────────
    Playbook(
        playbook_id="PB-005",
        name="Insecure Deserialization Response",
        description=(
            "Response for insecure deserialization (pickle, PyYAML full-load, Java "
            "ObjectInputStream) exposed to untrusted input."
        ),
        trigger_cwe=["CWE-502"],
        severity=IncidentSeverity.P1,
        phases=["Triage", "Contain", "Eradicate"],
        estimated_duration_minutes=150,
        references=[
            "https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data",
            "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html",
        ],
        mitre_techniques=["T1059", "T1190"],
        steps=[
            PlaybookStep(
                step_id="PB005-TRIAGE-001",
                name="Check If Deserialiser Is Exposed to User Input",
                description=(
                    "Determine whether pickle.loads / yaml.load / ObjectInputStream "
                    "receives data originating from HTTP requests, files, or queues "
                    "that an external party can control."
                ),
                action_type="investigate",
                automated=True,
                command_hint=(
                    "grep -rn --include='*.py' "
                    r"'pickle\.loads\|yaml\.load\b\|marshal\.loads' . | "
                    "grep -v '#' | grep -v test"
                ),
                expected_output="List of call sites; data flow from HTTP/file boundary confirmed or denied.",
                duration_minutes=20,
            ),
            PlaybookStep(
                step_id="PB005-CONTAIN-001",
                name="Disable Vulnerable Endpoint",
                description=(
                    "Return 503 for the affected endpoint via feature flag or Nginx "
                    "location block until a safe deserialization path is deployed."
                ),
                action_type="contain",
                automated=False,
                command_hint=(
                    "# Nginx — immediately block endpoint\n"
                    "location /api/deserialize {\n"
                    "    return 503 'Service temporarily unavailable';\n"
                    "}"
                ),
                expected_output="Endpoint returns 503; no deserialisation calls possible from outside.",
                duration_minutes=10,
            ),
            PlaybookStep(
                step_id="PB005-ERADICATE-001",
                name="Switch to JSON or MessagePack",
                description=(
                    "Replace pickle/yaml.load with json.loads or msgpack; if structured "
                    "data is needed, use a schema-validated Pydantic model."
                ),
                action_type="eradicate",
                automated=False,
                command_hint=(
                    "# BEFORE\n"
                    "# import pickle; obj = pickle.loads(request.body)\n"
                    "# AFTER\n"
                    "import json\n"
                    "from pydantic import BaseModel\n"
                    "class Payload(BaseModel): ...\n"
                    "obj = Payload.model_validate_json(request.body)"
                ),
                expected_output="No unsafe deserialisation in codebase; SAST and tests pass.",
                duration_minutes=90,
            ),
            PlaybookStep(
                step_id="PB005-RECOVER-001",
                name="Re-enable Endpoint and Monitor",
                description=(
                    "Deploy patched version; re-enable endpoint; add runtime "
                    "deserialization monitoring alerts."
                ),
                action_type="recover",
                automated=False,
                command_hint=(
                    "kubectl rollout restart deployment/api-server\n"
                    "kubectl rollout status deployment/api-server"
                ),
                expected_output="Deployment healthy; no pickle/yaml.load in runtime profiling.",
                duration_minutes=15,
            ),
        ],
    ),
    # ── 6. Weak Cryptography ────────────────────────────────────────────────
    Playbook(
        playbook_id="PB-006",
        name="Weak Cryptography Response",
        description=(
            "Migration plan for deprecated or weak cryptographic algorithms "
            "(MD5, SHA-1, DES, RC4, RSA-1024) protecting sensitive data."
        ),
        trigger_cwe=["CWE-327", "CWE-326", "CWE-328"],
        severity=IncidentSeverity.P2,
        phases=["Identify", "Plan", "Execute"],
        estimated_duration_minutes=300,
        references=[
            "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html",
            "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-175Br1.pdf",
        ],
        mitre_techniques=["T1600", "T1552"],
        steps=[
            PlaybookStep(
                step_id="PB006-IDENTIFY-001",
                name="Inventory All Cryptographic Usage",
                description=(
                    "Scan codebase for algorithm identifiers and map each usage to its "
                    "data sensitivity level (PII, passwords, session tokens, etc.)."
                ),
                action_type="investigate",
                automated=True,
                command_hint=(
                    "grep -rn --include='*.py' "
                    r"'md5\|sha1\|des\b\|rc4\|hashlib\.md5\|hashlib\.sha1' . | "
                    "grep -v '#' | grep -v test"
                ),
                expected_output="Inventory table: file, line, algorithm, data category.",
                duration_minutes=30,
            ),
            PlaybookStep(
                step_id="PB006-PLAN-001",
                name="Plan Cryptographic Migration",
                description=(
                    "For each weak usage, select the modern replacement: "
                    "SHA-256 / SHA-3 for hashing, AES-256-GCM for symmetric, "
                    "RSA-4096 or ECDSA P-256 for asymmetric, bcrypt/Argon2 for passwords."
                ),
                action_type="document",
                automated=False,
                command_hint=(
                    "# Document in ADR (Architecture Decision Record)\n"
                    "# | Old Algorithm | Replacement | Migration Path | Owner |\n"
                    "# | MD5 (checksums) | SHA-256 | Drop-in hashlib change | @team |"
                ),
                expected_output="Migration ADR approved; owners assigned; deadline set.",
                duration_minutes=60,
            ),
            PlaybookStep(
                step_id="PB006-EXECUTE-001",
                name="Execute Migration and Re-encrypt Data",
                description=(
                    "Apply code changes, run database migration to re-hash or re-encrypt "
                    "existing data, and verify with automated tests."
                ),
                action_type="eradicate",
                automated=False,
                command_hint=(
                    "# Python — bcrypt for password hashing\n"
                    "import bcrypt\n"
                    "hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))\n"
                    "# Run migration script to re-hash existing passwords on next login"
                ),
                expected_output="SAST shows no weak algorithms; test suite passes; data re-encrypted.",
                duration_minutes=180,
            ),
            PlaybookStep(
                step_id="PB006-VERIFY-001",
                name="Verify Cryptographic Controls",
                description=(
                    "Run automated crypto-audit tools and schedule annual review to "
                    "prevent regression to weak algorithms."
                ),
                action_type="investigate",
                automated=True,
                command_hint=(
                    "# bandit crypto checks\n"
                    "bandit -r . -t B303,B304,B305,B306,B307 -f json -o /tmp/crypto_audit.json"
                ),
                expected_output="bandit reports zero crypto findings; CI gate passes.",
                duration_minutes=20,
            ),
        ],
    ),
    # ── 7. XSS Vulnerability ────────────────────────────────────────────────
    Playbook(
        playbook_id="PB-007",
        name="Cross-Site Scripting (XSS) Response",
        description=(
            "Response for reflected, stored, and DOM-based XSS vulnerabilities "
            "that allow script injection into web application output."
        ),
        trigger_cwe=["CWE-79", "CWE-80"],
        severity=IncidentSeverity.P2,
        phases=["Assess", "Contain", "Eradicate"],
        estimated_duration_minutes=180,
        references=[
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy",
        ],
        mitre_techniques=["T1059.007", "T1185"],
        steps=[
            PlaybookStep(
                step_id="PB007-ASSESS-001",
                name="Assess Stored vs Reflected XSS",
                description=(
                    "Determine if the payload persists in the database (stored) or is "
                    "reflected immediately (reflected) — this determines urgency and "
                    "whether existing content must be sanitised."
                ),
                action_type="investigate",
                automated=False,
                command_hint=(
                    "# Check if payload is stored in DB\n"
                    "psql -c \"SELECT * FROM comments WHERE content LIKE '%<script%' LIMIT 20;\"\n"
                    "# Run DOM-XSS scanner\n"
                    "dalfox url 'https://TARGET/search?q=test' --silence"
                ),
                expected_output="XSS type confirmed; affected database rows enumerated (if stored).",
                duration_minutes=30,
            ),
            PlaybookStep(
                step_id="PB007-CONTAIN-001",
                name="Deploy Content Security Policy Headers",
                description=(
                    "Add strict CSP headers as an immediate defence-in-depth measure "
                    "to limit script execution to trusted sources."
                ),
                action_type="contain",
                automated=False,
                command_hint=(
                    "# nginx — add CSP header\n"
                    "add_header Content-Security-Policy "
                    "\"default-src 'self'; script-src 'self' 'nonce-{RANDOM}'; "
                    "object-src 'none'; base-uri 'self';\" always;"
                ),
                expected_output="CSP header present on all responses; browser blocks injected scripts.",
                duration_minutes=20,
            ),
            PlaybookStep(
                step_id="PB007-ERADICATE-001",
                name="Fix Input / Output Encoding",
                description=(
                    "Apply context-aware output encoding (HTML, JS, URL, CSS) at every "
                    "template rendering point; use a proven escaping library."
                ),
                action_type="eradicate",
                automated=False,
                command_hint=(
                    "# Python / Jinja2 — ensure autoescape is enabled\n"
                    "from jinja2 import Environment\n"
                    "env = Environment(autoescape=True)  # NOT autoescape=False\n"
                    "# For React — never use dangerouslySetInnerHTML without DOMPurify\n"
                    "import DOMPurify from 'dompurify';\n"
                    "const clean = DOMPurify.sanitize(dirtyHTML);"
                ),
                expected_output="All template output HTML-escaped; no raw user input in innerHTML.",
                duration_minutes=90,
            ),
            PlaybookStep(
                step_id="PB007-ERADICATE-002",
                name="Sanitise Stored Payloads in Database",
                description=(
                    "If stored XSS is confirmed, run a DB migration to strip or escape "
                    "existing malicious content."
                ),
                action_type="eradicate",
                automated=False,
                command_hint=(
                    "# Python — strip tags from stored content\n"
                    "import bleach\n"
                    "safe = bleach.clean(row['content'], tags=[], strip=True)\n"
                    "# Run as migration: UPDATE comments SET content = clean(content);"
                ),
                expected_output="Database contains no unescaped script tags.",
                duration_minutes=40,
            ),
        ],
    ),
    # ── 8. Supply Chain Attack ──────────────────────────────────────────────
    Playbook(
        playbook_id="PB-008",
        name="Supply Chain Attack Response",
        description=(
            "Response for confirmed or suspected malicious packages, "
            "dependency confusion, or typosquat attacks in the software supply chain."
        ),
        trigger_cwe=[],
        trigger_rule_ids=[
            "SUPPLY-CHAIN-001",
            "SUPPLY-CHAIN-002",
            "SUPPLY-CHAIN-003",
            "PKG-MALICIOUS-001",
            "TYPOSQUAT-001",
        ],
        severity=IncidentSeverity.P1,
        phases=["Identify", "Contain", "Investigate", "Eradicate", "Recover"],
        estimated_duration_minutes=360,
        references=[
            "https://slsa.dev/",
            "https://owasp.org/www-project-dependency-check/",
        ],
        mitre_techniques=["T1195", "T1072", "T1059"],
        steps=[
            PlaybookStep(
                step_id="PB008-IDENTIFY-001",
                name="Identify the Malicious Package",
                description=(
                    "Confirm the malicious package name, version range, and nature of "
                    "compromise (malware, credential stealer, backdoor, etc.)."
                ),
                action_type="investigate",
                automated=False,
                command_hint=(
                    "# Cross-reference with OSV / safety db\n"
                    "pip install safety && safety check --full-report\n"
                    "# Or use OSV scanner\n"
                    "osv-scanner --lockfile requirements.txt"
                ),
                expected_output="Confirmed package name, version, CVE/OSV ID, and compromise nature.",
                duration_minutes=30,
            ),
            PlaybookStep(
                step_id="PB008-CONTAIN-001",
                name="Remove Malicious Package Immediately",
                description=(
                    "Uninstall the package from all environments; update lock files "
                    "to pin to a safe version or remove the dependency entirely."
                ),
                action_type="contain",
                automated=False,
                command_hint=(
                    "pip uninstall -y <malicious-package>\n"
                    "# If using poetry:\n"
                    "poetry remove <malicious-package>\n"
                    "poetry lock --no-update\n"
                    "# If using npm:\n"
                    "npm uninstall <malicious-package>"
                ),
                expected_output="Package absent from all environments; lock files updated.",
                duration_minutes=20,
            ),
            PlaybookStep(
                step_id="PB008-INVESTIGATE-001",
                name="Audit Transitive Dependencies",
                description=(
                    "Generate a full SBOM and verify all transitive dependencies "
                    "against known-good hashes; identify any other packages the "
                    "malicious one may have pulled in."
                ),
                action_type="investigate",
                automated=True,
                command_hint=(
                    "# Generate SBOM with syft\n"
                    "syft packages dir:. -o spdx-json=/tmp/sbom.json\n"
                    "# Scan SBOM against Grype\n"
                    "grype sbom:/tmp/sbom.json --fail-on medium"
                ),
                expected_output="Clean SBOM; no additional malicious packages in dependency tree.",
                duration_minutes=45,
            ),
            PlaybookStep(
                step_id="PB008-INVESTIGATE-002",
                name="Determine Execution Scope",
                description=(
                    "Determine whether the malicious package was imported and executed "
                    "in production and what data it could have accessed."
                ),
                action_type="investigate",
                automated=False,
                command_hint=(
                    "# Check if package was imported in production\n"
                    "grep -rn --include='*.py' 'import <pkg>\\|from <pkg>' .\n"
                    "# Check process logs for evidence of package execution\n"
                    "journalctl -u app --since '7 days ago' | grep <pkg>"
                ),
                expected_output="Confirmed whether code ran in production; blast radius estimated.",
                duration_minutes=30,
            ),
            PlaybookStep(
                step_id="PB008-ERADICATE-001",
                name="Rebuild All Artefacts from Clean Sources",
                description=(
                    "Rebuild all container images, binaries, and deployable artefacts "
                    "from a clean environment without the compromised package."
                ),
                action_type="eradicate",
                automated=True,
                command_hint=(
                    "# Rebuild with --no-cache to avoid layer reuse\n"
                    "docker build --no-cache --pull -t app:clean .\n"
                    "# Verify SBOM of new image\n"
                    "syft packages registry:app:clean -o spdx-json | grype"
                ),
                expected_output="New image SBOM clean; old images deleted from registry.",
                duration_minutes=60,
            ),
            PlaybookStep(
                step_id="PB008-RECOVER-001",
                name="Add Dependency Pinning and Verification",
                description=(
                    "Implement hash pinning in lock files, add Sigstore/SLSA provenance "
                    "checks to CI, and enable automated dependency update PRs."
                ),
                action_type="recover",
                automated=False,
                command_hint=(
                    "# Pip — hash verification in requirements.txt\n"
                    "pip-compile --generate-hashes requirements.in\n"
                    "# Enable Dependabot / Renovate for automated updates\n"
                    "# Add SLSA provenance check in CI\n"
                    "slsa-verifier verify-artifact dist/*.whl --provenance-path *.intoto.jsonl"
                ),
                expected_output=(
                    "All dependencies hash-pinned; CI blocks unverified packages; "
                    "automated update PRs enabled."
                ),
                duration_minutes=90,
            ),
        ],
    ),
    # ── 9. Server-Side Request Forgery (SSRF) ───────────────────────────────
    Playbook(
        playbook_id="PB-009",
        name="Server-Side Request Forgery (SSRF) Response",
        description=(
            "Response for SSRF vulnerabilities that allow an attacker to induce "
            "the server to make requests to internal services or cloud metadata APIs."
        ),
        trigger_cwe=["CWE-918"],
        severity=IncidentSeverity.P2,
        phases=["Triage", "Contain", "Eradicate"],
        estimated_duration_minutes=120,
        references=[
            "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
            "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
        ],
        mitre_techniques=["T1190", "T1083"],
        steps=[
            PlaybookStep(
                step_id="PB009-TRIAGE-001",
                name="Check Cloud Metadata Access",
                description=(
                    "Determine if the SSRF vector can reach cloud metadata endpoints "
                    "(169.254.169.254) to exfiltrate IAM credentials."
                ),
                action_type="investigate",
                automated=False,
                command_hint=(
                    "# Check access logs for metadata IP\n"
                    "grep '169.254.169.254' /var/log/nginx/access.log\n"
                    "# AWS CloudTrail — check for unusual role assumptions\n"
                    "aws cloudtrail lookup-events --lookup-attributes "
                    "AttributeKey=EventName,AttributeValue=AssumeRole --max-items 100"
                ),
                expected_output="Metadata endpoint access confirmed or ruled out; IAM exposure assessed.",
                duration_minutes=20,
            ),
            PlaybookStep(
                step_id="PB009-CONTAIN-001",
                name="Block Internal Network Ranges at Application Level",
                description=(
                    "Add an egress allowlist to the URL-fetching code; block RFC-1918 "
                    "and link-local ranges before making outbound HTTP calls."
                ),
                action_type="contain",
                automated=False,
                command_hint=(
                    "# Python — block private ranges\n"
                    "import ipaddress, socket\n"
                    "def is_safe_url(url: str) -> bool:\n"
                    "    host = urllib.parse.urlparse(url).hostname\n"
                    "    ip = ipaddress.ip_address(socket.gethostbyname(host))\n"
                    "    return not (ip.is_private or ip.is_loopback or ip.is_link_local)"
                ),
                expected_output="Metadata and internal ranges unreachable from SSRF vector.",
                duration_minutes=30,
            ),
            PlaybookStep(
                step_id="PB009-ERADICATE-001",
                name="Implement URL Allowlist and DNS Rebinding Protection",
                description=(
                    "Replace ad-hoc URL validation with a centralised safe-fetch "
                    "library that enforces allowlists and re-validates post-DNS-resolution."
                ),
                action_type="eradicate",
                automated=False,
                command_hint=(
                    "# Use ssrf-filter or httpx with transport restrictions\n"
                    "# pip install ssrf-filter\n"
                    "from ssrf_filter import SsrfFilter\n"
                    "response = SsrfFilter.urlopen(untrusted_url)"
                ),
                expected_output="All outbound HTTP calls gated through safe-fetch library; CI test added.",
                duration_minutes=60,
            ),
        ],
    ),
    # ── 10. Authentication Bypass ───────────────────────────────────────────
    Playbook(
        playbook_id="PB-010",
        name="Authentication Bypass Response",
        description=(
            "Response for vulnerabilities that allow unauthenticated access to "
            "protected resources, including JWT algorithm confusion, session fixation, "
            "and broken access control."
        ),
        trigger_cwe=["CWE-287", "CWE-306", "CWE-384"],
        severity=IncidentSeverity.P1,
        phases=["Triage", "Contain", "Eradicate", "Recover"],
        estimated_duration_minutes=200,
        references=[
            "https://owasp.org/www-project-top-ten/2021/A07_2021-Identification_and_Authentication_Failures/",
            "https://portswigger.net/web-security/authentication",
        ],
        mitre_techniques=["T1078", "T1550", "T1190"],
        steps=[
            PlaybookStep(
                step_id="PB010-TRIAGE-001",
                name="Enumerate Unauthenticated Access Scope",
                description=(
                    "Identify all routes and resources accessible without valid "
                    "credentials and confirm whether any were accessed by attackers."
                ),
                action_type="investigate",
                automated=False,
                command_hint=(
                    "# Check auth middleware coverage\n"
                    "grep -rn --include='*.py' '@require_auth\\|@login_required\\|auth_required' . | wc -l\n"
                    "# List routes without auth decorator\n"
                    "grep -rn 'route\\|app.get\\|app.post' . | grep -v 'require_auth'"
                ),
                expected_output="Complete list of unauthenticated routes; access log evidence of exploitation.",
                duration_minutes=30,
            ),
            PlaybookStep(
                step_id="PB010-CONTAIN-001",
                name="Invalidate All Active Sessions",
                description=(
                    "Force-expire all user sessions and tokens; rotate JWT signing "
                    "keys to invalidate all existing JWTs."
                ),
                action_type="contain",
                automated=False,
                command_hint=(
                    "# Django — flush all sessions\n"
                    "python manage.py clearsessions\n"
                    "# Redis — flush all session keys\n"
                    "redis-cli --scan --pattern 'session:*' | xargs redis-cli del\n"
                    "# Rotate JWT secret\n"
                    "python -c \"import secrets; print(secrets.token_hex(64))\""
                ),
                expected_output="All sessions expired; new JWT signing key active; users must re-authenticate.",
                duration_minutes=15,
            ),
            PlaybookStep(
                step_id="PB010-ERADICATE-001",
                name="Fix Authentication Logic",
                description=(
                    "Patch the specific bypass (e.g., alg:none JWT, session fixation, "
                    "broken RBAC) and add regression tests."
                ),
                action_type="eradicate",
                automated=False,
                command_hint=(
                    "# Python-jose — reject alg:none\n"
                    "from jose import jwt\n"
                    "payload = jwt.decode(token, secret,\n"
                    "    algorithms=['HS256'],  # explicit allowlist, never 'none'\n"
                    "    options={'verify_aud': True})"
                ),
                expected_output="Auth bypass tests fail before fix, pass after; SAST clean.",
                duration_minutes=90,
            ),
            PlaybookStep(
                step_id="PB010-RECOVER-001",
                name="Implement MFA and Monitoring",
                description=(
                    "Enforce MFA on admin and sensitive endpoints; add anomaly "
                    "detection for auth events in SIEM."
                ),
                action_type="recover",
                automated=False,
                command_hint=(
                    "# Enable TOTP MFA via django-otp or similar\n"
                    "# Add SIEM rule: alert on >5 auth failures from single IP in 60s\n"
                    "# Example Kibana/ELK alert query:\n"
                    "# event.action: 'authentication_failure' AND count() > 5 OVER 1m"
                ),
                expected_output="MFA enforced; SIEM alert active; admin panel access audited.",
                duration_minutes=60,
            ),
        ],
    ),
]


# ---------------------------------------------------------------------------
# Severity mapping helpers
# ---------------------------------------------------------------------------

_SEVERITY_TO_INCIDENT: Dict[str, IncidentSeverity] = {
    "CRITICAL": IncidentSeverity.P1,
    "HIGH": IncidentSeverity.P2,
    "MEDIUM": IncidentSeverity.P3,
    "LOW": IncidentSeverity.P4,
    "INFO": IncidentSeverity.P4,
}

_INCIDENT_SEVERITY_ORDER: Dict[IncidentSeverity, int] = {
    IncidentSeverity.P1: 4,
    IncidentSeverity.P2: 3,
    IncidentSeverity.P3: 2,
    IncidentSeverity.P4: 1,
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _findings_to_incident_severity(findings: List[Finding]) -> IncidentSeverity:
    """Return the highest IncidentSeverity found in the list."""
    best = IncidentSeverity.P4
    for f in findings:
        candidate = _SEVERITY_TO_INCIDENT.get(f.severity.upper(), IncidentSeverity.P4)
        if _INCIDENT_SEVERITY_ORDER[candidate] > _INCIDENT_SEVERITY_ORDER[best]:
            best = candidate
    return best


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class IncidentResponseEngine:
    """Automates incident triage, playbook assignment, and report generation."""

    # ── Triage ───────────────────────────────────────────────────────────────

    def triage_findings(self, findings: List[Finding]) -> IncidentTicket:
        """Create an IncidentTicket from a list of findings."""
        if not findings:
            raise ValueError("Cannot triage an empty findings list.")

        severity = _findings_to_incident_severity(findings)
        year = datetime.now(timezone.utc).year
        ticket_id = f"IR-{year}-{random.randint(1000, 9999)}"

        affected_files: List[str] = sorted({f.file for f in findings})
        rule_ids: List[str] = list({f.rule_id for f in findings})

        titles_by_severity = {
            IncidentSeverity.P1: "Critical Security Incident",
            IncidentSeverity.P2: "High-Severity Security Incident",
            IncidentSeverity.P3: "Medium-Severity Security Event",
            IncidentSeverity.P4: "Low-Severity Security Notice",
        }
        title = titles_by_severity[severity]

        ticket = IncidentTicket(
            ticket_id=ticket_id,
            created_at=_now_iso(),
            severity=severity,
            title=title,
            affected_files=affected_files,
            findings=rule_ids,
            timeline=[
                {
                    "time": _now_iso(),
                    "event": f"Ticket {ticket_id} created by automated triage engine.",
                    "actor": "TythanAI",
                }
            ],
        )
        ticket = self.assign_playbook(ticket, findings)
        return ticket

    # ── Playbook assignment ──────────────────────────────────────────────────

    def assign_playbook(
        self, ticket: IncidentTicket, findings: List[Finding]
    ) -> IncidentTicket:
        """Select the best-matching playbook and attach its steps to the ticket."""
        cwe_ids = {f.cwe_id for f in findings if f.cwe_id}
        rule_ids = {f.rule_id for f in findings if f.rule_id}

        best_playbook: Optional[Playbook] = None
        best_score = -1

        for pb in BUILTIN_PLAYBOOKS:
            cwe_matches = len(cwe_ids & set(pb.trigger_cwe))
            rule_matches = len(rule_ids & set(pb.trigger_rule_ids))
            score = cwe_matches * 2 + rule_matches  # CWE match weighted higher
            if score > best_score:
                best_score = score
                best_playbook = pb

        if best_playbook is None or best_score == 0:
            # Fall back to generic incident response (first playbook)
            best_playbook = BUILTIN_PLAYBOOKS[0]

        # Deep-copy steps so mutations don't affect the canonical playbook
        ticket.playbook_steps = [s.model_copy(deep=True) for s in best_playbook.steps]
        ticket.assigned_playbook = best_playbook.name
        ticket.status = "investigating"

        ticket.timeline.append(
            {
                "time": _now_iso(),
                "event": f"Playbook '{best_playbook.name}' assigned ({len(ticket.playbook_steps)} steps).",
                "actor": "TythanAI",
            }
        )
        return ticket

    # ── Step completion ──────────────────────────────────────────────────────

    def complete_step(
        self, ticket: IncidentTicket, step_id: str, notes: str = ""
    ) -> IncidentTicket:
        """Mark a playbook step as COMPLETED and advance ticket status if all done."""
        found = False
        for step in ticket.playbook_steps:
            if step.step_id == step_id:
                step.status = PlaybookStepStatus.COMPLETED
                step.notes = notes
                found = True
                break

        if not found:
            raise ValueError(f"Step '{step_id}' not found in ticket {ticket.ticket_id}.")

        ticket.timeline.append(
            {
                "time": _now_iso(),
                "event": f"Step '{step_id}' completed.",
                "actor": "Analyst",
                "notes": notes,
            }
        )

        # Resolve if all non-skipped steps are complete or skipped
        pending_or_in_progress = [
            s
            for s in ticket.playbook_steps
            if s.status in (PlaybookStepStatus.PENDING, PlaybookStepStatus.IN_PROGRESS)
        ]
        if not pending_or_in_progress:
            ticket.status = "resolved"
            ticket.timeline.append(
                {
                    "time": _now_iso(),
                    "event": "All playbook steps completed — ticket resolved.",
                    "actor": "TythanAI",
                }
            )

        return ticket

    # ── Report generation ────────────────────────────────────────────────────

    def generate_report(self, ticket: IncidentTicket) -> str:
        """Return a Markdown incident report for the ticket."""
        lines: List[str] = []

        lines.append(f"# Incident Report: {ticket.ticket_id}")
        lines.append("")
        lines.append(f"**Severity**: {ticket.severity.value}")
        lines.append(f"**Status**: {ticket.status}")
        lines.append(f"**Created**: {ticket.created_at}")
        lines.append(f"**Title**: {ticket.title}")
        lines.append(f"**Assigned Playbook**: {ticket.assigned_playbook or '—'}")
        lines.append("")

        # Timeline
        lines.append("## Timeline")
        lines.append("")
        if ticket.timeline:
            for entry in ticket.timeline:
                ts = entry.get("time", "")
                event = entry.get("event", "")
                actor = entry.get("actor", "")
                extra = entry.get("notes", "")
                note_str = f" — *{extra}*" if extra else ""
                lines.append(f"- `{ts}` **{actor}**: {event}{note_str}")
        else:
            lines.append("_No timeline entries._")
        lines.append("")

        # Affected files
        lines.append("## Affected Files")
        lines.append("")
        if ticket.affected_files:
            for f in ticket.affected_files:
                lines.append(f"- `{f}`")
        else:
            lines.append("_No affected files recorded._")
        lines.append("")

        # Playbook progress table
        lines.append("## Playbook Progress")
        lines.append("")
        if ticket.playbook_steps:
            lines.append("| Step ID | Name | Status | Notes |")
            lines.append("|---------|------|--------|-------|")
            for step in ticket.playbook_steps:
                status_emoji = {
                    PlaybookStepStatus.PENDING: "⏳ pending",
                    PlaybookStepStatus.IN_PROGRESS: "🔄 in_progress",
                    PlaybookStepStatus.COMPLETED: "✅ completed",
                    PlaybookStepStatus.SKIPPED: "⏭ skipped",
                    PlaybookStepStatus.FAILED: "❌ failed",
                }.get(step.status, step.status.value)
                notes = step.notes.replace("|", "&#124;") if step.notes else "—"
                lines.append(
                    f"| `{step.step_id}` | {step.name} | {status_emoji} | {notes} |"
                )
        else:
            lines.append("_No playbook steps assigned._")
        lines.append("")

        # Resolution
        lines.append("## Resolution")
        lines.append("")
        if ticket.resolution_notes:
            lines.append(ticket.resolution_notes)
        else:
            lines.append("_Pending resolution._")
        lines.append("")

        return "\n".join(lines)

    # ── JSON export ──────────────────────────────────────────────────────────

    def to_json(self, ticket: IncidentTicket) -> str:
        """Serialize the ticket to a JSON string."""
        return ticket.model_dump_json(indent=2)


# ---------------------------------------------------------------------------
# Module-level convenience API
# ---------------------------------------------------------------------------


def create_incident(findings: List[Finding]) -> IncidentTicket:
    """Create an IncidentTicket from a list of findings using the default engine."""
    return IncidentResponseEngine().triage_findings(findings)


PLAYBOOKS = BUILTIN_PLAYBOOKS
