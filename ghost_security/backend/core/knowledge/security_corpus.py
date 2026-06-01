"""Security Corpus — unified knowledge store for CVE, CWE, CAPEC, OWASP, research, exploits.

Does NOT duplicate security_memory.py (which stores findings/patterns/scans).
This corpus stores structured threat intelligence and research knowledge.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class CorpusEntryType(str, Enum):
    CVE = "cve"
    CWE = "cwe"
    CAPEC = "capec"
    OWASP = "owasp"
    ADVISORY = "advisory"
    RESEARCH = "research"
    EXPLOIT = "exploit"
    REMEDIATION = "remediation"
    SECURE_CODING = "secure_coding"
    GENERATED_RULE = "generated_rule"


class VerificationStatus(str, Enum):
    UNVERIFIED = "unverified"
    PARTIALLY_VERIFIED = "partially_verified"
    VERIFIED = "verified"
    REJECTED = "rejected"


# ---------------------------------------------------------------------------
# Knowledge Confidence Score
# ---------------------------------------------------------------------------


@dataclass
class KnowledgeConfidenceScore:
    """Composite confidence for a corpus entry."""
    source_score: float = 0.0        # authority of source (NVD=1.0, community=0.5)
    confirmation_count: int = 0      # number of independent confirmations
    detection_success: float = 0.0   # rate of successful detections using this knowledge
    remediation_success: float = 0.0 # rate of successful remediations

    @property
    def total_score(self) -> float:
        confirmation_bonus = min(self.confirmation_count / 5.0, 1.0) * 0.2
        return round(
            self.source_score * 0.4
            + confirmation_bonus
            + self.detection_success * 0.25
            + self.remediation_success * 0.15,
            4,
        )

    def to_dict(self) -> dict:
        return {
            "source_score": self.source_score,
            "confirmation_count": self.confirmation_count,
            "detection_success": self.detection_success,
            "remediation_success": self.remediation_success,
            "total_score": self.total_score,
        }


# ---------------------------------------------------------------------------
# Corpus entry base
# ---------------------------------------------------------------------------


@dataclass
class CorpusEntry:
    """Base class for all corpus entries."""
    entry_id: str
    entry_type: CorpusEntryType
    source: str                               # NVD, OSV, OWASP, CISA, manual, etc.
    confidence: float = 0.7
    verification_status: VerificationStatus = VerificationStatus.UNVERIFIED
    tags: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    created_at: str = ""
    updated_at: str = ""
    knowledge_score: Optional[KnowledgeConfidenceScore] = None

    def __post_init__(self) -> None:
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()
        if not self.updated_at:
            self.updated_at = self.created_at

    def to_dict(self) -> dict:
        return {
            "entry_id": self.entry_id,
            "entry_type": self.entry_type.value,
            "source": self.source,
            "confidence": self.confidence,
            "verification_status": self.verification_status.value,
            "tags": self.tags,
            "references": self.references,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "knowledge_score": self.knowledge_score.to_dict() if self.knowledge_score else None,
        }

    def fingerprint(self) -> str:
        raw = f"{self.entry_type.value}:{self.entry_id}"
        return hashlib.sha1(raw.encode()).hexdigest()[:12]


@dataclass
class CVEEntry(CorpusEntry):
    cve_id: str = ""
    description: str = ""
    cvss_v3: float = 0.0
    severity: str = "UNKNOWN"
    cwe_ids: List[str] = field(default_factory=list)
    epss_score: float = 0.0
    is_kev: bool = False
    published: str = ""
    affected_packages: List[str] = field(default_factory=list)
    exploitation_patterns: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = super().to_dict()
        d.update({
            "cve_id": self.cve_id,
            "description": self.description,
            "cvss_v3": self.cvss_v3,
            "severity": self.severity,
            "cwe_ids": self.cwe_ids,
            "epss_score": self.epss_score,
            "is_kev": self.is_kev,
            "published": self.published,
            "affected_packages": self.affected_packages,
        })
        return d


@dataclass
class CWEEntry(CorpusEntry):
    cwe_id: str = ""
    name: str = ""
    description: str = ""
    extended_description: str = ""
    likelihood: str = ""    # HIGH/MEDIUM/LOW
    impact: str = ""
    owasp_category: str = ""
    vulnerability_patterns: List[str] = field(default_factory=list)
    remediation_patterns: List[str] = field(default_factory=list)
    detection_methods: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = super().to_dict()
        d.update({
            "cwe_id": self.cwe_id,
            "name": self.name,
            "description": self.description,
            "owasp_category": self.owasp_category,
            "vulnerability_patterns": self.vulnerability_patterns,
            "remediation_patterns": self.remediation_patterns,
        })
        return d


@dataclass
class CAPECEntry(CorpusEntry):
    capec_id: str = ""
    name: str = ""
    description: str = ""
    attack_steps: List[str] = field(default_factory=list)
    prerequisites: List[str] = field(default_factory=list)
    related_cwes: List[str] = field(default_factory=list)
    severity: str = "MEDIUM"
    likelihood: str = "MEDIUM"

    def to_dict(self) -> dict:
        d = super().to_dict()
        d.update({
            "capec_id": self.capec_id,
            "name": self.name,
            "description": self.description,
            "attack_steps": self.attack_steps,
            "related_cwes": self.related_cwes,
        })
        return d


@dataclass
class AdvisoryEntry(CorpusEntry):
    advisory_id: str = ""
    title: str = ""
    summary: str = ""
    affected_products: List[str] = field(default_factory=list)
    cve_ids: List[str] = field(default_factory=list)
    severity: str = "MEDIUM"
    published: str = ""
    remediation: str = ""


@dataclass
class ResearchEntry(CorpusEntry):
    title: str = ""
    abstract: str = ""
    authors: List[str] = field(default_factory=list)
    published: str = ""
    cwe_ids: List[str] = field(default_factory=list)
    findings_summary: str = ""
    techniques: List[str] = field(default_factory=list)


@dataclass
class ExploitEntry(CorpusEntry):
    exploit_id: str = ""
    title: str = ""
    cve_id: str = ""
    cwe_id: str = ""
    description: str = ""
    exploit_type: str = ""   # rce, sqli, xss, etc.
    steps: List[str] = field(default_factory=list)
    mitigations: List[str] = field(default_factory=list)
    severity: str = "HIGH"


@dataclass
class RemediationPatternEntry(CorpusEntry):
    pattern_id: str = ""
    cwe_id: str = ""
    name: str = ""
    description: str = ""
    before_code: str = ""    # vulnerable example
    after_code: str = ""     # fixed example
    language: str = ""       # python, javascript, go, etc.
    effectiveness: float = 0.0


@dataclass
class GeneratedRuleEntry(CorpusEntry):
    rule_id: str = ""
    cwe_id: str = ""
    rule_pattern: str = ""
    rule_yaml: str = ""
    validation_status: str = "proposed"  # proposed/validated/rejected/promoted
    false_positive_rate: float = 0.0
    false_negative_rate: float = 0.0
    detection_count: int = 0


# ---------------------------------------------------------------------------
# Embedded static knowledge base (offline, no network required)
# ---------------------------------------------------------------------------

_EMBEDDED_CWES: List[Dict[str, Any]] = [
    {
        "cwe_id": "CWE-89", "name": "SQL Injection",
        "owasp_category": "A03:2021",
        "description": "User-controlled input is embedded in SQL queries without parameterization.",
        "vulnerability_patterns": [r'execute\s*\(["\'].*\+', r'format\(.*WHERE'],
        "remediation_patterns": ["Use parameterized queries", "Use ORM"],
        "likelihood": "HIGH", "impact": "HIGH",
    },
    {
        "cwe_id": "CWE-79", "name": "Cross-Site Scripting",
        "owasp_category": "A03:2021",
        "description": "User input rendered in HTML without encoding.",
        "vulnerability_patterns": [r'innerHTML\s*=', r'document\.write\('],
        "remediation_patterns": ["HTML-encode all output", "Use CSP"],
        "likelihood": "HIGH", "impact": "MEDIUM",
    },
    {
        "cwe_id": "CWE-78", "name": "OS Command Injection",
        "owasp_category": "A03:2021",
        "description": "User input passed to shell without sanitization.",
        "vulnerability_patterns": [r'os\.system\(', r'shell=True'],
        "remediation_patterns": ["Use subprocess with shell=False", "Use shlex.quote"],
        "likelihood": "MEDIUM", "impact": "CRITICAL",
    },
    {
        "cwe_id": "CWE-22", "name": "Path Traversal",
        "owasp_category": "A01:2021",
        "description": "User-controlled path component not normalized.",
        "vulnerability_patterns": [r'open\(.*\+', r'Path\(.*user'],
        "remediation_patterns": ["Use os.path.realpath", "Validate path prefix"],
        "likelihood": "MEDIUM", "impact": "HIGH",
    },
    {
        "cwe_id": "CWE-502", "name": "Deserialization of Untrusted Data",
        "owasp_category": "A08:2021",
        "description": "Untrusted data deserialized without validation.",
        "vulnerability_patterns": [r'pickle\.load', r'yaml\.load\s*\('],
        "remediation_patterns": ["Use yaml.safe_load", "Validate/sign before deserializing"],
        "likelihood": "MEDIUM", "impact": "CRITICAL",
    },
    {
        "cwe_id": "CWE-798", "name": "Hardcoded Credentials",
        "owasp_category": "A07:2021",
        "description": "Secrets embedded in source code.",
        "vulnerability_patterns": [r'password\s*=\s*["\']', r'api_key\s*=\s*["\']'],
        "remediation_patterns": ["Use environment variables", "Use secrets manager"],
        "likelihood": "MEDIUM", "impact": "HIGH",
    },
    {
        "cwe_id": "CWE-327", "name": "Broken Cryptographic Algorithm",
        "owasp_category": "A02:2021",
        "description": "Use of cryptographically weak algorithms.",
        "vulnerability_patterns": [r'md5\(', r'sha1\(', r'DES\.'],
        "remediation_patterns": ["Use SHA-256/SHA-3", "Use bcrypt/argon2 for passwords"],
        "likelihood": "LOW", "impact": "HIGH",
    },
    {
        "cwe_id": "CWE-918", "name": "Server-Side Request Forgery",
        "owasp_category": "A10:2021",
        "description": "Application fetches URL from user input without validation.",
        "vulnerability_patterns": [r'requests\.get\s*\(.*user', r'urlopen\s*\('],
        "remediation_patterns": ["Allowlist external domains", "Block private IP ranges"],
        "likelihood": "MEDIUM", "impact": "HIGH",
    },
    {
        "cwe_id": "CWE-94", "name": "Code Injection",
        "owasp_category": "A03:2021",
        "description": "User input executed as code.",
        "vulnerability_patterns": [r'\beval\s*\(', r'\bexec\s*\('],
        "remediation_patterns": ["Eliminate eval/exec", "Use ast.literal_eval for literals"],
        "likelihood": "LOW", "impact": "CRITICAL",
    },
    {
        "cwe_id": "CWE-476", "name": "NULL Pointer Dereference",
        "owasp_category": "A06:2021",
        "description": "Null/None pointer dereferenced without check.",
        "vulnerability_patterns": [r'None\.\w+', r'\*\s*NULL'],
        "remediation_patterns": ["Check for None before access", "Use Optional types"],
        "likelihood": "HIGH", "impact": "MEDIUM",
    },
    {
        "cwe_id": "CWE-400", "name": "Uncontrolled Resource Consumption",
        "owasp_category": "A05:2021",
        "description": "Resource consumed without limit from user input.",
        "vulnerability_patterns": [r'range\s*\(\s*user', r'malloc\s*\(\s*user'],
        "remediation_patterns": ["Add size limits", "Use resource quotas"],
        "likelihood": "MEDIUM", "impact": "MEDIUM",
    },
    {
        "cwe_id": "CWE-611", "name": "Improper Restriction of XML External Entity",
        "owasp_category": "A05:2021",
        "description": "XML parser processes external entities.",
        "vulnerability_patterns": [r'etree\.parse', r'parseString\('],
        "remediation_patterns": ["Disable external entity processing", "Use defusedxml"],
        "likelihood": "MEDIUM", "impact": "HIGH",
    },
]

_EMBEDDED_CAPEC: List[Dict[str, Any]] = [
    {
        "capec_id": "CAPEC-66", "name": "SQL Injection",
        "description": "Attacker inserts SQL into application query.",
        "attack_steps": ["Identify injectable parameter", "Craft SQL payload", "Extract data"],
        "related_cwes": ["CWE-89"],
        "severity": "HIGH", "likelihood": "HIGH",
    },
    {
        "capec_id": "CAPEC-86", "name": "XSS via HTTP Request Headers",
        "description": "Attacker injects script via HTTP headers reflected in response.",
        "attack_steps": ["Identify reflected header", "Craft XSS payload", "Deliver to victim"],
        "related_cwes": ["CWE-79"],
        "severity": "MEDIUM", "likelihood": "HIGH",
    },
    {
        "capec_id": "CAPEC-88", "name": "OS Command Injection",
        "description": "Attacker injects OS commands via application input.",
        "attack_steps": ["Find command execution point", "Inject shell metacharacter", "Execute payload"],
        "related_cwes": ["CWE-78"],
        "severity": "CRITICAL", "likelihood": "MEDIUM",
    },
    {
        "capec_id": "CAPEC-126", "name": "Path Traversal",
        "description": "Attacker uses ../ sequences to access restricted files.",
        "attack_steps": ["Identify file path parameter", "Insert ../ sequences", "Access sensitive file"],
        "related_cwes": ["CWE-22"],
        "severity": "HIGH", "likelihood": "MEDIUM",
    },
    {
        "capec_id": "CAPEC-116", "name": "Excavation (Info Disclosure)",
        "description": "Attacker extracts sensitive data through verbose error messages.",
        "attack_steps": ["Trigger error conditions", "Analyze error messages", "Extract intelligence"],
        "related_cwes": ["CWE-200", "CWE-209"],
        "severity": "MEDIUM", "likelihood": "HIGH",
    },
    {
        "capec_id": "CAPEC-153", "name": "Input Data Manipulation",
        "description": "Attacker manipulates trusted data to exploit business logic.",
        "attack_steps": ["Identify trust boundary", "Manipulate input data", "Bypass validation"],
        "related_cwes": ["CWE-20"],
        "severity": "HIGH", "likelihood": "MEDIUM",
    },
    {
        "capec_id": "CAPEC-472", "name": "Browser Fingerprinting",
        "description": "Attacker identifies user browser to enable targeted attacks.",
        "attack_steps": ["Collect browser attributes", "Build fingerprint", "Link to user identity"],
        "related_cwes": ["CWE-200"],
        "severity": "LOW", "likelihood": "HIGH",
    },
    {
        "capec_id": "CAPEC-62", "name": "Cross-Site Request Forgery (CSRF)",
        "description": "Attacker tricks victim's browser into making unauthorized requests.",
        "attack_steps": ["Create malicious page", "Lure victim", "Execute unauthorized action"],
        "related_cwes": ["CWE-352"],
        "severity": "HIGH", "likelihood": "MEDIUM",
    },
]

_EMBEDDED_OWASP: List[Dict[str, Any]] = [
    {"category_id": "A01:2021", "name": "Broken Access Control", "cwe_ids": ["CWE-22", "CWE-284", "CWE-285"], "rank": 1},
    {"category_id": "A02:2021", "name": "Cryptographic Failures", "cwe_ids": ["CWE-327", "CWE-311", "CWE-319"], "rank": 2},
    {"category_id": "A03:2021", "name": "Injection", "cwe_ids": ["CWE-89", "CWE-79", "CWE-78", "CWE-94"], "rank": 3},
    {"category_id": "A04:2021", "name": "Insecure Design", "cwe_ids": ["CWE-209", "CWE-256"], "rank": 4},
    {"category_id": "A05:2021", "name": "Security Misconfiguration", "cwe_ids": ["CWE-400", "CWE-611"], "rank": 5},
    {"category_id": "A06:2021", "name": "Vulnerable Components", "cwe_ids": ["CWE-1026", "CWE-1035"], "rank": 6},
    {"category_id": "A07:2021", "name": "Authentication Failures", "cwe_ids": ["CWE-798", "CWE-287", "CWE-308"], "rank": 7},
    {"category_id": "A08:2021", "name": "Software Integrity Failures", "cwe_ids": ["CWE-502", "CWE-829"], "rank": 8},
    {"category_id": "A09:2021", "name": "Logging & Monitoring Failures", "cwe_ids": ["CWE-117", "CWE-223"], "rank": 9},
    {"category_id": "A10:2021", "name": "Server-Side Request Forgery", "cwe_ids": ["CWE-918"], "rank": 10},
]


def _build_embedded_corpus() -> List[CorpusEntry]:
    """Build the initial corpus from embedded static knowledge."""
    entries: List[CorpusEntry] = []
    now = datetime.now(timezone.utc).isoformat()

    # CWE entries
    for cwe_data in _EMBEDDED_CWES:
        entry = CWEEntry(
            entry_id=cwe_data["cwe_id"],
            entry_type=CorpusEntryType.CWE,
            source="MITRE CWE",
            confidence=0.95,
            verification_status=VerificationStatus.VERIFIED,
            tags=["cwe", cwe_data.get("owasp_category", "").lower()],
            references=[f"https://cwe.mitre.org/data/definitions/{cwe_data['cwe_id'].split('-')[1]}.html"],
            created_at=now,
            cwe_id=cwe_data["cwe_id"],
            name=cwe_data["name"],
            description=cwe_data["description"],
            owasp_category=cwe_data.get("owasp_category", ""),
            vulnerability_patterns=cwe_data.get("vulnerability_patterns", []),
            remediation_patterns=cwe_data.get("remediation_patterns", []),
            knowledge_score=KnowledgeConfidenceScore(
                source_score=0.95,
                confirmation_count=10,
                detection_success=0.85,
                remediation_success=0.80,
            ),
        )
        entries.append(entry)

    # CAPEC entries
    for capec_data in _EMBEDDED_CAPEC:
        entry = CAPECEntry(
            entry_id=capec_data["capec_id"],
            entry_type=CorpusEntryType.CAPEC,
            source="MITRE CAPEC",
            confidence=0.90,
            verification_status=VerificationStatus.VERIFIED,
            tags=["capec", "attack-pattern"],
            references=[f"https://capec.mitre.org/data/definitions/{capec_data['capec_id'].split('-')[1]}.html"],
            created_at=now,
            capec_id=capec_data["capec_id"],
            name=capec_data["name"],
            description=capec_data["description"],
            attack_steps=capec_data.get("attack_steps", []),
            related_cwes=capec_data.get("related_cwes", []),
            severity=capec_data.get("severity", "MEDIUM"),
            likelihood=capec_data.get("likelihood", "MEDIUM"),
        )
        entries.append(entry)

    # OWASP Top 10 entries
    for owasp_data in _EMBEDDED_OWASP:
        entry = CorpusEntry(
            entry_id=owasp_data["category_id"],
            entry_type=CorpusEntryType.OWASP,
            source="OWASP Top 10 2021",
            confidence=1.0,
            verification_status=VerificationStatus.VERIFIED,
            tags=["owasp", f"rank-{owasp_data['rank']}"] + owasp_data["cwe_ids"],
            references=["https://owasp.org/Top10/"],
            created_at=now,
        )
        entries.append(entry)

    return entries


# ---------------------------------------------------------------------------
# Security Corpus
# ---------------------------------------------------------------------------


class SecurityCorpus:
    """Unified security knowledge corpus. In-memory with optional SQLite persistence.

    Does NOT duplicate security_memory.py (findings/patterns/scans).
    Stores structured threat intelligence: CVE/CWE/CAPEC/OWASP/research/exploits.
    """

    def __init__(self, db_path: Optional[str] = None, load_embedded: bool = True) -> None:
        self._entries: Dict[str, CorpusEntry] = {}
        self._db_path = db_path
        self._type_index: Dict[str, List[str]] = {}   # type → [entry_ids]
        self._tag_index: Dict[str, List[str]] = {}    # tag → [entry_ids]

        if load_embedded:
            for entry in _build_embedded_corpus():
                self._store(entry)

        if db_path:
            self._init_db(db_path)
            self._load_from_db()

    # ── Public API ─────────────────────────────────────────────────────────

    def add(self, entry: CorpusEntry) -> str:
        """Add or update a corpus entry. Returns entry_id."""
        self._store(entry)
        if self._db_path:
            self._persist_entry(entry)
        return entry.entry_id

    def get(self, entry_id: str) -> Optional[CorpusEntry]:
        return self._entries.get(entry_id)

    def query_by_type(self, entry_type: CorpusEntryType) -> List[CorpusEntry]:
        ids = self._type_index.get(entry_type.value, [])
        return [self._entries[i] for i in ids if i in self._entries]

    def query_by_tag(self, tag: str) -> List[CorpusEntry]:
        ids = self._tag_index.get(tag.lower(), [])
        return [self._entries[i] for i in ids if i in self._entries]

    def query_by_cwe(self, cwe_id: str) -> List[CorpusEntry]:
        results = []
        for entry in self._entries.values():
            if isinstance(entry, CWEEntry) and entry.cwe_id == cwe_id:
                results.append(entry)
            elif isinstance(entry, CVEEntry) and cwe_id in entry.cwe_ids:
                results.append(entry)
            elif isinstance(entry, CAPECEntry) and cwe_id in entry.related_cwes:
                results.append(entry)
            elif cwe_id.lower() in [t.lower() for t in entry.tags]:
                results.append(entry)
        return results

    def search(self, keyword: str) -> List[CorpusEntry]:
        """Full-text search across entry_id, tags, and entry-type-specific fields."""
        keyword_lower = keyword.lower()
        results = []
        for entry in self._entries.values():
            text = " ".join([
                entry.entry_id.lower(),
                " ".join(t.lower() for t in entry.tags),
                getattr(entry, "description", "").lower(),
                getattr(entry, "name", "").lower(),
                getattr(entry, "title", "").lower(),
                getattr(entry, "summary", "").lower(),
            ])
            if keyword_lower in text:
                results.append(entry)
        return results

    def all_entries(self) -> Iterator[CorpusEntry]:
        yield from self._entries.values()

    @property
    def size(self) -> int:
        return len(self._entries)

    @property
    def cwe_count(self) -> int:
        return len(self._type_index.get(CorpusEntryType.CWE.value, []))

    @property
    def cve_count(self) -> int:
        return len(self._type_index.get(CorpusEntryType.CVE.value, []))

    @property
    def capec_count(self) -> int:
        return len(self._type_index.get(CorpusEntryType.CAPEC.value, []))

    def get_stats(self) -> dict:
        return {
            "total_entries": self.size,
            "by_type": {k: len(v) for k, v in self._type_index.items()},
            "cwe_count": self.cwe_count,
            "cve_count": self.cve_count,
            "capec_count": self.capec_count,
        }

    def to_json(self) -> str:
        return json.dumps({
            "stats": self.get_stats(),
            "entries": [e.to_dict() for e in self._entries.values()],
        }, indent=2, default=str)

    # ── Internal ───────────────────────────────────────────────────────────

    def _store(self, entry: CorpusEntry) -> None:
        self._entries[entry.entry_id] = entry
        # Type index
        tkey = entry.entry_type.value
        if tkey not in self._type_index:
            self._type_index[tkey] = []
        if entry.entry_id not in self._type_index[tkey]:
            self._type_index[tkey].append(entry.entry_id)
        # Tag index
        for tag in entry.tags:
            tl = tag.lower()
            if tl not in self._tag_index:
                self._tag_index[tl] = []
            if entry.entry_id not in self._tag_index[tl]:
                self._tag_index[tl].append(entry.entry_id)

    def _init_db(self, db_path: str) -> None:
        con = sqlite3.connect(db_path)
        con.execute("""
            CREATE TABLE IF NOT EXISTS corpus_entries (
                entry_id TEXT PRIMARY KEY,
                entry_type TEXT NOT NULL,
                source TEXT,
                confidence REAL,
                verification_status TEXT,
                tags TEXT,
                references TEXT,
                data TEXT,
                created_at TEXT,
                updated_at TEXT
            )
        """)
        con.commit()
        con.close()

    def _persist_entry(self, entry: CorpusEntry) -> None:
        try:
            con = sqlite3.connect(self._db_path)
            con.execute(
                "INSERT OR REPLACE INTO corpus_entries VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    entry.entry_id,
                    entry.entry_type.value,
                    entry.source,
                    entry.confidence,
                    entry.verification_status.value,
                    json.dumps(entry.tags),
                    json.dumps(entry.references),
                    json.dumps(entry.to_dict()),
                    entry.created_at,
                    entry.updated_at,
                ),
            )
            con.commit()
            con.close()
        except Exception:
            pass

    def _load_from_db(self) -> None:
        try:
            con = sqlite3.connect(self._db_path)
            rows = con.execute("SELECT entry_id, entry_type, data FROM corpus_entries").fetchall()
            con.close()
            for row in rows:
                entry_id, entry_type, data_str = row
                try:
                    data = json.loads(data_str) if data_str else {}
                    # Reconstruct as generic CorpusEntry (subtype reconstruction omitted for brevity)
                    entry = CorpusEntry(
                        entry_id=entry_id,
                        entry_type=CorpusEntryType(entry_type),
                        source=data.get("source", "db"),
                        confidence=data.get("confidence", 0.7),
                        tags=data.get("tags", []),
                        references=data.get("references", []),
                    )
                    if entry_id not in self._entries:
                        self._store(entry)
                except Exception:
                    pass
        except Exception:
            pass
