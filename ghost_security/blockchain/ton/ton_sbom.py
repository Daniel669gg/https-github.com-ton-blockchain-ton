"""
TythanAI Phase 8 — TON Blockchain SBOM (Software Bill of Materials)

Builds a complete inventory of TON smart contract projects:
- Contract names, types, and languages (FunC/Tact)
- Import dependencies and standard libraries
- Upgrade paths (set_code / code reassignment)
- Privileged actors (hardcoded addresses, owner patterns)
- Vulnerability summary per contract
- Dependency graph for inter-contract relationships

Produced per-project from source file analysis (no runtime required).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Source pattern matchers
# ---------------------------------------------------------------------------

_IMPORT_FUNC  = re.compile(r'#include\s+"([^"]+)"')
_IMPORT_TACT1 = re.compile(r'import\s+"([^"]+)"')
_IMPORT_TACT2 = re.compile(r'import\s+\{[^}]+\}\s+from\s+"([^"]+)"')

_STDLIB_REF   = re.compile(r'@stdlib/([^\s";]+)|stdlib\.fc|utils\.fc|params\.fc|op-codes\.fc')

_UPGRADE_FUNC = re.compile(r'\bset_code\s*\(')
_UPGRADE_TACT = re.compile(r'\bself\s*\.\s*code\s*=')

_PRIV_ADDR    = re.compile(r'[EUk][Qq][A-Za-z0-9_\-]{46}')   # TON raw address

_OWNER_ASSIGN = re.compile(
    r'(?:owner|admin|manager|authority|governor)\s*[:=]\s*([^\s;,\n]+)',
    re.IGNORECASE,
)

_CONTRACT_TYPE_MAP: List[tuple] = [
    (re.compile(r'JettonMaster|jetton.master|TokenRoot',    re.I), "jetton_master"),
    (re.compile(r'JettonWallet|jetton.wallet|TokenWallet',  re.I), "jetton_wallet"),
    (re.compile(r'NFTCollection|nft.collection',            re.I), "nft_collection"),
    (re.compile(r'NFTItem|nft.item',                        re.I), "nft_item"),
    (re.compile(r'Multisig|multisig|MultiSig',              re.I), "multisig"),
    (re.compile(r'Treasury|treasury',                       re.I), "treasury"),
    (re.compile(r'DAO|dao\b',                               re.I), "dao"),
    (re.compile(r'WalletV[234]|wallet.v[234]',              re.I), "wallet"),
    (re.compile(r'\bbridge\b|\bBridge\b',                   re.I), "bridge"),
    (re.compile(r'lockup|vesting|Lockup',                   re.I), "lockup"),
    (re.compile(r'proxy|Proxy',                             re.I), "proxy"),
]

# Risk level thresholds
_RISK_THRESHOLDS = [
    (lambda e: e.upgrade_path and len(e.vulnerability_ids) > 0,   "CRITICAL"),
    (lambda e: len(e.vulnerability_ids) >= 5,                      "HIGH"),
    (lambda e: len(e.vulnerability_ids) >= 2 or e.upgrade_path,   "MEDIUM"),
    (lambda e: len(e.vulnerability_ids) >= 1,                      "LOW"),
]


@dataclass
class SBOMEntry:
    """Inventory record for a single smart contract file."""
    name:              str
    contract_type:     str
    file:              str
    language:          str                          # "func" | "tact" | "tlb"
    dependencies:      List[str] = field(default_factory=list)
    libraries:         List[str] = field(default_factory=list)
    upgrade_path:      bool = False
    privileged_actors: List[str] = field(default_factory=list)
    vulnerability_ids: List[str] = field(default_factory=list)
    line_count:        int = 0
    risk_level:        str = "UNKNOWN"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name":              self.name,
            "contract_type":     self.contract_type,
            "file":              self.file,
            "language":          self.language,
            "dependencies":      self.dependencies,
            "libraries":         self.libraries,
            "upgrade_path":      self.upgrade_path,
            "privileged_actors": self.privileged_actors,
            "vulnerability_ids": self.vulnerability_ids,
            "line_count":        self.line_count,
            "risk_level":        self.risk_level,
        }


@dataclass
class BlockchainSBOM:
    """Project-level Blockchain Software Bill of Materials."""
    project_name:         str
    total_contracts:      int
    total_lines:          int
    upgradeable_count:    int
    has_privileged_actors: bool
    entries:              List[SBOMEntry] = field(default_factory=list)
    dependency_graph:     Dict[str, List[str]] = field(default_factory=dict)
    all_privileged_actors: List[str] = field(default_factory=list)

    @property
    def critical_contracts(self) -> List[SBOMEntry]:
        return [e for e in self.entries if e.risk_level == "CRITICAL"]

    @property
    def upgradeable_contracts(self) -> List[SBOMEntry]:
        return [e for e in self.entries if e.upgrade_path]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "project_name":          self.project_name,
            "total_contracts":       self.total_contracts,
            "total_lines":           self.total_lines,
            "upgradeable_count":     self.upgradeable_count,
            "has_privileged_actors": self.has_privileged_actors,
            "all_privileged_actors": self.all_privileged_actors,
            "dependency_graph":      self.dependency_graph,
            "critical_contracts":    [e.to_dict() for e in self.critical_contracts],
            "contracts":             [e.to_dict() for e in self.entries],
        }


class BlockchainSBOMBuilder:
    """
    Builds a BlockchainSBOM from a list of TON smart contract source files.
    Optionally incorporates scanner findings for vulnerability mapping.
    """

    def build(
        self,
        files: List[str],
        findings: Optional[List[Dict[str, Any]]] = None,
        project_name: str = "TON Project",
    ) -> BlockchainSBOM:
        # Index findings by file path
        findings_by_file: Dict[str, List[str]] = {}
        for f in (findings or []):
            fp = f.get("file", "")
            rid = f.get("rule_id", f.get("id", "?"))
            if fp:
                findings_by_file.setdefault(fp, []).append(rid)

        entries: List[SBOMEntry] = []
        dep_graph: Dict[str, List[str]] = {}

        for file_path in files:
            p = Path(file_path)
            if not p.exists():
                continue
            try:
                source = p.read_text(errors="replace")
            except OSError:
                continue
            lang = _detect_language(p)
            entry = self._analyze_file(p, source, lang)
            entry.vulnerability_ids = findings_by_file.get(file_path, [])
            entry.risk_level = self._compute_risk(entry)
            entries.append(entry)
            dep_graph[entry.name] = list(entry.dependencies)

        total_lines = sum(e.line_count for e in entries)
        upgradeable = sum(1 for e in entries if e.upgrade_path)

        all_actors: List[str] = []
        for e in entries:
            for a in e.privileged_actors:
                if a not in all_actors:
                    all_actors.append(a)

        return BlockchainSBOM(
            project_name=project_name,
            total_contracts=len(entries),
            total_lines=total_lines,
            upgradeable_count=upgradeable,
            has_privileged_actors=bool(all_actors),
            entries=entries,
            dependency_graph=dep_graph,
            all_privileged_actors=all_actors,
        )

    # ------------------------------------------------------------------
    # Per-file analysis
    # ------------------------------------------------------------------

    def _analyze_file(self, p: Path, source: str, lang: str) -> SBOMEntry:
        deps:   List[str] = _extract_imports(source)
        libs:   List[str] = _extract_libraries(source)
        upgrade = _has_upgrade(source, lang)
        actors: List[str] = _extract_privileged_actors(source)
        ctype  = _infer_contract_type(source)
        return SBOMEntry(
            name=p.stem,
            contract_type=ctype,
            file=str(p),
            language=lang,
            dependencies=deps,
            libraries=libs,
            upgrade_path=upgrade,
            privileged_actors=actors,
            line_count=source.count("\n") + 1,
        )

    @staticmethod
    def _compute_risk(entry: SBOMEntry) -> str:
        for condition, level in _RISK_THRESHOLDS:
            try:
                if condition(entry):
                    return level
            except Exception:
                pass
        return "SAFE"


# ---------------------------------------------------------------------------
# Extraction helpers
# ---------------------------------------------------------------------------

def _detect_language(p: Path) -> str:
    ext = p.suffix.lower()
    if ext in (".tact",):        return "tact"
    if ext in (".tlb",):         return "tlb"
    return "func"


def _extract_imports(source: str) -> List[str]:
    deps: List[str] = []
    for pat in (_IMPORT_FUNC, _IMPORT_TACT1, _IMPORT_TACT2):
        for m in pat.finditer(source):
            d = m.group(1)
            if d not in deps:
                deps.append(d)
    return deps


def _extract_libraries(source: str) -> List[str]:
    libs: List[str] = []
    for m in _STDLIB_REF.finditer(source):
        lib = m.group(0)
        if lib not in libs:
            libs.append(lib)
    return libs


def _has_upgrade(source: str, lang: str) -> bool:
    if lang == "tact":
        return bool(_UPGRADE_TACT.search(source))
    return bool(_UPGRADE_FUNC.search(source))


def _extract_privileged_actors(source: str) -> List[str]:
    actors: List[str] = []
    for m in _PRIV_ADDR.finditer(source):
        a = m.group(0)
        if a not in actors:
            actors.append(a)
    for m in _OWNER_ASSIGN.finditer(source):
        a = m.group(1).strip("\"'();,")
        if a and len(a) > 5 and a not in actors:
            actors.append(a)
    return actors


def _infer_contract_type(source: str) -> str:
    for pattern, ctype in _CONTRACT_TYPE_MAP:
        if pattern.search(source):
            return ctype
    return "unknown"
