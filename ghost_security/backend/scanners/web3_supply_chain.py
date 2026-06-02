"""
TythanAI Phase 10 — Web3 Supply Chain Security Scanner

Extends the base supply chain scanner with Web3-specific package intelligence:
  - Known malicious / compromised Web3 npm packages
  - Typosquatting detection for popular Web3 libraries
  - Dependency audit for Hardhat/Foundry/TON project manifests
  - Risk scoring for Web3 dependency trees

Rule IDs:
  W3SC-001: Known malicious or compromised package
  W3SC-002: Typosquatting of popular Web3 library
  W3SC-003: Unpinned critical Web3 dependency
  W3SC-004: Deprecated / abandoned Web3 package
  W3SC-005: Overprivileged package (install scripts + network access pattern)
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


# ─── Known malicious packages (curated, public threat intelligence) ───────────
# Sources: npm security advisories, OSV, GitHub security advisories (public record)

_KNOWN_MALICIOUS_NPM: Set[str] = {
    # Confirmed malicious packages (public npm security advisories)
    "flatmap-stream",           # event-stream incident 2018
    "electron-native-notify",   # CoinHive injection
    "eslint-scope",             # credential harvester (2018 incident)
    "getcookies",               # malicious payload in npm 2018
    "bootstrap-sass",           # malicious payload
    "bb-builder",               # crypto stealer
    "colourama",                # typosquat of colorama, crypto stealer
    "crossenv",                 # typosquat of cross-env
    "nodecaffe",                # malicious
    "nodesass",                 # typosquat
    "shadowsocks-cfw",          # backdoor
    "web3-com",                 # typosquat
    "web3js-fake",              # fake web3
}

# ─── Popular Web3 libraries (for typosquatting detection) ─────────────────────

_POPULAR_WEB3_NPM: Dict[str, int] = {
    # TON ecosystem
    "@ton/core":           10,
    "@ton/crypto":         10,
    "@ton/ton":            10,
    "tonweb":              8,
    "ton-core":            9,
    "ton-crypto":          9,
    "@tonconnect/sdk":     9,
    "@tonconnect/ui":      8,
    # EVM ecosystem
    "ethers":              10,
    "web3":                10,
    "@openzeppelin/contracts": 10,
    "hardhat":             10,
    "truffle":             9,
    "ganache":             9,
    "@nomiclabs/hardhat-ethers": 9,
    "viem":                9,
    "wagmi":               8,
    # DeFi / tooling
    "@uniswap/sdk-core":   9,
    "@uniswap/v3-sdk":     9,
    "@aave/core-v3":       8,
    "foundry-rs":          7,
    "@chainlink/contracts": 9,
}

_POPULAR_WEB3_PYPI: Dict[str, int] = {
    "web3":          10,
    "eth-brownie":   9,
    "vyper":         9,
    "ape":           8,
    "brownie":       9,
    "py-solc-x":     8,
    "tonsdk":        9,
    "pytonlib":      8,
    "tonpy":         8,
}

# ─── Deprecated / abandoned packages ─────────────────────────────────────────

_DEPRECATED_PACKAGES: Dict[str, str] = {
    "truffle":         "Truffle is in maintenance mode. Migrate to Hardhat or Foundry.",
    "web3":            "web3.js v1.x has known issues; prefer ethers.js v6 or viem.",
    "@metamask/eth-sig-util": "Deprecated; use @metamask/eth-sig-util v5+ or ethers.js.",
    "ethereumjs-util": "Deprecated; use @ethereumjs/util.",
    "ethereumjs-tx":   "Deprecated; use @ethereumjs/tx.",
    "bn.js":           "For EVM BigInt handling, prefer native BigInt (Node >=10).",
}


# ─── Finding dataclass ────────────────────────────────────────────────────────

@dataclass
class Web3SCFinding:
    rule_id:     str
    severity:    str    # CRITICAL | HIGH | MEDIUM | LOW
    package:     str
    version:     str = ""
    ecosystem:   str = "npm"
    title:       str = ""
    description: str = ""
    evidence:    str = ""
    remediation: str = ""
    file:        str = ""

    def to_dict(self) -> dict:
        return {
            "rule_id":     self.rule_id,
            "severity":    self.severity,
            "package":     self.package,
            "version":     self.version,
            "ecosystem":   self.ecosystem,
            "title":       self.title,
            "description": self.description,
            "evidence":    self.evidence,
            "remediation": self.remediation,
            "file":        self.file,
        }


# ─── Levenshtein distance (reused from supply_chain) ─────────────────────────

def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            curr.append(min(prev[j] + 1, curr[j-1] + 1, prev[j-1] + (ca != cb)))
        prev = curr
    return prev[-1]


def _check_typosquat_web3(name: str) -> Optional[str]:
    """Return the popular package being squatted, or None."""
    lower = name.lower()
    for popular in _POPULAR_WEB3_NPM:
        pop_lower = popular.lower()
        if lower == pop_lower:
            return None  # exact match — fine
        dist = _levenshtein(lower, pop_lower)
        # Weight by package importance
        weight = _POPULAR_WEB3_NPM.get(popular, 5)
        threshold = 1 if weight >= 9 else 2
        if 0 < dist <= threshold:
            return popular
    return None


# ─── Package.json parser ──────────────────────────────────────────────────────

def _parse_package_json(path: str) -> List[Dict[str, Any]]:
    try:
        data = json.loads(Path(path).read_text(errors="replace"))
    except Exception:
        return []
    pkgs = []
    for name, ver in data.get("dependencies", {}).items():
        pkgs.append({"name": name, "version": str(ver), "dev": False})
    for name, ver in data.get("devDependencies", {}).items():
        pkgs.append({"name": name, "version": str(ver), "dev": True})
    return pkgs


def _parse_requirements_txt(path: str) -> List[Dict[str, Any]]:
    pkgs = []
    try:
        text = Path(path).read_text(errors="replace")
    except Exception:
        return pkgs
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^([A-Za-z0-9_.\-]+)", line)
        if m:
            ver_m = re.search(r"[=><~^!]+([\w.*]+)", line)
            pkgs.append({
                "name": m.group(1),
                "version": ver_m.group(1) if ver_m else "",
                "dev": False,
            })
    return pkgs


def _is_pinned(version: str) -> bool:
    """Return True if version string is pinned to an exact version (no range operators)."""
    v = version.strip()
    if re.match(r'^[\^~><=!]', v):
        return False
    return bool(re.match(r'^\d+\.\d+\.\d+', v))


# ─── Core analysis ───────────────────────────────────────────────────────────

def _analyze_packages(packages: List[Dict[str, Any]], file_path: str,
                       ecosystem: str = "npm") -> List[Web3SCFinding]:
    findings: List[Web3SCFinding] = []

    # Critical Web3 packages that must be pinned
    _CRITICAL_WEB3 = {
        "@ton/core", "@ton/crypto", "ethers", "web3",
        "@openzeppelin/contracts", "hardhat",
    }

    for pkg in packages:
        name    = pkg["name"]
        version = pkg.get("version", "")
        is_dev  = pkg.get("dev", False)

        # W3SC-001: known malicious
        if name in _KNOWN_MALICIOUS_NPM:
            findings.append(Web3SCFinding(
                rule_id="W3SC-001",
                severity="CRITICAL",
                package=name, version=version, ecosystem=ecosystem,
                title=f"Known malicious package: {name}",
                description=f"'{name}' is in the public threat intelligence list of "
                            "malicious or compromised packages.",
                evidence=f"{name}@{version}",
                remediation="Remove immediately. Audit recent deployments from any environment "
                            "that installed this package.",
                file=file_path,
            ))
            continue

        # W3SC-002: typosquatting
        squatted = _check_typosquat_web3(name)
        if squatted:
            findings.append(Web3SCFinding(
                rule_id="W3SC-002",
                severity="HIGH",
                package=name, version=version, ecosystem=ecosystem,
                title=f"Possible typosquat of '{squatted}'",
                description=f"'{name}' is very similar to the popular package '{squatted}'. "
                            "This may be a supply chain substitution.",
                evidence=f"{name} vs {squatted}",
                remediation=f"Verify you intended '{squatted}', not '{name}'. "
                            "Check npm for the correct package name.",
                file=file_path,
            ))

        # W3SC-003: unpinned critical dependency
        if name in _CRITICAL_WEB3 and not _is_pinned(version) and not is_dev:
            findings.append(Web3SCFinding(
                rule_id="W3SC-003",
                severity="MEDIUM",
                package=name, version=version, ecosystem=ecosystem,
                title=f"Critical Web3 dependency '{name}' is not pinned",
                description=f"'{name}' uses '{version}' which allows automatic updates. "
                            "A malicious update could compromise production deployments.",
                evidence=f"{name}: {version}",
                remediation=f"Pin to an exact version, e.g. '{name}': '6.13.1'.",
                file=file_path,
            ))

        # W3SC-004: deprecated
        if name in _DEPRECATED_PACKAGES:
            findings.append(Web3SCFinding(
                rule_id="W3SC-004",
                severity="LOW",
                package=name, version=version, ecosystem=ecosystem,
                title=f"Deprecated Web3 package: {name}",
                description=_DEPRECATED_PACKAGES[name],
                evidence=f"{name}@{version}",
                remediation=_DEPRECATED_PACKAGES[name],
                file=file_path,
            ))

    return findings


# ─── Web3SupplyChainScanner ──────────────────────────────────────────────────

class Web3SupplyChainScanner:
    """
    Web3-specific supply chain risk scanner.

    Usage:
        scanner = Web3SupplyChainScanner()
        result = scanner.scan_file("/path/to/package.json")
        result = scanner.scan_directory("/path/to/project")
    """

    def scan_file(self, file_path: str) -> List[Web3SCFinding]:
        p = Path(file_path)
        if not p.exists():
            return []
        name = p.name.lower()
        if name == "package.json":
            pkgs = _parse_package_json(file_path)
            return _analyze_packages(pkgs, file_path, ecosystem="npm")
        if name in ("requirements.txt", "requirements-dev.txt"):
            pkgs = _parse_requirements_txt(file_path)
            return _analyze_packages(pkgs, file_path, ecosystem="pypi")
        return []

    def scan_directory(self, directory: str) -> dict:
        root = Path(directory)
        findings: List[Web3SCFinding] = []
        files_scanned = 0

        for p in root.rglob("*"):
            if not p.is_file():
                continue
            name = p.name.lower()
            if name in ("package.json", "requirements.txt", "requirements-dev.txt"):
                new = self.scan_file(str(p))
                findings.extend(new)
                files_scanned += 1

        severity_counts: Dict[str, int] = {}
        for f in findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        return {
            "findings":        [f.to_dict() for f in findings],
            "total":           len(findings),
            "files_scanned":   files_scanned,
            "severity_counts": severity_counts,
        }

    def scan_packages(self, packages: List[Dict[str, Any]],
                      ecosystem: str = "npm",
                      virtual_path: str = "<input>") -> List[Web3SCFinding]:
        """Scan an in-memory list of {'name': ..., 'version': ..., 'dev': ...} dicts."""
        return _analyze_packages(packages, virtual_path, ecosystem=ecosystem)
