"""
backend/core/supply_chain — Dependency-level taint analysis for supply chain security.

Extends the existing SupplyChainScanner with offline vulnerability matching,
manifest parsing, import tracking, CPG taint node generation, and Finding output.
"""
from .dependency_taint import (
    DependencyTaintAnalyzer,
    DependencyAnalysisResult,
    VulnerablePackage,
    InstalledPackage,
    ImportUsage,
    ManifestParser,
    VersionChecker,
    ImportTracker,
    KNOWN_VULNERABLE_PACKAGES,
)

__all__ = [
    "DependencyTaintAnalyzer",
    "DependencyAnalysisResult",
    "VulnerablePackage",
    "InstalledPackage",
    "ImportUsage",
    "ManifestParser",
    "VersionChecker",
    "ImportTracker",
    "KNOWN_VULNERABLE_PACKAGES",
]
