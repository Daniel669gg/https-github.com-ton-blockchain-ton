"""Compatibility shim — re-exports SemgrepScanner from semgrep_integration."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from scanners.semgrep_integration import SemgrepScanner  # noqa: F401

__all__ = ["SemgrepScanner"]
