"""Forwarding shim — canonical location is scanners/supply_chain_scanner.py.

Also re-exports the genuine module-level manifest parsers that historically
lived here.  After the scanner split, the real implementations moved to
``scanners/dependency_confusion.py``; these aliases preserve the original
``backend.scanners.supply_chain`` import surface (real functionality, no stubs).
"""
from scanners.supply_chain_scanner import SupplyChainScanner  # noqa: F401
from scanners.dependency_confusion import (  # noqa: F401
    _parse_requirements_txt,
    _parse_package_json,
)
