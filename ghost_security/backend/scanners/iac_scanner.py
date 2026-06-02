"""Forwarding shim — canonical location is scanners/iac_scanner.py."""
from scanners.iac_scanner import IaCScanner  # noqa: F401
IACScanner = IaCScanner  # alias for backward compatibility
