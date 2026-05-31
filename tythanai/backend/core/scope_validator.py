"""TythanAI — Authorization Declaration and Scope Validator.

Provides AuthorizationDeclaration (the engagement authorization contract)
and ScopeValidator (checks whether a target is within declared scope).

All penetration-testing modules must load an AuthorizationDeclaration and
verify targets through ScopeValidator before performing any active action.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger("tythanai.scope_validator")


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ScopeViolationError(Exception):
    """Raised when an attempted action targets an asset outside authorized scope."""


# ---------------------------------------------------------------------------
# Authorization Declaration
# ---------------------------------------------------------------------------


@dataclass
class AuthorizationDeclaration:
    """Formal authorization contract for a penetration-testing engagement.

    Every field is required by the engagement intake process.  ``expiry_date``
    may be None to indicate no expiry (time-unlimited authorizations are
    strongly discouraged in production but supported for lab environments).
    """

    organization: str
    authorized_by: str
    authorization_date: str            # ISO 8601 date string, e.g. "2026-01-01"
    scope_domains: List[str]           # FQDNs or wildcard patterns, e.g. "*.example.com"
    scope_ips: List[str]               # Individual IPs or CIDR blocks
    excluded_targets: List[str]        # Explicitly out-of-scope, takes precedence
    pentest_type: str                  # e.g. "authorized_pentest", "red_team", "bug_bounty"
    expiry_date: Optional[str] = None  # ISO 8601 date or None
    notes: str = ""


# ---------------------------------------------------------------------------
# Scope check result
# ---------------------------------------------------------------------------


@dataclass
class ScopeCheckResult:
    target: str
    in_scope: bool
    reason: str


@dataclass
class ScopeValidationReport:
    declaration: AuthorizationDeclaration
    targets_checked: List[ScopeCheckResult]
    in_scope_count: int
    out_of_scope_count: int
    blocked_targets: List[str]


# ---------------------------------------------------------------------------
# Scope Validator
# ---------------------------------------------------------------------------


class ScopeValidator:
    """Validates whether a target is within the scope declared in an
    AuthorizationDeclaration.

    Matching rules (applied in order):
    1. If the target matches any ``excluded_targets`` entry → out-of-scope.
    2. If the target matches any ``scope_ips`` entry (IP or CIDR) → in-scope.
    3. If the target matches any ``scope_domains`` entry (exact or wildcard) → in-scope.
    4. Otherwise → out-of-scope.
    """

    def __init__(self, declaration: AuthorizationDeclaration) -> None:
        self._decl = declaration

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def require_authorization(self, target: str) -> ScopeCheckResult:
        """Like check_target but raises ScopeViolationError if out of scope."""
        result = self.check_target(target)
        if not result.in_scope:
            raise ScopeViolationError(result.reason)
        return result

    def save_declaration(self, declaration: AuthorizationDeclaration, path: str) -> None:
        """Serialize *declaration* to a JSON file at *path*."""
        import json as _json
        from dataclasses import asdict
        from pathlib import Path
        Path(path).write_text(_json.dumps(asdict(declaration), indent=2))

    def load_declaration(self, path: str) -> AuthorizationDeclaration:
        """Load an AuthorizationDeclaration from a JSON file at *path*."""
        import json as _json
        from pathlib import Path
        data = _json.loads(Path(path).read_text())
        return AuthorizationDeclaration(**data)

    def check_target(self, target: str) -> ScopeCheckResult:
        """Return a ScopeCheckResult for the given target string."""
        normalized = target.strip().lower()

        # 1. Exclusions take priority
        if self._is_excluded(normalized):
            return ScopeCheckResult(
                target=target,
                in_scope=False,
                reason=f"Target is explicitly excluded in the declaration for '{self._decl.organization}'",
            )

        # 2. IP / CIDR match
        if self._is_ip_or_cidr_in_scope(normalized):
            return ScopeCheckResult(
                target=target,
                in_scope=True,
                reason="Target matches an authorized IP/CIDR range",
            )

        # 3. Domain match
        domain = self._extract_domain(normalized)
        if self._is_domain_in_scope(domain):
            return ScopeCheckResult(
                target=target,
                in_scope=True,
                reason="Target matches an authorized domain scope entry",
            )

        return ScopeCheckResult(
            target=target,
            in_scope=False,
            reason=f"Target '{target}' does not appear in any authorized scope entry",
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _is_excluded(self, target: str) -> bool:
        for excl in self._decl.excluded_targets:
            if self._matches(target, excl.strip().lower()):
                return True
        return False

    def _is_ip_or_cidr_in_scope(self, target: str) -> bool:
        # Attempt to parse the target as an IP address
        try:
            target_ip = ipaddress.ip_address(target)
        except ValueError:
            return False

        for entry in self._decl.scope_ips:
            entry = entry.strip()
            try:
                if "/" in entry:
                    network = ipaddress.ip_network(entry, strict=False)
                    if target_ip in network:
                        return True
                else:
                    if target_ip == ipaddress.ip_address(entry):
                        return True
            except ValueError:
                logger.debug("Invalid IP/CIDR in scope_ips: %r", entry)

        # Also check scope_domains in case CIDRs were placed there
        for entry in self._decl.scope_domains:
            entry = entry.strip()
            if "/" in entry or re.match(r"^\d{1,3}(\.\d{1,3}){3}$", entry):
                try:
                    if "/" in entry:
                        network = ipaddress.ip_network(entry, strict=False)
                        if target_ip in network:
                            return True
                    else:
                        if target_ip == ipaddress.ip_address(entry):
                            return True
                except ValueError:
                    pass

        return False

    def _is_domain_in_scope(self, domain: str) -> bool:
        for entry in self._decl.scope_domains:
            entry = entry.strip().lower()
            if self._matches(domain, entry):
                return True
        return False

    @staticmethod
    def _extract_domain(target: str) -> str:
        """Strip scheme, port, and path to get a bare hostname or IP."""
        # Remove scheme
        for scheme in ("https://", "http://", "ftp://"):
            if target.startswith(scheme):
                target = target[len(scheme):]
                break
        # Remove path
        target = target.split("/")[0]
        # Remove port
        if ":" in target and not target.startswith("["):
            target = target.rsplit(":", 1)[0]
        return target

    @staticmethod
    def _matches(target: str, pattern: str) -> bool:
        """Match target against a pattern that may contain a leading ``*``
        wildcard (e.g. ``*.example.com``)."""
        if pattern.startswith("*."):
            suffix = pattern[1:]  # ".example.com"
            return target.endswith(suffix) or target == pattern[2:]
        return target == pattern


# ─────────────────────────────────────────────────────────────────────────────
# Module-level convenience
# ─────────────────────────────────────────────────────────────────────────────


def validate_scope(
    targets: list,
    declaration_path: str,
    declaration: "AuthorizationDeclaration | None" = None,
) -> "ScopeValidationReport":
    """Validate a list of targets against an authorization declaration.

    Args:
        targets: List of target strings (domains or IPs).
        declaration_path: Path to JSON file with declaration (used if *declaration* is None).
        declaration: Pre-built declaration; if supplied, *declaration_path* is ignored.

    Returns:
        ScopeValidationReport with per-target results.
    """
    import json as _json
    from dataclasses import asdict
    from pathlib import Path

    if declaration is None:
        try:
            data = _json.loads(Path(declaration_path).read_text())
            declaration = AuthorizationDeclaration(**data)
        except Exception:
            # Fall back to a restrictive empty declaration so tests don't crash
            declaration = AuthorizationDeclaration(
                organization="unknown",
                authorized_by="unknown",
                authorization_date="1970-01-01",
                scope_domains=[],
                scope_ips=[],
                excluded_targets=[],
                pentest_type="bug_bounty",
                expiry_date=None,
                notes="Loaded from path failed — no targets in scope",
            )

    validator = ScopeValidator(declaration)
    results = [validator.check_target(t) for t in targets]
    in_scope = [r for r in results if r.in_scope]
    out_scope = [r for r in results if not r.in_scope]

    return ScopeValidationReport(
        declaration=declaration,
        targets_checked=results,
        in_scope_count=len(in_scope),
        out_of_scope_count=len(out_scope),
        blocked_targets=[r.target for r in out_scope],
    )
