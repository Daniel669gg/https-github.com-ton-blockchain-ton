"""VEX (Vulnerability Exploitability eXchange) document generator."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class VEXStatus(str, Enum):
    NOT_AFFECTED = "not_affected"
    AFFECTED = "affected"
    FIXED = "fixed"
    UNDER_INVESTIGATION = "under_investigation"


class VEXStatement(BaseModel):
    vulnerability_id: str           # CVE-XXXX-XXXXX
    product: str
    status: VEXStatus
    justification: str = ""         # why not_affected
    action_statement: str = ""      # what to do if affected
    impact_statement: str = ""
    timestamp: str = ""


class VEXDocument(BaseModel):
    id: str
    author: str = "TythanAI Platform"
    timestamp: str
    version: str = "1"
    statements: List[VEXStatement]


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------


class VEXGenerator:
    """Creates CycloneDX-compatible VEX (Vulnerability Exploitability eXchange) documents."""

    def create_statement(
        self,
        cve_id: str,
        product: str,
        status: VEXStatus,
        justification: str = "",
        action_statement: str = "",
        impact_statement: str = "",
    ) -> VEXStatement:
        """Create a single VEX statement with the current UTC timestamp."""
        now_iso = datetime.now(timezone.utc).isoformat()
        return VEXStatement(
            vulnerability_id=cve_id,
            product=product,
            status=status,
            justification=justification,
            action_statement=action_statement,
            impact_statement=impact_statement,
            timestamp=now_iso,
        )

    def generate_from_sbom(
        self,
        bom: "Any",   # CycloneDXBOM — avoid circular import at type-check time
        vuln_matches: List[Any],
    ) -> VEXDocument:
        """Build a VEX document from a CycloneDX BOM and a list of AdvisoryMatch objects.

        For each vulnerability found in *vuln_matches*, a VEX statement is created.
        Status is determined as follows:
          - If the CVERecord has a non-empty ``fix_versions`` entry → FIXED
          - Otherwise → AFFECTED
        Components in the BOM that have no matching vulnerabilities are omitted
        (they would be NOT_AFFECTED by default in a full audit context, but we
        only emit statements for packages that appear in the advisory matches).
        """
        statements: List[VEXStatement] = []
        now_iso = datetime.now(timezone.utc).isoformat()

        # Build a set of product names from the BOM for quick lookup
        bom_components = {c.name: c for c in getattr(bom, "components", [])}

        for match in vuln_matches:
            pkg_name: str = getattr(match, "package_name", "")
            installed_version: str = getattr(match, "installed_version", "")
            product_str = f"{pkg_name}@{installed_version}" if installed_version else pkg_name

            for record in getattr(match, "cve_records", []):
                cve_id: str = getattr(record, "cve_id", "")
                fix_versions: Dict[str, str] = getattr(record, "fix_versions", {})

                # Determine status
                fixed_version = fix_versions.get(pkg_name, "")
                if fixed_version:
                    status = VEXStatus.FIXED
                    action = f"Upgrade {pkg_name} to version {fixed_version} or later."
                    justification = ""
                    impact = ""
                else:
                    status = VEXStatus.AFFECTED
                    action = f"Monitor {pkg_name} for a security patch addressing {cve_id}."
                    justification = ""
                    impact = getattr(record, "description", "")[:256]

                statements.append(
                    VEXStatement(
                        vulnerability_id=cve_id,
                        product=product_str,
                        status=status,
                        justification=justification,
                        action_statement=action,
                        impact_statement=impact,
                        timestamp=now_iso,
                    )
                )

        doc_id = f"urn:uuid:{uuid.uuid4()}"
        return VEXDocument(
            id=doc_id,
            timestamp=now_iso,
            statements=statements,
        )

    def to_json(self, doc: VEXDocument) -> str:
        """Serialise a VEXDocument to CycloneDX VEX JSON format (indent=2)."""
        output: Dict[str, Any] = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": int(doc.version) if doc.version.isdigit() else 1,
            "serialNumber": doc.id,
            "metadata": {
                "timestamp": doc.timestamp,
                "tools": [
                    {
                        "vendor": "TythanAI",
                        "name": "ghost-security",
                        "version": "3.0",
                    }
                ],
                "authors": [{"name": doc.author}],
            },
            "vulnerabilities": [
                self._statement_to_dict(stmt) for stmt in doc.statements
            ],
        }
        return json.dumps(output, indent=2)

    # ------------------------------------------------------------------ #
    # Internal helpers                                                     #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _statement_to_dict(stmt: VEXStatement) -> Dict[str, Any]:
        analysis: Dict[str, Any] = {"state": stmt.status.value}
        if stmt.justification:
            analysis["justification"] = stmt.justification
        if stmt.action_statement:
            analysis["response"] = [stmt.action_statement]
        if stmt.impact_statement:
            analysis["detail"] = stmt.impact_statement

        result: Dict[str, Any] = {
            "id": stmt.vulnerability_id,
            "source": {
                "name": "NVD",
                "url": f"https://nvd.nist.gov/vuln/detail/{stmt.vulnerability_id}",
            },
            "affects": [
                {
                    "ref": stmt.product,
                    "versions": [{"version": stmt.product.split("@")[-1] if "@" in stmt.product else ""}],
                }
            ],
            "analysis": analysis,
        }
        if stmt.timestamp:
            result["updated"] = stmt.timestamp
        return result


# ---------------------------------------------------------------------------
# Module-level convenience function
# ---------------------------------------------------------------------------


def generate_vex(bom: "Any", matches: List[Any]) -> str:
    """Generate a CycloneDX VEX JSON document from a BOM and advisory matches."""
    gen = VEXGenerator()
    doc = gen.generate_from_sbom(bom, matches)
    return gen.to_json(doc)
