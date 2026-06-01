"""Reachable VEX — auto-assign VEX status based on code reachability analysis."""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from backend.sbom.vex import VEXDocument, VEXGenerator, VEXStatement, VEXStatus

logger = logging.getLogger(__name__)

# Justification text for NOT_AFFECTED auto-assignment
_NOT_AFFECTED_JUSTIFICATION = (
    "Reachability analysis determined that the vulnerable code path in this "
    "dependency is not reachable from application entry points. The affected "
    "function is imported but not invoked in any live execution path."
)

_AFFECTED_JUSTIFICATION = (
    "Reachability analysis confirmed that a tainted data flow reaches the "
    "vulnerable function in this dependency from an external entry point."
)


class ReachableVEXGenerator:
    """Extends VEXGenerator to auto-assign NOT_AFFECTED status using reachability data."""

    def __init__(self) -> None:
        self._vex_gen = VEXGenerator()

    # ------------------------------------------------------------------
    # Main API
    # ------------------------------------------------------------------

    def generate_from_reachability(
        self,
        base_vex: VEXDocument,
        reachable_cves: List[Any],  # List[ReachableCVE] from reachable_cve.py
    ) -> VEXDocument:
        """Update *base_vex* statements using reachability data.

        For each VEXStatement in *base_vex*:
          - If the corresponding CVE is NOT reachable → set status to NOT_AFFECTED
          - If the corresponding CVE IS reachable → set status to AFFECTED (or keep FIXED)
          - If no reachability data → keep the original status
        """
        reachability_map = self._build_reachability_map(reachable_cves)
        updated_statements: List[VEXStatement] = []
        now_iso = datetime.now(timezone.utc).isoformat()

        for stmt in base_vex.statements:
            cve_id = stmt.vulnerability_id
            if cve_id not in reachability_map:
                # No reachability data — keep as-is
                updated_statements.append(stmt)
                continue

            is_reachable, reach_score, call_path = reachability_map[cve_id]

            if stmt.status == VEXStatus.FIXED:
                # Already fixed — no override needed
                updated_statements.append(stmt)
                continue

            if not is_reachable:
                call_path_str = " → ".join(call_path) if call_path else "none"
                updated_statements.append(
                    VEXStatement(
                        vulnerability_id=cve_id,
                        product=stmt.product,
                        status=VEXStatus.NOT_AFFECTED,
                        justification=_NOT_AFFECTED_JUSTIFICATION,
                        action_statement="No action required — code path is not reachable.",
                        impact_statement=(
                            f"Reachability score: {reach_score:.2f}. "
                            f"Closest call path: {call_path_str}"
                        ),
                        timestamp=now_iso,
                    )
                )
            else:
                call_path_str = " → ".join(call_path) if call_path else "unknown"
                updated_statements.append(
                    VEXStatement(
                        vulnerability_id=cve_id,
                        product=stmt.product,
                        status=VEXStatus.AFFECTED,
                        justification="",
                        action_statement=stmt.action_statement or (
                            f"Patch or mitigate {stmt.product}. "
                            f"Reachable via: {call_path_str}"
                        ),
                        impact_statement=(
                            f"Reachability confirmed (score={reach_score:.2f}). "
                            f"Call path: {call_path_str}"
                        ),
                        timestamp=now_iso,
                    )
                )

        doc_id = f"urn:uuid:{uuid.uuid4()}"
        return VEXDocument(
            id=doc_id,
            author=base_vex.author,
            timestamp=now_iso,
            version=str(int(base_vex.version or "1") + 1),
            statements=updated_statements,
        )

    def auto_assign_not_affected(
        self,
        vex_doc: VEXDocument,
        reachable_map: Dict[str, bool],
    ) -> VEXDocument:
        """Simple boolean override — for each CVE in *reachable_map*,
        set NOT_AFFECTED if False, AFFECTED if True."""
        reachable_cves_compat = [
            _ReachableCVECompat(
                cve_id=cve_id,
                is_reachable=is_reach,
                reachability_score=1.0 if is_reach else 0.0,
                call_path=[],
            )
            for cve_id, is_reach in reachable_map.items()
        ]
        return self.generate_from_reachability(vex_doc, reachable_cves_compat)

    def to_json(self, doc: VEXDocument) -> str:
        """Delegate JSON serialisation to VEXGenerator."""
        return self._vex_gen.to_json(doc)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_reachability_map(
        reachable_cves: List[Any],
    ) -> Dict[str, tuple]:
        """Build {cve_id: (is_reachable, score, call_path)} from reachable CVEs."""
        result: Dict[str, tuple] = {}
        for rc in reachable_cves:
            cve_id = getattr(rc, "cve_id", "")
            if not cve_id:
                continue
            is_reachable = bool(getattr(rc, "is_reachable", False))
            reach_score = float(getattr(rc, "reachability_score", 0.0))
            call_path = list(getattr(rc, "call_path", []))
            # Keep the highest reachability score if multiple entries
            if cve_id not in result or reach_score > result[cve_id][1]:
                result[cve_id] = (is_reachable, reach_score, call_path)
        return result


# ---------------------------------------------------------------------------
# Minimal compat shim used by auto_assign_not_affected
# ---------------------------------------------------------------------------

class _ReachableCVECompat:
    __slots__ = ("cve_id", "is_reachable", "reachability_score", "call_path")

    def __init__(
        self,
        cve_id: str,
        is_reachable: bool,
        reachability_score: float,
        call_path: List[str],
    ) -> None:
        self.cve_id = cve_id
        self.is_reachable = is_reachable
        self.reachability_score = reachability_score
        self.call_path = call_path
