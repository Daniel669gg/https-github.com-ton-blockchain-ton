"""
core/incremental_query.py — Incremental Analysis Query Language (Phase 6, Part 11)

Provides a simple, chainable query DSL over IncrementalResult / ImpactSet data:

    q = IncrementalQuery(result)
    q.find("impacted_symbols").where(kind="function").limit(10).execute()
    q.find("invalidated_nodes").where(graph_type="call_graph").execute()
    q.find("changed_attack_paths").execute()
    q.find("changed_reachability").execute()
    q.find("incremental_findings").where(severity="HIGH").execute()
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set


# ---------------------------------------------------------------------------
# Query result item (uniform schema for all query types)
# ---------------------------------------------------------------------------

@dataclass
class QueryItem:
    kind:       str              # "symbol", "node", "attack_path", "finding", etc.
    id:         str              # unique identifier within its kind
    properties: Dict[str, Any]  = field(default_factory=dict)

    def get(self, key: str, default: Any = None) -> Any:
        return self.properties.get(key, default)

    def to_dict(self) -> dict:
        return {"kind": self.kind, "id": self.id, **self.properties}


# ---------------------------------------------------------------------------
# Query builder
# ---------------------------------------------------------------------------

class IncrementalQuery:
    """
    Chainable query over incremental analysis results.

    Supported find() targets:
        "impacted_symbols"       — symbols changed in this scan
        "invalidated_nodes"      — graph nodes that must be recomputed
        "changed_attack_paths"   — attack paths affected by changes
        "changed_reachability"   — reachability chains affected
        "incremental_findings"   — new findings from this scan

    Filters:
        .where(**kwargs)         — equality filter on item properties
        .where_fn(fn)            — arbitrary predicate
        .limit(n)                — cap result count
        .order_by(key, reverse)  — sort by a property

    Execution:
        .execute()               — returns List[QueryItem]
        .count()                 — returns int
        .ids()                   — returns List[str]
        .to_dicts()              — returns List[dict]
    """

    _SUPPORTED_TARGETS = {
        "impacted_symbols",
        "invalidated_nodes",
        "changed_attack_paths",
        "changed_reachability",
        "incremental_findings",
    }

    def __init__(self, result: Any) -> None:
        """
        result: an IncrementalResult (from core.incremental) or a plain dict with
                the same fields.
        """
        self._result = result
        self._target:   str                          = ""
        self._filters:  List[Dict[str, Any]]         = []
        self._predicates: List[Callable[[QueryItem], bool]] = []
        self._limit_n:  Optional[int]                = None
        self._sort_key: Optional[str]                = None
        self._sort_rev: bool                         = False

    # ------------------------------------------------------------------
    # Builder methods
    # ------------------------------------------------------------------

    def find(self, target: str) -> "IncrementalQuery":
        """Set the query target. Returns self for chaining."""
        if target not in self._SUPPORTED_TARGETS:
            raise ValueError(
                f"Unknown target {target!r}. Supported: {sorted(self._SUPPORTED_TARGETS)}"
            )
        self._target = target
        return self

    def where(self, **kwargs: Any) -> "IncrementalQuery":
        """Add equality filter(s) on QueryItem properties."""
        if kwargs:
            self._filters.append(kwargs)
        return self

    def where_fn(self, fn: Callable[[QueryItem], bool]) -> "IncrementalQuery":
        """Add a callable predicate filter."""
        self._predicates.append(fn)
        return self

    def limit(self, n: int) -> "IncrementalQuery":
        """Limit result count."""
        self._limit_n = n
        return self

    def order_by(self, key: str, reverse: bool = False) -> "IncrementalQuery":
        """Sort results by a property key."""
        self._sort_key = key
        self._sort_rev = reverse
        return self

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def execute(self) -> List[QueryItem]:
        """Run the query and return a list of QueryItem objects."""
        if not self._target:
            return []

        items = self._collect()
        items = self._apply_filters(items)
        if self._sort_key:
            items = sorted(items,
                           key=lambda it: it.properties.get(self._sort_key, ""),
                           reverse=self._sort_rev)
        if self._limit_n is not None:
            items = items[:self._limit_n]
        return items

    def count(self) -> int:
        return len(self.execute())

    def ids(self) -> List[str]:
        return [it.id for it in self.execute()]

    def to_dicts(self) -> List[dict]:
        return [it.to_dict() for it in self.execute()]

    # ------------------------------------------------------------------
    # Data collection per target
    # ------------------------------------------------------------------

    def _collect(self) -> List[QueryItem]:
        r = self._result
        # Normalise: accept both IncrementalResult dataclass and plain dict
        def _get(key: str, default: Any = None) -> Any:
            if isinstance(r, dict):
                return r.get(key, default)
            return getattr(r, key, default)

        target = self._target

        if target == "impacted_symbols":
            return self._collect_impacted_symbols(_get("impact_set"))

        if target == "invalidated_nodes":
            return self._collect_invalidated_nodes(_get("invalidated_nodes", {}))

        if target == "changed_attack_paths":
            return self._collect_attack_paths(_get("graph_rebuild_stats", {}))

        if target == "changed_reachability":
            return self._collect_reachability(_get("impact_set"), _get("changed_files", []))

        if target == "incremental_findings":
            return self._collect_findings(_get("new_findings", []))

        return []

    # -- impacted_symbols ------------------------------------------------

    def _collect_impacted_symbols(self, impact_set: Any) -> List[QueryItem]:
        if not impact_set:
            return []
        if isinstance(impact_set, dict):
            items: List[QueryItem] = []
            for sym in impact_set.get("directly_changed", []):
                items.append(QueryItem(
                    kind="symbol", id=sym,
                    properties={"type": "directly_changed", "symbol": sym, "kind": "unknown"},
                ))
            for sym in impact_set.get("callers", []):
                items.append(QueryItem(
                    kind="symbol", id=sym,
                    properties={"type": "caller", "symbol": sym, "kind": "unknown"},
                ))
            for sym in impact_set.get("entrypoints", []):
                items.append(QueryItem(
                    kind="symbol", id=sym,
                    properties={"type": "entrypoint", "symbol": sym, "kind": "unknown"},
                ))
            return items
        # ImpactSet object
        items = []
        for sym in getattr(impact_set, "directly_changed", set()):
            items.append(QueryItem(
                kind="symbol", id=sym,
                properties={"type": "directly_changed", "symbol": sym},
            ))
        for sym in getattr(impact_set, "callers", set()):
            items.append(QueryItem(
                kind="symbol", id=sym,
                properties={"type": "caller", "symbol": sym},
            ))
        for sym in getattr(impact_set, "entrypoints", set()):
            items.append(QueryItem(
                kind="symbol", id=sym,
                properties={"type": "entrypoint", "symbol": sym},
            ))
        return items

    # -- invalidated_nodes -----------------------------------------------

    def _collect_invalidated_nodes(self, invalidated: Dict[str, Any]) -> List[QueryItem]:
        items: List[QueryItem] = []
        for graph_type, node_ids in invalidated.items():
            if isinstance(node_ids, (list, set)):
                for nid in node_ids:
                    items.append(QueryItem(
                        kind="node", id=str(nid),
                        properties={"graph_type": graph_type, "node_id": str(nid)},
                    ))
            elif isinstance(node_ids, int):
                # Summarised as count
                items.append(QueryItem(
                    kind="node_count", id=graph_type,
                    properties={"graph_type": graph_type, "count": node_ids},
                ))
        return items

    # -- changed_attack_paths --------------------------------------------

    def _collect_attack_paths(self, rebuild_stats: Dict[str, Any]) -> List[QueryItem]:
        items: List[QueryItem] = []
        ag_stats = rebuild_stats.get("per_graph", {}).get("attack_graph", {})
        n = ag_stats.get("paths_recomputed", 0)
        for i in range(n):
            items.append(QueryItem(
                kind="attack_path", id=f"path_{i}",
                properties={"index": i, "status": "recomputed"},
            ))
        return items

    # -- changed_reachability --------------------------------------------

    def _collect_reachability(
        self, impact_set: Any, changed_files: List[str]
    ) -> List[QueryItem]:
        items: List[QueryItem] = []
        if isinstance(impact_set, dict):
            entry_points = impact_set.get("entrypoints", [])
        else:
            entry_points = list(getattr(impact_set, "entrypoints", set()))

        for ep in entry_points:
            items.append(QueryItem(
                kind="reachability_chain", id=ep,
                properties={"entrypoint": ep, "status": "invalidated"},
            ))
        for fp in changed_files:
            items.append(QueryItem(
                kind="reachability_file", id=fp,
                properties={"file": fp, "status": "changed"},
            ))
        return items

    # -- incremental_findings --------------------------------------------

    def _collect_findings(self, findings: List[dict]) -> List[QueryItem]:
        items: List[QueryItem] = []
        for i, f in enumerate(findings):
            fid = f.get("id") or f.get("rule_id") or f"{f.get('type','?')}_{i}"
            items.append(QueryItem(
                kind="finding", id=str(fid),
                properties=dict(f),
            ))
        return items

    # ------------------------------------------------------------------
    # Filter application
    # ------------------------------------------------------------------

    def _apply_filters(self, items: List[QueryItem]) -> List[QueryItem]:
        for flt in self._filters:
            items = [
                it for it in items
                if all(it.properties.get(k) == v for k, v in flt.items())
            ]
        for pred in self._predicates:
            items = [it for it in items if pred(it)]
        return items


# ---------------------------------------------------------------------------
# Convenience factory
# ---------------------------------------------------------------------------

def query(result: Any) -> IncrementalQuery:
    """Create an IncrementalQuery over *result*."""
    return IncrementalQuery(result)
