"""
backend/memory/memory_manager.py — TythanAI multi-level memory system.

Four memory layers:
  short_term  — per-session ephemeral context (collection name includes session_id)
  long_term   — persisted findings, fixes, confirmed patterns across sessions
  semantic    — CWE/CVE knowledge, attack patterns, security concepts
  episodic    — run history, agent decisions, re-evaluation records

Backend priority:
  1. ChromaDB (in-memory when persist_dir=None, PersistentClient otherwise)
  2. SQLite BM25-style fallback when chromadb is absent or raises

All public methods are safe to call even if ChromaDB is unavailable.
"""
from __future__ import annotations

import json
import logging
import math
import re
import sqlite3
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional
from uuid import uuid4

logger = logging.getLogger("tythanai.memory")

# ---------------------------------------------------------------------------
# Optional ChromaDB import
# ---------------------------------------------------------------------------
try:
    import chromadb as _chromadb  # type: ignore[import]
    _CHROMADB_AVAILABLE = True
except ImportError:
    _chromadb = None  # type: ignore[assignment]
    _CHROMADB_AVAILABLE = False


# ---------------------------------------------------------------------------
# Data-transfer objects
# ---------------------------------------------------------------------------

@dataclass
class MemoryEntry:
    """A single item stored in any memory layer."""
    entry_id: str
    content: str
    metadata: Dict[str, Any]
    timestamp: str
    memory_type: str  # "finding" | "episode" | "knowledge" | "pattern"


@dataclass
class MemorySearchResult:
    """A retrieved memory entry with relevance scores."""
    entry: MemoryEntry
    score: float    # 0.0 – 1.0  (higher = more relevant)
    distance: float  # lower = closer (ChromaDB convention; for SQLite: 1 - score)


# ---------------------------------------------------------------------------
# SQLite fallback — schema + BM25-style retrieval
# ---------------------------------------------------------------------------

_FALLBACK_SCHEMA = """
CREATE TABLE IF NOT EXISTS memory_entries (
    id            TEXT PRIMARY KEY,
    content       TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    memory_layer  TEXT NOT NULL,
    memory_type   TEXT NOT NULL DEFAULT 'knowledge',
    timestamp     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_me_layer ON memory_entries(memory_layer);
"""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _tokenize(text: str) -> List[str]:
    """Lowercase word tokenizer — no external deps."""
    return re.findall(r"[a-z0-9]+", text.lower())


def _bm25_score(query_tokens: List[str], doc_tokens: List[str], k1: float = 1.5, b: float = 0.75,
                avg_dl: float = 50.0) -> float:
    """
    Simplified BM25 score treating the whole corpus as a single doc for IDF
    (IDF defaults to 1.0 since we lack corpus-wide stats in the fallback).
    """
    if not query_tokens or not doc_tokens:
        return 0.0
    dl = len(doc_tokens)
    freq: Dict[str, int] = {}
    for tok in doc_tokens:
        freq[tok] = freq.get(tok, 0) + 1
    score = 0.0
    for qt in query_tokens:
        tf = freq.get(qt, 0)
        if tf == 0:
            continue
        numerator = tf * (k1 + 1)
        denominator = tf + k1 * (1 - b + b * dl / max(avg_dl, 1))
        score += numerator / denominator  # IDF = 1.0 per term
    # Normalize to 0-1 by capping at query length * (k1+1)
    max_possible = len(query_tokens) * (k1 + 1)
    return min(score / max(max_possible, 1.0), 1.0)


class _SQLiteFallback:
    """
    SQLite-backed memory store with BM25-style scoring.
    Used when ChromaDB is unavailable.
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            # Create a temp file that persists for the lifetime of the object
            self._tmpfile = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
            self._db_path = self._tmpfile.name
        else:
            self._tmpfile = None
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
            self._db_path = db_path
        self._init_schema()

    def _init_schema(self) -> None:
        with self._conn() as conn:
            conn.executescript(_FALLBACK_SCHEMA)
            conn.commit()

    @contextmanager
    def _conn(self) -> Generator[sqlite3.Connection, None, None]:
        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        try:
            yield conn
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def add(
        self,
        layer: str,
        entry_id: str,
        content: str,
        metadata: Dict[str, Any],
        memory_type: str,
    ) -> None:
        timestamp = metadata.get("timestamp", _now_iso())
        sql = """
            INSERT OR REPLACE INTO memory_entries
                (id, content, metadata_json, memory_layer, memory_type, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
        """
        with self._conn() as conn:
            conn.execute(sql, (
                entry_id,
                content,
                json.dumps(metadata),
                layer,
                memory_type,
                timestamp,
            ))
            conn.commit()

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def query(
        self,
        layer: str,
        query_text: str,
        top_k: int = 5,
    ) -> List[MemorySearchResult]:
        sql = "SELECT * FROM memory_entries WHERE memory_layer = ?"
        with self._conn() as conn:
            rows = conn.execute(sql, (layer,)).fetchall()

        if not rows:
            return []

        query_tokens = _tokenize(query_text)
        scored: List[tuple[float, MemorySearchResult]] = []

        # Compute average doc length for BM25
        all_docs = [_tokenize(row["content"]) for row in rows]
        avg_dl = sum(len(d) for d in all_docs) / max(len(all_docs), 1)

        for row, doc_tokens in zip(rows, all_docs):
            score = _bm25_score(query_tokens, doc_tokens, avg_dl=avg_dl)
            metadata = json.loads(row["metadata_json"])
            entry = MemoryEntry(
                entry_id=row["id"],
                content=row["content"],
                metadata=metadata,
                timestamp=row["timestamp"],
                memory_type=row["memory_type"],
            )
            scored.append((score, MemorySearchResult(
                entry=entry,
                score=score,
                distance=1.0 - score,
            )))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [r for _, r in scored[:top_k]]

    def query_all(self, layer: str) -> List[MemoryEntry]:
        """Return all entries for a layer (used for get_scan_summaries)."""
        sql = "SELECT * FROM memory_entries WHERE memory_layer = ? ORDER BY timestamp DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, (layer,)).fetchall()
        entries = []
        for row in rows:
            metadata = json.loads(row["metadata_json"])
            entries.append(MemoryEntry(
                entry_id=row["id"],
                content=row["content"],
                metadata=metadata,
                timestamp=row["timestamp"],
                memory_type=row["memory_type"],
            ))
        return entries

    def delete_layer(self, layer: str) -> None:
        with self._conn() as conn:
            conn.execute("DELETE FROM memory_entries WHERE memory_layer = ?", (layer,))
            conn.commit()

    def count(self, layer: str) -> int:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT COUNT(*) as cnt FROM memory_entries WHERE memory_layer = ?", (layer,)
            ).fetchone()
        return row["cnt"] if row else 0


# ---------------------------------------------------------------------------
# ChromaDB thin wrapper
# ---------------------------------------------------------------------------

class _ChromaCollection:
    """
    Wraps a single ChromaDB collection. All operations catch exceptions and
    re-raise as RuntimeError so the caller can decide to fall back.
    """

    def __init__(self, collection: Any) -> None:
        self._col = collection

    def add(self, entry_id: str, content: str, metadata: Dict[str, Any]) -> None:
        try:
            self._col.add(
                documents=[content],
                metadatas=[metadata],
                ids=[entry_id],
            )
        except Exception as exc:
            raise RuntimeError(f"ChromaDB add failed: {exc}") from exc

    def query(self, query_text: str, top_k: int) -> List[MemorySearchResult]:
        try:
            results = self._col.query(
                query_texts=[query_text],
                n_results=min(top_k, max(self._col.count(), 1)),
            )
        except Exception as exc:
            raise RuntimeError(f"ChromaDB query failed: {exc}") from exc

        items: List[MemorySearchResult] = []
        docs = results.get("documents", [[]])[0]
        metas = results.get("metadatas", [[]])[0]
        ids_ = results.get("ids", [[]])[0]
        distances = results.get("distances", [[]])[0]

        for doc, meta, id_, dist in zip(docs, metas, ids_, distances):
            # ChromaDB returns L2 distance; convert to 0-1 score
            score = max(0.0, 1.0 - dist / 2.0)
            entry = MemoryEntry(
                entry_id=id_,
                content=doc,
                metadata=dict(meta),
                timestamp=meta.get("timestamp", ""),
                memory_type=meta.get("memory_type", "knowledge"),
            )
            items.append(MemorySearchResult(entry=entry, score=score, distance=dist))
        return items

    def query_all(self, top_k: int = 1000) -> List[MemoryEntry]:
        try:
            count = self._col.count()
            if count == 0:
                return []
            results = self._col.get()
        except Exception as exc:
            raise RuntimeError(f"ChromaDB get failed: {exc}") from exc

        entries = []
        docs = results.get("documents", [])
        metas = results.get("metadatas", [])
        ids_ = results.get("ids", [])
        for doc, meta, id_ in zip(docs, metas, ids_):
            entries.append(MemoryEntry(
                entry_id=id_,
                content=doc,
                metadata=dict(meta),
                timestamp=meta.get("timestamp", ""),
                memory_type=meta.get("memory_type", "knowledge"),
            ))
        return entries

    def count(self) -> int:
        try:
            return self._col.count()
        except Exception:
            return 0


# ---------------------------------------------------------------------------
# MemoryManager — public API
# ---------------------------------------------------------------------------

class MemoryManager:
    """
    Multi-level memory manager with ChromaDB primary backend and SQLite fallback.

    persist_dir=None   → in-memory (ephemeral; good for tests)
    persist_dir="path" → persistent ChromaDB PersistentClient
    """

    _LONG_TERM_LAYER = "long_term"
    _SEMANTIC_LAYER = "semantic"
    _EPISODIC_LAYER = "episodic"

    def __init__(
        self,
        persist_dir: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> None:
        self._session_id = session_id or str(uuid4())
        self._persist_dir = persist_dir
        self._use_chroma = False

        # Short-term collection name is unique per session
        self._short_term_layer = f"short_term_{self._session_id}"

        # Try to initialise ChromaDB
        self._chroma_client: Any = None
        self._chroma_cols: Dict[str, _ChromaCollection] = {}

        if _CHROMADB_AVAILABLE:
            try:
                if persist_dir is None:
                    self._chroma_client = _chromadb.Client()
                else:
                    self._chroma_client = _chromadb.PersistentClient(path=persist_dir)
                self._use_chroma = True
                logger.debug("MemoryManager: ChromaDB backend active (persist=%s)", persist_dir)
            except Exception as exc:
                logger.warning("ChromaDB init failed, using SQLite fallback: %s", exc)
                self._use_chroma = False

        # SQLite fallback — always initialised (used when chroma fails or is absent)
        fallback_db: Optional[str] = None
        if persist_dir is not None:
            Path(persist_dir).mkdir(parents=True, exist_ok=True)
            fallback_db = str(Path(persist_dir) / "memory_fallback.db")
        self._fallback = _SQLiteFallback(db_path=fallback_db)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_chroma_col(self, layer: str) -> _ChromaCollection:
        """Return (cached) ChromaDB collection for a layer, creating if needed."""
        if layer not in self._chroma_cols:
            try:
                raw_col = self._chroma_client.get_or_create_collection(layer)
                self._chroma_cols[layer] = _ChromaCollection(raw_col)
            except Exception as exc:
                raise RuntimeError(f"ChromaDB collection creation failed for '{layer}': {exc}") from exc
        return self._chroma_cols[layer]

    def _store(
        self,
        layer: str,
        content: str,
        metadata: Dict[str, Any],
        memory_type: str,
        entry_id: Optional[str] = None,
    ) -> str:
        """Store a document in the given layer. Returns the entry_id."""
        eid = entry_id or str(uuid4())
        metadata = {**metadata, "memory_type": memory_type, "timestamp": _now_iso()}

        stored_via_chroma = False
        if self._use_chroma:
            try:
                col = self._get_chroma_col(layer)
                col.add(eid, content, metadata)
                stored_via_chroma = True
            except Exception as exc:
                logger.warning("ChromaDB store error (layer=%s), falling back: %s", layer, exc)

        if not stored_via_chroma:
            self._fallback.add(layer, eid, content, metadata, memory_type)

        return eid

    def _search(self, layer: str, query: str, top_k: int) -> List[MemorySearchResult]:
        """Search a layer. Falls back to SQLite on ChromaDB error."""
        if self._use_chroma:
            try:
                col = self._get_chroma_col(layer)
                return col.query(query, top_k)
            except Exception as exc:
                logger.warning("ChromaDB query error (layer=%s), falling back: %s", layer, exc)

        return self._fallback.query(layer, query, top_k)

    # ------------------------------------------------------------------
    # Short-term memory
    # ------------------------------------------------------------------

    def store_short_term(
        self,
        key: str,
        content: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Store an ephemeral entry for the current scan session."""
        meta = {**(metadata or {}), "key": key, "session_id": self._session_id}
        return self._store(
            self._short_term_layer,
            content,
            meta,
            memory_type="episode",
        )

    def get_short_term(self, query: str, top_k: int = 5) -> List[MemorySearchResult]:
        """Retrieve from current session's short-term memory."""
        return self._search(self._short_term_layer, query, top_k)

    def clear_short_term(self) -> None:
        """Delete all short-term entries for the current session."""
        if self._use_chroma:
            try:
                self._chroma_client.delete_collection(self._short_term_layer)
                self._chroma_cols.pop(self._short_term_layer, None)
            except Exception as exc:
                logger.warning("ChromaDB clear_short_term error: %s", exc)
                self._fallback.delete_layer(self._short_term_layer)
        else:
            self._fallback.delete_layer(self._short_term_layer)

    # ------------------------------------------------------------------
    # Long-term memory
    # ------------------------------------------------------------------

    def store_finding(
        self,
        finding: Any,  # backend.core.confidence.Finding
        verdict: str,
        session_id: str,
    ) -> str:
        """Persist a Finding with its verification verdict into long-term memory."""
        content = (
            f"Rule: {finding.rule_id} | File: {finding.file} | Line: {finding.line} | "
            f"Severity: {finding.severity} | CWE: {finding.cwe_id} | "
            f"Description: {finding.description} | Verdict: {verdict}"
        )
        meta = {
            "rule_id": finding.rule_id,
            "file": finding.file,
            "line": finding.line,
            "severity": finding.severity,
            "cwe_id": finding.cwe_id,
            "confidence": finding.confidence,
            "verdict": verdict,
            "session_id": session_id,
            "fingerprint": finding.fingerprint(),
        }
        return self._store(self._LONG_TERM_LAYER, content, meta, memory_type="finding")

    def retrieve_similar_findings(
        self,
        finding: Any,
        top_k: int = 5,
    ) -> List[MemorySearchResult]:
        """Find past findings similar to the provided one."""
        query = (
            f"{finding.rule_id} {finding.severity} {finding.cwe_id} {finding.description}"
        )
        return self._search(self._LONG_TERM_LAYER, query, top_k)

    def store_successful_fix(
        self,
        rule_id: str,
        fix_description: str,
        before_code: str,
        after_code: str,
    ) -> str:
        """Record a successfully applied fix for future reference."""
        content = (
            f"Rule: {rule_id} | Fix: {fix_description} | "
            f"Before: {before_code[:200]} | After: {after_code[:200]}"
        )
        meta = {
            "rule_id": rule_id,
            "fix_description": fix_description,
            "before_snippet": before_code[:500],
            "after_snippet": after_code[:500],
        }
        return self._store(self._LONG_TERM_LAYER, content, meta, memory_type="pattern")

    def retrieve_similar_fixes(
        self,
        rule_id: str,
        code_snippet: str,
        top_k: int = 3,
    ) -> List[MemorySearchResult]:
        """Retrieve previously recorded fixes similar to the given context."""
        query = f"{rule_id} fix {code_snippet[:300]}"
        return self._search(self._LONG_TERM_LAYER, query, top_k)

    def store_confirmed_pattern(
        self,
        pattern: str,
        rule_id: str,
        examples: List[str],
    ) -> str:
        """Store a confirmed vulnerability pattern with examples."""
        examples_text = " | ".join(examples[:5])
        content = f"Pattern: {pattern} | Rule: {rule_id} | Examples: {examples_text}"
        meta = {
            "pattern": pattern,
            "rule_id": rule_id,
            "examples": examples[:5],
        }
        return self._store(self._LONG_TERM_LAYER, content, meta, memory_type="pattern")

    # ------------------------------------------------------------------
    # Semantic memory
    # ------------------------------------------------------------------

    def store_knowledge(
        self,
        cwe_id: str,
        description: str,
        attack_examples: Optional[List[str]] = None,
    ) -> str:
        """Store CWE / CVE knowledge into semantic memory."""
        examples_text = " | ".join((attack_examples or [])[:5])
        content = f"CWE: {cwe_id} | {description} | Examples: {examples_text}"
        meta = {
            "cwe_id": cwe_id,
            "description": description[:1000],
            "attack_examples": (attack_examples or [])[:5],
        }
        return self._store(self._SEMANTIC_LAYER, content, meta, memory_type="knowledge")

    def retrieve_knowledge(
        self,
        query: str,
        top_k: int = 5,
    ) -> List[MemorySearchResult]:
        """Retrieve CWE / security knowledge relevant to the query."""
        return self._search(self._SEMANTIC_LAYER, query, top_k)

    def store_attack_pattern(
        self,
        name: str,
        description: str,
        mitre_id: str,
        severity: str,
    ) -> str:
        """Store a MITRE ATT&CK-style attack pattern."""
        content = (
            f"Attack Pattern: {name} | MITRE: {mitre_id} | Severity: {severity} | "
            f"Description: {description}"
        )
        meta = {
            "name": name,
            "mitre_id": mitre_id,
            "severity": severity,
            "description": description[:1000],
        }
        return self._store(self._SEMANTIC_LAYER, content, meta, memory_type="pattern")

    def retrieve_attack_patterns(
        self,
        context: str,
        top_k: int = 5,
    ) -> List[MemorySearchResult]:
        """Retrieve attack patterns relevant to the given context."""
        return self._search(self._SEMANTIC_LAYER, context, top_k)

    # ------------------------------------------------------------------
    # Episodic memory
    # ------------------------------------------------------------------

    def store_episode(
        self,
        scan_id: str,
        action: str,
        reasoning: str,
        outcome: str,
    ) -> str:
        """Record an agent decision episode."""
        content = (
            f"Scan: {scan_id} | Action: {action} | Reasoning: {reasoning} | "
            f"Outcome: {outcome}"
        )
        meta = {
            "scan_id": scan_id,
            "action": action,
            "reasoning": reasoning[:500],
            "outcome": outcome,
        }
        return self._store(self._EPISODIC_LAYER, content, meta, memory_type="episode")

    def get_episodes(
        self,
        query: str,
        top_k: int = 10,
    ) -> List[MemorySearchResult]:
        """Retrieve episodic records relevant to a query."""
        return self._search(self._EPISODIC_LAYER, query, top_k)

    def store_scan_summary(
        self,
        scan_id: str,
        summary: Dict[str, Any],
    ) -> str:
        """Persist a scan summary as an episodic entry."""
        content = (
            f"Scan summary: {scan_id} | "
            + " | ".join(f"{k}: {v}" for k, v in summary.items())
        )
        meta = {
            "scan_id": scan_id,
            "entry_kind": "scan_summary",
            **{k: str(v) for k, v in summary.items()},
        }
        return self._store(self._EPISODIC_LAYER, content, meta, memory_type="episode")

    def get_scan_summaries(
        self,
        top_k: int = 10,
    ) -> List[MemorySearchResult]:
        """
        Return the most recent scan summaries.
        Sorted by timestamp descending (newest first), capped at top_k.
        """
        if self._use_chroma:
            try:
                col = self._get_chroma_col(self._EPISODIC_LAYER)
                all_entries = col.query_all()
            except Exception as exc:
                logger.warning("ChromaDB get_scan_summaries error: %s", exc)
                all_entries = self._fallback.query_all(self._EPISODIC_LAYER)
        else:
            all_entries = self._fallback.query_all(self._EPISODIC_LAYER)

        summaries = [
            e for e in all_entries
            if e.metadata.get("entry_kind") == "scan_summary"
        ]
        summaries.sort(key=lambda e: e.timestamp, reverse=True)

        return [
            MemorySearchResult(entry=e, score=1.0, distance=0.0)
            for e in summaries[:top_k]
        ]

    # ------------------------------------------------------------------
    # Cross-layer retrieval
    # ------------------------------------------------------------------

    def retrieve_before_decision(
        self,
        context: str,
        top_k_per_layer: int = 3,
    ) -> Dict[str, List[MemorySearchResult]]:
        """
        Query all persistent layers before an agent makes a decision.
        Returns a dict with keys: "long_term", "semantic", "episodic".
        """
        return {
            "long_term": self._search(self._LONG_TERM_LAYER, context, top_k_per_layer),
            "semantic": self._search(self._SEMANTIC_LAYER, context, top_k_per_layer),
            "episodic": self._search(self._EPISODIC_LAYER, context, top_k_per_layer),
        }

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def get_stats(self) -> Dict[str, int]:
        """Return entry counts per collection."""
        layers = [
            self._short_term_layer,
            self._LONG_TERM_LAYER,
            self._SEMANTIC_LAYER,
            self._EPISODIC_LAYER,
        ]
        stats: Dict[str, int] = {}
        for layer in layers:
            if self._use_chroma:
                try:
                    col = self._get_chroma_col(layer)
                    stats[layer] = col.count()
                    continue
                except Exception as exc:
                    logger.warning("ChromaDB count error (layer=%s): %s", layer, exc)
            stats[layer] = self._fallback.count(layer)
        return stats
