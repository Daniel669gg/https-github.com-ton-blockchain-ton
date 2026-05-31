"""
TythanAI Platform — Local Embeddings
Feature 8: Replace OpenAI embeddings with local sentence-transformers.
Falls back gracefully to TF-IDF if sentence-transformers not installed.

No API keys required. Works fully offline.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import sqlite3
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Try sentence-transformers (best quality, ~80MB model download on first use)
try:
    from sentence_transformers import SentenceTransformer  # type: ignore
    _ST_AVAILABLE = True
except ImportError:
    _ST_AVAILABLE = False

# numpy is optional but speeds things up
try:
    import numpy as np  # type: ignore
    _NP_AVAILABLE = True
except ImportError:
    _NP_AVAILABLE = False

DB_PATH = Path(__file__).parent.parent / "data" / "embeddings.db"

_SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS embeddings (
    id         TEXT PRIMARY KEY,
    text       TEXT NOT NULL,
    model      TEXT NOT NULL,
    vector     BLOB NOT NULL,
    meta       TEXT DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_emb_model ON embeddings(model);
"""

# ── TF-IDF fallback ───────────────────────────────────────────────────────────

def _tokenize(text: str) -> List[str]:
    return re.findall(r"\b\w+\b", text.lower())


def _tfidf_vector(text: str, vocab: Dict[str, int],
                  idf: Optional[Dict[str, float]] = None) -> List[float]:
    tokens = _tokenize(text)
    tf: Dict[str, float] = {}
    for t in tokens:
        tf[t] = tf.get(t, 0) + 1
    n = len(tokens) or 1
    vec = [0.0] * len(vocab)
    for term, count in tf.items():
        if term in vocab:
            tfidf = (count / n) * (idf.get(term, 1.0) if idf else 1.0)
            vec[vocab[term]] = tfidf
    return vec


def _cosine(a: List[float], b: List[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(x * x for x in b))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


# ── Main class ────────────────────────────────────────────────────────────────

class LocalEmbeddings:
    """
    Embedding engine for TythanAI memory system.

    Priority:
      1. sentence-transformers (all-MiniLM-L6-v2, 384-dim) — best quality
      2. TF-IDF (in-process, no model download) — always available fallback

    The SQLite store caches computed embeddings so repeated queries are free.
    """

    DEFAULT_MODEL = "all-MiniLM-L6-v2"

    def __init__(self, db_path: Optional[Path] = None,
                 model_name: str = DEFAULT_MODEL,
                 use_local: bool = True):
        self._db_path = db_path or DB_PATH
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._model_name = model_name
        self._model = None
        self._use_local = use_local and _ST_AVAILABLE
        self._vocab: Dict[str, int] = {}
        self._corpus: List[Tuple[str, List[float]]] = []  # TF-IDF corpus
        self._init_db()
        if self._use_local:
            self._load_model()

    def _init_db(self):
        conn = sqlite3.connect(str(self._db_path))
        conn.executescript(_SCHEMA)
        conn.commit()
        conn.close()

    def _load_model(self):
        """Load sentence-transformer model (downloads ~80MB on first run)."""
        if not _ST_AVAILABLE:
            return
        try:
            self._model = SentenceTransformer(self._model_name)
        except Exception as e:
            print(f"[LocalEmbeddings] Could not load model: {e}. Using TF-IDF fallback.")
            self._use_local = False

    @property
    def backend(self) -> str:
        return "sentence-transformers" if self._use_local else "tfidf"

    def _embed_st(self, text: str) -> List[float]:
        """Embed via sentence-transformers."""
        vec = self._model.encode([text], convert_to_numpy=True)[0]
        return vec.tolist()

    def _embed_tfidf(self, text: str) -> List[float]:
        """Embed via TF-IDF (build vocab from stored corpus)."""
        tokens = set(_tokenize(text))
        for t in tokens:
            if t not in self._vocab:
                self._vocab[t] = len(self._vocab)
        return _tfidf_vector(text, self._vocab)

    def embed(self, text: str, meta: Optional[Dict] = None) -> str:
        """
        Compute embedding for text, cache in SQLite.
        Returns the embedding ID.
        """
        eid = hashlib.sha256(f"{self._model_name}::{text}".encode()).hexdigest()[:32]
        conn = sqlite3.connect(str(self._db_path))
        row = conn.execute("SELECT id FROM embeddings WHERE id=?", (eid,)).fetchone()
        if row:
            conn.close()
            return eid

        if self._use_local:
            vec = self._embed_st(text)
            model_tag = self._model_name
        else:
            vec = self._embed_tfidf(text)
            model_tag = "tfidf"

        import struct
        blob = struct.pack(f"{len(vec)}f", *vec)
        conn.execute(
            "INSERT INTO embeddings (id, text, model, vector, meta) VALUES (?,?,?,?,?)",
            (eid, text[:2000], model_tag, blob, json.dumps(meta or {}))
        )
        conn.commit()
        conn.close()
        return eid

    def _load_vector(self, eid: str) -> Optional[List[float]]:
        import struct
        conn = sqlite3.connect(str(self._db_path))
        row = conn.execute(
            "SELECT vector, model FROM embeddings WHERE id=?", (eid,)
        ).fetchone()
        conn.close()
        if not row:
            return None
        blob, model = row
        n = len(blob) // 4
        return list(struct.unpack(f"{n}f", blob))

    def similarity(self, text_a: str, text_b: str) -> float:
        """Cosine similarity between two texts."""
        id_a = self.embed(text_a)
        id_b = self.embed(text_b)
        va = self._load_vector(id_a)
        vb = self._load_vector(id_b)
        if va is None or vb is None:
            return 0.0
        # Pad shorter vector with zeros
        if len(va) != len(vb):
            m = max(len(va), len(vb))
            va = va + [0.0] * (m - len(va))
            vb = vb + [0.0] * (m - len(vb))
        return _cosine(va, vb)

    def search_similar(self, query: str, texts: List[str],
                       top_k: int = 5) -> List[Tuple[str, float]]:
        """
        Find most similar texts to query from a list.
        Returns [(text, score), ...] sorted by score desc.
        """
        qid = self.embed(query)
        qvec = self._load_vector(qid)
        if qvec is None:
            return []

        results = []
        for text in texts:
            tid = self.embed(text)
            tvec = self._load_vector(tid)
            if tvec is None:
                continue
            # Pad
            if len(qvec) != len(tvec):
                m = max(len(qvec), len(tvec))
                q2 = qvec + [0.0] * (m - len(qvec))
                t2 = tvec + [0.0] * (m - len(tvec))
            else:
                q2, t2 = qvec, tvec
            results.append((text, _cosine(q2, t2)))

        results.sort(key=lambda x: x[1], reverse=True)
        return results[:top_k]

    def embed_findings(self, findings: List[Dict]) -> List[str]:
        """Embed a list of findings, return list of embedding IDs."""
        ids = []
        for f in findings:
            text = (
                f"{f.get('type','')} {f.get('description','')} "
                f"{f.get('cwe','')} {f.get('evidence','')}"
            )
            meta = {
                "severity": f.get("severity", ""),
                "cwe": f.get("cwe", ""),
                "source": f.get("source", ""),
            }
            ids.append(self.embed(text.strip(), meta=meta))
        return ids

    def find_similar_findings(self, finding: Dict,
                              candidate_findings: List[Dict],
                              top_k: int = 5,
                              min_score: float = 0.6) -> List[Dict]:
        """Find findings similar to the given one (for dedup/clustering)."""
        query_text = (
            f"{finding.get('type','')} {finding.get('description','')} "
            f"{finding.get('cwe','')} {finding.get('evidence','')}"
        )
        texts = [
            f"{f.get('type','')} {f.get('description','')} "
            f"{f.get('cwe','')} {f.get('evidence','')}"
            for f in candidate_findings
        ]
        similar = self.search_similar(query_text, texts, top_k=top_k)
        result = []
        for text, score in similar:
            if score < min_score:
                continue
            idx = texts.index(text) if text in texts else -1
            if idx >= 0:
                r = dict(candidate_findings[idx])
                r["similarity_score"] = round(score, 3)
                result.append(r)
        return result

    def status(self) -> Dict:
        conn = sqlite3.connect(str(self._db_path))
        count = conn.execute("SELECT COUNT(*) FROM embeddings").fetchone()[0]
        conn.close()
        return {
            "backend": self.backend,
            "model": self._model_name if self._use_local else "tfidf",
            "cached_embeddings": count,
            "sentence_transformers_available": _ST_AVAILABLE,
        }


# Singleton
_ENGINE: Optional[LocalEmbeddings] = None

def get_embeddings() -> LocalEmbeddings:
    global _ENGINE
    if _ENGINE is None:
        _ENGINE = LocalEmbeddings()
    return _ENGINE
