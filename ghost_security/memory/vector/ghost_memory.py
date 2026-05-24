"""
Ghost Security Platform — Vector Memory (Qdrant)
Семантическая память для:
  • Поиск похожих находок из прошлых сканов
  • Индексирование истории выполнения
  • Retrieval-augmented analysis (RAG)
  • Self-improving: чем больше сканов, тем умнее recall

Если Qdrant недоступен — fallback на ChromaDB или in-memory.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


# ══════════════════════════════════════════════════════════════════════════════
# EMBEDDINGS
# ══════════════════════════════════════════════════════════════════════════════

class EmbeddingProvider:
    """
    Генерирует векторные эмбеддинги текста.
    Порядок: OpenAI → Ollama (nomic-embed-text) → TF-IDF fallback.
    """

    _DIM_OPENAI = 1536
    _DIM_MINI   = 64    # TF-IDF fallback

    def __init__(self) -> None:
        self._openai_key = os.getenv("OPENAI_API_KEY", "")
        self._ollama_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
        self._vocab: Dict[str, int] = {}  # TF-IDF vocab

    def embed(self, text: str) -> List[float]:
        """Embed text, trying providers in order."""
        if self._openai_key:
            vec = self._openai_embed(text)
            if vec:
                return vec
        vec = self._ollama_embed(text)
        if vec:
            return vec
        return self._tfidf_embed(text)

    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        return [self.embed(t) for t in texts]

    def dim(self) -> int:
        if self._openai_key:
            return self._DIM_OPENAI
        return self._DIM_MINI

    # ── Backends ──────────────────────────────────────────────────────────────

    def _openai_embed(self, text: str) -> List[float]:
        import urllib.request
        body = json.dumps({
            "input": text[:8000],
            "model": "text-embedding-3-small",
        }).encode()
        req = urllib.request.Request(
            "https://api.openai.com/v1/embeddings",
            data=body,
            headers={
                "Authorization": f"Bearer {self._openai_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                data = json.loads(r.read())
            return data["data"][0]["embedding"]
        except Exception:
            return []

    def _ollama_embed(self, text: str) -> List[float]:
        import urllib.request
        body = json.dumps({"model": "nomic-embed-text", "prompt": text[:4000]}).encode()
        req  = urllib.request.Request(
            f"{self._ollama_url}/api/embeddings",
            data=body, headers={"Content-Type": "application/json"}, method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                data = json.loads(r.read())
            return data.get("embedding", [])
        except Exception:
            return []

    def _tfidf_embed(self, text: str) -> List[float]:
        """Simple TF-IDF based sparse vector (dim=64)."""
        import math
        tokens = text.lower().split()
        freq: Dict[str, int] = {}
        for t in tokens:
            freq[t] = freq.get(t, 0) + 1
        # Update vocab
        for t in freq:
            if t not in self._vocab and len(self._vocab) < self._DIM_MINI:
                self._vocab[t] = len(self._vocab)
        vec = [0.0] * self._DIM_MINI
        for token, count in freq.items():
            idx = self._vocab.get(token)
            if idx is not None:
                tf  = count / max(len(tokens), 1)
                idf = math.log(1 + 1 / (1 + count))
                vec[idx] = tf * idf
        # L2 normalise
        norm = sum(x ** 2 for x in vec) ** 0.5
        if norm > 0:
            vec = [x / norm for x in vec]
        return vec


# ══════════════════════════════════════════════════════════════════════════════
# QDRANT CLIENT WRAPPER
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class MemoryEntry:
    id:         str
    text:       str
    metadata:   dict
    score:      float = 0.0

    def to_dict(self) -> dict:
        return {"id": self.id, "text": self.text, "metadata": self.metadata, "score": self.score}


class QdrantMemory:
    """
    Qdrant vector store для семантической памяти Ghost.
    Collections:
      ghost_findings     — найденные уязвимости
      ghost_remediations — успешные фиксы
      ghost_scans        — история сканирований
    """

    _COLLECTIONS = ["ghost_findings", "ghost_remediations", "ghost_scans"]

    def __init__(
        self,
        url:    str = "",
        api_key: str = "",
    ) -> None:
        self._url     = url or os.getenv("QDRANT_URL", "http://localhost:6333")
        self._api_key = api_key or os.getenv("QDRANT_API_KEY", "")
        self._embedder = EmbeddingProvider()
        self._client   = None
        self._available = False
        self._init()

    def _init(self) -> None:
        try:
            from qdrant_client import QdrantClient
            from qdrant_client.models import Distance, VectorParams
            kwargs: dict = {"url": self._url, "timeout": 5}
            if self._api_key:
                kwargs["api_key"] = self._api_key
            self._client = QdrantClient(**kwargs)
            # Health check
            self._client.get_collections()
            # Ensure collections exist
            dim = self._embedder.dim()
            for col in self._COLLECTIONS:
                existing = [c.name for c in self._client.get_collections().collections]
                if col not in existing:
                    self._client.create_collection(
                        collection_name=col,
                        vectors_config=VectorParams(size=dim, distance=Distance.COSINE),
                    )
            self._available = True
        except Exception:
            self._available = False

    def is_available(self) -> bool:
        return self._available

    # ── Store ─────────────────────────────────────────────────────────────────

    def store_finding(self, finding: dict, scan_id: str = "") -> bool:
        """Сохраняет finding в векторную БД для будущего поиска."""
        text = self._finding_text(finding)
        return self._upsert("ghost_findings", text, {
            "scan_id":   scan_id,
            "severity":  finding.get("severity", "MEDIUM"),
            "type":      finding.get("type", ""),
            "cwe":       finding.get("cwe", ""),
            "file":      finding.get("file", ""),
            "line":      finding.get("line", 0),
            "rule_id":   finding.get("rule_id", ""),
            "timestamp": time.time(),
        })

    def store_remediation(self, finding: dict, fix: str, was_applied: bool = False) -> bool:
        """Сохраняет успешный фикс для обучения."""
        text = f"FINDING: {self._finding_text(finding)}\nFIX: {fix}"
        return self._upsert("ghost_remediations", text, {
            "finding_type": finding.get("type", ""),
            "cwe":          finding.get("cwe", ""),
            "fix_preview":  fix[:200],
            "was_applied":  was_applied,
            "timestamp":    time.time(),
        })

    def store_scan(self, scan_id: str, target: str, summary: dict) -> bool:
        """Сохраняет резюме скана."""
        text = f"Scan of {target}: {json.dumps(summary)}"
        return self._upsert("ghost_scans", text, {
            "scan_id":   scan_id,
            "target":    target,
            "risk_score": summary.get("risk_score", 0),
            "findings":  summary.get("total_findings", 0),
            "timestamp": time.time(),
        })

    # ── Search ────────────────────────────────────────────────────────────────

    def similar_findings(
        self, finding: dict, limit: int = 5, min_score: float = 0.7
    ) -> List[MemoryEntry]:
        """Найти похожие уязвимости из истории."""
        text = self._finding_text(finding)
        return self._search("ghost_findings", text, limit, min_score)

    def get_remediations(
        self, finding: dict, limit: int = 3
    ) -> List[MemoryEntry]:
        """Найти успешные фиксы для похожих уязвимостей."""
        text = self._finding_text(finding)
        return self._search("ghost_remediations", text, limit, 0.6)

    def scan_history(self, target: str, limit: int = 10) -> List[MemoryEntry]:
        """Семантический поиск по истории сканов."""
        return self._search("ghost_scans", f"Scan of {target}", limit, 0.5)

    # ── Fallback: in-memory ───────────────────────────────────────────────────

    def store_finding_memory(self, finding: dict, scan_id: str = "") -> None:
        """In-memory fallback когда Qdrant недоступен."""
        self._memory_store.append({
            "text":     self._finding_text(finding),
            "metadata": {"scan_id": scan_id, **finding},
            "vec":      self._embedder.embed(self._finding_text(finding)),
        })

    def similar_findings_memory(self, finding: dict, limit: int = 5) -> List[MemoryEntry]:
        """Поиск в in-memory хранилище."""
        if not hasattr(self, "_memory_store"):
            self._memory_store: List[dict] = []
        query_vec = self._embedder.embed(self._finding_text(finding))
        scores = []
        for entry in self._memory_store:
            score = self._cosine(query_vec, entry["vec"])
            scores.append((score, entry))
        scores.sort(key=lambda x: -x[0])
        return [
            MemoryEntry(
                id       = hashlib.sha1(e["text"].encode()).hexdigest()[:12],
                text     = e["text"],
                metadata = e["metadata"],
                score    = s,
            )
            for s, e in scores[:limit]
        ]

    # ── Internal ──────────────────────────────────────────────────────────────

    def _upsert(self, collection: str, text: str, metadata: dict) -> bool:
        if not self._available:
            return False
        try:
            from qdrant_client.models import PointStruct
            point_id = int(hashlib.sha1(text.encode()).hexdigest()[:8], 16)
            vec      = self._embedder.embed(text)
            self._client.upsert(
                collection_name=collection,
                points=[PointStruct(id=point_id, vector=vec, payload=metadata)],
            )
            return True
        except Exception:
            return False

    def _search(
        self, collection: str, text: str, limit: int, min_score: float
    ) -> List[MemoryEntry]:
        if not self._available:
            return []
        try:
            vec     = self._embedder.embed(text)
            results = self._client.search(
                collection_name=collection,
                query_vector=vec,
                limit=limit,
                score_threshold=min_score,
            )
            return [
                MemoryEntry(
                    id       = str(r.id),
                    text     = r.payload.get("text", ""),
                    metadata = r.payload,
                    score    = r.score,
                )
                for r in results
            ]
        except Exception:
            return []

    @staticmethod
    def _finding_text(f: dict) -> str:
        return (
            f"{f.get('type','')} {f.get('message','') or f.get('description','')} "
            f"CWE:{f.get('cwe','')} OWASP:{f.get('owasp','')} "
            f"severity:{f.get('severity','')} file:{f.get('file','')}"
        ).strip()

    @staticmethod
    def _cosine(a: List[float], b: List[float]) -> float:
        if not a or not b or len(a) != len(b):
            return 0.0
        dot  = sum(x * y for x, y in zip(a, b))
        na   = sum(x ** 2 for x in a) ** 0.5
        nb   = sum(x ** 2 for x in b) ** 0.5
        return dot / (na * nb) if na * nb > 0 else 0.0

    def status(self) -> dict:
        if not self._available:
            return {"available": False, "url": self._url, "fallback": "in-memory"}
        try:
            cols = {}
            for col in self._COLLECTIONS:
                info = self._client.get_collection(col)
                cols[col] = info.points_count
            return {"available": True, "url": self._url, "collections": cols}
        except Exception as e:
            return {"available": False, "error": str(e)}


# ── ChromaDB fallback (уже есть в requirements) ───────────────────────────────

class ChromaMemory:
    """
    ChromaDB-based vector memory (уже в requirements.txt).
    Автоматически используется если Qdrant недоступен.
    """

    def __init__(self, persist_dir: str = "./data/chroma") -> None:
        self._dir      = persist_dir
        self._client   = None
        self._embedder = EmbeddingProvider()
        self._init()

    def _init(self) -> None:
        try:
            import chromadb
            self._client = chromadb.PersistentClient(path=self._dir)
            self._findings    = self._client.get_or_create_collection("ghost_findings")
            self._remediations = self._client.get_or_create_collection("ghost_remediations")
            self._available   = True
        except Exception:
            self._available = False

    def is_available(self) -> bool:
        return self._available

    def store_finding(self, finding: dict, scan_id: str = "") -> bool:
        if not self._available:
            return False
        try:
            text = QdrantMemory._finding_text(finding)
            fid  = hashlib.sha1(f"{scan_id}{text}".encode()).hexdigest()[:16]
            vec  = self._embedder.embed(text)
            self._findings.upsert(
                ids=[fid], embeddings=[vec], documents=[text],
                metadatas=[{"scan_id": scan_id, "severity": finding.get("severity",""), "cwe": finding.get("cwe","")}],
            )
            return True
        except Exception:
            return False

    def similar_findings(self, finding: dict, limit: int = 5) -> List[MemoryEntry]:
        if not self._available:
            return []
        try:
            text = QdrantMemory._finding_text(finding)
            vec  = self._embedder.embed(text)
            results = self._findings.query(query_embeddings=[vec], n_results=limit)
            entries = []
            for i, doc in enumerate(results["documents"][0]):
                score = 1 - results["distances"][0][i]  # convert distance to score
                entries.append(MemoryEntry(
                    id       = results["ids"][0][i],
                    text     = doc,
                    metadata = results["metadatas"][0][i],
                    score    = round(score, 3),
                ))
            return entries
        except Exception:
            return []


# ── Unified memory interface ──────────────────────────────────────────────────

class GhostMemory:
    """
    Единый интерфейс памяти.
    Автоматически выбирает: Qdrant → ChromaDB → in-memory.
    """

    def __init__(self) -> None:
        self._qdrant = QdrantMemory()
        self._chroma = ChromaMemory()
        self._store:  List[dict] = []  # in-memory last resort
        self._embedder = EmbeddingProvider()

    @property
    def backend(self) -> str:
        if self._qdrant.is_available():  return "qdrant"
        if self._chroma.is_available():  return "chromadb"
        return "in-memory"

    def store_finding(self, finding: dict, scan_id: str = "") -> None:
        if self._qdrant.is_available():
            self._qdrant.store_finding(finding, scan_id)
        elif self._chroma.is_available():
            self._chroma.store_finding(finding, scan_id)
        else:
            text = QdrantMemory._finding_text(finding)
            self._store.append({
                "text": text, "vec": self._embedder.embed(text),
                "meta": {"scan_id": scan_id, **finding},
            })

    def store_findings_batch(self, findings: List[dict], scan_id: str = "") -> None:
        for f in findings:
            self.store_finding(f, scan_id)

    def similar_findings(self, finding: dict, limit: int = 5) -> List[MemoryEntry]:
        if self._qdrant.is_available():
            return self._qdrant.similar_findings(finding, limit)
        if self._chroma.is_available():
            return self._chroma.similar_findings(finding, limit)
        # in-memory fallback
        query = self._embedder.embed(QdrantMemory._finding_text(finding))
        scored = sorted(
            self._store,
            key=lambda e: QdrantMemory._cosine(query, e["vec"]),
            reverse=True,
        )[:limit]
        return [MemoryEntry(
            id=hashlib.sha1(e["text"].encode()).hexdigest()[:12],
            text=e["text"], metadata=e["meta"],
            score=QdrantMemory._cosine(query, e["vec"]),
        ) for e in scored]

    def store_remediation(self, finding: dict, fix: str, applied: bool = False) -> None:
        if self._qdrant.is_available():
            self._qdrant.store_remediation(finding, fix, applied)

    def get_remediations(self, finding: dict, limit: int = 3) -> List[MemoryEntry]:
        if self._qdrant.is_available():
            return self._qdrant.get_remediations(finding, limit)
        return []

    def store_scan(self, scan_id: str, target: str, summary: dict) -> None:
        if self._qdrant.is_available():
            self._qdrant.store_scan(scan_id, target, summary)

    def status(self) -> dict:
        return {
            "backend":   self.backend,
            "qdrant":    self._qdrant.status(),
            "chromadb":  {"available": self._chroma.is_available()},
            "in_memory": len(self._store),
        }


MEMORY = GhostMemory()
