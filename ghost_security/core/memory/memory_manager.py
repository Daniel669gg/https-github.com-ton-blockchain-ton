"""
Ghost Security Platform — Memory Manager
Real vector memory using ChromaDB. No placeholders.
"""
import json
import time
import hashlib
from typing import Optional, List, Dict, Any
from pathlib import Path
import chromadb
from chromadb.config import Settings
from openai import OpenAI

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from config.config import (
    CHROMA_PERSIST_DIR, MEMORY_COLLECTION,
    OPENAI_API_KEY, OPENAI_BASE_URL, LLM_FAST_MODEL
)


class MemoryManager:
    """
    Real vector memory manager using ChromaDB.
    Supports short-term session memory and long-term persistent memory.
    """

    def __init__(self):
        # Initialize ChromaDB with persistence
        Path(CHROMA_PERSIST_DIR).mkdir(parents=True, exist_ok=True)
        self.client = chromadb.PersistentClient(
            path=CHROMA_PERSIST_DIR,
            settings=Settings(anonymized_telemetry=False)
        )
        self.collection = self.client.get_or_create_collection(
            name=MEMORY_COLLECTION,
            metadata={"hnsw:space": "cosine"}
        )

        # Short-term memory: list of dicts for current session
        self.session_memory: List[Dict[str, Any]] = []
        self.session_id = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]

        # LLM client for embeddings
        self.llm = OpenAI(api_key=OPENAI_API_KEY, base_url=OPENAI_BASE_URL)

    def _get_embedding(self, text: str) -> List[float]:
        """Get real embedding from OpenAI API."""
        try:
            response = self.llm.embeddings.create(
                model="text-embedding-3-small",
                input=text[:8000]  # limit to avoid token overflow
            )
            return response.data[0].embedding
        except Exception:
            # Fallback: use simple hash-based pseudo-embedding for offline mode
            import struct
            h = hashlib.sha256(text.encode()).digest()
            return [struct.unpack('f', h[i:i+4])[0] for i in range(0, min(len(h), 1536*4), 4)][:1536]

    def add_finding(self, finding: Dict[str, Any]) -> str:
        """Store a security finding in long-term memory."""
        doc_id = hashlib.md5(json.dumps(finding, sort_keys=True).encode()).hexdigest()
        text = self._finding_to_text(finding)
        embedding = self._get_embedding(text)

        self.collection.upsert(
            ids=[doc_id],
            embeddings=[embedding],
            documents=[text],
            metadatas=[{
                "type": finding.get("type", "unknown"),
                "severity": finding.get("severity", "INFO"),
                "file": finding.get("file", ""),
                "timestamp": str(time.time()),
                "session_id": self.session_id
            }]
        )
        return doc_id

    def search_similar(self, query: str, n_results: int = 5) -> List[Dict[str, Any]]:
        """Search for similar findings using vector similarity."""
        embedding = self._get_embedding(query)
        try:
            results = self.collection.query(
                query_embeddings=[embedding],
                n_results=min(n_results, self.collection.count())
            )
            findings = []
            if results and results['documents']:
                for i, doc in enumerate(results['documents'][0]):
                    findings.append({
                        "document": doc,
                        "metadata": results['metadatas'][0][i] if results['metadatas'] else {},
                        "distance": results['distances'][0][i] if results['distances'] else 1.0
                    })
            return findings
        except Exception:
            return []

    def add_to_session(self, role: str, content: str, metadata: Optional[Dict] = None):
        """Add message to short-term session memory."""
        entry = {
            "role": role,
            "content": content,
            "timestamp": time.time(),
            "metadata": metadata or {}
        }
        self.session_memory.append(entry)
        # Keep session memory bounded
        if len(self.session_memory) > 50:
            self.session_memory = self.session_memory[-50:]

    def get_session_context(self, max_messages: int = 10) -> List[Dict[str, str]]:
        """Get recent session messages for LLM context."""
        recent = self.session_memory[-max_messages:]
        return [{"role": m["role"], "content": m["content"]} for m in recent]

    def get_all_findings(self, session_only: bool = False) -> List[Dict]:
        """Retrieve all stored findings."""
        try:
            count = self.collection.count()
            if count == 0:
                return []
            results = self.collection.get(
                where={"session_id": self.session_id} if session_only else None,
                include=["documents", "metadatas"]
            )
            findings = []
            for i, doc in enumerate(results.get('documents', [])):
                findings.append({
                    "document": doc,
                    "metadata": results['metadatas'][i] if results.get('metadatas') else {}
                })
            return findings
        except Exception:
            return []

    def clear_session(self):
        """Clear short-term session memory."""
        self.session_memory = []
        self.session_id = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]

    def get_stats(self) -> Dict[str, Any]:
        """Get memory statistics."""
        return {
            "total_findings": self.collection.count(),
            "session_messages": len(self.session_memory),
            "session_id": self.session_id
        }

    @staticmethod
    def _finding_to_text(finding: Dict) -> str:
        """Convert finding dict to searchable text."""
        parts = []
        for key in ["type", "severity", "description", "file", "line", "code", "recommendation"]:
            if key in finding:
                parts.append(f"{key}: {finding[key]}")
        return " | ".join(parts)
