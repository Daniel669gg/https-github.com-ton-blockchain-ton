"""
backend/memory — TythanAI multi-level memory subsystem.

Provides ChromaDB-backed (with SQLite BM25 fallback) memory across four
orthogonal layers:

  short_term  — per-session ephemeral context
  long_term   — persisted findings, fixes, confirmed patterns
  semantic    — CWE/CVE knowledge and MITRE ATT&CK patterns
  episodic    — run history and agent decision log

Public surface:
    MemoryManager   — low-level collection operations
    KnowledgeBase   — high-level domain-aware wrapper
"""

from backend.memory.memory_manager import (
    MemoryEntry,
    MemorySearchResult,
    MemoryManager,
)
from backend.memory.knowledge_base import KnowledgeBase

__all__ = [
    "MemoryEntry",
    "MemorySearchResult",
    "MemoryManager",
    "KnowledgeBase",
]
