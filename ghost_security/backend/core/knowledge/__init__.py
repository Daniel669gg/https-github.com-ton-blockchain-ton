"""backend/core/knowledge — Security knowledge base."""
from .models import (
    CAPECEntry, CVEEntry, CWEEntry, ExploitPattern,
    FixPattern, VulnerabilityKnowledge,
)
from .store import KnowledgeStore
from .research_pipeline import ResearchPipeline, PipelineResult, SynthesizedRule

__all__ = [
    "CAPECEntry", "CVEEntry", "CWEEntry", "ExploitPattern", "FixPattern",
    "VulnerabilityKnowledge", "KnowledgeStore", "ResearchPipeline",
    "PipelineResult", "SynthesizedRule",
]
