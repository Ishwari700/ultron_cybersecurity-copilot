"""Pydantic Schema and Validation Models for VAPT Retrieval Evaluation Benchmark.

Phase 0: Gold-Standard 100-Query VAPT Retrieval Benchmark.
"""

from enum import Enum
import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator


class DifficultyLevel(str, Enum):
    EASY = "EASY"
    MEDIUM = "MEDIUM"
    HARD = "HARD"


class QueryType(str, Enum):
    DIRECT_CONCEPT = "DIRECT_CONCEPT"
    SECURITY_INVARIANT = "SECURITY_INVARIANT"
    EVIDENCE_GAP = "EVIDENCE_GAP"
    EXPERIMENT = "EXPERIMENT"
    PARAPHRASED = "PARAPHRASED"
    NEGATIVE_CONTROL = "NEGATIVE_CONTROL"


class TargetIdentifierType(str, Enum):
    CHUNK_ID = "chunk_id"
    DOCUMENT_ID = "document_id"
    KNOWLEDGE_TYPE = "knowledge_type"
    CATEGORY = "category"
    CWE_ID = "cwe_id"
    WSTG_ID = "wstg_id"


class RetrievalTargetSpec(BaseModel):
    """Specification of an expected or acceptable knowledge item."""
    type: str = Field(..., description="Semantic identifier type: chunk_id, document_id, knowledge_type, category, etc.")
    value: str = Field(..., description="Identifier value grounded in the corpus")
    reason: Optional[str] = Field(None, description="Optional rationale for why this item is expected or excluded")


class VaptRetrievalQuery(BaseModel):
    """Atomic evaluation unit for the VAPT retrieval benchmark."""
    query_id: str = Field(..., description="Deterministic unique identifier, e.g., VAPT-Q001")
    query: str = Field(..., description="Raw search query text presented to the retriever")
    security_domain: str = Field(..., description="Standard security domain classification")
    difficulty: DifficultyLevel = Field(..., description="Query difficulty: EASY, MEDIUM, HARD")
    query_type: QueryType = Field(..., description="Primary query taxonomy type")
    evidence_gap_type: str = Field(..., description="Associated architectural evidence gap classification")
    
    # Characteristic boolean flags for analytical slice filtering
    is_negative_control: bool = Field(False, description="True if query tests semantic discrimination / negative control")
    is_security_invariant: bool = Field(False, description="True if framed around non-negotiable security invariant")
    is_evidence_gap: bool = Field(False, description="True if framed as missing observation / evidence gap")
    is_experiment: bool = Field(False, description="True if focused on minimal manual experiment methodology")
    is_adversarial_or_paraphrased: bool = Field(False, description="True if query avoids canonical vulnerability keywords")

    expected_knowledge_types: List[str] = Field(default_factory=list, description="Expected KnowledgeType values")
    expected_categories: List[str] = Field(default_factory=list, description="Expected category tags")
    relevance_requirements: List[str] = Field(default_factory=list, description="Natural language relevance criteria")
    
    must_retrieve: List[RetrievalTargetSpec] = Field(..., description="Mandatory knowledge targets that must be retrieved")
    acceptable_retrievals: List[RetrievalTargetSpec] = Field(default_factory=list, description="Acceptable related knowledge targets")
    irrelevant_retrievals: List[RetrievalTargetSpec] = Field(default_factory=list, description="Negative controls / distractors that should not rank highly")
    
    relevance_ratings: Dict[str, int] = Field(
        ...,
        description="Ground-truth relevance ratings per chunk_id: 3=Highly Relevant, 2=Related/Useful, 1=Weakly Related, 0=Irrelevant"
    )
    notes: str = Field(..., description="Methodology notes explaining rationale and validation intent")

    @field_validator("relevance_ratings")
    @classmethod
    def validate_relevance_scores(cls, v: Dict[str, int]) -> Dict[str, int]:
        for cid, score in v.items():
            if score not in (0, 1, 2, 3):
                raise ValueError(f"Invalid relevance score {score} for {cid}; must be 0, 1, 2, or 3.")
        return v


class VaptRetrievalBenchmarkDataset(BaseModel):
    """Root container for the versioned 100-query benchmark dataset."""
    schema_version: str = "1.0.0"
    benchmark_name: str = "VAPT_RETRIEVAL_GOLD_STANDARD_BENCHMARK"
    description: str = "Implementation-independent gold-standard retrieval evaluation benchmark for general VAPT knowledge."
    corpus_document_count: int = 6
    corpus_chunk_count: int = 23
    total_queries: int = 100
    queries: List[VaptRetrievalQuery] = Field(..., description="List of 100 evaluation queries")


def load_vapt_benchmark(path: Path = Path("tests/evaluation/vapt_retrieval_queries.json")) -> VaptRetrievalBenchmarkDataset:
    """Load and validate the benchmark dataset from JSON."""
    if not path.exists():
        raise FileNotFoundError(f"Benchmark file not found at {path}")
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return VaptRetrievalBenchmarkDataset.model_validate(data)
