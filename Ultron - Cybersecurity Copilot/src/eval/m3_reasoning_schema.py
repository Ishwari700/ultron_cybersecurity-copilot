"""Data Models and Schema Definitions for M3 Retrieval -> Reasoning Evaluation.

Defines:
- M3ReasoningCase: Single controlled reasoning evaluation scenario
- M3ReasoningDataset: Collection of frozen reasoning benchmark cases
- M3ReasoningOutput: Standardized model output representation
- M3ScoringRubric: Explicit 0-4 point rubric criteria
- M3CaseEvaluationResult: Scored evaluation record for a single run
- M3ConfigurationSummary: Aggregate metrics for a retrieval configuration
"""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, computed_field


class DifficultyLevel(str, Enum):
    EASY = "EASY"
    MEDIUM = "MEDIUM"
    HARD = "HARD"


class ReasoningDecision(str, Enum):
    HYPOTHESIS = "HYPOTHESIS"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    NO_RELEVANT_FUNCTIONALITY = "NO_RELEVANT_FUNCTIONALITY"


class RetrievalConfigId(str, Enum):
    CONFIG_A_NO_RAG = "CONFIG_A_NO_RAG"
    CONFIG_B_FTS5 = "CONFIG_B_FTS5"
    CONFIG_C_OLD_BASELINE = "CONFIG_C_OLD_BASELINE"
    CONFIG_D_MINILM_HYBRID = "CONFIG_D_MINILM_HYBRID"
    CONFIG_E_MINILM_DENSE = "CONFIG_E_MINILM_DENSE"


class M3ReasoningCase(BaseModel):
    """A controlled cybersecurity reasoning case grounded in the VAPT corpus."""
    reasoning_case_id: str = Field(..., description="Unique identifier (e.g. RC-01)")
    case_name: str
    user_query: str
    security_domain: str
    target_evidence: Dict[str, Any] = Field(..., description="Lossless structural pack dict")
    expected_security_concept: str
    expected_security_invariant: str
    expected_evidence_requirements: List[str]
    expected_experiment_characteristics: str
    expected_falsification_characteristics: str
    expected_decision: ReasoningDecision
    relevant_knowledge_types: List[str]
    relevant_chunk_ids: List[str]
    difficulty: DifficultyLevel
    is_negative_control: bool = False
    is_evidence_gap: bool = False
    forbidden_or_unsupported_conclusions: List[str] = Field(default_factory=list)
    evaluation_notes: str


class M3ReasoningDataset(BaseModel):
    """Collection of frozen reasoning benchmark cases."""
    schema_version: str = "1.0.0"
    dataset_name: str = "M3_CONTROLLED_REASONING_BENCHMARK"
    description: str = "Controlled VAPT Retrieval -> Reasoning Evaluation Dataset"
    total_cases: int
    cases: List[M3ReasoningCase]


class M3ReasoningOutput(BaseModel):
    """Normalized structured evaluation representation of model output."""
    hypothesis: str = ""
    security_invariant: str = ""
    evidence_gap: Optional[str] = None
    manual_experiment: str = ""
    expected_secure_result: str = ""
    expected_vulnerable_result: str = ""
    falsification: str = ""
    decision: str = "HYPOTHESIS"
    confidence: float = 0.5
    empirical_facts: List[str] = Field(default_factory=list)
    methodology_references: List[str] = Field(default_factory=list)
    reasoning_trace_metadata: Dict[str, Any] = Field(default_factory=dict)
    raw_response: str = ""


class M3ScoringRubric(BaseModel):
    """Detailed scores for a single evaluation run (0-4 scale)."""
    hypothesis_correctness: float = Field(..., ge=0.0, le=4.0)
    evidence_grounding: float = Field(..., ge=0.0, le=4.0)
    evidence_gap_quality: float = Field(..., ge=0.0, le=4.0)
    security_invariant_correctness: float = Field(..., ge=0.0, le=4.0)
    experiment_quality: float = Field(..., ge=0.0, le=4.0)
    falsification_quality: float = Field(..., ge=0.0, le=4.0)
    false_positive_resistance: float = Field(..., ge=0.0, le=4.0)
    unsupported_claim_count: int = 0
    total_claims_count: int = 1
    unsupported_claim_rate: float = 0.0

    @computed_field
    @property
    def composite_reasoning_score(self) -> float:
        """Composite unweighted average of the 7 core reasoning dimensions (0-4)."""
        dims = [
            self.hypothesis_correctness,
            self.evidence_grounding,
            self.evidence_gap_quality,
            self.security_invariant_correctness,
            self.experiment_quality,
            self.falsification_quality,
            self.false_positive_resistance,
        ]
        return sum(dims) / len(dims)


class M3CaseEvaluationResult(BaseModel):
    """Full execution record for a single case under a specific configuration."""
    reasoning_case_id: str
    configuration_id: str
    execution_pipeline: str  # "3B_ONLY" or "CASCADE_3B_7B"
    model_3b: str = "qwen2.5-coder:3b"
    model_7b: Optional[str] = "qwen2.5-coder:7b"
    escalated_to_7b: bool = False
    retrieved_chunk_ids: List[str] = Field(default_factory=list)
    retrieval_latency_ms: float = 0.0
    inference_latency_3b_s: float = 0.0
    inference_latency_7b_s: float = 0.0
    total_latency_s: float = 0.0
    structured_output: M3ReasoningOutput
    scores: M3ScoringRubric
    decision_match: bool = False
    evaluation_notes: str = ""


class M3ConfigurationSummary(BaseModel):
    """Aggregate metrics across the dataset for a single configuration."""
    configuration_id: str
    configuration_name: str
    execution_pipeline: str
    total_cases: int
    mean_composite_score: float
    mean_hypothesis_correctness: float
    mean_evidence_grounding: float
    mean_evidence_gap_quality: float
    mean_security_invariant_correctness: float
    mean_experiment_quality: float
    mean_falsification_quality: float
    mean_false_positive_resistance: float
    mean_unsupported_claim_rate: float
    decision_accuracy: float
    escalation_rate: float
    mean_retrieval_latency_ms: float
    mean_reasoning_latency_s: float
