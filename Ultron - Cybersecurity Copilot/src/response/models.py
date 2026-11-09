"""Typed models and domain concepts for M11.5 Long Response Subsystem."""

from datetime import datetime, timezone
from enum import Enum
import hashlib
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, AliasChoices


class ResponseStatus(str, Enum):
    """Lifecycle status of a response generation session."""
    GENERATING = "GENERATING"
    CONTINUING = "CONTINUING"
    COMPLETED = "COMPLETED"
    USER_STOPPED = "USER_STOPPED"
    MODEL_STOPPED = "MODEL_STOPPED"
    TOKEN_LIMIT = "TOKEN_LIMIT"
    CONTEXT_LIMIT = "CONTEXT_LIMIT"
    TIMEOUT = "TIMEOUT"
    ERROR = "ERROR"
    VALIDATION_FAILED = "VALIDATION_FAILED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"


class GenerationTermination(str, Enum):
    """Underlying reason why model generation or continuation halted."""
    NATURAL_STOP = "NATURAL_STOP"
    LENGTH_CEILING = "LENGTH_CEILING"
    CONTEXT_EXHAUSTION = "CONTEXT_EXHAUSTION"
    TIMEOUT_ABORT = "TIMEOUT_ABORT"
    CLIENT_ABORT = "CLIENT_ABORT"
    ENGINE_ERROR = "ENGINE_ERROR"
    MAX_CHUNKS_REACHED = "MAX_CHUNKS_REACHED"
    SAFETY_BOUND_EXCEEDED = "SAFETY_BOUND_EXCEEDED"
    DAEMON_UNAVAILABLE = "DAEMON_UNAVAILABLE"
    MODEL_NOT_FOUND = "MODEL_NOT_FOUND"
    VALIDATION_ERROR = "VALIDATION_ERROR"
    EVIDENCE_MISSING = "EVIDENCE_MISSING"


class EpistemicStatus(str, Enum):
    """Epistemic status and grounding classification of an AI response."""
    DIRECT_OBSERVATION = "DIRECT_OBSERVATION"
    USER_PROVIDED = "USER_PROVIDED"
    EVIDENCE_BACKED = "EVIDENCE_BACKED"
    AUTHORITATIVE_KNOWLEDGE = "AUTHORITATIVE_KNOWLEDGE"
    EXTERNAL_SOURCE = "EXTERNAL_SOURCE"
    MODEL_HYPOTHESIS = "MODEL_HYPOTHESIS"
    MODEL_INFERENCE = "MODEL_INFERENCE"
    UNVERIFIED_CLAIM = "UNVERIFIED_CLAIM"
    EVIDENCE_GAP = "EVIDENCE_GAP"
    HUMAN_VERIFIED = "HUMAN_VERIFIED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class RuntimeOutcome(str, Enum):
    """Execution runtime outcome for model and pipeline dispatch."""
    SUCCESS = "SUCCESS"
    PARTIAL_SUCCESS = "PARTIAL_SUCCESS"
    DAEMON_UNAVAILABLE = "DAEMON_UNAVAILABLE"
    MODEL_UNAVAILABLE = "MODEL_UNAVAILABLE"
    TIMEOUT = "TIMEOUT"
    VALIDATION_FAILED = "VALIDATION_FAILED"
    ENGINE_ERROR = "ENGINE_ERROR"
    USER_ABORTED = "USER_ABORTED"
    EVIDENCE_UNAVAILABLE = "EVIDENCE_UNAVAILABLE"


class CompletenessState(str, Enum):
    """Heuristic assessment of whether generated text represents a finished thought."""
    COMPLETE = "COMPLETE"
    LIKELY_COMPLETE = "LIKELY_COMPLETE"
    LIKELY_INCOMPLETE = "LIKELY_INCOMPLETE"
    INCOMPLETE = "INCOMPLETE"
    UNKNOWN = "UNKNOWN"


def compute_content_hash(text: str) -> str:
    """Compute deterministic SHA-256 hash of chunk content."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class CitationReference(BaseModel):
    """Granular verified citation reference anchored to authoritative evidence or knowledge."""
    source_id: str
    source_type: str  # 'TARGET_EVIDENCE', 'AUTHORITATIVE_KNOWLEDGE', 'EXTERNAL_REFERENCE'
    epistemic_tier: str = "TARGET_EVIDENCE"
    assessment_id: Optional[str] = None
    investigation_id: Optional[str] = None
    title: Optional[str] = None
    locator: Optional[str] = None
    quotation: Optional[str] = None
    verified: bool = False
    resolution_status: Optional[str] = None
    provenance: Optional[str] = None
    rejection_reason: Optional[str] = None


class ResponseValidationReport(BaseModel):
    """Validation outcome assessing schema, epistemic constraints, citations, and structural integrity."""
    passed: bool = True
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    citation_precision: float = 1.0
    epistemic_status: EpistemicStatus = EpistemicStatus.MODEL_INFERENCE
    unclosed_code_blocks: int = 0
    duplicate_sections_detected: int = 0


class ResponseChunk(BaseModel):
    """Individual chunk produced in a multi-turn continuation generation."""
    chunk_id: str
    sequence_number: int
    content: str
    raw_content: str
    content_hash: str = ""
    token_count: int = 0
    generation_time: float = 0.0
    stop_reason: str = "stop"  # e.g., 'stop', 'length', 'timeout', 'abort'
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def model_post_init(self, __context: Any) -> None:
        if not self.content_hash and self.content is not None:
            self.content_hash = compute_content_hash(self.content)

    def verify_hash(self) -> bool:
        """Verify that content matches content_hash."""
        return self.content_hash == compute_content_hash(self.content)


class ContinuationState(BaseModel):
    """State tracking for automated or manual continuation."""
    chunk_count: int = 0
    cumulative_tokens: int = 0
    repacking_attempts: int = 0
    status: ResponseStatus = ResponseStatus.GENERATING
    termination_reason: Optional[GenerationTermination] = None
    can_continue: bool = True
    last_error: Optional[str] = None


class ResponseVersion(BaseModel):
    """Historical version of an assistant response across regenerations."""
    version_id: str
    response_id: str
    version_number: int
    content: str
    model: str
    status: ResponseStatus = ResponseStatus.COMPLETED
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class ResponseSession(BaseModel):
    """
    First-class canonical response session aggregating multi-chunk responses,
    preserving exact chunk provenance, citations, validation, and unified user-facing delivery.
    """
    response_id: str
    investigation_id: str
    assessment_id: Optional[str] = None
    request_id: Optional[str] = None
    parent_message_id: Optional[str] = None
    model: str = Field(
        default="qwen2.5-coder:7b",
        min_length=1,
        validation_alias=AliasChoices("model", "model_name"),
    )
    requested_model: Optional[str] = None
    fallback_model: Optional[str] = None
    fallback_used: bool = False
    fallback_reason: Optional[str] = None
    user_prompt: Optional[str] = None
    chunks: List[ResponseChunk] = Field(default_factory=list)
    cumulative_tokens: int = 0
    status: ResponseStatus = ResponseStatus.GENERATING
    termination_reason: Optional[GenerationTermination] = None
    final_content: str = ""
    started_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at: Optional[str] = None
    active_version: int = 1

    # Canonical metadata and epistemic contract fields
    epistemic_status: EpistemicStatus = EpistemicStatus.MODEL_INFERENCE
    runtime_outcome: RuntimeOutcome = RuntimeOutcome.SUCCESS
    validation_passed: bool = True
    validation_errors: List[str] = Field(default_factory=list)
    validation_warnings: List[str] = Field(default_factory=list)
    citations: List[CitationReference] = Field(default_factory=list)
    sources: List[str] = Field(default_factory=list)
    continuation_count: int = 0
    is_truncated: bool = False
    persisted: bool = False
    persistence_error: Optional[str] = None
    total_duration_seconds: float = 0.0
    model_config_params: Dict[str, Any] = Field(default_factory=dict)

    def add_chunk(self, chunk: ResponseChunk) -> None:
        """Append chunk and update cumulative metadata."""
        self.chunks.append(chunk)
        self.cumulative_tokens += chunk.token_count

    @property
    def model_name(self) -> str:
        """Backward-compatible property for callers expecting model_name."""
        return self.model

    @model_name.setter
    def model_name(self, value: str) -> None:
        self.model = value
