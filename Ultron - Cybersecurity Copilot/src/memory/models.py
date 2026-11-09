"""Domain models for M12 Security Research Memory Subsystem.

Defines strongly-typed representations for MemoryItem, EvidencePointer,
MemoryVersion, MemoryConflict, MemoryPromotion, MemoryAccessContext,
Retrieval metadata, and Deletion tombstones.
"""

from datetime import datetime, timezone
import hashlib
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from src.memory.enums import (
    ConflictType,
    EpistemicStatus,
    FreshnessState,
    LifecycleState,
    MemoryAuthority,
    MemoryNamespace,
    MemorySourceType,
    PromotionStatus,
    SensitivityClassification,
)


def compute_memory_hash(content: str) -> str:
    """Computes deterministic SHA-256 hash of memory content."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


class EvidencePointer(BaseModel):
    """
    Reference/pointer to canonical evidence stored in Plane 4.
    Memory never replaces or duplicates canonical evidence.
    """
    pointer_id: str
    memory_id: str
    target_evidence_id: str
    assessment_id: str
    evidence_type: str
    evidence_digest: str
    is_broken: bool = False
    verified_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def verify_target_evidence_exists(self, known_digests: List[str]) -> bool:
        """Validates that referenced canonical evidence digest exists."""
        self.is_broken = self.evidence_digest not in known_digests
        return not self.is_broken


class MemoryItem(BaseModel):
    """
    Core unit of research memory.
    Represents an auditable, typed piece of past knowledge or experience.
    """
    memory_id: str
    namespace: MemoryNamespace
    owner_id: str = "default_researcher"
    tenant_id: str = "default_tenant"
    assessment_id: Optional[str] = None
    source_type: MemorySourceType
    epistemic_status: EpistemicStatus
    authority_level: MemoryAuthority
    content: str
    normalized_content: str = ""
    title: str = ""
    summary: str = ""
    confidence: float = 1.0
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_accessed_at: Optional[str] = None
    source_timestamp: Optional[str] = None
    provenance_references: List[str] = Field(default_factory=list)
    evidence_references: List[str] = Field(default_factory=list)
    evidence_pointers: List[EvidencePointer] = Field(default_factory=list)
    content_hash: str = ""
    version: int = 1
    supersedes: Optional[str] = None
    superseded_by: Optional[str] = None
    retention_expiry: Optional[str] = None
    sensitivity_classification: SensitivityClassification = SensitivityClassification.INTERNAL
    sanitization_status: str = "PENDING"
    promotion_status: PromotionStatus = PromotionStatus.LOCAL_ONLY
    lifecycle_state: LifecycleState = LifecycleState.ACTIVE
    is_tombstone: bool = False
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def model_post_init(self, __context: Any) -> None:
        if not self.content_hash and self.content is not None:
            self.content_hash = compute_memory_hash(self.content)
        if not self.normalized_content and self.content is not None:
            self.normalized_content = " ".join(self.content.lower().split())

    def verify_hash(self) -> bool:
        """Verify that current content matches content_hash."""
        return self.content_hash == compute_memory_hash(self.content)


class MemoryVersion(BaseModel):
    """
    Historical snapshot of a memory item prior to mutation or correction.
    """
    version_id: str
    memory_id: str
    version_number: int
    content: str
    content_hash: str
    epistemic_status: EpistemicStatus
    authority_level: MemoryAuthority
    created_at: str
    superseded_by: Optional[str] = None
    change_rationale: str = ""


class MemoryConflict(BaseModel):
    """
    Explicit record of detected contradiction or disagreement between memory items.
    """
    conflict_id: str
    conflict_type: ConflictType
    memory_id_a: str
    memory_id_b: str
    description: str
    detected_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    resolution_status: str = "OPEN"  # OPEN, RESOLVED, CONTESTED
    resolution_notes: Optional[str] = None


class MemoryPromotion(BaseModel):
    """
    Auditable workflow record for promoting local memory to shared research.
    Requires explicit human approval.
    """
    promotion_id: str
    memory_id: str
    requester_id: str
    reviewer_id: Optional[str] = None
    source_namespace: MemoryNamespace
    target_namespace: MemoryNamespace
    status: PromotionStatus = PromotionStatus.CANDIDATE
    justification: str
    requested_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    reviewed_at: Optional[str] = None
    audit_event_id: Optional[str] = None


class MemoryAccessContext(BaseModel):
    """
    Mandatory security context required for memory queries and operations.
    Enforces tenant and assessment isolation. Fails closed if missing.
    """
    user_id: str = "default_user"
    tenant_id: str = "default_tenant"
    assessment_id: Optional[str] = None
    allowed_namespaces: List[MemoryNamespace] = Field(
        default_factory=lambda: [
            MemoryNamespace.GLOBAL_KNOWLEDGE,
            MemoryNamespace.USER_RESEARCH,
            MemoryNamespace.SHARED_RESEARCH,
            MemoryNamespace.VERIFIED_PATTERN,
            MemoryNamespace.ASSESSMENT_LOCAL,
            MemoryNamespace.TARGET_EVIDENCE_POINTER,
        ]
    )
    is_admin: bool = False
    audit_actor: str = "researcher"


class MemoryRetrievalItem(BaseModel):
    """
    An individual retrieved candidate with citation, scoring, and freshness metadata.
    """
    memory: MemoryItem
    relevance_score: float
    retrieval_method: str  # fts5, dense, hybrid_rrf
    rationale: str
    freshness: FreshnessState = FreshnessState.CURRENT
    effective_score: float = 0.0

    def compute_citation(self) -> Dict[str, Any]:
        """Produces transparent citation data for user inspection."""
        return {
            "memory_id": self.memory.memory_id,
            "namespace": self.memory.namespace.value,
            "epistemic_status": self.memory.epistemic_status.value,
            "authority_level": self.memory.authority_level.value,
            "source_type": self.memory.source_type.value,
            "assessment_id": self.memory.assessment_id,
            "confidence": self.memory.confidence,
            "created_at": self.memory.created_at,
            "relevance_score": round(self.relevance_score, 4),
            "effective_score": round(self.effective_score, 4),
            "freshness": self.freshness.value,
            "retrieved_reason": self.rationale,
        }


class MemoryRetrievalResult(BaseModel):
    """
    Full output of a memory retrieval query.
    """
    query: str
    access_context: MemoryAccessContext
    items: List[MemoryRetrievalItem] = Field(default_factory=list)
    total_found: int = 0
    retrieval_latency_ms: float = 0.0
    explanation: str = ""


class MemoryDeletionRecord(BaseModel):
    """
    Audit tombstone for a deleted memory item.
    Never preserves raw sensitive content.
    """
    tombstone_id: str
    memory_id: str
    namespace: MemoryNamespace
    assessment_id: Optional[str] = None
    deleted_by: str
    deleted_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    reason: str
    content_hash: str
