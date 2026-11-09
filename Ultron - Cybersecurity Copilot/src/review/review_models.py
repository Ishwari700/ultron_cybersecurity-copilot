"""Domain Models for Human Review in M8 Security Assessments.

Enforces:
- Deterministic review statuses and reviewer decisions
- Structured ReviewCase tracking hypotheses and findings awaiting human inspection
- Preservation of epistemic boundaries (OBSERVATION, MODEL_HYPOTHESIS, HUMAN_VERIFIED_FINDING, etc.)
- Strict attributable verification requirements
"""

from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator


class ReviewStatus(str, Enum):
    """Lifecycle status of a human review case."""
    PENDING = "PENDING"
    IN_REVIEW = "IN_REVIEW"
    NEEDS_EVIDENCE = "NEEDS_EVIDENCE"
    CONTESTED = "CONTESTED"
    APPROVED_FOR_VALIDATION = "APPROVED_FOR_VALIDATION"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"


class ReviewerDecision(str, Enum):
    """Explicit deterministic action taken by human reviewer."""
    CONFIRM = "CONFIRM"
    REJECT = "REJECT"
    REQUEST_MORE_EVIDENCE = "REQUEST_MORE_EVIDENCE"
    MARK_CONTESTED = "MARK_CONTESTED"


class ReviewTargetType(str, Enum):
    """Type of entity undergoing review."""
    HYPOTHESIS = "HYPOTHESIS"
    TENTATIVE_FINDING = "TENTATIVE_FINDING"


class ReviewCase(BaseModel):
    """Structured human review case containing full analytical provenance."""
    review_id: str
    assessment_id: str
    target_id: str  # hypothesis_id or finding_id
    target_type: ReviewTargetType = ReviewTargetType.HYPOTHESIS
    title: str = ""
    description: str = ""
    severity: str = "MEDIUM"
    affected_asset: str = ""
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    reviewer_id: Optional[str] = None
    status: ReviewStatus = ReviewStatus.PENDING
    epistemic_status: str = "MODEL_HYPOTHESIS"  # OBSERVATION, MODEL_HYPOTHESIS, CONTESTED, HUMAN_REVIEW_PENDING, HUMAN_VERIFIED_FINDING
    supporting_evidence: List[str] = Field(default_factory=list)
    contradicting_evidence: List[str] = Field(default_factory=list)
    evidence_gaps: List[str] = Field(default_factory=list)
    falsification_result: Optional[Dict[str, Any]] = None
    consensus_result: Optional[Dict[str, Any]] = None
    proposed_experiments: List[Dict[str, Any]] = Field(default_factory=list)
    reviewer_decision: Optional[ReviewerDecision] = None
    reviewer_notes: Optional[str] = None
    decision_timestamp: Optional[str] = None
    audit_reference: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    provenance_hash: str = ""

    @field_validator("status", mode="before")
    @classmethod
    def validate_status(cls, v: Any) -> Any:
        if isinstance(v, str):
            return ReviewStatus(v)
        return v

    def compute_provenance_hash(self) -> str:
        """Deterministic SHA-256 hash across immutable case inputs."""
        payload = {
            "review_id": self.review_id,
            "assessment_id": self.assessment_id,
            "target_id": self.target_id,
            "target_type": self.target_type.value,
            "title": self.title,
            "affected_asset": self.affected_asset,
            "supporting_evidence": sorted(self.supporting_evidence),
            "evidence_gaps": sorted(self.evidence_gaps),
            "created_at": self.created_at,
        }
        raw = json.dumps(payload, sort_keys=True).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    @classmethod
    def create(
        cls,
        assessment_id: str,
        target_id: str,
        target_type: ReviewTargetType = ReviewTargetType.HYPOTHESIS,
        title: str = "",
        description: str = "",
        severity: str = "MEDIUM",
        affected_asset: str = "",
        epistemic_status: str = "MODEL_HYPOTHESIS",
        supporting_evidence: Optional[List[str]] = None,
        contradicting_evidence: Optional[List[str]] = None,
        evidence_gaps: Optional[List[str]] = None,
        falsification_result: Optional[Dict[str, Any]] = None,
        consensus_result: Optional[Dict[str, Any]] = None,
        proposed_experiments: Optional[List[Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> "ReviewCase":
        raw_seed = f"{assessment_id}:{target_id}:{datetime.now(timezone.utc).isoformat()}"
        rev_id = f"REV-{hashlib.sha256(raw_seed.encode()).hexdigest()[:12].upper()}"
        inst = cls(
            review_id=rev_id,
            assessment_id=assessment_id,
            target_id=target_id,
            target_type=target_type,
            title=title,
            description=description,
            severity=severity,
            affected_asset=affected_asset,
            epistemic_status=epistemic_status,
            supporting_evidence=supporting_evidence or [],
            contradicting_evidence=contradicting_evidence or [],
            evidence_gaps=evidence_gaps or [],
            falsification_result=falsification_result,
            consensus_result=consensus_result,
            proposed_experiments=proposed_experiments or [],
            metadata=metadata or {},
        )
        inst.provenance_hash = inst.compute_provenance_hash()
        return inst
