"""Action Request Models for Human Review in M8.

Enforces:
- Attributable reviewer identity
- Explicit notes and evidence references
- Structured payloads for each review transition
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class RequestEvidenceRequest(BaseModel):
    """Payload to request additional evidence or negative controls."""
    reviewer_id: str
    notes: str
    missing_gaps: List[str] = Field(default_factory=list)


class ContestRequest(BaseModel):
    """Payload to dispute an analytical hypothesis."""
    reviewer_id: str
    reason: str
    alternative_explanation: Optional[str] = None


class RejectRequest(BaseModel):
    """Payload to reject an analytical hypothesis or finding."""
    reviewer_id: str
    reason: str


class ApproveForValidationRequest(BaseModel):
    """Payload to approve a hypothesis for deterministic finding validation."""
    reviewer_id: str
    notes: Optional[str] = None


class SubmitVerificationRequest(BaseModel):
    """Payload to submit explicit human verification through FindingValidator."""
    reviewer_id: str
    reviewer_notes: str
    evidence_references: List[str] = Field(default_factory=list)
    finding_override: Optional[Dict[str, Any]] = None
