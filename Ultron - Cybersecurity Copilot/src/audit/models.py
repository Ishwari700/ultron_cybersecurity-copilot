"""Domain Models for Tamper-Evident Assessment Audit Trail (Phase 20).

Enforces:
- SHA-256 cryptographic event chaining across all assessment events
- Immutability of historical lifecycle logs
- Prevention of historical log rewrites
"""

from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class AuditEventType(str, Enum):
    """Canonical event taxonomy for security assessments."""
    ASSESSMENT_CREATED = "ASSESSMENT_CREATED"
    ASSET_ADDED = "ASSET_ADDED"
    ARTIFACT_IMPORTED = "ARTIFACT_IMPORTED"
    ARTIFACT_QUARANTINED = "ARTIFACT_QUARANTINED"
    AGENT_ANALYSIS_COMPLETED = "AGENT_ANALYSIS_COMPLETED"
    EVIDENCE_ADDED = "EVIDENCE_ADDED"
    HYPOTHESIS_CREATED = "HYPOTHESIS_CREATED"
    FALSIFICATION_COMPLETED = "FALSIFICATION_COMPLETED"
    REVIEW_STARTED = "REVIEW_STARTED"
    EVIDENCE_REQUESTED = "EVIDENCE_REQUESTED"
    FINDING_REJECTED = "FINDING_REJECTED"
    HUMAN_VERIFICATION_SUBMITTED = "HUMAN_VERIFICATION_SUBMITTED"
    FINDING_VALIDATED = "FINDING_VALIDATED"
    REPORT_GENERATED = "REPORT_GENERATED"
    REPORT_FINALIZED = "REPORT_FINALIZED"
    REPORT_EXPORTED = "REPORT_EXPORTED"

    # Milestone 11 Experiment and Safe PoC Audit Events
    EXPERIMENT_CREATED = "EXPERIMENT_CREATED"
    EXPERIMENT_PREFLIGHTED = "EXPERIMENT_PREFLIGHTED"
    AUTHORIZATION_VERIFIED = "AUTHORIZATION_VERIFIED"
    SCOPE_VERIFIED = "SCOPE_VERIFIED"
    RISK_CLASSIFIED = "RISK_CLASSIFIED"
    HUMAN_APPROVAL_REQUESTED = "HUMAN_APPROVAL_REQUESTED"
    HUMAN_APPROVED = "HUMAN_APPROVED"
    EXECUTION_STARTED = "EXECUTION_STARTED"
    EXECUTION_COMPLETED = "EXECUTION_COMPLETED"
    EXECUTION_ABORTED = "EXECUTION_ABORTED"
    OBSERVATION_CAPTURED = "OBSERVATION_CAPTURED"
    NEGATIVE_CONTROL_EXECUTED = "NEGATIVE_CONTROL_EXECUTED"
    REVIEW_CREATED = "REVIEW_CREATED"


class ImmutableAuditEvent(BaseModel):
    """Cryptographically chained, immutable audit record."""
    event_id: str
    assessment_id: str
    actor: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    event_type: AuditEventType
    object_id: str
    previous_event_hash: str = "GENESIS"
    event_hash: str = ""
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def compute_event_hash(self) -> str:
        """Computes deterministic SHA-256 hash chaining to previous event."""
        payload = {
            "previous_event_hash": self.previous_event_hash,
            "event_id": self.event_id,
            "assessment_id": self.assessment_id,
            "actor": self.actor,
            "timestamp": self.timestamp,
            "event_type": self.event_type.value,
            "object_id": self.object_id,
            "metadata": json.dumps(self.metadata, sort_keys=True),
        }
        raw = json.dumps(payload, sort_keys=True).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()
