"""Tamper-Evident Review Audit Logger with Cryptographic Event Chaining.

Enforces:
- Cryptographic hash-chained audit trail
- Immutability of review history
- Complete traceability of human decisions, requests for evidence, and validation attempts
"""

from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ReviewAuditEvent(BaseModel):
    """Immutable audit event in the review ledger."""
    event_id: str
    assessment_id: str
    actor: str  # reviewer_id or system component
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    event_type: str
    object_id: str
    previous_event_hash: str = "GENESIS"
    event_hash: str = ""
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def compute_hash(self) -> str:
        """Computes deterministic SHA-256 hash chaining to previous event."""
        payload = {
            "previous_event_hash": self.previous_event_hash,
            "event_id": self.event_id,
            "assessment_id": self.assessment_id,
            "actor": self.actor,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "object_id": self.object_id,
            "metadata": json.dumps(self.metadata, sort_keys=True),
        }
        raw = json.dumps(payload, sort_keys=True).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()


class ReviewAuditLogger:
    """Manages append-only, chained audit logs for reviews within an assessment."""

    def __init__(self, assessment_id: str):
        self.assessment_id = assessment_id
        self._events: List[ReviewAuditEvent] = []
        self._last_hash: str = "GENESIS"

    @property
    def events(self) -> List[ReviewAuditEvent]:
        return list(self._events)

    def append_event(
        self,
        actor: str,
        event_type: str,
        object_id: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ReviewAuditEvent:
        """Appends a new cryptographically chained audit event."""
        raw_seed = f"{self.assessment_id}:{object_id}:{event_type}:{len(self._events)}:{datetime.now(timezone.utc).isoformat()}"
        event_id = f"EVT-{hashlib.sha256(raw_seed.encode()).hexdigest()[:12].upper()}"

        event = ReviewAuditEvent(
            event_id=event_id,
            assessment_id=self.assessment_id,
            actor=actor,
            event_type=event_type,
            object_id=object_id,
            previous_event_hash=self._last_hash,
            metadata=metadata or {},
        )
        event.event_hash = event.compute_hash()
        self._events.append(event)
        self._last_hash = event.event_hash
        return event

    def verify_integrity(self) -> bool:
        """Verifies that the entire audit chain is valid and untampered."""
        expected_prev = "GENESIS"
        for evt in self._events:
            if evt.previous_event_hash != expected_prev:
                return False
            if evt.event_hash != evt.compute_hash():
                return False
            expected_prev = evt.event_hash
        return True
