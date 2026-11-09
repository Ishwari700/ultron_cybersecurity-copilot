"""Cryptographically Chained Audit Ledger.

Enforces:
- Append-only semantics (no rewriting or reordering)
- Verification of hash chains across all events
- Detection of historical modifications
"""

from datetime import datetime, timezone
import hashlib
from typing import Any, Dict, List, Optional
from src.audit.models import AuditEventType, ImmutableAuditEvent


class AuditLedger:
    """Assessment-scoped immutable audit ledger."""

    def __init__(self, assessment_id: str):
        self.assessment_id = assessment_id
        self._events: List[ImmutableAuditEvent] = []
        self._last_hash: str = "GENESIS"

    def append(
        self,
        actor: str,
        event_type: AuditEventType,
        object_id: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ImmutableAuditEvent:
        """Appends a new event and updates the hash chain."""
        now_ts = datetime.now(timezone.utc).isoformat()
        raw_seed = f"{self.assessment_id}:{object_id}:{event_type.value}:{len(self._events)}:{now_ts}"
        event_id = f"AUD-{hashlib.sha256(raw_seed.encode()).hexdigest()[:12].upper()}"

        event = ImmutableAuditEvent(
            event_id=event_id,
            assessment_id=self.assessment_id,
            actor=actor,
            timestamp=now_ts,
            event_type=event_type,
            object_id=object_id,
            previous_event_hash=self._last_hash,
            metadata=metadata or {},
        )
        event.event_hash = event.compute_event_hash()

        self._events.append(event)
        self._last_hash = event.event_hash
        return event

    def get_events(self, event_type: Optional[AuditEventType] = None) -> List[ImmutableAuditEvent]:
        """Returns all events, optionally filtered by event type."""
        if not event_type:
            return list(self._events)
        return [e for e in self._events if e.event_type == event_type]

    def verify_integrity(self) -> bool:
        """
        Validates the complete cryptographic hash chain.
        Returns False if any event was modified, deleted, or reordered.
        """
        expected_prev = "GENESIS"
        for evt in self._events:
            if evt.previous_event_hash != expected_prev:
                return False
            if evt.event_hash != evt.compute_event_hash():
                return False
            expected_prev = evt.event_hash
        return True
