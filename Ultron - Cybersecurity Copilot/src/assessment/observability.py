"""Structured Assessment Observability and Audit Telemetry for M6.

Records immutable audit trails for every key lifecycle event:
- ASSESSMENT_CREATED
- AUTHORIZATION_ACCEPTED
- SCOPE_DEFINED
- ASSET_DISCOVERED
- OBSERVATION_IMPORTED
- HYPOTHESIS_CREATED
- EVIDENCE_GAP_CREATED
- EXPERIMENT_PROPOSED
- EXPERIMENT_APPROVED
- EXPERIMENT_RESULT_IMPORTED
- HYPOTHESIS_UPDATED
- FINDING_CREATED
- FINDING_VERIFIED
- FINDING_REJECTED
- REPORT_GENERATED
"""

from datetime import datetime, timezone
import hashlib
from typing import Any, Dict, List, Optional
from src.assessment.models import AssessmentAuditRecord


class AssessmentAuditLogger:
    """In-memory and persistent audit logger for assessment telemetry."""

    def __init__(self, assessment_id: str) -> None:
        self.assessment_id = assessment_id
        self._events: List[AssessmentAuditRecord] = []

    def record_event(
        self,
        event_type: str,
        actor: str,
        component: str,
        authorization_state: str,
        scope_state: str,
        epistemic_state: str = "FACT",
        input_reference: Optional[str] = None,
        output_reference: Optional[str] = None,
        provenance: Optional[Dict[str, Any]] = None,
    ) -> AssessmentAuditRecord:
        """Records an auditable lifecycle event."""
        now_iso = datetime.now(timezone.utc).isoformat()
        seed = f"{self.assessment_id}:{event_type}:{now_iso}:{len(self._events)}"
        event_id = f"EVT-{hashlib.sha256(seed.encode('utf-8')).hexdigest()[:12].upper()}"

        record = AssessmentAuditRecord(
            event_id=event_id,
            assessment_id=self.assessment_id,
            timestamp=now_iso,
            actor=actor,
            component=component,
            event_type=event_type,
            input_reference=input_reference,
            output_reference=output_reference,
            authorization_state=authorization_state,
            scope_state=scope_state,
            epistemic_state=epistemic_state,
            provenance=provenance or {},
        )
        self._events.append(record)
        return record

    def get_events(self) -> List[AssessmentAuditRecord]:
        """Returns all recorded audit events."""
        return list(self._events)
