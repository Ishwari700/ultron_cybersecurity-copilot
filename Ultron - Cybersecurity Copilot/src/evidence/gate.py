"""EvidencePreservationGate: Pre-Router Evidence Integrity and Advisory Triage Gatekeeper.

Enforces evidence preservation, channel separation, taxonomy category validity,
and ungrounded ID quarantine. Produces GateValidationResult (Schema 5).
Does NOT accept, construct, or mutate DeterministicRoutingDecision.
"""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
import yaml

from src.core.logging import AuditLogger
from src.evidence.cascade_models import (
    CanonicalEvidenceIntegrityError,
    GateValidationResult,
    LosslessStructuralPack,
    RawTriageOutput,
    TriageMetadataPacket,
)


class EvidencePreservationGate:
    """
    Enforces evidence preservation, channel separation, category validity, and ungrounded ID quarantine.
    Holds exclusive downstream-facing authority over:
        1. Channel A structural preservation
        2. Channel B triage normalization
        3. Quarantine of hallucinated IDs
        4. Setting category_invalid on TriageMetadataPacket
        5. Setting fail_safe_required on GateValidationResult
        6. Dual-action side effects: audit emission AND gate_triggers recording
    """

    _cached_taxonomy: Optional[Set[str]] = None

    @classmethod
    def load_registered_categories(cls, path: str = "taxonomy/categories.yaml") -> Set[str]:
        """Load registered taxonomy category IDs from public taxonomy YAML."""
        if cls._cached_taxonomy is not None:
            return cls._cached_taxonomy

        p = Path(path)
        if not p.exists():
            # Fallback to default canonical categories if file path not found
            cats = {"API-BOLA-001", "API-BFLA-002", "STATE-MACHINE-001", "INFO-EXPOSURE-001"}
            cls._cached_taxonomy = cats
            return cats

        with open(p, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or []

        cats = set()
        for item in data:
            if isinstance(item, dict) and "id" in item:
                cats.add(item["id"])

        cls._cached_taxonomy = cats
        return cats

    @classmethod
    def validate(
        cls,
        channel_a: LosslessStructuralPack,
        raw_triage: Optional[RawTriageOutput],
        registered_categories: Optional[Set[str]] = None,
        audit_logger: Optional[AuditLogger] = None,
    ) -> GateValidationResult:
        """
        Validates advisory 3B output against canonical Channel A evidence, enforces taxonomy category validity,
        quarantines ungrounded IDs, and returns a GateValidationResult (Schema 5).

        FAILURE MODES:
            - Corrupt Canonical Evidence: If channel_a is None or missing required identifiers,
              raises CanonicalEvidenceIntegrityError -> halts pipeline before GateValidationResult can be constructed.
            - Missing 3B Output: If raw_triage is None, produces GateValidationResult with validated_triage = None,
              fail_safe_required = True, emits TRIAGE_OUTPUT_MALFORMED_OR_MISSING audit event, and appends to gate_triggers.
            - Malformed 3B Output: If raw_triage.is_malformed is True, sets fail_safe_required = True,
              emits TRIAGE_OUTPUT_MALFORMED_OR_MISSING audit event, and appends to gate_triggers.
            - Invalid Category: If non-null suspected_category not in registered taxonomy,
              sets category_invalid = True on TriageMetadataPacket, sets fail_safe_required = True,
              emits TRIAGE_CATEGORY_INVALID audit event, and appends to gate_triggers.
            - Ungrounded ID: If raw_triage cites IDs not in Channel A, sets fail_safe_required = True,
              emits TRIAGE_HALLUCINATION audit event, appends to gate_triggers, and strips citations from validated_triage.
        """
        # Step 1: Canonical Evidence Integrity Verification
        if channel_a is None or not getattr(channel_a, "endpoint_id", None) or not getattr(channel_a, "asset_id", None):
            raise CanonicalEvidenceIntegrityError(
                "Canonical evidence Channel A is missing, None, or lacks required endpoint/asset identifiers."
            )

        gate_triggers: List[str] = []
        audit_event_ids: List[str] = []
        fail_safe_required = False

        def emit_audit(event_type: str, details: Dict[str, Any]) -> None:
            if audit_logger is not None:
                record = audit_logger.log_event(
                    event_type=event_type,
                    actor="EvidencePreservationGate",
                    subject_id=channel_a.endpoint_id,
                    details=details,
                )
                audit_event_ids.append(record.get("payload_hash", f"{event_type}-{len(audit_event_ids)}"))
            else:
                audit_event_ids.append(f"{event_type}-{len(audit_event_ids)}")

        # Step 2: Missing 3B Triage Output
        if raw_triage is None:
            fail_safe_required = True
            emit_audit(
                "TRIAGE_OUTPUT_MALFORMED_OR_MISSING",
                {"reason": "3B triage runner returned None / empty output", "endpoint_id": channel_a.endpoint_id},
            )
            gate_triggers.append("TRIAGE_OUTPUT_MALFORMED_OR_MISSING")

            return GateValidationResult(
                schema_version="2.0.0",
                validated_triage=None,
                gate_triggers=gate_triggers,
                fail_safe_required=fail_safe_required,
                audit_event_ids=audit_event_ids,
            )

        # Step 3: Malformed 3B Triage Output Flag
        if raw_triage.is_malformed:
            fail_safe_required = True
            emit_audit(
                "TRIAGE_OUTPUT_MALFORMED_OR_MISSING",
                {"reason": "3B triage output flagged is_malformed by 3B runner parser", "endpoint_id": channel_a.endpoint_id},
            )
            gate_triggers.append("TRIAGE_OUTPUT_MALFORMED_OR_MISSING")

        # Step 4: Taxonomy Category Validation
        categories = registered_categories if registered_categories is not None else cls.load_registered_categories()
        category_invalid = False

        if raw_triage.suspected_category is not None:
            if raw_triage.suspected_category not in categories:
                category_invalid = True
                fail_safe_required = True
                emit_audit(
                    "TRIAGE_CATEGORY_INVALID",
                    {
                        "suspected_category": raw_triage.suspected_category,
                        "registered_categories": sorted(list(categories)),
                        "endpoint_id": channel_a.endpoint_id,
                    },
                )
                gate_triggers.append("TRIAGE_CATEGORY_INVALID")

        # Step 5: ID Grounding & Hallucination Check
        # Build canonical ID sets from Channel A
        canonical_param_ids: Set[str] = set()
        for p in channel_a.parameter_lineage:
            if isinstance(p, dict):
                if p.get("param_id"):
                    canonical_param_ids.add(str(p["param_id"]))
                if p.get("param_name"):
                    canonical_param_ids.add(str(p["param_name"]))

        canonical_fact_ids: Set[str] = set()
        for f in channel_a.observed_facts:
            if isinstance(f, dict) and f.get("fact_id"):
                canonical_fact_ids.add(str(f["fact_id"]))

        canonical_ident_ids: Set[str] = set()
        for ident in channel_a.identity_matrix:
            if isinstance(ident, dict) and ident.get("identity_id"):
                canonical_ident_ids.add(str(ident["identity_id"]))

        has_hallucination = False
        valid_cited_params: List[str] = []
        if raw_triage.cited_parameter_ids:
            for pid in raw_triage.cited_parameter_ids:
                if pid in canonical_param_ids:
                    valid_cited_params.append(pid)
                else:
                    has_hallucination = True

        valid_cited_facts: List[str] = []
        if raw_triage.cited_fact_ids:
            for fid in raw_triage.cited_fact_ids:
                if fid in canonical_fact_ids:
                    valid_cited_facts.append(fid)
                else:
                    has_hallucination = True

        if has_hallucination:
            fail_safe_required = True
            emit_audit(
                "TRIAGE_HALLUCINATION",
                {
                    "endpoint_id": channel_a.endpoint_id,
                    "cited_params": raw_triage.cited_parameter_ids,
                    "cited_facts": raw_triage.cited_fact_ids,
                    "canonical_params": sorted(list(canonical_param_ids)),
                    "canonical_facts": sorted(list(canonical_fact_ids)),
                },
            )
            gate_triggers.append("TRIAGE_HALLUCINATION")

        # Step 6: Construct Validated Triage Packet (Schema 2b)
        validated_triage = TriageMetadataPacket(
            schema_version="2.0.0",
            suspected_category=raw_triage.suspected_category,
            decision=raw_triage.decision,
            triage_rationale=raw_triage.triage_rationale,
            suggested_experiment_class=raw_triage.suggested_experiment_class,
            is_sensitive_category=raw_triage.is_sensitive_category,
            is_malformed=raw_triage.is_malformed,
            category_invalid=category_invalid,
            candidate_security_property=raw_triage.candidate_security_property,
            cited_parameter_ids=valid_cited_params if raw_triage.cited_parameter_ids is not None else None,
            cited_fact_ids=valid_cited_facts if raw_triage.cited_fact_ids is not None else None,
        )

        return GateValidationResult(
            schema_version="2.0.0",
            validated_triage=validated_triage,
            gate_triggers=gate_triggers,
            fail_safe_required=fail_safe_required,
            audit_event_ids=audit_event_ids,
        )
