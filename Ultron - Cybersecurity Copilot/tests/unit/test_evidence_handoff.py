"""Test Suite B: EvidencePreservationGate & Handoff Verification.

Verifies:
- Gate Contract & Schema 5: EvidencePreservationGate.validate produces GateValidationResult
  without accepting or mutating routing_decision.
- Dual-Action Side Effects: Every fail-safe condition emits an audit event AND appends to gate_triggers.
- Taxonomy Category Validation: Known valid category vs invalid category (TRIAGE_CATEGORY_INVALID).
- Ungrounded ID Handling (TRIAGE_HALLUCINATION): Quarantining ungrounded citations while preserving Channel A.
- Null Propagation Invariant: raw_triage is None -> validated_triage is None, fail_safe_required = True.
- Canonical Integrity Failure: Corrupt/None Channel A -> CanonicalEvidenceIntegrityError (HOLD/BLOCK).
"""

import pytest

from src.evidence.cascade_models import (
    CanonicalEvidenceIntegrityError,
    GateValidationResult,
    LosslessStructuralPack,
    RawTriageOutput,
    TriageMetadataPacket,
)
from src.evidence.gate import EvidencePreservationGate


@pytest.fixture
def clean_channel_a():
    return LosslessStructuralPack(
        schema_version="2.0.0",
        asset_id="ASSET-USERS-01",
        endpoint_id="EP-USERS-01",
        route_template="/api/v1/users/{id}",
        http_method="GET",
        application_mutability="READ_ONLY",
        parameter_lineage=[
            {"param_id": "PARAM-ID-1", "param_name": "id", "location": "path"}
        ],
        identity_matrix=[
            {"identity_id": "user_100", "role": "STANDARD_USER"}
        ],
        observed_facts=[
            {"fact_id": "FACT-REQ-1", "statement": "GET /api/v1/users/100 -> 200"}
        ],
    )


def test_gate_valid_raw_triage_passes_without_forced_fail_safe(clean_channel_a):
    raw_triage = RawTriageOutput(
        schema_version="2.0.0",
        suspected_category="API-BOLA-001",
        decision="BENIGN_NO_ISSUE",
        triage_rationale="Legitimate access observed",
        is_sensitive_category=True,
        is_malformed=False,
        cited_parameter_ids=["PARAM-ID-1"],
        cited_fact_ids=["FACT-REQ-1"],
    )

    res = EvidencePreservationGate.validate(clean_channel_a, raw_triage)
    assert isinstance(res, GateValidationResult)
    assert res.fail_safe_required is False
    assert res.gate_triggers == []
    assert res.validated_triage is not None
    assert res.validated_triage.category_invalid is False
    assert res.validated_triage.cited_parameter_ids == ["PARAM-ID-1"]
    assert res.validated_triage.cited_fact_ids == ["FACT-REQ-1"]


def test_gate_null_raw_triage_null_propagation_and_fail_safe(clean_channel_a):
    """Null propagation: 3B runner failed / timed out -> validated_triage=None."""
    res = EvidencePreservationGate.validate(clean_channel_a, raw_triage=None)

    assert isinstance(res, GateValidationResult)
    assert res.validated_triage is None
    assert res.fail_safe_required is True
    assert "TRIAGE_OUTPUT_MALFORMED_OR_MISSING" in res.gate_triggers
    # Dual action: audit event ID recorded
    assert len(res.audit_event_ids) >= 1


def test_gate_malformed_flag_triggers_fail_safe(clean_channel_a):
    raw_triage = RawTriageOutput(
        schema_version="2.0.0",
        decision="INSUFFICIENT_EVIDENCE",
        triage_rationale="Unparseable JSON from model",
        is_malformed=True,
    )

    res = EvidencePreservationGate.validate(clean_channel_a, raw_triage)
    assert res.fail_safe_required is True
    assert "TRIAGE_OUTPUT_MALFORMED_OR_MISSING" in res.gate_triggers
    assert res.validated_triage.is_malformed is True


def test_gate_invalid_category_validation(clean_channel_a):
    """Unregistered category triggers TRIAGE_CATEGORY_INVALID and sets category_invalid=True."""
    raw_triage = RawTriageOutput(
        schema_version="2.0.0",
        suspected_category="UNKNOWN-UNREGISTERED-CATEGORY",
        decision="SUSPECTED_VULNERABILITY",
        triage_rationale="Suspicious anomaly",
        is_malformed=False,
    )

    res = EvidencePreservationGate.validate(clean_channel_a, raw_triage)
    assert res.fail_safe_required is True
    assert "TRIAGE_CATEGORY_INVALID" in res.gate_triggers
    assert res.validated_triage.category_invalid is True
    assert len(res.audit_event_ids) >= 1


def test_gate_ungrounded_id_quarantine_and_channel_a_preservation(clean_channel_a):
    """Hallucinated parameter and fact IDs are stripped and trigger TRIAGE_HALLUCINATION."""
    raw_triage = RawTriageOutput(
        schema_version="2.0.0",
        suspected_category="API-BOLA-001",
        decision="SUSPECTED_VULNERABILITY",
        triage_rationale="Hallucinated IDs cited",
        cited_parameter_ids=["PARAM-ID-1", "PARAM-INVENTED-GHOST"],
        cited_fact_ids=["FACT-REQ-1", "FACT-INVENTED-GHOST"],
    )

    original_params = list(clean_channel_a.parameter_lineage)
    original_facts = list(clean_channel_a.observed_facts)

    res = EvidencePreservationGate.validate(clean_channel_a, raw_triage)

    # 1. Fail safe required and trigger recorded
    assert res.fail_safe_required is True
    assert "TRIAGE_HALLUCINATION" in res.gate_triggers
    assert len(res.audit_event_ids) >= 1

    # 2. Ghost IDs quarantined / stripped from validated triage
    assert res.validated_triage.cited_parameter_ids == ["PARAM-ID-1"]
    assert res.validated_triage.cited_fact_ids == ["FACT-REQ-1"]

    # 3. Channel A preserved completely unchanged
    assert clean_channel_a.parameter_lineage == original_params
    assert clean_channel_a.observed_facts == original_facts


def test_gate_corrupt_channel_a_raises_integrity_error():
    """Corrupt Channel A halts pipeline immediately before GateValidationResult construction."""
    with pytest.raises(CanonicalEvidenceIntegrityError):
        EvidencePreservationGate.validate(None, None)
