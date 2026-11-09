"""Test Suite for Phase 3: Lossless Structural Models & Canonical Provenance Hash.

Verifies:
- Frozen v2.0.0 schemas: LosslessStructuralPack, RawTriageOutput, TriageMetadataPacket,
  DeterministicRoutingDecision, CascadeHandoffPacket, GateValidationResult.
- Centralized canonical serialization and provenance hashing contract (Addendum E):
  1. Identical objects produce identical canonical bytes and digest.
  2. Dictionary key reordering does not change the digest.
  3. Semantic changes change the digest.
  4. Optional fields serialize deterministically, including validated_triage=None and audit_event_ids=[].
  5. The hash binds Channel A + GateValidationResult + final RoutingDecision.
  6. Semantic list insertion order is strictly preserved (not converted to unordered sets).
"""

import pytest

from src.evidence.cascade_models import (
    CascadeHandoffPacket,
    DeterministicRoutingDecision,
    GateValidationResult,
    LosslessStructuralPack,
    RawTriageOutput,
    TriageMetadataPacket,
)
from src.evidence.provenance import (
    canonical_json_serialize,
    compute_canonical_sha256,
    compute_provenance_hash,
)


@pytest.fixture
def sample_channel_a():
    return LosslessStructuralPack(
        schema_version="2.0.0",
        asset_id="ASSET-001",
        endpoint_id="EP-001",
        route_template="/api/v1/resource",
        http_method="POST",
        application_mutability="STATE_CHANGING",
        parameter_lineage=[{"param_name": "id", "location": "path"}],
        identity_matrix=[{"identity_id": "u1", "role": "USER"}],
        auth_header_delta=False,
        status_code_changed_under_different_role=True,
        has_privilege_level_delta=True,
        has_unauthenticated_success=False,
        has_cross_role_response_shape_delta=False,
        has_cross_identity_object_access_success=True,
        has_evidence_parse_asymmetry=False,
        has_unseen_endpoint_parameter=False,
        has_numeric_path_identifier=True,
        has_observed_contradictions=False,
        observed_facts=[{"fact_id": "FACT-001", "status": 200}],
    )


@pytest.fixture
def sample_gate_result():
    return GateValidationResult(
        schema_version="2.0.0",
        validated_triage=TriageMetadataPacket(
            schema_version="2.0.0",
            suspected_category="API-BOLA-001",
            decision="SUSPECTED_VULNERABILITY",
            triage_rationale="Observed unauthorized resource access",
            category_invalid=False,
            is_malformed=False,
        ),
        gate_triggers=["TRIAGE_CATEGORY_INVALID"],
        fail_safe_required=True,
        audit_event_ids=["AUDIT-001", "AUDIT-002"],
    )


@pytest.fixture
def sample_routing_decision():
    return DeterministicRoutingDecision(
        schema_version="2.0.0",
        escalate=True,
        has_high_risk_signal=True,
        high_risk_signals=["PRIVILEGE_LEVEL_DELTA_DETECTED", "CROSS_IDENTITY_OBJECT_ACCESS_SUCCESS"],
        deep_analysis_triggers=["TRIAGE_CATEGORY_INVALID"],
        reasons=["PRIVILEGE_LEVEL_DELTA_DETECTED", "CROSS_IDENTITY_OBJECT_ACCESS_SUCCESS", "TRIAGE_CATEGORY_INVALID"],
        fail_safe_triggered=True,
        evaluated_timestamp="2026-09-18T12:00:00Z",
    )


def test_schema_versions_are_v2_0_0(sample_channel_a, sample_gate_result, sample_routing_decision):
    assert sample_channel_a.schema_version == "2.0.0"
    assert sample_gate_result.schema_version == "2.0.0"
    assert sample_routing_decision.schema_version == "2.0.0"
    assert sample_gate_result.validated_triage.schema_version == "2.0.0"

    handoff = CascadeHandoffPacket(
        schema_version="2.0.0",
        channel_a_structural=sample_channel_a,
        routing_decision=sample_routing_decision,
        provenance_hash=compute_provenance_hash(sample_channel_a, sample_gate_result, sample_routing_decision),
        validated_triage=sample_gate_result.validated_triage,
    )
    assert handoff.schema_version == "2.0.0"


def test_identical_objects_produce_identical_canonical_bytes_and_digest(
    sample_channel_a, sample_gate_result, sample_routing_decision
):
    """Test 1: Repeated construction produces byte-identical serialization and identical digests."""
    b1 = canonical_json_serialize(sample_channel_a)
    b2 = canonical_json_serialize(sample_channel_a)
    assert b1 == b2

    h1 = compute_provenance_hash(sample_channel_a, sample_gate_result, sample_routing_decision)
    h2 = compute_provenance_hash(sample_channel_a, sample_gate_result, sample_routing_decision)
    assert h1 == h2
    assert len(h1) == 64


def test_dict_key_reordering_does_not_change_digest():
    """Test 2: Key reordering in dicts does not alter canonical serialization or digest."""
    dict_a = {"alpha": 1, "beta": 2, "gamma": {"z": 10, "a": 20}}
    dict_b = {"gamma": {"a": 20, "z": 10}, "beta": 2, "alpha": 1}

    bytes_a = canonical_json_serialize(dict_a)
    bytes_b = canonical_json_serialize(dict_b)

    assert bytes_a == bytes_b
    assert compute_canonical_sha256(dict_a) == compute_canonical_sha256(dict_b)


def test_semantic_changes_change_the_digest(sample_channel_a, sample_gate_result, sample_routing_decision):
    """Test 3: Changing a semantically relevant field changes the provenance hash."""
    base_hash = compute_provenance_hash(sample_channel_a, sample_gate_result, sample_routing_decision)

    # Change Channel A field
    modified_channel_a = sample_channel_a.model_copy(update={"route_template": "/api/v2/different"})
    hash_mod_a = compute_provenance_hash(modified_channel_a, sample_gate_result, sample_routing_decision)
    assert hash_mod_a != base_hash

    # Change Gate result field
    modified_gate = sample_gate_result.model_copy(update={"fail_safe_required": False})
    hash_mod_gate = compute_provenance_hash(sample_channel_a, modified_gate, sample_routing_decision)
    assert hash_mod_gate != base_hash

    # Change Routing decision field
    modified_routing = sample_routing_decision.model_copy(update={"escalate": False})
    hash_mod_routing = compute_provenance_hash(sample_channel_a, sample_gate_result, modified_routing)
    assert hash_mod_routing != base_hash


def test_optional_fields_serialize_deterministically(sample_channel_a, sample_routing_decision):
    """Test 4: Optional fields serialize deterministically, including validated_triage=None and audit_event_ids=[]."""
    gate_none = GateValidationResult(
        schema_version="2.0.0",
        validated_triage=None,
        gate_triggers=["TRIAGE_OUTPUT_MALFORMED_OR_MISSING"],
        fail_safe_required=True,
        audit_event_ids=[],
    )

    h1 = compute_provenance_hash(sample_channel_a, gate_none, sample_routing_decision)
    h2 = compute_provenance_hash(sample_channel_a, gate_none, sample_routing_decision)
    assert h1 == h2


def test_provenance_hash_binds_three_components(sample_channel_a, sample_gate_result, sample_routing_decision):
    """Test 5: Hash binds Channel A + GateValidationResult + final RoutingDecision."""
    p_hash = compute_provenance_hash(sample_channel_a, sample_gate_result, sample_routing_decision)

    # Verify that changing any one of the 3 components changes p_hash
    ch_a_diff = sample_channel_a.model_copy(update={"asset_id": "DIFFERENT-ASSET"})
    assert compute_provenance_hash(ch_a_diff, sample_gate_result, sample_routing_decision) != p_hash

    gate_diff = sample_gate_result.model_copy(update={"gate_triggers": []})
    assert compute_provenance_hash(sample_channel_a, gate_diff, sample_routing_decision) != p_hash

    route_diff = sample_routing_decision.model_copy(update={"reasons": []})
    assert compute_provenance_hash(sample_channel_a, sample_gate_result, route_diff) != p_hash


def test_semantic_list_insertion_order_is_preserved():
    """Test 6: List ordering matters semantically and is NOT converted to an unordered set."""
    gate_order_1 = GateValidationResult(
        schema_version="2.0.0",
        gate_triggers=["TRIGGER_A", "TRIGGER_B"],
        audit_event_ids=["EV_1", "EV_2"],
        fail_safe_required=True,
    )
    gate_order_2 = GateValidationResult(
        schema_version="2.0.0",
        gate_triggers=["TRIGGER_B", "TRIGGER_A"],  # Different order
        audit_event_ids=["EV_1", "EV_2"],
        fail_safe_required=True,
    )

    b1 = canonical_json_serialize(gate_order_1)
    b2 = canonical_json_serialize(gate_order_2)
    # Order must be preserved, so serializations and digests MUST differ
    assert b1 != b2
    assert compute_canonical_sha256(gate_order_1) != compute_canonical_sha256(gate_order_2)
