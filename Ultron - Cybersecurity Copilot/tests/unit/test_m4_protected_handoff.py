"""
Milestone M4.7 / Intervention I6 Unit Test Suite.

Verifies the protected 3B -> 7B invariant handoff serializer and runtime integration:
1. valid handoff serializes successfully
2. identical handoff -> byte-identical serialization
3. field order is deterministic
4. exact invariant preserved
5. exact EvidenceGapType preserved
6. Class-1 predicate values preserved exactly
7. unsupported EvidenceGapType fails closed
8. missing required handoff state fails closed
9. null/invalid handoff fails closed
10. unknown handoff field fails closed where schema requires strictness
11. mutation after serialization cannot alter canonical handoff
12. no free-form 3B reasoning trace included
13. no confidence/probability included
14. no ground-truth field included
15. no evaluation-label field included
16. no benchmark expected outcome included
17. no secret/token/credential fields included
18. no scope authority included
19. 7B receives only serialized handoff fields
20. I1 is not invoked (schema=None, no format constraint)
21. I2 is not invoked (no namespace partitioning)
22. I3 is not invoked (no counterfactual resolver)
23. I4 is not invoked (no BAIR prompt or extractor)
24. I5 is not invoked (no deterministic decision policy)
25. exactly one 7B LLM inference call
26. schema=None
27. primary runtime envelope unchanged
28. repeated execution with identical inputs produces identical handoff hash
29. changing one permitted handoff field changes the handoff deterministically
30. changing one prohibited/non-handoff field does not enter the serialized handoff
"""

import copy
import json
import pytest
from typing import Any, Dict

from src.evidence.cascade_models import (
    CascadeHandoffPacket,
    DeterministicRoutingDecision,
    LosslessStructuralPack,
    RawTriageOutput,
    TriageMetadataPacket,
)
from src.knowledge.models import EvidenceGapType
from src.engine.handoff_serializer import (
    CANONICAL_CLASS1_PREDICATE_KEYS,
    HandoffSerializer,
    HandoffValidationError,
    ProtectedHandoffDescriptor,
)
from src.engine.context_builder import (
    ReasoningContextBuilder,
    TRACK_D,
)
from src.engine.runner import (
    PRIMARY_KEEP_ALIVE,
    PRIMARY_NUM_CTX,
    PRIMARY_NUM_PREDICT,
    PRIMARY_SEED,
    PRIMARY_TEMPERATURE,
    ReasoningRunner,
)
from src.engine.models import (
    HypothesisModelOutput,
    I6ExecutionResult,
    PrimaryFailureCategory,
)


def make_sample_structural_pack(**kwargs) -> LosslessStructuralPack:
    base_kwargs = {
        "asset_id": "AST-AUTH-01",
        "endpoint_id": "EP-USERS-01",
        "route_template": "/api/v1/users/{id}",
        "http_method": "GET",
        "application_mutability": "READ_ONLY",
        "auth_header_delta": True,
        "has_cross_identity_object_access_success": True,
        "has_cross_role_response_shape_delta": False,
        "has_evidence_parse_asymmetry": False,
        "has_numeric_path_identifier": True,
        "has_observed_contradictions": False,
        "has_privilege_level_delta": False,
        "has_unauthenticated_success": False,
        "has_unseen_endpoint_parameter": False,
        "status_code_changed_under_different_role": True,
        "observed_facts": [
            {
                "fact_id": "FACT-001",
                "statement": "Endpoint /api/v1/users/{id} returned 200 under cross-tenant auth token",
                "trust": "UNTRUSTED",
            }
        ],
    }
    base_kwargs.update(kwargs)
    return LosslessStructuralPack(**base_kwargs)


def make_sample_cascade_packet(
    pack: LosslessStructuralPack,
    suspected_category: str = "API-BOLA-001",
    triage_rationale: str = "Potential BOLA observed on object ID",
    candidate_security_property: str = "Cross-tenant object access without ownership validation is disallowed",
) -> CascadeHandoffPacket:
    triage = TriageMetadataPacket(
        suspected_category=suspected_category,
        decision="SUSPECTED_VULNERABILITY",
        triage_rationale=triage_rationale,
        suggested_experiment_class="ID_SWAP",
        is_sensitive_category=True,
        candidate_security_property=candidate_security_property,
    )
    routing = DeterministicRoutingDecision(
        escalate=True,
        has_high_risk_signal=True,
        fail_safe_triggered=False,
    )
    return CascadeHandoffPacket(
        channel_a_structural=pack,
        routing_decision=routing,
        provenance_hash="sample_hash_" + "0" * 52,
        validated_triage=triage,
    )


# ---------------------------------------------------------------------------
# Test Cases (Requirements 1 - 30)
# ---------------------------------------------------------------------------

def test_01_valid_handoff_serializes_successfully():
    """Requirement 1: Valid handoff serializes successfully."""
    pack = make_sample_structural_pack()
    descriptor = HandoffSerializer.serialize(
        invariant="Cross-tenant object access is disallowed",
        evidence_gap_type=EvidenceGapType.MISSING_CROSS_IDENTITY_OBJECT_VERIFICATION,
        class1_predicates=pack,
    )
    assert isinstance(descriptor, ProtectedHandoffDescriptor)
    assert descriptor.schema_version == "2.0.0"
    assert descriptor.invariant == "Cross-tenant object access is disallowed"
    assert descriptor.evidence_gap_type == EvidenceGapType.MISSING_CROSS_IDENTITY_OBJECT_VERIFICATION
    assert len(descriptor.handoff_hash) == 64
    assert "=== PROTECTED 3B -> 7B INVARIANT HANDOFF (PARTITION P3) ===" in descriptor.serialized_handoff


def test_02_identical_handoff_byte_identical_serialization():
    """Requirement 2: Identical handoff produces byte-identical serialized output."""
    pack = make_sample_structural_pack()
    d1 = HandoffSerializer.serialize(
        invariant="Tenant isolation must be maintained across requests",
        evidence_gap_type=EvidenceGapType.MISSING_TENANT_ISOLATION_CHECK,
        class1_predicates=pack,
    )
    d2 = HandoffSerializer.serialize(
        invariant="Tenant isolation must be maintained across requests",
        evidence_gap_type=EvidenceGapType.MISSING_TENANT_ISOLATION_CHECK,
        class1_predicates=pack,
    )
    assert d1.serialized_handoff == d2.serialized_handoff
    assert d1.handoff_hash == d2.handoff_hash
    assert d1 == d2


def test_03_field_order_is_deterministic():
    """Requirement 3: Field order in serialized output is strictly deterministic and canonical."""
    pack = make_sample_structural_pack()
    d = HandoffSerializer.serialize(
        invariant="Role hierarchy enforcement required",
        evidence_gap_type=EvidenceGapType.MISSING_ROLE_HIERARCHY_ENFORCEMENT,
        class1_predicates=pack,
    )
    lines = [line.strip() for line in d.serialized_handoff.splitlines() if line.strip().startswith("auth_") or line.strip().startswith("has_") or line.strip().startswith("status_")]
    keys_in_output = [l.split(":")[0].strip() for l in lines]
    assert keys_in_output == sorted(CANONICAL_CLASS1_PREDICATE_KEYS)


def test_04_exact_invariant_preserved():
    """Requirement 4: Exact invariant string is preserved byte-identically."""
    pack = make_sample_structural_pack()
    test_inv = "Users of role USER cannot invoke admin-only endpoints without explicit privilege escalation"
    d = HandoffSerializer.serialize(
        invariant=test_inv,
        evidence_gap_type=EvidenceGapType.MISSING_ROLE_HIERARCHY_ENFORCEMENT,
        class1_predicates=pack,
    )
    assert d.invariant == test_inv
    assert f"SECURITY_INVARIANT: {test_inv}" in d.serialized_handoff


def test_05_exact_evidence_gap_type_preserved():
    """Requirement 5: Exact EvidenceGapType is preserved."""
    pack = make_sample_structural_pack()
    for gap in EvidenceGapType:
        d = HandoffSerializer.serialize(
            invariant="Standard invariant",
            evidence_gap_type=gap,
            class1_predicates=pack,
        )
        assert d.evidence_gap_type == gap
        assert f"EVIDENCE_GAP_TYPE: {gap.value}" in d.serialized_handoff


def test_06_class1_predicate_values_preserved_exactly():
    """Requirement 6: Class-1 predicate values preserved exactly."""
    pack = make_sample_structural_pack(
        has_cross_identity_object_access_success=True,
        has_privilege_level_delta=False,
        auth_header_delta=True,
    )
    d = HandoffSerializer.serialize(
        invariant="Invariant check",
        evidence_gap_type=EvidenceGapType.MISSING_CROSS_IDENTITY_OBJECT_VERIFICATION,
        class1_predicates=pack,
    )
    assert d.class1_predicates["has_cross_identity_object_access_success"] is True
    assert d.class1_predicates["has_privilege_level_delta"] is False
    assert d.class1_predicates["auth_header_delta"] is True
    assert "has_cross_identity_object_access_success: True" in d.serialized_handoff
    assert "has_privilege_level_delta: False" in d.serialized_handoff


def test_07_unsupported_evidence_gap_type_fails_closed():
    """Requirement 7: Unsupported EvidenceGapType fails closed."""
    pack = make_sample_structural_pack()
    with pytest.raises(HandoffValidationError):
        HandoffSerializer.serialize(
            invariant="Invariant test",
            evidence_gap_type="ARBITRARY_NATURAL_LANGUAGE_GAP",
            class1_predicates=pack,
        )


def test_08_missing_required_handoff_state_fails_closed():
    """Requirement 8: Missing required handoff state fails closed."""
    pack = make_sample_structural_pack()
    with pytest.raises(HandoffValidationError):
        HandoffSerializer.serialize(
            invariant="",  # Empty invariant
            evidence_gap_type=EvidenceGapType.MISSING_CROSS_IDENTITY_OBJECT_VERIFICATION,
            class1_predicates=pack,
        )

    with pytest.raises(HandoffValidationError):
        HandoffSerializer.serialize(
            invariant="   ",  # Whitespace invariant
            evidence_gap_type=EvidenceGapType.MISSING_CROSS_IDENTITY_OBJECT_VERIFICATION,
            class1_predicates=pack,
        )

    with pytest.raises(HandoffValidationError):
        HandoffSerializer.serialize(
            invariant="TODO",  # Placeholder invariant
            evidence_gap_type=EvidenceGapType.MISSING_CROSS_IDENTITY_OBJECT_VERIFICATION,
            class1_predicates=pack,
        )


def test_09_null_invalid_handoff_fails_closed():
    """Requirement 9: Null / invalid handoff fails closed."""
    with pytest.raises(HandoffValidationError):
        HandoffSerializer.serialize(
            invariant="Valid invariant",
            evidence_gap_type=EvidenceGapType.MISSING_MUTATION_STATE_BOUNDARY,
            class1_predicates=None,  # Null predicates
        )

    with pytest.raises(HandoffValidationError):
        HandoffSerializer.from_cascade_packet(
            handoff_packet=None,
            evidence_gap_type=EvidenceGapType.MISSING_MUTATION_STATE_BOUNDARY,
        )


def test_10_unknown_handoff_field_fails_closed_where_strict():
    """Requirement 10: Unknown handoff field fails closed where schema requires strictness."""
    predicates_with_extra = {
        "auth_header_delta": True,
        "has_cross_identity_object_access_success": False,
        "arbitrary_unsupported_key": True,
    }
    with pytest.raises(HandoffValidationError):
        HandoffSerializer.serialize(
            invariant="Valid invariant",
            evidence_gap_type=EvidenceGapType.MISSING_MUTATION_STATE_BOUNDARY,
            class1_predicates=predicates_with_extra,
        )


def test_11_mutation_after_serialization_cannot_alter_canonical_handoff():
    """Requirement 11: Mutation after serialization cannot alter canonical handoff."""
    pack = make_sample_structural_pack()
    d = HandoffSerializer.serialize(
        invariant="Immutable invariant",
        evidence_gap_type=EvidenceGapType.MISSING_UNAUTHENTICATED_ACCESS_CHECK,
        class1_predicates=pack,
    )
    # 1. Attribute assignment raises AttributeError
    with pytest.raises(AttributeError):
        d.invariant = "Modified invariant"

    with pytest.raises(AttributeError):
        d.evidence_gap_type = EvidenceGapType.MISSING_TENANT_ISOLATION_CHECK

    # 2. In-place dictionary mutation on class1_predicates raises TypeError
    with pytest.raises(TypeError):
        d.class1_predicates["has_unauthenticated_success"] = True


def test_12_no_free_form_3b_reasoning_trace_included():
    """Requirement 12: No free-form 3B reasoning trace included in serialized handoff."""
    pack = make_sample_structural_pack()
    raw_triage = RawTriageOutput(
        suspected_category="API-BOLA-001",
        decision="SUSPECTED_VULNERABILITY",
        triage_rationale="SUBJECTIVE_3B_FREE_FORM_RATIONALE_TRACE_SHOULD_NEVER_ENTER_7B_PROMPT",
        suggested_experiment_class="ID_SWAP",
        candidate_security_property="Target must enforce authorization",
    )
    d = HandoffSerializer.from_3b_triage(
        raw_triage=raw_triage,
        channel_a=pack,
        evidence_gap_type=EvidenceGapType.MISSING_CROSS_IDENTITY_OBJECT_VERIFICATION,
    )
    assert "SUBJECTIVE_3B_FREE_FORM_RATIONALE_TRACE" not in d.serialized_handoff
    assert "triage_rationale" not in d.serialized_handoff


def test_13_no_confidence_or_probability_included():
    """Requirement 13: No confidence or probability scoring included."""
    pack = make_sample_structural_pack()
    raw_dict = {
        "candidate_security_property": "Valid invariant",
        "confidence": 0.95,
        "probability": 0.88,
        "score": 9.8,
    }
    with pytest.raises(HandoffValidationError):
        HandoffSerializer.from_3b_triage(
            raw_triage=raw_dict,
            channel_a=pack,
            evidence_gap_type=EvidenceGapType.MISSING_CROSS_IDENTITY_OBJECT_VERIFICATION,
        )


def test_14_no_ground_truth_field_included():
    """Requirement 14: No ground-truth field included."""
    pack = make_sample_structural_pack()
    raw_dict = {
        "candidate_security_property": "Valid invariant",
        "is_vulnerable": True,
        "ground_truth": "API-BOLA-001",
        "oracle_verdict": "VULNERABLE",
    }
    with pytest.raises(HandoffValidationError):
        HandoffSerializer.from_3b_triage(
            raw_triage=raw_dict,
            channel_a=pack,
            evidence_gap_type=EvidenceGapType.MISSING_CROSS_IDENTITY_OBJECT_VERIFICATION,
        )


def test_15_no_evaluation_label_field_included():
    """Requirement 15: No evaluation-label field included."""
    pack = make_sample_structural_pack()
    raw_dict = {
        "candidate_security_property": "Valid invariant",
        "evaluation_track": "TRACK_D",
        "tp_label": True,
        "eval_label": "BENCHMARK_TEST",
    }
    with pytest.raises(HandoffValidationError):
        HandoffSerializer.from_3b_triage(
            raw_triage=raw_dict,
            channel_a=pack,
            evidence_gap_type=EvidenceGapType.MISSING_CROSS_IDENTITY_OBJECT_VERIFICATION,
        )


def test_16_no_benchmark_expected_outcome_included():
    """Requirement 16: No benchmark expected outcome included."""
    pack = make_sample_structural_pack()
    raw_dict = {
        "candidate_security_property": "Valid invariant",
        "expected_outcome": "HYPOTHESIS",
        "expected_decision": "HYPOTHESIS",
    }
    with pytest.raises(HandoffValidationError):
        HandoffSerializer.from_3b_triage(
            raw_triage=raw_dict,
            channel_a=pack,
            evidence_gap_type=EvidenceGapType.MISSING_CROSS_IDENTITY_OBJECT_VERIFICATION,
        )


def test_17_no_secret_token_credential_fields_included():
    """Requirement 17: No secret, token, or credential fields included."""
    pack = make_sample_structural_pack()
    raw_dict = {
        "candidate_security_property": "Valid invariant",
        "authorization": "Bearer eyJhbGciOi...",
        "cookie": "session_id=secret123",
        "api_key": "AKIAIOSFODNN7EXAMPLE",
        "csrf_token": "token_xyz",
    }
    with pytest.raises(HandoffValidationError):
        HandoffSerializer.from_3b_triage(
            raw_triage=raw_dict,
            channel_a=pack,
            evidence_gap_type=EvidenceGapType.MISSING_CROSS_IDENTITY_OBJECT_VERIFICATION,
        )


def test_18_no_scope_authority_included():
    """Requirement 18: No scope authority included in serialized handoff."""
    pack = make_sample_structural_pack()
    d = HandoffSerializer.serialize(
        invariant="Standard scope invariant",
        evidence_gap_type=EvidenceGapType.MISSING_UNAUTHENTICATED_ACCESS_CHECK,
        class1_predicates=pack,
    )
    assert "[ADVISORY ONLY: NOT SCOPE AUTHORITY, NOT CONFIRMATION AUTHORITY, NOT EXECUTION AUTHORITY]" in d.serialized_handoff
    assert "scope_authority" not in d.serialized_handoff
    assert "scope_override" not in d.serialized_handoff


def test_19_7b_receives_only_serialized_handoff_fields():
    """Requirement 19: 7B prompt receives only serialized handoff fields in Partition P3."""
    pack = make_sample_structural_pack()
    cascade = make_sample_cascade_packet(pack=pack, triage_rationale="HIDDEN_PROSE_3B")
    descriptor = HandoffSerializer.from_cascade_packet(
        handoff_packet=cascade,
        evidence_gap_type=EvidenceGapType.MISSING_CROSS_IDENTITY_OBJECT_VERIFICATION,
    )
    ctx = ReasoningContextBuilder.build_context(
        handoff_packet=cascade,
        model_identifier="qwen2.5-coder:7b",
        cascade_mode=TRACK_D,
        enable_i6_handoff=True,
        protected_handoff=descriptor,
    )
    assert ctx.provenance_metadata.get("i6_handoff_enabled") is True
    assert ctx.provenance_metadata.get("i6_handoff_hash") == descriptor.handoff_hash
    # P3 contains protected handoff and excludes 3B free-text rationale
    assert descriptor.serialized_handoff in ctx.prompt
    assert "HIDDEN_PROSE_3B" not in ctx.prompt
    assert "CHANNEL B: ADVISORY 3B TRIAGE METADATA" not in ctx.prompt


def test_20_i1_is_not_invoked():
    """Requirement 20: I1 schema-constrained generation is not invoked; schema is strictly None."""
    pack = make_sample_structural_pack()
    descriptor = HandoffSerializer.serialize(
        invariant="Invariant check",
        evidence_gap_type=EvidenceGapType.MISSING_MUTATION_STATE_BOUNDARY,
        class1_predicates=pack,
    )
    runner = ReasoningRunner(
        config=None,
        llm_caller=lambda prompt, schema: (
            assert_no_schema(schema),
            json.dumps({
                "invariant": "Tested invariant",
                "evidence_gap": "Missing verification",
                "affected_target": "AST-01",
                "decision": "INSUFFICIENT_EVIDENCE",
                "supporting_evidence_ids": [],
                "methodology_references": [],
                "experiment_proposal": "Perform test request",
            })
        )[1]
    )

    def assert_no_schema(s):
        assert s is None

    result = runner.execute_i6_generation(
        prompt="Test I6 prompt",
        protected_handoff=descriptor,
    )
    assert result.classification.is_valid is True
    assert result.fail_closed is False


def test_21_i2_is_not_invoked():
    """Requirement 21: I2 namespace partitioning prompt is not invoked."""
    pack = make_sample_structural_pack()
    cascade = make_sample_cascade_packet(pack=pack)
    descriptor = HandoffSerializer.from_cascade_packet(
        handoff_packet=cascade,
        evidence_gap_type=EvidenceGapType.MISSING_CROSS_IDENTITY_OBJECT_VERIFICATION,
    )
    ctx = ReasoningContextBuilder.build_context(
        handoff_packet=cascade,
        model_identifier="qwen2.5-coder:7b",
        cascade_mode=TRACK_D,
        enable_i6_handoff=True,
        protected_handoff=descriptor,
    )
    assert ctx.provenance_metadata.get("i2_namespace_enabled") is None
    assert "empirical_fact_ids" not in ctx.system_prompt
    assert "methodology_chunk_ids" not in ctx.system_prompt


def test_22_i3_is_not_invoked():
    """Requirement 22: I3 counterfactual prompt templates are not invoked."""
    pack = make_sample_structural_pack()
    cascade = make_sample_cascade_packet(pack=pack)
    descriptor = HandoffSerializer.from_cascade_packet(
        handoff_packet=cascade,
        evidence_gap_type=EvidenceGapType.MISSING_CROSS_IDENTITY_OBJECT_VERIFICATION,
    )
    ctx = ReasoningContextBuilder.build_context(
        handoff_packet=cascade,
        model_identifier="qwen2.5-coder:7b",
        cascade_mode=TRACK_D,
        enable_i6_handoff=True,
        protected_handoff=descriptor,
    )
    assert ctx.provenance_metadata.get("i3_counterfactual_enabled") is None
    assert "COUNTERFACTUAL REASONING INSTRUCTIONS" not in ctx.prompt


def test_23_i4_is_not_invoked():
    """Requirement 23: I4 BAIR representation / extractor is not invoked."""
    pack = make_sample_structural_pack()
    cascade = make_sample_cascade_packet(pack=pack)
    descriptor = HandoffSerializer.from_cascade_packet(
        handoff_packet=cascade,
        evidence_gap_type=EvidenceGapType.MISSING_CROSS_IDENTITY_OBJECT_VERIFICATION,
    )
    ctx = ReasoningContextBuilder.build_context(
        handoff_packet=cascade,
        model_identifier="qwen2.5-coder:7b",
        cascade_mode=TRACK_D,
        enable_i6_handoff=True,
        protected_handoff=descriptor,
    )
    assert ctx.provenance_metadata.get("i4_bair_enabled") is None
    assert "<bair>" not in ctx.system_prompt


def test_24_i5_is_not_invoked():
    """Requirement 24: I5 deterministic decision policy is not invoked."""
    pack = make_sample_structural_pack()
    cascade = make_sample_cascade_packet(pack=pack)
    descriptor = HandoffSerializer.from_cascade_packet(
        handoff_packet=cascade,
        evidence_gap_type=EvidenceGapType.MISSING_CROSS_IDENTITY_OBJECT_VERIFICATION,
    )
    ctx = ReasoningContextBuilder.build_context(
        handoff_packet=cascade,
        model_identifier="qwen2.5-coder:7b",
        cascade_mode=TRACK_D,
        enable_i6_handoff=True,
        protected_handoff=descriptor,
    )
    assert ctx.provenance_metadata.get("i5_decision_policy_enabled") is None
    assert "CALIBRATED ABSTENTION CONTRACT" not in ctx.system_prompt


def test_25_exactly_one_7b_llm_inference_call():
    """Requirement 25: Exactly one 7B LLM inference call executed."""
    call_count = 0

    def mock_caller(prompt, schema):
        nonlocal call_count
        call_count += 1
        return json.dumps({
            "invariant": "Test invariant",
            "evidence_gap": "Test gap",
            "affected_target": "AST-01",
            "decision": "NO_RELEVANT_FUNCTIONALITY",
            "supporting_evidence_ids": [],
            "methodology_references": [],
            "experiment_proposal": "Verify absence of mutation",
        })

    runner = ReasoningRunner(config=None, llm_caller=mock_caller)
    pack = make_sample_structural_pack()
    descriptor = HandoffSerializer.serialize(
        invariant="Test invariant",
        evidence_gap_type=EvidenceGapType.MISSING_MUTATION_STATE_BOUNDARY,
        class1_predicates=pack,
    )
    result = runner.execute_i6_generation(
        prompt="Test single call",
        protected_handoff=descriptor,
    )
    assert call_count == 1
    assert result.classification.is_valid is True


def test_26_schema_is_strictly_none():
    """Requirement 26: Schema passed to Ollama/caller is strictly None."""
    received_schema = "INITIAL"

    def mock_caller(prompt, schema):
        nonlocal received_schema
        received_schema = schema
        return json.dumps({
            "invariant": "Test invariant",
            "evidence_gap": "Test gap",
            "affected_target": "AST-01",
            "decision": "NO_RELEVANT_FUNCTIONALITY",
            "supporting_evidence_ids": [],
            "methodology_references": [],
            "experiment_proposal": "Verify parameters",
        })

    runner = ReasoningRunner(config=None, llm_caller=mock_caller)
    pack = make_sample_structural_pack()
    descriptor = HandoffSerializer.serialize(
        invariant="Test invariant",
        evidence_gap_type=EvidenceGapType.MISSING_INPUT_TYPE_TAMPER_CONTROL,
        class1_predicates=pack,
    )
    runner.execute_i6_generation(prompt="Prompt", protected_handoff=descriptor)
    assert received_schema is None


def test_27_primary_runtime_envelope_unchanged():
    """Requirement 27: Primary runtime envelope constants remain unchanged."""
    assert PRIMARY_NUM_CTX == 2048
    assert PRIMARY_NUM_PREDICT == 300
    assert PRIMARY_TEMPERATURE == 0.0
    assert PRIMARY_SEED == 42
    assert PRIMARY_KEEP_ALIVE == "60m"


def test_28_repeated_execution_with_identical_inputs_produces_identical_hash():
    """Requirement 28: Repeated serialization with identical inputs produces identical handoff hash."""
    pack = make_sample_structural_pack()
    hashes = set()
    for _ in range(50):
        d = HandoffSerializer.serialize(
            invariant="Identical invariant repetition check",
            evidence_gap_type=EvidenceGapType.MISSING_ROLE_HIERARCHY_ENFORCEMENT,
            class1_predicates=pack,
        )
        hashes.add(d.handoff_hash)
    assert len(hashes) == 1


def test_29_changing_one_permitted_handoff_field_changes_hash_deterministically():
    """Requirement 29: Changing one permitted handoff field changes the hash deterministically."""
    pack1 = make_sample_structural_pack(has_privilege_level_delta=False)
    pack2 = make_sample_structural_pack(has_privilege_level_delta=True)

    d1 = HandoffSerializer.serialize(
        invariant="Base invariant",
        evidence_gap_type=EvidenceGapType.MISSING_ROLE_HIERARCHY_ENFORCEMENT,
        class1_predicates=pack1,
    )
    d2 = HandoffSerializer.serialize(
        invariant="Base invariant",
        evidence_gap_type=EvidenceGapType.MISSING_ROLE_HIERARCHY_ENFORCEMENT,
        class1_predicates=pack2,
    )
    assert d1.handoff_hash != d2.handoff_hash
    assert d1.serialized_handoff != d2.serialized_handoff


def test_30_changing_one_prohibited_non_handoff_field_does_not_enter_serialized_handoff():
    """Requirement 30: Changing one prohibited / non-handoff field does not enter the serialized handoff."""
    pack = make_sample_structural_pack()
    triage1 = RawTriageOutput(
        suspected_category="API-BOLA-001",
        decision="BENIGN_NO_ISSUE",
        triage_rationale="Rationale variant 1",
        candidate_security_property="Common invariant",
    )
    triage2 = RawTriageOutput(
        suspected_category="API-MASS-001",
        decision="SUSPECTED_VULNERABILITY",
        triage_rationale="Rationale variant 2 with completely different text",
        candidate_security_property="Common invariant",
    )
    d1 = HandoffSerializer.from_3b_triage(
        raw_triage=triage1,
        channel_a=pack,
        evidence_gap_type=EvidenceGapType.MISSING_CROSS_IDENTITY_OBJECT_VERIFICATION,
    )
    d2 = HandoffSerializer.from_3b_triage(
        raw_triage=triage2,
        channel_a=pack,
        evidence_gap_type=EvidenceGapType.MISSING_CROSS_IDENTITY_OBJECT_VERIFICATION,
    )
    assert d1.serialized_handoff == d2.serialized_handoff
    assert d1.handoff_hash == d2.handoff_hash
    assert "Rationale variant 1" not in d1.serialized_handoff
    assert "Rationale variant 2" not in d2.serialized_handoff
    assert "API-BOLA-001" not in d1.serialized_handoff
    assert "API-MASS-001" not in d2.serialized_handoff
