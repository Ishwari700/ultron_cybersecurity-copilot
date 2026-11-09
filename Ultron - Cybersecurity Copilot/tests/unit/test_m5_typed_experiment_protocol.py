"""
Milestone M5 Phase 6.6 — Typed Experiment-Outcome Protocol Verification Suite.

Validates the Phase 6.6 deterministic experiment protocol implementation:
- Deterministic 4-tuple compatibility: (category, action, supporting, disproving)
- Closed action and outcome taxonomies
- Strict fail-closed semantics for invalid, unknown, mismatched, or identical outcomes
- Absolute rejection of legacy free-text falsification plans
- Governance of typed fields over natural language descriptions
- Six-layer architectural agreement: Prompt == Schema == Extractor == Parser == Validator == Adapter
- Dual-track decoding agreement: I1=0 (schema=None) vs I1=1 (schema=BairJsonObject.get_inference_schema())
- Token budget verification for the frozen primary envelope (qwen2.5-coder:7b, num_predict=300)
"""

import json
import pytest
from pydantic import ValidationError
from typing import Dict, Any, List

from src.engine.models import (
    BairJsonObject,
    HypothesisDecision,
    HypothesisModelOutput,
    ExperimentActionPredicate,
    SemanticOutcomePredicate,
    HttpOutcomePredicate,
    VALID_ACTION_PREDICATES,
    VALID_OUTCOME_PREDICATES,
    OutputProtocolIdentifier,
)
from src.engine.protocol import (
    JSON_BAIR_PROMPT_INSTRUCTION,
    get_protocol_contract,
)
from src.engine.bair_extractor import (
    parse_bair_json,
    map_bair_json_to_s0,
)
from src.engine.decision_policy import (
    ExperimentPolarityValidator,
    deterministic_decide,
    EvidenceState,
    DecisionPredicate,
)
from src.evidence.cascade_models import LosslessStructuralPack


def _create_base_pack(category_id: str = "API-BOLA-001") -> LosslessStructuralPack:
    """Helper to create a valid baseline LosslessStructuralPack for testing."""
    is_state = "STATE" in category_id or "MUTATION" in category_id or "LIFECYCLE" in category_id
    return LosslessStructuralPack(
        schema_version="2.0.0",
        asset_id="ASSET-TEST-01",
        endpoint_id="EP-TEST-01",
        route_template="/api/v1/resource/{id}",
        http_method="POST" if is_state else "GET",
        application_mutability="STATE_CHANGING" if is_state else "READ_ONLY",
        parameter_lineage=[{"location": "path", "param_name": "id", "param_type": "string"}],
        identity_matrix=[{"identity_id": "user_a", "role": "customer"}],
        has_privilege_level_delta=False,
        has_cross_identity_object_access_success=False,
        has_observed_contradictions=False,
        observed_facts=[
            {
                "fact_id": "FACT-TEST-01",
                "certainty": "DOCUMENTED",
                "statement": "Endpoint accesses resource.",
                "source_tool": "openapi",
            }
        ],
        raw_body_sample="",
    )


def _create_evidence_state(category_id: str = "API-BOLA-001", empirical: bool = True) -> EvidenceState:
    """Helper to create a deterministic EvidenceState for testing."""
    is_state = "STATE" in category_id or "MUTATION" in category_id or "LIFECYCLE" in category_id
    return EvidenceState(
        channel_a=_create_base_pack(category_id),
        target_asset={
            "application_mutability": "STATE_CHANGING" if is_state else "READ_ONLY",
            "parameters": [{"param_name": "id"}],
        },
        category_id=category_id,
        empirical_evidence_present=empirical,
    )


# ===========================================================================
# Section 9 Required Deterministic Tests: Tests A through P
# ===========================================================================

def test_a_valid_bola_semantic_predicates():
    """
    Test A: Valid BOLA with semantic predicates
    SUBSTITUTE_RESOURCE_IDENTIFIER
    supporting = CROSS_IDENTITY_OBJECT_ACCESSIBLE
    disproving = CROSS_IDENTITY_OBJECT_DENIED
    => ACCEPT
    """
    # 1. Compatibility Registry
    is_valid, reason = ExperimentPolarityValidator.validate_tuple(
        category_id="API-BOLA-001",
        experiment_action=ExperimentActionPredicate.SUBSTITUTE_RESOURCE_IDENTIFIER.value,
        supporting_outcome=SemanticOutcomePredicate.CROSS_IDENTITY_OBJECT_ACCESSIBLE.value,
        disproving_outcome=SemanticOutcomePredicate.CROSS_IDENTITY_OBJECT_DENIED.value,
    )
    assert is_valid is True
    assert reason is None

    # 2. BairJsonObject Validation
    bair = BairJsonObject(
        invariant="Object access restricted to authorized tenant",
        evidence_gap="Tenant ID not checked on resource",
        affected_target="/api/v1/orders/{id}",
        decision=HypothesisDecision.HYPOTHESIS,
        empirical_facts=["FACT-TEST-01"],
        methodology_references=[],
        experiment_action="SUBSTITUTE_RESOURCE_IDENTIFIER",
        supporting_outcome="CROSS_IDENTITY_OBJECT_ACCESSIBLE",
        disproving_outcome="CROSS_IDENTITY_OBJECT_DENIED",
        falsification_description="Swap order ID with peer tenant",
    )
    assert bair.decision == HypothesisDecision.HYPOTHESIS

    # 3. Deterministic Decision Policy
    cand = map_bair_json_to_s0(bair, target_asset={"application_mutability": "READ_ONLY", "parameters": [{"param_name": "id"}]}, category_id="API-BOLA-001")
    ev_state = _create_evidence_state("API-BOLA-001")
    result = deterministic_decide(candidate=cand, evidence_state=ev_state)
    assert result.is_valid is True
    assert result.final_decision == HypothesisDecision.HYPOTHESIS
    assert result.predicate_identifier == DecisionPredicate.HYPOTHESIS_GROUNDED


def test_b_valid_bola_http_predicates():
    """
    Test B: Valid BOLA with HTTP predicates
    supporting = HTTP_200_OK
    disproving = HTTP_403_FORBIDDEN
    => ACCEPT
    """
    is_valid, reason = ExperimentPolarityValidator.validate_tuple(
        category_id="API-BOLA-001",
        experiment_action=ExperimentActionPredicate.SUBSTITUTE_RESOURCE_IDENTIFIER.value,
        supporting_outcome=HttpOutcomePredicate.HTTP_200_OK.value,
        disproving_outcome=HttpOutcomePredicate.HTTP_403_FORBIDDEN.value,
    )
    assert is_valid is True
    assert reason is None

    bair = BairJsonObject(
        invariant="Object access restricted to owner",
        evidence_gap="Missing owner check",
        affected_target="/api/v1/orders/{id}",
        decision=HypothesisDecision.HYPOTHESIS,
        empirical_facts=["FACT-TEST-01"],
        methodology_references=[],
        experiment_action="SUBSTITUTE_RESOURCE_IDENTIFIER",
        supporting_outcome="HTTP_200_OK",
        disproving_outcome="HTTP_403_FORBIDDEN",
    )
    cand = map_bair_json_to_s0(bair, target_asset={"application_mutability": "READ_ONLY", "parameters": [{"param_name": "id"}]}, category_id="API-BOLA-001")
    ev_state = _create_evidence_state("API-BOLA-001")
    result = deterministic_decide(candidate=cand, evidence_state=ev_state)
    assert result.is_valid is True
    assert result.final_decision == HypothesisDecision.HYPOTHESIS
    assert result.predicate_identifier == DecisionPredicate.HYPOTHESIS_GROUNDED


def test_c_inverted_bola_fails_closed():
    """
    Test C: Inverted BOLA
    supporting = HTTP_403_FORBIDDEN
    disproving = HTTP_200_OK
    => REJECT
    """
    is_valid, reason = ExperimentPolarityValidator.validate_tuple(
        category_id="API-BOLA-001",
        experiment_action="SUBSTITUTE_RESOURCE_IDENTIFIER",
        supporting_outcome="HTTP_403_FORBIDDEN",
        disproving_outcome="HTTP_200_OK",
    )
    assert is_valid is False
    assert "not a valid breach outcome" in reason

    cand = HypothesisModelOutput(
        decision=HypothesisDecision.HYPOTHESIS,
        invariant="Object access restricted to owner",
        evidence_gap="Missing owner check",
        affected_target="/api/v1/orders/{id}",
        supporting_evidence_ids=["FACT-TEST-01"],
        methodology_references=[],
        experiment_action="SUBSTITUTE_RESOURCE_IDENTIFIER",
        supporting_outcome="HTTP_403_FORBIDDEN",
        disproving_outcome="HTTP_200_OK",
    )
    ev_state = _create_evidence_state("API-BOLA-001")
    result = deterministic_decide(candidate=cand, evidence_state=ev_state)
    assert result.is_valid is False
    assert result.predicate_identifier == DecisionPredicate.FAIL_CLOSED_INCOMPLETE_HYPOTHESIS


def test_d_valid_state_machine_semantic_predicates():
    """
    Test D: Valid state machine with semantic predicates
    EXECUTE_OUT_OF_ORDER_TRANSITION
    supporting = STATE_TRANSITION_ACCEPTED
    disproving = STATE_TRANSITION_REJECTED
    => ACCEPT
    """
    is_valid, reason = ExperimentPolarityValidator.validate_tuple(
        category_id="API-STATE-001",
        experiment_action="EXECUTE_OUT_OF_ORDER_TRANSITION",
        supporting_outcome="STATE_TRANSITION_ACCEPTED",
        disproving_outcome="STATE_TRANSITION_REJECTED",
    )
    assert is_valid is True

    bair = BairJsonObject(
        invariant="Transitions must follow finite state machine",
        evidence_gap="Missing state prerequisite verification",
        affected_target="/api/v1/orders/{id}/refund",
        decision=HypothesisDecision.HYPOTHESIS,
        empirical_facts=["FACT-TEST-01"],
        methodology_references=[],
        experiment_action="EXECUTE_OUT_OF_ORDER_TRANSITION",
        supporting_outcome="STATE_TRANSITION_ACCEPTED",
        disproving_outcome="STATE_TRANSITION_REJECTED",
    )
    cand = map_bair_json_to_s0(bair, target_asset={"application_mutability": "STATE_CHANGING", "parameters": [{"param_name": "id"}]}, category_id="API-STATE-001")
    ev_state = _create_evidence_state("API-STATE-001")
    result = deterministic_decide(candidate=cand, evidence_state=ev_state)
    assert result.is_valid is True
    assert result.final_decision == HypothesisDecision.HYPOTHESIS
    assert result.predicate_identifier == DecisionPredicate.HYPOTHESIS_GROUNDED


def test_e_valid_state_machine_http_predicates():
    """
    Test E: Valid state machine with HTTP predicates
    supporting = HTTP_200_OK
    disproving = HTTP_409_CONFLICT
    => ACCEPT
    """
    is_valid, reason = ExperimentPolarityValidator.validate_tuple(
        category_id="API-STATE-001",
        experiment_action="EXECUTE_OUT_OF_ORDER_TRANSITION",
        supporting_outcome="HTTP_200_OK",
        disproving_outcome="HTTP_409_CONFLICT",
    )
    assert is_valid is True

    bair = BairJsonObject(
        invariant="Transitions must follow finite state machine",
        evidence_gap="Missing state prerequisite verification",
        affected_target="/api/v1/orders/{id}/refund",
        decision=HypothesisDecision.HYPOTHESIS,
        empirical_facts=["FACT-TEST-01"],
        methodology_references=[],
        experiment_action="EXECUTE_OUT_OF_ORDER_TRANSITION",
        supporting_outcome="HTTP_200_OK",
        disproving_outcome="HTTP_409_CONFLICT",
    )
    cand = map_bair_json_to_s0(bair, target_asset={"application_mutability": "STATE_CHANGING", "parameters": [{"param_name": "id"}]}, category_id="API-STATE-001")
    ev_state = _create_evidence_state("API-STATE-001")
    result = deterministic_decide(candidate=cand, evidence_state=ev_state)
    assert result.is_valid is True
    assert result.final_decision == HypothesisDecision.HYPOTHESIS
    assert result.predicate_identifier == DecisionPredicate.HYPOTHESIS_GROUNDED


def test_f_inverted_state_machine_fails_closed():
    """
    Test F: Inverted state machine
    supporting = HTTP_409_CONFLICT
    disproving = STATE_TRANSITION_ACCEPTED
    => REJECT
    """
    is_valid, reason = ExperimentPolarityValidator.validate_tuple(
        category_id="API-STATE-001",
        experiment_action="EXECUTE_OUT_OF_ORDER_TRANSITION",
        supporting_outcome="HTTP_409_CONFLICT",
        disproving_outcome="STATE_TRANSITION_ACCEPTED",
    )
    assert is_valid is False
    assert "not a valid breach outcome" in reason

    cand = HypothesisModelOutput(
        decision=HypothesisDecision.HYPOTHESIS,
        invariant="Transitions must follow finite state machine",
        evidence_gap="Missing state prerequisite verification",
        affected_target="/api/v1/orders/{id}/refund",
        supporting_evidence_ids=["FACT-TEST-01"],
        methodology_references=[],
        experiment_action="EXECUTE_OUT_OF_ORDER_TRANSITION",
        supporting_outcome="HTTP_409_CONFLICT",
        disproving_outcome="STATE_TRANSITION_ACCEPTED",
    )
    ev_state = _create_evidence_state("API-STATE-001")
    result = deterministic_decide(candidate=cand, evidence_state=ev_state)
    assert result.is_valid is False
    assert result.predicate_identifier == DecisionPredicate.FAIL_CLOSED_INCOMPLETE_HYPOTHESIS


def test_g_category_action_mismatch_fails_closed():
    """
    Test G: Category/action mismatch
    BOLA + EXECUTE_OUT_OF_ORDER_TRANSITION
    => REJECT
    """
    is_valid, reason = ExperimentPolarityValidator.validate_tuple(
        category_id="API-BOLA-001",
        experiment_action="EXECUTE_OUT_OF_ORDER_TRANSITION",
        supporting_outcome="STATE_TRANSITION_ACCEPTED",
        disproving_outcome="STATE_TRANSITION_REJECTED",
    )
    assert is_valid is False
    assert "not compatible with category" in reason

    cand = HypothesisModelOutput(
        decision=HypothesisDecision.HYPOTHESIS,
        invariant="Object access restricted to owner",
        evidence_gap="Missing owner check",
        affected_target="/api/v1/orders/{id}",
        supporting_evidence_ids=["FACT-TEST-01"],
        methodology_references=[],
        experiment_action="EXECUTE_OUT_OF_ORDER_TRANSITION",
        supporting_outcome="STATE_TRANSITION_ACCEPTED",
        disproving_outcome="STATE_TRANSITION_REJECTED",
    )
    ev_state = _create_evidence_state("API-BOLA-001")
    result = deterministic_decide(candidate=cand, evidence_state=ev_state)
    assert result.is_valid is False
    assert result.predicate_identifier == DecisionPredicate.FAIL_CLOSED_INCOMPLETE_HYPOTHESIS


def test_h_action_outcome_mismatch_fails_closed():
    """
    Test H: Action/outcome mismatch
    SUBSTITUTE_RESOURCE_IDENTIFIER + STATE_TRANSITION_ACCEPTED
    => REJECT
    """
    is_valid, reason = ExperimentPolarityValidator.validate_tuple(
        category_id="API-BOLA-001",
        experiment_action="SUBSTITUTE_RESOURCE_IDENTIFIER",
        supporting_outcome="STATE_TRANSITION_ACCEPTED",
        disproving_outcome="CROSS_IDENTITY_OBJECT_DENIED",
    )
    assert is_valid is False
    assert "not a valid breach outcome" in reason

    cand = HypothesisModelOutput(
        decision=HypothesisDecision.HYPOTHESIS,
        invariant="Object access restricted to owner",
        evidence_gap="Missing owner check",
        affected_target="/api/v1/orders/{id}",
        supporting_evidence_ids=["FACT-TEST-01"],
        methodology_references=[],
        experiment_action="SUBSTITUTE_RESOURCE_IDENTIFIER",
        supporting_outcome="STATE_TRANSITION_ACCEPTED",
        disproving_outcome="CROSS_IDENTITY_OBJECT_DENIED",
    )
    ev_state = _create_evidence_state("API-BOLA-001")
    result = deterministic_decide(candidate=cand, evidence_state=ev_state)
    assert result.is_valid is False
    assert result.predicate_identifier == DecisionPredicate.FAIL_CLOSED_INCOMPLETE_HYPOTHESIS


def test_i_unknown_category_fails_closed():
    """
    Test I: Unknown category
    => REJECT
    """
    is_valid, reason = ExperimentPolarityValidator.validate_tuple(
        category_id="API-UNKNOWN-999",
        experiment_action="SUBSTITUTE_RESOURCE_IDENTIFIER",
        supporting_outcome="CROSS_IDENTITY_OBJECT_ACCESSIBLE",
        disproving_outcome="CROSS_IDENTITY_OBJECT_DENIED",
    )
    assert is_valid is False
    assert "Unrecognized category ID" in reason

    cand = HypothesisModelOutput(
        decision=HypothesisDecision.HYPOTHESIS,
        invariant="Invariant",
        evidence_gap="Gap",
        affected_target="/api/v1/test",
        supporting_evidence_ids=["FACT-TEST-01"],
        methodology_references=[],
        experiment_action="SUBSTITUTE_RESOURCE_IDENTIFIER",
        supporting_outcome="CROSS_IDENTITY_OBJECT_ACCESSIBLE",
        disproving_outcome="CROSS_IDENTITY_OBJECT_DENIED",
    )
    ev_state = _create_evidence_state("API-UNKNOWN-999")
    result = deterministic_decide(candidate=cand, evidence_state=ev_state)
    assert result.is_valid is False
    assert result.predicate_identifier == DecisionPredicate.FAIL_CLOSED_INCOMPLETE_HYPOTHESIS


def test_j_unknown_action_fails_closed():
    """
    Test J: Unknown action
    => REJECT
    """
    # 1. BairJsonObject rejects unknown enum action
    with pytest.raises(ValidationError) as exc:
        BairJsonObject(
            invariant="Invariant",
            evidence_gap="Gap",
            affected_target="/api/v1/test",
            decision=HypothesisDecision.HYPOTHESIS,
            empirical_facts=["FACT-TEST-01"],
            methodology_references=[],
            experiment_action="INVENTED_ACTION_FOO",
            supporting_outcome="CROSS_IDENTITY_OBJECT_ACCESSIBLE",
            disproving_outcome="CROSS_IDENTITY_OBJECT_DENIED",
        )
    assert "Unknown experiment_action predicate" in str(exc.value)

    # 2. Polarity validator rejects unknown action
    is_valid, reason = ExperimentPolarityValidator.validate_tuple(
        category_id="API-BOLA-001",
        experiment_action="INVENTED_ACTION_FOO",
        supporting_outcome="CROSS_IDENTITY_OBJECT_ACCESSIBLE",
        disproving_outcome="CROSS_IDENTITY_OBJECT_DENIED",
    )
    assert is_valid is False
    assert "not compatible with category" in reason


def test_k_unknown_outcome_fails_closed():
    """
    Test K: Unknown outcome
    => REJECT
    """
    # 1. BairJsonObject rejects unknown outcome
    with pytest.raises(ValidationError) as exc:
        BairJsonObject(
            invariant="Invariant",
            evidence_gap="Gap",
            affected_target="/api/v1/test",
            decision=HypothesisDecision.HYPOTHESIS,
            empirical_facts=["FACT-TEST-01"],
            methodology_references=[],
            experiment_action="SUBSTITUTE_RESOURCE_IDENTIFIER",
            supporting_outcome="INVENTED_OUTCOME_BAR",
            disproving_outcome="CROSS_IDENTITY_OBJECT_DENIED",
        )
    assert "Unknown outcome predicate" in str(exc.value)

    # 2. Polarity validator rejects unknown outcome
    is_valid, reason = ExperimentPolarityValidator.validate_tuple(
        category_id="API-BOLA-001",
        experiment_action="SUBSTITUTE_RESOURCE_IDENTIFIER",
        supporting_outcome="INVENTED_OUTCOME_BAR",
        disproving_outcome="CROSS_IDENTITY_OBJECT_DENIED",
    )
    assert is_valid is False
    assert "not a valid breach outcome" in reason


def test_l_identical_outcomes_fail_closed():
    """
    Test L: Identical outcomes (supporting == disproving)
    => REJECT
    """
    # 1. BairJsonObject rejects identical outcomes
    with pytest.raises(ValidationError) as exc:
        BairJsonObject(
            invariant="Invariant",
            evidence_gap="Gap",
            affected_target="/api/v1/test",
            decision=HypothesisDecision.HYPOTHESIS,
            empirical_facts=["FACT-TEST-01"],
            methodology_references=[],
            experiment_action="SUBSTITUTE_RESOURCE_IDENTIFIER",
            supporting_outcome="HTTP_200_OK",
            disproving_outcome="HTTP_200_OK",
        )
    assert "supporting_outcome and disproving_outcome cannot be identical" in str(exc.value)

    # 2. Polarity validator rejects identical outcomes
    is_valid, reason = ExperimentPolarityValidator.validate_tuple(
        category_id="API-BOLA-001",
        experiment_action="SUBSTITUTE_RESOURCE_IDENTIFIER",
        supporting_outcome="HTTP_200_OK",
        disproving_outcome="HTTP_200_OK",
    )
    assert is_valid is False
    assert "supporting_outcome and disproving_outcome cannot be identical" in reason


def test_m_missing_typed_fields_on_hypothesis_fails_closed():
    """
    Test M: Missing typed fields on HYPOTHESIS
    => REJECT
    """
    # 1. BairJsonObject rejects HYPOTHESIS without typed fields
    with pytest.raises(ValidationError) as exc:
        BairJsonObject(
            invariant="Invariant",
            evidence_gap="Gap",
            affected_target="/api/v1/test",
            decision=HypothesisDecision.HYPOTHESIS,
            empirical_facts=["FACT-TEST-01"],
            methodology_references=[],
            experiment_action=None,
            supporting_outcome=None,
            disproving_outcome=None,
        )
    assert "Mandatory experiment_action slot missing" in str(exc.value) or "HYPOTHESIS requires typed experiment fields" in str(exc.value)

    # 2. Decision policy rejects HYPOTHESIS candidate missing typed fields
    cand = HypothesisModelOutput(
        decision=HypothesisDecision.HYPOTHESIS,
        invariant="Invariant",
        evidence_gap="Gap",
        affected_target="/api/v1/test",
        supporting_evidence_ids=["FACT-TEST-01"],
        methodology_references=[],
        experiment_action=None,
        supporting_outcome=None,
        disproving_outcome=None,
    )
    ev_state = _create_evidence_state("API-BOLA-001")
    result = deterministic_decide(candidate=cand, evidence_state=ev_state)
    assert result.is_valid is False
    assert result.predicate_identifier == DecisionPredicate.FAIL_CLOSED_INCOMPLETE_HYPOTHESIS


def test_n_insufficient_evidence_without_experiment_accepted():
    """
    Test N: INSUFFICIENT_EVIDENCE without experiment
    => ACCEPT
    """
    # 1. BairJsonObject allows INSUFFICIENT_EVIDENCE without typed experiment fields
    bair = BairJsonObject(
        invariant="Tenant isolation must be maintained",
        evidence_gap="No endpoints found exposing tenant records",
        affected_target="/api/v1/public/info",
        decision=HypothesisDecision.INSUFFICIENT_EVIDENCE,
        empirical_facts=["FACT-TEST-01"],
        methodology_references=[],
    )
    assert bair.decision == HypothesisDecision.INSUFFICIENT_EVIDENCE
    assert bair.experiment_action is None
    assert bair.supporting_outcome is None
    assert bair.disproving_outcome is None

    # 2. Decision policy accepts candidate as INSUFFICIENT_EVIDENCE_CONFIRMED
    cand = map_bair_json_to_s0(bair, target_asset={"application_mutability": "READ_ONLY", "parameters": []}, category_id="API-BOLA-001")
    ev_state = _create_evidence_state("API-BOLA-001", empirical=True)
    result = deterministic_decide(candidate=cand, evidence_state=ev_state)
    assert result.is_valid is True
    assert result.final_decision == HypothesisDecision.INSUFFICIENT_EVIDENCE
    assert result.predicate_identifier == DecisionPredicate.INSUFFICIENT_EVIDENCE_CONFIRMED


def test_o_description_contradiction_governed_by_typed_fields():
    """
    Test O: Human-readable falsification_description contradicts typed fields.
    Typed fields govern; description cannot authorize invalid polarity,
    nor does inverted description invalidate valid typed fields.
    """
    # Case 1: Valid typed fields with contradictory / nonsense description -> ACCEPTED
    bair_valid = BairJsonObject(
        invariant="Object access restricted to owner",
        evidence_gap="Missing owner check",
        affected_target="/api/v1/orders/{id}",
        decision=HypothesisDecision.HYPOTHESIS,
        empirical_facts=["FACT-TEST-01"],
        methodology_references=[],
        experiment_action="SUBSTITUTE_RESOURCE_IDENTIFIER",
        supporting_outcome="CROSS_IDENTITY_OBJECT_ACCESSIBLE",
        disproving_outcome="CROSS_IDENTITY_OBJECT_DENIED",
        falsification_description="Disprove if 200 OK, support if 403 Forbidden (CONTRADICTORY TEXT)",
    )
    cand_valid = map_bair_json_to_s0(bair_valid, target_asset={"application_mutability": "READ_ONLY", "parameters": [{"param_name": "id"}]}, category_id="API-BOLA-001")
    ev_state = _create_evidence_state("API-BOLA-001")
    result_valid = deterministic_decide(candidate=cand_valid, evidence_state=ev_state)
    assert result_valid.is_valid is True
    assert result_valid.final_decision == HypothesisDecision.HYPOTHESIS

    # Case 2: Inverted typed fields with seemingly valid description -> REJECTED
    # Natural language description cannot bypass or authorize invalid typed polarity
    cand_invalid = HypothesisModelOutput(
        decision=HypothesisDecision.HYPOTHESIS,
        invariant="Object access restricted to owner",
        evidence_gap="Missing owner check",
        affected_target="/api/v1/orders/{id}",
        supporting_evidence_ids=["FACT-TEST-01"],
        methodology_references=[],
        experiment_action="SUBSTITUTE_RESOURCE_IDENTIFIER",
        supporting_outcome="CROSS_IDENTITY_OBJECT_DENIED",  # Inverted!
        disproving_outcome="CROSS_IDENTITY_OBJECT_ACCESSIBLE",
        falsification_description="Proper plan in natural language: support if 200, disprove if 403",
    )
    result_invalid = deterministic_decide(candidate=cand_invalid, evidence_state=ev_state)
    assert result_invalid.is_valid is False
    assert result_invalid.predicate_identifier == DecisionPredicate.FAIL_CLOSED_INCOMPLETE_HYPOTHESIS


def test_p_legacy_free_text_falsification_plan_fails_closed():
    """
    Test P: Legacy free-text falsification_plan only
    => FAIL CLOSED under new protocol
    """
    # 1. BairJsonObject strictly rejects legacy plan without typed fields
    with pytest.raises(ValidationError) as exc:
        BairJsonObject(
            invariant="Resource access restricted to owner",
            evidence_gap="Missing ownership check",
            affected_target="/api/v1/orders/{id}",
            decision=HypothesisDecision.HYPOTHESIS,
            empirical_facts=["FACT-TEST-01"],
            methodology_references=[],
            falsification_plan="Support if 200 returned with other user order; disprove if 403 Forbidden returned",
        )
    assert "Legacy free-text falsification_plan cannot authorize a HYPOTHESIS" in str(exc.value)

    # 2. Decision policy strictly rejects legacy candidate with only experiment_proposal
    cand = HypothesisModelOutput(
        decision=HypothesisDecision.HYPOTHESIS,
        invariant="Resource access restricted to owner",
        evidence_gap="Missing ownership check",
        affected_target="/api/v1/orders/{id}",
        supporting_evidence_ids=["FACT-TEST-01"],
        methodology_references=[],
        experiment_proposal="Support if 200 returned with other user order; disprove if 403 Forbidden returned",
        experiment_action=None,
        supporting_outcome=None,
        disproving_outcome=None,
    )
    ev_state = _create_evidence_state("API-BOLA-001")
    result = deterministic_decide(candidate=cand, evidence_state=ev_state)
    assert result.is_valid is False
    assert result.predicate_identifier == DecisionPredicate.FAIL_CLOSED_INCOMPLETE_HYPOTHESIS


# ===========================================================================
# Section 7 & 11: Six-Layer Agreement and Decoding Contract Tests
# ===========================================================================

def test_six_layer_architectural_agreement():
    """
    Verifies the M5 invariant across all 6 layers:
    PromptInstructions == RuntimeSchema == Extractor == Parser == Validator == Adapter
    """
    # Layer 1: Prompt Instructions
    assert "experiment_action" in JSON_BAIR_PROMPT_INSTRUCTION
    assert "supporting_outcome" in JSON_BAIR_PROMPT_INSTRUCTION
    assert "disproving_outcome" in JSON_BAIR_PROMPT_INSTRUCTION
    assert "falsification_description" in JSON_BAIR_PROMPT_INSTRUCTION

    # Layer 2: Runtime Schema
    schema = BairJsonObject.get_inference_schema()
    props = schema["properties"]
    assert "experiment_action" in props
    assert "supporting_outcome" in props
    assert "disproving_outcome" in props
    assert "falsification_description" in props
    # Action enum options in schema match VALID_ACTION_PREDICATES (excluding None for optional)
    assert (set(props["experiment_action"]["enum"]) - {None}) == VALID_ACTION_PREDICATES
    # Outcome enum options in schema match VALID_OUTCOME_PREDICATES (excluding None for optional)
    assert (set(props["supporting_outcome"]["enum"]) - {None}) == VALID_OUTCOME_PREDICATES
    assert (set(props["disproving_outcome"]["enum"]) - {None}) == VALID_OUTCOME_PREDICATES

    # Layer 3: Extractor
    raw_payload = json.dumps({
        "invariant": "Owner check",
        "evidence_gap": "Gap",
        "affected_target": "/api/v1/orders/{id}",
        "decision": "HYPOTHESIS",
        "empirical_facts": ["FACT-TEST-01"],
        "methodology_references": [],
        "experiment_action": "SUBSTITUTE_RESOURCE_IDENTIFIER",
        "supporting_outcome": "CROSS_IDENTITY_OBJECT_ACCESSIBLE",
        "disproving_outcome": "CROSS_IDENTITY_OBJECT_DENIED",
        "falsification_description": "Test description",
    })
    extracted = parse_bair_json(raw_payload)
    assert extracted["experiment_action"] == "SUBSTITUTE_RESOURCE_IDENTIFIER"
    assert extracted["supporting_outcome"] == "CROSS_IDENTITY_OBJECT_ACCESSIBLE"
    assert extracted["disproving_outcome"] == "CROSS_IDENTITY_OBJECT_DENIED"
    assert extracted["falsification_description"] == "Test description"

    # Layer 4: Parser
    bair = BairJsonObject(**extracted)
    assert bair.experiment_action == "SUBSTITUTE_RESOURCE_IDENTIFIER"
    assert bair.supporting_outcome == "CROSS_IDENTITY_OBJECT_ACCESSIBLE"
    assert bair.disproving_outcome == "CROSS_IDENTITY_OBJECT_DENIED"
    assert bair.falsification_description == "Test description"

    # Layer 5: Validator
    is_valid, reason = ExperimentPolarityValidator.validate_tuple(
        category_id="API-BOLA-001",
        experiment_action=bair.experiment_action,
        supporting_outcome=bair.supporting_outcome,
        disproving_outcome=bair.disproving_outcome,
    )
    assert is_valid is True

    # Layer 6: Adapter
    s0 = map_bair_json_to_s0(bair, target_asset={"application_mutability": "READ_ONLY", "parameters": [{"param_name": "id"}]}, category_id="API-BOLA-001")
    assert s0.experiment_action == "SUBSTITUTE_RESOURCE_IDENTIFIER"
    assert s0.supporting_outcome == "CROSS_IDENTITY_OBJECT_ACCESSIBLE"
    assert s0.disproving_outcome == "CROSS_IDENTITY_OBJECT_DENIED"
    assert s0.falsification_description == "Test description"
    assert "Action: SUBSTITUTE_RESOURCE_IDENTIFIER" in s0.experiment_proposal


def test_dual_track_decoding_contract_agreement():
    """
    Verify: I1=0 and I1=1 both use the SAME typed protocol contract.
    Only the decoding constraint differs:
    I1=0: runtime_schema = None
    I1=1: runtime_schema = BairJsonObject.get_inference_schema()
    """
    proto_contract = get_protocol_contract(OutputProtocolIdentifier.JSON_BAIR)
    schema_i1_off = proto_contract.runtime_schema_factory(False)
    schema_i1_on = proto_contract.runtime_schema_factory(True)

    # I1=0 has no schema constraint passed to LLM
    assert schema_i1_off is None
    # I1=1 has strict JSON schema constraint passed to LLM
    assert schema_i1_on is not None
    assert "properties" in schema_i1_on
    assert "experiment_action" in schema_i1_on["properties"]

    # Both tracks share exact same parser, validator, and adapter functions
    assert proto_contract.parser is parse_bair_json
    assert proto_contract.adapter is map_bair_json_to_s0


# ===========================================================================
# Section 12: Token Budget Verification
# ===========================================================================

def test_typed_fields_token_budget_envelope():
    """
    Verify that the typed fields fit comfortably within the frozen primary envelope:
    qwen2.5-coder:7b
    num_ctx=2048
    num_predict=300
    temperature=0.0
    seed=42
    one inference call
    """
    # Sample maximal JSON emission with typed fields
    maximal_bair_dict = {
        "invariant": "Resource access must be restricted to the authenticated resource owner or tenant.",
        "evidence_gap": "The endpoint does not verify ownership or tenant isolation for the requested identifier.",
        "affected_target": "/api/v1/tenants/{tenant_id}/billing/invoices/{invoice_id}/download",
        "decision": "HYPOTHESIS",
        "empirical_facts": [
            "FACT-ECOMMERCE_ORDERS-ORD-REFUND-DOC",
            "FACT-ECOMMERCE_ORDERS-ORD-REFUND-PARAM-ID",
        ],
        "methodology_references": [
            "CHK-DOC-WSTG-ATHZ-04-001-01",
            "CHK-DOC-WSTG-ATHZ-04-001-02",
        ],
        "experiment_action": "SUBSTITUTE_RESOURCE_IDENTIFIER",
        "supporting_outcome": "CROSS_IDENTITY_OBJECT_ACCESSIBLE",
        "disproving_outcome": "CROSS_IDENTITY_OBJECT_DENIED",
        "falsification_description": "Issue request with tenant A credentials referencing tenant B invoice identifier.",
    }

    serialized = json.dumps(maximal_bair_dict, indent=2)
    # Character count heuristic: ~4 chars per token for JSON
    # 300 tokens budget ~= 1200 characters
    char_count = len(serialized)
    estimated_tokens = char_count / 3.5

    assert char_count < 1000, f"Maximal BAIR JSON is {char_count} chars; expected < 1000"
    assert estimated_tokens < 250, f"Estimated tokens {estimated_tokens} exceeds conservative 250 token bound"
    assert estimated_tokens < 300, f"Estimated tokens {estimated_tokens} exceeds num_predict=300 limit"
