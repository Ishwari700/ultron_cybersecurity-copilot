"""Hermetic Unit Tests for Milestone M4.6 / Intervention I5: Deterministic Decision Policy.

Verifies:
1. HYPOTHESIS -> remains HYPOTHESIS when all required predicates pass
2. HYPOTHESIS -> fail closed when grounding fails
3. HYPOTHESIS -> fail closed when falsification is incomplete
4. INSUFFICIENT_EVIDENCE -> remains INSUFFICIENT_EVIDENCE on relevant target
5. NO_RELEVANT_FUNCTIONALITY -> remains NO_RELEVANT_FUNCTIONALITY on irrelevant target
6. HYPOTHESIS -> NO_RELEVANT_FUNCTIONALITY on explicit irrelevant target
7. INSUFFICIENT_EVIDENCE -> NO_RELEVANT_FUNCTIONALITY on explicit irrelevant target
8. NO_RELEVANT_FUNCTIONALITY -> INSUFFICIENT_EVIDENCE on explicit relevant target
9. unsupported decision -> fail closed
10. CONFIRMED -> fail closed
11. malformed candidate -> fail closed
12. missing predicate state -> fail closed
13. invalid/fabricated evidence ID -> fail closed
14. repeated identical input -> identical final decision
15. all non-decision S0 fields remain byte-identical
16. no evidence citation substitution
17. no semantic rewriting
18. no ground-truth access
19. no probability/confidence threshold access
20. no learned classifier import/use
21. relevance predicate uses only structured canonical inputs
22. discriminating-evidence predicate uses only structured canonical inputs
23. candidate prose cannot alter is_relevant_functionality
24. candidate prose cannot alter is_discriminating_evidence_absent
25. I1 is not called (schema=None, no format constraint)
26. I2 is not called (no namespace-partitioning prompt)
27. I3 is not called (no counterfactual template resolver)
28. I4 is not called (no BAIR prompt / extractor)
29. I6 is not called (no 3B->7B invariant handoff serializer)
30. exactly one LLM call
31. schema=None
"""

import inspect
import json
import pytest
from typing import Any, Dict, List, Optional

from src.engine.decision_policy import (
    DecisionPolicyResult,
    DecisionPredicate,
    EvidenceState,
    deterministic_decide,
    is_discriminating_evidence_absent,
    is_empirical_evidence_grounded,
    is_falsification_complete,
    is_relevant_functionality,
)
from src.engine.models import (
    HypothesisDecision,
    HypothesisModelOutput,
    I5ExecutionResult,
)
from src.engine.runner import ReasoningRunner
from src.engine.context_builder import ReasoningContextBuilder, TRACK_D
from src.evidence.cascade_models import (
    CascadeHandoffPacket,
    DeterministicRoutingDecision,
    LosslessStructuralPack,
)


def make_valid_candidate(
    decision: str = "HYPOTHESIS",
    invariant: str = "INV-001: Cross-tenant access must return HTTP 403",
    evidence_gap: str = "GAP-001: Need verification with secondary tenant ID",
    affected_target: str = "/api/v1/tenants/{tenant_id}",
    supporting_evidence_ids: Optional[List[str]] = None,
    methodology_references: Optional[List[str]] = None,
    experiment_proposal: str = "Observation supporting hypothesis: HTTP 200 with tenant data. Observation disproving/falsifying hypothesis: HTTP 403 Forbidden.",
    experiment_action: Optional[str] = "SUBSTITUTE_RESOURCE_IDENTIFIER",
    supporting_outcome: Optional[str] = "HTTP_200_OK",
    disproving_outcome: Optional[str] = "HTTP_403_FORBIDDEN",
    falsification_description: Optional[str] = None,
) -> HypothesisModelOutput:
    """Helper to build canonical HypothesisModelOutput candidate."""
    return HypothesisModelOutput(
        decision=decision,
        invariant=invariant,
        evidence_gap=evidence_gap,
        affected_target=affected_target,
        supporting_evidence_ids=supporting_evidence_ids or ["FACT-001"],
        methodology_references=methodology_references or [],
        experiment_proposal=experiment_proposal,
        experiment_action=experiment_action,
        supporting_outcome=supporting_outcome,
        disproving_outcome=disproving_outcome,
        falsification_description=falsification_description,
        reasoning_summary="Evidence indicates potential authorization bypass.",
        category="API-BOLA-001",
        asset_id="/api/v1/tenants/{tenant_id}",
    )


def make_evidence_state(
    application_mutability: str = "STATE_CHANGING",
    has_privilege_level_delta: bool = False,
    has_cross_identity_object_access_success: bool = True,
    has_numeric_path_identifier: bool = True,
    observed_facts: Optional[List[Dict[str, Any]]] = None,
    retrieved_evidence: Optional[List[Dict[str, Any]]] = None,
    category_id: str = "API-BOLA-001",
    empirical_evidence_present: Optional[bool] = None,
    parameter_lineage: Optional[List[Dict[str, Any]]] = None,
    identity_matrix: Optional[List[Dict[str, Any]]] = None,
    grounding_validator: Optional[Any] = None,
) -> EvidenceState:
    """Helper to construct canonical EvidenceState."""
    if observed_facts is None:
        facts = [{"fact_id": "FACT-001", "statement": "GET /api/v1/tenants/42 returns HTTP 200 for user2."}]
    else:
        facts = observed_facts

    if retrieved_evidence is None:
        ret_ev = facts
    else:
        ret_ev = retrieved_evidence

    ch_a = LosslessStructuralPack(
        asset_id="AST-001",
        endpoint_id="EP-001",
        route_template="/api/v1/tenants/{tenant_id}",
        http_method="GET",
        application_mutability=application_mutability,
        has_privilege_level_delta=has_privilege_level_delta,
        has_cross_identity_object_access_success=has_cross_identity_object_access_success,
        has_numeric_path_identifier=has_numeric_path_identifier,
        parameter_lineage=parameter_lineage or [{"param_id": "P-01", "param_name": "tenant_id", "location": "path"}],
        identity_matrix=identity_matrix or [{"role": "user1"}, {"role": "user2"}],
        observed_facts=facts,
    )
    return EvidenceState(
        channel_a=ch_a,
        retrieved_evidence=ret_ev,
        target_asset={"asset_id": "AST-001", "application_mutability": application_mutability},
        category_id=category_id,
        empirical_evidence_present=empirical_evidence_present,
        grounding_validator=grounding_validator,
    )


def make_irrelevant_evidence_state() -> EvidenceState:
    """Helper for an endpoint completely outside the security property (negative control)."""
    ch_a = LosslessStructuralPack(
        asset_id="AST-STATIC-01",
        endpoint_id="EP-STATIC-01",
        route_template="/health",
        http_method="GET",
        application_mutability="READ_ONLY",
        has_privilege_level_delta=False,
        status_code_changed_under_different_role=False,
        has_unauthenticated_success=False,
        has_cross_role_response_shape_delta=False,
        has_cross_identity_object_access_success=False,
        has_unseen_endpoint_parameter=False,
        has_numeric_path_identifier=False,
        has_observed_contradictions=False,
        has_evidence_parse_asymmetry=False,
        auth_header_delta=False,
        parameter_lineage=[],
        identity_matrix=[],
        observed_facts=[],
    )
    return EvidenceState(
        channel_a=ch_a,
        retrieved_evidence=[],
        target_asset={"asset_id": "AST-STATIC-01", "application_mutability": "READ_ONLY"},
        category_id="API-BOLA-001",
        empirical_evidence_present=False,
    )


# ===========================================================================
# 1-8: Core Decision Precedence Tests
# ===========================================================================

def test_01_hypothesis_remains_hypothesis_when_all_predicates_pass():
    """Requirement 1: HYPOTHESIS -> remains HYPOTHESIS when all required predicates pass."""
    cand = make_valid_candidate(decision="HYPOTHESIS")
    state = make_evidence_state()

    res = deterministic_decide(cand, state)

    assert res.is_valid is True
    assert res.final_decision == HypothesisDecision.HYPOTHESIS
    assert res.decision_changed is False
    assert res.predicate_identifier == DecisionPredicate.HYPOTHESIS_GROUNDED
    assert res.canonical_hypothesis is not None
    assert res.canonical_hypothesis.decision == HypothesisDecision.HYPOTHESIS


def test_02_hypothesis_fails_closed_when_grounding_fails():
    """Requirement 2: HYPOTHESIS -> fail closed when grounding fails."""
    cand = make_valid_candidate(decision="HYPOTHESIS", supporting_evidence_ids=["FACT-UNGROUNDED-999"])
    state = make_evidence_state(observed_facts=[{"fact_id": "FACT-001", "statement": "Valid fact"}])

    res = deterministic_decide(cand, state)

    assert res.is_valid is False
    assert res.final_decision is None
    assert res.predicate_identifier == DecisionPredicate.FAIL_CLOSED_GROUNDING_REJECTION
    assert "grounding check failed" in (res.fail_closed_reason or "")


def test_03_hypothesis_fails_closed_when_falsification_is_incomplete():
    """Requirement 3: HYPOTHESIS -> fail closed when falsification is incomplete."""
    cand = make_valid_candidate(
        decision="HYPOTHESIS",
        experiment_proposal="Only supporting: send request and get 200 OK.",
        disproving_outcome=None,
    )
    state = make_evidence_state()

    res = deterministic_decide(cand, state)

    assert res.is_valid is False
    assert res.final_decision is None
    assert res.predicate_identifier == DecisionPredicate.FAIL_CLOSED_INCOMPLETE_HYPOTHESIS
    assert "experiment proposal is incomplete" in (res.fail_closed_reason or "")


def test_04_insufficient_evidence_remains_insufficient_evidence_on_relevant_target():
    """Requirement 4: INSUFFICIENT_EVIDENCE -> remains INSUFFICIENT_EVIDENCE on relevant target."""
    cand = make_valid_candidate(decision="INSUFFICIENT_EVIDENCE")
    state = make_evidence_state()

    res = deterministic_decide(cand, state)

    assert res.is_valid is True
    assert res.final_decision == HypothesisDecision.INSUFFICIENT_EVIDENCE
    assert res.decision_changed is False
    assert res.predicate_identifier == DecisionPredicate.INSUFFICIENT_EVIDENCE_CONFIRMED
    assert res.canonical_hypothesis.decision == HypothesisDecision.INSUFFICIENT_EVIDENCE


def test_05_no_relevant_functionality_remains_no_relevant_on_irrelevant_target():
    """Requirement 5: NO_RELEVANT_FUNCTIONALITY -> remains NO_RELEVANT_FUNCTIONALITY on irrelevant target."""
    cand = make_valid_candidate(decision="NO_RELEVANT_FUNCTIONALITY", supporting_evidence_ids=[])
    state = make_irrelevant_evidence_state()

    res = deterministic_decide(cand, state)

    assert res.is_valid is True
    assert res.final_decision == HypothesisDecision.NO_RELEVANT_FUNCTIONALITY
    assert res.decision_changed is False
    assert res.predicate_identifier == DecisionPredicate.NO_RELEVANT_FUNCTIONALITY_CONFIRMED
    assert res.canonical_hypothesis.decision == HypothesisDecision.NO_RELEVANT_FUNCTIONALITY


def test_06_hypothesis_calibrated_to_no_relevant_on_explicit_irrelevant_target():
    """Requirement 6: HYPOTHESIS -> NO_RELEVANT_FUNCTIONALITY on explicit irrelevant target (TNR protection)."""
    cand = make_valid_candidate(decision="HYPOTHESIS", supporting_evidence_ids=[])
    state = make_irrelevant_evidence_state()

    res = deterministic_decide(cand, state)

    assert res.is_valid is True
    assert res.final_decision == HypothesisDecision.NO_RELEVANT_FUNCTIONALITY
    assert res.decision_changed is True
    assert res.predicate_identifier == DecisionPredicate.NO_RELEVANT_FUNCTIONALITY_IRRELEVANT_TARGET
    assert res.canonical_hypothesis.decision == HypothesisDecision.NO_RELEVANT_FUNCTIONALITY


def test_07_insufficient_evidence_calibrated_to_no_relevant_on_explicit_irrelevant_target():
    """Requirement 7: INSUFFICIENT_EVIDENCE -> NO_RELEVANT_FUNCTIONALITY on explicit irrelevant target."""
    cand = make_valid_candidate(decision="INSUFFICIENT_EVIDENCE", supporting_evidence_ids=[])
    state = make_irrelevant_evidence_state()

    res = deterministic_decide(cand, state)

    assert res.is_valid is True
    assert res.final_decision == HypothesisDecision.NO_RELEVANT_FUNCTIONALITY
    assert res.decision_changed is True
    assert res.predicate_identifier == DecisionPredicate.NO_RELEVANT_FUNCTIONALITY_IRRELEVANT_TARGET
    assert res.canonical_hypothesis.decision == HypothesisDecision.NO_RELEVANT_FUNCTIONALITY


def test_08_no_relevant_calibrated_to_insufficient_evidence_on_explicit_relevant_target():
    """Requirement 8: NO_RELEVANT_FUNCTIONALITY -> INSUFFICIENT_EVIDENCE on explicit relevant target (reduces abstention)."""
    cand = make_valid_candidate(decision="NO_RELEVANT_FUNCTIONALITY", supporting_evidence_ids=[])
    state = make_evidence_state()  # Relevant target

    res = deterministic_decide(cand, state)

    assert res.is_valid is True
    assert res.final_decision == HypothesisDecision.INSUFFICIENT_EVIDENCE
    assert res.decision_changed is True
    assert res.predicate_identifier == DecisionPredicate.INSUFFICIENT_EVIDENCE_RELEVANT_FUNCTIONALITY
    assert res.canonical_hypothesis.decision == HypothesisDecision.INSUFFICIENT_EVIDENCE


# ===========================================================================
# 9-13: Fail-Closed & Robustness Boundary Tests
# ===========================================================================

def test_09_unsupported_decision_fails_closed():
    """Requirement 9: unsupported decision -> fail closed."""
    # We bypass Pydantic enum validation by mocking or raw object
    cand = make_valid_candidate(decision="HYPOTHESIS")
    cand.__dict__["decision"] = "UNKNOWN_OR_VULNERABLE"
    state = make_evidence_state()

    res = deterministic_decide(cand, state)

    assert res.is_valid is False
    assert res.final_decision is None
    assert res.predicate_identifier == DecisionPredicate.FAIL_CLOSED_UNSUPPORTED_DECISION


def test_10_confirmed_decision_fails_closed():
    """Requirement 10: CONFIRMED -> fail closed."""
    cand = make_valid_candidate(decision="HYPOTHESIS")
    cand.__dict__["decision"] = "CONFIRMED"
    state = make_evidence_state()

    res = deterministic_decide(cand, state)

    assert res.is_valid is False
    assert res.final_decision is None
    assert res.predicate_identifier == DecisionPredicate.FAIL_CLOSED_FORBIDDEN_CONFIRMED


def test_11_malformed_candidate_fails_closed():
    """Requirement 11: malformed candidate (None) -> fail closed."""
    state = make_evidence_state()

    res = deterministic_decide(None, state)

    assert res.is_valid is False
    assert res.final_decision is None
    assert res.predicate_identifier == DecisionPredicate.FAIL_CLOSED_MALFORMED_CANDIDATE


def test_12_missing_predicate_state_fails_closed():
    """Requirement 12: missing predicate state -> fail closed."""
    cand = make_valid_candidate()

    res1 = deterministic_decide(cand, None)
    assert res1.is_valid is False
    assert res1.predicate_identifier == DecisionPredicate.FAIL_CLOSED_MISSING_PREDICATE_STATE

    res2 = deterministic_decide(cand, EvidenceState(channel_a=None, target_asset=None))
    assert res2.is_valid is False
    assert res2.predicate_identifier == DecisionPredicate.FAIL_CLOSED_MISSING_PREDICATE_STATE


def test_13_invalid_or_fabricated_evidence_id_fails_closed():
    """Requirement 13: invalid/fabricated evidence ID -> fail closed."""
    # Cross-namespace CHK in supporting_evidence_ids fails immediately in Layer 0
    cand = make_valid_candidate(supporting_evidence_ids=["CHK-DOC-001"])
    state = make_evidence_state()

    res = deterministic_decide(cand, state)

    assert res.is_valid is False
    assert res.predicate_identifier == DecisionPredicate.FAIL_CLOSED_INVALID_EVIDENCE


# ===========================================================================
# 14-17: Idempotency, Immutability, & Evidence Preservation
# ===========================================================================

def test_14_repeated_identical_input_produces_identical_decision():
    """Requirement 14: repeated identical input -> identical final decision."""
    cand = make_valid_candidate(decision="NO_RELEVANT_FUNCTIONALITY")
    state = make_evidence_state()

    res1 = deterministic_decide(cand, state)
    res2 = deterministic_decide(cand, state)

    assert res1.final_decision == res2.final_decision
    assert res1.predicate_identifier == res2.predicate_identifier
    assert res1.decision_changed == res2.decision_changed
    assert res1.canonical_hypothesis.model_dump() == res2.canonical_hypothesis.model_dump()


def test_15_all_non_decision_s0_fields_remain_byte_identical():
    """Requirement 15: all non-decision S0 fields remain byte-identical."""
    cand = make_valid_candidate(
        decision="NO_RELEVANT_FUNCTIONALITY",
        invariant="Exact invariant string 123",
        evidence_gap="Exact evidence gap 456",
        affected_target="/api/v1/exact/path",
        supporting_evidence_ids=["FACT-001"],
        methodology_references=["CHK-001"],
        experiment_proposal="Observation supporting: 200. Observation falsifying: 403.",
    )
    state = make_evidence_state()

    res = deterministic_decide(cand, state)
    out = res.canonical_hypothesis

    assert out.decision == HypothesisDecision.INSUFFICIENT_EVIDENCE  # Changed
    # Everything else byte-identical:
    assert out.invariant == cand.invariant
    assert out.evidence_gap == cand.evidence_gap
    assert out.affected_target == cand.affected_target
    assert out.supporting_evidence_ids == cand.supporting_evidence_ids
    assert out.methodology_references == cand.methodology_references
    assert out.experiment_proposal == cand.experiment_proposal
    assert out.reasoning_summary == cand.reasoning_summary
    assert out.category == cand.category
    assert out.asset_id == cand.asset_id


def test_16_no_evidence_citation_substitution():
    """Requirement 16: no evidence citation substitution."""
    cand = make_valid_candidate(supporting_evidence_ids=["FACT-001"])
    state = make_evidence_state()

    res = deterministic_decide(cand, state)
    assert res.canonical_hypothesis.supporting_evidence_ids == ["FACT-001"]


def test_17_no_semantic_rewriting():
    """Requirement 17: no semantic rewriting of invariant or experiment proposal."""
    cand = make_valid_candidate(
        invariant="Raw unedited invariant",
        experiment_proposal="Observation supporting hypothesis: status 200. Observation disproving hypothesis: status 403.",
    )
    state = make_evidence_state()

    res = deterministic_decide(cand, state)
    assert res.canonical_hypothesis.invariant == "Raw unedited invariant"
    assert res.canonical_hypothesis.experiment_proposal == "Observation supporting hypothesis: status 200. Observation disproving hypothesis: status 403."


# ===========================================================================
# 18-24: Determinism & Purity Checks (No Ground Truth, No Classifiers, No Prose Inference)
# ===========================================================================

def test_18_no_ground_truth_access():
    """Requirement 18: no ground-truth access in decision policy module or signatures."""
    sig = inspect.signature(deterministic_decide)
    params = list(sig.parameters.keys())
    assert "ground_truth" not in params
    assert "is_vulnerable" not in params
    assert "label" not in params

    # Also inspect EvidenceState fields
    fields = EvidenceState.model_fields.keys()
    assert "ground_truth" not in fields
    assert "label" not in fields


def test_19_no_probability_or_confidence_threshold_access():
    """Requirement 19: no probability/confidence threshold access."""
    # Ensure no confidence or score parameters exist in deterministic_decide
    sig = inspect.signature(deterministic_decide)
    assert "confidence" not in sig.parameters
    assert "threshold" not in sig.parameters
    assert "score" not in sig.parameters


def test_20_no_learned_classifier_import_or_use():
    """Requirement 20: no learned classifier is imported or invoked."""
    import src.engine.decision_policy as dp
    module_source = inspect.getsource(dp)
    for forbidden in ["sklearn", "torch", "tensorflow", "xgboost", "lightgbm", "transformers"]:
        assert forbidden not in module_source, f"Forbidden learned classifier library detected: {forbidden}"


def test_21_relevance_predicate_uses_only_structured_canonical_inputs():
    """Requirement 21: relevance predicate uses only structured canonical inputs."""
    # State with mutability=READ_ONLY and no deltas is False
    irrel_state = make_irrelevant_evidence_state()
    assert is_relevant_functionality(irrel_state) is False

    # State with STATE_CHANGING is True
    rel_state = make_evidence_state(application_mutability="STATE_CHANGING")
    assert is_relevant_functionality(rel_state) is True

    # State with READ_ONLY but has_privilege_level_delta=True is True
    priv_state = make_evidence_state(application_mutability="READ_ONLY", has_privilege_level_delta=True)
    assert is_relevant_functionality(priv_state) is True


def test_22_discriminating_evidence_predicate_uses_only_structured_canonical_inputs():
    """Requirement 22: discriminating-evidence predicate uses only structured canonical inputs."""
    # Empty empirical evidence -> absent
    empty_state = make_evidence_state(observed_facts=[])
    assert is_discriminating_evidence_absent(empty_state) is True

    # Populated empirical evidence -> not absent
    full_state = make_evidence_state(observed_facts=[{"fact_id": "FACT-001", "statement": "Observed fact"}])
    assert is_discriminating_evidence_absent(full_state) is False


def test_23_candidate_prose_cannot_alter_is_relevant_functionality():
    """Requirement 23: candidate prose cannot alter is_relevant_functionality."""
    state = make_irrelevant_evidence_state()

    # Even if candidate writes "CRITICAL VULNERABILITY DETECTED" in reasoning summary
    cand = make_valid_candidate(
        decision="HYPOTHESIS",
        invariant="CRITICAL VULNERABILITY INJECTED",
    )
    cand.reasoning_summary = "This endpoint is definitely relevant and vulnerable to injection!"

    res = deterministic_decide(cand, state)
    # Must still calibrate to NO_RELEVANT_FUNCTIONALITY because structured state is irrelevant
    assert res.final_decision == HypothesisDecision.NO_RELEVANT_FUNCTIONALITY


def test_24_candidate_prose_cannot_alter_is_discriminating_evidence_absent():
    """Requirement 24: candidate prose cannot alter is_discriminating_evidence_absent."""
    # Evidence state has zero empirical facts
    state = make_evidence_state(observed_facts=[])
    assert is_discriminating_evidence_absent(state) is True

    # Even if candidate writes "All discriminating evidence was completely observed."
    cand = make_valid_candidate()
    cand.evidence_gap = "Zero missing observations; all discriminating evidence was completely observed."

    # Predicate function takes EvidenceState only and ignores candidate prose completely
    assert is_discriminating_evidence_absent(state) is True


# ===========================================================================
# 25-31: Single-Factor Isolation & Compute Envelope Checks
# ===========================================================================

def test_25_i1_is_not_called_schema_is_strictly_none():
    """Requirement 25 & 31: I1 is not called; schema is strictly None (no format={...})."""
    captured_schema = "SENTINEL"

    def mock_caller(prompt: str, schema: Any) -> str:
        nonlocal captured_schema
        captured_schema = schema
        return json.dumps({
            "decision": "NO_RELEVANT_FUNCTIONALITY",
            "invariant": "Standard invariant",
            "evidence_gap": "None",
            "affected_target": "/api/v1/test",
            "supporting_evidence_ids": [],
            "methodology_references": [],
            "reasoning_summary": "Clean",
            "experiment_proposal": "None",
        })

    runner = ReasoningRunner(llm_caller=mock_caller)
    state = make_evidence_state()
    res = runner.execute_i5_generation(
        prompt="Test prompt",
        channel_a=state.channel_a,
        retrieved_evidence=state.retrieved_evidence,
        target_asset=state.target_asset,
        category_id="API-BOLA-001",
    )

    assert captured_schema is None, f"I5 violated isolation: passed schema={captured_schema}"
    assert res.classification.is_valid is True
    assert res.final_decision == HypothesisDecision.INSUFFICIENT_EVIDENCE.value


def test_26_i2_is_not_called_no_namespace_partitioning():
    """Requirement 26: I2 is not called; prompt has no epistemic namespace partitioning."""
    runner = ReasoningRunner()
    prompt = runner.build_i5_decision_prompt(
        target_asset={"asset_id": "AST-01", "method": "GET", "normalized_path": "/test"},
        category_id="API-BOLA-001",
        retrieved_evidence=[{"fact_id": "FACT-001", "statement": "Target observation"}],
    )

    assert "<empirical_target_evidence>" not in prompt
    assert "<security_testing_methodology>" not in prompt
    assert "empirical_fact_ids" not in prompt
    assert "methodology_chunk_ids" not in prompt


def test_27_i3_is_not_called_no_counterfactual_resolver():
    """Requirement 27: I3 is not called; no counterfactual templates."""
    runner = ReasoningRunner()
    prompt = runner.build_i5_decision_prompt(
        target_asset={"asset_id": "AST-01", "method": "GET", "normalized_path": "/test"},
        category_id="API-BOLA-001",
        retrieved_evidence=[{"fact_id": "FACT-001", "statement": "Target observation"}],
    )

    assert "COUNTERFACTUAL REASONING INSTRUCTIONS" not in prompt
    assert "EVALUATION FRAMEWORK (DO NOT ASSUME A VULNERABILITY EXISTS)" not in prompt
    assert "COUNTERFACTUAL VIOLATION CONDITION" not in prompt


def test_28_i4_is_not_called_no_bair_prompt_or_extractor():
    """Requirement 28: I4 is not called; no BAIR XML prompt or extractor."""
    runner = ReasoningRunner()
    prompt = runner.build_i5_decision_prompt(
        target_asset={"asset_id": "AST-01", "method": "GET", "normalized_path": "/test"},
        category_id="API-BOLA-001",
        retrieved_evidence=[{"fact_id": "FACT-001", "statement": "Target observation"}],
    )

    assert "<bair>" not in prompt
    assert "</bair>" not in prompt
    assert "BOUNDED ANALYTICAL INFERENCE REPRESENTATION" not in prompt


def test_29_i6_is_not_called_no_handoff_serializer():
    """Requirement 29: I6 is not called; no 3B->7B invariant handoff serializer invoked."""
    pack = LosslessStructuralPack(
        asset_id="AST-01",
        endpoint_id="EP-01",
        route_template="/api/test",
        http_method="GET",
        application_mutability="READ_ONLY",
        observed_facts=[],
    )
    handoff = CascadeHandoffPacket(
        channel_a_structural=pack,
        validated_triage=None,
        routing_decision=DeterministicRoutingDecision(
            route_to_7b=True,
            reason="Unit test",
            escalate=False,
            has_high_risk_signal=False,
            fail_safe_triggered=False,
        ),
        provenance_hash="0" * 64,
    )

    ctx = ReasoningContextBuilder.build_context(
        handoff_packet=handoff,
        model_identifier="qwen2.5-coder:7b",
        cascade_mode=TRACK_D,
        enable_i5_decision_policy=True,
    )
    assert ctx.provenance_metadata.get("i5_decision_policy_enabled") is True
    assert ctx.provenance_metadata.get("i6_handoff_enabled") is None


def test_30_exactly_one_llm_call():
    """Requirement 30: exactly one LLM inference call; no second LLM arbitration."""
    call_count = 0

    def mock_caller(prompt: str, schema: Any) -> str:
        nonlocal call_count
        call_count += 1
        return json.dumps({
            "decision": "HYPOTHESIS",
            "invariant": "INV-001",
            "evidence_gap": "GAP-001",
            "affected_target": "/api/test",
            "supporting_evidence_ids": ["FACT-001"],
            "methodology_references": [],
            "reasoning_summary": "Analysis",
            "experiment_proposal": "Observation supporting: 200. Observation disproving: 403.",
            "experiment_action": "SUBSTITUTE_RESOURCE_IDENTIFIER",
            "supporting_outcome": "HTTP_200_OK",
            "disproving_outcome": "HTTP_403_FORBIDDEN",
        })

    runner = ReasoningRunner(llm_caller=mock_caller)
    state = make_evidence_state()
    res = runner.execute_i5_generation(
        prompt="Test prompt",
        channel_a=state.channel_a,
        retrieved_evidence=state.retrieved_evidence,
        target_asset=state.target_asset,
        category_id="API-BOLA-001",
    )

    assert call_count == 1, f"Expected exactly 1 LLM call, got {call_count}"
    assert res.classification.is_valid is True
    assert res.final_decision == HypothesisDecision.HYPOTHESIS.value
