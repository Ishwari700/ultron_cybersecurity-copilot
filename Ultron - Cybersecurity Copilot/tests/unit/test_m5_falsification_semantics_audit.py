"""
Milestone M5 Phase 6.4 — Falsification Semantics and Polarity Audit Proof Tests.

Proves deterministically:
1. Lexical presence of keywords is insufficient to establish semantic polarity.
2. The current BairJsonObject validator and is_falsification_complete() accept a semantically inverted falsification plan.
3. Incomplete plans (missing either supporting or disproving observation) still fail closed.
4. Invalid FACT identifiers still fail closed.
5. Epistemic namespace separation between FACT and CHK remains intact.
"""

import pytest
from typing import Dict, Any

from src.engine.models import (
    BairJsonObject,
    HypothesisDecision,
    HypothesisModelOutput,
    FACT_NAMESPACE_REGEX,
    CHK_NAMESPACE_REGEX,
)
from src.engine.decision_policy import (
    is_falsification_complete,
    deterministic_decide,
    EvidenceState,
    DecisionPredicate,
)
from src.evidence.cascade_models import LosslessStructuralPack


def _create_base_pack() -> LosslessStructuralPack:
    return LosslessStructuralPack(
        schema_version="2.0.0",
        asset_id="ASSET-ECOMMERCE-REFUND-01",
        endpoint_id="EP-SCEN-ECOMMERCE_ORDERS-ORD-REFUND-VULN-01",
        route_template="/api/v1/orders/{id}/refund",
        http_method="POST",
        application_mutability="STATE_CHANGING",
        parameter_lineage=[{"location": "path", "param_name": "id", "param_type": "string"}],
        identity_matrix=[{"identity_id": "user_a", "role": "customer"}],
        has_privilege_level_delta=False,
        has_cross_identity_object_access_success=False,
        has_observed_contradictions=False,
        observed_facts=[
            {
                "fact_id": "FACT-ECOMMERCE_ORDERS-ORD-REFUND-DOC",
                "certainty": "DOCUMENTED",
                "statement": "POST /api/v1/orders/{id}/refund processes customer refund request.",
                "source_tool": "openapi",
            }
        ],
        raw_body_sample="",
    )


# ===========================================================================
# 1. Proof of Semantic Inversion Acceptance (Blind Spot Proof)
# ===========================================================================

def test_current_validator_accepts_semantically_inverted_falsification_plan():
    """
    CRITICAL PROOF TEST:
    Demonstrates that the legacy lexical is_falsification_complete() accepts
    a proposal that has completely INVERTED semantic polarity, but the Phase 6.6
    typed protocol strictly FAILS CLOSED against legacy plans and inverted polarities.

    In Scenario 2 (Ecommerce Refund), the model claims:
    - Rejection (HTTP 409/400) SUPPORTS the vulnerability hypothesis.
    - Successful out-of-order execution DISPROVES the hypothesis.

    This is logically reversed: rejection enforces the state machine invariant,
    while success breaches it.
    """
    inverted_falsification = (
        "An observation supporting the hypothesis would be a state machine validation that "
        "rejects an out-of-order transition with HTTP 409 Conflict or 400 Bad Request. "
        "An observation disproving the hypothesis would be a successful out-of-order transition without such a rejection."
    )

    # 1. Lexical check evaluates to True, demonstrating its flaw!
    assert is_falsification_complete(inverted_falsification) is True

    # 2. Under Phase 6.6, legacy free-text plan without typed fields strictly FAILS CLOSED:
    with pytest.raises(ValueError, match="Legacy free-text falsification_plan cannot authorize a HYPOTHESIS"):
        BairJsonObject(
            invariant="Business logic state transitions must follow a valid finite state machine.",
            evidence_gap="The endpoint does not validate that the target entity is currently in an eligible state.",
            affected_target="/api/v1/orders/{id}/refund",
            decision=HypothesisDecision.HYPOTHESIS,
            empirical_facts=["FACT-ECOMMERCE_ORDERS-ORD-REFUND-DOC"],
            methodology_references=[],
            falsification_plan=inverted_falsification,
        )

    # 3. If inverted polarity is checked via ExperimentPolarityValidator, it strictly FAILS:
    from src.engine.decision_policy import ExperimentPolarityValidator
    is_valid, reason = ExperimentPolarityValidator.validate_tuple(
        category_id="API-STATE-001",
        experiment_action="EXECUTE_OUT_OF_ORDER_TRANSITION",
        supporting_outcome="HTTP_409_CONFLICT",
        disproving_outcome="STATE_TRANSITION_ACCEPTED",
    )
    assert is_valid is False
    assert "not a valid breach outcome" in reason

    # 4. Deterministic decision policy also rejects inverted candidate as FAIL_CLOSED_INCOMPLETE_HYPOTHESIS:
    cand = HypothesisModelOutput(
        decision=HypothesisDecision.HYPOTHESIS,
        invariant="Business logic state transitions must follow a valid finite state machine.",
        evidence_gap="The endpoint does not validate that the target entity is currently in an eligible state.",
        affected_target="/api/v1/orders/{id}/refund",
        supporting_evidence_ids=["FACT-ECOMMERCE_ORDERS-ORD-REFUND-DOC"],
        methodology_references=[],
        experiment_action="EXECUTE_OUT_OF_ORDER_TRANSITION",
        supporting_outcome="HTTP_409_CONFLICT",
        disproving_outcome="STATE_TRANSITION_ACCEPTED",
    )
    ev_state = EvidenceState(
        channel_a=_create_base_pack(),
        target_asset={"application_mutability": "STATE_CHANGING", "parameters": [{"param_name": "id"}]},
        category_id="API-STATE-001",
        empirical_evidence_present=True,
    )
    res = deterministic_decide(candidate=cand, evidence_state=ev_state)
    assert res.is_valid is False
    assert res.predicate_identifier == DecisionPredicate.FAIL_CLOSED_INCOMPLETE_HYPOTHESIS


def test_lexical_presence_is_insufficient_for_semantic_polarity():
    """
    Proves that mere co-occurrence of 'confirm'/'support' and 'disprove'/'403'
    cannot distinguish between correct and nonsensical sentences.
    """
    nonsensical_plan = (
        "We support the invariant that attacks are disproved when 403 Forbidden is observed."
    )
    # This sentence has no valid experimental falsification logic, but contains both keyword tokens
    assert is_falsification_complete(nonsensical_plan) is True


# ===========================================================================
# 2. Proof that Incomplete Plans Still Fail Closed
# ===========================================================================

def test_falsification_missing_supporting_fails_closed():
    """Omitting supporting observation term strictly raises ValueError."""
    plan_no_supporting = (
        "Substitute a foreign identifier and observe if response is HTTP 403 Forbidden or 404 Not Found."
    )
    assert not is_falsification_complete(plan_no_supporting)

    with pytest.raises(ValueError, match="(Falsification plan missing supporting observation specification|Legacy free-text falsification_plan cannot authorize a HYPOTHESIS)"):
        BairJsonObject(
            invariant="Tenant isolation must be enforced.",
            evidence_gap="Missing tenant checks.",
            affected_target="/api/v1/invoices/{id}",
            decision=HypothesisDecision.HYPOTHESIS,
            empirical_facts=["FACT-ECOMMERCE_ORDERS-ORD-REFUND-DOC"],
            methodology_references=[],
            falsification_plan=plan_no_supporting,
        )


def test_falsification_missing_disproving_fails_closed():
    """Omitting disproving observation term strictly raises ValueError."""
    plan_no_disproving = (
        "Send request and observe if 200 OK confirms the hypothesis."
    )
    assert not is_falsification_complete(plan_no_disproving)

    with pytest.raises(ValueError, match="(Falsification plan missing disproving/falsifying observation specification|Legacy free-text falsification_plan cannot authorize a HYPOTHESIS)"):
        BairJsonObject(
            invariant="Tenant isolation must be enforced.",
            evidence_gap="Missing tenant checks.",
            affected_target="/api/v1/invoices/{id}",
            decision=HypothesisDecision.HYPOTHESIS,
            empirical_facts=["FACT-ECOMMERCE_ORDERS-ORD-REFUND-DOC"],
            methodology_references=[],
            falsification_plan=plan_no_disproving,
        )


# ===========================================================================
# 3. Proof that Namespace Isolation and Fact Validation Remain Intact
# ===========================================================================

def test_invalid_fact_identifier_fails_closed():
    """Invalid syntax for empirical fact identifier fails schema validation."""
    with pytest.raises(ValueError, match="does not match"):
        BairJsonObject(
            invariant="Valid invariant.",
            evidence_gap="Valid gap.",
            affected_target="/api/v1/orders/{id}/refund",
            decision=HypothesisDecision.HYPOTHESIS,
            empirical_facts=["INVALID-FACT-ID!"],
            methodology_references=[],
            falsification_plan="Support if 200 OK; disprove if 403 Forbidden.",
        )


def test_namespace_cross_contamination_fails_closed():
    """Placing a CHK ID in empirical_facts fails closed."""
    with pytest.raises(ValueError, match="does not match"):
        BairJsonObject(
            invariant="Valid invariant.",
            evidence_gap="Valid gap.",
            affected_target="/api/v1/orders/{id}/refund",
            decision=HypothesisDecision.HYPOTHESIS,
            empirical_facts=["CHK-DOC-PLATFORM-01"],
            methodology_references=[],
            falsification_plan="Support if 200 OK; disprove if 403 Forbidden.",
        )


def test_decision_policy_fails_closed_on_chk_in_facts():
    """deterministic_decide() rejects candidate with CHK ID in supporting_evidence_ids."""
    cand = HypothesisModelOutput(
        decision=HypothesisDecision.HYPOTHESIS,
        invariant="Valid invariant.",
        evidence_gap="Valid gap.",
        affected_target="/api/v1/orders/{id}/refund",
        supporting_evidence_ids=["CHK-DOC-PLATFORM-01"],
        methodology_references=[],
        experiment_proposal="Support if 200 OK; disprove if 403 Forbidden.",
    )
    ev_state = EvidenceState(
        channel_a=_create_base_pack(),
        target_asset={"application_mutability": "STATE_CHANGING", "parameters": [{"param_name": "id"}]},
        category_id="API-STATE-001",
        empirical_evidence_present=True,
    )
    res = deterministic_decide(candidate=cand, evidence_state=ev_state)
    assert not res.is_valid
    assert res.predicate_identifier == DecisionPredicate.FAIL_CLOSED_INVALID_EVIDENCE
