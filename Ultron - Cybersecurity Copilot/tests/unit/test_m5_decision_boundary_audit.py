"""
Milestone M5 Phase 6.3 — Targeted Negative-Control and Decision-Boundary Audit Regression Tests.

Deterministic test suite enforcing decision-boundary invariants:
1. Patched target evidence alone cannot cause relevant-functionality state corruption.
2. VAPT methodology alone cannot force HYPOTHESIS without discriminating target empirical evidence.
3. I5 never promotes non-HYPOTHESIS candidates to HYPOTHESIS and strictly enforces bounded falsification.
4. Target evidence is strictly bound and verified: non-existent FACT IDs cause fail-closed rejection.
"""

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
    BairJsonObject,
    HypothesisDecision,
    HypothesisModelOutput,
)
from src.evidence.cascade_models import LosslessStructuralPack


def _create_clean_channel_a(
    route: str = "/api/v1/invoices/{id}",
    method: str = "GET",
    mutability: str = "READ_ONLY",
    params: Optional[List[Dict[str, Any]]] = None,
    identities: Optional[List[Dict[str, Any]]] = None,
    facts: Optional[List[Dict[str, Any]]] = None,
) -> LosslessStructuralPack:
    """Helper to construct a canonical LosslessStructuralPack."""
    return LosslessStructuralPack(
        schema_version="2.0.0",
        asset_id="ASSET-SAAS_BILLING-INV-DETAILS-01",
        endpoint_id="EP-SCEN-SAAS_BILLING-INV-DETAILS-PATCH-01",
        route_template=route,
        http_method=method,
        application_mutability=mutability,
        parameter_lineage=params if params is not None else [
            {"location": "path", "param_name": "id", "param_type": "string"}
        ],
        identity_matrix=identities if identities is not None else [
            {"identity_id": "user_a", "role": "customer"},
            {"identity_id": "user_b", "role": "customer"},
        ],
        has_privilege_level_delta=False,
        has_cross_identity_object_access_success=False,
        has_observed_contradictions=False,
        observed_facts=facts if facts is not None else [
            {
                "fact_id": "FACT-SAAS_BILLING-INV-DETAILS-DOC",
                "certainty": "DOCUMENTED",
                "statement": "GET /api/v1/invoices/{id} retrieves billing invoice records. Requires active customer session.",
                "source_tool": "openapi",
            }
        ],
        raw_body_sample="",
    )


def _create_valid_candidate(
    decision: HypothesisDecision = HypothesisDecision.HYPOTHESIS,
    supporting_facts: Optional[List[str]] = None,
    methodology_refs: Optional[List[str]] = None,
    proposal: Optional[str] = None,
) -> HypothesisModelOutput:
    """Helper to construct a canonical HypothesisModelOutput."""
    return HypothesisModelOutput(
        decision=decision,
        invariant="Object access must verify that the requesting identity owns or is explicitly authorized to access the specific target resource identifier.",
        evidence_gap="The evidence does not demonstrate explicit server-side object ownership verification.",
        affected_target="/api/v1/invoices/{id}",
        supporting_evidence_ids=supporting_facts if supporting_facts is not None else ["FACT-SAAS_BILLING-INV-DETAILS-DOC"],
        methodology_references=methodology_refs if methodology_refs is not None else ["CHK-DOC-PLATFORM-INV-01-002-01"],
        experiment_proposal=proposal if proposal is not None else (
            "Substitute a foreign object identifier in the request and observe if the response is HTTP 403 Forbidden or 404 Not Found. "
            "If the response is 200 OK with foreign object contents, the hypothesis is confirmed."
        ),
    )


# ===========================================================================
# 1. Patched Evidence State Corruption Prevention Tests
# ===========================================================================

def test_patched_negative_control_static_endpoint_is_not_relevant():
    """Negative control static endpoint (no params, single/no identity) evaluates is_relevant_functionality=False."""
    pack = _create_clean_channel_a(
        route="/pricing",
        method="GET",
        mutability="READ_ONLY",
        params=[],
        identities=[],
        facts=[{"fact_id": "FACT-PUBLIC-PRICING", "certainty": "DOCUMENTED", "statement": "Public static pricing"}],
    )
    ev_state = EvidenceState(
        channel_a=pack,
        target_asset={"application_mutability": "READ_ONLY", "parameters": [], "identities": []},
        category_id="API-AUTH-NONE",
        empirical_evidence_present=True,
    )
    assert not is_relevant_functionality(ev_state)

    # Even if model erroneously outputs HYPOTHESIS, policy forces NO_RELEVANT_FUNCTIONALITY
    cand = _create_valid_candidate(
        decision=HypothesisDecision.HYPOTHESIS,
        supporting_facts=["FACT-PUBLIC-PRICING"],
    )
    res = deterministic_decide(candidate=cand, evidence_state=ev_state)
    assert res.final_decision == HypothesisDecision.NO_RELEVANT_FUNCTIONALITY
    assert res.predicate_identifier == DecisionPredicate.NO_RELEVANT_FUNCTIONALITY_IRRELEVANT_TARGET
    assert res.decision_changed is True


def test_patched_evidence_does_not_corrupt_class1_structural_predicates():
    """Patched evidence with neutral OpenAPI documentation leaves Class-1 structural deltas False."""
    pack = _create_clean_channel_a()
    assert pack.has_privilege_level_delta is False
    assert pack.has_cross_identity_object_access_success is False
    assert pack.has_observed_contradictions is False
    assert pack.status_code_changed_under_different_role is False
    assert pack.has_unauthenticated_success is False


# ===========================================================================
# 2. VAPT Methodology Anchoring & Isolation Tests
# ===========================================================================

def test_vapt_methodology_alone_without_target_empirical_facts_fails_closed():
    """VAPT methodology references (CHK-*) cannot ground a HYPOTHESIS if empirical facts are absent."""
    pack = _create_clean_channel_a(facts=[])
    ev_state = EvidenceState(
        channel_a=pack,
        target_asset={"application_mutability": "READ_ONLY", "parameters": [{"param_name": "id"}], "identities": [{"identity_id": "user_a"}, {"identity_id": "user_b"}]},
        category_id="API-BOLA-001",
        empirical_evidence_present=False,  # No empirical traffic facts
    )

    # Candidate has methodology references but empty supporting_evidence_ids
    cand = _create_valid_candidate(
        decision=HypothesisDecision.HYPOTHESIS,
        supporting_facts=[],
        methodology_refs=["CHK-DOC-PLATFORM-INV-01-002-01"],
    )

    assert not is_empirical_evidence_grounded(cand, ev_state)

    res = deterministic_decide(candidate=cand, evidence_state=ev_state)
    assert not res.is_valid
    assert res.final_decision is None
    assert res.predicate_identifier == DecisionPredicate.FAIL_CLOSED_GROUNDING_REJECTION


def test_vapt_chk_id_in_supporting_evidence_ids_fails_closed_layer_0():
    """Cross-namespace leakage of CHK ID into supporting_evidence_ids fails closed immediately."""
    pack = _create_clean_channel_a()
    ev_state = EvidenceState(
        channel_a=pack,
        target_asset={"parameters": [{"param_name": "id"}], "identities": [{"identity_id": "user_a"}, {"identity_id": "user_b"}]},
        category_id="API-BOLA-001",
        empirical_evidence_present=True,
    )

    cand = _create_valid_candidate(
        decision=HypothesisDecision.HYPOTHESIS,
        supporting_facts=["CHK-DOC-PLATFORM-INV-01-002-01"],  # ILLEGAL: CHK in facts
    )

    res = deterministic_decide(candidate=cand, evidence_state=ev_state)
    assert not res.is_valid
    assert res.final_decision is None
    assert res.predicate_identifier == DecisionPredicate.FAIL_CLOSED_INVALID_EVIDENCE


# ===========================================================================
# 3. I5 Decision Policy Predicate Invariant Tests
# ===========================================================================

def test_i5_never_promotes_insufficient_evidence_to_hypothesis():
    """Candidate INSUFFICIENT_EVIDENCE on relevant functionality remains INSUFFICIENT_EVIDENCE."""
    pack = _create_clean_channel_a()
    ev_state = EvidenceState(
        channel_a=pack,
        target_asset={"parameters": [{"param_name": "id"}], "identities": [{"identity_id": "user_a"}, {"identity_id": "user_b"}]},
        category_id="API-BOLA-001",
        empirical_evidence_present=True,
    )

    cand = _create_valid_candidate(
        decision=HypothesisDecision.INSUFFICIENT_EVIDENCE,
        supporting_facts=["FACT-SAAS_BILLING-INV-DETAILS-DOC"],
        methodology_refs=["CHK-DOC-PLATFORM-INV-01-002-01"],
    )

    res = deterministic_decide(candidate=cand, evidence_state=ev_state)
    assert res.is_valid
    assert res.final_decision == HypothesisDecision.INSUFFICIENT_EVIDENCE
    assert res.predicate_identifier == DecisionPredicate.INSUFFICIENT_EVIDENCE_CONFIRMED
    assert res.decision_changed is False


def test_i5_rejects_hypothesis_with_incomplete_falsification_plan():
    """HYPOTHESIS candidate missing supporting branch in falsification plan fails closed."""
    pack = _create_clean_channel_a()
    ev_state = EvidenceState(
        channel_a=pack,
        target_asset={"parameters": [{"param_name": "id"}], "identities": [{"identity_id": "user_a"}, {"identity_id": "user_b"}]},
        category_id="API-BOLA-001",
        empirical_evidence_present=True,
    )

    # Missing supporting branch (only mentions 403/404 disproving)
    incomplete_proposal = "Substitute a foreign object identifier in the request and observe if the response is HTTP 403 Forbidden or 404 Not Found."
    assert not is_falsification_complete(incomplete_proposal)

    cand = _create_valid_candidate(
        decision=HypothesisDecision.HYPOTHESIS,
        proposal=incomplete_proposal,
    )

    res = deterministic_decide(candidate=cand, evidence_state=ev_state)
    assert not res.is_valid
    assert res.final_decision is None
    assert res.predicate_identifier == DecisionPredicate.FAIL_CLOSED_INCOMPLETE_HYPOTHESIS


def test_bair_json_schema_fails_closed_on_one_sided_falsification():
    """BairJsonObject validator strictly rejects one-sided falsification plans."""
    with pytest.raises(ValueError, match=r"(Falsification plan missing supporting observation specification|Legacy free-text falsification_plan cannot authorize a HYPOTHESIS)"):
        BairJsonObject(
            invariant="Object access must verify ownership.",
            evidence_gap="Missing verification.",
            affected_target="/api/v1/invoices/{id}",
            decision=HypothesisDecision.HYPOTHESIS,
            empirical_facts=["FACT-SAAS_BILLING-INV-DETAILS-DOC"],
            methodology_references=["CHK-DOC-PLATFORM-INV-01-002-01"],
            falsification_plan="Substitute a foreign object identifier in the request and observe if the response is HTTP 403 Forbidden or 404 Not Found.",
        )


# ===========================================================================
# 4. Target Evidence Binding & Non-Existent Fact Rejection Tests
# ===========================================================================

def test_i5_rejects_hypothesis_citing_unobserved_fact_id():
    """Candidate citing a FACT ID not present in channel_a observed_facts fails closed."""
    pack = _create_clean_channel_a(
        facts=[{"fact_id": "FACT-REAL-001", "certainty": "DOCUMENTED", "statement": "Real fact"}]
    )
    ev_state = EvidenceState(
        channel_a=pack,
        target_asset={"parameters": [{"param_name": "id"}], "identities": [{"identity_id": "user_a"}, {"identity_id": "user_b"}]},
        category_id="API-BOLA-001",
        empirical_evidence_present=True,
    )

    cand = _create_valid_candidate(
        decision=HypothesisDecision.HYPOTHESIS,
        supporting_facts=["FACT-FABRICATED-999"],  # Non-existent fact
    )

    assert not is_empirical_evidence_grounded(cand, ev_state)

    res = deterministic_decide(candidate=cand, evidence_state=ev_state)
    assert not res.is_valid
    assert res.final_decision is None
    assert res.predicate_identifier == DecisionPredicate.FAIL_CLOSED_GROUNDING_REJECTION


def test_target_evidence_facts_strictly_bound_in_canonical_s0_adaptation():
    """Evidence grounding is preserved and immutable throughout adaptation."""
    cand = _create_valid_candidate(
        supporting_facts=["FACT-SAAS_BILLING-INV-DETAILS-DOC"]
    )
    assert cand.supporting_evidence_ids == ["FACT-SAAS_BILLING-INV-DETAILS-DOC"]
    assert "CHK-DOC-PLATFORM-INV-01-002-01" in cand.methodology_references
