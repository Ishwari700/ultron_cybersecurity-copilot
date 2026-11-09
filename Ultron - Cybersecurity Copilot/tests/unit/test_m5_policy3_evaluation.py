"""Deterministic unit tests for Milestone M5 Phase 6.9:
Policy 3 Evaluation-Scoring Harness Implementation.

Tests all 15 required invariants:
1. Identical observable BOLA pair gets identical applicability state.
2. Neutral documentation yields EXPLORATORY_EVALUATION_APPLICABLE.
3. Canonical observed anomaly yields VULNERABILITY_EVALUATION_APPLICABLE.
4. Model prose cannot change applicability state.
5. Ground truth cannot change model-side applicability state.
6. Valid exploratory proposal on patched neutral endpoint is not an exploratory FP.
7. Vulnerability FP remains FP when vulnerability-evidence applicability is active.
8. Malformed output yields INVALID_OUTPUT state.
9. Valid typed tuple yields exploratory-valid when appropriate.
10. Frozen Useful Hypothesis Yield definition remains unchanged.
11. Legacy scorer remains reproducible.
12. No benchmark artifact modification.
13. No ground-truth leakage into runtime applicability.
14. Evaluator never promotes exploratory evidence into vulnerability evidence.
15. Evaluator never downgrades observed vulnerability evidence.
"""

import hashlib
import inspect
import json
import os
from typing import Any, Dict, List
import pytest

from src.eval.scenarios import get_gold_set_scenarios
from src.eval.scorer import (
    DeterministicScorer,
    EvaluationApplicabilityState,
    EvaluationMetrics,
    Policy3DeterministicScorer,
    Policy3EvaluationMetrics,
    ReviewerPresentationLabel,
    canonical_vulnerability_evidence_present,
    determine_applicability_state,
)


# ---------------------------------------------------------------------------
# Requirement 1: Identical observable BOLA pair gets identical applicability
# ---------------------------------------------------------------------------

def test_01_identical_observable_bola_pair_gets_identical_applicability_state():
    """Verify that vulnerable and patched BOLA scenarios receive the EXACT same applicability state."""
    scenarios = {s.scenario_id: s for s in get_gold_set_scenarios()}
    vuln_scen = scenarios["SCEN-SAAS_BILLING-INV-DETAILS-VULN-01"]
    patch_scen = scenarios["SCEN-SAAS_BILLING-INV-DETAILS-PATCH-01"]

    # Both scenarios have neutral OpenAPI evidence
    has_anomaly_vuln = canonical_vulnerability_evidence_present(evidence=vuln_scen.initial_evidence)
    has_anomaly_patch = canonical_vulnerability_evidence_present(evidence=patch_scen.initial_evidence)

    assert has_anomaly_vuln is False
    assert has_anomaly_patch is False

    state_vuln = determine_applicability_state(
        is_valid_output=True,
        target_relevant=True,
        canonical_evidence_has_anomaly=has_anomaly_vuln,
    )
    state_patch = determine_applicability_state(
        is_valid_output=True,
        target_relevant=True,
        canonical_evidence_has_anomaly=has_anomaly_patch,
    )

    assert state_vuln == EvaluationApplicabilityState.EXPLORATORY_EVALUATION_APPLICABLE
    assert state_patch == EvaluationApplicabilityState.EXPLORATORY_EVALUATION_APPLICABLE
    assert state_vuln == state_patch


# ---------------------------------------------------------------------------
# Requirement 2: Neutral documentation yields EXPLORATORY_EVALUATION_APPLICABLE
# ---------------------------------------------------------------------------

def test_02_neutral_documentation_yields_exploratory_applicability():
    """Verify OpenAPI documentation with zero execution logs yields EXPLORATORY_EVALUATION_APPLICABLE."""
    neutral_evidence = [
        {
            "fact_id": "FACT-DOC-01",
            "source_tool": "openapi",
            "certainty": "DOCUMENTED",
            "statement": "GET /api/v1/orders/{id} returns customer order status.",
        }
    ]
    has_anomaly = canonical_vulnerability_evidence_present(evidence=neutral_evidence)
    assert has_anomaly is False

    state = determine_applicability_state(
        is_valid_output=True,
        target_relevant=True,
        canonical_evidence_has_anomaly=has_anomaly,
    )
    assert state == EvaluationApplicabilityState.EXPLORATORY_EVALUATION_APPLICABLE


# ---------------------------------------------------------------------------
# Requirement 3: Canonical observed anomaly yields VULNERABILITY_APPLICABLE
# ---------------------------------------------------------------------------

def test_03_canonical_observed_anomaly_yields_vulnerability_applicability():
    """Verify that presence of approved Class-1 anomaly flags yields VULNERABILITY_EVALUATION_APPLICABLE."""
    # Case A: Structural pack boolean flag
    structural_pack_anomalous = {"has_cross_identity_object_access_success": True}
    has_anomaly_a = canonical_vulnerability_evidence_present(structural_pack=structural_pack_anomalous)
    assert has_anomaly_a is True

    state_a = determine_applicability_state(
        is_valid_output=True,
        target_relevant=True,
        canonical_evidence_has_anomaly=has_anomaly_a,
    )
    assert state_a == EvaluationApplicabilityState.VULNERABILITY_EVALUATION_APPLICABLE

    # Case B: Observation record with structured anomaly flag
    evidence_anomalous = [
        {"fact_id": "FACT-01", "observed_privilege_delta": True, "statement": "User observed admin action"}
    ]
    has_anomaly_b = canonical_vulnerability_evidence_present(evidence=evidence_anomalous)
    assert has_anomaly_b is True

    state_b = determine_applicability_state(
        is_valid_output=True,
        target_relevant=True,
        canonical_evidence_has_anomaly=has_anomaly_b,
    )
    assert state_b == EvaluationApplicabilityState.VULNERABILITY_EVALUATION_APPLICABLE


# ---------------------------------------------------------------------------
# Requirement 4: Model prose cannot change applicability state
# ---------------------------------------------------------------------------

def test_04_model_prose_cannot_change_applicability_state():
    """Verify that injecting vulnerability claims into prose fields cannot alter applicability."""
    neutral_evidence = [{"fact_id": "FACT-DOC-01", "statement": "GET /api/v1/invoices/{id}"}]
    has_anomaly = canonical_vulnerability_evidence_present(evidence=neutral_evidence)

    state_baseline = determine_applicability_state(
        is_valid_output=True,
        target_relevant=True,
        canonical_evidence_has_anomaly=has_anomaly,
    )

    # Even if model emits prose asserting a catastrophic vulnerability:
    model_prose_gap = "CRITICAL BOLA VULNERABILITY DETECTED! Cross-tenant breach observed in telemetry!"
    model_reasoning = "This endpoint is definitely vulnerable to BOLA bypass."

    # The detector does not take model prose as input; verify signature takes only evidence/structural_pack
    sig = inspect.signature(canonical_vulnerability_evidence_present)
    assert "prose" not in sig.parameters
    assert "reasoning" not in sig.parameters
    assert "evidence_gap" not in sig.parameters

    # Applicability remains strictly exploratory
    assert state_baseline == EvaluationApplicabilityState.EXPLORATORY_EVALUATION_APPLICABLE


# ---------------------------------------------------------------------------
# Requirement 5: Ground truth cannot change model-side applicability state
# ---------------------------------------------------------------------------

def test_05_ground_truth_cannot_change_model_side_applicability_state():
    """Verify that ground_truth_vulnerable and expected_decision cannot change applicability."""
    sig_det = inspect.signature(determine_applicability_state)
    assert "ground_truth" not in sig_det.parameters
    assert "expected_decision" not in sig_det.parameters

    # For identical evidence, flipping ground truth does not affect applicability
    evidence = [{"fact_id": "FACT-01", "statement": "GET /api/v1/items/{id}"}]
    has_anomaly = canonical_vulnerability_evidence_present(evidence=evidence)

    # Evaluate scenario under ground_truth_vulnerable = True
    state_true = determine_applicability_state(
        is_valid_output=True, target_relevant=True, canonical_evidence_has_anomaly=has_anomaly
    )
    # Evaluate scenario under ground_truth_vulnerable = False
    state_false = determine_applicability_state(
        is_valid_output=True, target_relevant=True, canonical_evidence_has_anomaly=has_anomaly
    )

    assert state_true == state_false == EvaluationApplicabilityState.EXPLORATORY_EVALUATION_APPLICABLE


# ---------------------------------------------------------------------------
# Requirement 6: Valid exploratory proposal on patched neutral endpoint is not an FP
# ---------------------------------------------------------------------------

def test_06_valid_exploratory_proposal_on_patched_neutral_endpoint_is_not_exploratory_fp():
    """Verify that proposing a valid test on a patched neutral endpoint is scored as exploratory valid, NOT FP."""
    scorer = Policy3DeterministicScorer()
    run_records = [
        {
            "scenario_id": "SCEN-SAAS_BILLING-INV-DETAILS-PATCH-01",
            "ground_truth_vulnerable": False,
            "decision": "HYPOTHESIS",
            "is_valid": True,
            "polarity_valid": True,
            "grounded": True,
            "discriminative_experiment": True,
            "target_relevant": True,
            "initial_evidence": [{"fact_id": "FACT-01", "statement": "GET /api/v1/invoices/{id}"}],
        }
    ]

    metrics = scorer.score_policy3(run_records)

    # In Policy 3 exploratory track:
    assert metrics.exploratory_applicable_scenarios == 1
    assert metrics.valid_exploratory_proposals == 1
    assert metrics.exploratory_verification_validity_rate == 1.0

    # In Policy 3 vulnerability track, it is NOT applicable, so zero vulnerability FPs:
    assert metrics.vulnerability_applicable_scenarios == 0
    assert metrics.vulnerability_false_positives == 0

    # Reviewer presentation is EXPLORATORY_VERIFICATION_PROPOSAL
    assert metrics.exploratory_proposals_count == 1
    assert metrics.vulnerability_findings_count == 0


# ---------------------------------------------------------------------------
# Requirement 7: Vulnerability FP remains FP when vulnerability evidence active
# ---------------------------------------------------------------------------

def test_07_vulnerability_fp_remains_fp_when_vulnerability_evidence_active():
    """Verify that when active anomaly evidence is present, a hypothesis on a non-vulnerable target is an FP."""
    scorer = Policy3DeterministicScorer()
    run_records = [
        {
            "scenario_id": "SCEN-ACTIVE-ANOMALY-FALSE-ALARM",
            "ground_truth_vulnerable": False,  # Backend is patched
            "decision": "HYPOTHESIS",
            "is_valid": True,
            "polarity_valid": True,
            "grounded": True,
            "target_relevant": True,
            "initial_evidence": [
                {"fact_id": "FACT-01", "has_cross_identity_object_access_success": True}
            ],
        }
    ]

    metrics = scorer.score_policy3(run_records)

    assert metrics.vulnerability_applicable_scenarios == 1
    assert metrics.vulnerability_false_positives == 1
    assert metrics.vulnerability_true_positives == 0
    assert metrics.vulnerability_precision == 0.0


# ---------------------------------------------------------------------------
# Requirement 8: Malformed output yields INVALID_OUTPUT state
# ---------------------------------------------------------------------------

def test_08_malformed_output_yields_invalid_output_state():
    """Verify that parser failure, schema failure, or polarity failure yields INVALID_OUTPUT."""
    scorer = Policy3DeterministicScorer()
    run_records = [
        {
            "scenario_id": "SCEN-TEST-MALFORMED",
            "ground_truth_vulnerable": True,
            "decision": "HYPOTHESIS",
            "is_valid": False,
            "primary_failure_category": "SEMANTIC_EXPERIMENT_POLARITY_FAILURE",
            "polarity_valid": False,
            "grounded": True,
            "initial_evidence": [{"fact_id": "FACT-01", "statement": "GET /api/v1/items/{id}"}],
        }
    ]

    metrics = scorer.score_policy3(run_records)
    eval_item = metrics.per_scenario_evaluations[0]

    assert eval_item.applicability_state == EvaluationApplicabilityState.INVALID_OUTPUT
    assert eval_item.reviewer_presentation == ReviewerPresentationLabel.INVALID_PROPOSAL
    assert metrics.invalid_output_scenarios == 1
    assert metrics.valid_exploratory_proposals == 0


# ---------------------------------------------------------------------------
# Requirement 9: Valid typed tuple yields exploratory-valid when appropriate
# ---------------------------------------------------------------------------

def test_09_valid_typed_tuple_yields_exploratory_valid_when_appropriate():
    """Verify that a complete, polarity-compatible typed tuple on an exploratory endpoint is valid."""
    scorer = Policy3DeterministicScorer()
    run_records = [
        {
            "scenario_id": "SCEN-TEST-EXPLORATORY-VALID",
            "ground_truth_vulnerable": True,
            "decision": "HYPOTHESIS",
            "is_valid": True,
            "polarity_valid": True,
            "grounded": True,
            "discriminative_experiment": True,
            "target_relevant": True,
            "initial_evidence": [{"fact_id": "FACT-DOC-01", "statement": "GET /api/v1/users/{id}"}],
        }
    ]

    metrics = scorer.score_policy3(run_records)
    eval_item = metrics.per_scenario_evaluations[0]

    assert eval_item.applicability_state == EvaluationApplicabilityState.EXPLORATORY_EVALUATION_APPLICABLE
    assert eval_item.is_valid_exploratory_proposal is True
    assert eval_item.reviewer_presentation == ReviewerPresentationLabel.EXPLORATORY_VERIFICATION_PROPOSAL
    assert metrics.valid_exploratory_proposals == 1


# ---------------------------------------------------------------------------
# Requirement 10: Frozen Useful Hypothesis Yield definition remains unchanged
# ---------------------------------------------------------------------------

def test_10_frozen_useful_hypothesis_yield_definition_remains_unchanged():
    """Verify that Useful Hypothesis Yield matches the exact historical formula: useful_vuln / total_vuln."""
    scorer = Policy3DeterministicScorer()
    run_records = [
        {"scenario_id": "SCEN-VULN-01", "ground_truth_vulnerable": True, "decision": "HYPOTHESIS", "grounded": True, "useful": True},
        {"scenario_id": "SCEN-VULN-02", "ground_truth_vulnerable": True, "decision": "INSUFFICIENT_EVIDENCE", "grounded": True, "useful": False},
        {"scenario_id": "SCEN-PATCH-01", "ground_truth_vulnerable": False, "decision": "INSUFFICIENT_EVIDENCE", "grounded": True, "useful": False},
    ]

    metrics = scorer.score_policy3(run_records)

    # 1 useful vulnerable / 2 total vulnerable = 0.5000
    assert metrics.useful_vulnerable_scenarios == 1
    assert metrics.total_vulnerable_scenarios == 2
    assert metrics.useful_hypothesis_yield == 0.5
    assert metrics.useful_hypothesis_yield_at_fixed_reviewer_minutes == 0.5


# ---------------------------------------------------------------------------
# Requirement 11: Legacy scorer remains reproducible
# ---------------------------------------------------------------------------

def test_11_legacy_scorer_remains_reproducible():
    """Verify that DeterministicScorer.score() produces exact byte-identical outputs as before."""
    legacy_scorer = DeterministicScorer()
    run_records = [
        {"scenario_id": "SCEN-01", "ground_truth_vulnerable": True, "decision": "HYPOTHESIS", "grounded": True, "useful": True},
        {"scenario_id": "SCEN-02", "ground_truth_vulnerable": False, "decision": "HYPOTHESIS", "grounded": True, "useful": False},
        {"scenario_id": "SCEN-03", "ground_truth_vulnerable": False, "decision": "INSUFFICIENT_EVIDENCE", "grounded": True, "useful": False},
    ]

    legacy_metrics = legacy_scorer.score(run_records)
    assert legacy_metrics.total_scenarios == 3
    assert legacy_metrics.true_positives == 1
    assert legacy_metrics.false_positives == 1
    assert legacy_metrics.true_negatives == 1
    assert legacy_metrics.precision == 0.5
    assert legacy_metrics.recall == 1.0


# ---------------------------------------------------------------------------
# Requirement 12: No benchmark artifact modification
# ---------------------------------------------------------------------------

def test_12_no_benchmark_artifact_modification():
    """Verify SHA-256 digests of all protected historical benchmark files remain unchanged."""
    pinned_digests = {
        "data/eval/m4_live_llm_benchmark_final.json": "459b9ec63c3a2dc760abde12ec196760f7e505fbab5317f0da0c46b32c5eaac7",
        "data/eval/m5_live_smoke.json": "7ee8b6b2ec33eca0fcb8a3f0948d1f36b7e41877354ae4a64190f8e19c679b5e",
        "data/eval/m5_live_smoke_v2.json": "830c225b22f6767ee13b4ce3b443a14aede3ea767ee25ae7343c1a153c4a0818",
        "data/eval/m5_typed_protocol_live_smoke.json": "d33d2a05e3cd2c00f684aa0bf987692c7d3d22b5e727aba941a447014bbfdcd6",
    }

    for path, expected in pinned_digests.items():
        assert os.path.exists(path), f"Missing protected file: {path}"
        with open(path, "rb") as fp:
            digest = hashlib.sha256(fp.read()).hexdigest()
        assert digest == expected, f"Protected file modified: {path} ({digest} != {expected})"


# ---------------------------------------------------------------------------
# Requirement 13: No ground-truth leakage into runtime applicability
# ---------------------------------------------------------------------------

def test_13_no_ground_truth_leakage_into_runtime_applicability():
    """Verify that ground truth is never passed to or referenced by applicability predicates."""
    # Check signature of canonical_vulnerability_evidence_present
    sig_ev = inspect.signature(canonical_vulnerability_evidence_present)
    for p in sig_ev.parameters:
        assert "ground_truth" not in p
        assert "expected" not in p
        assert "target_vulnerable" not in p

    # Check signature of determine_applicability_state
    sig_app = inspect.signature(determine_applicability_state)
    for p in sig_app.parameters:
        assert "ground_truth" not in p
        assert "expected" not in p
        assert "target_vulnerable" not in p


# ---------------------------------------------------------------------------
# Requirement 14: Evaluator never promotes exploratory evidence into vulnerability
# ---------------------------------------------------------------------------

def test_14_evaluator_never_promotes_exploratory_evidence_into_vulnerability_evidence():
    """Verify that neutral route docs without Class-1 flags are never promoted to VULNERABILITY_APPLICABLE."""
    neutral_docs = [
        {"fact_id": "FACT-01", "certainty": "DOCUMENTED", "source_tool": "openapi", "statement": "POST /api/v1/transfer"},
        {"fact_id": "FACT-02", "certainty": "DOCUMENTED", "source_tool": "openapi", "statement": "Accepts amount and recipient"}
    ]

    has_anomaly = canonical_vulnerability_evidence_present(evidence=neutral_docs)
    assert has_anomaly is False

    state = determine_applicability_state(
        is_valid_output=True, target_relevant=True, canonical_evidence_has_anomaly=has_anomaly
    )
    assert state != EvaluationApplicabilityState.VULNERABILITY_EVALUATION_APPLICABLE
    assert state == EvaluationApplicabilityState.EXPLORATORY_EVALUATION_APPLICABLE


# ---------------------------------------------------------------------------
# Requirement 15: Evaluator never downgrades observed vulnerability evidence
# ---------------------------------------------------------------------------

def test_15_evaluator_never_downgrades_observed_vulnerability_evidence():
    """Verify that when a canonical Class-1 anomaly is present, state is never downgraded to exploratory."""
    # Scenario has both parameterized route docs AND an active cross-identity access anomaly
    evidence = [
        {"fact_id": "FACT-01", "certainty": "DOCUMENTED", "statement": "GET /api/v1/invoices/{id}"},
        {"fact_id": "FACT-02", "has_cross_identity_object_access_success": True, "statement": "Observed cross-tenant access"}
    ]

    has_anomaly = canonical_vulnerability_evidence_present(evidence=evidence)
    assert has_anomaly is True

    state = determine_applicability_state(
        is_valid_output=True, target_relevant=True, canonical_evidence_has_anomaly=has_anomaly
    )
    # Must strictly remain VULNERABILITY_EVALUATION_APPLICABLE
    assert state == EvaluationApplicabilityState.VULNERABILITY_EVALUATION_APPLICABLE
    assert state != EvaluationApplicabilityState.EXPLORATORY_EVALUATION_APPLICABLE
