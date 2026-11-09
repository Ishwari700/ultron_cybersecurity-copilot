"""Unit tests for the Headless Simulator, Synthetic Apps, and Ablation Framework."""

from src.eval.ablation import AblationFramework
from src.eval.scenarios import get_gold_set_scenarios
from src.eval.scorer import DeterministicScorer
from src.eval.simulator import HeadlessSimulator
from src.eval.synthetic_app import SyntheticApp
from src.evidence.models import EpistemicCertainty
from src.hypothesis.experiment import ExpectedObservations, ExperimentProposal, MutationClass


def test_synthetic_app_vulnerable_vs_patched():
    """Verify SyntheticApp distinguishes vulnerable vs patched BOLA authorization."""
    vuln_app = SyntheticApp("test-app", vulnerable_variant=True)
    patched_app = SyntheticApp("test-app", vulnerable_variant=False)

    # user_b attempts to access user_a's invoice INV-100
    headers_b = {"Authorization": "Bearer token_b"}

    # Vulnerable variant allows access -> HTTP 200
    status_vuln, body_vuln = vuln_app.handle_request("GET", "/api/v1/invoices/INV-100", headers=headers_b)
    assert status_vuln == 200
    assert body_vuln["invoice"]["owner"] == "user_a"

    # Patched variant blocks unauthorized tenant -> HTTP 403
    status_patched, body_patched = patched_app.handle_request("GET", "/api/v1/invoices/INV-100", headers=headers_b)
    assert status_patched == 403
    assert "Access forbidden" in body_patched["error"]


def test_headless_simulator_execution():
    """Verify HeadlessSimulator executes experiment proposals and evaluates discriminative outcomes."""
    sim = HeadlessSimulator()
    vuln_app = SyntheticApp("test-app", vulnerable_variant=True)
    patched_app = SyntheticApp("test-app", vulnerable_variant=False)

    exp = ExperimentProposal(
        objective="Verify BOLA on INV-100",
        target_asset_id="ASSET-INV-01",
        mutation_class=MutationClass.CROSS_IDENTITY_REPLAY,
        actor_identity_id="user_b",
        target_identity_id="user_a",
        expected_observations=ExpectedObservations(
            supporting_observation="Returns HTTP 200 with unauthorized invoice payload",
            contradicting_observation="Returns HTTP 403 Forbidden or 404 Not Found",
        ),
    )

    # Run on vulnerable app -> Expect SUPPORTING observation
    result_vuln = sim.execute_experiment(exp, vuln_app)
    assert result_vuln.observation_type == "SUPPORTING"
    assert result_vuln.status_code == 200
    assert result_vuln.discriminative is True
    assert result_vuln.evidence_item.certainty == EpistemicCertainty.OBSERVED

    # Run on patched app -> Expect CONTRADICTING observation
    result_patched = sim.execute_experiment(exp, patched_app)
    assert result_patched.observation_type == "CONTRADICTING"
    assert result_patched.status_code == 403


def test_deterministic_scorer():
    """Verify DeterministicScorer computes accurate benchmark metrics."""
    scorer = DeterministicScorer()
    sample_results = [
        # True Positive (Vulnerable & Hypothesis generated)
        {"scenario_id": "S1", "ground_truth_vulnerable": True, "decision": "HYPOTHESIS", "grounded": True, "discriminative_experiment": True, "useful": True},
        # True Negative (Patched & Abstained)
        {"scenario_id": "S2", "ground_truth_vulnerable": False, "decision": "INSUFFICIENT_EVIDENCE", "grounded": True, "discriminative_experiment": False, "useful": False},
        # False Positive (Patched & Hypothesis generated)
        {"scenario_id": "S3", "ground_truth_vulnerable": False, "decision": "HYPOTHESIS", "grounded": True, "discriminative_experiment": True, "useful": False},
    ]

    metrics = scorer.score(sample_results)
    assert metrics.total_scenarios == 3
    assert metrics.true_positives == 1
    assert metrics.false_positives == 1
    assert metrics.true_negatives == 1
    assert metrics.precision == 0.5
    assert metrics.recall == 1.0
    assert metrics.grounding_accuracy == 1.0
    assert metrics.abstention_precision == 1.0


def test_ablation_framework_execution():
    """Verify AblationFramework executes all 5 tracks across gold-set scenarios."""
    framework = AblationFramework()
    results = framework.run_all_ablations()

    assert "TRACK_A_RULES" in results
    assert "TRACK_B_RAG_3B" in results
    assert "TRACK_C_RAG_7B" in results
    assert "TRACK_D_APP_MODEL_INVARIANTS" in results
    assert "TRACK_E_FULL_V6" in results

    v6_metrics = results["TRACK_E_FULL_V6"]
    assert v6_metrics.total_scenarios == len(get_gold_set_scenarios())
    assert v6_metrics.grounding_accuracy == 1.0
    assert v6_metrics.discriminative_experiment_rate == 1.0


def test_simulator_distinguishes_all_three_observation_types():
    """
    Priority 4: Proves that the HeadlessSimulator correctly and deterministically
    distinguishes:
    1. Supporting observations (vulnerable condition confirmed, HTTP 200)
    2. Contradicting observations (invariant upheld, HTTP 403)
    3. Unresolved observations (unexpected server fault, HTTP 500)
    """
    sim = HeadlessSimulator()
    exp = ExperimentProposal(
        objective="Distinguish competing hypotheses for invoice access",
        target_asset_id="ASSET-INV-01",
        mutation_class=MutationClass.CROSS_IDENTITY_REPLAY,
        actor_identity_id="user_b",
        target_identity_id="user_a",
        expected_observations=ExpectedObservations(
            supporting_observation="Returns HTTP 200 with victim invoice payload",
            contradicting_observation="Returns HTTP 403 Access Forbidden",
            unresolved_observation="Returns HTTP 500 Internal Server Error",
        ),
    )

    # 1. Supporting outcome
    app_vuln = SyntheticApp("app_test", vulnerable_variant=True)
    res_supp = sim.execute_experiment(exp, app_vuln)
    assert res_supp.observation_type == "SUPPORTING"
    assert res_supp.status_code == 200

    # 2. Contradicting outcome
    app_patched = SyntheticApp("app_test", vulnerable_variant=False)
    res_cont = sim.execute_experiment(exp, app_patched)
    assert res_cont.observation_type == "CONTRADICTING"
    assert res_cont.status_code == 403

    # 3. Unresolved outcome (internal server error / crash)
    app_unresolved = SyntheticApp("app_test", simulate_server_error=True)
    res_unres = sim.execute_experiment(exp, app_unresolved)
    assert res_unres.observation_type == "UNRESOLVED"
    assert res_unres.status_code == 500


def test_experiment_scoring_requires_discrimination_between_competing_explanations():
    """
    Priority 4: Verify that an experiment is scored on whether it discriminates
    between competing explanations, NOT merely whether it executes.
    """
    sim = HeadlessSimulator()
    app = SyntheticApp("app_test", vulnerable_variant=True)

    # Experiment A: Properly discriminative
    valid_exp = ExperimentProposal(
        objective="Discriminative test",
        target_asset_id="ASSET-01",
        mutation_class=MutationClass.CROSS_IDENTITY_REPLAY,
        expected_observations=ExpectedObservations(
            supporting_observation="HTTP 200 with data",
            contradicting_observation="HTTP 403 Forbidden",
        ),
    )
    assert valid_exp.is_discriminative() is True
    res_valid = sim.execute_experiment(valid_exp, app)
    assert res_valid.discriminative is True

    # Experiment B: Non-discriminative (same observation expected regardless of outcome)
    invalid_exp = ExperimentProposal(
        objective="Trivial non-discriminative test",
        target_asset_id="ASSET-01",
        mutation_class=MutationClass.CROSS_IDENTITY_REPLAY,
        expected_observations=ExpectedObservations(
            supporting_observation="Server responds with HTTP status",
            contradicting_observation="Server responds with HTTP status",
        ),
    )
    assert invalid_exp.is_discriminative() is False
    res_invalid = sim.execute_experiment(invalid_exp, app)
    # Simulator executed it, BUT flagged discriminative as False!
    assert res_invalid.discriminative is False

    # Scorer evaluation: Non-discriminative experiment penalizes the score
    scorer = DeterministicScorer()
    run_records = [
        {
            "scenario_id": "SC-01",
            "ground_truth_vulnerable": True,
            "decision": "HYPOTHESIS",
            "grounded": True,
            "discriminative_experiment": res_valid.discriminative,
            "useful": True,
        },
        {
            "scenario_id": "SC-02",
            "ground_truth_vulnerable": True,
            "decision": "HYPOTHESIS",
            "grounded": True,
            "discriminative_experiment": res_invalid.discriminative, # Failed discrimination
            "useful": True,
        },
    ]
    metrics = scorer.score(run_records)
    assert metrics.discriminative_experiment_rate == 0.5 # Exactly 1 of 2 discriminative
    assert metrics.discriminative_experiment_rate < 1.0


def test_step_skipping_workflow_observation_outcomes():
    """
    Priority 4: Verify step-skipping state machine transitions distinguish
    supporting (refund before pay succeeds), contradicting (refund before pay rejected),
    and unresolved (server crash).
    """
    sim = HeadlessSimulator()
    exp = ExperimentProposal(
        objective="Attempt refund on unpaid order",
        target_asset_id="ASSET-REFUND",
        mutation_class=MutationClass.STEP_SKIPPING,
        expected_observations=ExpectedObservations(
            supporting_observation="HTTP 200 Refund issued without payment",
            contradicting_observation="HTTP 400 Cannot refund an unpaid order",
        ),
    )

    # Vulnerable allows skipping pay -> SUPPORTING
    res_vuln = sim.execute_experiment(exp, SyntheticApp("app_order", vulnerable_variant=True))
    assert res_vuln.observation_type == "SUPPORTING"
    assert res_vuln.status_code == 200

    # Patched blocks skipping pay -> CONTRADICTING
    res_patched = sim.execute_experiment(exp, SyntheticApp("app_order", vulnerable_variant=False))
    assert res_patched.observation_type == "CONTRADICTING"
    assert res_patched.status_code == 400

    # Server error -> UNRESOLVED
    res_err = sim.execute_experiment(exp, SyntheticApp("app_order", simulate_server_error=True))
    assert res_err.observation_type == "UNRESOLVED"
    assert res_err.status_code == 500

