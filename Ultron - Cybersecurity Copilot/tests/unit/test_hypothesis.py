"""Unit tests for Hypothesis State Machine and Experiment Proposals."""

from pathlib import Path
from src.database.manager import DatabaseManager
from src.engine.models import HypothesisDecision, HypothesisModelOutput
from src.hypothesis.experiment import ExpectedObservations, ExperimentProposal, MutationClass, SafetyLevel
from src.hypothesis.state_machine import EvidenceState, HypothesisState, HypothesisStateMachine


def test_experiment_proposal_discriminative_check():
    """Verify is_discriminative checks that supporting and contradicting observations differ."""
    exp = ExperimentProposal(
        objective="Test BOLA on invoices",
        target_asset_id="ASSET-101",
        mutation_class=MutationClass.CROSS_IDENTITY_REPLAY,
        actor_identity_id="user_b",
        target_identity_id="user_a",
        expected_observations=ExpectedObservations(
            supporting_observation="Returns HTTP 200 with Alice's invoice payload",
            contradicting_observation="Returns HTTP 403 Forbidden or 404 Not Found",
        ),
        safety_level=SafetyLevel.READ_ONLY_SAFE,
    )
    assert exp.is_discriminative() is True

    # Non-discriminative experiment (supporting == contradicting)
    bad_exp = ExperimentProposal(
        objective="Bad test",
        target_asset_id="ASSET-101",
        mutation_class=MutationClass.CROSS_IDENTITY_REPLAY,
        expected_observations=ExpectedObservations(
            supporting_observation="Returns 200",
            contradicting_observation="Returns 200",
        ),
    )
    assert bad_exp.is_discriminative() is False


def test_hypothesis_lifecycle_and_revision(tmp_path: Path):
    """Verify hypothesis lifecycle: creation, review, experiment revision, and confirmation."""
    db_file = tmp_path / "hyp_test.db"
    db_manager = DatabaseManager(db_path=db_file)
    db_manager.initialize_schema()

    # Seed asset
    db_manager.insert_asset({
        "asset_id": "ASSET-LIFECYCLE",
        "method": "GET",
        "host": "api.target.com",
        "raw_path": "/profile",
        "normalized_path": "/profile",
    })

    sm = HypothesisStateMachine(db_manager)

    output = HypothesisModelOutput(
        reasoning_summary="Initial hypothesis formulation.",
        decision=HypothesisDecision.HYPOTHESIS,
        category="API-BOLA-001",
        asset_id="ASSET-LIFECYCLE",
    )

    # 1. Create Hypothesis -> State New, Revision 1
    hyp_id = sm.create_hypothesis(output)
    hyp = db_manager.get_hypothesis(hyp_id)
    assert hyp["state"] == HypothesisState.NEW.value
    assert hyp["revision"] == 1
    assert hyp["evidence_state"] == EvidenceState.PARTIAL.value

    # 2. Start Review -> Under Review
    sm.start_review(hyp_id)
    assert db_manager.get_hypothesis(hyp_id)["state"] == HypothesisState.UNDER_REVIEW.value

    # 3. Revise with Supporting Experiment Result -> Revision 2, Evidence State STRONG
    revised = sm.revise_with_experiment_observation(
        hypothesis_id=hyp_id,
        observation_type="SUPPORTING",
        new_evidence_ref="logs/experiment_run_01.txt",
        observation_notes="Observed cross-identity access success",
    )
    assert revised["revision"] == 2
    assert revised["evidence_state"] == EvidenceState.STRONG.value

    # 4. Human Verification Confirmation
    sm.confirm_with_human_verification(
        hypothesis_id=hyp_id,
        actor="lead_researcher",
        evidence_ref="logs/experiment_run_01.txt",
        session_id="SESS-DASHBOARD-001",
        notes="Verified against test account",
    )
    confirmed_hyp = db_manager.get_hypothesis(hyp_id)
    assert confirmed_hyp["state"] == HypothesisState.CONFIRMED.value

    # 5. Report Finding
    sm.report_hypothesis(hyp_id)
    reported_hyp = db_manager.get_hypothesis(hyp_id)
    assert reported_hyp["state"] == HypothesisState.REPORTED.value
