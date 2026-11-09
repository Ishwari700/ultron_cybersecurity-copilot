"""End-to-end integration test validating the closed reasoning loop:
Evidence -> Application Model -> Security Invariant -> Evidence Gap ->
Hypothesis -> Experiment Proposal -> New Observed Evidence -> Hypothesis Revision.
"""

import pytest
from src.database.manager import DatabaseManager
from src.engine.models import (
    AppModelDelta,
    HypothesisDecision,
    HypothesisModelOutput,
    ViolationAssessment,
    ViolationRelation,
)
from src.eval.synthetic_app import SyntheticApp
from src.eval.simulator import HeadlessSimulator
from src.evidence.models import (
    CanonicalEvidence,
    EpistemicCertainty,
    EvidenceTrust,
)
from src.hypothesis.experiment import (
    ExpectedObservations,
    ExperimentProposal,
    MutationClass,
    SafetyLevel,
)
from src.hypothesis.state_machine import (
    EvidenceState,
    HypothesisState,
    HypothesisStateMachine,
)
from src.invariants.models import InvariantOrigin, SecurityInvariant


def test_closed_reasoning_loop_end_to_end(tmp_path):
    """
    Demonstrate full deterministic progression:
    1. Evidence ingested
    2. Application Model updated
    3. Security Invariant asserted
    4. Evidence Gap identified
    5. Hypothesis formed (Revision 1, PARTIAL)
    6. Experiment Proposal constructed (discriminative)
    7. New Observed Evidence produced by Simulator (HTTP 200)
    8. Hypothesis Revised (Revision 2, STRONG evidence)
    """
    db_path = tmp_path / "reasoning_loop.db"
    db = DatabaseManager(db_path=db_path)
    db.initialize_schema()
    state_machine = HypothesisStateMachine(db)
    simulator = HeadlessSimulator()

    # -------------------------------------------------------------
    # Step 1: Initial Evidence Ingested
    # -------------------------------------------------------------
    scope_id = "SCOPE-RL-001"
    db.insert_scope_decision({
        "scope_decision_id": scope_id,
        "decision": "ALLOW",
        "requested_url": "https://api.target.com/api/v1/invoices/INV-100",
        "canonical_host": "api.target.com",
        "resolved_addresses": ["93.184.216.34"],
        "matched_rule": "*.target.com",
        "out_of_scope_rule": None,
        "tool_policy": "low_impact_active",
        "reason": "Explicit test scope",
        "scope_policy_version": "v6",
    })

    fact_1 = CanonicalEvidence.compute_fact_id("burp", "user_a accessed invoice INV-100")
    asset_id = CanonicalEvidence.compute_asset_id("GET", "api.target.com", "/api/v1/invoices/INV-100")

    db.insert_evidence_item({
        "fact_id": fact_1,
        "certainty": "OBSERVED",
        "statement": "GET /api/v1/invoices/INV-100 returned HTTP 200 for user_a",
        "source_tool": "burp",
        "trust": "UNTRUSTED",
        "scope_decision_id": scope_id,
    })

    # -------------------------------------------------------------
    # Step 2: Application Model Population
    # -------------------------------------------------------------
    db.insert_identity({"identity_id": "user_a", "role": "customer", "notes": "Test tenant A"})
    db.insert_identity({"identity_id": "user_b", "role": "customer", "notes": "Test tenant B"})

    db.insert_asset({
        "asset_id": asset_id,
        "method": "GET",
        "host": "api.target.com",
        "raw_path": "/api/v1/invoices/INV-100",
        "normalized_path": "/api/v1/invoices/{id}",
        "scope_decision_id": scope_id,
    })
    db.insert_parameter({
        "param_id": f"{asset_id}:id:path",
        "asset_id": asset_id,
        "param_name": "id",
        "location": "path",
    })

    # Verify asset and parameter exist in DB
    asset = db.get_asset(asset_id)
    assert asset is not None
    assert asset["normalized_path"] == "/api/v1/invoices/{id}"

    # -------------------------------------------------------------
    # Step 3: Security Invariant Formulation
    # -------------------------------------------------------------
    inv_id = "INV-TENANT-ISOLATION-001"
    inv = SecurityInvariant(
        invariant_id=inv_id,
        description="A customer tenant (user_b) cannot access invoice resources owned by another tenant (user_a)",
        origin=InvariantOrigin.OBSERVED,
        derived_from=[fact_1],
    )
    db.insert_security_invariant(inv.model_dump())

    # Verify invariant persisted
    persisted_inv = db.get_security_invariant(inv_id)
    assert persisted_inv is not None
    assert persisted_inv["invariant_id"] == inv_id

    # -------------------------------------------------------------
    # Step 4: Evidence Gap Identification
    # -------------------------------------------------------------
    evidence_gap = [
        "No evidence observed for user_b attempting GET /api/v1/invoices/INV-100",
        "Cross-tenant isolation between user_a and user_b remains untested",
    ]

    # -------------------------------------------------------------
    # Step 5: Hypothesis Formation (Revision 1)
    # -------------------------------------------------------------
    hyp_proposal = HypothesisModelOutput(
        app_model_delta=AppModelDelta(
            observation="Observed legitimate tenant retrieval, cross-tenant check missing",
        ),
        violation_assessment=ViolationAssessment(
            relation=ViolationRelation.SUPPORTED,
            evidence_ids=[fact_1],
        ),
        decision=HypothesisDecision.HYPOTHESIS,
        category="BOLA_IDOR",
        asset_id=asset_id,
        actor_identity_id="user_b",
        target_identity_id="user_a",
        missing_evidence=evidence_gap,
        safety_check="Read-only GET request on test tenant invoice",
        supporting_evidence_ids=[fact_1],
    )

    hyp_id = state_machine.create_hypothesis(hyp_proposal)
    assert hyp_id is not None

    initial_hyp = db.get_hypothesis(hyp_id)
    assert initial_hyp["state"] == HypothesisState.NEW.value
    assert initial_hyp["revision"] == 1
    assert initial_hyp["evidence_state"] == EvidenceState.PARTIAL.value
    assert initial_hyp["category"] == "BOLA_IDOR"

    # -------------------------------------------------------------
    # Step 6: Discriminative Experiment Proposal
    # -------------------------------------------------------------
    experiment = ExperimentProposal(
        objective="Verify if user_b token can read user_a invoice INV-100",
        target_asset_id=asset_id,
        mutation_class=MutationClass.CROSS_IDENTITY_REPLAY,
        actor_identity_id="user_b",
        target_identity_id="user_a",
        expected_observations=ExpectedObservations(
            supporting_observation="Returns HTTP 200 with user_a invoice data",
            contradicting_observation="Returns HTTP 403 Forbidden or 404 Not Found",
            unresolved_observation="Returns HTTP 500 Internal Server Error",
        ),
        safety_level=SafetyLevel.READ_ONLY_SAFE,
        required_test_data="Pre-seeded test tenant tokens",
        rollback_requirement="None - read only operation",
    )
    assert experiment.is_discriminative() is True

    # -------------------------------------------------------------
    # Step 7: Execution against Headless Simulator -> New Observed Evidence
    # -------------------------------------------------------------
    app_vulnerable = SyntheticApp(app_id="app_saas_001", vulnerable_variant=True)
    exec_result = simulator.execute_experiment(experiment, app_vulnerable, scope_decision_id=scope_id)

    assert exec_result.discriminative is True
    assert exec_result.observation_type == "SUPPORTING"
    assert exec_result.status_code == 200
    assert "invoice" in exec_result.response_data

    # Store new evidence into database with OBSERVED certainty
    new_evidence = exec_result.evidence_item
    assert new_evidence.certainty == EpistemicCertainty.OBSERVED
    db.insert_evidence_item({
        "fact_id": new_evidence.fact_id,
        "certainty": "OBSERVED",
        "statement": new_evidence.statement,
        "source_tool": "headless_simulator",
        "trust": "UNTRUSTED",
        "scope_decision_id": scope_id,
    })

    # -------------------------------------------------------------
    # Step 8: Hypothesis Revision (Revision 2, STRONG Evidence)
    # -------------------------------------------------------------
    revised_hyp = state_machine.revise_with_experiment_observation(
        hypothesis_id=hyp_id,
        observation_type=exec_result.observation_type,
        new_evidence_ref=new_evidence.fact_id,
        observation_notes=f"Simulator returned HTTP 200 supporting BOLA: {exec_result.response_data}",
    )

    assert revised_hyp["revision"] == 2
    assert revised_hyp["evidence_state"] == EvidenceState.STRONG.value
    assert revised_hyp["evidence_ref"] == new_evidence.fact_id

    # -------------------------------------------------------------
    # Verification: Confirm with Human Verification Gate
    # -------------------------------------------------------------
    state_machine.start_review(hyp_id)
    state_machine.confirm_with_human_verification(
        hypothesis_id=hyp_id,
        actor="lead_analyst",
        evidence_ref=new_evidence.fact_id,
        session_id="SESS-VAL-001",
        notes="Empirically confirmed BOLA vulnerability through simulator reproduction",
    )

    confirmed_hyp = db.get_hypothesis(hyp_id)
    assert confirmed_hyp["state"] == HypothesisState.CONFIRMED.value


def test_closed_reasoning_loop_contradicting_outcome(tmp_path):
    """
    Demonstrate that when simulator returns CONTRADICTING evidence (HTTP 403 on patched app),
    the hypothesis is deterministically transitioned to REJECTED at Revision 2.
    """
    db_path = tmp_path / "reasoning_loop_contradict.db"
    db = DatabaseManager(db_path=db_path)
    db.initialize_schema()
    state_machine = HypothesisStateMachine(db)
    simulator = HeadlessSimulator()

    scope_id = "SCOPE-RL-002"
    db.insert_scope_decision({
        "scope_decision_id": scope_id,
        "decision": "ALLOW",
        "requested_url": "https://api.target.com/api/v1/invoices/INV-100",
        "canonical_host": "api.target.com",
        "resolved_addresses": ["93.184.216.34"],
        "matched_rule": "*.target.com",
        "out_of_scope_rule": None,
        "tool_policy": "low_impact_active",
        "reason": "Explicit test scope",
        "scope_policy_version": "v6",
    })

    asset_id = CanonicalEvidence.compute_asset_id("GET", "api.target.com", "/api/v1/invoices/INV-100")
    fact_1 = CanonicalEvidence.compute_fact_id("burp", "initial traffic")

    db.insert_identity({"identity_id": "user_a", "role": "customer"})
    db.insert_identity({"identity_id": "user_b", "role": "customer"})
    db.insert_asset({
        "asset_id": asset_id,
        "method": "GET",
        "host": "api.target.com",
        "raw_path": "/api/v1/invoices/INV-100",
        "normalized_path": "/api/v1/invoices/{id}",
        "scope_decision_id": scope_id,
    })

    db.insert_evidence_item({
        "fact_id": fact_1,
        "certainty": "OBSERVED",
        "statement": "Initial baseline traffic",
        "source_tool": "burp",
        "trust": "UNTRUSTED",
        "scope_decision_id": scope_id,
    })

    hyp_proposal = HypothesisModelOutput(
        app_model_delta=AppModelDelta(observation="Suspected BOLA"),
        violation_assessment=ViolationAssessment(
            relation=ViolationRelation.SUPPORTED,
            evidence_ids=[fact_1],
        ),
        decision=HypothesisDecision.HYPOTHESIS,
        category="BOLA_IDOR",
        asset_id=asset_id,
        actor_identity_id="user_b",
        target_identity_id="user_a",
        missing_evidence=["Cross-tenant check"],
        safety_check="Safe GET",
        supporting_evidence_ids=[fact_1],
    )

    hyp_id = state_machine.create_hypothesis(hyp_proposal)

    experiment = ExperimentProposal(
        objective="Test cross-tenant replay against patched backend",
        target_asset_id=asset_id,
        mutation_class=MutationClass.CROSS_IDENTITY_REPLAY,
        actor_identity_id="user_b",
        target_identity_id="user_a",
        expected_observations=ExpectedObservations(
            supporting_observation="Returns HTTP 200 with data",
            contradicting_observation="Returns HTTP 403 Forbidden",
        ),
    )

    # Execute against PATCHED (secure) variant
    app_patched = SyntheticApp(app_id="app_saas_001_patched", vulnerable_variant=False)
    exec_result = simulator.execute_experiment(experiment, app_patched, scope_decision_id=scope_id)

    assert exec_result.observation_type == "CONTRADICTING"
    assert exec_result.status_code == 403

    # Revise hypothesis with contradicting observation
    revised = state_machine.revise_with_experiment_observation(
        hypothesis_id=hyp_id,
        observation_type="CONTRADICTING",
        new_evidence_ref=exec_result.evidence_item.fact_id,
        observation_notes="Access denied with HTTP 403. Invariant holds.",
    )

    assert revised["revision"] == 2
    assert revised["state"] == HypothesisState.REJECTED.value
