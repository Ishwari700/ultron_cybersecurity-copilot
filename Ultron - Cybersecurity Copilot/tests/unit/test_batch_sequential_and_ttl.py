"""Test Suite for Phase 9: Abstract Execution Interface & Mode 1 Batch-Sequential Scaffolding.

Verifies:
- IPreExecutionTTLValidator & MockPreExecutionTTLValidator (M2 Boundary):
  1. Valid fresh token references return valid=True.
  2. Missing token references return TOKEN_REFERENCE_NOT_FOUND.
  3. Expired token references return TOKEN_EXPIRED and requires_refresh=True.
- Mode 1 BatchSequentialPipeline:
  1. Phase 1 Triage Sweep computes survivor set based on deterministic escalation.
  2. Phase 2 Model Transition tracks load latency.
  3. Phase 3 7B Deep Reasoning processes only survivors.
  4. Decoupled latency instrumentation (MODEL_LOAD_LATENCY, MODEL_INFERENCE_LATENCY, TTD).
  5. 3B Health & Operational SLO tracking (3B_FAILURE_RATE).
  6. Non-overriding invariant: 3B failure causes safe escalation to 7B.
"""

import time
import pytest

from src.evidence.cascade_models import (
    LosslessStructuralPack,
    RawTriageOutput,
)
from src.evidence.vault import RedactionVault
from src.engine.batch_sequential import (
    BatchSequentialPipeline,
    SLO_DIAGNOSTIC_ALERT_THRESHOLD,
    SLO_OPERATIONAL_VIOLATION_THRESHOLD,
    SLO_TARGET_MAX_FAILURE_RATE,
)
from src.hypothesis.experiment import ExpectedObservations, ExperimentProposal, MutationClass
from src.hypothesis.ttl_validator import MockPreExecutionTTLValidator


# ---------------------------------------------------------------------------
# 1. Abstract Pre-Execution TTL Validator Tests
# ---------------------------------------------------------------------------

def test_mock_ttl_validator_valid_unexpired_token():
    vault = RedactionVault()
    future_time = time.time() + 3600  # expires in 1 hour
    vault.register_token_metadata(token_ref="TOKEN_REF_1", identity_id="user_1", expires_at=future_time)

    proposal = ExperimentProposal(
        objective="Test BOLA access",
        target_asset_id="ASSET-1",
        mutation_class=MutationClass.CROSS_IDENTITY_REPLAY,
        expected_observations=ExpectedObservations(
            supporting_observation="200 OK",
            contradicting_observation="403 Forbidden",
        ),
        required_token_references=["TOKEN_REF_1"],
    )

    validator = MockPreExecutionTTLValidator()
    result = validator.validate_proposal(proposal, vault)
    assert result.valid is True
    assert result.requires_refresh is False


def test_mock_ttl_validator_missing_token():
    vault = RedactionVault()
    proposal = ExperimentProposal(
        objective="Test BOLA access",
        target_asset_id="ASSET-1",
        mutation_class=MutationClass.CROSS_IDENTITY_REPLAY,
        expected_observations=ExpectedObservations(
            supporting_observation="200 OK",
            contradicting_observation="403 Forbidden",
        ),
        required_token_references=["NON_EXISTENT_TOKEN"],
    )

    validator = MockPreExecutionTTLValidator()
    result = validator.validate_proposal(proposal, vault)
    assert result.valid is False
    assert result.error == "TOKEN_REFERENCE_NOT_FOUND"


def test_mock_ttl_validator_expired_token():
    vault = RedactionVault()
    past_time = time.time() - 100  # Expired in past
    vault.register_token_metadata(token_ref="TOKEN_EXPIRED_REF", identity_id="user_1", expires_at=past_time)

    proposal = ExperimentProposal(
        objective="Test BOLA access",
        target_asset_id="ASSET-1",
        mutation_class=MutationClass.CROSS_IDENTITY_REPLAY,
        expected_observations=ExpectedObservations(
            supporting_observation="200 OK",
            contradicting_observation="403 Forbidden",
        ),
        required_token_references=["TOKEN_EXPIRED_REF"],
    )

    validator = MockPreExecutionTTLValidator()
    result = validator.validate_proposal(proposal, vault)
    assert result.valid is False
    assert result.error == "TOKEN_EXPIRED"
    assert result.requires_refresh is True
    assert result.identity_id == "user_1"


# ---------------------------------------------------------------------------
# 2. Mode 1 Batch-Sequential Pipeline Execution Tests
# ---------------------------------------------------------------------------

def test_batch_sequential_lifecycle_and_survivor_processing():
    """Verify 3-phase execution lifecycle and survivor filtering."""
    # Scenario 1: Clean benign endpoint -> should abstain (not in survivor set)
    sc1 = {
        "scenario_id": "SC-BENIGN-01",
        "channel_a": LosslessStructuralPack(
            schema_version="2.0.0",
            asset_id="ASSET-1",
            endpoint_id="EP-1",
            route_template="/api/v1/ping",
            http_method="GET",
            application_mutability="READ_ONLY",
        ),
    }
    # Scenario 2: Vulnerable endpoint presenting Class-1 signal -> should escalate to 7B
    sc2 = {
        "scenario_id": "SC-VULN-02",
        "channel_a": LosslessStructuralPack(
            schema_version="2.0.0",
            asset_id="ASSET-2",
            endpoint_id="EP-2",
            route_template="/api/v1/accounts/1",
            http_method="GET",
            application_mutability="READ_ONLY",
            has_privilege_level_delta=True,
        ),
    }

    # Mock 3B triage runner returning benign decisions
    def mock_3b_runner(ch_a):
        return RawTriageOutput(
            schema_version="2.0.0",
            decision="BENIGN_NO_ISSUE",
            triage_rationale="Evaluated",
            is_malformed=False,
        )

    # Mock 7B reasoning runner
    reasoning_calls = []
    def mock_7b_runner(ctx):
        reasoning_calls.append(ctx.model_identifier)
        return {"hypothesis": "CONFIRMED_ESCALATED_ANALYSIS"}

    # Mock model transition
    def mock_transition():
        return 0.05  # Simulated 50ms transition

    pipeline = BatchSequentialPipeline(
        triage_runner_fn=mock_3b_runner,
        reasoning_runner_fn=mock_7b_runner,
        model_transition_fn=mock_transition,
    )

    summary = pipeline.run_sweep([sc1, sc2])

    assert summary.total_scenarios == 2
    assert summary.triage_attempted == 2
    assert summary.triage_failures == 0
    assert summary.survivor_count == 1
    assert summary.escalation_rate == 0.5
    assert summary.total_7b_calls == 1
    assert len(reasoning_calls) == 1

    # Check that only SC-VULN-02 was executed by 7B
    rec1 = summary.records[0]
    rec2 = summary.records[1]

    assert rec1.routing_decision.escalate is False
    assert rec1.reasoning_hypothesis is None

    assert rec2.routing_decision.escalate is True
    assert rec2.reasoning_hypothesis == {"hypothesis": "CONFIRMED_ESCALATED_ANALYSIS"}
    assert rec2.model_load_latency == 0.05


def test_batch_sequential_3b_health_slo_and_failsafe():
    """Verify that failing 3B triggers fail-safe escalation and records 3B_FAILURE_RATE."""
    sc1 = {
        "scenario_id": "SC-FAIL-01",
        "channel_a": LosslessStructuralPack(
            schema_version="2.0.0",
            asset_id="ASSET-1",
            endpoint_id="EP-1",
            route_template="/api/v1/test",
            http_method="GET",
            application_mutability="READ_ONLY",
        ),
    }

    # Runner that throws an exception (simulating crash / timeout)
    def failing_3b_runner(ch_a):
        raise RuntimeError("Simulated Ollama crash")

    pipeline = BatchSequentialPipeline(
        triage_runner_fn=failing_3b_runner,
        reasoning_runner_fn=lambda ctx: {"analyzed": True},
    )

    summary = pipeline.run_sweep([sc1])

    assert summary.triage_failures == 1
    assert summary.failure_rate_3b == 1.0
    assert summary.slo_alert_triggered is True
    assert summary.slo_violation is True

    # Critical invariant: 3B crash must NOT suppress escalation (it fails safe to 7B)
    assert summary.survivor_count == 1
    rec = summary.records[0]
    assert rec.routing_decision.escalate is True
    assert rec.routing_decision.fail_safe_triggered is True
    assert "TRIAGE_OUTPUT_MALFORMED_OR_MISSING" in rec.routing_decision.reasons
    assert rec.reasoning_hypothesis == {"analyzed": True}


def test_batch_sequential_slo_threshold_boundaries():
    """Verify Section 6.3 3B Health SLO diagnostic alert (>2.0%) and violation (>5.0%) thresholds."""
    assert SLO_TARGET_MAX_FAILURE_RATE == 0.05
    assert SLO_DIAGNOSTIC_ALERT_THRESHOLD == 0.02
    assert SLO_OPERATIONAL_VIOLATION_THRESHOLD == 0.05

    def make_scenarios(n):
        return [
            {
                "scenario_id": f"SC-{i}",
                "channel_a": LosslessStructuralPack(
                    schema_version="2.0.0",
                    asset_id=f"ASSET-{i}",
                    endpoint_id=f"EP-{i}",
                    route_template=f"/api/v1/test/{i}",
                    http_method="GET",
                    application_mutability="READ_ONLY",
                ),
            }
            for i in range(n)
        ]

    # Test Case 1: 100 scenarios, 2 failures -> 2.0% (<= 2.0%: no alert, no violation)
    failed_indices = {0, 1}
    def runner(ch_a):
        idx = int(ch_a.asset_id.split("-")[1])
        if idx in failed_indices:
            raise RuntimeError("Fail")
        return RawTriageOutput(
            schema_version="2.0.0",
            decision="BENIGN_NO_ISSUE",
            triage_rationale="OK",
            is_malformed=False,
        )

    pipeline = BatchSequentialPipeline(triage_runner_fn=runner)
    summary = pipeline.run_sweep(make_scenarios(100))
    assert summary.failure_rate_3b == 0.02
    assert summary.slo_alert_triggered is False
    assert summary.slo_violation is False

    # Test Case 2: 100 scenarios, 3 failures -> 3.0% (> 2.0%: alert triggered, but <= 5.0%: no violation)
    failed_indices = {0, 1, 2}
    pipeline = BatchSequentialPipeline(triage_runner_fn=runner)
    summary = pipeline.run_sweep(make_scenarios(100))
    assert summary.failure_rate_3b == 0.03
    assert summary.slo_alert_triggered is True
    assert summary.slo_violation is False

    # Test Case 3: 100 scenarios, 5 failures -> 5.0% (<= 5.0%: alert triggered, but violation false)
    failed_indices = {0, 1, 2, 3, 4}
    pipeline = BatchSequentialPipeline(triage_runner_fn=runner)
    summary = pipeline.run_sweep(make_scenarios(100))
    assert summary.failure_rate_3b == 0.05
    assert summary.slo_alert_triggered is True
    assert summary.slo_violation is False

    # Test Case 4: 100 scenarios, 6 failures -> 6.0% (> 5.0%: both alert and violation triggered)
    failed_indices = {0, 1, 2, 3, 4, 5}
    pipeline = BatchSequentialPipeline(triage_runner_fn=runner)
    summary = pipeline.run_sweep(make_scenarios(100))
    assert summary.failure_rate_3b == 0.06
    assert summary.slo_alert_triggered is True
    assert summary.slo_violation is True
