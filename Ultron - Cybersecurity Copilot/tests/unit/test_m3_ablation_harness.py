"""Unit tests for M3.15 4-Track Ablation Harness and Causal Parity."""

import pytest
from src.engine.context_builder import M3Track
from src.eval.m3_ablation import (
    CausalParityViolationError,
    M3AblationHarness,
    M3ScenarioExecutionResult,
)
from src.eval.scenarios import EvaluationScenario


@pytest.fixture
def sample_scenario():
    return EvaluationScenario(
        scenario_id="SCEN-TEST-BOLA-01",
        name="Test BOLA Scenario",
        app_family="saas_billing",
        category="Broken Object Level Authorization",
        category_id="API-BOLA-001",
        ground_truth_vulnerable=True,
        expected_decision="HYPOTHESIS",
        target_asset={
            "asset_id": "ASSET-TEST-01",
            "method": "GET",
            "raw_path": "/api/v1/invoices/100",
            "normalized_path": "/api/v1/invoices/{id}",
            "application_mutability": "READ",
        },
        initial_evidence=[
            {
                "fact_id": "FACT-00000001",
                "statement": "Observed invoice response for user B with status 200 OK.",
            }
        ],
    )


def test_tracks_context_and_retrieval_isolation(sample_scenario):
    harness = M3AblationHarness(live_mode=False)

    res_a = harness.run_scenario(sample_scenario, track=M3Track.TRACK_A)
    assert "<untrusted_target_data>" not in res_a.prompt
    assert "<vapt_methodology_advisory>" not in res_a.prompt
    assert res_a.target_evidence_bytes == b""

    res_b = harness.run_scenario(sample_scenario, track=M3Track.TRACK_B)
    assert "<untrusted_target_data>" in res_b.prompt
    assert "<vapt_methodology_advisory>" not in res_b.prompt
    assert len(res_b.target_evidence_bytes) > 0

    res_c = harness.run_scenario(sample_scenario, track=M3Track.TRACK_C)
    assert "<untrusted_target_data>" not in res_c.prompt
    assert "<vapt_methodology_advisory>" in res_c.prompt
    assert res_c.target_evidence_bytes == b""

    res_d = harness.run_scenario(sample_scenario, track=M3Track.TRACK_D)
    assert "<untrusted_target_data>" in res_d.prompt
    assert "<vapt_methodology_advisory>" in res_d.prompt
    assert len(res_d.target_evidence_bytes) > 0


def test_strict_b_d_causal_parity(sample_scenario):
    harness = M3AblationHarness(live_mode=False)
    paired = harness.run_paired_b_d(sample_scenario)

    assert paired.parity_verified is True
    assert paired.result_b.target_evidence_bytes == paired.result_d.target_evidence_bytes
    assert len(paired.result_b.target_evidence_bytes) > 0


def test_causal_parity_violation_raises(sample_scenario, monkeypatch):
    harness = M3AblationHarness(live_mode=False)

    # Force a mutation on Track D's target evidence
    original_run = harness.run_scenario

    def mock_run(scenario, track, budget_tier="TIER_1"):
        res = original_run(scenario, track, budget_tier)
        if track == M3Track.TRACK_D:
            # Corrupt target evidence bytes
            res.target_evidence_bytes = res.target_evidence_bytes + b"_MUTATED"
        return res

    monkeypatch.setattr(harness, "run_scenario", mock_run)

    with pytest.raises(CausalParityViolationError, match="Causal parity failure"):
        harness.run_paired_b_d(sample_scenario)
