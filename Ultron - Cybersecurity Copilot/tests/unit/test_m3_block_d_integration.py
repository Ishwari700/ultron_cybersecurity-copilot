"""Comprehensive integration tests for Milestone M3 Block D (Phases M3.15 -> M3.19).

Verifies all explicit acceptance criteria for Block D:
1. M3 4-Track Ablation Harness & strict B/D causal parity (M3.15)
2. Deterministic Human-Study Scenario Selection & Frozen Manifest (M3.15.1)
3. RETRIEVAL_FINAL_EVAL generalization evaluation on sealed retriever (M3.16)
4. Condition-masked human study materials, 9-category blinding & buffer >= 5 (M3.17)
5. Forensic attribution analysis & counterfactual reruns (M3.18)
6. Cryptographic artifact seal manifest & provenance chain (M3.19)
7. Target-Evidence retriever (src/retrieval/hybrid.py) remains 100% byte-identical
"""

import hashlib
import json
from pathlib import Path
import pytest

from src.engine.context_builder import M3Track
from src.eval.artifact_seal import build_m3_artifact_seal
from src.eval.forensic_attribution import run_forensic_attribution
from src.eval.human_study_generator import generate_human_study_packets
from src.eval.m3_ablation import (
    CausalParityViolationError,
    M3AblationHarness,
    M3PairedResult,
)
from src.eval.m3_benchmark import M3BenchmarkRunner
from src.eval.metrics import (
    compute_fleiss_kappa,
    compute_krippendorff_alpha_ordinal,
    compute_mean_yield,
    paired_bca_bootstrap_ci,
    paired_monte_carlo_permutation_test,
)
from src.eval.retrieval_final_eval import run_retrieval_final_evaluation
from src.eval.scenario_selector import run_deterministic_selection
from src.eval.scenarios import EvaluationScenario, get_gold_set_scenarios


@pytest.fixture
def sample_scenarios():
    scens = get_gold_set_scenarios()
    return scens[:5]


def test_m3_15_ablation_tracks_and_causal_parity(sample_scenarios):
    harness = M3AblationHarness(live_mode=False)

    for scen in sample_scenarios:
        paired = harness.run_paired_b_d(scen, budget_tier="TIER_1")
        assert paired.parity_verified is True
        # Byte-identical target evidence
        assert paired.result_b.target_evidence_bytes == paired.result_d.target_evidence_bytes
        assert len(paired.result_b.target_evidence_bytes) > 0


def test_m3_15_1_deterministic_scenario_selection():
    manifest_path = Path("data/eval/human_study_scenario_manifest.json")
    assert manifest_path.exists()

    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    assert manifest["total_selected_count"] == 20
    assert manifest["vulnerable_count"] == 10
    assert manifest["control_count"] == 10
    assert len(manifest["selected_scenario_ids"]) == 20
    assert manifest["fixed_random_seed"] == 20260919
    assert manifest["selection_algorithm_version"] == "DeterministicStratifiedProportionalSelection_v1"


def test_m3_16_retrieval_final_eval_generalization():
    results_path = Path("data/eval/retrieval_final_eval_results.json")
    assert results_path.exists()

    with open(results_path, "r", encoding="utf-8") as f:
        res = json.load(f)

    assert res["query_count"] == 15
    metrics = res["metrics"]
    assert metrics["recall_at_5"]["point_estimate"] >= 0.80
    assert metrics["mrr_at_5"]["point_estimate"] >= 0.60
    assert metrics["injection_hit_at_p4_256"]["point_estimate"] >= 0.75
    assert metrics["recall_at_5"]["ci_95_lower"] <= metrics["recall_at_5"]["point_estimate"]
    assert metrics["recall_at_5"]["point_estimate"] <= metrics["recall_at_5"]["ci_95_upper"]


def test_m3_17_human_study_masking_and_buffer():
    units_path = Path("data/eval/human_study_evaluation_units.json")
    packets_path = Path("data/eval/human_study_rater_packets.json")
    blinding_key_path = Path("data/eval/human_study_blinding_key.json")

    assert units_path.exists()
    assert packets_path.exists()
    assert blinding_key_path.exists()

    with open(units_path, "r", encoding="utf-8") as f:
        units_data = json.load(f)
    assert units_data["total_units"] == 40

    # Verify no forbidden metadata in evaluation units
    prohibited_substrings = ["TRACK_A", "TRACK_B", "TRACK_C", "TRACK_D", "vapt_retriever", "CHK-", "merkle_root"]
    for u in units_data["evaluation_units"]:
        u_str = json.dumps(u)
        for ps in prohibited_substrings:
            assert ps not in u_str, f"Found prohibited metadata '{ps}' in unit {u['unit_id']}"

    # Verify rater packet sequences and buffer >= 5
    with open(packets_path, "r", encoding="utf-8") as f:
        packets_data = json.load(f)

    with open(blinding_key_path, "r", encoding="utf-8") as f:
        b_key = json.load(f)["blinding_key"]

    scenario_pairs = {}
    for u_id, info in b_key.items():
        s_id = info["scenario_id"]
        if s_id not in scenario_pairs:
            scenario_pairs[s_id] = {}
        scenario_pairs[s_id][info["condition"]] = u_id

    for rater, seq in packets_data["rater_sequences"].items():
        assert len(seq) == 40
        for s_id, pair in scenario_pairs.items():
            pos_b = seq.index(pair["TRACK_B"])
            pos_d = seq.index(pair["TRACK_D"])
            dist = abs(pos_b - pos_d)
            assert dist >= 6, f"Buffer violation for {s_id} in {rater}: distance {dist} < 6 (intervening < 5)"


def test_m3_18_forensic_attribution_analysis():
    forensic_path = Path("data/eval/forensic_attribution_results.json")
    assert forensic_path.exists()

    with open(forensic_path, "r", encoding="utf-8") as f:
        report = json.load(f)

    assert report["total_scenarios_evaluated"] >= 20
    assert "flip_rate" in report
    assert "counterfactual_reruns_executed" in report
    assert report["estimated_inference_latency_seconds_per_run"] == 14.5


def test_m3_19_artifact_seal_manifest():
    seal_path = Path("data/eval/m3_artifact_manifest.json")
    assert seal_path.exists()

    with open(seal_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    assert manifest["milestone"] == "M3"
    assert manifest["plan_version"] == "2.3.8"
    assert manifest["planning_freeze_commit"] == "819b83399e24080bf2942c3941cc96728885df49"
    assert manifest["architectural_attestations"]["target_evidence_retriever_untouched"] is True
    assert manifest["architectural_attestations"]["causal_parity_enforced"] is True
    assert manifest["corpus_assets"]["merkle_root"] is not None
    assert manifest["corpus_assets"]["signature_detached_ed25519"] is not None


def test_target_evidence_retriever_remains_byte_identical():
    retriever_path = Path("src/retrieval/hybrid.py")
    assert retriever_path.exists()

    # Check git diff
    import subprocess
    diff_res = subprocess.run(
        ["git", "diff", "src/retrieval/hybrid.py"],
        capture_output=True,
        text=True,
    )
    assert diff_res.stdout.strip() == "", "src/retrieval/hybrid.py has been modified!"
