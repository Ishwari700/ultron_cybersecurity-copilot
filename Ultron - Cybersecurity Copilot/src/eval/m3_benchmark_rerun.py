"""M3 Post-RAG Validation Rerun Runner.

Executes a fresh 84-scenario benchmark across all 4 tracks (A, B, C, D) against
the current implementation, verifies causal parity for all 84 pairs, records
detailed per-scenario execution data, and generates a distinct rerun validation
artifact while strictly preserving the frozen historical baseline.
"""

from datetime import datetime, timezone
import json
from pathlib import Path
import time
from typing import Any, Dict, List

from src.engine.context_builder import M3Track
from src.engine.models import HypothesisDecision
from src.eval.forensic_attribution import run_forensic_attribution
from src.eval.m3_ablation import (
    CausalParityViolationError,
    M3AblationHarness,
    M3PairedResult,
    M3ScenarioExecutionResult,
)
from src.eval.scenarios import EvaluationScenario, get_gold_set_scenarios


def run_fresh_84_scenario_rerun(
    source_commit: str = "cc8858d50428e1c4283d755f8e1e78ac44cbb70d",
    output_path: Path = Path("data/eval/m3_benchmark_rerun_20260920.json"),
    budget_tier: str = "TIER_1",
) -> Dict[str, Any]:
    """
    Executes a fresh 84-scenario benchmark across Tracks A, B, C, and D.
    Enforces strict B/D causal parity for all 84 scenarios.
    """
    scenarios: List[EvaluationScenario] = get_gold_set_scenarios()
    total_scens = len(scenarios)
    assert total_scens == 84, f"Expected exactly 84 scenarios, got {total_scens}"

    start_ts = datetime.now(timezone.utc).isoformat()
    t_start = time.perf_counter()

    harness = M3AblationHarness(live_mode=False)

    eval_tracks = [M3Track.TRACK_A, M3Track.TRACK_B, M3Track.TRACK_C, M3Track.TRACK_D]

    track_results: Dict[str, List[M3ScenarioExecutionResult]] = {t.value: [] for t in eval_tracks}
    paired_b_d_results: List[M3PairedResult] = []
    per_scenario_records: List[Dict[str, Any]] = []

    parity_verified_count = 0
    parity_discrepancy_count = 0

    for scen in scenarios:
        # Run paired B and D with parity enforcement
        paired = harness.run_paired_b_d(scen, budget_tier=budget_tier)
        if not paired.parity_verified:
            parity_discrepancy_count += 1
            raise CausalParityViolationError(f"Causal parity failed on scenario {scen.scenario_id}")
        parity_verified_count += 1
        paired_b_d_results.append(paired)
        track_results[M3Track.TRACK_B.value].append(paired.result_b)
        track_results[M3Track.TRACK_D.value].append(paired.result_d)

        # Run Track A and Track C
        res_a = harness.run_scenario(scen, track=M3Track.TRACK_A, budget_tier=budget_tier)
        res_c = harness.run_scenario(scen, track=M3Track.TRACK_C, budget_tier=budget_tier)
        track_results[M3Track.TRACK_A.value].append(res_a)
        track_results[M3Track.TRACK_C.value].append(res_c)

        # Build comprehensive scenario record
        per_scenario_records.append({
            "scenario_id": scen.scenario_id,
            "name": scen.name,
            "category_id": scen.category_id,
            "ground_truth_vulnerable": scen.ground_truth_vulnerable,
            "tracks": {
                "TRACK_A": {
                    "decision": res_a.hypothesis_output.decision.value if res_a.hypothesis_output else None,
                    "grounding_status": res_a.grounding_status,
                    "supporting_evidence_ids": res_a.supporting_evidence_ids,
                    "cited_methodology_chunk_ids": res_a.cited_methodology_chunk_ids,
                    "latency_ms": round(res_a.latency_ms, 2),
                },
                "TRACK_B": {
                    "decision": paired.result_b.hypothesis_output.decision.value if paired.result_b.hypothesis_output else None,
                    "grounding_status": paired.result_b.grounding_status,
                    "supporting_evidence_ids": paired.result_b.supporting_evidence_ids,
                    "cited_methodology_chunk_ids": paired.result_b.cited_methodology_chunk_ids,
                    "latency_ms": round(paired.result_b.latency_ms, 2),
                },
                "TRACK_C": {
                    "decision": res_c.hypothesis_output.decision.value if res_c.hypothesis_output else None,
                    "grounding_status": res_c.grounding_status,
                    "supporting_evidence_ids": res_c.supporting_evidence_ids,
                    "cited_methodology_chunk_ids": res_c.cited_methodology_chunk_ids,
                    "latency_ms": round(res_c.latency_ms, 2),
                },
                "TRACK_D": {
                    "decision": paired.result_d.hypothesis_output.decision.value if paired.result_d.hypothesis_output else None,
                    "grounding_status": paired.result_d.grounding_status,
                    "supporting_evidence_ids": paired.result_d.supporting_evidence_ids,
                    "cited_methodology_chunk_ids": paired.result_d.cited_methodology_chunk_ids,
                    "latency_ms": round(paired.result_d.latency_ms, 2),
                    "retrieved_chunk_count": len(paired.result_d.cited_methodology_chunk_ids),
                },
            },
            "paired_b_d_parity_verified": paired.parity_verified,
            "paired_b_d_decision_flipped": paired.decision_flipped,
            "paired_b_d_flip_type": paired.flip_type,
        })

    # Compute track summaries
    track_summaries: Dict[str, Any] = {}
    for t_name, results in track_results.items():
        total = len(results)
        hypo_count = sum(
            1 for r in results
            if r.hypothesis_output and r.hypothesis_output.decision == HypothesisDecision.HYPOTHESIS
        )
        abstain_count = sum(
            1 for r in results
            if r.hypothesis_output and r.hypothesis_output.decision in (
                HypothesisDecision.INSUFFICIENT_EVIDENCE,
                HypothesisDecision.NO_RELEVANT_FUNCTIONALITY,
            )
        )
        valid_grounding = sum(1 for r in results if r.grounding_status == "VALID")

        ctrl_total = sum(1 for s in scenarios if not s.ground_truth_vulnerable)
        ctrl_correct = sum(
            1 for s, r in zip(scenarios, results)
            if not s.ground_truth_vulnerable and r.hypothesis_output and r.hypothesis_output.decision in (
                HypothesisDecision.INSUFFICIENT_EVIDENCE,
                HypothesisDecision.NO_RELEVANT_FUNCTIONALITY,
            )
        )
        vuln_total = sum(1 for s in scenarios if s.ground_truth_vulnerable)
        vuln_correct = sum(
            1 for s, r in zip(scenarios, results)
            if s.ground_truth_vulnerable and r.hypothesis_output and r.hypothesis_output.decision == HypothesisDecision.HYPOTHESIS
        )

        track_summaries[t_name] = {
            "total_scenarios": total,
            "hypothesis_decisions": hypo_count,
            "abstention_decisions": abstain_count,
            "abstention_rate": round(abstain_count / total, 4) if total > 0 else 0.0,
            "valid_grounding_count": valid_grounding,
            "grounding_validity_rate": round(valid_grounding / total, 4) if total > 0 else 0.0,
            "true_negative_rate_controls": round(ctrl_correct / ctrl_total, 4) if ctrl_total > 0 else 0.0,
            "true_positive_rate_vulnerable": round(vuln_correct / vuln_total, 4) if vuln_total > 0 else 0.0,
            "mean_latency_ms": round(sum(r.latency_ms for r in results) / total, 2) if total > 0 else 0.0,
        }

    # Execute forensic attribution
    forensic_path = output_path.parent / "forensic_attribution_rerun_temp.json"
    forensic_report = run_forensic_attribution(
        paired_results=paired_b_d_results,
        scenarios=scenarios,
        harness=harness,
        output_path=forensic_path,
    )
    if forensic_path.exists():
        forensic_path.unlink()

    completion_ts = datetime.now(timezone.utc).isoformat()
    wall_clock_s = round(time.perf_counter() - t_start, 3)

    payload = {
        "benchmark_type": "M3_POST_RAG_VALIDATION_RERUN",
        "benchmark_version": "2.3.8",
        "source_commit": source_commit,
        "execution_mode": "DETERMINISTIC_HERMETIC_SIMULATOR",
        "model_execution_detail": {
            "is_live_ollama_inference": False,
            "description": "Deterministic hermetic simulation mode (real prompt assembly, real ONNX+FTS5 retrieval, real context budgeting, real grounding validation; simulated reasoning output).",
            "model_name": None,
            "model_digest": None,
            "tokenizer": "cl100k_base (CanonicalP4CapacityOracle/tiktoken)",
            "temperature": 0.0,
            "seed": 42,
        },
        "retrieval_configuration": {
            "selected_backend": "Candidate 1 (Local ONNX Vector + SQLite FTS5)",
            "onnx_model": "all-MiniLM-L6-v2 (quantized ONNX)",
            "fts5_table": "vapt_chunks_fts",
            "rrf_k": 60,
            "rrf_weights": {"vector": 0.5, "fts5": 0.5},
            "p4_budget_ceiling": 256,
        },
        "start_timestamp": start_ts,
        "completion_timestamp": completion_ts,
        "wall_clock_seconds": wall_clock_s,
        "total_scenarios_evaluated": total_scens,
        "tracks_evaluated": [t.value for t in eval_tracks],
        "causal_parity": {
            "verified_all_scenarios": (parity_discrepancy_count == 0 and parity_verified_count == total_scens),
            "verified_pair_count": parity_verified_count,
            "discrepancy_count": parity_discrepancy_count,
            "contract": "TargetEvidencePayload(Track B) == TargetEvidencePayload(Track D) byte-identical",
        },
        "track_summaries": track_summaries,
        "forensic_attribution": {
            "total_flips": forensic_report.get("total_flips_observed", 0),
            "flip_rate": forensic_report.get("flip_rate", 0.0),
            "k_fp_count": forensic_report.get("k_fp_count", 0),
            "k_fn_count": forensic_report.get("k_fn_count", 0),
            "other_flips_count": forensic_report.get("other_flips_count", 0),
            "counterfactual_reruns_executed": forensic_report.get("counterfactual_reruns_executed", 0),
        },
        "per_scenario_results": per_scenario_records,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=True)

    return payload


if __name__ == "__main__":
    res = run_fresh_84_scenario_rerun()
    print(f"Rerun completed successfully. Scenarios: {res['total_scenarios_evaluated']}. Parity: {res['causal_parity']['verified_all_scenarios']}")
