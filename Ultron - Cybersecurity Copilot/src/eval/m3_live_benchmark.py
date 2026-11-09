"""Milestone M3 Live LLM Benchmark Runner (qwen2.5-coder:7b).

Executes the full 84-scenario benchmark across all 4 tracks (A, B, C, D) using
actual local Ollama 7B inference with schema-constrained decoding.

Enforces:
- Strict B/D Target-Evidence byte-parity on every scenario
- Autoregressive structured hypothesis validation
- Epistemic grounding validation (FACT vs CHK isolation)
- Incremental checkpoint persistence after each scenario
- Complete raw output and metric preservation
"""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import time
from typing import Any, Dict, List, Optional

from src.engine.context_builder import M3Track
from src.engine.models import HypothesisDecision, HypothesisModelOutput
from src.engine.runner import ReasoningRunner
from src.eval.m3_ablation import (
    CausalParityViolationError,
    M3AblationHarness,
    M3PairedResult,
    M3ScenarioExecutionResult,
)
from src.eval.metrics import calculate_scenario_yield, compute_mean_yield
from src.eval.scenarios import EvaluationScenario, get_gold_set_scenarios

PINNED_7B_MODEL = "qwen2.5-coder:7b"
PINNED_7B_DIGEST = "dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364"


def run_live_llm_benchmark(
    scenarios: Optional[List[EvaluationScenario]] = None,
    output_path: Path = Path("data/eval/m3_live_llm_benchmark_20260920.json"),
    checkpoint_path: Path = Path("data/eval/m3_live_llm_benchmark_checkpoint.json"),
    budget_tier: str = "TIER_1",
    max_scenarios: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Executes the 4-track live LLM benchmark across all 84 frozen scenarios.
    """
    scens = scenarios or get_gold_set_scenarios()
    if max_scenarios is not None:
        scens = scens[:max_scenarios]

    total_scens = len(scens)
    print(f"Starting Live LLM Benchmark on {total_scens} scenarios across Tracks A, B, C, D...")

    start_ts = datetime.now(timezone.utc).isoformat()
    t_global_start = time.perf_counter()

    runner_7b = ReasoningRunner(model_name=PINNED_7B_MODEL)
    harness = M3AblationHarness(live_mode=True, runner_7b=runner_7b)

    eval_tracks = [M3Track.TRACK_A, M3Track.TRACK_B, M3Track.TRACK_C, M3Track.TRACK_D]

    # Check for existing checkpoint to resume if available
    per_scenario_records: List[Dict[str, Any]] = []
    completed_scen_ids = set()

    if checkpoint_path.exists():
        try:
            with open(checkpoint_path, "r", encoding="utf-8") as f:
                ckpt = json.load(f)
                per_scenario_records = ckpt.get("per_scenario_results", [])
                completed_scen_ids = set(r["scenario_id"] for r in per_scenario_records)
                print(f"Resuming from checkpoint with {len(completed_scen_ids)} scenarios already completed.")
        except Exception as e:
            print(f"Could not load checkpoint ({e}), starting clean.")
            per_scenario_records = []
            completed_scen_ids = set()

    parity_verified_count = sum(1 for r in per_scenario_records if r.get("paired_b_d_parity_verified"))
    parity_discrepancy_count = 0

    for idx, scen in enumerate(scens, start=1):
        if scen.scenario_id in completed_scen_ids:
            continue

        print(f"[{idx}/{total_scens}] Running scenario {scen.scenario_id} ({scen.name})...")
        t_scen_start = time.perf_counter()

        # Step 1: Paired B and D execution with strict parity check
        paired: M3PairedResult = harness.run_paired_b_d(scen, budget_tier=budget_tier)
        if not paired.parity_verified:
            parity_discrepancy_count += 1
            raise CausalParityViolationError(
                f"Causal parity failure on live scenario {scen.scenario_id}!"
            )
        parity_verified_count += 1

        # Step 2: Track A (No Retrieval)
        res_a: M3ScenarioExecutionResult = harness.run_scenario(scen, track=M3Track.TRACK_A, budget_tier=budget_tier)

        # Step 3: Track C (VAPT Knowledge Only)
        res_c: M3ScenarioExecutionResult = harness.run_scenario(scen, track=M3Track.TRACK_C, budget_tier=budget_tier)

        scen_elapsed = time.perf_counter() - t_scen_start
        print(f"    Completed in {scen_elapsed:.2f}s | B={paired.result_b.hypothesis_output.decision if paired.result_b.hypothesis_output else 'None'} | D={paired.result_d.hypothesis_output.decision if paired.result_d.hypothesis_output else 'None'}")

        # Compute payload hash for B and D target evidence
        b_ev_hash = hashlib.sha256(paired.result_b.target_evidence_bytes).hexdigest()
        d_ev_hash = hashlib.sha256(paired.result_d.target_evidence_bytes).hexdigest()

        record = {
            "scenario_id": scen.scenario_id,
            "name": scen.name,
            "category_id": scen.category_id,
            "ground_truth_vulnerable": scen.ground_truth_vulnerable,
            "target_evidence_bytes_hash": b_ev_hash,
            "tracks": {
                "TRACK_A": {
                    "decision": res_a.hypothesis_output.decision.value if res_a.hypothesis_output else None,
                    "grounding_status": res_a.grounding_status,
                    "supporting_evidence_ids": res_a.supporting_evidence_ids,
                    "cited_methodology_chunk_ids": res_a.cited_methodology_chunk_ids,
                    "reasoning_summary": res_a.hypothesis_output.reasoning_summary if res_a.hypothesis_output else None,
                    "raw_output": res_a.raw_model_output,
                    "latency_ms": round(res_a.latency_ms, 2),
                },
                "TRACK_B": {
                    "decision": paired.result_b.hypothesis_output.decision.value if paired.result_b.hypothesis_output else None,
                    "grounding_status": paired.result_b.grounding_status,
                    "supporting_evidence_ids": paired.result_b.supporting_evidence_ids,
                    "cited_methodology_chunk_ids": paired.result_b.cited_methodology_chunk_ids,
                    "reasoning_summary": paired.result_b.hypothesis_output.reasoning_summary if paired.result_b.hypothesis_output else None,
                    "raw_output": paired.result_b.raw_model_output,
                    "latency_ms": round(paired.result_b.latency_ms, 2),
                },
                "TRACK_C": {
                    "decision": res_c.hypothesis_output.decision.value if res_c.hypothesis_output else None,
                    "grounding_status": res_c.grounding_status,
                    "supporting_evidence_ids": res_c.supporting_evidence_ids,
                    "cited_methodology_chunk_ids": res_c.cited_methodology_chunk_ids,
                    "reasoning_summary": res_c.hypothesis_output.reasoning_summary if res_c.hypothesis_output else None,
                    "raw_output": res_c.raw_model_output,
                    "latency_ms": round(res_c.latency_ms, 2),
                },
                "TRACK_D": {
                    "decision": paired.result_d.hypothesis_output.decision.value if paired.result_d.hypothesis_output else None,
                    "grounding_status": paired.result_d.grounding_status,
                    "supporting_evidence_ids": paired.result_d.supporting_evidence_ids,
                    "cited_methodology_chunk_ids": paired.result_d.cited_methodology_chunk_ids,
                    "reasoning_summary": paired.result_d.hypothesis_output.reasoning_summary if paired.result_d.hypothesis_output else None,
                    "raw_output": paired.result_d.raw_model_output,
                    "latency_ms": round(paired.result_d.latency_ms, 2),
                    "retrieved_chunk_ids": paired.result_d.cited_methodology_chunk_ids,
                },
            },
            "paired_b_d_parity_verified": paired.parity_verified,
            "paired_b_d_parity_hashes_match": (b_ev_hash == d_ev_hash),
            "paired_b_d_decision_flipped": paired.decision_flipped,
            "paired_b_d_flip_type": paired.flip_type,
        }
        per_scenario_records.append(record)
        completed_scen_ids.add(scen.scenario_id)

        # Checkpoint save after every scenario
        checkpoint_payload = {
            "checkpoint_timestamp": datetime.now(timezone.utc).isoformat(),
            "completed_scenarios_count": len(per_scenario_records),
            "total_scenarios": total_scens,
            "per_scenario_results": per_scenario_records,
        }
        checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
        with open(checkpoint_path, "w", encoding="utf-8") as f:
            json.dump(checkpoint_payload, f, indent=2, sort_keys=True)

    # Compute comprehensive track summaries from all completed scenarios
    track_summaries: Dict[str, Any] = {}
    for t in [M3Track.TRACK_A, M3Track.TRACK_B, M3Track.TRACK_C, M3Track.TRACK_D]:
        t_name = t.value
        total = len(per_scenario_records)
        hypo_count = sum(
            1 for r in per_scenario_records
            if r["tracks"][t_name]["decision"] == HypothesisDecision.HYPOTHESIS.value
        )
        abstain_count = sum(
            1 for r in per_scenario_records
            if r["tracks"][t_name]["decision"] in (
                HypothesisDecision.INSUFFICIENT_EVIDENCE.value,
                HypothesisDecision.NO_RELEVANT_FUNCTIONALITY.value,
            )
        )
        valid_grounding = sum(
            1 for r in per_scenario_records
            if r["tracks"][t_name]["grounding_status"] == "VALID"
        )

        ctrl_total = sum(1 for r in per_scenario_records if not r["ground_truth_vulnerable"])
        ctrl_correct = sum(
            1 for r in per_scenario_records
            if not r["ground_truth_vulnerable"] and r["tracks"][t_name]["decision"] in (
                HypothesisDecision.INSUFFICIENT_EVIDENCE.value,
                HypothesisDecision.NO_RELEVANT_FUNCTIONALITY.value,
            )
        )
        vuln_total = sum(1 for r in per_scenario_records if r["ground_truth_vulnerable"])
        vuln_correct = sum(
            1 for r in per_scenario_records
            if r["ground_truth_vulnerable"] and r["tracks"][t_name]["decision"] == HypothesisDecision.HYPOTHESIS.value
        )

        # False Positives on negative controls
        fp_count = sum(
            1 for r in per_scenario_records
            if not r["ground_truth_vulnerable"] and r["tracks"][t_name]["decision"] == HypothesisDecision.HYPOTHESIS.value
        )
        # False Negatives on vulnerable scenarios
        fn_count = sum(
            1 for r in per_scenario_records
            if r["ground_truth_vulnerable"] and r["tracks"][t_name]["decision"] != HypothesisDecision.HYPOTHESIS.value
        )

        # Useful hypothesis yield (scenario-level)
        useful_count = vuln_correct

        track_summaries[t_name] = {
            "total_scenarios": total,
            "hypothesis_decisions": hypo_count,
            "abstention_decisions": abstain_count,
            "abstention_rate": round(abstain_count / total, 4) if total > 0 else 0.0,
            "useful_hypothesis_count": useful_count,
            "useful_hypothesis_rate": round(useful_count / total, 4) if total > 0 else 0.0,
            "valid_grounding_count": valid_grounding,
            "grounding_validity_rate": round(valid_grounding / total, 4) if total > 0 else 0.0,
            "true_negative_rate_controls": round(ctrl_correct / ctrl_total, 4) if ctrl_total > 0 else 0.0,
            "true_positive_rate_vulnerable": round(vuln_correct / vuln_total, 4) if vuln_total > 0 else 0.0,
            "false_positive_count": fp_count,
            "false_negative_count": fn_count,
            "mean_latency_ms": round(sum(r["tracks"][t_name]["latency_ms"] for r in per_scenario_records) / total, 2) if total > 0 else 0.0,
        }

    # Compute Primary Causal Estimand: B -> D
    b_yield = track_summaries["TRACK_B"]["useful_hypothesis_rate"]
    d_yield = track_summaries["TRACK_D"]["useful_hypothesis_rate"]
    delta_yield = round(d_yield - b_yield, 4)

    # Forensic flips between B and D
    flips = [
        {
            "scenario_id": r["scenario_id"],
            "category_id": r["category_id"],
            "ground_truth_vulnerable": r["ground_truth_vulnerable"],
            "track_b_decision": r["tracks"]["TRACK_B"]["decision"],
            "track_d_decision": r["tracks"]["TRACK_D"]["decision"],
            "flip_type": r["paired_b_d_flip_type"],
            "retrieved_chunks": r["tracks"]["TRACK_D"]["cited_methodology_chunk_ids"],
            "track_b_summary": r["tracks"]["TRACK_B"]["reasoning_summary"],
            "track_d_summary": r["tracks"]["TRACK_D"]["reasoning_summary"],
        }
        for r in per_scenario_records
        if r["paired_b_d_decision_flipped"]
    ]

    completion_ts = datetime.now(timezone.utc).isoformat()
    total_wall_clock_s = round(time.perf_counter() - t_global_start, 2)

    final_payload = {
        "benchmark_type": "M3_LIVE_LLM_BENCHMARK",
        "benchmark_version": "2.3.8",
        "execution_mode": "LIVE_MODEL_INFERENCE",
        "model_metadata": {
            "model_name": PINNED_7B_MODEL,
            "model_digest": PINNED_7B_DIGEST,
            "ollama_version": "0.34.1",
            "tokenizer": "cl100k_base (CanonicalP4CapacityOracle/tiktoken) / Qwen2.5-Coder-7B-Tokenizer",
            "quantization": "Q4_K_M",
            "temperature": 0.0,
            "seed": 42,
            "num_ctx": 2048,
            "num_predict": 300,
            "keep_alive": "60m",
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
        "wall_clock_seconds": total_wall_clock_s,
        "total_scenarios_evaluated": len(per_scenario_records),
        "tracks_evaluated": [t.value for t in eval_tracks],
        "causal_parity": {
            "verified_all_scenarios": (parity_discrepancy_count == 0 and parity_verified_count == len(per_scenario_records)),
            "verified_pair_count": parity_verified_count,
            "discrepancy_count": parity_discrepancy_count,
            "contract": "TargetEvidencePayload(Track B) == TargetEvidencePayload(Track D) byte-identical",
        },
        "primary_causal_estimand": {
            "track_b_useful_yield": b_yield,
            "track_d_useful_yield": d_yield,
            "delta_b_to_d": delta_yield,
            "total_flips_count": len(flips),
        },
        "track_summaries": track_summaries,
        "forensic_flips": flips,
        "per_scenario_results": per_scenario_records,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(final_payload, f, indent=2, sort_keys=True)

    print(f"Live LLM Benchmark complete! Output saved to: {output_path}")
    return final_payload


if __name__ == "__main__":
    run_live_llm_benchmark()
