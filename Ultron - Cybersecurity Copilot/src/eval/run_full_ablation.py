"""Full 84-scenario benchmark runner for EXP-0006 (Real Local LLM Ablation).

Executes all 5 tracks across the 84-scenario gold set partitioned across 6 families:
- Development split (28 scenarios: saas_billing, ecommerce_orders)
- Validation split (28 scenarios: identity_provider, document_collaboration)
- Evaluation split (28 scenarios: healthcare_portal, iot_fleet_mgmt)

Features:
- Incremental checkpointing per track to disk.
- Complete RAG tracing for all scenarios.
- Measures latencies, memory footprint, and token counts.
- Computes all 9 independent metrics with 95% Wilson confidence intervals.
- Generates paired 2x2 contingency tables and McNemar exact tests.
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from src.eval.ablation import AblationFramework
from src.eval.scenarios import EvaluationScenario, get_gold_set_scenarios
from src.eval.scorer import DeterministicScorer, compute_paired_contingency_table


def run_full_benchmark(
    budget_tier: str = "LOW",
    output_file: Optional[Path] = None,
    tracks_to_run: Optional[List[str]] = None,
    scenario_limit: Optional[int] = None,
) -> Dict[str, Any]:
    """Execute the full 84-scenario ablation benchmark across Tracks A-E."""
    all_scenarios = get_gold_set_scenarios()
    if scenario_limit:
        all_scenarios = all_scenarios[:scenario_limit]

    print(f"============================================================")
    print(f" EXP-0006: Real Local LLM 5-Track Ablation Benchmark")
    print(f" Total Scenarios: {len(all_scenarios)} | Budget Tier: {budget_tier}")
    print(f"============================================================")

    out_path = output_file or Path("data/exp0006_full_ablation_results.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)

    framework = AblationFramework(live_mode=True)
    scorer = DeterministicScorer()

    tracks = tracks_to_run or [
        "TRACK_A_RULES",
        "TRACK_B_RAG_3B",
        "TRACK_C_RAG_7B",
        "TRACK_D_APP_MODEL_INVARIANTS",
        "TRACK_E_FULL_V6",
    ]

    # Load existing checkpoint if present
    benchmark_data: Dict[str, Any] = {
        "experiment_id": "EXP-0006",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "budget_tier": budget_tier,
        "total_scenarios": len(all_scenarios),
        "tracks": {},
        "raw_records": {},
        "paired_contingency_tables": {},
    }
    if out_path.exists():
        try:
            with open(out_path, "r", encoding="utf-8") as f:
                existing = json.load(f)
                benchmark_data["tracks"].update(existing.get("tracks", {}))
                benchmark_data["raw_records"].update(existing.get("raw_records", {}))
        except Exception:
            pass

    for track in tracks:
        print(f"\n============================================================")
        print(f" Starting {track} ({len(all_scenarios)} scenarios)")
        print(f"============================================================")

        t0 = time.time()
        raw_recs = framework.run_track_raw(track, all_scenarios, budget_tier=budget_tier)
        duration = round(time.time() - t0, 2)
        metrics = scorer.score(raw_recs)

        benchmark_data["raw_records"][track] = raw_recs
        benchmark_data["tracks"][track] = {
            "metrics": metrics.model_dump(),
            "execution_duration_seconds": duration,
            "avg_latency_per_scenario": round(duration / len(all_scenarios), 2),
        }

        print(f"\n--- {track} Completed in {duration}s ---")
        print(f"  Precision:           {metrics.precision} [95% CI: {metrics.precision_ci_95}]")
        print(f"  Recall:              {metrics.recall} [95% CI: {metrics.recall_ci_95}]")
        print(f"  F1 Score:            {metrics.f1_score}")
        print(f"  Useful Yield:        {metrics.useful_hypothesis_yield} [95% CI: {metrics.useful_yield_ci_95}]")
        print(f"  Abstention Quality:  {metrics.abstention_quality}")
        print(f"  Canonical ID Valid:  {metrics.canonical_id_validity}")
        print(f"  Decision Correctness:{metrics.decision_correctness}")

        # Checkpoint to disk after each track
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(benchmark_data, f, indent=2)
        print(f"  [Checkpoint saved to {out_path}]")

    # Compute paired McNemar contingency tables (Track E vs Tracks A, B, C, D)
    if "TRACK_E_FULL_V6" in benchmark_data["raw_records"]:
        recs_e = benchmark_data["raw_records"]["TRACK_E_FULL_V6"]
        for other_track in ["TRACK_A_RULES", "TRACK_B_RAG_3B", "TRACK_C_RAG_7B", "TRACK_D_APP_MODEL_INVARIANTS"]:
            if other_track in benchmark_data["raw_records"]:
                recs_other = benchmark_data["raw_records"][other_track]
                table = compute_paired_contingency_table(
                    results_track_1=recs_other,
                    results_track_2=recs_e,
                    key="useful",
                    vulnerable_only=True,
                )
                benchmark_data["paired_contingency_tables"][f"track_e_vs_{other_track.lower()}"] = table

    # Save final results
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(benchmark_data, f, indent=2)

    print(f"\n============================================================")
    print(f" Full Benchmark Complete! Results saved to: {out_path.resolve()}")
    print(f"============================================================")
    return benchmark_data


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run EXP-0006 Real LLM Ablation Benchmark")
    parser.add_argument("--tier", default="LOW", choices=["LOW", "MEDIUM", "HIGH"], help="Budget tier")
    parser.add_argument("--limit", type=int, default=None, help="Limit number of scenarios")
    parser.add_argument("--track", default=None, help="Specific track to run")
    args = parser.parse_args()

    selected_tracks = [args.track] if args.track else None
    run_full_benchmark(budget_tier=args.tier, tracks_to_run=selected_tracks, scenario_limit=args.limit)
