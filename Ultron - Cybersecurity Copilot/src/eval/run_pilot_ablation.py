"""Execution script for the small pilot ablation study with real local Ollama models.

Runs N=12 representative scenarios (2 per family across all 6 families) across Tracks A-E:
- Records retrieval query, candidate IDs, retrieval method, ranking, token budget cropping, and prompt evidence context.
- Records real inference latencies and model outputs from qwen2.5-coder:3b and qwen2.5-coder:7b.
- Executes closed-loop simulator feedback in Track E.
- Computes all 9 independent metrics with Wilson confidence intervals.
- Generates JSON reproducibility artifacts.
"""

import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from src.eval.ablation import AblationFramework
from src.eval.scenarios import EvaluationScenario, get_gold_set_scenarios
from src.eval.scorer import DeterministicScorer


def get_pilot_scenarios() -> List[EvaluationScenario]:
    """Select 12 representative scenarios across all 6 application families:
    - 6 Vulnerable Scenarios (1 per family)
    - 4 Patched Scenarios (saas_billing, ecommerce_orders, identity_provider, document_collaboration)
    - 2 Negative-Control Scenarios (healthcare_portal, iot_fleet_mgmt)
    Total: N=12 exactly (6 vulnerable, 6 non-vulnerable).
    """
    all_scenarios = get_gold_set_scenarios()
    families = [
        "saas_billing",
        "ecommerce_orders",
        "identity_provider",
        "document_collaboration",
        "healthcare_portal",
        "iot_fleet_mgmt",
    ]
    pilot: List[EvaluationScenario] = []

    # 1. 6 Vulnerable scenarios (1 per family)
    for fam in families:
        fam_scens = [s for s in all_scenarios if s.app_family == fam]
        vuln = [s for s in fam_scens if s.ground_truth_vulnerable][0]
        pilot.append(vuln)

    # 2. 4 Patched scenarios (first 4 families)
    for fam in families[:4]:
        fam_scens = [s for s in all_scenarios if s.app_family == fam]
        patched = [s for s in fam_scens if not s.ground_truth_vulnerable and s.category_id != "API-AUTH-NONE"][0]
        pilot.append(patched)

    # 3. 2 Negative Control scenarios (last 2 families)
    for fam in families[4:]:
        fam_scens = [s for s in all_scenarios if s.app_family == fam]
        neg = [s for s in fam_scens if s.category_id == "API-AUTH-NONE"][0]
        pilot.append(neg)

    assert len(pilot) == 12
    assert sum(1 for s in pilot if s.ground_truth_vulnerable) == 6
    assert sum(1 for s in pilot if not s.ground_truth_vulnerable and s.category_id != "API-AUTH-NONE") == 4
    assert sum(1 for s in pilot if s.category_id == "API-AUTH-NONE") == 2
    return pilot


def run_pilot(output_file: Optional[Path] = None, budget_tier: str = "LOW") -> Dict[str, Any]:
    """Run pilot ablation study across Tracks A-E."""
    pilot_scens = get_pilot_scenarios()
    print(f"============================================================")
    print(f" Starting Live Pilot Ablation (N={len(pilot_scens)} scenarios, tier={budget_tier})")
    print(f"============================================================")

    framework = AblationFramework(live_mode=True)
    scorer = DeterministicScorer()

    tracks = [
        "TRACK_A_RULES",
        "TRACK_B_RAG_3B",
        "TRACK_C_RAG_7B",
        "TRACK_D_APP_MODEL_INVARIANTS",
        "TRACK_E_FULL_V6",
    ]

    pilot_results: Dict[str, Any] = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "budget_tier": budget_tier,
        "scenarios_count": len(pilot_scens),
        "scenarios": [s.scenario_id for s in pilot_scens],
        "tracks": {},
        "raw_records": {},
        "representative_examples": [],
    }

    for track in tracks:
        print(f"\n--- Executing {track} ---")
        t0 = time.time()
        raw_recs = framework.run_track_raw(track, pilot_scens, budget_tier=budget_tier)
        duration = round(time.time() - t0, 2)
        metrics = scorer.score(raw_recs)

        pilot_results["raw_records"][track] = raw_recs
        pilot_results["tracks"][track] = {
            "metrics": metrics.model_dump(),
            "execution_duration_seconds": duration,
            "avg_latency_per_scenario": round(duration / len(pilot_scens), 2),
        }

        print(f"[{track}] Completed in {duration}s:")
        print(f"  Precision: {metrics.precision} (CI: {metrics.precision_ci_95})")
        print(f"  Recall:    {metrics.recall} (CI: {metrics.recall_ci_95})")
        print(f"  F1:        {metrics.f1_score}")
        print(f"  Useful Yld:{metrics.useful_hypothesis_yield}")
        print(f"  Abstention:{metrics.abstention_quality}")
        print(f"  Canon ID:  {metrics.canonical_id_validity}")
        print(f"  Grounding: {metrics.structural_grounding_rate}")

    # Extract representative examples (retrieval -> prompt context -> model response)
    # Pick 1 vulnerable scenario and 1 patched scenario from Track E and Track C
    for track in ["TRACK_C_RAG_7B", "TRACK_E_FULL_V6"]:
        recs = pilot_results["raw_records"][track]
        for r in recs[:2]:
            trace = r.get("retrieval_trace") or {}
            pilot_results["representative_examples"].append({
                "track": track,
                "scenario_id": r["scenario_id"],
                "decision": r["decision"],
                "ground_truth_vulnerable": r["ground_truth_vulnerable"],
                "useful": r["useful"],
                "retrieval_query": trace.get("query"),
                "retrieved_evidence_ids": trace.get("retrieved_evidence_ids"),
                "retrieval_method": trace.get("retrieval_method"),
                "retrieval_ranking": trace.get("retrieval_ranking"),
                "prompt_evidence_context": trace.get("prompt_evidence_context"),
                "termination_reason": r.get("termination_reason"),
            })

    # Save to disk
    out_path = output_file or Path("data/pilot_ablation_results.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(pilot_results, f, indent=2)

    print(f"\nPilot results saved to: {out_path.resolve()}")
    return pilot_results


if __name__ == "__main__":
    run_pilot()
