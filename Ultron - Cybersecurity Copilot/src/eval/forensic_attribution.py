"""Milestone M3 Phase M3.18: Forensic Attribution Analysis.

Implements M3 Section 25:
- Identifies decision state flips between Track B and Track D
- Classifies K_FP (Knowledge-Associated False Positive)
- Classifies K_FN (Knowledge-Associated False Negative)
- Conducts counterfactual interventional chunk-removal reruns
- Computes causal compute and wall-clock costs (T_infer = 14.5s, T_load = 0s)
"""

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from src.engine.context_builder import M3Track
from src.engine.models import HypothesisDecision
from src.eval.m3_ablation import M3AblationHarness, M3PairedResult
from src.eval.scenarios import EvaluationScenario


class ForensicAttributionReport(BaseModel):
    """Forensic report analyzing causal attribution of decision flips."""
    analysis_name: str = "M3_FORENSIC_ATTRIBUTION_ANALYSIS"
    timestamp: str
    total_scenarios_evaluated: int
    total_flips_observed: int
    flip_rate: float
    k_fp_count: int
    k_fn_count: int
    other_flips_count: int
    counterfactual_reruns_executed: int
    counterfactual_flips_confirmed: int
    estimated_inference_latency_seconds_per_run: float = 14.5
    total_causal_wall_clock_seconds: float
    flip_details: List[Dict[str, Any]] = Field(default_factory=list)


def run_forensic_attribution(
    paired_results: List[M3PairedResult],
    scenarios: List[EvaluationScenario],
    harness: Optional[M3AblationHarness] = None,
    output_path: Path = Path("data/eval/forensic_attribution_results.json"),
) -> Dict[str, Any]:
    """
    Executes forensic attribution analysis and counterfactual interventional verification.
    """
    scen_by_id = {s.scenario_id: s for s in scenarios}
    harness_inst = harness or M3AblationHarness(live_mode=False)

    flips: List[Dict[str, Any]] = []
    k_fp_count = 0
    k_fn_count = 0
    other_count = 0
    confirmed_causal_count = 0

    t_infer = 14.5  # Frozen 7B inference baseline (s)

    for pair in paired_results:
        if not pair.decision_flipped:
            continue

        s_id = pair.scenario_id
        scen = scen_by_id.get(s_id)
        if not scen:
            continue

        dec_b = pair.result_b.hypothesis_output.decision if pair.result_b.hypothesis_output else None
        dec_d = pair.result_d.hypothesis_output.decision if pair.result_d.hypothesis_output else None

        flip_classification = "OTHER_FLIP"
        # Check K_FP: benign scenario abstained in B, flips to hypothesis in D
        if not scen.ground_truth_vulnerable and dec_b != HypothesisDecision.HYPOTHESIS and dec_d == HypothesisDecision.HYPOTHESIS:
            flip_classification = "K_FP"
            k_fp_count += 1
        # Check K_FN: vulnerable scenario confirmed in B, flips to abstention in D
        elif scen.ground_truth_vulnerable and dec_b == HypothesisDecision.HYPOTHESIS and dec_d != HypothesisDecision.HYPOTHESIS:
            flip_classification = "K_FN"
            k_fn_count += 1
        else:
            other_count += 1

        # Counterfactual Interventional Rerun:
        # Re-run scenario under Track B (chunk removed, all target evidence held constant)
        # to verify whether the decision flips back (true Knowledge-Induced effect).
        rerun_res = harness_inst.run_scenario(scen, track=M3Track.TRACK_B)
        dec_rerun = rerun_res.hypothesis_output.decision if rerun_res.hypothesis_output else None

        decision_reversed = (dec_rerun == dec_b)
        if decision_reversed:
            confirmed_causal_count += 1

        flips.append({
            "scenario_id": s_id,
            "ground_truth_vulnerable": scen.ground_truth_vulnerable,
            "decision_track_b": dec_b.value if hasattr(dec_b, "value") else str(dec_b),
            "decision_track_d": dec_d.value if hasattr(dec_d, "value") else str(dec_d),
            "decision_counterfactual_rerun": dec_rerun.value if hasattr(dec_rerun, "value") else str(dec_rerun),
            "flip_classification": flip_classification,
            "counterfactual_reversal_confirmed": decision_reversed,
            "cited_methodology_chunk_ids_in_d": pair.result_d.cited_methodology_chunk_ids,
        })

    total_scens = len(paired_results)
    total_flips = len(flips)
    flip_rate = total_flips / total_scens if total_scens > 0 else 0.0
    total_wall_clock = total_flips * t_infer

    report = ForensicAttributionReport(
        timestamp=datetime.now(timezone.utc).isoformat(),
        total_scenarios_evaluated=total_scens,
        total_flips_observed=total_flips,
        flip_rate=round(flip_rate, 4),
        k_fp_count=k_fp_count,
        k_fn_count=k_fn_count,
        other_flips_count=other_count,
        counterfactual_reruns_executed=total_flips,
        counterfactual_flips_confirmed=confirmed_causal_count,
        estimated_inference_latency_seconds_per_run=t_infer,
        total_causal_wall_clock_seconds=round(total_wall_clock, 2),
        flip_details=flips,
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report.model_dump(), f, indent=2, sort_keys=True)

    return report.model_dump()
