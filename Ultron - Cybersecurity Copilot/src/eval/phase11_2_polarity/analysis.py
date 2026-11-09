"""
Milestone M5 Phase 11.2: Diagnostic Analysis & Historical Simulation Module.

Computes:
1. P0 vs P1 comparative metrics (VTER, candidate yield, failure taxonomy, latency).
2. Paired 2x2 scenario success comparison.
3. Secondary Post-Hoc Simulation on Phase 10 Polarity Failures (strictly partitioned).
"""

from collections import Counter, defaultdict
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from src.engine.decision_policy import ExperimentPolarityValidator
from src.eval.phase11_2_polarity.outcome_binding import CANONICAL_PRIMARY_OUTCOME_PAIRS


def analyze_diagnostic_results(
    diagnostic_records: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Analyzes live diagnostic records across conditions P0 and P1.
    """
    conditions = ["P0", "P1"]
    cond_stats: Dict[str, Any] = {}

    for cid in conditions:
        recs = [r for r in diagnostic_records if r["condition_id"] == cid]
        n = len(recs)
        if n == 0:
            continue

        cands = [r for r in recs if r["model_output"]["candidate_decision"] == "HYPOTHESIS"]
        valid_typeds = [r for r in recs if r["validation"]["is_valid_typed_experiment"]]
        useful_vulns = [r for r in recs if r["validation"]["is_useful_vulnerable_hypothesis"]]
        absts = [r for r in recs if r["model_output"]["candidate_decision"] != "HYPOTHESIS" and not r["vulnerable_variant"]]

        latencies = [r["runtime_telemetry"]["total_latency_ms"] for r in recs if r["runtime_telemetry"]["total_latency_ms"] is not None]
        sorted_lats = sorted(latencies)
        mean_lat = round(sum(latencies) / len(latencies), 1) if latencies else 0.0
        med_lat = round(sorted_lats[len(sorted_lats) // 2], 1) if sorted_lats else 0.0

        fail_counts = Counter(r["attribution"]["primary_failure_code"] for r in recs)

        cand_count = len(cands)
        valid_exp_count = len(valid_typeds)
        vter = round((valid_exp_count / cand_count) * 100.0, 2) if cand_count > 0 else 0.0
        scenario_success_rate = round((valid_exp_count / n) * 100.0, 2)

        cond_stats[cid] = {
            "total_calls": n,
            "candidate_hypotheses": cand_count,
            "valid_typed_experiments": valid_exp_count,
            "valid_typed_experiment_rate_vter": vter,
            "scenario_success_rate": scenario_success_rate,
            "useful_vulnerable_hypotheses": len(useful_vulns),
            "valid_control_abstentions": len(absts),
            "primary_failure_counts": dict(fail_counts),
            "mean_latency_ms": mean_lat,
            "median_latency_ms": med_lat,
            "calls": recs,
        }

    # Paired Scenario Comparison (8 scenarios)
    scenario_pairs: Dict[str, Dict[str, Any]] = defaultdict(dict)
    for r in diagnostic_records:
        sid = r["scenario_id"]
        cid = r["condition_id"]
        scenario_pairs[sid][cid] = r["validation"]["is_valid_typed_experiment"]

    # 2x2 Contingency Table for McNemar:
    # P0 success / P1 success
    n_00 = sum(1 for sid, res in scenario_pairs.items() if not res.get("P0") and not res.get("P1"))
    n_01 = sum(1 for sid, res in scenario_pairs.items() if not res.get("P0") and res.get("P1"))
    n_10 = sum(1 for sid, res in scenario_pairs.items() if res.get("P0") and not res.get("P1"))
    n_11 = sum(1 for sid, res in scenario_pairs.items() if res.get("P0") and res.get("P1"))

    contingency = {
        "P0_fail_P1_fail": n_00,
        "P0_fail_P1_success": n_01,
        "P0_success_P1_fail": n_10,
        "P0_success_P1_success": n_11,
    }

    return {
        "condition_statistics": cond_stats,
        "paired_contingency": contingency,
        "total_scenarios_evaluated": len(scenario_pairs),
    }


def run_historical_replay_simulation(
    corpus_jsonl_path: str = "data/eval/m5_phase11_1_failure_corpus.jsonl",
    repo_root: Optional[Path] = None,
) -> Dict[str, Any]:
    """
    SECONDARY ANALYSIS ONLY: Post-hoc replay simulation on Phase 10 Polarity Failures.
    
    IMPORTANT GOVERNANCE NOTICE:
    This is an offline simulation only. It does NOT modify historical Phase 10 records
    and must NEVER be cited as live empirical evidence.
    """
    root = repo_root or Path(__file__).resolve().parent.parent.parent.parent
    corpus_file = root / corpus_jsonl_path
    if not corpus_file.exists():
        return {"error": f"Corpus file not found: {corpus_jsonl_path}"}

    phase10_records = []
    with open(corpus_file, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            rec = json.loads(line)
            if rec["provenance"]["source_phase"] == "PHASE_10":
                phase10_records.append(rec)

    # Filter to primary polarity failures
    polarity_failures = [
        r for r in phase10_records
        if r["attribution"]["primary_failure_code"] == "POLARITY_FAILURE"
    ]

    total_pol_failures = len(polarity_failures)
    simulated_recoveries = 0
    by_condition = defaultdict(lambda: {"total_polarity_failures": 0, "simulated_recoverable": 0})

    registry = ExperimentPolarityValidator.TUPLE_COMPATIBILITY_REGISTRY

    for r in polarity_failures:
        cid = r["identity"]["condition_id"]
        cat_id = r["identity"]["target_category_id"]
        act = r["model_output"]["experiment_action"]

        by_condition[cid]["total_polarity_failures"] += 1

        # Check if action is compatible and canonical outcomes exist
        if cat_id in registry and act in registry[cat_id]:
            pair_key = (cat_id, act)
            if pair_key in CANONICAL_PRIMARY_OUTCOME_PAIRS:
                supp, disp = CANONICAL_PRIMARY_OUTCOME_PAIRS[pair_key]
                p_ok, _ = ExperimentPolarityValidator.validate_tuple(
                    category_id=cat_id,
                    experiment_action=act,
                    supporting_outcome=supp,
                    disproving_outcome=disp,
                )
                if p_ok:
                    simulated_recoveries += 1
                    by_condition[cid]["simulated_recoverable"] += 1

    return {
        "analysis_type": "POST_HOC_HISTORICAL_SIMULATION",
        "governance_status": "ANALYSIS_ONLY_NOT_LIVE_EVIDENCE",
        "source_phase": "PHASE_10",
        "total_polarity_failures_evaluated": total_pol_failures,
        "simulated_recoverable_hypotheses": simulated_recoveries,
        "simulated_recovery_rate_pct": round((simulated_recoveries / total_pol_failures) * 100.0, 2) if total_pol_failures > 0 else 0.0,
        "breakdown_by_condition": dict(by_condition),
        "caveat": (
            "Historical simulation indicates the upper-bound counterfactual yield if the 7B reasoner's "
            "intended hypothesis had its polarity bound deterministically, assuming semantic intent matched the prompt."
        ),
    }
