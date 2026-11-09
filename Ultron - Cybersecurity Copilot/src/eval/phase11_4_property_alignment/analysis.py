"""
Milestone M5 Phase 11.4: Analysis Engine for Property Alignment and Track D Diagnostics.

Computes:
- Step 1 (P3 vs P4) comparative metrics:
  - VTER (Valid Typed Experiment Rate)
  - Security Property Selection & Compatibility Rates
  - SP1-SP5, SP99 Failure Decomposition
  - Grounding & Polarity Preservation
  - Latency and Useful Vulnerable Hypothesis Yield
- Step 2 (P4 Track A vs P5 Track D) comparative metrics:
  - VTER impact of Track D context
  - Grounding robustness under dual-RAG / cascade payload
  - Schema integrity under Track D
  - Useful hypothesis yield comparison
"""

from collections import Counter
import statistics
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from src.eval.phase11_4_property_alignment.property_validator import SecurityPropertyFailureCode


class Phase11_4ConditionMetrics(BaseModel):
    """Metrics container for a single experimental cell."""
    condition_id: str
    track_id: str
    total_calls: int
    candidate_hypotheses: int
    valid_typed_experiments: int
    valid_typed_experiment_rate_pct: float
    grounded_candidates: int
    grounding_eligible_candidates: int
    grounding_success_rate_pct: float
    property_compatible_candidates: int
    property_eligible_candidates: int
    property_compatibility_rate_pct: float
    useful_vulnerable_hypotheses: int
    valid_control_abstentions: int
    runtime_timeouts: int
    mean_latency_ms: float
    median_latency_ms: float
    primary_failure_distribution: Dict[str, int]
    property_failure_distribution: Dict[str, int]
    grounding_code_distribution: Dict[str, int]


class Phase11_4AnalysisResult(BaseModel):
    """Complete comparative analysis of Phase 11.4 results."""
    step1_p3: Phase11_4ConditionMetrics
    step1_p4: Phase11_4ConditionMetrics
    step2_p4_track_a: Phase11_4ConditionMetrics
    step2_p5_track_d: Phase11_4ConditionMetrics
    scenario_matrix_step1: List[Dict[str, Any]]
    scenario_matrix_step2: List[Dict[str, Any]]
    total_calls_analyzed: int


def compute_metrics_for_subset(
    records: List[Dict[str, Any]],
    condition_id: str,
    track_id: str,
) -> Phase11_4ConditionMetrics:
    """Computes audited metrics for a condition and track."""
    subset = [
        r for r in records
        if r["condition_id"] == condition_id and r["context"]["context_track"] == track_id
    ]
    total_calls = len(subset)

    cand_hyp = 0
    valid_typed = 0
    grounded_cands = 0
    grounding_eligible = 0
    prop_comp = 0
    prop_eligible = 0
    useful_vuln = 0
    valid_abst = 0
    timeouts = 0
    latencies: List[float] = []

    primary_failures: Counter = Counter()
    prop_failures: Counter = Counter()
    grounding_codes: Counter = Counter()

    for r in subset:
        val = r["validation"]
        att = r["attribution"]
        rt = r["runtime_telemetry"]
        mo = r["model_output"]
        cand_dec = mo.get("candidate_decision")
        is_vuln = r.get("vulnerable_variant", False)

        lat = rt.get("total_latency_ms", 0.0)
        latencies.append(lat)
        if rt.get("timed_out", False):
            timeouts += 1

        p_code = att.get("primary_failure_code", "UNKNOWN")
        primary_failures[p_code] += 1

        g_code = val.get("grounding_failure_code")
        if g_code:
            grounding_codes[g_code] += 1

        sp_code = val.get("security_property_failure_code")
        if sp_code:
            prop_failures[sp_code] += 1

        is_hyp = (cand_dec == "HYPOTHESIS")
        if is_hyp:
            cand_hyp += 1

        if val.get("schema_valid", False) and not rt.get("timed_out", False):
            grounding_eligible += 1
            if val.get("grounding_valid", False):
                grounded_cands += 1

            if is_hyp:
                prop_eligible += 1
                if val.get("property_valid", False):
                    prop_comp += 1

        if val.get("is_valid_typed_experiment", False):
            valid_typed += 1

        if val.get("is_useful_vulnerable_hypothesis", False):
            useful_vuln += 1

        if not is_vuln and cand_dec in ("NO_RELEVANT_FUNCTIONALITY", "INSUFFICIENT_EVIDENCE") and val.get("grounding_valid", False):
            valid_abst += 1

    vter = (valid_typed / cand_hyp * 100.0) if cand_hyp > 0 else 0.0
    gsr = (grounded_cands / grounding_eligible * 100.0) if grounding_eligible > 0 else 0.0
    pcr = (prop_comp / prop_eligible * 100.0) if prop_eligible > 0 else 0.0

    mean_lat = round(statistics.mean(latencies), 1) if latencies else 0.0
    median_lat = round(statistics.median(latencies), 1) if latencies else 0.0

    return Phase11_4ConditionMetrics(
        condition_id=condition_id,
        track_id=track_id,
        total_calls=total_calls,
        candidate_hypotheses=cand_hyp,
        valid_typed_experiments=valid_typed,
        valid_typed_experiment_rate_pct=round(vter, 2),
        grounded_candidates=grounded_cands,
        grounding_eligible_candidates=grounding_eligible,
        grounding_success_rate_pct=round(gsr, 2),
        property_compatible_candidates=prop_comp,
        property_eligible_candidates=prop_eligible,
        property_compatibility_rate_pct=round(pcr, 2),
        useful_vulnerable_hypotheses=useful_vuln,
        valid_control_abstentions=valid_abst,
        runtime_timeouts=timeouts,
        mean_latency_ms=mean_lat,
        median_latency_ms=median_lat,
        primary_failure_distribution=dict(primary_failures),
        property_failure_distribution=dict(prop_failures),
        grounding_code_distribution=dict(grounding_codes),
    )


def analyze_phase11_4_results(records: List[Dict[str, Any]]) -> Phase11_4AnalysisResult:
    """Analyzes complete 32-call dataset across Step 1 and Step 2."""
    # Step 1 subsets
    step1_records = [r for r in records if r.get("stage") == "STEP_1"]
    step1_p3 = compute_metrics_for_subset(step1_records, "P3", "TRACK_A")
    step1_p4 = compute_metrics_for_subset(step1_records, "P4", "TRACK_A")

    # Step 2 subsets
    step2_records = [r for r in records if r.get("stage") == "STEP_2"]
    step2_p4 = compute_metrics_for_subset(step2_records, "P4_TRACK_A", "TRACK_A")
    step2_p5 = compute_metrics_for_subset(step2_records, "P5_TRACK_D", "TRACK_D")

    # Build Step 1 comparison matrix
    scenarios_s1 = sorted(list({r["scenario_id"] for r in step1_records}))
    matrix_s1 = []
    for sid in scenarios_s1:
        p3_r = next((r for r in step1_records if r["scenario_id"] == sid and r["condition_id"] == "P3"), {})
        p4_r = next((r for r in step1_records if r["scenario_id"] == sid and r["condition_id"] == "P4"), {})
        matrix_s1.append({
            "scenario_id": sid,
            "vulnerable_variant": p3_r.get("vulnerable_variant", False),
            "category_id": p3_r.get("category_id", ""),
            "p3": {
                "decision": p3_r.get("model_output", {}).get("candidate_decision"),
                "property": p3_r.get("model_output", {}).get("attack_predicate", {}).get("security_property") if p3_r.get("model_output", {}).get("attack_predicate") else None,
                "property_valid": p3_r.get("validation", {}).get("property_valid"),
                "primary_failure": p3_r.get("attribution", {}).get("primary_failure_code"),
                "is_valid_typed": p3_r.get("validation", {}).get("is_valid_typed_experiment"),
            },
            "p4": {
                "decision": p4_r.get("model_output", {}).get("candidate_decision"),
                "property": p4_r.get("model_output", {}).get("attack_predicate", {}).get("security_property") if p4_r.get("model_output", {}).get("attack_predicate") else None,
                "property_valid": p4_r.get("validation", {}).get("property_valid"),
                "primary_failure": p4_r.get("attribution", {}).get("primary_failure_code"),
                "is_valid_typed": p4_r.get("validation", {}).get("is_valid_typed_experiment"),
            },
        })

    # Build Step 2 comparison matrix
    scenarios_s2 = sorted(list({r["scenario_id"] for r in step2_records}))
    matrix_s2 = []
    for sid in scenarios_s2:
        p4_r = next((r for r in step2_records if r["scenario_id"] == sid and r["condition_id"] == "P4_TRACK_A"), {})
        p5_r = next((r for r in step2_records if r["scenario_id"] == sid and r["condition_id"] == "P5_TRACK_D"), {})
        matrix_s2.append({
            "scenario_id": sid,
            "vulnerable_variant": p4_r.get("vulnerable_variant", False),
            "category_id": p4_r.get("category_id", ""),
            "p4_track_a": {
                "decision": p4_r.get("model_output", {}).get("candidate_decision"),
                "grounding_valid": p4_r.get("validation", {}).get("grounding_valid"),
                "property_valid": p4_r.get("validation", {}).get("property_valid"),
                "primary_failure": p4_r.get("attribution", {}).get("primary_failure_code"),
                "is_valid_typed": p4_r.get("validation", {}).get("is_valid_typed_experiment"),
            },
            "p5_track_d": {
                "decision": p5_r.get("model_output", {}).get("candidate_decision"),
                "grounding_valid": p5_r.get("validation", {}).get("grounding_valid"),
                "property_valid": p5_r.get("validation", {}).get("property_valid"),
                "primary_failure": p5_r.get("attribution", {}).get("primary_failure_code"),
                "is_valid_typed": p5_r.get("validation", {}).get("is_valid_typed_experiment"),
            },
        })

    return Phase11_4AnalysisResult(
        step1_p3=step1_p3,
        step1_p4=step1_p4,
        step2_p4_track_a=step2_p4,
        step2_p5_track_d=step2_p5,
        scenario_matrix_step1=matrix_s1,
        scenario_matrix_step2=matrix_s2,
        total_calls_analyzed=len(records),
    )
