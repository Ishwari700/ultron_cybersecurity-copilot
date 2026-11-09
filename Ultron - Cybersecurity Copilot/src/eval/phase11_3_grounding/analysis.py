"""
Milestone M5 Phase 11.3: Grounding Recovery Diagnostic Analysis Engine.

Computes:
- Valid Typed Experiment Rate (VTER) per condition (P1, P2, P3)
- Grounding Success Rate per condition
- Deterministic Grounding Failure Decomposition (G1-G8, G99)
- Primary & Contributing Failure Taxonomy
- Latency statistics (mean, median)
- Scenario-level paired comparison
"""

from collections import Counter
import statistics
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from src.eval.phase11_3_grounding.validator import GroundingFailureCode


class ConditionMetrics(BaseModel):
    """Audited metrics container for a single condition."""
    condition_id: str
    total_calls: int
    candidate_hypotheses: int
    valid_typed_experiments: int
    valid_typed_experiment_rate_pct: float
    grounded_candidates: int
    grounding_eligible_candidates: int
    grounding_success_rate_pct: float
    useful_vulnerable_hypotheses: int
    valid_control_abstentions: int
    runtime_timeouts: int
    mean_latency_ms: float
    median_latency_ms: float
    primary_failure_distribution: Dict[str, int]
    grounding_code_distribution: Dict[str, int]


class DiagnosticAnalysisResult(BaseModel):
    """Complete comparative analysis of Phase 11.3 results."""
    p1_metrics: ConditionMetrics
    p2_metrics: ConditionMetrics
    p3_metrics: ConditionMetrics
    scenario_matrix: List[Dict[str, Any]]
    total_calls_analyzed: int


def compute_condition_metrics(
    records: List[Dict[str, Any]],
    condition_id: str,
) -> ConditionMetrics:
    """Computes audited metrics for a single condition."""
    cond_records = [r for r in records if r["condition_id"] == condition_id]
    total_calls = len(cond_records)

    cand_hyp = 0
    valid_typed = 0
    grounded_cands = 0
    grounding_eligible = 0
    useful_vuln = 0
    valid_control_abst = 0
    timeouts = 0
    latencies: List[float] = []

    primary_failures: Counter = Counter()
    grounding_codes: Counter = Counter()

    for r in cond_records:
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

        is_hyp = (cand_dec == "HYPOTHESIS")
        if is_hyp:
            cand_hyp += 1

        if val.get("schema_valid", False) and not rt.get("timed_out", False):
            grounding_eligible += 1
            if val.get("grounding_valid", False):
                grounded_cands += 1

        if val.get("is_valid_typed_experiment", False):
            valid_typed += 1

        if val.get("is_useful_vulnerable_hypothesis", False):
            useful_vuln += 1

        # Valid control abstention: control scenario where model abstained and output was valid
        if not is_vuln and cand_dec in ("NO_RELEVANT_FUNCTIONALITY", "INSUFFICIENT_EVIDENCE") and val.get("grounding_valid", False):
            valid_control_abst += 1

    vter = (valid_typed / cand_hyp * 100.0) if cand_hyp > 0 else 0.0
    gsr = (grounded_cands / grounding_eligible * 100.0) if grounding_eligible > 0 else 0.0

    mean_lat = round(statistics.mean(latencies), 1) if latencies else 0.0
    median_lat = round(statistics.median(latencies), 1) if latencies else 0.0

    return ConditionMetrics(
        condition_id=condition_id,
        total_calls=total_calls,
        candidate_hypotheses=cand_hyp,
        valid_typed_experiments=valid_typed,
        valid_typed_experiment_rate_pct=round(vter, 2),
        grounded_candidates=grounded_cands,
        grounding_eligible_candidates=grounding_eligible,
        grounding_success_rate_pct=round(gsr, 2),
        useful_vulnerable_hypotheses=useful_vuln,
        valid_control_abstentions=valid_control_abst,
        runtime_timeouts=timeouts,
        mean_latency_ms=mean_lat,
        median_latency_ms=median_lat,
        primary_failure_distribution=dict(primary_failures),
        grounding_code_distribution=dict(grounding_codes),
    )


def analyze_phase11_3_results(records: List[Dict[str, Any]]) -> DiagnosticAnalysisResult:
    """Performs full comparative analysis across P1, P2, and P3."""
    p1 = compute_condition_metrics(records, "P1")
    p2 = compute_condition_metrics(records, "P2")
    p3 = compute_condition_metrics(records, "P3")

    # Group by scenario to build scenario comparison matrix
    scenarios = sorted(list({r["scenario_id"] for r in records}))
    scenario_matrix = []

    for sid in scenarios:
        scen_recs = {r["condition_id"]: r for r in records if r["scenario_id"] == sid}
        p1_r = scen_recs.get("P1", {})
        p2_r = scen_recs.get("P2", {})
        p3_r = scen_recs.get("P3", {})

        scenario_matrix.append({
            "scenario_id": sid,
            "vulnerable_variant": p1_r.get("vulnerable_variant", False),
            "category_id": p1_r.get("category_id", ""),
            "p1": {
                "decision": p1_r.get("model_output", {}).get("candidate_decision"),
                "grounding_valid": p1_r.get("validation", {}).get("grounding_valid"),
                "grounding_code": p1_r.get("validation", {}).get("grounding_failure_code"),
                "primary_failure": p1_r.get("attribution", {}).get("primary_failure_code"),
                "is_valid_typed": p1_r.get("validation", {}).get("is_valid_typed_experiment"),
            },
            "p2": {
                "decision": p2_r.get("model_output", {}).get("candidate_decision"),
                "grounding_valid": p2_r.get("validation", {}).get("grounding_valid"),
                "grounding_code": p2_r.get("validation", {}).get("grounding_failure_code"),
                "primary_failure": p2_r.get("attribution", {}).get("primary_failure_code"),
                "is_valid_typed": p2_r.get("validation", {}).get("is_valid_typed_experiment"),
            },
            "p3": {
                "decision": p3_r.get("model_output", {}).get("candidate_decision"),
                "grounding_valid": p3_r.get("validation", {}).get("grounding_valid"),
                "grounding_code": p3_r.get("validation", {}).get("grounding_failure_code"),
                "primary_failure": p3_r.get("attribution", {}).get("primary_failure_code"),
                "is_valid_typed": p3_r.get("validation", {}).get("is_valid_typed_experiment"),
            },
        })

    return DiagnosticAnalysisResult(
        p1_metrics=p1,
        p2_metrics=p2,
        p3_metrics=p3,
        scenario_matrix=scenario_matrix,
        total_calls_analyzed=len(records),
    )
