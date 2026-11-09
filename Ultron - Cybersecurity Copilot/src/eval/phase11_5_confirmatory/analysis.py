"""
Milestone M5 Phase 11.5: Confirmatory Benchmark Statistical Analysis Engine.

Calculates:
- Population-level primary endpoint: Scenario-Level Useful Hypothesis Rate (and Useful Vulnerable Hypotheses / 36)
- Paired 2x2 contingency tables and exact two-sided McNemar tests
- All 23 required secondary metrics for P4-TA and P5-TD:
  1. Candidate HYPOTHESIS attempts
  2. Valid typed experiments
  3. VTER (Valid Typed Experiment Rate)
  4. Completed-call VTER
  5. Useful vulnerable hypotheses
  6. Correct vulnerable decisions
  7. Correct control abstentions
  8. TPR (True Positive Rate)
  9. TNR (True Negative Rate)
  10. FP (False Positives)
  11. FN (False Negatives)
  12. Vulnerable-scenario abstention rate
  13. Control-scenario abstention rate
  14. Grounding success rate
  15. Schema failure rate
  16. Property compatibility rate
  17. Polarity failure rate
  18. Action incompatibility rate
  19. Category incompatibility rate
  20. Runtime timeout count
  21. Mean latency
  22. Median latency
  23. P95 latency
- Failure taxonomy tracking (SP1-SP5, SP99, G1-G8, schema, polarity, timeouts)
"""

from collections import Counter
import math
from pathlib import Path
import statistics
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field


def exact_mcnemar_test(b: int, c: int) -> float:
    """Computes exact two-sided McNemar test p-value using binomial distribution."""
    n = b + c
    if n == 0:
        return 1.0
    k_min = min(b, c)
    prob = sum(math.comb(n, k) * (0.5 ** n) for k in range(k_min + 1))
    return min(1.0, 2.0 * prob)


class ConfirmatoryConditionMetrics(BaseModel):
    """Authoritative metrics container for a confirmatory condition."""
    condition_id: str
    track_id: str
    total_calls: int
    vulnerable_calls: int
    control_calls: int
    candidate_hypotheses: int
    valid_typed_experiments: int
    vter_pct: float
    completed_call_vter_pct: float
    useful_vulnerable_hypotheses: int
    useful_vulnerable_hypothesis_rate_pct: float
    correct_vulnerable_decisions: int
    correct_control_abstentions: int
    tpr_pct: float
    tnr_pct: float
    false_positives: int
    false_negatives: int
    vuln_abstention_count: int
    vuln_abstention_rate_pct: float
    control_abstention_count: int
    control_abstention_rate_pct: float
    grounding_success_rate_pct: float
    schema_failure_rate_pct: float
    property_compatibility_rate_pct: float
    polarity_failure_rate_pct: float
    action_incompatibility_rate_pct: float
    category_incompatibility_rate_pct: float
    runtime_timeouts: int
    mean_latency_ms: float
    median_latency_ms: float
    p95_latency_ms: float
    primary_failure_counts: Dict[str, int]
    property_failure_counts: Dict[str, int]
    grounding_failure_counts: Dict[str, int]


class PairedComparisonResult(BaseModel):
    """Result of paired McNemar hypothesis test on a binary endpoint."""
    endpoint_name: str
    contingency_table: Dict[str, int]  # {'a_both_pos': int, 'b_ta_pos_td_neg': int, 'c_ta_neg_td_pos': int, 'd_both_neg': int}
    total_pairs: int
    ta_positive_count: int
    td_positive_count: int
    discordant_pairs: int
    exact_p_value: float
    odds_ratio: Optional[float] = None
    effect_size_diff_pct: float


class Phase11_5AnalysisReport(BaseModel):
    """Comprehensive analysis report for Phase 11.5 confirmatory benchmark."""
    p4_ta_metrics: ConfirmatoryConditionMetrics
    p5_td_metrics: ConfirmatoryConditionMetrics
    primary_paired_test: PairedComparisonResult
    secondary_paired_tests: Dict[str, PairedComparisonResult]
    total_scenarios_evaluated: int
    total_calls_analyzed: int
    population_verified: bool


def compute_condition_metrics(records: List[Dict[str, Any]], condition_id: str) -> ConfirmatoryConditionMetrics:
    """Computes all 23 required secondary metrics for a condition."""
    subset = [r for r in records if r["condition_id"] == condition_id]
    total_calls = len(subset)
    track_id = subset[0]["context"]["context_track"] if subset else "UNKNOWN"

    vuln_records = [r for r in subset if r["vulnerable_variant"]]
    control_records = [r for r in subset if not r["vulnerable_variant"]]

    cand_hyp = 0
    valid_typed = 0
    completed_calls = 0
    useful_vuln = 0
    correct_vuln_dec = 0
    correct_ctrl_abst = 0
    fp = 0
    fn = 0
    vuln_abst = 0
    ctrl_abst = 0

    grounding_eligible = 0
    grounding_success = 0
    schema_failures = 0
    prop_eligible = 0
    prop_compatible = 0
    polarity_failures = 0
    action_incompatibilities = 0
    cat_incompatibilities = 0
    timeouts = 0

    latencies: List[float] = []
    primary_failures: Counter = Counter()
    property_failures: Counter = Counter()
    grounding_failures: Counter = Counter()

    for r in subset:
        val = r["validation"]
        att = r["attribution"]
        rt = r["runtime_telemetry"]
        mo = r["model_output"]
        is_vuln = r["vulnerable_variant"]

        lat = rt.get("total_latency_ms", 0.0)
        latencies.append(lat)

        p_code = att.get("primary_failure_code", "UNKNOWN")
        primary_failures[p_code] += 1

        sp_code = val.get("security_property_failure_code")
        if sp_code:
            property_failures[sp_code] += 1

        g_code = val.get("grounding_failure_code")
        if g_code:
            grounding_failures[g_code] += 1

        if rt.get("timed_out", False):
            timeouts += 1
        else:
            completed_calls += 1

        if not val.get("schema_valid", False) and not rt.get("timed_out", False):
            schema_failures += 1

        dec = mo.get("candidate_decision")
        is_hyp = (dec == "HYPOTHESIS")
        is_abst = (dec in ("NO_RELEVANT_FUNCTIONALITY", "INSUFFICIENT_EVIDENCE"))

        if is_hyp:
            cand_hyp += 1

        if is_vuln:
            if is_hyp:
                correct_vuln_dec += 1
            elif is_abst:
                vuln_abst += 1
                fn += 1
        else:
            # Control scenario
            if is_abst:
                ctrl_abst += 1
                if val.get("grounding_valid", True):
                    correct_ctrl_abst += 1
            elif is_hyp:
                fp += 1

        if val.get("schema_valid", False) and not rt.get("timed_out", False):
            grounding_eligible += 1
            if val.get("grounding_valid", False):
                grounding_success += 1

            if is_hyp:
                prop_eligible += 1
                if val.get("property_valid", False):
                    prop_compatible += 1
                else:
                    cat_incompatibilities += 1

                if not val.get("polarity_valid", False):
                    polarity_failures += 1

                if not val.get("skeleton_compliant", False):
                    action_incompatibilities += 1

        if val.get("is_valid_typed_experiment", False):
            valid_typed += 1

        if val.get("is_useful_vulnerable_hypothesis", False):
            useful_vuln += 1

    total_vuln = len(vuln_records)
    total_ctrl = len(control_records)

    vter = (valid_typed / cand_hyp * 100.0) if cand_hyp > 0 else 0.0
    completed_cand_hyp = sum(1 for r in subset if r.get("model_output", {}).get("candidate_decision") == "HYPOTHESIS" and not r.get("runtime_telemetry", {}).get("timed_out", False))
    comp_vter = (valid_typed / completed_cand_hyp * 100.0) if completed_cand_hyp > 0 else 0.0
    useful_rate = (useful_vuln / total_vuln * 100.0) if total_vuln > 0 else 0.0
    tpr = (useful_vuln / total_vuln * 100.0) if total_vuln > 0 else 0.0
    tnr = (correct_ctrl_abst / total_ctrl * 100.0) if total_ctrl > 0 else 0.0
    vuln_abst_rate = (vuln_abst / total_vuln * 100.0) if total_vuln > 0 else 0.0
    ctrl_abst_rate = (ctrl_abst / total_ctrl * 100.0) if total_ctrl > 0 else 0.0

    gsr = (grounding_success / grounding_eligible * 100.0) if grounding_eligible > 0 else 0.0
    sfr = (schema_failures / total_calls * 100.0) if total_calls > 0 else 0.0
    pcr = (prop_compatible / prop_eligible * 100.0) if prop_eligible > 0 else 0.0
    pfr = (polarity_failures / cand_hyp * 100.0) if cand_hyp > 0 else 0.0
    air = (action_incompatibilities / cand_hyp * 100.0) if cand_hyp > 0 else 0.0
    cir = (cat_incompatibilities / cand_hyp * 100.0) if cand_hyp > 0 else 0.0

    mean_lat = round(statistics.mean(latencies), 1) if latencies else 0.0
    median_lat = round(statistics.median(latencies), 1) if latencies else 0.0
    sorted_lats = sorted(latencies)
    p95_idx = int(math.ceil(0.95 * len(sorted_lats))) - 1
    p95_lat = round(sorted_lats[p95_idx], 1) if sorted_lats else 0.0

    return ConfirmatoryConditionMetrics(
        condition_id=condition_id,
        track_id=track_id,
        total_calls=total_calls,
        vulnerable_calls=total_vuln,
        control_calls=total_ctrl,
        candidate_hypotheses=cand_hyp,
        valid_typed_experiments=valid_typed,
        vter_pct=round(vter, 2),
        completed_call_vter_pct=round(comp_vter, 2),
        useful_vulnerable_hypotheses=useful_vuln,
        useful_vulnerable_hypothesis_rate_pct=round(useful_rate, 2),
        correct_vulnerable_decisions=correct_vuln_dec,
        correct_control_abstentions=correct_ctrl_abst,
        tpr_pct=round(tpr, 2),
        tnr_pct=round(tnr, 2),
        false_positives=fp,
        false_negatives=fn,
        vuln_abstention_count=vuln_abst,
        vuln_abstention_rate_pct=round(vuln_abst_rate, 2),
        control_abstention_count=ctrl_abst,
        control_abstention_rate_pct=round(ctrl_abst_rate, 2),
        grounding_success_rate_pct=round(gsr, 2),
        schema_failure_rate_pct=round(sfr, 2),
        property_compatibility_rate_pct=round(pcr, 2),
        polarity_failure_rate_pct=round(pfr, 2),
        action_incompatibility_rate_pct=round(air, 2),
        category_incompatibility_rate_pct=round(cir, 2),
        runtime_timeouts=timeouts,
        mean_latency_ms=mean_lat,
        median_latency_ms=median_lat,
        p95_latency_ms=p95_lat,
        primary_failure_counts=dict(primary_failures),
        property_failure_counts=dict(property_failures),
        grounding_failure_counts=dict(grounding_failures),
    )


def compute_paired_comparison(
    records: List[Dict[str, Any]],
    endpoint_extractor: Any,
    endpoint_name: str,
    vulnerable_only: bool = False,
    control_only: bool = False,
) -> PairedComparisonResult:
    """Computes paired 2x2 contingency table and exact McNemar test for an endpoint."""
    scenario_ids = sorted(list({r["scenario_id"] for r in records}))
    if vulnerable_only:
        vuln_sids = {r["scenario_id"] for r in records if r["vulnerable_variant"]}
        scenario_ids = [s for s in scenario_ids if s in vuln_sids]
    elif control_only:
        ctrl_sids = {r["scenario_id"] for r in records if not r["vulnerable_variant"]}
        scenario_ids = [s for s in scenario_ids if s in ctrl_sids]

    a = 0  # TA +, TD +
    b = 0  # TA +, TD -
    c = 0  # TA -, TD +
    d = 0  # TA -, TD -

    for sid in scenario_ids:
        ta_rec = next((r for r in records if r["scenario_id"] == sid and r["condition_id"] == "P4_TRACK_A"), None)
        td_rec = next((r for r in records if r["scenario_id"] == sid and r["condition_id"] == "P5_TRACK_D"), None)

        ta_pos = endpoint_extractor(ta_rec) if ta_rec else False
        td_pos = endpoint_extractor(td_rec) if td_rec else False

        if ta_pos and td_pos:
            a += 1
        elif ta_pos and not td_pos:
            b += 1
        elif not ta_pos and td_pos:
            c += 1
        else:
            d += 1

    total = len(scenario_ids)
    ta_pos_cnt = a + b
    td_pos_cnt = a + c
    discordant = b + c
    p_val = exact_mcnemar_test(b, c)
    odds_ratio = (b / c) if c > 0 else (float("inf") if b > 0 else 1.0)
    diff_pct = round(((td_pos_cnt - ta_pos_cnt) / total * 100.0), 2) if total > 0 else 0.0

    return PairedComparisonResult(
        endpoint_name=endpoint_name,
        contingency_table={
            "a_both_pos": a,
            "b_ta_pos_td_neg": b,
            "c_ta_neg_td_pos": c,
            "d_both_neg": d,
        },
        total_pairs=total,
        ta_positive_count=ta_pos_cnt,
        td_positive_count=td_pos_cnt,
        discordant_pairs=discordant,
        exact_p_value=round(p_val, 6),
        odds_ratio=round(odds_ratio, 3) if odds_ratio != float("inf") else None,
        effect_size_diff_pct=diff_pct,
    )


def analyze_phase11_5_confirmatory(records: List[Dict[str, Any]]) -> Phase11_5AnalysisReport:
    """Executes full population confirmatory statistical analysis."""
    p4_metrics = compute_condition_metrics(records, "P4_TRACK_A")
    p5_metrics = compute_condition_metrics(records, "P5_TRACK_D")

    # Primary Paired Endpoint: Useful Vulnerable Hypothesis (evaluated on 36 vulnerable scenarios)
    primary_test = compute_paired_comparison(
        records=records,
        endpoint_extractor=lambda r: bool(r.get("validation", {}).get("is_useful_vulnerable_hypothesis", False)),
        endpoint_name="Useful Vulnerable Hypothesis (Primary)",
        vulnerable_only=True,
    )

    # Secondary Paired Endpoints
    sec_tests = {
        "valid_typed_experiment": compute_paired_comparison(
            records=records,
            endpoint_extractor=lambda r: bool(r.get("validation", {}).get("is_valid_typed_experiment", False)),
            endpoint_name="Valid Typed Experiment (All 84 Scenarios)",
            vulnerable_only=False,
        ),
        "grounding_validity": compute_paired_comparison(
            records=records,
            endpoint_extractor=lambda r: bool(r.get("validation", {}).get("grounding_valid", False)),
            endpoint_name="Grounding Validity (All 84 Scenarios)",
            vulnerable_only=False,
        ),
        "schema_validity": compute_paired_comparison(
            records=records,
            endpoint_extractor=lambda r: bool(r.get("validation", {}).get("schema_valid", False)),
            endpoint_name="Schema Validity (All 84 Scenarios)",
            vulnerable_only=False,
        ),
        "correct_control_abstention": compute_paired_comparison(
            records=records,
            endpoint_extractor=lambda r: bool(
                not r.get("vulnerable_variant", True)
                and r.get("model_output", {}).get("candidate_decision") in ("NO_RELEVANT_FUNCTIONALITY", "INSUFFICIENT_EVIDENCE")
                and r.get("validation", {}).get("grounding_valid", True)
            ),
            endpoint_name="Correct Control Abstention (48 Control Scenarios)",
            vulnerable_only=False,
            control_only=True,
        ),
    }

    scen_count = len({r["scenario_id"] for r in records})

    return Phase11_5AnalysisReport(
        p4_ta_metrics=p4_metrics,
        p5_td_metrics=p5_metrics,
        primary_paired_test=primary_test,
        secondary_paired_tests=sec_tests,
        total_scenarios_evaluated=scen_count,
        total_calls_analyzed=len(records),
        population_verified=(scen_count == 84 and len(records) == 168),
    )
