"""
Milestone M5 Phase 11.5: Canonical Reconciliation and Metrics Verification Engine.

Performs rigorous post-execution statistical reconciliation of the immutable Phase 11.5
confirmatory live benchmark dataset (data/eval/m5_phase11_5_live_results.json).

Generates:
  - data/eval/m5_phase11_5_canonical_metrics.json
Ensures absolute mathematical consistency across:
  - Canonical denominators
  - Failure taxonomy (primary and contributing)
  - Paired contingency tables and McNemar tests
  - Disputed-record audit
"""

from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import statistics
from typing import Any, Dict, List, Optional

from src.eval.phase11_5_confirmatory.analysis import (
    analyze_phase11_5_confirmatory,
    exact_mcnemar_test,
    Phase11_5AnalysisReport,
)

EXPECTED_RAW_RESULTS_SHA256 = "27cc801cc020da3e4a905d9142780e8e4394afcf58027f01cdfde0d18da98a6f"
REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent


def compute_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compute_file_sha256(path: Path) -> str:
    if not path.exists():
        return "FILE_NOT_FOUND"
    return compute_sha256(path.read_bytes())


def generate_canonical_metrics(
    raw_results_path: Optional[Path] = None,
    output_metrics_path: Optional[Path] = None,
    repo_root: Optional[Path] = None,
) -> Dict[str, Any]:
    """Generates the authoritative data/eval/m5_phase11_5_canonical_metrics.json artifact."""
    root = repo_root or REPO_ROOT
    raw_path = raw_results_path or (root / "data/eval/m5_phase11_5_live_results.json")
    out_path = output_metrics_path or (root / "data/eval/m5_phase11_5_canonical_metrics.json")

    assert raw_path.exists(), f"Raw results file not found at {raw_path}"
    raw_bytes = raw_path.read_bytes()
    raw_sha = compute_sha256(raw_bytes)
    assert raw_sha == EXPECTED_RAW_RESULTS_SHA256, (
        f"Raw results hash mismatch! Expected {EXPECTED_RAW_RESULTS_SHA256}, got {raw_sha}"
    )

    records: List[Dict[str, Any]] = json.loads(raw_bytes.decode("utf-8"))
    assert len(records) == 168, f"Expected 168 records, got {len(records)}"

    p4_records = [r for r in records if r["condition_id"] == "P4_TRACK_A"]
    p5_records = [r for r in records if r["condition_id"] == "P5_TRACK_D"]
    assert len(p4_records) == 84, f"Expected 84 P4 records, got {len(p4_records)}"
    assert len(p5_records) == 84, f"Expected 84 P5 records, got {len(p5_records)}"

    unique_scenarios = sorted(list({r["scenario_id"] for r in records}))
    assert len(unique_scenarios) == 84, f"Expected 84 unique scenarios, got {len(unique_scenarios)}"

    vuln_scenarios = sorted(list({r["scenario_id"] for r in records if r["vulnerable_variant"]}))
    ctrl_scenarios = sorted(list({r["scenario_id"] for r in records if not r["vulnerable_variant"]}))
    assert len(vuln_scenarios) == 36, f"Expected 36 vulnerable scenarios, got {len(vuln_scenarios)}"
    assert len(ctrl_scenarios) == 48, f"Expected 48 control scenarios, got {len(ctrl_scenarios)}"

    # Run core statistical engine
    analysis_report: Phase11_5AnalysisReport = analyze_phase11_5_confirmatory(records)
    ta_m = analysis_report.p4_ta_metrics
    td_m = analysis_report.p5_td_metrics

    # Latency statistics
    def get_lat_stats(subset: List[Dict[str, Any]]) -> Dict[str, float]:
        lats = [r["runtime_telemetry"]["total_latency_ms"] for r in subset]
        s_lats = sorted(lats)
        p95_idx = int(0.95 * len(s_lats))
        return {
            "mean_ms": round(statistics.mean(lats), 1),
            "median_ms": round(statistics.median(lats), 1),
            "p95_ms": round(s_lats[p95_idx], 1),
            "min_ms": round(min(lats), 1),
            "max_ms": round(max(lats), 1),
        }

    p4_lat = get_lat_stats(p4_records)
    p5_lat = get_lat_stats(p5_records)

    # Contributing failures aggregation
    def get_contributing_counts(subset: List[Dict[str, Any]]) -> Dict[str, int]:
        c: Counter = Counter()
        for r in subset:
            for code in r.get("attribution", {}).get("contributing_failure_codes", []):
                c[code] += 1
        return dict(sorted(c.items()))

    p4_contrib = get_contributing_counts(p4_records)
    p5_contrib = get_contributing_counts(p5_records)

    # Disputed records audit (specifically tracking all non-standard P5 calls)
    disputed_records = []
    for r in p5_records:
        val = r["validation"]
        att = r["attribution"]
        rt = r["runtime_telemetry"]
        mo = r["model_output"]
        if (
            not val.get("is_valid_typed_experiment")
            or rt.get("timed_out")
            or mo.get("candidate_decision") != "HYPOTHESIS"
            or att.get("primary_failure_code") != "VALID_TYPED"
        ):
            disputed_records.append({
                "call_index": r["call_index"],
                "scenario_id": r["scenario_id"],
                "condition_id": r["condition_id"],
                "vulnerable_variant": r["vulnerable_variant"],
                "candidate_decision": mo.get("candidate_decision"),
                "timed_out": rt.get("timed_out"),
                "total_latency_ms": rt.get("total_latency_ms"),
                "raw_primary_category": att.get("details", {}).get("raw_primary_category"),
                "validation": {
                    "is_valid_typed_experiment": val.get("is_valid_typed_experiment"),
                    "is_useful_vulnerable_hypothesis": val.get("is_useful_vulnerable_hypothesis"),
                    "grounding_valid": val.get("grounding_valid"),
                    "schema_valid": val.get("schema_valid"),
                    "property_valid": val.get("property_valid"),
                    "polarity_valid": val.get("polarity_valid"),
                    "skeleton_compliant": val.get("skeleton_compliant"),
                },
                "attribution": {
                    "primary_failure_code": att.get("primary_failure_code"),
                    "primary_failure_name": att.get("primary_failure_name"),
                    "contributing_failure_codes": att.get("contributing_failure_codes"),
                },
                "reconciliation_explanation": (
                    "Early abstention on vulnerable scenario. The model abstained with NO_RELEVANT_FUNCTIONALITY, "
                    "which represents a false negative / premature abstention on a vulnerable target."
                    if r["call_index"] == 46 else
                    "Valid abstention on control scenario. The model correctly abstained with NO_RELEVANT_FUNCTIONALITY "
                    "on a patched control scenario. In the failure taxonomy, a valid abstention has no failure and is "
                    "classified under F01 (VALID / Success). However, an abstention is NOT an experiment proposal, so "
                    "validation.is_valid_typed_experiment is False. This accounts for the delta between 80 valid typed "
                    "experiments and 81 F01 success attributions in P5."
                    if r["call_index"] == 47 else
                    "Inference timeout exceeding the 30.0s hard cutoff ceiling. Elapsed latency exceeded 30.0s, "
                    "resulting in zero response payload generated."
                ),
            })

    canonical_data = {
        "metadata": {
            "title": "Milestone M5 Phase 11.5 Canonical Reconciled Metrics",
            "calculation_version": "1.0.0",
            "timestamp_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ"),
            "dataset_sha256": raw_sha,
            "raw_dataset_path": "data/eval/m5_phase11_5_live_results.json",
            "status": "IMMUTABLE_VERIFIED",
        },
        "population_counts": {
            "total_unique_scenarios": len(unique_scenarios),
            "vulnerable_scenarios": len(vuln_scenarios),
            "control_scenarios": len(ctrl_scenarios),
            "p4_track_a_calls": len(p4_records),
            "p5_track_d_calls": len(p5_records),
            "total_calls": len(records),
        },
        "denominators": {
            "A_ALL_CALLS": {
                "count_p4": 84,
                "count_p5": 84,
                "description": "Total scheduled inference calls per condition across all 84 scenarios.",
                "used_by": ["Runtime Timeouts", "All-Call Schema Validity", "All-Call Grounding Validity", "Latency Statistics"],
            },
            "B_COMPLETED_CALLS": {
                "count_p4": 84,
                "count_p5": 82,
                "description": "All calls minus runtime timeouts. P5 had 2 timeouts (calls 145 & 147), leaving 82 completed calls.",
                "used_by": ["Completed-Call Grounding Success Rate (82/82 = 100.0%)", "Completed-Call Schema Failure Rate (0/82 = 0.0%)", "Completed-Call VTER (80/80 = 100.0%)"],
            },
            "C_CANDIDATE_HYPOTHESES": {
                "count_p4": 84,
                "count_p5": 80,
                "description": "Calls where the model emitted candidate_decision == 'HYPOTHESIS'. In P5, 2 calls timed out and 2 calls abstained (NO_RELEVANT_FUNCTIONALITY), leaving 80 candidate hypotheses.",
                "used_by": ["Population VTER", "Completed-Call VTER", "Polarity Failure Rate", "Action Incompatibility Rate", "Category Incompatibility Rate"],
            },
            "D_VALID_TYPED_EXPERIMENTS": {
                "count_p4": 84,
                "count_p5": 80,
                "description": "Calls where validation.is_valid_typed_experiment is True (passed schema, skeleton, grounding, polarity, and security property gates).",
                "used_by": ["VTER Numerator", "Secondary Paired Comparison (Valid Typed Experiments)"],
            },
            "E_VULNERABLE_SCENARIOS": {
                "count_p4": 36,
                "count_p5": 36,
                "description": "Total vulnerable variant scenarios in the gold benchmark population.",
                "used_by": ["Primary Endpoint (Useful Vulnerable Hypothesis Yield)", "True Positive Rate (TPR)", "Vulnerable Abstention Rate", "False Negatives (FN)"],
            },
            "F_CONTROL_SCENARIOS": {
                "count_p4": 48,
                "count_p5": 48,
                "description": "Total control variant scenarios (patched, safe, or negative controls) in the gold benchmark population.",
                "used_by": ["Correct Control Abstention Rate", "True Negative Rate (TNR)", "Control Abstention Rate", "False Positives (FP)"],
            },
        },
        "per_condition_metrics": {
            "P4_TRACK_A": ta_m.model_dump(),
            "P5_TRACK_D": td_m.model_dump(),
            "deltas_p5_minus_p4": {
                "candidate_hypotheses": td_m.candidate_hypotheses - ta_m.candidate_hypotheses,
                "valid_typed_experiments": td_m.valid_typed_experiments - ta_m.valid_typed_experiments,
                "vter_pct": round(td_m.vter_pct - ta_m.vter_pct, 2),
                "completed_call_vter_pct": round(td_m.completed_call_vter_pct - ta_m.completed_call_vter_pct, 2),
                "useful_vulnerable_hypotheses": td_m.useful_vulnerable_hypotheses - ta_m.useful_vulnerable_hypotheses,
                "useful_vulnerable_hypothesis_rate_pct": round(td_m.useful_vulnerable_hypothesis_rate_pct - ta_m.useful_vulnerable_hypothesis_rate_pct, 2),
                "correct_vulnerable_decisions": td_m.correct_vulnerable_decisions - ta_m.correct_vulnerable_decisions,
                "correct_control_abstentions": td_m.correct_control_abstentions - ta_m.correct_control_abstentions,
                "tpr_pct": round(td_m.tpr_pct - ta_m.tpr_pct, 2),
                "tnr_pct": round(td_m.tnr_pct - ta_m.tnr_pct, 2),
                "false_positives": td_m.false_positives - ta_m.false_positives,
                "false_negatives": td_m.false_negatives - ta_m.false_negatives,
                "vuln_abstention_rate_pct": round(td_m.vuln_abstention_rate_pct - ta_m.vuln_abstention_rate_pct, 2),
                "control_abstention_rate_pct": round(td_m.control_abstention_rate_pct - ta_m.control_abstention_rate_pct, 2),
                "grounding_success_rate_pct": round(td_m.grounding_success_rate_pct - ta_m.grounding_success_rate_pct, 2),
                "schema_failure_rate_pct": round(td_m.schema_failure_rate_pct - ta_m.schema_failure_rate_pct, 2),
                "property_compatibility_rate_pct": round(td_m.property_compatibility_rate_pct - ta_m.property_compatibility_rate_pct, 2),
                "polarity_failure_rate_pct": round(td_m.polarity_failure_rate_pct - ta_m.polarity_failure_rate_pct, 2),
                "action_incompatibility_rate_pct": round(td_m.action_incompatibility_rate_pct - ta_m.action_incompatibility_rate_pct, 2),
                "category_incompatibility_rate_pct": round(td_m.category_incompatibility_rate_pct - ta_m.category_incompatibility_rate_pct, 2),
                "runtime_timeouts": td_m.runtime_timeouts - ta_m.runtime_timeouts,
                "mean_latency_ms": round(td_m.mean_latency_ms - ta_m.mean_latency_ms, 1),
                "median_latency_ms": round(td_m.median_latency_ms - ta_m.median_latency_ms, 1),
                "p95_latency_ms": round(td_m.p95_latency_ms - ta_m.p95_latency_ms, 1),
            },
        },
        "failure_taxonomy": {
            "primary_failure_distribution": {
                "P4_TRACK_A": ta_m.primary_failure_counts,
                "P5_TRACK_D": td_m.primary_failure_counts,
            },
            "contributing_failure_distribution": {
                "P4_TRACK_A": p4_contrib,
                "P5_TRACK_D": p5_contrib,
            },
            "reconciliation_note_on_f01": (
                "In P5 Track D, primary failure code VALID_TYPED (F01) has count 81, whereas valid typed experiments "
                "has count 80. The 81st F01 call is Call 47 (SCEN-ECOMMERCE_ORDERS-ORD-DISPATCH-PATCH-05), which is a control "
                "scenario where the model correctly abstained. In the failure taxonomy, a correct control abstention has no "
                "failure and is categorized under F01 (Success). However, because an abstention does not produce an experiment proposal, "
                "validation.is_valid_typed_experiment is False. Thus, P5 contains exactly 80 valid typed experiment proposals and "
                "1 valid control abstention (81 successful calls without failure)."
            ),
        },
        "paired_statistical_analysis": {
            "primary_endpoint": analysis_report.primary_paired_test.model_dump(),
            "secondary_endpoints": {
                k: v.model_dump() for k, v in analysis_report.secondary_paired_tests.items()
            },
        },
        "latency_statistics": {
            "P4_TRACK_A": p4_lat,
            "P5_TRACK_D": p5_lat,
        },
        "disputed_records_audit": disputed_records,
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(canonical_data, indent=2), encoding="utf-8")

    # Keep report in sync
    from src.eval.phase11_5_confirmatory.report_generation import generate_phase11_5_report
    generate_phase11_5_report(
        canonical_metrics_path=out_path,
        repo_root=root,
    )

    return canonical_data


if __name__ == "__main__":
    data = generate_canonical_metrics()
    h = compute_file_sha256(REPO_ROOT / "data/eval/m5_phase11_5_canonical_metrics.json")
    print(f"Canonical metrics generated successfully. SHA256: {h}")
