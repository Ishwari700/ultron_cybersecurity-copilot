"""
Milestone M5 Phase 11.1: Polarity and Falsification Analysis.

Analyzes candidate hypothesis attempts to evaluate:
- Pure action failure vs pure polarity failure vs compound failures
- Exact polarity inversions (supporting in safe set, disproving in breach set)
- Tautological outcomes (supporting == disproving)
- Vocabulary compliance and token distributions
"""

from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

from src.engine.decision_policy import ExperimentPolarityValidator
from src.eval.phase11_failure_analysis.attribution import (
    evaluate_action_compatibility,
    is_exact_polarity_inversion,
)


def run_polarity_analysis(
    corpus_records: List[Dict[str, Any]],
    phase_filter: Optional[str] = "PHASE_10",
) -> Dict[str, Any]:
    """
    Performs deterministic polarity and falsification analysis across corpus records.
    Filters by phase if specified (defaults to PHASE_10).
    """
    records = corpus_records
    if phase_filter:
        records = [r for r in records if r["provenance"]["source_phase"] == phase_filter]

    # Filter to candidate hypothesis attempts
    candidate_records = [
        r for r in records
        if r["attribution"].get("is_hypothesis_candidate", False)
        or (
            r["model_output"]["experiment_action"] is not None
            and r["model_output"]["supporting_outcome"] is not None
        )
    ]

    failure_partition: Dict[str, int] = {
        "valid_typed_experiments": 0,
        "pure_action_failure": 0,
        "pure_polarity_failure": 0,
        "compound_action_and_polarity_failure": 0,
        "category_failure": 0,
        "other_candidate_failure": 0,
    }

    polarity_details: Dict[str, int] = {
        "exact_polarity_inversion": 0,
        "tautological_identical_outcomes": 0,
        "invalid_breach_token": 0,
        "invalid_safe_token": 0,
        "both_tokens_invalid": 0,
    }

    condition_polarity_stats: Dict[str, Dict[str, int]] = defaultdict(lambda: {
        "candidate_attempts": 0,
        "valid_typed": 0,
        "pure_polarity_failures": 0,
        "exact_inversions": 0,
        "action_failures": 0,
        "timeouts_or_grounding": 0,
    })

    inversion_cases: List[Dict[str, Any]] = []

    for r in candidate_records:
        cid = r["identity"]["condition_id"]
        cat_id = r["identity"]["target_category_id"]
        act = r["model_output"]["experiment_action"]
        supp = r["model_output"]["supporting_outcome"]
        disp = r["model_output"]["disproving_outcome"]

        stats = condition_polarity_stats[cid]
        stats["candidate_attempts"] += 1

        reg = ExperimentPolarityValidator.TUPLE_COMPATIBILITY_REGISTRY
        if cat_id not in reg:
            failure_partition["category_failure"] += 1
            continue

        act_ok, act_reason, valid_breaches, valid_safes = evaluate_action_compatibility(cat_id, act)
        polarity_ok = bool(r["attribution"]["polarity_valid"])
        p_code = r["attribution"]["primary_failure_code"]

        if p_code == "VALID_TYPED" and r["attribution"]["is_valid_typed_experiment"]:
            failure_partition["valid_typed_experiments"] += 1
            stats["valid_typed"] += 1
            continue

        if p_code in ["RUNTIME_TIMEOUT", "GROUNDING_FAILURE", "SCHEMA_FAILURE"]:
            stats["timeouts_or_grounding"] += 1

        # Check polarity details
        exact_inv = is_exact_polarity_inversion(supp, disp, valid_breaches, valid_safes)
        if exact_inv:
            polarity_details["exact_polarity_inversion"] += 1
            stats["exact_inversions"] += 1
            inversion_cases.append({
                "scenario_id": r["identity"]["scenario_id"],
                "condition_id": cid,
                "category_id": cat_id,
                "action": act,
                "supporting_outcome": supp,
                "disproving_outcome": disp,
            })

        if supp and disp and supp.strip() == disp.strip():
            polarity_details["tautological_identical_outcomes"] += 1

        supp_bad = supp not in valid_breaches if supp else True
        disp_bad = disp not in valid_safes if disp else True
        if supp_bad and disp_bad:
            polarity_details["both_tokens_invalid"] += 1
        elif supp_bad:
            polarity_details["invalid_breach_token"] += 1
        elif disp_bad:
            polarity_details["invalid_safe_token"] += 1

        # 4-way Partitioning
        if not act_ok and not polarity_ok:
            failure_partition["compound_action_and_polarity_failure"] += 1
            stats["action_failures"] += 1
        elif not act_ok and polarity_ok:
            failure_partition["pure_action_failure"] += 1
            stats["action_failures"] += 1
        elif act_ok and not polarity_ok:
            failure_partition["pure_polarity_failure"] += 1
            stats["pure_polarity_failures"] += 1
        else:
            failure_partition["other_candidate_failure"] += 1

    total_cand = len(candidate_records)

    return {
        "phase": phase_filter,
        "total_candidate_attempts": total_cand,
        "failure_partition": failure_partition,
        "polarity_mechanism_details": polarity_details,
        "condition_breakdown": dict(condition_polarity_stats),
        "exact_inversion_count": len(inversion_cases),
        "sample_inversions": inversion_cases[:10],
    }


def format_polarity_partition_markdown(analysis_res: Dict[str, Any]) -> str:
    """Formats the failure partition into a GitHub markdown table."""
    fp = analysis_res["failure_partition"]
    total = analysis_res["total_candidate_attempts"]

    lines = []
    lines.append("| Failure Sub-Category | Candidate Attempts | Percentage of Candidates | Description |")
    lines.append("| :--- | :---: | :---: | :--- |")

    descriptions = {
        "valid_typed_experiments": "Passed all action, polarity, and skeleton checks",
        "pure_polarity_failure": "Legal action selected, but breach/safe predicates failed or inverted",
        "compound_action_and_polarity_failure": "Both action was incompatible and outcomes were invalid",
        "pure_action_failure": "Incompatible action, but outcomes theoretically aligned",
        "category_failure": "Category unrecognized or mismatched",
        "other_candidate_failure": "Timeout, grounding, or schema failure before polarity check",
    }

    for key, count in fp.items():
        pct = (count / total * 100.0) if total > 0 else 0.0
        name = key.replace("_", " ").title()
        desc = descriptions.get(key, "")
        lines.append(f"| **{name}** | {count} | {pct:.2f}% | {desc} |")

    return "\n".join(lines)
