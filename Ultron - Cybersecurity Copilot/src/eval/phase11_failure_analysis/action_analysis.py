"""
Milestone M5 Phase 11.1: Action Selection Analysis.

Analyzes candidate hypothesis attempts to evaluate:
- Model-selected experiment actions vs deterministically legal actions
- Action confusion matrix
- Action compatibility breakdown by condition, category, and context package
"""

from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

from src.engine.decision_policy import ExperimentPolarityValidator
from src.engine.experiment_skeleton import resolve_deterministic_action


def run_action_selection_analysis(
    corpus_records: List[Dict[str, Any]],
    phase_filter: Optional[str] = "PHASE_10",
) -> Dict[str, Any]:
    """
    Performs deterministic action selection analysis across corpus records.
    Filters by phase if specified (defaults to PHASE_10).
    """
    records = corpus_records
    if phase_filter:
        records = [r for r in records if r["provenance"]["source_phase"] == phase_filter]

    # Filter to candidate hypothesis attempts
    candidate_records = [
        r for r in records
        if r["attribution"].get("is_hypothesis_candidate", False)
        or r["model_output"]["experiment_action"] is not None
    ]

    # All known actions in protocol
    all_known_actions = [
        "SUBSTITUTE_RESOURCE_IDENTIFIER",
        "EXECUTE_OUT_OF_ORDER_TRANSITION",
        "REPLAY_STEP_WITH_LOWER_ROLE",
        "INVOKE_WITHOUT_CREDENTIALS",
        "TAMPER_REQUEST_PARAMETER",
    ]

    confusion_matrix: Dict[str, Dict[str, int]] = {
        m_act: {l_act: 0 for l_act in all_known_actions + ["OTHER_LEGAL"]}
        for m_act in all_known_actions + ["NONE_OR_UNKNOWN"]
    }

    condition_action_stats: Dict[str, Dict[str, int]] = defaultdict(lambda: {
        "candidate_attempts": 0,
        "action_compatible": 0,
        "action_incompatible": 0,
        "action_missing": 0,
    })

    category_action_stats: Dict[str, Dict[str, int]] = defaultdict(lambda: {
        "candidate_attempts": 0,
        "action_compatible": 0,
        "action_incompatible": 0,
    })

    incompatible_cases: List[Dict[str, Any]] = []

    for r in candidate_records:
        cid = r["identity"]["condition_id"]
        cat_id = r["identity"]["target_category_id"]
        model_act = r["model_output"]["experiment_action"]

        condition_action_stats[cid]["candidate_attempts"] += 1
        category_action_stats[cat_id]["candidate_attempts"] += 1

        # Determine legal action(s) for this category
        reg = ExperimentPolarityValidator.TUPLE_COMPATIBILITY_REGISTRY
        legal_actions = list(reg.get(cat_id, {}).keys())
        primary_legal = resolve_deterministic_action(cat_id) if cat_id in reg else "UNKNOWN"

        m_key = model_act if model_act in all_known_actions else "NONE_OR_UNKNOWN"
        l_key = primary_legal if primary_legal in all_known_actions else "OTHER_LEGAL"

        confusion_matrix[m_key][l_key] += 1

        if not model_act:
            condition_action_stats[cid]["action_missing"] += 1
            condition_action_stats[cid]["action_incompatible"] += 1
            category_action_stats[cat_id]["action_incompatible"] += 1
            incompatible_cases.append({
                "scenario_id": r["identity"]["scenario_id"],
                "condition_id": cid,
                "category_id": cat_id,
                "model_action": None,
                "primary_legal_action": primary_legal,
                "reason": "Missing action",
            })
        elif model_act in legal_actions:
            condition_action_stats[cid]["action_compatible"] += 1
            category_action_stats[cat_id]["action_compatible"] += 1
        else:
            condition_action_stats[cid]["action_incompatible"] += 1
            category_action_stats[cat_id]["action_incompatible"] += 1
            incompatible_cases.append({
                "scenario_id": r["identity"]["scenario_id"],
                "condition_id": cid,
                "category_id": cat_id,
                "model_action": model_act,
                "primary_legal_action": primary_legal,
                "legal_actions": legal_actions,
                "reason": f"Action '{model_act}' incompatible with category '{cat_id}'",
            })

    # Summary rates
    total_cand = len(candidate_records)
    total_compat = sum(s["action_compatible"] for s in condition_action_stats.values())
    total_incompat = sum(s["action_incompatible"] for s in condition_action_stats.values())

    return {
        "phase": phase_filter,
        "total_candidate_attempts": total_cand,
        "total_action_compatible": total_compat,
        "total_action_incompatible": total_incompat,
        "action_compatibility_rate": round(total_compat / total_cand * 100.0, 2) if total_cand > 0 else 0.0,
        "confusion_matrix": confusion_matrix,
        "condition_breakdown": dict(condition_action_stats),
        "category_breakdown": dict(category_action_stats),
        "incompatible_cases_count": len(incompatible_cases),
        "sample_incompatible_cases": incompatible_cases[:10],
    }


def format_action_confusion_markdown(analysis_res: Dict[str, Any]) -> str:
    """Formats the action confusion matrix into a GitHub markdown table."""
    cm = analysis_res["confusion_matrix"]
    legal_cols = [
        "SUBSTITUTE_RESOURCE_IDENTIFIER",
        "EXECUTE_OUT_OF_ORDER_TRANSITION",
        "REPLAY_STEP_WITH_LOWER_ROLE",
        "INVOKE_WITHOUT_CREDENTIALS",
        "TAMPER_REQUEST_PARAMETER",
    ]

    short_names = {
        "SUBSTITUTE_RESOURCE_IDENTIFIER": "SUB_ID",
        "EXECUTE_OUT_OF_ORDER_TRANSITION": "OUT_OF_ORDER",
        "REPLAY_STEP_WITH_LOWER_ROLE": "LOWER_ROLE",
        "INVOKE_WITHOUT_CREDENTIALS": "NO_CREDS",
        "TAMPER_REQUEST_PARAMETER": "TAMPER_PARAM",
        "NONE_OR_UNKNOWN": "NONE/UNK",
        "OTHER_LEGAL": "OTHER",
    }

    lines = []
    lines.append("| Model Selected Action \\ Legal Action | " + " | ".join(short_names.get(c, c) for c in legal_cols) + " | Total Model |")
    lines.append("| :--- | " + " | ".join([":---:"] * len(legal_cols)) + " | :---: |")

    for m_act in list(cm.keys()):
        row = [cm[m_act].get(l_act, 0) for l_act in legal_cols]
        total_m = sum(cm[m_act].values())
        if total_m > 0:
            lines.append(f"| **{short_names.get(m_act, m_act)}** | " + " | ".join(str(cnt) for cnt in row) + f" | **{total_m}** |")

    return "\n".join(lines)
