"""
Milestone M5 Phase 11.1: Failure Attribution Engine.

Applies deterministic precedence rules to classify model outputs into exactly
one primary failure code and a list of contributing failure codes.
"""

from typing import Any, Dict, List, Optional, Set, Tuple
from src.engine.decision_policy import ExperimentPolarityValidator
from src.eval.phase11_failure_analysis.taxonomy import (
    FailureCode,
    FailureAttributionResult,
    TAXONOMY_METADATA,
)


def evaluate_action_compatibility(
    category_id: Optional[str],
    experiment_action: Optional[str],
) -> Tuple[bool, Optional[str], Set[str], Set[str]]:
    """
    Checks if an experiment action is compatible with the vulnerability category.
    Returns (is_compatible, reason, valid_breaches, valid_safes).
    """
    if not category_id:
        return False, "Missing category_id", set(), set()
    cat = category_id.strip()
    registry = ExperimentPolarityValidator.TUPLE_COMPATIBILITY_REGISTRY
    if cat not in registry:
        return False, f"Unregistered category: '{cat}'", set(), set()

    cat_actions = registry[cat]
    if not experiment_action:
        return False, "Missing experiment_action", set(), set()
    act = experiment_action.strip()
    if act not in cat_actions:
        return False, f"Action '{act}' not permitted for category '{cat}'", set(), set()

    breach_set, safe_set = cat_actions[act]
    return True, None, breach_set, safe_set


def is_exact_polarity_inversion(
    supporting_outcome: Optional[str],
    disproving_outcome: Optional[str],
    valid_breaches: Set[str],
    valid_safes: Set[str],
) -> bool:
    """Returns True if supporting outcome is in safe set and disproving outcome is in breach set."""
    if not supporting_outcome or not disproving_outcome:
        return False
    supp = supporting_outcome.strip()
    disp = disproving_outcome.strip()
    return supp in valid_safes and disp in valid_breaches


def attribute_failure(
    record: Dict[str, Any],
    scenario_category_id: Optional[str] = None,
    ground_truth_vulnerable: Optional[bool] = None,
) -> FailureAttributionResult:
    """
    Deterministically attributes failure categories for a single call record.
    Follows rigid precedence ladder:
      1. Runtime / Transport
      2. Parser
      3. Schema / Protocol
      4. Grounding
      5. Action Selection
      6. Polarity
      7. Category Selection
      8. Early Abstention
      9. Valid Typed Experiment / Success
      10. Unresolved (Fail-safe F99)
    """
    primary_cat_raw = str(record.get("primary_failure_category", "")).strip()
    cand_dec = str(record.get("candidate_decision", "")).strip()
    final_dec = str(record.get("final_decision", "")).strip()
    timed_out = bool(record.get("timed_out", False)) or primary_cat_raw == "RUNTIME_TIMEOUT"
    is_vuln = bool(record.get("vulnerable_variant", ground_truth_vulnerable if ground_truth_vulnerable is not None else False))
    cat_id = str(record.get("category_id") or scenario_category_id or "").strip()
    act = record.get("experiment_action")
    supp = record.get("supporting_outcome")
    disp = record.get("disproving_outcome")
    cond_id = str(record.get("condition_id", "")).strip()
    track_id = str(record.get("track_id", "")).strip()
    is_track_d = "D" in cond_id or "D" in track_id or "TRACK_D" in track_id

    is_hyp_cand = (
        "HYPOTHESIS" in cand_dec
        or "HYPOTHESIS" in final_dec
        or (act is not None and supp is not None and disp is not None)
    )

    act_ok, act_reason, valid_breaches, valid_safes = evaluate_action_compatibility(cat_id, act)
    polarity_ok = bool(record.get("polarity_valid", False))
    skeleton_ok = record.get("skeleton_compliant")
    grounding_ok = primary_cat_raw != "SEMANTIC_GROUNDING_FAILURE"

    exact_inversion = is_exact_polarity_inversion(supp, disp, valid_breaches, valid_safes)

    contributing: List[FailureCode] = []
    details: Dict[str, Any] = {
        "candidate_decision": cand_dec,
        "experiment_action": act,
        "supporting_outcome": supp,
        "disproving_outcome": disp,
        "polarity_reason": record.get("polarity_reason"),
        "skeleton_reason": record.get("skeleton_reason"),
        "raw_primary_category": primary_cat_raw,
    }

    # Evaluate Precedence Ladder for Primary Failure
    primary_code: Optional[FailureCode] = None

    # Step 1: Runtime / Transport Gate
    if timed_out:
        primary_code = FailureCode.F02
        if is_track_d:
            contributing.append(FailureCode.F12)
            contributing.append(FailureCode.F13)
    elif primary_cat_raw == "RUNTIME_TRANSPORT_FAILURE":
        primary_code = FailureCode.F03

    # Step 2: Parser Gate
    elif primary_cat_raw == "PARSER_FAILURE":
        primary_code = FailureCode.F04
        if is_track_d:
            contributing.append(FailureCode.F12)

    # Step 3: Schema / Protocol Gate
    elif primary_cat_raw == "SCHEMA_VALIDITY_FAILURE":
        primary_code = FailureCode.F05
        if is_track_d:
            contributing.append(FailureCode.F12)

    # Step 4: Grounding Gate
    elif primary_cat_raw == "SEMANTIC_GROUNDING_FAILURE":
        primary_code = FailureCode.F06
        contributing.append(FailureCode.F15)
        if is_track_d:
            contributing.append(FailureCode.F12)
            contributing.append(FailureCode.F13)

    # Step 5: Action Selection Gate
    elif is_hyp_cand and not act_ok:
        primary_code = FailureCode.F08
        details["action_error"] = act_reason
        if not polarity_ok:
            contributing.append(FailureCode.F07)

    # Step 6: Polarity Gate
    elif is_hyp_cand and (not polarity_ok or primary_cat_raw == "SEMANTIC_EXPERIMENT_POLARITY_FAILURE"):
        primary_code = FailureCode.F07
        if exact_inversion:
            contributing.append(FailureCode.F16)
        if supp == disp and supp is not None:
            details["tautological_outcomes"] = True

    # Step 7: Category Selection Gate (if category mismatch detected)
    elif is_hyp_cand and scenario_category_id and cat_id != scenario_category_id:
        primary_code = FailureCode.F09

    # Step 8: Early Abstention Gate (on vulnerable target)
    elif not is_hyp_cand and is_vuln and primary_cat_raw == "VALID":
        primary_code = FailureCode.F11
        contributing.append(FailureCode.F10)

    # Step 9: Verification & Success Gate
    elif primary_cat_raw == "VALID":
        # Check if it is a valid typed experiment
        is_valid_typed = False
        if is_hyp_cand:
            if cond_id in ["C1", "C2"]:
                is_valid_typed = bool(skeleton_ok) and polarity_ok
            else:
                is_valid_typed = polarity_ok
        else:
            # Valid abstention on control
            is_valid_typed = not is_vuln

        if is_valid_typed:
            primary_code = FailureCode.F01
        else:
            primary_code = FailureCode.F99

    # Step 10: Fallback / Unresolved
    else:
        primary_code = FailureCode.F99

    # Ensure primary code is in contributing list
    if primary_code not in contributing:
        contributing.insert(0, primary_code)

    is_valid_typed_exp = (primary_code == FailureCode.F01 and is_hyp_cand)

    return FailureAttributionResult(
        primary_code=primary_code,
        primary_name=TAXONOMY_METADATA[primary_code]["name"],
        contributing_codes=contributing,
        observed_validator_failure=primary_cat_raw,
        is_valid_typed=is_valid_typed_exp,
        is_hypothesis_candidate=is_hyp_cand,
        is_action_compatible=act_ok,
        is_polarity_valid=polarity_ok,
        is_grounding_valid=grounding_ok,
        is_exact_polarity_inversion=exact_inversion,
        details=details,
    )
