"""
Milestone M5 Phase 11.2: Deterministic Outcome Binding Engine.

Maps a validated AttackPredicate and (category_id, experiment_action) pair
to canonical supporting (breach) and disproving (safe) outcomes using the
trusted TUPLE_COMPATIBILITY_REGISTRY.

Guarantees:
- Deterministic derivation: 100% reproducible outcome binding.
- Strict fail-closed semantics: Ambiguous, misaligned, or unregistered predicates fail.
- Ground truth firewall: Operates with ZERO knowledge of scenario ground truth (vulnerable vs patched).
- Explicit provenance: Emitted outcomes are tagged with outcome_origin="DETERMINISTICALLY_DERIVED".
"""

from typing import Any, Dict, Optional, Set, Tuple
from pydantic import BaseModel, ConfigDict, Field

from src.engine.decision_policy import ExperimentPolarityValidator
from src.eval.phase11_2_polarity.attack_predicate import (
    AttackPredicate,
    CATEGORY_SECURITY_PROPERTY_MAP,
    SecurityPropertyDomain,
)

# Canonical primary breach/safe pairs for registered categories & actions
CANONICAL_PRIMARY_OUTCOME_PAIRS: Dict[Tuple[str, str], Tuple[str, str]] = {
    ("API-BOLA-001", "SUBSTITUTE_RESOURCE_IDENTIFIER"): (
        "HTTP_200_OK",
        "HTTP_403_FORBIDDEN",
    ),
    ("API-DEVICE-BOLA-001", "SUBSTITUTE_RESOURCE_IDENTIFIER"): (
        "HTTP_200_OK",
        "HTTP_403_FORBIDDEN",
    ),
    ("API-CROSS-TENANT-001", "SUBSTITUTE_RESOURCE_IDENTIFIER"): (
        "HTTP_200_OK",
        "HTTP_403_FORBIDDEN",
    ),
    ("API-STATE-001", "EXECUTE_OUT_OF_ORDER_TRANSITION"): (
        "STATE_TRANSITION_ACCEPTED",
        "STATE_TRANSITION_REJECTED",
    ),
    ("API-LIFECYCLE-001", "EXECUTE_OUT_OF_ORDER_TRANSITION"): (
        "STATE_TRANSITION_ACCEPTED",
        "STATE_TRANSITION_REJECTED",
    ),
    ("API-MULTI-STEP-AUTH-001", "EXECUTE_OUT_OF_ORDER_TRANSITION"): (
        "STATE_TRANSITION_ACCEPTED",
        "STATE_TRANSITION_REJECTED",
    ),
    ("API-ROLE-BOUNDARY-001", "REPLAY_STEP_WITH_LOWER_ROLE"): (
        "PRIVILEGE_ELEVATION_SUCCEEDS",
        "PRIVILEGE_ELEVATION_DENIED",
    ),
    ("API-BFLA-001", "REPLAY_STEP_WITH_LOWER_ROLE"): (
        "PRIVILEGE_ELEVATION_SUCCEEDS",
        "PRIVILEGE_ELEVATION_DENIED",
    ),
    ("API-BFLA-002", "REPLAY_STEP_WITH_LOWER_ROLE"): (
        "PRIVILEGE_ELEVATION_SUCCEEDS",
        "PRIVILEGE_ELEVATION_DENIED",
    ),
    ("API-AUTH-NONE", "INVOKE_WITHOUT_CREDENTIALS"): (
        "UNAUTHENTICATED_ACCESS_ALLOWED",
        "UNAUTHENTICATED_ACCESS_DENIED",
    ),
    ("API-MUTATION-001", "TAMPER_REQUEST_PARAMETER"): (
        "STATUS_SUCCESS_2XX",
        "STATUS_CLIENT_ERROR_4XX",
    ),
}


class OutcomeBindingResult(BaseModel):
    """Result of deterministic outcome binding from an AttackPredicate."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    is_valid: bool = Field(..., description="True if predicate and category-action binding succeeded")
    supporting_outcome: Optional[str] = Field(default=None, description="Derived breach outcome")
    disproving_outcome: Optional[str] = Field(default=None, description="Derived safe outcome")
    outcome_origin: str = Field(default="DETERMINISTICALLY_DERIVED", description="Provenance marker")
    error_message: Optional[str] = Field(default=None, description="Failure reason if invalid")
    diagnostic_details: Dict[str, Any] = Field(default_factory=dict, description="Audit telemetry")


def derive_outcomes_from_attack_predicate(
    category_id: Optional[str],
    experiment_action: Optional[str],
    attack_predicate: Optional[AttackPredicate],
    target_asset_id: Optional[str] = None,
) -> OutcomeBindingResult:
    """
    Deterministically resolves canonical supporting and disproving outcomes from an AttackPredicate.
    
    Precedence / Validation Ladder:
    1. Category & Action presence and registry membership.
    2. Attack predicate presence and structural integrity.
    3. Action alignment: predicate.operation == experiment_action.
    4. Security property alignment: predicate.security_property compatible with category.
    5. Target non-emptiness.
    6. Canonical outcome resolution from TUPLE_COMPATIBILITY_REGISTRY.
    """
    cat = (category_id or "").strip()
    act = (experiment_action or "").strip()

    # 1. Category & Action Registry Check
    registry = ExperimentPolarityValidator.TUPLE_COMPATIBILITY_REGISTRY
    if not cat:
        return OutcomeBindingResult(
            is_valid=False,
            error_message="Missing category_id",
            diagnostic_details={"stage": "CATEGORY_CHECK"},
        )
    if cat not in registry:
        return OutcomeBindingResult(
            is_valid=False,
            error_message=f"Category '{cat}' not found in compatibility registry",
            diagnostic_details={"stage": "CATEGORY_CHECK", "category_id": cat},
        )
    if not act:
        return OutcomeBindingResult(
            is_valid=False,
            error_message="Missing experiment_action",
            diagnostic_details={"stage": "ACTION_CHECK"},
        )
    if act not in registry[cat]:
        return OutcomeBindingResult(
            is_valid=False,
            error_message=f"Action '{act}' not permitted for category '{cat}'",
            diagnostic_details={"stage": "ACTION_CHECK", "category_id": cat, "experiment_action": act},
        )

    # 2. Attack Predicate Presence Check
    if attack_predicate is None:
        return OutcomeBindingResult(
            is_valid=False,
            error_message="Missing mandatory attack_predicate",
            diagnostic_details={"stage": "PREDICATE_PRESENCE"},
        )

    # 3. Action Alignment Check
    pred_op = (attack_predicate.operation or "").strip()
    if pred_op != act:
        return OutcomeBindingResult(
            is_valid=False,
            error_message=f"Predicate operation '{pred_op}' does not match supplied experiment_action '{act}'",
            diagnostic_details={"stage": "OPERATION_MISMATCH", "expected": act, "actual": pred_op},
        )

    # 4. Security Property Domain Alignment Check
    valid_properties = CATEGORY_SECURITY_PROPERTY_MAP.get(cat, set())
    pred_prop_str = (attack_predicate.security_property or "").strip()
    try:
        pred_prop = SecurityPropertyDomain(pred_prop_str)
    except ValueError:
        return OutcomeBindingResult(
            is_valid=False,
            error_message=f"Unrecognized security_property '{pred_prop_str}'",
            diagnostic_details={"stage": "PROPERTY_CHECK", "security_property": pred_prop_str},
        )

    if pred_prop not in valid_properties:
        valid_names = sorted([p.value for p in valid_properties])
        return OutcomeBindingResult(
            is_valid=False,
            error_message=f"Security property '{pred_prop.value}' incompatible with category '{cat}'. Expected one of: {valid_names}",
            diagnostic_details={"stage": "PROPERTY_MISMATCH", "category_id": cat, "property": pred_prop.value},
        )

    # 5. Target Integrity Check
    pred_target = (attack_predicate.target or "").strip()
    if not pred_target:
        return OutcomeBindingResult(
            is_valid=False,
            error_message="Attack predicate target cannot be empty",
            diagnostic_details={"stage": "TARGET_EMPTY"},
        )

    # 6. Canonical Outcome Resolution
    pair_key = (cat, act)
    valid_breaches, valid_safes = registry[cat][act]

    if pair_key in CANONICAL_PRIMARY_OUTCOME_PAIRS:
        supp, disp = CANONICAL_PRIMARY_OUTCOME_PAIRS[pair_key]
    else:
        # Deterministic fallback: sort outcomes alphabetically and pick first
        sorted_breaches = sorted(list(valid_breaches))
        sorted_safes = sorted(list(valid_safes))
        supp = sorted_breaches[0]
        disp = sorted_safes[0]

    # Invariant safety assertion: resolved outcomes must belong to the registry sets
    if supp not in valid_breaches or disp not in valid_safes:
        return OutcomeBindingResult(
            is_valid=False,
            error_message=f"Internal binding corruption: derived outcomes ({supp}, {disp}) not in registry",
            diagnostic_details={"stage": "INTERNAL_INTEGRITY"},
        )

    return OutcomeBindingResult(
        is_valid=True,
        supporting_outcome=supp,
        disproving_outcome=disp,
        outcome_origin="DETERMINISTICALLY_DERIVED",
        error_message=None,
        diagnostic_details={
            "category_id": cat,
            "experiment_action": act,
            "security_property": pred_prop.value,
            "target": pred_target,
            "derived_supporting": supp,
            "derived_disproving": disp,
        },
    )
