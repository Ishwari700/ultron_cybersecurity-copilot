"""
Milestone M5 Phase 11.2: Deterministic Preflight Unit Test Suite.

Verifies the 17 preregistered requirements before live execution:
1. P1 schema validity
2. AttackPredicate model
3. Missing attack predicate
4. Invalid category/predicate combination
5. Invalid action/predicate combination
6. Valid BOLA predicate
7. Valid state-machine predicate
8. Valid role-boundary predicate
9. Valid cross-tenant predicate
10. Ambiguous predicate fails closed
11. Derived outcomes are deterministic
12. Derived outcomes cannot be overridden by model output
13. Ground truth cannot enter the derivation path
14. Vulnerable/control labels cannot enter the derivation path
15. Supporting/disproving outcomes are marked deterministic
16. P0 behavior remains unchanged
17. Sealed historical artifact hashes remain unchanged
"""

import hashlib
import inspect
from pathlib import Path
import pytest
from pydantic import ValidationError

from src.engine.decision_policy import ExperimentPolarityValidator
from src.engine.models import (
    BairJsonObject,
    HypothesisDecision,
    VALID_ACTION_PREDICATES,
)
from src.eval.phase11_2_polarity.attack_predicate import (
    AttackPredicate,
    SecurityPropertyDomain,
    CATEGORY_SECURITY_PROPERTY_MAP,
)
from src.eval.phase11_2_polarity.outcome_binding import (
    derive_outcomes_from_attack_predicate,
    CANONICAL_PRIMARY_OUTCOME_PAIRS,
    OutcomeBindingResult,
)
from src.eval.phase11_2_polarity.protocol import (
    P1BairJsonObject,
    parse_p1_response,
)
from src.eval.phase11_2_polarity.runner import (
    DIAGNOSTIC_SCENARIO_IDS,
    get_diagnostic_condition_order,
)


REPO_ROOT = Path(__file__).resolve().parent.parent.parent


# ---------------------------------------------------------------------------
# Requirement 17: Sealed Historical Artifact Hashes Remain Unchanged
# ---------------------------------------------------------------------------

SEALED_HISTORICAL_HASHES = {
    "data/eval/m5_phase7_benchmark_final.json": "1e0ed90c4aa672f135d2d2f2240a14d22fa0037c03efda33634f4bf10ff0b125",
    "data/eval/m5_phase8_semantic_study.json": "b1df9a62fb07d76e0abf6e3935ccbabdaa1713f4c594019ae30c9e59567a45c6",
    "data/eval/m5_phase9_semantic_budget_study.json": "3c0d3e503c7ed24470b14dfde0bd763c631a9b5dbf70c047bbca72cfaab07f95",
    "data/eval/m5_phase10_full_population_validation.json": "6821d207729de97ac99657a09e38c25895a73285fe9c485d299dc27f37d2bdba",
    "data/eval/m5_phase10_checkpoint.json": "40f9f725fca5fdf05a76836182960b7f0d4c303a182d6e8af068a1b57e8f4537",
}


@pytest.mark.parametrize("rel_path, expected_sha", SEALED_HISTORICAL_HASHES.items())
def test_17_sealed_historical_artifact_hashes_unchanged(rel_path: str, expected_sha: str):
    """Assert all sealed historical datasets remain bit-for-bit identical."""
    path = REPO_ROOT / rel_path
    assert path.exists(), f"Historical file missing: {rel_path}"
    with open(path, "rb") as f:
        actual_sha = hashlib.sha256(f.read()).hexdigest()
    assert actual_sha == expected_sha, (
        f"Sealed artifact mutated: {rel_path}!\nExpected: {expected_sha}\nActual:   {actual_sha}"
    )


# ---------------------------------------------------------------------------
# Requirement 1: P1 Schema Validity
# ---------------------------------------------------------------------------

def test_01_p1_schema_validity():
    """Verify that P1BairJsonObject generates a valid JSON schema for Ollama constrained decoding."""
    schema = P1BairJsonObject.get_inference_schema()
    assert schema["type"] == "object"
    assert "properties" in schema
    assert "required" in schema
    assert "attack_predicate" in schema["properties"]
    assert "supporting_outcome" not in schema["properties"]
    assert "disproving_outcome" not in schema["properties"]
    assert "decision" in schema["properties"]


# ---------------------------------------------------------------------------
# Requirement 2: AttackPredicate Model
# ---------------------------------------------------------------------------

def test_02_attack_predicate_model():
    """Verify that valid AttackPredicate instances instantiate and serialize properly."""
    pred = AttackPredicate(
        subject="UNAUTHORIZED_ACTOR",
        operation="SUBSTITUTE_RESOURCE_IDENTIFIER",
        target="/api/v1/invoices/{invoice_id}",
        security_property="RESOURCE_OWNERSHIP_INTEGRITY",
        expected_violation="Attacker accesses another tenant's invoice",
    )
    d = pred.to_canonical_dict()
    assert d["subject"] == "UNAUTHORIZED_ACTOR"
    assert d["operation"] == "SUBSTITUTE_RESOURCE_IDENTIFIER"
    assert d["target"] == "/api/v1/invoices/{invoice_id}"
    assert d["security_property"] == "RESOURCE_OWNERSHIP_INTEGRITY"


# ---------------------------------------------------------------------------
# Requirement 3: Missing Attack Predicate
# ---------------------------------------------------------------------------

def test_03_missing_attack_predicate_fails():
    """Verify that HYPOTHESIS decision with missing attack_predicate fails validation."""
    with pytest.raises(ValidationError, match="Mandatory attack_predicate slot missing"):
        P1BairJsonObject(
            decision=HypothesisDecision.HYPOTHESIS,
            invariant="Resource ownership must be enforced",
            affected_target="/api/v1/invoices",
            empirical_facts=["FACT-1"],
            attack_predicate=None,
        )

    # Calling binding with None predicate must fail closed
    res = derive_outcomes_from_attack_predicate("API-BOLA-001", "SUBSTITUTE_RESOURCE_IDENTIFIER", None)
    assert res.is_valid is False
    assert "Missing mandatory attack_predicate" in res.error_message


# ---------------------------------------------------------------------------
# Requirement 4: Invalid Category/Predicate Combination
# ---------------------------------------------------------------------------

def test_04_invalid_category_predicate_combination():
    """Verify that using an incompatible security property for a category fails closed."""
    # BOLA category with STATE_TRANSITION_INTEGRITY property
    pred = AttackPredicate(
        subject="ACTOR_A",
        operation="SUBSTITUTE_RESOURCE_IDENTIFIER",
        target="/api/v1/resource",
        security_property="STATE_TRANSITION_INTEGRITY",
    )
    res = derive_outcomes_from_attack_predicate(
        category_id="API-BOLA-001",
        experiment_action="SUBSTITUTE_RESOURCE_IDENTIFIER",
        attack_predicate=pred,
    )
    assert res.is_valid is False
    assert "incompatible with category" in res.error_message


# ---------------------------------------------------------------------------
# Requirement 5: Invalid Action/Predicate Combination
# ---------------------------------------------------------------------------

def test_05_invalid_action_predicate_combination():
    """Verify that a mismatch between predicate operation and supplied action fails closed."""
    pred = AttackPredicate(
        subject="ACTOR_A",
        operation="EXECUTE_OUT_OF_ORDER_TRANSITION",
        target="/api/v1/resource",
        security_property="RESOURCE_OWNERSHIP_INTEGRITY",
    )
    res = derive_outcomes_from_attack_predicate(
        category_id="API-BOLA-001",
        experiment_action="SUBSTITUTE_RESOURCE_IDENTIFIER",  # Mismatched
        attack_predicate=pred,
    )
    assert res.is_valid is False
    assert "does not match supplied experiment_action" in res.error_message


# ---------------------------------------------------------------------------
# Requirement 6: Valid BOLA Predicate
# ---------------------------------------------------------------------------

def test_06_valid_bola_predicate():
    """Verify outcome derivation for a valid BOLA attack predicate."""
    pred = AttackPredicate(
        subject="ATTACKER_CALLER",
        operation="SUBSTITUTE_RESOURCE_IDENTIFIER",
        target="/api/v1/invoices/inv_999",
        security_property="RESOURCE_OWNERSHIP_INTEGRITY",
    )
    res = derive_outcomes_from_attack_predicate(
        category_id="API-BOLA-001",
        experiment_action="SUBSTITUTE_RESOURCE_IDENTIFIER",
        attack_predicate=pred,
    )
    assert res.is_valid is True
    assert res.supporting_outcome == "HTTP_200_OK"
    assert res.disproving_outcome == "HTTP_403_FORBIDDEN"
    assert res.outcome_origin == "DETERMINISTICALLY_DERIVED"


# ---------------------------------------------------------------------------
# Requirement 7: Valid State-Machine Predicate
# ---------------------------------------------------------------------------

def test_07_valid_state_machine_predicate():
    """Verify outcome derivation for a valid state/lifecycle attack predicate."""
    pred = AttackPredicate(
        subject="ORDER_BUYER",
        operation="EXECUTE_OUT_OF_ORDER_TRANSITION",
        target="/api/v1/orders/{order_id}/refund",
        security_property="STATE_TRANSITION_INTEGRITY",
    )
    res = derive_outcomes_from_attack_predicate(
        category_id="API-LIFECYCLE-001",
        experiment_action="EXECUTE_OUT_OF_ORDER_TRANSITION",
        attack_predicate=pred,
    )
    assert res.is_valid is True
    assert res.supporting_outcome == "STATE_TRANSITION_ACCEPTED"
    assert res.disproving_outcome == "STATE_TRANSITION_REJECTED"


# ---------------------------------------------------------------------------
# Requirement 8: Valid Role-Boundary Predicate
# ---------------------------------------------------------------------------

def test_08_valid_role_boundary_predicate():
    """Verify outcome derivation for a valid role-boundary attack predicate."""
    pred = AttackPredicate(
        subject="LOWER_ROLE_USER",
        operation="REPLAY_STEP_WITH_LOWER_ROLE",
        target="/api/v1/admin/users/{id}/roles",
        security_property="ROLE_BOUNDARY_ENFORCEMENT",
    )
    res = derive_outcomes_from_attack_predicate(
        category_id="API-ROLE-BOUNDARY-001",
        experiment_action="REPLAY_STEP_WITH_LOWER_ROLE",
        attack_predicate=pred,
    )
    assert res.is_valid is True
    assert res.supporting_outcome == "PRIVILEGE_ELEVATION_SUCCEEDS"
    assert res.disproving_outcome == "PRIVILEGE_ELEVATION_DENIED"


# ---------------------------------------------------------------------------
# Requirement 9: Valid Cross-Tenant Predicate
# ---------------------------------------------------------------------------

def test_09_valid_cross_tenant_predicate():
    """Verify outcome derivation for a valid cross-tenant attack predicate."""
    pred = AttackPredicate(
        subject="TENANT_B_ACTOR",
        operation="SUBSTITUTE_RESOURCE_IDENTIFIER",
        target="/api/v1/invoices/summary",
        security_property="TENANT_ISOLATION",
    )
    res = derive_outcomes_from_attack_predicate(
        category_id="API-CROSS-TENANT-001",
        experiment_action="SUBSTITUTE_RESOURCE_IDENTIFIER",
        attack_predicate=pred,
    )
    assert res.is_valid is True
    assert res.supporting_outcome == "HTTP_200_OK"
    assert res.disproving_outcome == "HTTP_403_FORBIDDEN"


# ---------------------------------------------------------------------------
# Requirement 10: Ambiguous Predicate Fails Closed
# ---------------------------------------------------------------------------

def test_10_ambiguous_predicate_fails_closed():
    """Verify that blank target or unknown property fails closed."""
    with pytest.raises(ValidationError):
        AttackPredicate(
            subject="ACTOR",
            operation="SUBSTITUTE_RESOURCE_IDENTIFIER",
            target="",  # Empty target
            security_property="RESOURCE_OWNERSHIP_INTEGRITY",
        )

    with pytest.raises(ValidationError):
        AttackPredicate(
            subject="ACTOR",
            operation="SUBSTITUTE_RESOURCE_IDENTIFIER",
            target="/api/v1/res",
            security_property="UNKNOWN_PROPERTY",  # Unknown domain
        )


# ---------------------------------------------------------------------------
# Requirement 11: Derived Outcomes Are Deterministic
# ---------------------------------------------------------------------------

def test_11_derived_outcomes_are_deterministic():
    """Verify identical repeated outcome derivations return bit-for-bit identical results."""
    pred = AttackPredicate(
        subject="USER_X",
        operation="SUBSTITUTE_RESOURCE_IDENTIFIER",
        target="/api/v1/res",
        security_property="RESOURCE_OWNERSHIP_INTEGRITY",
    )
    r1 = derive_outcomes_from_attack_predicate("API-BOLA-001", "SUBSTITUTE_RESOURCE_IDENTIFIER", pred)
    r2 = derive_outcomes_from_attack_predicate("API-BOLA-001", "SUBSTITUTE_RESOURCE_IDENTIFIER", pred)
    assert r1.model_dump() == r2.model_dump()


# ---------------------------------------------------------------------------
# Requirement 12: Derived Outcomes Cannot Be Overridden by Model Output
# ---------------------------------------------------------------------------

def test_12_derived_outcomes_cannot_be_overridden_by_model():
    """Verify that model prose or extra keys cannot change the deterministic outcomes."""
    pred = AttackPredicate(
        subject="ACTOR_ATTACKER",
        operation="SUBSTITUTE_RESOURCE_IDENTIFIER",
        target="/api/v1/res",
        security_property="RESOURCE_OWNERSHIP_INTEGRITY",
        expected_violation="HTTP_403_FORBIDDEN should be returned",  # model confusion in text
    )
    res = derive_outcomes_from_attack_predicate("API-BOLA-001", "SUBSTITUTE_RESOURCE_IDENTIFIER", pred)
    # Supporting outcome must still be canonical breach HTTP_200_OK, NOT HTTP_403_FORBIDDEN!
    assert res.supporting_outcome == "HTTP_200_OK"
    assert res.disproving_outcome == "HTTP_403_FORBIDDEN"


# ---------------------------------------------------------------------------
# Requirement 13 & 14: Ground Truth Firewall
# ---------------------------------------------------------------------------

def test_13_14_ground_truth_firewall():
    """Assert derive_outcomes_from_attack_predicate does not inspect ground truth parameters."""
    sig = inspect.signature(derive_outcomes_from_attack_predicate)
    param_names = list(sig.parameters.keys())
    assert "vulnerable" not in param_names
    assert "vulnerable_variant" not in param_names
    assert "ground_truth" not in param_names
    assert "expected_decision" not in param_names


# ---------------------------------------------------------------------------
# Requirement 15: Supporting/Disproving Outcomes Marked Deterministic
# ---------------------------------------------------------------------------

def test_15_outcomes_marked_deterministic():
    """Verify outcome_origin is explicitly tagged as DETERMINISTICALLY_DERIVED."""
    pred = AttackPredicate(
        subject="ACTOR",
        operation="SUBSTITUTE_RESOURCE_IDENTIFIER",
        target="/api/v1/res",
        security_property="RESOURCE_OWNERSHIP_INTEGRITY",
    )
    res = derive_outcomes_from_attack_predicate("API-BOLA-001", "SUBSTITUTE_RESOURCE_IDENTIFIER", pred)
    assert res.outcome_origin == "DETERMINISTICALLY_DERIVED"


# ---------------------------------------------------------------------------
# Requirement 16: P0 Behavior Remains Unchanged
# ---------------------------------------------------------------------------

def test_16_p0_behavior_unchanged():
    """Verify that standard BairJsonObject model validation still functions identically."""
    p0 = BairJsonObject(
        decision=HypothesisDecision.HYPOTHESIS,
        invariant="Ownership must be enforced",
        evidence_gap="Unobserved authorization check",
        affected_target="/api/v1/invoices",
        empirical_facts=["FACT-1"],
        experiment_action="SUBSTITUTE_RESOURCE_IDENTIFIER",
        supporting_outcome="HTTP_200_OK",
        disproving_outcome="HTTP_403_FORBIDDEN",
        falsification_description="Test cross-user ID",
    )
    assert p0.experiment_action == "SUBSTITUTE_RESOURCE_IDENTIFIER"
    assert p0.supporting_outcome == "HTTP_200_OK"
    assert p0.disproving_outcome == "HTTP_403_FORBIDDEN"

    # Fails when supporting and disproving are identical
    with pytest.raises(ValidationError, match="cannot be identical"):
        BairJsonObject(
            decision=HypothesisDecision.HYPOTHESIS,
            invariant="Ownership must be enforced",
            evidence_gap="Unobserved authorization check",
            affected_target="/api/v1/invoices",
            empirical_facts=["FACT-1"],
            experiment_action="SUBSTITUTE_RESOURCE_IDENTIFIER",
            supporting_outcome="HTTP_200_OK",
            disproving_outcome="HTTP_200_OK",
        )
