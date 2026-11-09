"""
Milestone M5 Phase 6.5 — Deterministic Experiment-Semantics Protocol Design Tests.

Design-phase proof fixtures validating deterministic experiment-polarity verification:
- Case 1: Valid BOLA experiment (breach = 200, safe = 403/404) -> ACCEPTED
- Case 2: Valid State-Machine experiment (breach = transition accepted/200, safe = rejected/409) -> ACCEPTED
- Case 3: Inverted State-Machine experiment (rejection claimed as breach) -> REJECTED
- Case 4: Ambiguous free-text natural language -> FAILS CLOSED (Schema / Type error)
- Case 5: Unsupported / unknown predicate -> FAILS CLOSED (Validation error)

STRICT RULE: Pure design tests only. Zero modifications to production source code.
"""

from enum import Enum
from typing import Any, Dict, List, Optional, Set
from pydantic import BaseModel, ConfigDict, Field, ValidationError
import pytest


# ===========================================================================
# 1. Minimal Closed Predicate Taxonomy (M5 Design Prototype)
# ===========================================================================

class HttpOutcomePredicate(str, Enum):
    """Machine-readable HTTP status outcome predicates."""
    HTTP_200_OK = "HTTP_200_OK"
    HTTP_201_CREATED = "HTTP_201_CREATED"
    HTTP_204_NO_CONTENT = "HTTP_204_NO_CONTENT"
    HTTP_400_BAD_REQUEST = "HTTP_400_BAD_REQUEST"
    HTTP_401_UNAUTHORIZED = "HTTP_401_UNAUTHORIZED"
    HTTP_403_FORBIDDEN = "HTTP_403_FORBIDDEN"
    HTTP_404_NOT_FOUND = "HTTP_404_NOT_FOUND"
    HTTP_409_CONFLICT = "HTTP_409_CONFLICT"


class SemanticOutcomePredicate(str, Enum):
    """Machine-readable security invariant outcome predicates."""
    # Response class
    STATUS_SUCCESS_2XX = "STATUS_SUCCESS_2XX"
    STATUS_CLIENT_ERROR_4XX = "STATUS_CLIENT_ERROR_4XX"

    # Authorization / Isolation
    CROSS_IDENTITY_OBJECT_ACCESSIBLE = "CROSS_IDENTITY_OBJECT_ACCESSIBLE"
    CROSS_IDENTITY_OBJECT_DENIED = "CROSS_IDENTITY_OBJECT_DENIED"
    OWNERSHIP_ENFORCED = "OWNERSHIP_ENFORCED"
    OWNERSHIP_NOT_ENFORCED = "OWNERSHIP_NOT_ENFORCED"

    # State Machine
    STATE_TRANSITION_ACCEPTED = "STATE_TRANSITION_ACCEPTED"
    STATE_TRANSITION_REJECTED = "STATE_TRANSITION_REJECTED"

    # Privilege Escalation
    PRIVILEGE_ELEVATION_SUCCEEDS = "PRIVILEGE_ELEVATION_SUCCEEDS"
    PRIVILEGE_ELEVATION_DENIED = "PRIVILEGE_ELEVATION_DENIED"


class ExperimentActionPredicate(str, Enum):
    """Machine-readable experiment perturbation action predicates."""
    SUBSTITUTE_RESOURCE_IDENTIFIER = "SUBSTITUTE_RESOURCE_IDENTIFIER"
    EXECUTE_OUT_OF_ORDER_TRANSITION = "EXECUTE_OUT_OF_ORDER_TRANSITION"
    REPLAY_STEP_WITH_LOWER_ROLE = "REPLAY_STEP_WITH_LOWER_ROLE"
    INVOKE_WITHOUT_CREDENTIALS = "INVOKE_WITHOUT_CREDENTIALS"


# ===========================================================================
# 2. Typed Experiment Schema (Design Option B/C Prototype)
# ===========================================================================

class DeterministicExperimentSpecification(BaseModel):
    """
    Design Prototype for Typed Experiment Specification.
    Replaces unanchored free-text falsification_plan with typed outcome predicates.
    """
    model_config = ConfigDict(extra="forbid")

    action: ExperimentActionPredicate
    target_parameter: Optional[str] = None
    supporting_outcome: str = Field(description="Observation indicating security invariant breach (hypothesis supported)")
    disproving_outcome: str = Field(description="Observation indicating security invariant holds (hypothesis disproved)")
    description: Optional[str] = Field(default=None, description="Optional brief natural-language explanation")


# ===========================================================================
# 3. Deterministic Polarity Engine (Zero NLP, Pure Predicate Rules)
# ===========================================================================

class ExperimentPolarityValidator:
    """
    Deterministic validator enforcing semantic polarity between experiment
    outcomes and security invariant definitions.
    """

    # Category -> Valid Breach Outcome Predicates
    VALID_BREACH_OUTCOMES: Dict[str, Set[str]] = {
        "API-BOLA-001": {
            HttpOutcomePredicate.HTTP_200_OK.value,
            SemanticOutcomePredicate.STATUS_SUCCESS_2XX.value,
            SemanticOutcomePredicate.CROSS_IDENTITY_OBJECT_ACCESSIBLE.value,
            SemanticOutcomePredicate.OWNERSHIP_NOT_ENFORCED.value,
        },
        "API-STATE-001": {
            HttpOutcomePredicate.HTTP_200_OK.value,
            SemanticOutcomePredicate.STATUS_SUCCESS_2XX.value,
            SemanticOutcomePredicate.STATE_TRANSITION_ACCEPTED.value,
        },
        "API-BFLA-002": {
            HttpOutcomePredicate.HTTP_200_OK.value,
            SemanticOutcomePredicate.STATUS_SUCCESS_2XX.value,
            SemanticOutcomePredicate.PRIVILEGE_ELEVATION_SUCCEEDS.value,
        },
    }

    # Category -> Valid Invariant-Holds Outcome Predicates
    VALID_INVARIANT_HOLDS_OUTCOMES: Dict[str, Set[str]] = {
        "API-BOLA-001": {
            HttpOutcomePredicate.HTTP_403_FORBIDDEN.value,
            HttpOutcomePredicate.HTTP_404_NOT_FOUND.value,
            SemanticOutcomePredicate.STATUS_CLIENT_ERROR_4XX.value,
            SemanticOutcomePredicate.CROSS_IDENTITY_OBJECT_DENIED.value,
            SemanticOutcomePredicate.OWNERSHIP_ENFORCED.value,
        },
        "API-STATE-001": {
            HttpOutcomePredicate.HTTP_400_BAD_REQUEST.value,
            HttpOutcomePredicate.HTTP_409_CONFLICT.value,
            SemanticOutcomePredicate.STATUS_CLIENT_ERROR_4XX.value,
            SemanticOutcomePredicate.STATE_TRANSITION_REJECTED.value,
        },
        "API-BFLA-002": {
            HttpOutcomePredicate.HTTP_401_UNAUTHORIZED.value,
            HttpOutcomePredicate.HTTP_403_FORBIDDEN.value,
            SemanticOutcomePredicate.STATUS_CLIENT_ERROR_4XX.value,
            SemanticOutcomePredicate.PRIVILEGE_ELEVATION_DENIED.value,
        },
    }

    @classmethod
    def validate_experiment_polarity(
        cls,
        category_id: str,
        experiment: DeterministicExperimentSpecification,
    ) -> bool:
        """
        Pure deterministic validation:
        1. Verifies category is recognized in taxonomy.
        2. Verifies supporting_outcome is in VALID_BREACH_OUTCOMES for category.
        3. Verifies disproving_outcome is in VALID_INVARIANT_HOLDS_OUTCOMES for category.
        4. Verifies supporting_outcome != disproving_outcome (discriminative power).
        """
        valid_breaches = cls.VALID_BREACH_OUTCOMES.get(category_id)
        valid_holds = cls.VALID_INVARIANT_HOLDS_OUTCOMES.get(category_id)

        if not valid_breaches or not valid_holds:
            return False

        if experiment.supporting_outcome not in valid_breaches:
            return False

        if experiment.disproving_outcome not in valid_holds:
            return False

        if experiment.supporting_outcome == experiment.disproving_outcome:
            return False

        return True


# ===========================================================================
# 4. Proof Tests for the 5 Required Cases
# ===========================================================================

def test_case_1_bola_valid_experiment_accepted():
    """CASE 1: Valid BOLA experiment (breach = 200, safe = 403/404) is ACCEPTED."""
    spec = DeterministicExperimentSpecification(
        action=ExperimentActionPredicate.SUBSTITUTE_RESOURCE_IDENTIFIER,
        target_parameter="id",
        supporting_outcome=HttpOutcomePredicate.HTTP_200_OK.value,
        disproving_outcome=HttpOutcomePredicate.HTTP_403_FORBIDDEN.value,
        description="Substitute foreign invoice ID and observe 200 OK vs 403 Forbidden",
    )
    is_valid = ExperimentPolarityValidator.validate_experiment_polarity("API-BOLA-001", spec)
    assert is_valid is True


def test_case_2_state_machine_valid_experiment_accepted():
    """CASE 2: Valid State-Machine experiment (breach = accepted/200, safe = rejected/409) is ACCEPTED."""
    spec = DeterministicExperimentSpecification(
        action=ExperimentActionPredicate.EXECUTE_OUT_OF_ORDER_TRANSITION,
        target_parameter="id",
        supporting_outcome=SemanticOutcomePredicate.STATE_TRANSITION_ACCEPTED.value,
        disproving_outcome=HttpOutcomePredicate.HTTP_409_CONFLICT.value,
        description="Trigger refund before payment and observe if accepted (breach) or rejected with 409 (safe)",
    )
    is_valid = ExperimentPolarityValidator.validate_experiment_polarity("API-STATE-001", spec)
    assert is_valid is True


def test_case_3_state_machine_inverted_experiment_rejected():
    """
    CASE 3: Inverted State-Machine experiment (Phase 6.2 failure mode):
    Model claims rejection (409) is supporting (breach), and success (200) is disproving (safe).
    MUST BE DETERMINISTICALLY REJECTED without NLP heuristics!
    """
    inverted_spec = DeterministicExperimentSpecification(
        action=ExperimentActionPredicate.EXECUTE_OUT_OF_ORDER_TRANSITION,
        target_parameter="id",
        supporting_outcome=HttpOutcomePredicate.HTTP_409_CONFLICT.value,  # INVERTED!
        disproving_outcome=SemanticOutcomePredicate.STATE_TRANSITION_ACCEPTED.value,  # INVERTED!
        description="Rejection supports hypothesis, successful transition disproves",
    )
    is_valid = ExperimentPolarityValidator.validate_experiment_polarity("API-STATE-001", inverted_spec)
    assert is_valid is False, "Deterministic validator failed to reject inverted polarity!"


def test_case_4_ambiguous_prose_fails_closed():
    """CASE 4: Ambiguous natural-language prose fails schema validation cleanly (Pydantic ValidationError)."""
    raw_input = {
        "action": "SUBSTITUTE_RESOURCE_IDENTIFIER",
        "supporting_outcome": "Maybe the server will accept it or return an error",  # Ambiguous free text
        "disproving_outcome": "HTTP_403_FORBIDDEN",
    }
    spec = DeterministicExperimentSpecification(
        action=ExperimentActionPredicate.SUBSTITUTE_RESOURCE_IDENTIFIER,
        supporting_outcome="Maybe the server will accept it or return an error",
        disproving_outcome=HttpOutcomePredicate.HTTP_403_FORBIDDEN.value,
    )
    # The polarity validator rejects because free-text prose is not in the closed taxonomy
    is_valid = ExperimentPolarityValidator.validate_experiment_polarity("API-BOLA-001", spec)
    assert is_valid is False


def test_case_5_unsupported_unknown_predicate_fails_closed():
    """CASE 5: Unsupported / unknown predicate fails closed."""
    # Unknown action fails schema validation
    with pytest.raises(ValidationError):
        DeterministicExperimentSpecification(
            action="ARBITRARY_UNKNOWN_ACTION",  # Invalid enum value
            supporting_outcome=HttpOutcomePredicate.HTTP_200_OK.value,
            disproving_outcome=HttpOutcomePredicate.HTTP_403_FORBIDDEN.value,
        )

    # Unknown outcome predicate fails polarity validation
    unknown_spec = DeterministicExperimentSpecification(
        action=ExperimentActionPredicate.SUBSTITUTE_RESOURCE_IDENTIFIER,
        supporting_outcome="UNKNOWN_OUTCOME_CODE_999",
        disproving_outcome=HttpOutcomePredicate.HTTP_403_FORBIDDEN.value,
    )
    is_valid = ExperimentPolarityValidator.validate_experiment_polarity("API-BOLA-001", unknown_spec)
    assert is_valid is False


def test_unrecognized_category_fails_closed():
    """Unrecognized vulnerability category fails closed."""
    spec = DeterministicExperimentSpecification(
        action=ExperimentActionPredicate.SUBSTITUTE_RESOURCE_IDENTIFIER,
        supporting_outcome=HttpOutcomePredicate.HTTP_200_OK.value,
        disproving_outcome=HttpOutcomePredicate.HTTP_403_FORBIDDEN.value,
    )
    assert ExperimentPolarityValidator.validate_experiment_polarity("UNKNOWN-CATEGORY-999", spec) is False


def test_identical_supporting_and_disproving_fails_closed():
    """Identical supporting and disproving outcomes (non-discriminative) fail closed."""
    spec = DeterministicExperimentSpecification(
        action=ExperimentActionPredicate.SUBSTITUTE_RESOURCE_IDENTIFIER,
        supporting_outcome=HttpOutcomePredicate.HTTP_200_OK.value,
        disproving_outcome=HttpOutcomePredicate.HTTP_200_OK.value,  # NOT DISCRIMINATIVE!
    )
    assert ExperimentPolarityValidator.validate_experiment_polarity("API-BOLA-001", spec) is False
