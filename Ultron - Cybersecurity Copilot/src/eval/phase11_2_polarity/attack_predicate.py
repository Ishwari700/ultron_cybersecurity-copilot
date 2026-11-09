"""
Milestone M5 Phase 11.2: Typed Attack Predicate Models.

Defines the typed, bounded AttackPredicate representation replacing model-generated
outcome selection (supporting_outcome / disproving_outcome) with a structured attack predicate.

Guarantees:
- Typed fields (subject, operation, target, security_property, expected_violation).
- Strict validation against permitted operations and security property domains.
- Zero reliance on free-form regex search or heuristic guessing.
- Zero exposure of breach/safe partition labels to the language model.
"""

from enum import Enum
from typing import Any, Dict, List, Optional, Set
from pydantic import BaseModel, ConfigDict, Field, field_validator

from src.engine.models import (
    ExperimentActionPredicate,
    VALID_ACTION_PREDICATES,
)


class SecurityPropertyDomain(str, Enum):
    """Authoritative security invariant properties verifiable via perturbation experiments."""
    RESOURCE_OWNERSHIP_INTEGRITY = "RESOURCE_OWNERSHIP_INTEGRITY"
    OBJECT_LEVEL_AUTHORIZATION = "OBJECT_LEVEL_AUTHORIZATION"
    TENANT_ISOLATION = "TENANT_ISOLATION"
    CROSS_TENANT_AUTHORIZATION = "CROSS_TENANT_AUTHORIZATION"
    STATE_TRANSITION_INTEGRITY = "STATE_TRANSITION_INTEGRITY"
    LIFECYCLE_ORDERING = "LIFECYCLE_ORDERING"
    ROLE_BOUNDARY_ENFORCEMENT = "ROLE_BOUNDARY_ENFORCEMENT"
    FUNCTION_LEVEL_AUTHORIZATION = "FUNCTION_LEVEL_AUTHORIZATION"
    AUTHENTICATION_REQUIREMENT = "AUTHENTICATION_REQUIREMENT"
    MUTATION_INTEGRITY = "MUTATION_INTEGRITY"


# Deterministic mapping between vulnerability category and allowable security properties
CATEGORY_SECURITY_PROPERTY_MAP: Dict[str, Set[SecurityPropertyDomain]] = {
    "API-BOLA-001": {
        SecurityPropertyDomain.RESOURCE_OWNERSHIP_INTEGRITY,
        SecurityPropertyDomain.OBJECT_LEVEL_AUTHORIZATION,
    },
    "API-DEVICE-BOLA-001": {
        SecurityPropertyDomain.RESOURCE_OWNERSHIP_INTEGRITY,
        SecurityPropertyDomain.OBJECT_LEVEL_AUTHORIZATION,
    },
    "API-CROSS-TENANT-001": {
        SecurityPropertyDomain.TENANT_ISOLATION,
        SecurityPropertyDomain.CROSS_TENANT_AUTHORIZATION,
    },
    "API-STATE-001": {
        SecurityPropertyDomain.STATE_TRANSITION_INTEGRITY,
        SecurityPropertyDomain.LIFECYCLE_ORDERING,
    },
    "API-LIFECYCLE-001": {
        SecurityPropertyDomain.STATE_TRANSITION_INTEGRITY,
        SecurityPropertyDomain.LIFECYCLE_ORDERING,
    },
    "API-MULTI-STEP-AUTH-001": {
        SecurityPropertyDomain.STATE_TRANSITION_INTEGRITY,
        SecurityPropertyDomain.LIFECYCLE_ORDERING,
        SecurityPropertyDomain.AUTHENTICATION_REQUIREMENT,
    },
    "API-ROLE-BOUNDARY-001": {
        SecurityPropertyDomain.ROLE_BOUNDARY_ENFORCEMENT,
        SecurityPropertyDomain.FUNCTION_LEVEL_AUTHORIZATION,
    },
    "API-BFLA-001": {
        SecurityPropertyDomain.ROLE_BOUNDARY_ENFORCEMENT,
        SecurityPropertyDomain.FUNCTION_LEVEL_AUTHORIZATION,
    },
    "API-BFLA-002": {
        SecurityPropertyDomain.ROLE_BOUNDARY_ENFORCEMENT,
        SecurityPropertyDomain.FUNCTION_LEVEL_AUTHORIZATION,
    },
    "API-MUTATION-001": {
        SecurityPropertyDomain.MUTATION_INTEGRITY,
    },
    "API-AUTH-NONE": {
        SecurityPropertyDomain.AUTHENTICATION_REQUIREMENT,
    },
}


class AttackPredicate(BaseModel):
    """
    Typed, bounded representation of a security attack predicate.
    
    The model articulates what invariant violation it is attempting to induce
    rather than choosing lexical outcome tokens (which causes polarity inversions).
    """
    model_config = ConfigDict(extra="forbid", frozen=True)

    subject: str = Field(
        ...,
        description="The acting entity or identity role (e.g., UNAUTHORIZED_ACTOR, TENANT_B_USER, LOWER_ROLE_ACTOR, ANONYMOUS_CALLER).",
        min_length=3,
        max_length=100,
    )
    operation: str = Field(
        ...,
        description="The perturbation action applied (must match supplied experiment_action from closed taxonomy).",
    )
    target: str = Field(
        ...,
        description="The affected resource identifier, parameter, or endpoint under test.",
        min_length=2,
        max_length=150,
    )
    security_property: str = Field(
        ...,
        description="The security invariant property asserted to be breached from SecurityPropertyDomain.",
    )
    expected_violation: Optional[str] = Field(
        default=None,
        description="Brief natural language statement describing the specific unauthorized condition.",
        max_length=300,
    )

    @field_validator("operation")
    @classmethod
    def validate_operation_in_taxonomy(cls, v: str) -> str:
        clean_op = (v or "").strip()
        if clean_op not in VALID_ACTION_PREDICATES:
            valid_list = sorted(list(VALID_ACTION_PREDICATES))
            raise ValueError(
                f"Invalid operation '{clean_op}'. Must be one of registered action predicates: {valid_list}"
            )
        return clean_op

    @field_validator("security_property")
    @classmethod
    def validate_security_property_domain(cls, v: str) -> str:
        clean_prop = (v or "").strip()
        valid_props = {e.value for e in SecurityPropertyDomain}
        if clean_prop not in valid_props:
            raise ValueError(
                f"Invalid security_property '{clean_prop}'. Must be one of: {sorted(list(valid_props))}"
            )
        return clean_prop

    def to_canonical_dict(self) -> Dict[str, Any]:
        """Serializes the attack predicate deterministically."""
        return {
            "subject": self.subject,
            "operation": self.operation,
            "target": self.target,
            "security_property": self.security_property,
            "expected_violation": self.expected_violation,
        }
