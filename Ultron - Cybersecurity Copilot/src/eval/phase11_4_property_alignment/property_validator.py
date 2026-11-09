"""
Milestone M5 Phase 11.4: Deterministic Security Property Validator.

Implements strict, deterministic validation of attack_predicate.security_property
and failure decomposition adhering to the SP1-SP5, SP99 taxonomy:
SP1  = PROPERTY_MISSING
SP2  = PROPERTY_OUT_OF_SET
SP3  = PROPERTY_CATEGORY_MISMATCH
SP4  = PROPERTY_INVARIANT_MISMATCH
SP5  = PROPERTY_EVIDENCE_GAP_MISMATCH
SP99 = PROPERTY_UNRESOLVED
"""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from src.eval.phase11_2_polarity.attack_predicate import SecurityPropertyDomain
from src.eval.phase11_4_property_alignment.property_registry import (
    get_allowed_security_properties,
    is_property_allowed_for_category,
)


class SecurityPropertyFailureCode(str, Enum):
    """Authoritative Phase 11.4 Security Property Failure Taxonomy."""
    SP1 = "PROPERTY_MISSING"
    SP2 = "PROPERTY_OUT_OF_SET"
    SP3 = "PROPERTY_CATEGORY_MISMATCH"
    SP4 = "PROPERTY_INVARIANT_MISMATCH"
    SP5 = "PROPERTY_EVIDENCE_GAP_MISMATCH"
    SP99 = "PROPERTY_UNRESOLVED"


class PropertyValidationResult(BaseModel):
    """Result of deterministic security property evaluation."""
    is_valid: bool
    primary_code: Optional[SecurityPropertyFailureCode] = None
    contributing_codes: List[SecurityPropertyFailureCode] = Field(default_factory=list)
    reason: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)


def validate_security_property(
    category_id: Optional[str],
    security_property: Optional[str],
    invariant_definition: Optional[str] = None,
    evidence_gap_type: Optional[str] = None,
) -> PropertyValidationResult:
    """
    Deterministically validates candidate security property against category rules.
    Precedence:
    1. SP1: Property missing or empty.
    2. SP2: Property not a valid member of SecurityPropertyDomain.
    3. SP3: Property category mismatch (not in category allowed set).
    4. SP4 / SP5: Semantic invariant/gap compatibility checks.
    """
    cat = (category_id or "").strip()
    prop = (security_property or "").strip()

    details = {
        "category_id": cat,
        "security_property": prop,
        "allowed_properties": get_allowed_security_properties(cat),
    }

    # Step 1: Missing property check
    if not prop:
        return PropertyValidationResult(
            is_valid=False,
            primary_code=SecurityPropertyFailureCode.SP1,
            contributing_codes=[],
            reason="PROPERTY_MISSING: attack_predicate.security_property is missing or empty",
            details=details,
        )

    # Step 2: Global vocabulary check
    all_domains = {e.value for e in SecurityPropertyDomain}
    if prop not in all_domains:
        return PropertyValidationResult(
            is_valid=False,
            primary_code=SecurityPropertyFailureCode.SP2,
            contributing_codes=[],
            reason=f"PROPERTY_OUT_OF_SET: '{prop}' not a recognized SecurityPropertyDomain",
            details=details,
        )

    # Step 3: Category allowed-set containment check
    allowed = get_allowed_security_properties(cat)
    if not allowed:
        return PropertyValidationResult(
            is_valid=False,
            primary_code=SecurityPropertyFailureCode.SP3,
            contributing_codes=[],
            reason=f"PROPERTY_CATEGORY_MISMATCH: Category '{cat}' has no registered allowed security properties",
            details=details,
        )

    if prop not in allowed:
        return PropertyValidationResult(
            is_valid=False,
            primary_code=SecurityPropertyFailureCode.SP3,
            contributing_codes=[],
            reason=f"PROPERTY_CATEGORY_MISMATCH: Property '{prop}' is not allowed for category '{cat}'. Expected one of: {allowed}",
            details=details,
        )

    # Step 4: Semantic Invariant Compatibility Check (SP4)
    # If invariant specifies object/ownership but role/lifecycle is selected
    if invariant_definition:
        inv_lower = invariant_definition.lower()
        if "ownership" in inv_lower and prop in ("LIFECYCLE_ORDERING", "STATE_TRANSITION_INTEGRITY"):
            return PropertyValidationResult(
                is_valid=False,
                primary_code=SecurityPropertyFailureCode.SP4,
                contributing_codes=[],
                reason=f"PROPERTY_INVARIANT_MISMATCH: Property '{prop}' contradicts ownership invariant definition",
                details=details,
            )
        if "state" in inv_lower and prop in ("ROLE_BOUNDARY_ENFORCEMENT", "FUNCTION_LEVEL_AUTHORIZATION"):
            return PropertyValidationResult(
                is_valid=False,
                primary_code=SecurityPropertyFailureCode.SP4,
                contributing_codes=[],
                reason=f"PROPERTY_INVARIANT_MISMATCH: Property '{prop}' contradicts state transition invariant definition",
                details=details,
            )

    # Step 5: Evidence Gap Compatibility Check (SP5)
    if evidence_gap_type:
        gap_lower = evidence_gap_type.lower()
        if "tenant" in gap_lower and prop in ("ROLE_BOUNDARY_ENFORCEMENT", "MUTATION_INTEGRITY"):
            return PropertyValidationResult(
                is_valid=False,
                primary_code=SecurityPropertyFailureCode.SP5,
                contributing_codes=[],
                reason=f"PROPERTY_EVIDENCE_GAP_MISMATCH: Property '{prop}' incompatible with tenant isolation evidence gap",
                details=details,
            )

    return PropertyValidationResult(
        is_valid=True,
        primary_code=None,
        contributing_codes=[],
        reason="Security property validly aligned with category and invariant",
        details=details,
    )
