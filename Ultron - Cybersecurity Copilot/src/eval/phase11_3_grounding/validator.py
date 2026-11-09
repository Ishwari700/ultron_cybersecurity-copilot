"""
Milestone M5 Phase 11.3: Deterministic Grounding Validator & Failure Decomposer.

Implements the strict, deterministic grounding validation and G1-G8, G99 failure taxonomy:
G1  = FACT_ID_INVALID
G2  = FACT_ID_NOT_IN_ALLOWED_SET
G3  = TARGET_ID_INVALID
G4  = TARGET_ID_NOT_IN_ALLOWED_SET
G5  = TARGET_NOT_STRUCTURALLY_GROUNDED
G6  = FACT_TARGET_CROSS_MISMATCH
G7  = FREE_FORM_TARGET_REJECTED
G8  = OTHER_GROUNDING_FAILURE
G99 = UNRESOLVED
"""

from enum import Enum
import re
from typing import Any, Dict, List, Optional, Set
from pydantic import BaseModel, Field

from src.evidence.cascade_models import LosslessStructuralPack

FACT_ID_PATTERN = re.compile(r"^FACT-[A-Za-z0-9_\-]+$")
EP_ID_PATTERN = re.compile(r"^EP-[A-Za-z0-9_\-]+$")
ASSET_ID_PATTERN = re.compile(r"^ASSET-[A-Za-z0-9_\-]+$")
PARAM_ID_PATTERN = re.compile(r"^PARAM-[A-Za-z0-9_\-]+$")
ROUTE_PATTERN = re.compile(r"^/[a-zA-Z0-9_\-/{}.]+$")


class GroundingFailureCode(str, Enum):
    """Authoritative Phase 11.3 Grounding Failure Taxonomy."""
    G1 = "FACT_ID_INVALID"
    G2 = "FACT_ID_NOT_IN_ALLOWED_SET"
    G3 = "TARGET_ID_INVALID"
    G4 = "TARGET_ID_NOT_IN_ALLOWED_SET"
    G5 = "TARGET_NOT_STRUCTURALLY_GROUNDED"
    G6 = "FACT_TARGET_CROSS_MISMATCH"
    G7 = "FREE_FORM_TARGET_REJECTED"
    G8 = "OTHER_GROUNDING_FAILURE"
    G99 = "UNRESOLVED"


class GroundingValidationResult(BaseModel):
    """Detailed result of deterministic grounding evaluation."""
    is_valid: bool
    primary_code: Optional[GroundingFailureCode] = None
    contributing_codes: List[GroundingFailureCode] = Field(default_factory=list)
    reason: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)


def is_free_form_prose(target: Optional[str]) -> bool:
    """
    Detects whether affected_target is natural language prose or conversational string
    rather than a bounded technical identifier.
    """
    if not target:
        return False
    t = target.strip()
    # Check for whitespace (more than single token)
    if " " in t:
        return True
    # Check for sentence punctuation
    if any(p in t for p in [".", ",", ";", "!", "?"]):
        return True
    # Check for conversational English cues or partition references
    prose_cues = ["the", "target", "endpoint", "is", "for", "partition", "record", "order", "invoice", "user"]
    t_lower = t.lower()
    if any(cue == t_lower for cue in prose_cues):
        return True
    # Non-identifier strings like NO_RELEVANT_FUNCTIONALITY in target slot
    if t in ("NO_RELEVANT_FUNCTIONALITY", "INSUFFICIENT_EVIDENCE", "HYPOTHESIS"):
        return True
    return False


def is_valid_target_syntax(target: str) -> bool:
    """Checks if target matches any legitimate technical identifier syntax."""
    if not target:
        return False
    t = target.strip()
    return bool(
        EP_ID_PATTERN.match(t)
        or ASSET_ID_PATTERN.match(t)
        or PARAM_ID_PATTERN.match(t)
        or ROUTE_PATTERN.match(t)
    )


class Phase11GroundingValidator:
    """
    Deterministic validator enforcing Grounding Recovery rules across P1, P2, and P3.
    """

    def validate_grounding(
        self,
        parsed_dict: Dict[str, Any],
        allowed_fact_ids: List[str],
        allowed_target_ids: List[str],
        pack: LosslessStructuralPack,
        condition_id: str = "P1",
    ) -> GroundingValidationResult:
        """
        Validates output facts and target against allowed sets and structural envelope.
        Follows strict deterministic precedence:
        1. Free-form prose check on affected_target (G7)
        2. Epistemic tier confusion / empty facts on hypothesis (G8)
        3. Fact ID format validation (G1)
        4. Fact ID allowed-set containment (G2)
        5. Target ID syntax check (G3)
        6. Target ID allowed-set containment for P3 (G4)
        7. Target structural grounding in Channel A envelope (G5)
        8. Cross-mismatch between facts and target (G6)
        """
        decision = str(parsed_dict.get("decision", "")).strip().upper()
        target_ref = parsed_dict.get("affected_target")
        facts_cited = list(parsed_dict.get("empirical_facts") or [])
        methodology = list(parsed_dict.get("methodology_references") or [])

        contributing: List[GroundingFailureCode] = []
        details: Dict[str, Any] = {
            "decision": decision,
            "affected_target": target_ref,
            "empirical_facts": facts_cited,
            "allowed_fact_ids": allowed_fact_ids,
            "allowed_target_ids": allowed_target_ids,
            "condition_id": condition_id,
        }

        # Step 1: Check for Free-form Prose in Target (G7)
        if target_ref and is_free_form_prose(target_ref):
            return GroundingValidationResult(
                is_valid=False,
                primary_code=GroundingFailureCode.G7,
                contributing_codes=contributing,
                reason=f"FREE_FORM_TARGET_REJECTED: affected_target contains free-form prose or invalid string: '{target_ref}'",
                details=details,
            )

        # Step 2: Epistemic Tier Separation & Target Evidence Primacy (G8)
        # A. Epistemic confusion: CHK in empirical_facts or FACT in methodology
        chk_in_facts = [f for f in facts_cited if "CHK-" in f]
        fact_in_meth = [m for m in methodology if "FACT-" in m]
        if chk_in_facts or fact_in_meth:
            return GroundingValidationResult(
                is_valid=False,
                primary_code=GroundingFailureCode.G8,
                contributing_codes=contributing,
                reason=f"EPISTEMIC_CONFUSION: Namespace breach: chk_in_facts={chk_in_facts}, fact_in_meth={fact_in_meth}",
                details=details,
            )

        # B. HYPOTHESIS must have supporting target facts
        if decision == "HYPOTHESIS" and not facts_cited:
            return GroundingValidationResult(
                is_valid=False,
                primary_code=GroundingFailureCode.G8,
                contributing_codes=contributing,
                reason="UNGROUNDED_HYPOTHESIS: Decision HYPOTHESIS requires at least one supporting empirical fact ID",
                details=details,
            )

        # Step 3: Fact ID Format Validation (G1)
        invalid_format_facts = [f for f in facts_cited if not FACT_ID_PATTERN.match(f)]
        if invalid_format_facts:
            return GroundingValidationResult(
                is_valid=False,
                primary_code=GroundingFailureCode.G1,
                contributing_codes=contributing,
                reason=f"FACT_ID_INVALID: Cited facts do not match pattern ^FACT-[A-Za-z0-9_-]+$: {invalid_format_facts}",
                details=details,
            )

        # Step 4: Fact ID Allowed-Set Containment (G2)
        # Under P2 and P3, cited facts must strictly belong to allowed_fact_ids.
        # Under P1 (control), ungrounded facts are also detected here as G2.
        allowed_facts_set = set(allowed_fact_ids)
        unallowed_facts = [f for f in facts_cited if f not in allowed_facts_set]
        if unallowed_facts:
            return GroundingValidationResult(
                is_valid=False,
                primary_code=GroundingFailureCode.G2,
                contributing_codes=contributing,
                reason=f"FACT_ID_NOT_IN_ALLOWED_SET: Cited facts not in allowed scenario evidence: {unallowed_facts}",
                details=details,
            )

        # Step 5: Target ID Format Validation (G3)
        if not target_ref or not is_valid_target_syntax(target_ref):
            return GroundingValidationResult(
                is_valid=False,
                primary_code=GroundingFailureCode.G3,
                contributing_codes=contributing,
                reason=f"TARGET_ID_INVALID: affected_target does not match valid identifier syntax: '{target_ref}'",
                details=details,
            )

        # Step 6: Target ID Allowed-Set Containment (G4)
        if condition_id == "P3":
            allowed_targets_set = set(allowed_target_ids)
            if target_ref not in allowed_targets_set:
                return GroundingValidationResult(
                    is_valid=False,
                    primary_code=GroundingFailureCode.G4,
                    contributing_codes=contributing,
                    reason=f"TARGET_ID_NOT_IN_ALLOWED_SET: affected_target '{target_ref}' not in P3 allowed targets {allowed_target_ids}",
                    details=details,
                )

        # Step 7: Target Structural Grounding in Channel A (G5)
        # Even under P1 and P2, the target must exist in the Channel A pack
        is_structurally_grounded = (
            target_ref == pack.endpoint_id
            or target_ref == pack.asset_id
            or target_ref == pack.route_template
            or any(
                target_ref == (p.get("param_id") if isinstance(p, dict) else str(p))
                for p in pack.parameter_lineage
            )
            or any(
                target_ref == (p.get("name") if isinstance(p, dict) else str(p))
                for p in pack.parameter_lineage
            )
        )
        if not is_structurally_grounded:
            return GroundingValidationResult(
                is_valid=False,
                primary_code=GroundingFailureCode.G5,
                contributing_codes=contributing,
                reason=f"TARGET_NOT_STRUCTURALLY_GROUNDED: affected_target '{target_ref}' not found in Channel A envelope",
                details=details,
            )

        # Step 8: Cross Mismatch Check (G6)
        # If facts are present, ensure they belong to this structural pack's observed facts
        pack_facts = {
            f.get("fact_id") for f in pack.observed_facts if isinstance(f, dict) and f.get("fact_id")
        }
        mismatched = [f for f in facts_cited if f not in pack_facts]
        if mismatched:
            return GroundingValidationResult(
                is_valid=False,
                primary_code=GroundingFailureCode.G6,
                contributing_codes=contributing,
                reason=f"FACT_TARGET_CROSS_MISMATCH: Cited facts {mismatched} do not belong to target envelope {pack.endpoint_id}",
                details=details,
            )

        # Passed all grounding checks
        return GroundingValidationResult(
            is_valid=True,
            primary_code=None,
            contributing_codes=[],
            reason="All facts and targets validly grounded against scenario envelope",
            details=details,
        )
