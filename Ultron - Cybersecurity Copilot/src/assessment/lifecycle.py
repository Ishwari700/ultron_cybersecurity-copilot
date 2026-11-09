"""Assessment Lifecycle State Machine for M6.

Enforces:
1. Deterministic transitions between formal assessment states.
2. Target interaction is forbidden in DRAFT, AUTHORIZATION_PENDING, EXPIRED, REVOKED, or CANCELLED.
3. Automated LLM systems cannot authorize, expand scope, or confirm findings.
4. Fail-closed transition guards.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from src.assessment.models import (
    AssessmentLifecycleState,
    AssessmentRecord,
    AuthorizationRecord,
    AuthorizationStatus,
)
from src.assessment.authorization import AuthorizationValidator, AuthorizationValidationError


# Permitted state transition DAG
LEGAL_TRANSITIONS: Dict[AssessmentLifecycleState, Set[AssessmentLifecycleState]] = {
    AssessmentLifecycleState.DRAFT: {
        AssessmentLifecycleState.AUTHORIZATION_PENDING,
        AssessmentLifecycleState.AUTHORIZED,
        AssessmentLifecycleState.CANCELLED,
    },
    AssessmentLifecycleState.AUTHORIZATION_PENDING: {
        AssessmentLifecycleState.AUTHORIZED,
        AssessmentLifecycleState.CANCELLED,
        AssessmentLifecycleState.REVOKED,
    },
    AssessmentLifecycleState.AUTHORIZED: {
        AssessmentLifecycleState.SCOPE_DEFINED,
        AssessmentLifecycleState.CANCELLED,
        AssessmentLifecycleState.REVOKED,
        AssessmentLifecycleState.EXPIRED,
    },
    AssessmentLifecycleState.SCOPE_DEFINED: {
        AssessmentLifecycleState.ASSESSMENT_ACTIVE,
        AssessmentLifecycleState.CANCELLED,
        AssessmentLifecycleState.REVOKED,
        AssessmentLifecycleState.EXPIRED,
    },
    AssessmentLifecycleState.ASSESSMENT_ACTIVE: {
        AssessmentLifecycleState.VALIDATION_PENDING,
        AssessmentLifecycleState.HUMAN_REVIEW,
        AssessmentLifecycleState.COMPLETED,
        AssessmentLifecycleState.CANCELLED,
        AssessmentLifecycleState.REVOKED,
        AssessmentLifecycleState.EXPIRED,
    },
    AssessmentLifecycleState.VALIDATION_PENDING: {
        AssessmentLifecycleState.HUMAN_REVIEW,
        AssessmentLifecycleState.ASSESSMENT_ACTIVE,
        AssessmentLifecycleState.CANCELLED,
        AssessmentLifecycleState.REVOKED,
        AssessmentLifecycleState.EXPIRED,
    },
    AssessmentLifecycleState.HUMAN_REVIEW: {
        AssessmentLifecycleState.COMPLETED,
        AssessmentLifecycleState.ASSESSMENT_ACTIVE,
        AssessmentLifecycleState.VALIDATION_PENDING,
        AssessmentLifecycleState.CANCELLED,
        AssessmentLifecycleState.REVOKED,
        AssessmentLifecycleState.EXPIRED,
    },
    AssessmentLifecycleState.COMPLETED: {
        AssessmentLifecycleState.ARCHIVED,
    },
    AssessmentLifecycleState.ARCHIVED: set(),
    AssessmentLifecycleState.CANCELLED: set(),
    AssessmentLifecycleState.EXPIRED: set(),
    AssessmentLifecycleState.REVOKED: set(),
}


class AssessmentLifecycleEngine:
    """State machine governing assessment status and active permissions."""

    @staticmethod
    def transition(
        assessment: AssessmentRecord,
        target_state: AssessmentLifecycleState,
        actor: str,
        reason: str,
        authorization: Optional[AuthorizationRecord] = None,
        scope_defined: bool = False,
    ) -> AssessmentRecord:
        """
        Attempts to transition the assessment into target_state.
        Fails closed and raises ValueError on illegal transitions or missing preconditions.
        """
        # Block automated LLM actors from advancing critical gates
        if "LLM" in actor.upper() or "MODEL" in actor.upper() or "COPILOT" in actor.upper():
            raise PermissionError(
                f"LIFECYCLE_GUARD_VIOLATION: Automated agent '{actor}' cannot transition assessment states."
            )

        current_state = assessment.state

        # Check DAG legality
        allowed = LEGAL_TRANSITIONS.get(current_state, set())
        if target_state not in allowed:
            raise ValueError(
                f"ILLEGAL_LIFECYCLE_TRANSITION: Cannot transition assessment {assessment.assessment_id} "
                f"from {current_state.value} to {target_state.value}."
            )

        # Precondition checks
        if target_state == AssessmentLifecycleState.AUTHORIZED:
            if not authorization:
                raise ValueError("PRECONDITION_FAILED: Target state AUTHORIZED requires valid AuthorizationRecord.")
            is_valid, auth_reason = AuthorizationValidator.validate_authorization(authorization)
            if not is_valid:
                raise ValueError(f"PRECONDITION_FAILED: Authorization invalid ({auth_reason}).")

        if target_state == AssessmentLifecycleState.SCOPE_DEFINED:
            if not scope_defined and not assessment.scope_policy_id:
                raise ValueError("PRECONDITION_FAILED: Target state SCOPE_DEFINED requires defined scope policy.")

        if target_state == AssessmentLifecycleState.ASSESSMENT_ACTIVE:
            if not authorization:
                raise ValueError("PRECONDITION_FAILED: ASSESSMENT_ACTIVE requires active AuthorizationRecord.")
            is_valid, auth_reason = AuthorizationValidator.validate_authorization(authorization)
            if not is_valid:
                raise ValueError(f"PRECONDITION_FAILED: Cannot activate assessment with invalid auth ({auth_reason}).")
            if not authorization.is_currently_valid():
                raise ValueError("PRECONDITION_FAILED: Cannot activate assessment with expired or revoked authorization.")
            if not scope_defined and not assessment.scope_policy_id:
                raise ValueError("PRECONDITION_FAILED: ASSESSMENT_ACTIVE requires defined scope.")
            # Enforce immutable scope policy binding
            if assessment.scope_policy_hash and authorization.scope_policy_hash:
                if assessment.scope_policy_hash != authorization.scope_policy_hash:
                    raise ValueError(
                        f"PRECONDITION_FAILED: Scope policy hash mismatch. "
                        f"Authorization authorizes '{authorization.scope_policy_hash}', "
                        f"but active policy is '{assessment.scope_policy_hash}'."
                    )

        now_iso = datetime.now(timezone.utc).isoformat()
        transition_entry = {
            "from_state": current_state.value,
            "to_state": target_state.value,
            "actor": actor,
            "reason": reason,
            "timestamp": now_iso,
        }

        assessment.state = target_state
        assessment.updated_at = now_iso
        assessment.state_history.append(transition_entry)

        return assessment

    @staticmethod
    def is_target_interaction_allowed(
        state: AssessmentLifecycleState,
        authorization: Optional[AuthorizationRecord] = None,
    ) -> Tuple[bool, str]:
        """
        Determines whether passive telemetry ingestion or active validation may occur.
        Fails closed if state does not permit target actions.
        """
        if state in {
            AssessmentLifecycleState.DRAFT,
            AssessmentLifecycleState.AUTHORIZATION_PENDING,
            AssessmentLifecycleState.AUTHORIZED,
            AssessmentLifecycleState.CANCELLED,
            AssessmentLifecycleState.COMPLETED,
            AssessmentLifecycleState.ARCHIVED,
            AssessmentLifecycleState.EXPIRED,
            AssessmentLifecycleState.REVOKED,
        }:
            return False, f"TARGET_ACTION_BLOCKED: Assessment state '{state.value}' forbids target interaction."

        if state == AssessmentLifecycleState.ASSESSMENT_ACTIVE and authorization is None:
            return False, "TARGET_ACTION_BLOCKED: Active assessment requires authorization record."

        if authorization is not None:
            is_valid, auth_reason = AuthorizationValidator.validate_authorization(authorization)
            if not is_valid:
                return False, f"TARGET_ACTION_BLOCKED: Authorization is invalid ({auth_reason})."
            if not authorization.is_currently_valid():
                return False, "TARGET_ACTION_BLOCKED: Authorization is expired or revoked."

        return True, "TARGET_ACTION_PERMITTED: Assessment is in an active permitted state."
