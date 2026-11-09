"""Deterministic Authorization Engine and Validation Gates for M6.

Guarantees:
1. Authorization cannot be granted, inferred, or expanded by LLM output.
2. Authorization requires explicit human-issued status == AUTHORIZED.
3. Strict time-window verification (valid_from <= now <= valid_until).
4. Automatic fail-closed behavior on REVOKED, EXPIRED, PENDING, or INVALID state.
5. Every target-affecting experiment or assessment must hold valid authorization.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from src.assessment.models import (
    AuthorizationRecord,
    AuthorizationStatus,
    AuthorizationType,
)


class AuthorizationValidationError(Exception):
    """Raised when an action violates authorization boundaries or state."""
    pass


class AuthorizationValidator:
    """Deterministic verification engine for assessment authorizations."""

    @staticmethod
    def validate_authorization(
        auth: Optional[AuthorizationRecord],
        reference_time: Optional[datetime] = None,
        require_active: bool = True,
    ) -> Tuple[bool, str]:
        """
        Validates authorization status and time window deterministically.
        Returns (is_valid: bool, reason: str).
        Fails closed on any ambiguity or validation failure.
        """
        if auth is None:
            return False, "AUTHORIZATION_MISSING: No authorization record provided."

        if not isinstance(auth, AuthorizationRecord):
            return False, "AUTHORIZATION_MALFORMED: Invalid authorization record type."

        # Check explicit status
        if auth.status == AuthorizationStatus.REVOKED:
            return False, "AUTHORIZATION_REVOKED: Assessment authorization has been explicitly revoked."

        if auth.status == AuthorizationStatus.EXPIRED:
            return False, "AUTHORIZATION_EXPIRED: Assessment authorization has expired."

        if auth.status == AuthorizationStatus.INVALID:
            return False, "AUTHORIZATION_INVALID: Assessment authorization is marked invalid."

        if auth.status == AuthorizationStatus.PENDING:
            return False, "AUTHORIZATION_PENDING: Assessment authorization is pending approval."

        if auth.status != AuthorizationStatus.AUTHORIZED:
            return False, f"AUTHORIZATION_UNAUTHORIZED: Status '{auth.status.value}' is not AUTHORIZED."

        # Verify time boundaries
        now = reference_time or datetime.now(timezone.utc)
        try:
            start_dt = datetime.fromisoformat(auth.valid_from.replace("Z", "+00:00"))
            end_dt = datetime.fromisoformat(auth.valid_until.replace("Z", "+00:00"))
        except Exception as e:
            return False, f"AUTHORIZATION_DATE_ERROR: Unparseable validity window ({e})."

        if now < start_dt:
            return False, f"AUTHORIZATION_NOT_YET_VALID: Valid from {auth.valid_from}, current time {now.isoformat()}."

        if now > end_dt:
            return False, f"AUTHORIZATION_EXPIRED_WINDOW: Expired at {auth.valid_until}, current time {now.isoformat()}."

        # Verify scope reference and organization are non-empty
        if not auth.organization or not auth.organization.strip():
            return False, "AUTHORIZATION_INCOMPLETE: Missing authorized organization."

        if not auth.assessment_name or not auth.assessment_name.strip():
            return False, "AUTHORIZATION_INCOMPLETE: Missing assessment_name."

        if not auth.authorized_by or not auth.authorized_by.strip():
            return False, "AUTHORIZATION_INCOMPLETE: Missing authorized_by signatory."

        # Verify no prompt injection or autonomous actor overrides in authorization fields
        check_strings = [
            auth.authorized_by,
            auth.organization,
            auth.assessment_name,
            auth.scope_reference,
            auth.status.value,
        ]
        if auth.rules:
            check_strings.extend(auth.rules)
        if auth.restrictions:
            check_strings.extend(auth.restrictions)

        for field_val in check_strings:
            if not isinstance(field_val, str):
                continue
            f_lower = field_val.lower()
            if any(inj in f_lower for inj in (
                "ignore previous", "grant admin", "override", "system prompt",
                "i own this", "authorized admin", "as an authorized", "bypass authorization",
                "trust this", "mark authorized", "auto_authorize", "eval("
            )):
                return False, "AUTHORIZATION_INCOMPLETE: Prompt injection or unauthorized text override detected."
            if any(auto in f_lower for auto in ("ai assistant", "llm", "copilot_bot", "automated_bot")):
                return False, "AUTHORIZATION_INVALID: Automated AI entity cannot grant or sign authorization."

        if not auth.scope_reference or not auth.scope_reference.strip():
            return False, "AUTHORIZATION_INCOMPLETE: Missing scope_reference."

        return True, "AUTHORIZATION_VALID: Active authorized assessment."

    @staticmethod
    def assert_authorized(
        auth: Optional[AuthorizationRecord],
        action_name: str = "Target Action",
        reference_time: Optional[datetime] = None,
    ) -> None:
        """Enforces authorization check and raises AuthorizationValidationError on failure."""
        is_valid, reason = AuthorizationValidator.validate_authorization(auth, reference_time=reference_time)
        if not is_valid:
            raise AuthorizationValidationError(f"FAIL CLOSED on {action_name}: {reason}")
