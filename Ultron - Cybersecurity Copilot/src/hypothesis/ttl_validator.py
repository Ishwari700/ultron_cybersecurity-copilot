"""Pre-execution TTL Freshness Validator Contract (M2 Boundary).

Defines abstract interface IPreExecutionTTLValidator and MockPreExecutionTTLValidator.
M2 establishes the contract and verifies that 7B-emitted proposals contain properly bound token references.
No live token refresh, dynamic re-authentication, or session lifecycle logic is implemented in M2 (M2.75 Scope).
"""

from abc import ABC, abstractmethod
from typing import Optional
from pydantic import BaseModel

from src.evidence.vault import RedactionVault
from src.hypothesis.experiment import ExperimentProposal


class TTLValidationResult(BaseModel):
    """Result of validating token freshness prior to experiment dispatch."""
    valid: bool
    error: Optional[str] = None
    requires_refresh: bool = False
    identity_id: Optional[str] = None


class IPreExecutionTTLValidator(ABC):
    """Abstract interface contract for pre-execution token freshness validation (M2 Boundary)."""

    @abstractmethod
    def validate_proposal(
        self, experiment: ExperimentProposal, vault: RedactionVault
    ) -> TTLValidationResult:
        """Validates presence and freshness of ephemeral tokens prior to experiment execution."""
        pass


class MockPreExecutionTTLValidator(IPreExecutionTTLValidator):
    """M2 mock implementation verifying interface contracts without live network refresh."""

    def validate_proposal(
        self, experiment: ExperimentProposal, vault: RedactionVault
    ) -> TTLValidationResult:
        for token_ref in experiment.required_token_references:
            token_meta = vault.get_token_metadata(token_ref)
            if token_meta is None:
                return TTLValidationResult(valid=False, error="TOKEN_REFERENCE_NOT_FOUND")
            if token_meta.is_expired(clock_skew_seconds=30):
                # In M2: Flags expiration deterministically without initiating out-of-band refresh
                return TTLValidationResult(
                    valid=False,
                    error="TOKEN_EXPIRED",
                    requires_refresh=True,
                    identity_id=token_meta.identity_id,
                )
        return TTLValidationResult(valid=True)
