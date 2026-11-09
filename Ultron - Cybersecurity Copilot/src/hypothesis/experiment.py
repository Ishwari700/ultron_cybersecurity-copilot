"""Structured, discriminative experiment proposal models."""

from enum import Enum
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class MutationClass(str, Enum):
    CROSS_IDENTITY_REPLAY = "cross_identity_replay"
    STEP_SKIPPING = "step_skipping"
    PARAMETER_TAMPERING = "parameter_tampering"
    PRIVILEGE_ELEVATION = "privilege_elevation"
    UNAUTHENTICATED_ACCESS = "unauthenticated_access"


class SafetyLevel(str, Enum):
    READ_ONLY_SAFE = "READ_ONLY_SAFE"
    STATE_CHANGING_REQUIRES_APPROVAL = "STATE_CHANGING_REQUIRES_APPROVAL"
    DESTRUCTIVE_ISOLATED_DATA = "DESTRUCTIVE_ISOLATED_DATA"


class ExpectedObservations(BaseModel):
    """
    Discriminative expected outcomes distinguishing competing security explanations.
    """
    supporting_observation: str # Observation A: Supports Hypothesis
    contradicting_observation: str # Observation B: Contradicts Hypothesis
    unresolved_observation: str = "Request returned 500 internal server error or network timeout"


class ExperimentProposal(BaseModel):
    """
    Executable, discriminative experiment proposal designed by the reasoning engine.
    """
    objective: str
    target_asset_id: str
    mutation_class: MutationClass
    actor_identity_id: Optional[str] = None
    target_identity_id: Optional[str] = None
    expected_observations: ExpectedObservations
    safety_level: SafetyLevel = SafetyLevel.READ_ONLY_SAFE
    required_token_references: list[str] = Field(default_factory=list)
    required_test_data: str = "Standard test tenant identifiers"
    rollback_requirement: str = "No rollback needed for read-only operations"

    def is_discriminative(self) -> bool:
        """Verify that supporting and contradicting observations distinguish different states."""
        supp = self.expected_observations.supporting_observation.strip().lower()
        cont = self.expected_observations.contradicting_observation.strip().lower()
        return bool(supp and cont and supp != cont)
