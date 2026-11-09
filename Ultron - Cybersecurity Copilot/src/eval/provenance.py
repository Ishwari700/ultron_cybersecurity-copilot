"""Execution provenance models and validators for Milestone M5."""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, model_validator


class ExecutionProvenance(str, Enum):
    LIVE_LLM = "LIVE_LLM"
    DETERMINISTIC_SIMULATOR = "DETERMINISTIC_SIMULATOR"
    HERMETIC_PIPELINE = "HERMETIC_PIPELINE"
    HYBRID = "HYBRID"


class EvaluationProvenanceRecord(BaseModel):
    """
    Explicit provenance metadata distinguishing live LLM inference,
    deterministic simulation, hermetic rules, and hybrid execution.
    """
    execution_provenance: ExecutionProvenance
    execution_mode: str = "offline"
    simulator_active: bool = False
    live_model_active: bool = False
    model_name: Optional[str] = None
    model_digest: Optional[str] = None
    runtime_version: str = "6.0.0"
    inference_count: int = 0
    ground_truth_source: str = "scenario_ground_truth"
    evaluator_source: str = "deterministic_scorer"

    # Strict separation of telemetry components
    model_observations: List[Dict[str, Any]] = Field(default_factory=list)
    simulator_ground_truth: Dict[str, Any] = Field(default_factory=dict)
    evaluator_labels: Dict[str, Any] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_provenance_invariants(self) -> "EvaluationProvenanceRecord":
        """Rejects impossible provenance combinations."""
        if self.execution_provenance == ExecutionProvenance.LIVE_LLM:
            if self.simulator_active:
                raise ValueError(
                    "LIVE_LLM provenance cannot have simulator_active=True; "
                    "use HYBRID provenance when simulator feedback accompanies live inference."
                )
            if not self.live_model_active:
                raise ValueError("LIVE_LLM provenance requires live_model_active=True.")
            if not self.model_name:
                raise ValueError("LIVE_LLM provenance requires explicit model_name.")
            if self.inference_count <= 0:
                raise ValueError("LIVE_LLM provenance requires inference_count > 0.")

        elif self.execution_provenance == ExecutionProvenance.DETERMINISTIC_SIMULATOR:
            if self.live_model_active:
                raise ValueError("DETERMINISTIC_SIMULATOR cannot have live_model_active=True.")
            if self.inference_count > 0:
                raise ValueError("DETERMINISTIC_SIMULATOR cannot have inference_count > 0.")
            if not self.simulator_active:
                raise ValueError("DETERMINISTIC_SIMULATOR must have simulator_active=True.")

        elif self.execution_provenance == ExecutionProvenance.HERMETIC_PIPELINE:
            if self.live_model_active:
                raise ValueError("HERMETIC_PIPELINE cannot have live_model_active=True.")
            if self.simulator_active:
                raise ValueError("HERMETIC_PIPELINE cannot have simulator_active=True.")
            if self.inference_count > 0:
                raise ValueError("HERMETIC_PIPELINE cannot have inference_count > 0.")

        elif self.execution_provenance == ExecutionProvenance.HYBRID:
            if not self.simulator_active:
                raise ValueError("HYBRID provenance requires simulator_active=True.")
            if not self.live_model_active:
                raise ValueError("HYBRID provenance requires live_model_active=True.")
            if not self.model_name:
                raise ValueError("HYBRID provenance requires explicit model_name.")
            if self.inference_count <= 0:
                raise ValueError("HYBRID provenance requires inference_count > 0.")

        return self
