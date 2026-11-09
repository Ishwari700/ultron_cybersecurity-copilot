"""Milestone M11.6: Observation + Evidence Capture Engine.

Enforces:
1. Observation Integrity: Observations come strictly from actual execution outputs (INV-M11-08).
2. Anti-Fabrication: The model may NOT synthesize, modify, or fabricate observations to match a hypothesis.
3. Cryptographic Hashing: Every observation has a deterministic SHA-256 hash of its actual payload.
4. Deterministic Normalization and Canonical Evidence Conversion (Section 9.3).
5. Epistemic Separation: Epistemic status is strictly OBSERVATION / FACT, never MODEL_HYPOTHESIS.
"""

from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from src.experiment.models import ControlledExperiment, ExperimentStatus
from src.experiment.lab_runner import LabExecutionResult
from src.experiment.poc import SafePoC
from src.experiment.state_machine import ExperimentStateMachine
from src.assessment.models import (
    AssessmentScopeStatus,
    CanonicalObservation,
    ObservationType,
)
from src.audit.ledger import AuditLedger
from src.audit.models import AuditEventType


class ControlledObservation(BaseModel):
    """
    Direct, tamper-evident capture of actual execution outputs.
    """
    observation_id: str
    experiment_id: str
    assessment_id: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    environment: str
    input_reference: Dict[str, Any] = Field(default_factory=dict)
    output: str = ""
    stdout: str = ""
    stderr: str = ""
    http_responses: List[Dict[str, Any]] = Field(default_factory=list)
    exit_code: int = 0
    status: str = "CAPTURED"
    artifact_references: List[str] = Field(default_factory=list)
    provenance: Dict[str, Any] = Field(default_factory=dict)
    content_hash: str = ""

    @classmethod
    def create(
        cls,
        experiment_id: str,
        assessment_id: str,
        environment: str,
        input_reference: Dict[str, Any],
        output: str,
        stdout: str = "",
        stderr: str = "",
        http_responses: Optional[List[Dict[str, Any]]] = None,
        exit_code: int = 0,
        status: str = "CAPTURED",
        artifact_references: Optional[List[str]] = None,
        provenance: Optional[Dict[str, Any]] = None,
    ) -> "ControlledObservation":
        payload = {
            "experiment_id": experiment_id,
            "assessment_id": assessment_id,
            "environment": environment,
            "input_reference": input_reference,
            "output": output,
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": exit_code,
            "http_responses": http_responses or [],
        }
        raw_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
        h = hashlib.sha256(raw_bytes).hexdigest()
        obs_id = f"OBS-M11-{h[:12].upper()}"

        return cls(
            observation_id=obs_id,
            experiment_id=experiment_id,
            assessment_id=assessment_id,
            environment=environment,
            input_reference=input_reference,
            output=output,
            stdout=stdout,
            stderr=stderr,
            http_responses=http_responses or [],
            exit_code=exit_code,
            status=status,
            artifact_references=artifact_references or [],
            provenance=provenance or {
                "source": "ControlledLabRunner",
                "execution_plane": "PLANE_A_LOCAL_LAB",
            },
            content_hash=h,
        )

    def verify_integrity(self) -> bool:
        """Verifies that the recorded content matches the cryptographic hash."""
        payload = {
            "experiment_id": self.experiment_id,
            "assessment_id": self.assessment_id,
            "environment": self.environment,
            "input_reference": self.input_reference,
            "output": self.output,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "exit_code": self.exit_code,
            "http_responses": self.http_responses,
        }
        raw_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
        computed = hashlib.sha256(raw_bytes).hexdigest()
        return computed == self.content_hash


class ControlledObservationCapture:
    """
    Captures execution outputs into verified ControlledObservation records and CanonicalObservation evidence.
    """

    @classmethod
    def capture_from_execution(
        cls,
        experiment: ControlledExperiment,
        execution_result: LabExecutionResult,
        poc: Optional[SafePoC] = None,
        audit_ledger: Optional[AuditLedger] = None,
    ) -> ControlledObservation:
        """
        Creates a ControlledObservation strictly from actual lab execution results.
        Enforces INV-M11-08: No fabricated observations.
        """
        # Determine actual primary output representation
        if execution_result.http_responses:
            output_repr = json.dumps(execution_result.http_responses, sort_keys=True)
        elif execution_result.stdout:
            output_repr = execution_result.stdout
        elif execution_result.stderr:
            output_repr = f"STDERR: {execution_result.stderr}"
        else:
            output_repr = f"Exit code {execution_result.exit_code}"

        inputs_ref = {
            "poc_inputs": poc.inputs if poc else {},
            "proposed_actions": experiment.proposed_actions,
            "execution_id": execution_result.execution_id,
        }

        obs = ControlledObservation.create(
            experiment_id=experiment.experiment_id,
            assessment_id=experiment.assessment_id,
            environment=experiment.environment_type.value,
            input_reference=inputs_ref,
            output=output_repr,
            stdout=execution_result.stdout,
            stderr=execution_result.stderr,
            http_responses=execution_result.http_responses,
            exit_code=execution_result.exit_code,
            status=execution_result.status.value,
            artifact_references=execution_result.artifacts_created,
            provenance={
                "execution_id": execution_result.execution_id,
                "duration_seconds": execution_result.duration_seconds,
                "cleaned_up": execution_result.cleaned_up,
                "canary_marker": poc.canary_marker if poc else None,
            },
        )

        experiment.observation_ids.append(obs.observation_id)

        # Transition state machine: EXECUTING -> OBSERVATIONS_CAPTURED
        if experiment.status == ExperimentStatus.EXECUTING:
            ExperimentStateMachine.transition(
                experiment,
                ExperimentStatus.OBSERVATIONS_CAPTURED,
                actor="observation_capture",
                reason=f"Captured verified observation {obs.observation_id}",
            )

        # Audit logging
        if audit_ledger:
            audit_ledger.append(
                actor="observation_capture",
                event_type=AuditEventType.OBSERVATION_CAPTURED,
                object_id=obs.observation_id,
                metadata={
                    "experiment_id": experiment.experiment_id,
                    "content_hash": obs.content_hash,
                    "exit_code": obs.exit_code,
                },
            )

        return obs

    @classmethod
    def to_canonical_observation(
        cls,
        obs: ControlledObservation,
        asset_id: Optional[str] = None,
        scope_decision: AssessmentScopeStatus = AssessmentScopeStatus.IN_SCOPE,
    ) -> CanonicalObservation:
        """
        Converts ControlledObservation into canonical M6/M8 CanonicalObservation entity for downstream validation.
        """
        norm_data = {
            "experiment_id": obs.experiment_id,
            "environment": obs.environment,
            "exit_code": obs.exit_code,
            "status": obs.status,
            "stdout": obs.stdout,
            "stderr": obs.stderr,
            "http_responses": obs.http_responses,
            "target_identifier": asset_id or obs.environment,
        }

        # Choose observation type
        obs_type = ObservationType.HTTP_RESPONSE if obs.http_responses else ObservationType.TOOL_OUTPUT

        return CanonicalObservation.create(
            assessment_id=obs.assessment_id,
            asset_id=asset_id or obs.environment,
            observation_type=obs_type,
            source=f"ControlledExperiment:{obs.experiment_id}",
            normalized_data=norm_data,
            scope_decision=scope_decision,
            scope_rule="Plane A Local Lab Isolation",
            raw_reference=obs.output[:500],
            confidence=1.0,
            provenance=obs.provenance,
        )
