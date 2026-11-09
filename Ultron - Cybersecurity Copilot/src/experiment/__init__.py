"""Milestone M11: Controlled Security Experiment and Safe PoC Engine.

Exported classes and schemas:
- ExecutionPlane, ExperimentEnvironmentType, ExperimentRiskLevel, ExperimentStatus, ControlledExperiment
- SafePoC, SafePoCValidator, PoCVulnerabilityClass
- PreflightSafetyEngine, PreflightReport, PreflightDecision
- ControlledLabRunner, LabExecutionResult, LabExecutionStatus
- HumanApprovalGate, HumanApprovalRequest, ExecutionAuthorizationToken
- ControlledObservation, ControlledObservationCapture
- DifferentialVerificationEngine, DifferentialComparisonResult, FalsificationReport
- ExperimentReplayEngine, ExperimentReplayRecord
- FindingCandidate, FindingValidationBridge
- ExperimentStateMachine, HumanApprovalRejectedError, InvalidStateTransitionError
"""

from src.experiment.models import (
    ControlledExperiment,
    ExecutionAuthorizationToken,
    ExecutionPlane,
    ExperimentEnvironmentType,
    ExperimentRiskLevel,
    ExperimentStatus,
    FalsificationOutcome,
    RollbackPlan,
)
from src.experiment.poc import (
    PoCVulnerabilityClass,
    SafePoC,
    SafePoCValidator,
)
from src.experiment.state_machine import (
    ExperimentStateMachine,
    HumanApprovalRejectedError,
    InvalidStateTransitionError,
)
from src.experiment.preflight import (
    PreflightDecision,
    PreflightReport,
    PreflightSafetyEngine,
)
from src.experiment.lab_runner import (
    ControlledLabRunner,
    LabExecutionResult,
    LabExecutionStatus,
)
from src.experiment.approval import (
    HumanApprovalGate,
    HumanApprovalRequest,
)
from src.experiment.observation import (
    ControlledObservation,
    ControlledObservationCapture,
)
from src.experiment.falsification import (
    DifferentialComparisonResult,
    DifferentialVerificationEngine,
    FalsificationReport,
)
from src.experiment.replay import (
    ExperimentReplayEngine,
    ExperimentReplayRecord,
)
from src.experiment.validator_bridge import (
    FindingCandidate,
    FindingValidationBridge,
)

__all__ = [
    "ControlledExperiment",
    "ExecutionAuthorizationToken",
    "ExecutionPlane",
    "ExperimentEnvironmentType",
    "ExperimentRiskLevel",
    "ExperimentStatus",
    "FalsificationOutcome",
    "RollbackPlan",
    "PoCVulnerabilityClass",
    "SafePoC",
    "SafePoCValidator",
    "ExperimentStateMachine",
    "HumanApprovalRejectedError",
    "InvalidStateTransitionError",
    "PreflightDecision",
    "PreflightReport",
    "PreflightSafetyEngine",
    "ControlledLabRunner",
    "LabExecutionResult",
    "LabExecutionStatus",
    "HumanApprovalGate",
    "HumanApprovalRequest",
    "ControlledObservation",
    "ControlledObservationCapture",
    "DifferentialComparisonResult",
    "DifferentialVerificationEngine",
    "FalsificationReport",
    "ExperimentReplayEngine",
    "ExperimentReplayRecord",
    "FindingCandidate",
    "FindingValidationBridge",
]
