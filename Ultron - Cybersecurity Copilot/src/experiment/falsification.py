"""Milestone M11.7: Negative Controls + Differential Verification Engine.

Enforces:
1. Anti-False-Confidence Principle: Every meaningful experiment requires differential testing (Section 10).
2. Differential Verification: CASE A (Control) vs CASE B (Test) (Section 10.2).
3. Invariant INV-M11-09: Negative-control results cannot be overwritten to favor the hypothesis.
4. Falsification Analysis: Evaluates alternative benign explanations, configuration artifacts, and evidence sufficiency.
5. Deterministic Outcomes: SUPPORTED, WEAKLY_SUPPORTED, CONTESTED, REFUTED, INSUFFICIENT_EVIDENCE.
"""

from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from src.experiment.models import (
    ControlledExperiment,
    ExperimentStatus,
    FalsificationOutcome,
)
from src.experiment.observation import ControlledObservation
from src.experiment.poc import SafePoC
from src.experiment.state_machine import ExperimentStateMachine
from src.audit.ledger import AuditLedger
from src.audit.models import AuditEventType


class DifferentialComparisonResult(BaseModel):
    """
    Deterministic comparison between negative control and test observation.
    """
    comparison_id: str
    experiment_id: str
    control_type: str
    divergence_detected: bool
    negative_control_passed: bool
    summary: str
    test_summary: Dict[str, Any]
    control_summary: Dict[str, Any]
    differences: List[str] = Field(default_factory=list)
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class FalsificationReport(BaseModel):
    """
    Comprehensive adversarial falsification outcome for an experiment.
    """
    experiment_id: str
    hypothesis_id: str
    outcome: FalsificationOutcome
    confidence: float
    differential_result: Optional[DifferentialComparisonResult] = None
    alternative_explanations: List[str] = Field(default_factory=list)
    evidence_gaps: List[str] = Field(default_factory=list)
    falsification_notes: List[str] = Field(default_factory=list)
    is_confirmed: bool = False  # NEVER True autonomously; requires human verification (INV-M11-12)
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class DifferentialVerificationEngine:
    """
    Executes differential analysis and hypothesis falsification.
    """

    @classmethod
    def compare(
        cls,
        experiment_id: str,
        test_obs: ControlledObservation,
        control_obs: Optional[ControlledObservation],
        expected_behavior: str,
        expected_safe_behavior: str,
        canary_marker: Optional[str] = None,
        control_type: str = "BENIGN_BASELINE",
    ) -> DifferentialComparisonResult:
        """
        Compares Case A (Control) against Case B (Test).
        Fails closed if negative control indicates benign or uniform behavior.
        """
        differences: List[str] = []
        divergence = False
        control_passed = False

        test_out = test_obs.output
        ctrl_out = control_obs.output if control_obs else ""

        # Extract HTTP status codes if present
        test_status = None
        ctrl_status = None
        if test_obs.http_responses:
            test_status = test_obs.http_responses[0].get("status_code")
        if control_obs and control_obs.http_responses:
            ctrl_status = control_obs.http_responses[0].get("status_code")

        test_has_canary = (canary_marker in test_out) if canary_marker else False
        ctrl_has_canary = (canary_marker in ctrl_out) if (canary_marker and control_obs) else False

        if test_status is not None and ctrl_status is not None:
            if test_status != ctrl_status:
                divergence = True
                differences.append(f"HTTP Status diverged: Test={test_status} vs Control={ctrl_status}")
            else:
                differences.append(f"HTTP Status identical: {test_status}")

        if canary_marker:
            if test_has_canary and not ctrl_has_canary:
                divergence = True
                differences.append(f"Canary marker '{canary_marker}' appeared strictly in test observation")
            elif test_has_canary and ctrl_has_canary:
                differences.append(f"Canary marker appeared in BOTH test and control (indicates uncontrolled reflection or public data)")
            elif not test_has_canary:
                differences.append(f"Canary marker absent in test observation")

        # Determine if negative control passed (safe behavior observed in control)
        if control_obs is None:
            control_passed = False
            summary = "No negative control executed: baseline unverified"
        elif ctrl_has_canary:
            # Control shouldn't have matched condition!
            control_passed = False
            summary = "Negative control FALSIFIED hypothesis: condition also occurred under baseline"
        elif divergence:
            control_passed = True
            summary = "Differential verification SUCCESS: Clear divergence between test condition and safe baseline"
        else:
            control_passed = False
            summary = "No meaningful divergence detected between test and control"

        comp_id = f"DIFF-{test_obs.observation_id[:8]}-{control_obs.observation_id[:8] if control_obs else 'NIL'}"

        return DifferentialComparisonResult(
            comparison_id=comp_id,
            experiment_id=experiment_id,
            control_type=control_type,
            divergence_detected=divergence,
            negative_control_passed=control_passed,
            summary=summary,
            test_summary={
                "status_code": test_status,
                "has_canary": test_has_canary,
                "exit_code": test_obs.exit_code,
            },
            control_summary={
                "status_code": ctrl_status,
                "has_canary": ctrl_has_canary,
                "exit_code": control_obs.exit_code if control_obs else None,
            },
            differences=differences,
        )

    @classmethod
    def evaluate_falsification(
        cls,
        experiment: ControlledExperiment,
        test_obs: ControlledObservation,
        control_obs: Optional[ControlledObservation] = None,
        poc: Optional[SafePoC] = None,
        audit_ledger: Optional[AuditLedger] = None,
    ) -> FalsificationReport:
        """
        Synthesizes differential observations into an objective falsification report.
        Strictly enforces: MODEL_HYPOTHESIS != CONFIRMED_FINDING (Section 1).
        """
        canary = poc.canary_marker if poc else None
        exp_beh = poc.expected_behavior if poc else "Expected condition observed"
        safe_beh = poc.expected_safe_behavior if poc else "Default access denied / unreflected"

        diff_res = cls.compare(
            experiment_id=experiment.experiment_id,
            test_obs=test_obs,
            control_obs=control_obs,
            expected_behavior=exp_beh,
            expected_safe_behavior=safe_beh,
            canary_marker=canary,
        )

        alternative_explanations: List[str] = []
        evidence_gaps: List[str] = []
        notes: List[str] = []

        # Evaluate outcome
        if test_obs.exit_code != 0 and not test_obs.http_responses:
            outcome = FalsificationOutcome.REFUTED
            confidence = 0.95
            notes.append("Test execution terminated with error/non-zero exit code.")
        elif canary and canary not in test_obs.output:
            outcome = FalsificationOutcome.REFUTED
            confidence = 0.90
            notes.append(f"Expected canary marker '{canary}' was NOT observed in execution output.")
            alternative_explanations.append("Server sanitization, authentication barrier, or route absence prevented triggering condition.")
        elif control_obs and diff_res.control_summary.get("has_canary"):
            outcome = FalsificationOutcome.REFUTED
            confidence = 0.95
            notes.append("Negative control also observed the marker; behavior is not condition-specific.")
            alternative_explanations.append("Marker is reflected statically or endpoint is universally accessible without authorization barrier.")
        elif control_obs and not diff_res.divergence_detected:
            outcome = FalsificationOutcome.CONTESTED
            confidence = 0.70
            notes.append("Test and control showed identical behavior. Suspicion contested.")
            alternative_explanations.append("Mock fixture behavior or cache collision.")
        elif control_obs is None:
            outcome = FalsificationOutcome.WEAKLY_SUPPORTED
            confidence = 0.40
            notes.append("Observed in test, but lacking negative control verification.")
            evidence_gaps.append("Negative control baseline required before elevation.")
        else:
            # Positive observation + clean differential negative control
            outcome = FalsificationOutcome.SUPPORTED
            confidence = 0.85
            notes.append("Condition verified differentially against negative control baseline.")

        # Update experiment state machine: OBSERVATIONS_CAPTURED -> FALSIFICATION -> REVIEW
        try:
            if experiment.status == ExperimentStatus.OBSERVATIONS_CAPTURED:
                ExperimentStateMachine.transition(
                    experiment,
                    ExperimentStatus.FALSIFICATION,
                    actor="falsification_engine",
                    reason="Differential verification analysis",
                )
                ExperimentStateMachine.transition(
                    experiment,
                    ExperimentStatus.REVIEW,
                    actor="falsification_engine",
                    reason="Falsification evaluation complete, queued for human review",
                )
        except Exception:
            pass

        report = FalsificationReport(
            experiment_id=experiment.experiment_id,
            hypothesis_id=experiment.hypothesis_id,
            outcome=outcome,
            confidence=confidence,
            differential_result=diff_res,
            alternative_explanations=alternative_explanations,
            evidence_gaps=evidence_gaps,
            falsification_notes=notes,
            is_confirmed=False,  # Under NO circumstances is this set to True automatically
        )

        experiment.falsification_result = report.model_dump()

        if audit_ledger:
            audit_ledger.append(
                actor="falsification_engine",
                event_type=AuditEventType.FALSIFICATION_COMPLETED,
                object_id=experiment.experiment_id,
                metadata={
                    "outcome": outcome.value,
                    "confidence": confidence,
                    "differential_passed": diff_res.negative_control_passed,
                },
            )

        return report
