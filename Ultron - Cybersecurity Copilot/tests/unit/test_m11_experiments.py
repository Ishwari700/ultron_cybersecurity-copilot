"""Unit Tests for Milestone M11: Controlled Security Experiment and Safe PoC Engine."""

import time
import pytest
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
from src.experiment.state_machine import (
    ExperimentStateMachine,
    HumanApprovalRejectedError,
    InvalidStateTransitionError,
)
from src.experiment.poc import (
    PoCVulnerabilityClass,
    SafePoC,
    SafePoCValidator,
)
from src.experiment.preflight import (
    PreflightDecision,
    PreflightSafetyEngine,
)
from src.experiment.approval import (
    HumanApprovalGate,
)
from src.experiment.lab_runner import (
    ControlledLabRunner,
    LabExecutionResult,
    LabExecutionStatus,
)
from src.experiment.observation import (
    ControlledObservation,
    ControlledObservationCapture,
)
from src.experiment.falsification import (
    DifferentialVerificationEngine,
)
from src.experiment.replay import (
    ExperimentReplayEngine,
)
from src.experiment.validator_bridge import (
    FindingValidationBridge,
)
from src.assessment.models import (
    AssessmentRecord,
    AssessmentScopeStatus,
    AuthorizationRecord,
    AuthorizationStatus,
    AuthorizationType,
)


def test_controlled_experiment_creation():
    exp = ControlledExperiment.create(
        assessment_id="ASM-M11-TEST",
        hypothesis_id="HYP-001",
        authorization_reference="AUTH-REF-M11",
        scope_reference="SCOPE-REF-M11",
        proposed_actions=[{"type": "http_get", "url": "http://127.0.0.1:8080/api/profile"}],
    )
    assert exp.status == ExperimentStatus.DRAFT
    assert exp.execution_plane == ExecutionPlane.PLANE_A_LOCAL_LAB
    assert len(exp.state_history) == 1
    assert exp.state_history[0]["to_state"] == "DRAFT"


def test_experiment_state_machine_valid_transitions():
    exp = ControlledExperiment.create(
        assessment_id="ASM-M11-TEST",
        hypothesis_id="HYP-001",
        authorization_reference="AUTH-REF-M11",
        scope_reference="SCOPE-REF-M11",
        proposed_actions=[{"type": "synthetic_check"}],
    )
    ExperimentStateMachine.transition(exp, ExperimentStatus.PROPOSED, actor="researcher_alice", reason="Proposing exp")
    assert exp.status == ExperimentStatus.PROPOSED

    ExperimentStateMachine.transition(exp, ExperimentStatus.PREFLIGHT, actor="system", reason="Running preflight")
    assert exp.status == ExperimentStatus.PREFLIGHT

    ExperimentStateMachine.transition(exp, ExperimentStatus.AWAITING_HUMAN_APPROVAL, actor="system", reason="Awaiting approval")
    assert exp.status == ExperimentStatus.AWAITING_HUMAN_APPROVAL

    ExperimentStateMachine.transition(exp, ExperimentStatus.APPROVED, actor="researcher_alice", reason="Human approved")
    assert exp.status == ExperimentStatus.APPROVED

    ExperimentStateMachine.transition(exp, ExperimentStatus.READY, actor="researcher_alice", reason="Ready to execute")
    assert exp.status == ExperimentStatus.READY

    ExperimentStateMachine.transition(exp, ExperimentStatus.EXECUTING, actor="lab_runner", reason="Executing")
    assert exp.status == ExperimentStatus.EXECUTING


def test_experiment_state_machine_illegal_transition():
    exp = ControlledExperiment.create(
        assessment_id="ASM-M11-TEST",
        hypothesis_id="HYP-001",
        authorization_reference="AUTH-REF-M11",
        scope_reference="SCOPE-REF-M11",
        proposed_actions=[],
    )
    # Cannot jump from DRAFT to EXECUTING directly
    with pytest.raises(InvalidStateTransitionError):
        ExperimentStateMachine.transition(exp, ExperimentStatus.EXECUTING, actor="alice", reason="Skipping gates")


def test_poc_validator_benign_allowed():
    poc = SafePoC.create(
        experiment_id="EXP-001",
        title="Safe IDOR Proof of Condition",
        objective="Verify object accessor response on local fixture",
        vulnerability_class=PoCVulnerabilityClass.IDOR,
        actions=[{"type": "http_get", "url": "http://127.0.0.1:8080/user/2"}],
        expected_behavior="HTTP 200 with test canary",
        expected_safe_behavior="HTTP 403 Forbidden",
        canary_marker="CANARY_SAFE_USER_2",
    )
    is_safe, violations = SafePoCValidator.validate_poc(poc)
    assert is_safe is True
    assert len(violations) == 0


def test_poc_validator_destructive_blocked():
    poc = SafePoC.create(
        experiment_id="EXP-002",
        title="Destructive SQL Injection",
        objective="Drop test table",
        vulnerability_class=PoCVulnerabilityClass.SQL_INJECTION,
        actions=[{"type": "command", "command": "rm -rf /var/data && DROP TABLE users"}],
        expected_behavior="Data cleared",
        expected_safe_behavior="Query rejected",
    )
    is_safe, violations = SafePoCValidator.validate_poc(poc)
    assert is_safe is False
    assert any("destructive" in v.lower() for v in violations)


def test_execution_token_creation_and_integrity():
    actions = [{"type": "synthetic_check", "id": 1}]
    token = ExecutionAuthorizationToken.create(
        experiment_id="EXP-001",
        assessment_id="ASM-001",
        target_environment="LOCAL_LAB",
        actions=actions,
        risk_level=ExperimentRiskLevel.LOW,
        approved_by="lead_researcher_bob",
        ttl_seconds=10,
    )
    assert not token.is_expired()
    assert token.verify_action_integrity(actions) is True

    # Mutated actions fail integrity check
    mutated_actions = [{"type": "synthetic_check", "id": 2}]
    assert token.verify_action_integrity(mutated_actions) is False


def test_preflight_risk_classification_and_decisions():
    # Plane A Local Lab benign
    exp = ControlledExperiment.create(
        assessment_id="ASM-M11-TEST",
        hypothesis_id="HYP-001",
        authorization_reference="AUTH-REF-M11",
        scope_reference="SCOPE-REF-M11",
        proposed_actions=[{"type": "synthetic_check"}],
    )
    report = PreflightSafetyEngine.evaluate(exp)
    assert report.decision == PreflightDecision.AWAITING_HUMAN_APPROVAL
    assert report.risk_level == ExperimentRiskLevel.LOW

    # Plane B Authorized Target: Plan Only
    exp_b = ControlledExperiment.create(
        assessment_id="ASM-M11-TEST",
        hypothesis_id="HYP-002",
        target_id="https://target.corp/api",
        execution_plane=ExecutionPlane.PLANE_B_AUTHORIZED_TARGET,
        environment_type=ExperimentEnvironmentType.AUTHORIZED_TARGET,
        authorization_reference="AUTH-REF-M11",
        scope_reference="target.corp",
        proposed_actions=[{"type": "http_request", "url": "https://target.corp/api"}],
    )
    auth_rec = AuthorizationRecord(
        authorization_id="AUTH-001",
        organization="Corp",
        assessment_name="Prod Audit",
        authorized_by="Security Director",
        authorized_at="2026-01-01T00:00:00Z",
        valid_from="2026-01-01T00:00:00Z",
        valid_until="2026-12-31T23:59:59Z",
        authorization_type=AuthorizationType.INTERNAL_SECURITY_ASSESSMENT,
        scope_reference="target.corp",
        status=AuthorizationStatus.AUTHORIZED,
    )
    report_b = PreflightSafetyEngine.evaluate(exp_b, auth_record=auth_rec)
    assert report_b.decision == PreflightDecision.PLAN_ONLY
    assert report_b.risk_level == ExperimentRiskLevel.HIGH


def test_observation_capture_and_tamper_detection():
    exp = ControlledExperiment.create(
        assessment_id="ASM-M11-TEST",
        hypothesis_id="HYP-001",
        authorization_reference="AUTH-REF-M11",
        scope_reference="SCOPE-REF-M11",
        proposed_actions=[],
    )
    exec_res = LabExecutionResult(
        execution_id="EXEC-001",
        experiment_id=exp.experiment_id,
        status=LabExecutionStatus.SUCCESS,
        exit_code=0,
        stdout="Test observed output with CANARY_123",
    )
    obs = ControlledObservationCapture.capture_from_execution(exp, exec_res)
    assert obs.verify_integrity() is True
    assert "CANARY_123" in obs.output
    assert obs.observation_id in exp.observation_ids

    # Tampering with observation payload invalidates integrity
    obs.output = "Tampered output"
    assert obs.verify_integrity() is False


def test_differential_verification_divergence():
    test_obs = ControlledObservation.create(
        experiment_id="EXP-DIFF",
        assessment_id="ASM-DIFF",
        environment="LOCAL_LAB",
        input_reference={},
        output="Status 200 OK Body: CANARY_FOUND",
        http_responses=[{"status_code": 200, "body": "CANARY_FOUND"}],
    )
    control_obs = ControlledObservation.create(
        experiment_id="EXP-DIFF",
        assessment_id="ASM-DIFF",
        environment="LOCAL_LAB",
        input_reference={},
        output="Status 403 Forbidden Access Denied",
        http_responses=[{"status_code": 403, "body": "Denied"}],
    )
    diff = DifferentialVerificationEngine.compare(
        experiment_id="EXP-DIFF",
        test_obs=test_obs,
        control_obs=control_obs,
        expected_behavior="CANARY_FOUND",
        expected_safe_behavior="Denied",
        canary_marker="CANARY_FOUND",
    )
    assert diff.divergence_detected is True
    assert diff.negative_control_passed is True


def test_differential_verification_falsified_when_control_matches():
    # If negative control also reflects canary, hypothesis is refuted
    test_obs = ControlledObservation.create(
        experiment_id="EXP-DIFF-2",
        assessment_id="ASM-DIFF",
        environment="LOCAL_LAB",
        input_reference={},
        output="CANARY_VALUE_XYZ",
    )
    control_obs = ControlledObservation.create(
        experiment_id="EXP-DIFF-2",
        assessment_id="ASM-DIFF",
        environment="LOCAL_LAB",
        input_reference={},
        output="CANARY_VALUE_XYZ in control",
    )
    diff = DifferentialVerificationEngine.compare(
        experiment_id="EXP-DIFF-2",
        test_obs=test_obs,
        control_obs=control_obs,
        expected_behavior="CANARY_VALUE_XYZ",
        expected_safe_behavior="No canary",
        canary_marker="CANARY_VALUE_XYZ",
    )
    assert diff.negative_control_passed is False
    assert "FALSIFIED" in diff.summary


def test_controlled_lab_runner_process_and_cleanup():
    exp = ControlledExperiment.create(
        assessment_id="ASM-M11-TEST",
        hypothesis_id="HYP-001",
        authorization_reference="AUTH-REF-M11",
        scope_reference="SCOPE-REF-M11",
        proposed_actions=[
            {"type": "command", "command": ["cmd", "/c", "echo", "HELLO_ISOLATED_LAB"]}
        ],
    )
    res = ControlledLabRunner.execute_experiment(exp)
    assert res.status == LabExecutionStatus.SUCCESS
    assert res.exit_code == 0
    assert "HELLO_ISOLATED_LAB" in res.stdout
    assert res.cleaned_up is True


def test_rollback_plan_execution():
    plan = RollbackPlan(
        rollback_id="RB-001",
        description="Clean up created state",
        actions=[{"command": ["cmd", "/c", "echo", "ROLLBACK_DONE"]}],
    )
    exp = ControlledExperiment.create(
        assessment_id="ASM-M11-TEST",
        hypothesis_id="HYP-001",
        authorization_reference="AUTH-REF-M11",
        scope_reference="SCOPE-REF-M11",
        proposed_actions=[{"type": "synthetic_check"}],
        rollback_plan=plan,
    )
    res = ControlledLabRunner.execute_experiment(exp)
    assert res.rollback_attempted is True
    assert res.rollback_success is True


def test_experiment_replay_reproducible_and_mismatch():
    exp = ControlledExperiment.create(
        assessment_id="ASM-M11-TEST",
        hypothesis_id="HYP-001",
        authorization_reference="AUTH-REF-M11",
        scope_reference="SCOPE-REF-M11",
        proposed_actions=[{"type": "command", "command": ["cmd", "/c", "echo", "CANARY_REPLAY_123"]}],
    )
    poc = SafePoC.create(
        experiment_id=exp.experiment_id,
        title="Replay PoC",
        objective="Verify repeatability",
        vulnerability_class=PoCVulnerabilityClass.IDOR,
        actions=exp.proposed_actions,
        expected_behavior="Echo canary",
        expected_safe_behavior="None",
        canary_marker="CANARY_REPLAY_123",
    )
    orig_res = ControlledLabRunner.execute_experiment(exp, poc=poc)

    # Identical replay succeeds
    rep_rec = ExperimentReplayEngine.replay_experiment(exp, orig_res, poc=poc)
    assert rep_rec.is_reproducible is True
    assert rep_rec.status == "REPRODUCED"

    # Mismatch detected if original expected different exit code
    mutated_orig = orig_res.model_copy(update={"exit_code": 99})
    mismatch_rec = ExperimentReplayEngine.replay_experiment(exp, mutated_orig, poc=poc)
    assert mismatch_rec.is_reproducible is False
    assert mismatch_rec.status == "REPRODUCTION_MISMATCH"


def test_finding_validation_bridge_flow():
    exp = ControlledExperiment.create(
        assessment_id="ASM-M11-TEST",
        hypothesis_id="HYP-001",
        authorization_reference="AUTH-REF-M11",
        scope_reference="SCOPE-REF-M11",
        proposed_actions=[],
    )
    poc = SafePoC.create(
        experiment_id=exp.experiment_id,
        title="Candidate Finding Title",
        objective="Verify auth condition",
        vulnerability_class=PoCVulnerabilityClass.AUTHENTICATION_BYPASS,
        actions=[],
        expected_behavior="Condition true",
        expected_safe_behavior="Condition false",
    )
    obs = ControlledObservation.create(
        experiment_id=exp.experiment_id,
        assessment_id=exp.assessment_id,
        environment="LOCAL_LAB",
        input_reference={},
        output="Result verified",
    )
    diff = DifferentialVerificationEngine.compare(
        experiment_id=exp.experiment_id,
        test_obs=obs,
        control_obs=None,
        expected_behavior="Condition true",
        expected_safe_behavior="Condition false",
    )
    from src.experiment.falsification import FalsificationReport
    falsif = FalsificationReport(
        experiment_id=exp.experiment_id,
        hypothesis_id=exp.hypothesis_id,
        outcome=FalsificationOutcome.SUPPORTED,
        confidence=0.85,
        differential_result=diff,
    )

    candidate = FindingValidationBridge.create_finding_candidate(exp, poc, obs, falsif)
    assert candidate.epistemic_status == "FINDING_CANDIDATE"

    review_case = FindingValidationBridge.create_review_case(candidate, exp, poc)
    assert review_case.epistemic_status == "HUMAN_REVIEW_PENDING"
    assert review_case.status.value == "PENDING"
