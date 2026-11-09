"""Integration Tests for Milestone M11 Pipeline:
End-to-End Hypothesis → Safe PoC → Preflight → Human Approval → Lab Execution → Observation → Negative Control → Falsification → FindingCandidate → ReviewCase → FindingValidator.
"""

import pytest
from src.experiment.models import (
    ControlledExperiment,
    ExecutionPlane,
    ExperimentEnvironmentType,
    ExperimentRiskLevel,
    ExperimentStatus,
    FalsificationOutcome,
    RollbackPlan,
)
from src.experiment.state_machine import ExperimentStateMachine
from src.experiment.poc import (
    PoCVulnerabilityClass,
    SafePoC,
)
from src.experiment.preflight import (
    PreflightDecision,
    PreflightSafetyEngine,
)
from src.experiment.approval import HumanApprovalGate
from src.experiment.lab_runner import (
    ControlledLabRunner,
    LabExecutionStatus,
)
from src.experiment.observation import (
    ControlledObservation,
    ControlledObservationCapture,
)
from src.experiment.falsification import (
    DifferentialVerificationEngine,
)
from src.experiment.validator_bridge import (
    FindingValidationBridge,
)
from src.audit.ledger import AuditLedger
from src.assessment.models import (
    AssessmentFinding,
    AssessmentHypothesis,
    AssessmentRecord,
    AssessmentScopeStatus,
    AuthorizationRecord,
    AuthorizationStatus,
    AuthorizationType,
    FindingSeverity,
    FindingVerificationStatus,
)
from src.assessment.validation import (
    AssessmentValidationContext,
    FindingValidator,
)


def test_m11_end_to_end_local_lab_pipeline():
    # 1. Setup Audit Ledger & Assessment
    ledger = AuditLedger("ASM-M11-E2E")

    # 2. Researcher develops Hypothesis and proposes Controlled Experiment
    hyp_id = "HYP-IDOR-E2E"
    exp = ControlledExperiment.create(
        assessment_id="ASM-M11-E2E",
        hypothesis_id=hyp_id,
        authorization_reference="AUTH-LAB-LOCAL",
        scope_reference="127.0.0.1",
        proposed_actions=[
            {"type": "command", "command": ["cmd", "/c", "echo", "CANARY_E2E_USER2"]}
        ],
    )
    ExperimentStateMachine.transition(exp, ExperimentStatus.PROPOSED, actor="researcher_carol", reason="Proposed test")

    # 3. Design Safe PoC (Proof of Condition over Full Exploitation)
    poc = SafePoC.create(
        experiment_id=exp.experiment_id,
        title="Safe Verification of User 2 Data Reflection",
        objective="Verify whether mock service reflects user 2 canary",
        vulnerability_class=PoCVulnerabilityClass.IDOR,
        actions=exp.proposed_actions,
        expected_behavior="Echoes CANARY_E2E_USER2",
        expected_safe_behavior="Access denied",
        canary_marker="CANARY_E2E_USER2",
    )

    # 4. Preflight Safety Engine
    ExperimentStateMachine.transition(exp, ExperimentStatus.PREFLIGHT, actor="preflight_engine", reason="Running preflight")
    report = PreflightSafetyEngine.evaluate(exp, poc=poc)
    assert report.decision == PreflightDecision.AWAITING_HUMAN_APPROVAL
    assert report.risk_level == ExperimentRiskLevel.LOW
    assert len(report.violations) == 0

    ExperimentStateMachine.transition(exp, ExperimentStatus.AWAITING_HUMAN_APPROVAL, actor="preflight_engine", reason="Preflight passed")

    # 5. Human Approval Gate
    token = HumanApprovalGate.submit_human_approval(
        exp,
        approver_identity="senior_analyst_dan",
        comments="Approved for isolated local lab test",
        audit_ledger=ledger,
    )
    assert exp.status == ExperimentStatus.READY
    assert token.is_expired() is False

    # 6. Controlled Lab Execution (Plane A)
    exec_result = ControlledLabRunner.execute_experiment(exp, poc=poc, token=token)
    assert exec_result.status == LabExecutionStatus.SUCCESS
    assert exec_result.cleaned_up is True

    # 7. Observation Capture (tamper-evident hash)
    obs = ControlledObservationCapture.capture_from_execution(exp, exec_result, poc=poc, audit_ledger=ledger)
    assert exp.status == ExperimentStatus.OBSERVATIONS_CAPTURED
    assert "CANARY_E2E_USER2" in obs.output

    # 8. Negative Control & Differential Falsification
    control_obs = ControlledObservation.create(
        experiment_id=exp.experiment_id,
        assessment_id=exp.assessment_id,
        environment="LOCAL_LAB",
        input_reference={"role": "unauthenticated"},
        output="Access Denied: 403 Forbidden",
    )
    falsif = DifferentialVerificationEngine.evaluate_falsification(
        experiment=exp,
        test_obs=obs,
        control_obs=control_obs,
        poc=poc,
        audit_ledger=ledger,
    )
    assert falsif.outcome == FalsificationOutcome.SUPPORTED
    assert falsif.differential_result.negative_control_passed is True
    assert exp.status == ExperimentStatus.REVIEW

    # 9. Finding Candidate Generation
    candidate = FindingValidationBridge.create_finding_candidate(exp, poc, obs, falsif)
    assert candidate.epistemic_status == "FINDING_CANDIDATE"

    # 10. ReviewCase Submission
    review_case = FindingValidationBridge.create_review_case(candidate, exp, poc)
    assert review_case.status.value == "PENDING"
    assert review_case.epistemic_status == "HUMAN_REVIEW_PENDING"

    # 11. Authoritative 13-Point FindingValidator Integration
    # Create canonical CanonicalObservation
    can_obs = ControlledObservationCapture.to_canonical_observation(obs, asset_id="127.0.0.1")

    finding = AssessmentFinding(
        finding_id="FIND-M11-E2E",
        assessment_id="ASM-M11-E2E",
        title="IDOR in User Object Accessor",
        severity=FindingSeverity.MEDIUM,
        asset="127.0.0.1",
        affected_component="User Profile API",
        description="Observed canary differential in isolated lab",
        impact="Unauthorized object data disclosure",
        evidence=[can_obs.observation_id],
        reproduction_reference=exp.experiment_id,
        security_invariant="AUTHORIZATION_BOLA",
        root_cause="Missing object ownership verification",
        remediation="Implement tenant-scoped access control",
        references=["CWE-639"],
        verification_status=FindingVerificationStatus.HUMAN_VERIFIED,
        verified_by="human_auditor_eve",
        verified_at="2026-01-01T00:00:00Z",
    )

    auth_record = AuthorizationRecord(
        authorization_id="AUTH-LAB-LOCAL",
        organization="Lab Corp",
        assessment_name="Lab Test",
        authorized_by="Lead Director",
        authorized_at="2026-01-01T00:00:00Z",
        valid_from="2026-01-01T00:00:00Z",
        valid_until="2026-12-31T23:59:59Z",
        authorization_type=AuthorizationType.INTERNAL_SECURITY_ASSESSMENT,
        scope_reference="127.0.0.1",
        status=AuthorizationStatus.AUTHORIZED,
    )

    assessment_record = AssessmentRecord(
        assessment_id="ASM-M11-E2E",
        organization="Lab Corp",
        assessment_name="Lab Test",
        authorization_id="AUTH-LAB-LOCAL",
    )

    hyp_record = AssessmentHypothesis(
        hypothesis_id=hyp_id,
        assessment_id="ASM-M11-E2E",
        title="IDOR in user endpoint",
        description="Object access without verification",
        domain="API",
        supporting_observations=[can_obs.observation_id],
        negative_control="Differential baseline with unauthenticated request",
    )

    ctx = AssessmentValidationContext(
        assessment=assessment_record,
        authorization=auth_record,
        scope_gate=None,
        observations={can_obs.observation_id: can_obs},
        hypotheses={hyp_id: hyp_record},
    )

    is_valid, failures = FindingValidationBridge.validate_with_authoritative_validator(finding, ctx)
    assert is_valid is True
    assert len(failures) == 0


def test_m11_plane_b_target_plan_only_enforced():
    exp_b = ControlledExperiment.create(
        assessment_id="ASM-PROD-TARGET",
        hypothesis_id="HYP-PROD-01",
        target_id="https://authorized.target.com/api",
        execution_plane=ExecutionPlane.PLANE_B_AUTHORIZED_TARGET,
        environment_type=ExperimentEnvironmentType.AUTHORIZED_TARGET,
        authorization_reference="AUTH-PROD",
        scope_reference="authorized.target.com",
        proposed_actions=[{"type": "http_request", "url": "https://authorized.target.com/api"}],
    )
    auth_rec = AuthorizationRecord(
        authorization_id="AUTH-PROD",
        organization="Prod Corp",
        assessment_name="Prod Bounty",
        authorized_by="CISO",
        authorized_at="2026-01-01T00:00:00Z",
        valid_from="2026-01-01T00:00:00Z",
        valid_until="2026-12-31T23:59:59Z",
        authorization_type=AuthorizationType.BUG_BOUNTY,
        scope_reference="authorized.target.com",
        status=AuthorizationStatus.AUTHORIZED,
    )
    report = PreflightSafetyEngine.evaluate(exp_b, auth_record=auth_rec)
    # MUST be PLAN_ONLY; autonomous execution is strictly forbidden
    assert report.decision == PreflightDecision.PLAN_ONLY

    # Runner immediately aborts if an attempt is made to execute Plane B autonomously
    exec_res = ControlledLabRunner.execute_experiment(exp_b)
    assert exec_res.status == LabExecutionStatus.ABORTED
    assert "Plane B" in exec_res.stderr
