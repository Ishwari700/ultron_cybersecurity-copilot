"""Unit tests for M6 Experiments, 13-Point Finding Validator, and Reporting."""

from datetime import datetime, timezone, timedelta
import pytest

from src.assessment.models import (
    AssessmentFinding,
    AssessmentHypothesis,
    AssessmentLifecycleState,
    AssessmentRecord,
    AssessmentScopeStatus,
    AuthorizationRecord,
    AuthorizationStatus,
    AuthorizationType,
    CanonicalObservation,
    ExperimentRiskLevel,
    ExperimentStatus,
    FindingSeverity,
    FindingVerificationStatus,
    ObservationType,
)
from src.assessment.experiments import SafeExperimentEngine
from src.assessment.validation import FindingValidator, FindingValidationError, AssessmentValidationContext
from src.assessment.reporting import AssessmentReportGenerator, AssessmentReportContext
from src.scope.gate import ScopeGate
from src.scope.models import ScopePolicy


def _build_test_context():
    now = datetime.now(timezone.utc)
    rec = AssessmentRecord(
        assessment_id="ASM-VAL-01",
        organization="FinSec",
        assessment_name="Q4_Pentest",
        state=AssessmentLifecycleState.ASSESSMENT_ACTIVE,
    )
    auth = AuthorizationRecord(
        authorization_id="AUTH-VAL-01",
        organization="FinSec",
        assessment_name="Q4_Pentest",
        authorized_by="Lead_Auditor",
        authorized_at=now.isoformat(),
        valid_from=(now - timedelta(days=1)).isoformat(),
        valid_until=(now + timedelta(days=1)).isoformat(),
        authorization_type=AuthorizationType.PENETRATION_TEST,
        scope_reference="SCOPE-VAL-01",
        status=AuthorizationStatus.AUTHORIZED,
    )
    gate = ScopeGate(
        policy=ScopePolicy(program_name="TestScope", platform="LOCAL", in_scope=["api.finsec.com"]),
        allow_private_ranges=True,
    )
    obs = CanonicalObservation.create(
        assessment_id=rec.assessment_id,
        asset_id="ASSET-api.finsec.com",
        observation_type=ObservationType.HTTP_RESPONSE,
        source="TEST_HAR",
        normalized_data={"target_identifier": "api.finsec.com", "status_code": 200, "url": "https://api.finsec.com/accounts/123"},
        scope_decision=AssessmentScopeStatus.IN_SCOPE,
        scope_rule="api.finsec.com",
    )
    hyp = AssessmentHypothesis(
        hypothesis_id="HYP-VAL-01",
        assessment_id=rec.assessment_id,
        title="BOLA on accounts endpoint",
        description="User A can access User B account",
        domain="API_SECURITY",
        supporting_observations=[obs.observation_id],
        negative_control="Verify User A accessing User A returns 200, but User B without auth returns 401.",
    )
    ctx = AssessmentValidationContext(
        assessment=rec,
        authorization=auth,
        scope_gate=gate,
        observations={obs.observation_id: obs},
        hypotheses={hyp.hypothesis_id: hyp},
    )
    return ctx, obs, hyp


def test_safe_experiment_engine_defaults():
    """Verify experiments default strictly to human execution and non-destructive."""
    gate = ScopeGate(
        policy=ScopePolicy(program_name="ExpTest", platform="LOCAL", in_scope=["api.finsec.com"]),
        allow_private_ranges=True,
    )
    ctx, _, hyp = _build_test_context()
    engine = SafeExperimentEngine("ASM-VAL-01", gate)

    exp = engine.propose_experiment(
        hypothesis_id=hyp.hypothesis_id,
        objective="Verify differential status code on cross-account fetch",
        target_asset="api.finsec.com",
        authorization=ctx.authorization,
        steps=["Step 1", "Step 2"],
        expected_secure_result="HTTP 403 Forbidden",
        expected_vulnerable_result="HTTP 200 OK with account details",
        falsification_condition="Server enforces object owner check",
        negative_control="Same-user request succeeds",
    )

    assert exp.requires_human_execution is True
    assert exp.destructive_potential is False
    assert exp.risk_level == ExperimentRiskLevel.PASSIVE
    assert exp.status == ExperimentStatus.PROPOSED


def test_command_generation_safety():
    """Verify generated command contains authorization and scope annotations."""
    gate = ScopeGate(
        policy=ScopePolicy(program_name="CmdTest", platform="LOCAL", in_scope=["api.finsec.com"]),
        allow_private_ranges=True,
    )
    ctx, _, _ = _build_test_context()
    engine = SafeExperimentEngine("ASM-VAL-01", gate)

    cmd_dict = engine.generate_safe_command_suggestion("curl", "https://api.finsec.com/test", ctx.authorization)
    assert "curl" in cmd_dict["suggested_command"]
    assert "AuthorizedSecurityAssessment" in cmd_dict["suggested_command"]
    assert cmd_dict["execution_mode"] == "HUMAN_OPERATED_ONLY"


def test_13_point_finding_validator_full_pass():
    """Verify finding passes all 13 checks when fully grounded and human-verified."""
    ctx, obs, hyp = _build_test_context()

    finding = AssessmentFinding(
        finding_id="FIND-PASS-01",
        assessment_id=ctx.assessment.assessment_id,
        title="Confirmed BOLA on /accounts/{id}",
        severity=FindingSeverity.HIGH,
        asset="api.finsec.com",
        affected_component="/accounts/{id}",
        description="ID substitution allows unauthorized data retrieval",
        impact="Cross-user privacy breach",
        evidence=[obs.observation_id],
        reproduction_reference="EXP-TEST-01",
        security_invariant="INV-BOLA-01",
        root_cause="Missing authorization check in account handler",
        remediation="Enforce current_user.id == account.owner_id",
        verification_status=FindingVerificationStatus.HUMAN_VERIFIED,
        verified_by="Lead_Security_Researcher",
        verified_at=datetime.now(timezone.utc).isoformat(),
    )

    is_valid, failures = FindingValidator.validate_finding(finding, ctx)
    assert is_valid is True
    assert len(failures) == 0


def test_13_point_finding_validator_rejects_unverified():
    """Verify validator rejects finding if not HUMAN_VERIFIED."""
    ctx, obs, _ = _build_test_context()

    finding = AssessmentFinding(
        finding_id="FIND-FAIL-01",
        assessment_id=ctx.assessment.assessment_id,
        title="Unverified finding",
        severity=FindingSeverity.HIGH,
        asset="api.finsec.com",
        affected_component="/accounts",
        description="Test",
        impact="Test",
        evidence=[obs.observation_id],
        reproduction_reference="EXP-01",
        security_invariant="INV-BOLA-01",
        root_cause="Test",
        remediation="Test",
        verification_status=FindingVerificationStatus.UNVERIFIED,
    )

    is_valid, failures = FindingValidator.validate_finding(finding, ctx)
    assert is_valid is False
    assert any("CHECK_12_FAILED" in f for f in failures)


def test_13_point_finding_validator_rejects_out_of_scope_asset():
    """Verify validator rejects finding if asset is out of scope."""
    ctx, obs, _ = _build_test_context()

    finding = AssessmentFinding(
        finding_id="FIND-OOS-01",
        assessment_id=ctx.assessment.assessment_id,
        title="Out of scope finding",
        severity=FindingSeverity.HIGH,
        asset="out-of-scope-external.org",
        affected_component="/api",
        description="Test",
        impact="Test",
        evidence=[obs.observation_id],
        reproduction_reference="EXP-01",
        security_invariant="INV-01",
        root_cause="Test",
        remediation="Test",
        verification_status=FindingVerificationStatus.HUMAN_VERIFIED,
        verified_by="Researcher",
    )

    is_valid, failures = FindingValidator.validate_finding(finding, ctx)
    assert is_valid is False
    assert any("CHECK_4_FAILED" in f for f in failures)
