"""Unit tests for M6 Assessment Lifecycle State Machine."""

from datetime import datetime, timezone, timedelta
import pytest

from src.assessment.models import (
    AssessmentLifecycleState,
    AssessmentRecord,
    AuthorizationRecord,
    AuthorizationStatus,
    AuthorizationType,
)
from src.assessment.lifecycle import AssessmentLifecycleEngine


def _make_auth(valid: bool = True) -> AuthorizationRecord:
    now = datetime.now(timezone.utc)
    v_from = (now - timedelta(days=1)).isoformat()
    v_until = (now + timedelta(days=1)).isoformat() if valid else (now - timedelta(hours=1)).isoformat()
    return AuthorizationRecord(
        authorization_id="AUTH-LC-01",
        organization="TestOrg",
        assessment_name="LifecycleTest",
        authorized_by="Lead",
        authorized_at=now.isoformat(),
        valid_from=v_from,
        valid_until=v_until,
        authorization_type=AuthorizationType.INTERNAL_SECURITY_ASSESSMENT,
        scope_reference="SCOPE-LC",
        status=AuthorizationStatus.AUTHORIZED if valid else AuthorizationStatus.EXPIRED,
    )


def test_lifecycle_normal_progression():
    """Verify standard happy-path progression through lifecycle states."""
    rec = AssessmentRecord(
        assessment_id="ASM-LC-01",
        organization="TestOrg",
        assessment_name="LifecycleProgression",
        state=AssessmentLifecycleState.DRAFT,
    )
    auth = _make_auth(valid=True)

    # DRAFT -> AUTHORIZATION_PENDING
    rec = AssessmentLifecycleEngine.transition(rec, AssessmentLifecycleState.AUTHORIZATION_PENDING, "HUMAN_OP", "Submitted for auth")
    assert rec.state == AssessmentLifecycleState.AUTHORIZATION_PENDING

    # AUTHORIZATION_PENDING -> AUTHORIZED
    rec = AssessmentLifecycleEngine.transition(rec, AssessmentLifecycleState.AUTHORIZED, "HUMAN_OP", "Auth approved", authorization=auth)
    assert rec.state == AssessmentLifecycleState.AUTHORIZED

    # AUTHORIZED -> SCOPE_DEFINED
    rec = AssessmentLifecycleEngine.transition(rec, AssessmentLifecycleState.SCOPE_DEFINED, "HUMAN_OP", "Scope set", authorization=auth, scope_defined=True)
    assert rec.state == AssessmentLifecycleState.SCOPE_DEFINED

    # SCOPE_DEFINED -> ASSESSMENT_ACTIVE
    rec = AssessmentLifecycleEngine.transition(rec, AssessmentLifecycleState.ASSESSMENT_ACTIVE, "HUMAN_OP", "Active testing begun", authorization=auth, scope_defined=True)
    assert rec.state == AssessmentLifecycleState.ASSESSMENT_ACTIVE

    # ASSESSMENT_ACTIVE -> VALIDATION_PENDING
    rec = AssessmentLifecycleEngine.transition(rec, AssessmentLifecycleState.VALIDATION_PENDING, "HUMAN_OP", "Awaiting human experiment validation")
    assert rec.state == AssessmentLifecycleState.VALIDATION_PENDING

    # VALIDATION_PENDING -> HUMAN_REVIEW
    rec = AssessmentLifecycleEngine.transition(rec, AssessmentLifecycleState.HUMAN_REVIEW, "HUMAN_OP", "Under researcher review")
    assert rec.state == AssessmentLifecycleState.HUMAN_REVIEW

    # HUMAN_REVIEW -> COMPLETED
    rec = AssessmentLifecycleEngine.transition(rec, AssessmentLifecycleState.COMPLETED, "HUMAN_OP", "Engagement finished")
    assert rec.state == AssessmentLifecycleState.COMPLETED

    # COMPLETED -> ARCHIVED
    rec = AssessmentLifecycleEngine.transition(rec, AssessmentLifecycleState.ARCHIVED, "HUMAN_OP", "Assessment archived")
    assert rec.state == AssessmentLifecycleState.ARCHIVED


def test_illegal_transition_blocked():
    """Verify illegal jumps in the state DAG raise ValueError."""
    rec = AssessmentRecord(
        assessment_id="ASM-LC-02",
        organization="TestOrg",
        assessment_name="IllegalTransition",
        state=AssessmentLifecycleState.DRAFT,
    )
    with pytest.raises(ValueError) as exc:
        AssessmentLifecycleEngine.transition(rec, AssessmentLifecycleState.ASSESSMENT_ACTIVE, "HUMAN_OP", "Skip ahead")
    assert "ILLEGAL_LIFECYCLE_TRANSITION" in str(exc.value)


def test_automated_ai_actor_blocked_from_transitioning():
    """Verify AI models or LLM copilot actors cannot trigger lifecycle transitions."""
    rec = AssessmentRecord(
        assessment_id="ASM-LC-03",
        organization="TestOrg",
        assessment_name="BotTransition",
        state=AssessmentLifecycleState.DRAFT,
    )
    with pytest.raises(PermissionError) as exc:
        AssessmentLifecycleEngine.transition(rec, AssessmentLifecycleState.AUTHORIZED, "COPILOT_LLM_AGENT", "Self-authorize")
    assert "LIFECYCLE_GUARD_VIOLATION" in str(exc.value)


def test_expired_authorization_blocks_activation():
    """Verify assessment cannot become active with expired authorization."""
    rec = AssessmentRecord(
        assessment_id="ASM-LC-04",
        organization="TestOrg",
        assessment_name="ExpiredActivation",
        state=AssessmentLifecycleState.SCOPE_DEFINED,
    )
    bad_auth = _make_auth(valid=False)
    with pytest.raises(ValueError) as exc:
        AssessmentLifecycleEngine.transition(
            rec,
            AssessmentLifecycleState.ASSESSMENT_ACTIVE,
            "HUMAN_OP",
            "Try to activate with expired auth",
            authorization=bad_auth,
            scope_defined=True,
        )
    assert "PRECONDITION_FAILED" in str(exc.value)
