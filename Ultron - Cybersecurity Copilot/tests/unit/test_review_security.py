"""Unit tests for M8 Human Review Security and Validation Controls.

Verifies:
- INV-SEC-03 / INV-M8-01: UI/API/Agent cannot directly promote an unverified finding.
- INV-M8-07: Human verification must be explicit and attributable (non-empty, non-AI).
- FindingValidator is authoritative gatekeeper.
- Audit trail integrity and cryptographic event chaining.
"""

from datetime import datetime, timezone
import pytest

from src.assessment.manager import AssessmentManager
from src.assessment.models import (
    AssessmentRecord,
    AssessmentScopeStatus,
    AssessmentHypothesis,
    AuthorizationRecord,
    AuthorizationStatus,
    AuthorizationType,
    FindingSeverity,
    FindingVerificationStatus,
    ObservationType,
)
from src.review.review_actions import (
    ApproveForValidationRequest,
    ContestRequest,
    RejectRequest,
    RequestEvidenceRequest,
    SubmitVerificationRequest,
)
from src.review.review_models import ReviewCase, ReviewStatus, ReviewTargetType
from src.review.review_service import ReviewService
from src.scope.models import ScopePolicy


@pytest.fixture
def mock_assessment_setup():
    """Sets up an authorized assessment with in-scope asset and observation."""
    mgr = AssessmentManager()
    rec = mgr.create_assessment(
        organization="TargetCorp",
        assessment_name="Q4 Web & API Assessment",
    )
    aid = rec.assessment_id

    auth = AuthorizationRecord(
        authorization_id="AUTH-REV-01",
        organization="TargetCorp",
        assessment_name="Q4 Web & API Assessment",
        authorized_by="Jane Doe, CISO",
        authorized_at="2026-01-01T00:00:00Z",
        valid_from="2026-01-01T00:00:00Z",
        valid_until="2026-12-31T23:59:59Z",
        authorization_type=AuthorizationType.BUG_BOUNTY,
        scope_reference="POLICY-REV-01",
        status=AuthorizationStatus.AUTHORIZED,
    )
    mgr.set_authorization(aid, auth)

    policy = ScopePolicy(
        program_name="TargetCorp",
        platform="HackerOne",
        in_scope=["api.targetcorp.com"],
        out_of_scope=[],
    )
    mgr.set_scope(aid, policy)
    mgr.activate_assessment(aid)

    # Ingest in-scope observation
    har_sample = {
        "log": {"entries": [
            {
                "request": {
                    "url": "https://api.targetcorp.com/api/v1/users/123",
                    "method": "GET",
                    "headers": [{"name": "Authorization", "value": "Bearer testtoken"}],
                },
                "response": {"status": 200, "headers": []},
            },
        ]}
    }
    report = mgr.import_telemetry(aid, "har", har_sample)
    obs = report["new_observations"][0]

    # Propose hypothesis with negative control
    cont = mgr.get_container(aid)
    hyp = AssessmentHypothesis(
        hypothesis_id="HYP-REV-01",
        assessment_id=aid,
        title="BOLA on /api/v1/users/123",
        description="Object ID 123 accessible across sessions.",
        asset_ids=["api.targetcorp.com"],
        domain="API_SECURITY",
        supporting_observations=[obs.observation_id],
        negative_control="User B session must be rejected with 403.",
    )
    cont.review_workspace.load_hypothesis(hyp)

    return mgr, obs, hyp, aid


def test_review_service_create_case_and_status(mock_assessment_setup):
    mgr, obs, hyp, aid = mock_assessment_setup
    svc = ReviewService(mgr)

    case = svc.create_review_case_from_hypothesis(
        assessment_id=aid,
        hypothesis_id=hyp.hypothesis_id,
        reviewer_id="lead_analyst_bob",
    )
    assert case.status == ReviewStatus.IN_REVIEW
    assert case.reviewer_id == "lead_analyst_bob"
    assert case.target_id == hyp.hypothesis_id
    assert obs.observation_id in case.supporting_evidence
    assert case.epistemic_status == "MODEL_HYPOTHESIS"


def test_request_evidence_updates_status(mock_assessment_setup):
    mgr, obs, hyp, aid = mock_assessment_setup
    svc = ReviewService(mgr)
    case = svc.create_review_case_from_hypothesis(aid, hyp.hypothesis_id)

    updated = svc.request_evidence(
        assessment_id=aid,
        review_id=case.review_id,
        req=RequestEvidenceRequest(
            reviewer_id="reviewer_alice",
            notes="Missing negative control verification on tenant 2.",
            missing_gaps=["EVIDENCE_GAP: Tenant 2 session response"],
        ),
    )
    assert updated.status == ReviewStatus.NEEDS_EVIDENCE
    assert "EVIDENCE_GAP: Tenant 2 session response" in updated.evidence_gaps
    assert updated.reviewer_id == "reviewer_alice"


def test_contest_and_reject_actions(mock_assessment_setup):
    mgr, obs, hyp, aid = mock_assessment_setup
    svc = ReviewService(mgr)
    case = svc.create_review_case_from_hypothesis(aid, hyp.hypothesis_id)

    # Contest
    contested = svc.contest(
        assessment_id=aid,
        review_id=case.review_id,
        req=ContestRequest(
            reviewer_id="reviewer_alice",
            reason="Endpoint returns public directory data, not private PII.",
            alternative_explanation="Public profile view intentional by design.",
        ),
    )
    assert contested.status == ReviewStatus.CONTESTED
    assert contested.epistemic_status == "CONTESTED"

    # Reject
    rejected = svc.reject(
        assessment_id=aid,
        review_id=case.review_id,
        req=RejectRequest(
            reviewer_id="reviewer_alice",
            reason="Confirmed benign by design.",
        ),
    )
    assert rejected.status == ReviewStatus.REJECTED


def test_automated_ai_cannot_sign_off_on_verification(mock_assessment_setup):
    """INV-M8-07: Automated entities (LLM, AI, Bot) cannot sign off on findings."""
    mgr, obs, hyp, aid = mock_assessment_setup
    svc = ReviewService(mgr)
    case = svc.create_review_case_from_hypothesis(aid, hyp.hypothesis_id)

    for invalid_reviewer in ["", "   ", "AI_Assistant", "Copilot_LLM", "Auto_Bot", "SYSTEM"]:
        ok, finding, errs = svc.submit_human_verification(
            assessment_id=aid,
            review_id=case.review_id,
            req=SubmitVerificationRequest(
                reviewer_id=invalid_reviewer,
                reviewer_notes="Approving vulnerability automatically.",
            ),
        )
        assert ok is False
        assert finding is None
        assert any("CHECK_12_FAILED" in e for e in errs)


def test_human_verification_fails_closed_if_finding_validator_fails(mock_assessment_setup):
    """INV-M8-01: UI/API cannot bypass FindingValidator; validation failure blocks promotion."""
    mgr, obs, hyp, aid = mock_assessment_setup
    svc = ReviewService(mgr)

    # Inject critical evidence gap into hypothesis
    hyp.evidence_gaps.append("CRITICAL: Negative control completely missing")

    case = svc.create_review_case_from_hypothesis(aid, hyp.hypothesis_id)
    svc.approve_for_validation(
        assessment_id=aid,
        review_id=case.review_id,
        req=ApproveForValidationRequest(reviewer_id="human_sec_analyst"),
    )

    # Human attempts to verify, but FindingValidator Check 13 will reject due to CRITICAL gap
    ok, finding, errs = svc.submit_human_verification(
        assessment_id=aid,
        review_id=case.review_id,
        req=SubmitVerificationRequest(
            reviewer_id="human_sec_analyst",
            reviewer_notes="Attempting sign-off despite unresolved critical gap.",
        ),
    )
    assert ok is False
    assert finding is None
    assert any("CHECK_13_FAILED" in e for e in errs)
    # Verify no finding was recorded in container
    cont = mgr.get_container(aid)
    assert len(cont.findings) == 0


def test_human_verification_succeeds_when_all_checks_satisfied(mock_assessment_setup):
    """When human verifier approves and FindingValidator 13-point checklist passes, finding is promoted."""
    mgr, obs, hyp, aid = mock_assessment_setup
    svc = ReviewService(mgr)

    case = svc.create_review_case_from_hypothesis(aid, hyp.hypothesis_id)

    ok, finding, errs = svc.submit_human_verification(
        assessment_id=aid,
        review_id=case.review_id,
        req=SubmitVerificationRequest(
            reviewer_id="human_sec_analyst_alice",
            reviewer_notes="Manually executed negative control; confirmed BOLA.",
            evidence_references=[obs.observation_id],
        ),
    )
    assert ok is True
    assert finding is not None
    assert errs == []
    assert finding.verification_status == FindingVerificationStatus.HUMAN_VERIFIED
    assert finding.verified_by == "human_sec_analyst_alice"
    cont = mgr.get_container(aid)
    assert len(cont.findings) == 1

    # Check review case epistemic status updated
    updated_case = svc.get_case(aid, case.review_id)
    assert updated_case.epistemic_status == "HUMAN_VERIFIED_FINDING"


def test_review_workspace_view_and_audit_integrity(mock_assessment_setup):
    mgr, obs, hyp, aid = mock_assessment_setup
    svc = ReviewService(mgr)

    case = svc.create_review_case_from_hypothesis(aid, hyp.hypothesis_id)
    svc.request_evidence(
        aid,
        case.review_id,
        RequestEvidenceRequest(reviewer_id="bob", notes="Check TLS cipher", missing_gaps=["TLS_CIPHER"]),
    )

    view = svc.get_review_workspace_view(aid, case.review_id)
    assert "review_case" in view
    assert "epistemic_badge" in view
    assert view["epistemic_badge"]["status"] == "MODEL_HYPOTHESIS"
    assert view["target_and_scope"]["is_in_scope"] is True
    assert len(view["evidence_items"]) >= 1
    assert view["audit_integrity"] is True
    assert len(view["audit_trail"]) >= 2
