"""Unit tests for M8 Reporting Engine Security, Epistemic Segregation, and Attestation.

Verifies:
- INV-M8-06: Report generator cannot represent unverified findings as verified findings.
- INV-M8-08: Report export must preserve epistemic status.
- SARIF export only includes verified findings in runs.results.
- PDF generation produces valid binary %PDF-1.4 header.
- Deterministic report attestation SHA-256 hash.
- Bug bounty draft includes mandatory draft review banner.
"""

import json
import pytest

from src.assessment.manager import AssessmentManager
from src.assessment.models import (
    AssessmentFinding,
    AssessmentHypothesis,
    AuthorizationRecord,
    AuthorizationStatus,
    AuthorizationType,
    FindingSeverity,
    FindingVerificationStatus,
    ObservationType,
)
from src.reporting.asvs import AsvsReportRenderer
from src.reporting.bug_bounty import BugBountyDraftRenderer
from src.reporting.builder import ReportDataBuilder
from src.reporting.html import HtmlReportRenderer
from src.reporting.markdown import MarkdownReportRenderer
from src.reporting.pdf import PdfReportRenderer
from src.reporting.sarif import SarifReportRenderer
from src.scope.models import ScopePolicy


@pytest.fixture
def mock_assessment_with_findings():
    """Sets up an assessment with 1 verified finding and 1 unverified hypothesis."""
    mgr = AssessmentManager()
    rec = mgr.create_assessment(
        organization="TargetCorp",
        assessment_name="Q4 Comprehensive Assessment",
    )
    aid = rec.assessment_id

    auth = AuthorizationRecord(
        authorization_id="AUTH-REP-01",
        organization="TargetCorp",
        assessment_name="Q4 Comprehensive Assessment",
        authorized_by="Jane Doe, CISO",
        authorized_at="2026-01-01T00:00:00Z",
        valid_from="2026-01-01T00:00:00Z",
        valid_until="2026-12-31T23:59:59Z",
        authorization_type=AuthorizationType.PENETRATION_TEST,
        scope_reference="POLICY-REP-01",
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

    cont = mgr.get_container(aid)

    # 1. Add verified finding
    finding_verified = AssessmentFinding(
        finding_id="FIND-V-001",
        assessment_id=aid,
        title="Broken Object Level Authorization on /accounts",
        severity=FindingSeverity.HIGH,
        asset="api.targetcorp.com",
        affected_component="/api/v1/accounts/{id}",
        description="Users can read accounts belonging to other tenants.",
        impact="Complete confidentiality breach of financial statements.",
        evidence=["OBS-1111", "OBS-2222"],
        reproduction_reference="GET /api/v1/accounts/1002 with token 1001",
        security_invariant="INV-BOLA-01",
        root_cause="Missing authorization check in account handler.",
        remediation="Enforce tenant check before querying account statement.",
        verification_status=FindingVerificationStatus.HUMAN_VERIFIED,
        verified_by="security_analyst_alice",
        verified_at="2026-10-07T12:00:00Z",
    )
    mgr.register_candidate_finding(aid, finding_verified)

    # 2. Add unverified hypothesis (must remain segregated!)
    hyp_unverified = AssessmentHypothesis(
        hypothesis_id="HYP-U-001",
        assessment_id=aid,
        title="Potential Rate Limiting Bypass on Login",
        description="High volume requests were observed without HTTP 429.",
        asset_ids=["api.targetcorp.com"],
        domain="WEB_API",
        supporting_observations=["OBS-3333"],
        negative_control="100 requests per minute should trigger 429.",
    )
    cont.review_workspace.load_hypothesis(hyp_unverified)

    return mgr, aid


def test_report_builder_segregates_verified_and_unverified(mock_assessment_with_findings):
    mgr, aid = mock_assessment_with_findings
    data = ReportDataBuilder.build_report_data(mgr, aid, is_draft=True)

    # INV-M8-06: Verified findings must only contain HUMAN_VERIFIED items
    assert len(data.verified_findings) == 1
    assert data.verified_findings[0].finding_id == "FIND-V-001"
    assert data.verified_findings[0].epistemic_status == "HUMAN_VERIFIED_FINDING"

    # Unverified items are strictly segregated into unverified_hypotheses
    assert len(data.unverified_hypotheses) == 1
    assert data.unverified_hypotheses[0]["hypothesis_id"] == "HYP-U-001"
    assert data.unverified_hypotheses[0]["epistemic_status"] == "MODEL_HYPOTHESIS"

    # Attestation hash is populated
    assert data.attestation is not None
    assert len(data.attestation.sha256_hash) == 64


def test_markdown_and_html_renderers(mock_assessment_with_findings):
    mgr, aid = mock_assessment_with_findings
    data = ReportDataBuilder.build_report_data(mgr, aid, is_draft=True)

    md = MarkdownReportRenderer.render(data)
    assert "# Security Assessment Report" in md
    assert "[DRAFT — HUMAN REVIEW REQUIRED]" in md
    assert "FIND-V-001" in md
    assert "Unverified Hypotheses & Open Inquiries" in md
    assert "HYP-U-001" in md

    html_out = HtmlReportRenderer.render(data)
    assert "<!DOCTYPE html>" in html_out
    assert "FIND-V-001" in html_out
    assert "badge-verified" in html_out
    assert "MODEL_HYPOTHESIS" in html_out


def test_pdf_renderer_produces_valid_pdf_binary(mock_assessment_with_findings):
    mgr, aid = mock_assessment_with_findings
    data = ReportDataBuilder.build_report_data(mgr, aid, is_draft=False)

    pdf_bytes = PdfReportRenderer.render_bytes(data)
    assert isinstance(pdf_bytes, bytes)
    assert pdf_bytes.startswith(b"%PDF-1.4")
    assert b"%%EOF" in pdf_bytes
    assert b"FIND-V-001" in pdf_bytes


def test_sarif_renderer_excludes_unverified_hypotheses(mock_assessment_with_findings):
    """INV-M8-06: SARIF runs.results contains ONLY verified findings."""
    mgr, aid = mock_assessment_with_findings
    data = ReportDataBuilder.build_report_data(mgr, aid, is_draft=False)

    sarif = SarifReportRenderer.render(data)
    assert sarif["version"] == "2.1.0"
    results = sarif["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["properties"]["finding_id"] == "FIND-V-001"
    assert results[0]["properties"]["epistemic_status"] == "HUMAN_VERIFIED_FINDING"

    # Ensure unverified hypothesis is NOT in results
    result_finding_ids = [r["properties"]["finding_id"] for r in results]
    assert "HYP-U-001" not in result_finding_ids


def test_asvs_mapping_and_bug_bounty_draft(mock_assessment_with_findings):
    mgr, aid = mock_assessment_with_findings
    data = ReportDataBuilder.build_report_data(mgr, aid, is_draft=True)

    # ASVS mapping
    asvs = AsvsReportRenderer.render_mapping(data)
    assert asvs["asvs_version"] == "4.0.3"
    assert asvs["asvs_categories_covered"] >= 1

    # Bug bounty draft
    bb_draft = BugBountyDraftRenderer.render_report_drafts(data)
    assert "DRAFT — HUMAN REVIEW REQUIRED BEFORE SUBMISSION" in bb_draft
    assert "Broken Object Level Authorization" in bb_draft
    assert "Steps to Reproduce" in bb_draft
