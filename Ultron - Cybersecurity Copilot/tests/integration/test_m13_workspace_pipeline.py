"""End-to-End Integration Test Suite for M13 Full Security Assessment Workspace.

Verifies the complete unified workspace lifecycle:
1. Assessment creation & initialization
2. Authorization & ScopeGate policy binding
3. Scope validation (allowed, denied, fail-closed)
4. Assessment activation
5. Asset inventory management
6. Artifact registry integration with SHA-256 integrity
7. Telemetry ingestion & canonical observation extraction
8. Attack surface mapping & specialized analytical agents
9. Hypothesis generation with evidence gap identification
10. Controlled reproduction experiments (Plane A & Plane B)
11. 13-point finding validation checklist & human verification
12. Comprehensive report export with unverified quarantine
13. View state persistence & navigation across all 12 sections
14. Real-time workspace search & audit activity timeline
15. Multi-tenant and cross-assessment isolation
"""

from datetime import datetime, timezone, timedelta
import hashlib
import pytest

from src.assessment.manager import AssessmentManager
from src.assessment.models import (
    AssessmentLifecycleState,
    AssessmentScopeStatus,
    AssetType,
    AuthorizationRecord,
    AuthorizationStatus,
    AuthorizationType,
    FindingSeverity,
    FindingVerificationStatus,
    AssessmentFinding,
    ExperimentStatus,
)
from src.assessment.validation import AssessmentValidationContext
from src.artifacts.metadata import ArtifactType
from src.scope.models import ScopePolicy
from src.workspace.models import (
    AssessmentSection,
    WorkspaceViewState,
)
from src.workspace.service import UnifiedWorkspaceService


@pytest.fixture
def workspace_stack():
    """Provides fresh instances of AssessmentManager and UnifiedWorkspaceService."""
    mgr = AssessmentManager()
    svc = UnifiedWorkspaceService(assessment_manager=mgr)
    return mgr, svc


def test_m13_workspace_end_to_end_lifecycle(workspace_stack):
    """Exercises the complete end-to-end M13 workspace lifecycle."""
    mgr, svc = workspace_stack
    now = datetime.now(timezone.utc)

    # 1. Assessment Creation
    rec = mgr.create_assessment("ApexSecurity", "Q1-Workspace-Assessment", created_by="CHIEF_AUDITOR")
    assert rec.assessment_id.startswith("ASM-")
    assert rec.state == AssessmentLifecycleState.DRAFT
    assert rec.created_by == "CHIEF_AUDITOR"

    # Verify summary listing in workspace service
    summaries = svc.list_assessment_summaries()
    assert len(summaries) >= 1
    target_summary = next(s for s in summaries if s.assessment_id == rec.assessment_id)
    assert target_summary.organization == "ApexSecurity"
    assert target_summary.state == AssessmentLifecycleState.DRAFT

    # 2. Authorization Record Binding
    auth = AuthorizationRecord(
        authorization_id=f"AUTH-{rec.assessment_id}",
        organization="ApexSecurity",
        assessment_name="Q1-Workspace-Assessment",
        authorized_by="Director of AppSec",
        authorized_at=now.isoformat(),
        valid_from=(now - timedelta(days=1)).isoformat(),
        valid_until=(now + timedelta(days=30)).isoformat(),
        authorization_type=AuthorizationType.INTERNAL_SECURITY_ASSESSMENT,
        scope_reference="APEX-POLICY-2026-V1",
        rules=["Strict non-destructive testing", "Zero automated exploitation"],
        restrictions=["No denial of service", "No production database alteration"],
        status=AuthorizationStatus.AUTHORIZED,
    )
    mgr.set_authorization(rec.assessment_id, auth)

    # 3. Scope Policy Binding & ScopeGate Target Validation
    scope = ScopePolicy(
        program_name="Apex AppSec Policy",
        platform="M13_WORKSPACE",
        in_scope=["api.apex.local", "invoices.apex.local", "192.168.10.50"],
        out_of_scope=["internal-db.apex.local", "hr.apex.local"],
    )
    mgr.set_scope(rec.assessment_id, scope)

    # Test ScopeGate validations via workspace service
    val_in_scope = svc.validate_scope_target(rec.assessment_id, "https://api.apex.local/v1/user")
    assert val_in_scope["is_allowed"] is True

    val_out_of_scope = svc.validate_scope_target(rec.assessment_id, "https://internal-db.apex.local/admin")
    assert val_out_of_scope["is_allowed"] is False
    assert "out-of-scope" in val_out_of_scope["reason"].lower() or "out_of_scope" in val_out_of_scope["reason"].lower()

    val_unknown = svc.validate_scope_target(rec.assessment_id, "https://unknown.target.com/api")
    assert val_unknown["is_allowed"] is False

    # 4. Assessment Activation
    mgr.activate_assessment(rec.assessment_id, actor="CHIEF_AUDITOR")
    active_rec = mgr.get_assessment(rec.assessment_id)
    assert active_rec.state == AssessmentLifecycleState.ASSESSMENT_ACTIVE

    # 5. Asset Inventory Management
    cont = mgr.get_container(rec.assessment_id)
    asset_1 = cont.asset_graph.add_asset(
        canonical_identifier="api.apex.local",
        asset_type=AssetType.DOMAIN,
        scope_status=AssessmentScopeStatus.IN_SCOPE,
        tags=["core-api", "production-edge"],
    )
    assert asset_1.canonical_identifier == "api.apex.local"

    # 6. Artifact Registry Integration (SHA-256 Integrity)
    sample_content = b"GET /v1/invoices/INV-9001 HTTP/1.1\r\nHost: api.apex.local\r\n\r\n"
    sample_hash = hashlib.sha256(sample_content).hexdigest()
    art_meta = svc.register_artifact(
        assessment_id=rec.assessment_id,
        filename="traffic_session.har",
        artifact_type=ArtifactType.HAR,
        size_bytes=len(sample_content),
        sha256_hash=sample_hash,
        source="BurpSuite_Proxy",
        description="Captured HTTP baseline session",
    )
    assert art_meta.artifact_id.startswith("ART-")
    assert art_meta.sha256 == sample_hash
    assert art_meta.quarantine_status.value == "QUARANTINED"  # Initially quarantined until inspected

    artifacts_list = svc.list_artifacts(rec.assessment_id)
    assert len(artifacts_list) >= 1

    # 7. Telemetry Ingestion & Canonical Observations
    sample_har = {
        "log": {
            "entries": [
                {
                    "request": {
                        "url": "https://api.apex.local/v1/invoices/INV-9001",
                        "method": "GET",
                        "headers": [{"name": "Authorization", "value": "Bearer token_alice"}],
                    },
                    "response": {
                        "status": 200,
                        "headers": [{"name": "Content-Type", "value": "application/json"}],
                    },
                },
                {
                    "request": {
                        "url": "https://api.apex.local/admin/system-diagnostics",
                        "method": "GET",
                        "headers": [],
                    },
                    "response": {
                        "status": 403,
                        "headers": [{"name": "Content-Type", "value": "application/json"}],
                    },
                },
            ]
        }
    }
    telem_report = mgr.import_telemetry(rec.assessment_id, "har", sample_har, tool_name="BurpSuite_Proxy")
    assert telem_report["valid_observations"] == 2
    assert telem_report["in_scope_count"] == 2

    # 8. Attack Surface Mapping & Hypotheses Generation
    hyps = mgr.generate_hypotheses(rec.assessment_id)
    assert len(hyps) >= 1
    target_hyp = hyps[0]
    assert target_hyp.epistemic_status == "MODEL_HYPOTHESIS"
    assert target_hyp.hypothesis_id.startswith("HYP-")
    assert len(target_hyp.evidence_gaps) >= 1

    # 9. Controlled Experiment Proposal & Safe Manual Result Import
    exp = mgr.propose_experiment(
        assessment_id=rec.assessment_id,
        hypothesis_id=target_hyp.hypothesis_id,
        objective="Verify access boundaries on invoice endpoint",
        target_asset="api.apex.local",
        steps=[
            "1. Obtain authentication token for User Bob",
            "2. Request GET /v1/invoices/INV-9001 with User Bob token",
            "3. Observe HTTP status code and response payload",
        ],
        expected_secure_result="HTTP 403 Forbidden with access denied error",
        expected_vulnerable_result="HTTP 200 OK with User Alice invoice details",
        falsification_condition="Access denied with 403 / 401 response",
        negative_control="Unauthenticated request receives HTTP 401 Unauthorized",
    )
    assert exp.experiment_id.startswith("EXP-")
    assert exp.status.value == "PROPOSED"

    # Human approval required before importing results
    cont.experiment_engine.approve_experiment(exp.experiment_id, approver_name="SECURITY_LEAD")

    # Human researcher executes controlled experiment and imports results
    exp_result = mgr.import_experiment_result(
        experiment_id=exp.experiment_id,
        result_payload={
            "status_code": 200,
            "observed_body": '{"invoice_id": "INV-9001", "owner": "Alice", "amount": 5400}',
            "reproduced": True,
        },
        executed_by="RESEARCHER_LEAD",
    )
    assert exp_result.status == ExperimentStatus.EXECUTED or exp_result.status.value in ("EXECUTED", "COMPLETED")
    assert exp_result.executed_by == "RESEARCHER_LEAD"

    # 10. 13-Point Checklist Validation & Human Finding Verification
    obs_list = cont.telemetry_pipeline.get_observations()
    obs_id = obs_list[0].observation_id if obs_list else "OBS-1"

    candidate_finding = AssessmentFinding(
        finding_id=f"FIND-E2E-{rec.assessment_id}",
        assessment_id=rec.assessment_id,
        title="Broken Object-Level Authorization (BOLA) on Invoices Endpoint",
        severity=FindingSeverity.HIGH,
        asset="api.apex.local",
        affected_component="/v1/invoices/{id}",
        description="User Bob can view User Alice's confidential invoice INV-9001 via cross-tenant ID substitution.",
        impact="Full unauthorized disclosure of sensitive financial records across tenant boundaries.",
        evidence=[obs_id],
        reproduction_reference=exp.experiment_id,
        security_invariant="INV-BOLA-01",
        root_cause="Missing resource ownership check before returning invoice record.",
        remediation="Validate request subject matches resource owner or tenant ID.",
        references=["OWASP API1:2023"],
    )
    mgr.register_candidate_finding(rec.assessment_id, candidate_finding)

    finding = mgr.verify_finding(
        finding_id=candidate_finding.finding_id,
        human_reviewer="HUMAN_AUDITOR_JANE",
        justification="Verified cross-user IDOR using isolated test tokens. Invariant violated.",
    )
    assert finding.finding_id.startswith("FIND-")
    assert finding.verification_status == FindingVerificationStatus.HUMAN_VERIFIED
    assert finding.verified_by == "HUMAN_AUDITOR_JANE"

    # 11. Comprehensive Report Generation & Markdown Export
    report_md = svc.export_report_markdown(rec.assessment_id)
    assert "ApexSecurity" in report_md
    assert "Broken Object-Level Authorization (BOLA)" in report_md
    assert "HUMAN_AUDITOR_JANE" in report_md
    assert "INTERNAL_SECURITY_ASSESSMENT" in report_md
    assert "Unverified Hypotheses & Open Evidence Gaps" in report_md

    # 12. View State Persistence Across All 12 Sections
    for section in AssessmentSection:
        updated_state = svc.update_view_state(
            rec.assessment_id,
            WorkspaceViewState(active_section=section, search_query="invoice"),
        )
        assert updated_state.active_section == section

        # Fetch workspace shell model
        ws = svc.get_assessment_workspace(rec.assessment_id)
        assert ws.view_state.active_section == section
        assert ws.overview.finding_count >= 1

    # 13. Workspace Search & Audit Activity Timeline
    search_results = svc.search_workspace("invoice", assessment_id=rec.assessment_id)
    assert len(search_results) >= 1
    assert any("invoice" in r.title.lower() or "invoice" in r.snippet.lower() for r in search_results)

    activity = svc.get_activity_timeline(rec.assessment_id)
    assert len(activity) >= 5
    action_types = {a.event_type for a in activity}
    assert "OBSERVATION_IMPORTED" in action_types
    assert "HYPOTHESIS_CREATED" in action_types


def test_m13_workspace_cross_assessment_isolation(workspace_stack):
    """Verifies complete cross-tenant and cross-assessment data isolation."""
    mgr, svc = workspace_stack
    now = datetime.now(timezone.utc)

    # Create Assessment A
    rec_a = mgr.create_assessment("AlphaCorp", "Alpha-Project")
    auth_a = AuthorizationRecord(
        authorization_id=f"AUTH-{rec_a.assessment_id}",
        organization="AlphaCorp",
        assessment_name="Alpha-Project",
        authorized_by="Alpha CSO",
        authorized_at=now.isoformat(),
        valid_from="2026-01-01T00:00:00Z",
        valid_until="2027-01-01T00:00:00Z",
        authorization_type=AuthorizationType.INTERNAL_SECURITY_ASSESSMENT,
        scope_reference="ALPHA-SCOPE",
        status=AuthorizationStatus.AUTHORIZED,
    )
    mgr.set_authorization(rec_a.assessment_id, auth_a)
    scope_a = ScopePolicy(program_name="Alpha Policy", platform="M13", in_scope=["alpha.com"], out_of_scope=[])
    mgr.set_scope(rec_a.assessment_id, scope_a)
    mgr.activate_assessment(rec_a.assessment_id)

    # Ingest data into Assessment A
    sample_har = {
        "log": {
            "entries": [
                {
                    "request": {
                        "url": "https://alpha.com/user/100",
                        "method": "GET",
                        "headers": [{"name": "Authorization", "value": "Bearer alpha"}],
                    },
                    "response": {"status": 200, "headers": []},
                }
            ]
        }
    }
    mgr.import_telemetry(rec_a.assessment_id, "har", sample_har)
    svc.register_artifact(
        assessment_id=rec_a.assessment_id,
        filename="alpha_secret.pcap",
        artifact_type=ArtifactType.PCAP,
        size_bytes=1024,
        sha256_hash="a" * 64,
        source="Sniffer",
    )

    # Create Assessment B (Completely isolated)
    rec_b = mgr.create_assessment("BetaCorp", "Beta-Project")
    auth_b = AuthorizationRecord(
        authorization_id=f"AUTH-{rec_b.assessment_id}",
        organization="BetaCorp",
        assessment_name="Beta-Project",
        authorized_by="Beta CSO",
        authorized_at=now.isoformat(),
        valid_from="2026-01-01T00:00:00Z",
        valid_until="2027-01-01T00:00:00Z",
        authorization_type=AuthorizationType.INTERNAL_SECURITY_ASSESSMENT,
        scope_reference="BETA-SCOPE",
        status=AuthorizationStatus.AUTHORIZED,
    )
    mgr.set_authorization(rec_b.assessment_id, auth_b)
    scope_b = ScopePolicy(program_name="Beta Policy", platform="M13", in_scope=["beta.com"], out_of_scope=[])
    mgr.set_scope(rec_b.assessment_id, scope_b)
    mgr.activate_assessment(rec_b.assessment_id)

    # Verify Assessment B has ZERO data from Assessment A
    overview_b = svc.get_workspace_overview(rec_b.assessment_id)
    assert overview_b.asset_count == 0
    assert overview_b.observation_count == 0
    assert overview_b.hypothesis_count == 0
    assert overview_b.finding_count == 0
    assert overview_b.artifact_count == 0

    artifacts_b = svc.list_artifacts(rec_b.assessment_id)
    assert len(artifacts_b) == 0

    activity_b = svc.get_activity_timeline(rec_b.assessment_id)
    assert not any("alpha" in a.summary.lower() for a in activity_b)

    # Scoped search in Assessment B for "alpha" yields 0 items
    search_b = svc.search_workspace("alpha", assessment_id=rec_b.assessment_id)
    assert len(search_b) == 0
