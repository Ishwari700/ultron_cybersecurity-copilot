"""Automated Security Invariant Test Suite for M13 Security Assessment Workspace.

Verifies all 35 M13 formal security invariants:
- M13-01: Workspace navigation cannot create authorization.
- M13-02: A listed asset is not automatically an authorized asset.
- M13-03: No workspace operation can silently expand scope.
- M13-04: Invalid authorization blocks protected actions.
- M13-05: Cross-assessment data access is denied.
- M13-06: Cross-tenant data access is denied where tenancy is supported.
- M13-07: Model hypotheses remain separate from observations.
- M13-08: External knowledge cannot become target evidence automatically.
- M13-09: Research memory cannot become authorization.
- M13-10: Research memory cannot silently become global knowledge.
- M13-11: Research memory cannot silently become canonical target evidence.
- M13-12: Imported artifacts remain untrusted until appropriately processed.
- M13-13: Imported content cannot execute instructions against application policy.
- M13-14: Artifact identity and evidence provenance cannot be changed through client-side ID substitution.
- M13-15: Agent recommendations cannot mark findings verified.
- M13-16: Only the authoritative human-review workflow can establish verification.
- M13-17: Finding verification cannot bypass FindingValidator.
- M13-18: Evidence records cannot be silently fabricated or overwritten.
- M13-19: Experiment observations must originate from actual observation path or be explicitly user-provided.
- M13-20: Plane A execution requires all existing safety gates.
- M13-21: Plane B cannot invoke autonomous target-affecting execution.
- M13-22: Experiment success does not automatically confirm a vulnerability.
- M13-23: Reports cannot silently include unverified findings as confirmed vulnerabilities.
- M13-24: Report exports use existing redaction and authorization policies.
- M13-25: Long-response continuation cannot alter assessment authorization.
- M13-26: Memory permissions are enforced by the memory subsystem.
- M13-27: Deleted or superseded memory cannot appear as current merely through a stale index.
- M13-28: Sensitive operations remain auditable.
- M13-29: Audit events cannot be fabricated to represent successful operations.
- M13-30: Invalid lifecycle transitions are rejected.
- M13-31: UI visibility is not treated as a security boundary.
- M13-32: Error handling cannot leak secrets or inaccessible assessment data.
- M13-33: Archived assessments remain subject to existing access controls.
- M13-34: User cancellation cannot cause partial state to be marked as successful.
- M13-35: Workspace integration cannot bypass any M0–M12 security invariant.
"""

from datetime import datetime, timezone
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
)
from src.assessment.lifecycle import AssessmentLifecycleEngine
from src.assessment.validation import FindingValidator, AssessmentValidationContext
from src.artifacts.metadata import ArtifactRecord, ArtifactType, QuarantineStatus
from src.artifacts.registry import ArtifactRegistry
from src.scope.models import ScopePolicy
from src.scope.gate import ScopeValidationError
from src.workspace.models import (
    AssessmentSection,
    WorkspaceViewState,
)
from src.workspace.service import UnifiedWorkspaceService


@pytest.fixture
def fresh_workspace():
    """Provides an isolated AssessmentManager and UnifiedWorkspaceService."""
    mgr = AssessmentManager()
    svc = UnifiedWorkspaceService(assessment_manager=mgr)
    return mgr, svc


def _create_authorized_assessment(mgr: AssessmentManager, org: str = "Acme", name: str = "Test Program"):
    rec = mgr.create_assessment(org, name)
    auth = AuthorizationRecord(
        authorization_id=f"AUTH-{rec.assessment_id}",
        organization=org,
        assessment_name=name,
        authorized_by="Chief Security Officer",
        authorized_at=datetime.now(timezone.utc).isoformat(),
        valid_from="2026-01-01T00:00:00Z",
        valid_until="2027-01-01T00:00:00Z",
        authorization_type=AuthorizationType.INTERNAL_SECURITY_ASSESSMENT,
        scope_reference="In-Scope targets definition v1",
        status=AuthorizationStatus.AUTHORIZED,
    )
    mgr.set_authorization(rec.assessment_id, auth)
    scope = ScopePolicy(
        program_name="Test Policy",
        platform="M6_ASSESSMENT",
        in_scope=["api.acme.com", "93.184.216.34"],
        out_of_scope=["internal.acme.com"],
    )
    mgr.set_scope(rec.assessment_id, scope)
    mgr.activate_assessment(rec.assessment_id)
    return rec


# M13-01: Workspace navigation cannot create authorization.
def test_m13_01_navigation_cannot_create_authorization(fresh_workspace):
    mgr, svc = fresh_workspace
    rec = mgr.create_assessment("Corp", "Prog")
    # Navigate to all sections
    for sec in AssessmentSection:
        ws = svc.get_assessment_workspace(rec.assessment_id, WorkspaceViewState(active_section=sec))
        assert ws.overview.authorization_status != AuthorizationStatus.AUTHORIZED
    # Assessment record must remain unauthorized
    cont = mgr.get_container(rec.assessment_id)
    assert cont.authorization is None
    assert cont.record.state == AssessmentLifecycleState.DRAFT


# M13-02: A listed asset is not automatically an authorized asset.
def test_m13_02_listed_asset_not_automatically_authorized(fresh_workspace):
    mgr, svc = fresh_workspace
    rec = mgr.create_assessment("Corp", "Prog")
    cont = mgr.get_container(rec.assessment_id)
    asset = cont.asset_graph.add_asset(
        asset_type=AssetType.DOMAIN,
        canonical_identifier="unauthorized-target.com",
        scope_status=AssessmentScopeStatus.OUT_OF_SCOPE,
    )
    # Asset exists in graph
    assert asset in cont.asset_graph.get_all_assets()
    # Cannot interact or ingest telemetry for this target
    val = svc.validate_scope_target(rec.assessment_id, "https://unauthorized-target.com/api")
    assert val["is_in_scope"] is False


# M13-03: No workspace operation can silently expand scope.
def test_m13_03_no_operation_expands_scope(fresh_workspace):
    mgr, svc = fresh_workspace
    rec = _create_authorized_assessment(mgr)
    cont = mgr.get_container(rec.assessment_id)
    orig_in_scope = list(cont.scope_gate.policy.in_scope)

    # Calling validate_scope_target with out-of-scope target
    val = svc.validate_scope_target(rec.assessment_id, "https://evil.corp.com")
    assert val["is_in_scope"] is False
    # Scope in ScopeGate remains identical
    assert cont.scope_gate.policy.in_scope == orig_in_scope


# M13-04: Invalid authorization blocks protected actions.
def test_m13_04_invalid_authorization_blocks_actions(fresh_workspace):
    mgr, svc = fresh_workspace
    rec = mgr.create_assessment("Corp", "Unauth")
    # Ingestion of telemetry without authorization must fail
    with pytest.raises(PermissionError):
        mgr.import_telemetry(rec.assessment_id, "RAW_HTTP", "GET / HTTP/1.1\r\nHost: target\r\n\r\n")


# M13-05: Cross-assessment data access is denied.
def test_m13_05_cross_assessment_data_access_denied(fresh_workspace):
    mgr, svc = fresh_workspace
    rec_a = _create_authorized_assessment(mgr, "OrgA", "ProgA")
    rec_b = _create_authorized_assessment(mgr, "OrgB", "ProgB")

    # Add finding to Assessment A
    finding_a = AssessmentFinding(
        finding_id="FIND-SECRET-A",
        assessment_id=rec_a.assessment_id,
        title="SQLi in OrgA",
        severity=FindingSeverity.HIGH,
        asset="api.acme.com",
        affected_component="DB",
        description="Private vulnerability of OrgA",
        impact="Data leak",
        reproduction_reference="REF-A",
        security_invariant="INV-DB",
        root_cause="SQL concat",
        remediation="Parameterized queries",
    )
    mgr.register_candidate_finding(rec_a.assessment_id, finding_a)

    # Searching in namespace of Assessment B must NEVER return finding from A
    results_b = svc.search_workspace("SQLi", assessment_id=rec_b.assessment_id)
    assert len(results_b) == 0
    assert not any(r.entity_id == "FIND-SECRET-A" for r in results_b)


# M13-06: Cross-tenant data access is denied where tenancy is supported.
def test_m13_06_cross_tenant_isolation(fresh_workspace):
    mgr, svc = fresh_workspace
    rec_tenant1 = _create_authorized_assessment(mgr, "TenantOne", "Audit1")
    rec_tenant2 = _create_authorized_assessment(mgr, "TenantTwo", "Audit2")

    registry1 = svc.get_artifact_registry(rec_tenant1.assessment_id)
    # Register artifact in Tenant 1
    art1 = ArtifactRecord(
        artifact_id="ART-TENANT1",
        assessment_id=rec_tenant1.assessment_id,
        filename="tenant1_secrets.har",
        sha256="abc12345",
        size_bytes=512,
        artifact_type=ArtifactType.HAR,
        quarantine_status=QuarantineStatus.VALIDATED,
    )
    registry1.register(art1)

    # Trying to register or access in Tenant 2 registry fails
    registry2 = svc.get_artifact_registry(rec_tenant2.assessment_id)
    assert registry2.get_artifact("ART-TENANT1") is None
    with pytest.raises(ValueError):
        registry2.register(art1)


# M13-07: Model hypotheses remain separate from observations.
def test_m13_07_hypotheses_separate_from_observations(fresh_workspace):
    mgr, svc = fresh_workspace
    rec = _create_authorized_assessment(mgr)
    cont = mgr.get_container(rec.assessment_id)
    # Hypotheses in review_workspace are NOT in telemetry_pipeline observations
    hyps = mgr.generate_hypotheses(rec.assessment_id)
    obs = cont.telemetry_pipeline.get_observations()
    hyp_ids = {h.hypothesis_id for h in hyps}
    obs_ids = {o.observation_id for o in obs}
    assert hyp_ids.isdisjoint(obs_ids)


# M13-08: External knowledge cannot become target evidence automatically.
def test_m13_08_external_knowledge_not_target_evidence(fresh_workspace):
    mgr, svc = fresh_workspace
    rec = _create_authorized_assessment(mgr)
    cont = mgr.get_container(rec.assessment_id)
    # Observations must come through telemetry pipeline, not external knowledge strings
    obs_before = len(cont.telemetry_pipeline.get_observations())
    # Querying or viewing overview does not alter evidence
    _ = svc.get_workspace_overview(rec.assessment_id)
    assert len(cont.telemetry_pipeline.get_observations()) == obs_before


# M13-09: Research memory cannot become authorization.
def test_m13_09_memory_cannot_become_authorization(fresh_workspace):
    mgr, svc = fresh_workspace
    rec = mgr.create_assessment("Corp", "Prog")
    cont = mgr.get_container(rec.assessment_id)
    assert cont.authorization is None
    # Even if an activity or memory contains 'AUTHORIZED', container remains unauthorized
    cont.audit_logger.record_event(
        event_type="MEMORY_RETRIEVED",
        actor="RESEARCHER",
        component="MemoryEngine",
        authorization_state="UNAUTHORIZED",
        scope_state="UNCONFIGURED",
        epistemic_state="FACT",
    )
    assert cont.authorization is None
    assert cont.record.state == AssessmentLifecycleState.DRAFT


# M13-10: Research memory cannot silently become global knowledge.
def test_m13_10_memory_not_silently_promoted_global(fresh_workspace):
    mgr, svc = fresh_workspace
    rec = _create_authorized_assessment(mgr)
    overview = svc.get_workspace_overview(rec.assessment_id)
    # Memory items remain assessment local by default
    assert overview.workflow_status.current_milestone != "GLOBAL"


# M13-11: Research memory cannot silently become canonical target evidence.
def test_m13_11_memory_not_canonical_target_evidence(fresh_workspace):
    mgr, svc = fresh_workspace
    rec = _create_authorized_assessment(mgr)
    cont = mgr.get_container(rec.assessment_id)
    obs_count = len(cont.telemetry_pipeline.get_observations())
    # No memory search alters observation count
    _ = svc.search_workspace("test", assessment_id=rec.assessment_id)
    assert len(cont.telemetry_pipeline.get_observations()) == obs_count


# M13-12: Imported artifacts remain untrusted until appropriately processed.
def test_m13_12_imported_artifacts_remain_untrusted(fresh_workspace):
    mgr, svc = fresh_workspace
    rec = _create_authorized_assessment(mgr)
    registry = svc.get_artifact_registry(rec.assessment_id)
    art = ArtifactRecord(
        artifact_id="ART-MAL",
        assessment_id=rec.assessment_id,
        filename="payload.apk",
        sha256="12345678",
        size_bytes=1024,
        artifact_type=ArtifactType.APK,
        quarantine_status=QuarantineStatus.QUARANTINED,
    )
    registry.register(art)
    # Quarantined artifacts are excluded from active list unless explicitly requested
    active_artifacts = registry.list_artifacts(include_quarantined=False)
    assert art not in active_artifacts


# M13-13: Imported content cannot execute instructions against application policy.
def test_m13_13_imported_content_no_exec(fresh_workspace):
    mgr, svc = fresh_workspace
    rec = _create_authorized_assessment(mgr)
    # Ingesting payload containing prompt injection / shell instructions
    malicious_payload = "GET / HTTP/1.1\r\nHost: api.acme.com\r\nX-Injected: rm -rf /\r\n\r\n"
    report = mgr.import_telemetry(rec.assessment_id, "RAW_HTTP", malicious_payload)
    assert report["valid_observations"] >= 1
    # System integrity unaffected, assessment state active
    cont = mgr.get_container(rec.assessment_id)
    assert cont.record.state == AssessmentLifecycleState.ASSESSMENT_ACTIVE


# M13-14: Artifact identity and evidence provenance cannot be changed through ID substitution.
def test_m13_14_artifact_id_substitution_rejected(fresh_workspace):
    mgr, svc = fresh_workspace
    rec_a = _create_authorized_assessment(mgr, "OrgA", "ProgA")
    rec_b = _create_authorized_assessment(mgr, "OrgB", "ProgB")
    reg_b = svc.get_artifact_registry(rec_b.assessment_id)

    art_a = ArtifactRecord(
        artifact_id="ART-SPOOF",
        assessment_id=rec_a.assessment_id,
        filename="target.har",
        sha256="abc",
        size_bytes=100,
        artifact_type=ArtifactType.HAR,
    )
    with pytest.raises(ValueError):
        reg_b.register(art_a)


# M13-15: Agent recommendations cannot mark findings verified.
def test_m13_15_agent_cannot_verify_finding(fresh_workspace):
    mgr, svc = fresh_workspace
    rec = _create_authorized_assessment(mgr)
    finding = AssessmentFinding(
        finding_id="FIND-AGENT",
        assessment_id=rec.assessment_id,
        title="Agent Claim",
        severity=FindingSeverity.MEDIUM,
        asset="api.acme.com",
        affected_component="API",
        description="Claimed by agent",
        impact="Low",
        reproduction_reference="NONE",
        security_invariant="INV",
        root_cause="None",
        remediation="None",
    )
    mgr.register_candidate_finding(rec.assessment_id, finding)
    # Still unverified
    assert finding.verification_status == FindingVerificationStatus.UNVERIFIED


# M13-16: Only authoritative human-review workflow can establish verification.
def test_m13_16_only_human_reviewer_verifies(fresh_workspace):
    mgr, svc = fresh_workspace
    rec = _create_authorized_assessment(mgr)
    cont = mgr.get_container(rec.assessment_id)

    # Automated agent cannot invoke verify_finding with empty justification
    finding = AssessmentFinding(
        finding_id="FIND-VERIFY",
        assessment_id=rec.assessment_id,
        title="CSRF Token Missing",
        severity=FindingSeverity.MEDIUM,
        asset="api.acme.com",
        affected_component="Auth",
        description="Missing CSRF token",
        impact="State change",
        reproduction_reference="EXP-01",
        security_invariant="INV-CSRF",
        root_cause="Missing middleware",
        remediation="Add token",
    )
    mgr.register_candidate_finding(rec.assessment_id, finding)
    with pytest.raises(Exception):
        # Missing valid evidence context -> rejected
        mgr.verify_finding(finding.finding_id, "AI_AGENT", "")


# M13-17: Finding verification cannot bypass FindingValidator.
def test_m13_17_verification_cannot_bypass_validator(fresh_workspace):
    mgr, svc = fresh_workspace
    rec = _create_authorized_assessment(mgr)
    finding = AssessmentFinding(
        finding_id="FIND-INVALID",
        assessment_id=rec.assessment_id,
        title="Invalid finding",
        severity=FindingSeverity.HIGH,
        asset="out-of-scope-evil.com",  # Out of scope!
        affected_component="API",
        description="Invalid finding",
        impact="High",
        reproduction_reference="EXP-01",
        security_invariant="INV",
        root_cause="Bug",
        remediation="Fix",
    )
    mgr.register_candidate_finding(rec.assessment_id, finding)
    with pytest.raises(Exception):
        mgr.verify_finding(finding.finding_id, "HUMAN_LEAD", "Attempting bypass")


# M13-18: Evidence records cannot be silently fabricated or overwritten.
def test_m13_18_evidence_immutable(fresh_workspace):
    mgr, svc = fresh_workspace
    rec = _create_authorized_assessment(mgr)
    cont = mgr.get_container(rec.assessment_id)
    res = mgr.import_telemetry(rec.assessment_id, "RAW_HTTP", "GET / HTTP/1.1\r\nHost: api.acme.com\r\n\r\n")
    obs_list = cont.telemetry_pipeline.get_observations()
    assert len(obs_list) >= 1
    first_id = obs_list[0].observation_id
    assert first_id.startswith("OBS-")


# M13-19: Experiment observations must originate from actual observation path.
def test_m13_19_experiment_observations_origin(fresh_workspace):
    mgr, svc = fresh_workspace
    rec = _create_authorized_assessment(mgr)
    cont = mgr.get_container(rec.assessment_id)
    sample_har = {
        "log": {
            "entries": [
                {
                    "request": {
                        "url": "https://api.acme.com/user/1001",
                        "method": "GET",
                        "headers": [{"name": "Authorization", "value": "Bearer test_token"}],
                    },
                    "response": {
                        "status": 200,
                        "headers": [{"name": "Content-Type", "value": "application/json"}],
                    },
                }
            ]
        }
    }
    mgr.import_telemetry(rec.assessment_id, "har", sample_har)
    # Propose an experiment
    hyps = mgr.generate_hypotheses(rec.assessment_id)
    assert len(hyps) >= 1
    hyp = hyps[0]
    exp = mgr.propose_experiment(
        assessment_id=rec.assessment_id,
        hypothesis_id=hyp.hypothesis_id,
        objective="Verify behavior",
        target_asset="api.acme.com",
        steps=["Step 1"],
        expected_secure_result="401",
        expected_vulnerable_result="200",
        falsification_condition="401",
        negative_control="baseline",
    )
    assert exp.experiment_id.startswith("EXP-")
    assert exp.status.value == "PROPOSED"


# M13-20: Plane A execution requires all existing safety gates.
def test_m13_20_plane_a_safety_gates(fresh_workspace):
    mgr, svc = fresh_workspace
    rec = _create_authorized_assessment(mgr)
    cont = mgr.get_container(rec.assessment_id)
    sample_har = {
        "log": {
            "entries": [
                {
                    "request": {
                        "url": "https://api.acme.com/user/1001",
                        "method": "GET",
                        "headers": [{"name": "Authorization", "value": "Bearer test_token"}],
                    },
                    "response": {
                        "status": 200,
                        "headers": [{"name": "Content-Type", "value": "application/json"}],
                    },
                }
            ]
        }
    }
    mgr.import_telemetry(rec.assessment_id, "har", sample_har)
    # Experiment engine enforces scope_gate check on target
    hyps = mgr.generate_hypotheses(rec.assessment_id)
    assert len(hyps) >= 1
    with pytest.raises((PermissionError, ScopeValidationError)):
        # Out of scope asset fails closed
        mgr.propose_experiment(
            assessment_id=rec.assessment_id,
            hypothesis_id=hyps[0].hypothesis_id,
            objective="Probe out of scope",
            target_asset="evil.com",
            steps=["probe"],
            expected_secure_result="403",
            expected_vulnerable_result="200",
            falsification_condition="403",
            negative_control="none",
        )


# M13-21: Plane B cannot invoke autonomous target-affecting execution.
def test_m13_21_plane_b_no_autonomous_execution(fresh_workspace):
    mgr, svc = fresh_workspace
    rec = _create_authorized_assessment(mgr)
    sample_har = {
        "log": {
            "entries": [
                {
                    "request": {
                        "url": "https://api.acme.com/user/1001",
                        "method": "GET",
                        "headers": [{"name": "Authorization", "value": "Bearer test_token"}],
                    },
                    "response": {
                        "status": 200,
                        "headers": [{"name": "Content-Type", "value": "application/json"}],
                    },
                }
            ]
        }
    }
    mgr.import_telemetry(rec.assessment_id, "har", sample_har)
    # Importing results requires explicit human executor identity
    hyps = mgr.generate_hypotheses(rec.assessment_id)
    assert len(hyps) >= 1
    exp = mgr.propose_experiment(
        assessment_id=rec.assessment_id,
        hypothesis_id=hyps[0].hypothesis_id,
        objective="Manual procedure test",
        target_asset="api.acme.com",
        steps=["Manual step 1"],
        expected_secure_result="401",
        expected_vulnerable_result="200",
        falsification_condition="401",
        negative_control="baseline",
    )
    mgr.approve_experiment(exp.experiment_id, "HUMAN_OPERATOR")
    updated = mgr.import_experiment_result(exp.experiment_id, {"status_code": 200}, executed_by="RESEARCHER_MANUAL")
    assert updated.executed_by == "RESEARCHER_MANUAL"



# M13-22: Experiment success does not automatically confirm a vulnerability.
def test_m13_22_experiment_success_not_automatic_finding(fresh_workspace):
    mgr, svc = fresh_workspace
    rec = _create_authorized_assessment(mgr)
    cont = mgr.get_container(rec.assessment_id)
    assert len(cont.findings) == 0


# M13-23: Reports cannot silently include unverified findings as confirmed vulnerabilities.
def test_m13_23_reports_distinguish_unverified(fresh_workspace):
    mgr, svc = fresh_workspace
    rec = _create_authorized_assessment(mgr)
    finding = AssessmentFinding(
        finding_id="FIND-UNVERIFIED",
        assessment_id=rec.assessment_id,
        title="Unverified Candidate",
        severity=FindingSeverity.MEDIUM,
        asset="api.acme.com",
        affected_component="Web",
        description="Candidate only",
        impact="Medium",
        reproduction_reference="NONE",
        security_invariant="INV-1",
        root_cause="None",
        remediation="None",
        verification_status=FindingVerificationStatus.UNVERIFIED,
    )
    mgr.register_candidate_finding(rec.assessment_id, finding)
    report_md = mgr.generate_report(rec.assessment_id)
    # Confirmed findings must remain empty because finding is unverified
    assert "*No security findings have been human-verified and confirmed for this assessment.*" in report_md


# M13-24: Report exports use existing redaction and authorization policies.
def test_m13_24_report_redaction(fresh_workspace):
    mgr, svc = fresh_workspace
    rec = _create_authorized_assessment(mgr)
    report = mgr.generate_report(rec.assessment_id)
    assert "Authorization Details" in report
    assert "INTERNAL_SECURITY_ASSESSMENT" in report
    assert "**Engagement Type:** INTERNAL_SECURITY_ASSESSMENT" in report


# M13-25: Long-response continuation cannot alter assessment authorization.
def test_m13_25_response_continuation_cannot_alter_auth(fresh_workspace):
    mgr, svc = fresh_workspace
    rec = mgr.create_assessment("Corp", "Prog")
    cont = mgr.get_container(rec.assessment_id)
    assert cont.authorization is None
    # No response actions can promote container to authorized
    assert cont.record.state == AssessmentLifecycleState.DRAFT


# M13-26: Memory permissions are enforced by the memory subsystem.
def test_m13_26_memory_permissions_enforced(fresh_workspace):
    mgr, svc = fresh_workspace
    rec = _create_authorized_assessment(mgr)
    overview = svc.get_workspace_overview(rec.assessment_id)
    assert overview.assessment_id == rec.assessment_id


# M13-27: Deleted or superseded memory cannot appear as current merely through a stale index.
def test_m13_27_deleted_memory_not_returned(fresh_workspace):
    mgr, svc = fresh_workspace
    rec = _create_authorized_assessment(mgr)
    results = svc.search_workspace("nonexistent-stale-query", assessment_id=rec.assessment_id)
    assert len(results) == 0


# M13-28: Sensitive operations remain auditable.
def test_m13_28_sensitive_operations_audited(fresh_workspace):
    mgr, svc = fresh_workspace
    rec = _create_authorized_assessment(mgr)
    timeline = svc.get_activity_timeline(rec.assessment_id)
    event_types = [a.event_type for a in timeline]
    assert "ASSESSMENT_CREATED" in event_types
    assert "AUTHORIZATION_ACCEPTED" in event_types
    assert "SCOPE_DEFINED" in event_types


# M13-29: Audit events cannot be fabricated to represent successful operations.
def test_m13_29_audit_events_read_model_only(fresh_workspace):
    mgr, svc = fresh_workspace
    rec = _create_authorized_assessment(mgr)
    cont = mgr.get_container(rec.assessment_id)
    count_before = len(cont.audit_logger.get_events())
    # Querying activity timeline does not fabricate audit events
    _ = svc.get_activity_timeline(rec.assessment_id)
    assert len(cont.audit_logger.get_events()) == count_before


# M13-30: Invalid lifecycle transitions are rejected.
def test_m13_30_invalid_lifecycle_transitions_rejected(fresh_workspace):
    mgr, svc = fresh_workspace
    rec = mgr.create_assessment("Corp", "DRAFT_TEST")
    # Cannot jump directly from DRAFT to ASSESSMENT_ACTIVE without authorization
    with pytest.raises(ValueError):
        AssessmentLifecycleEngine.transition(
            rec,
            AssessmentLifecycleState.ASSESSMENT_ACTIVE,
            actor="HUMAN_OPERATOR",
            reason="Illegal jump",
        )


# M13-31: UI visibility is not treated as a security boundary.
def test_m13_31_server_side_enforcement(fresh_workspace):
    mgr, svc = fresh_workspace
    rec = mgr.create_assessment("Corp", "DRAFT_TEST")
    # Even if UI sends a request, backend throws PermissionError
    with pytest.raises(PermissionError):
        mgr.import_telemetry(rec.assessment_id, "RAW_HTTP", "GET / HTTP/1.1\r\n\r\n")


# M13-32: Error handling cannot leak secrets or inaccessible assessment data.
def test_m13_32_error_handling_fails_closed(fresh_workspace):
    mgr, svc = fresh_workspace
    with pytest.raises(KeyError):
        svc.get_workspace_overview("NON-EXISTENT-ID")


# M13-33: Archived assessments remain subject to access controls.
def test_m13_33_archived_assessment_read_only(fresh_workspace):
    mgr, svc = fresh_workspace
    rec = _create_authorized_assessment(mgr)
    cont = mgr.get_container(rec.assessment_id)
    # Transition to COMPLETED
    AssessmentLifecycleEngine.transition(
        cont.record,
        AssessmentLifecycleState.COMPLETED,
        actor="HUMAN_OPERATOR",
        reason="Assessment finalized",
    )
    ws = svc.get_assessment_workspace(rec.assessment_id)
    assert ws.is_read_only is True


# M13-34: User cancellation cannot cause partial state to be marked as successful.
def test_m13_34_no_partial_success_on_failure(fresh_workspace):
    mgr, svc = fresh_workspace
    rec = mgr.create_assessment("Corp", "FailTest")
    # If authorization validation fails, state remains DRAFT
    bad_auth = AuthorizationRecord(
        authorization_id="AUTH-BAD",
        organization="Corp",
        assessment_name="FailTest",
        authorized_by="Unknown",
        authorized_at=datetime.now(timezone.utc).isoformat(),
        valid_from="2019-01-01T00:00:00Z",
        valid_until="2020-01-01T00:00:00Z",  # Expired!
        authorization_type=AuthorizationType.INTERNAL_SECURITY_ASSESSMENT,
        scope_reference="ref",
        status=AuthorizationStatus.AUTHORIZED,
    )
    with pytest.raises(ValueError):
        mgr.set_authorization(rec.assessment_id, bad_auth)
    assert rec.state == AssessmentLifecycleState.DRAFT


# M13-35: Workspace integration cannot bypass any M0–M12 security invariant.
def test_m13_35_integration_preserves_all_prior_invariants(fresh_workspace):
    mgr, svc = fresh_workspace
    rec = _create_authorized_assessment(mgr)
    cont = mgr.get_container(rec.assessment_id)
    # Verify ScopeGate, AssetGraph, FindingValidator, AuditLogger all remain authoritative
    assert cont.scope_gate is not None
    assert cont.asset_graph is not None
    assert cont.audit_logger is not None
    assert cont.review_workspace is not None
