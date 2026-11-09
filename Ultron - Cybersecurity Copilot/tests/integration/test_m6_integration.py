"""End-to-End Integration Test Suite for M6 Authorized Pentest Copilot.

Tests the complete lifecycle:
Authorization
-> Scope
-> Target / Asset Inventory
-> Passive Telemetry
-> Attack Surface Mapping
-> Security Analysis
-> Hypotheses
-> Evidence Gaps
-> Safe Manual Experiments
-> Human Execution
-> Observations
-> Impact Assessment
-> Human Verification
-> Finding
-> Report
"""

from datetime import datetime, timezone, timedelta
from src.assessment.models import (
    AssessmentLifecycleState,
    AssessmentScopeStatus,
    AssetType,
    AttackSurfaceState,
    AuthorizationRecord,
    AuthorizationStatus,
    AuthorizationType,
    ExperimentRiskLevel,
    ExperimentStatus,
    FindingSeverity,
    FindingVerificationStatus,
)
from src.assessment.manager import AssessmentManager
from src.scope.models import ScopePolicy


def test_m6_end_to_end_assessment_workflow():
    """Full integration test exercising the complete authorized assessment pipeline."""
    mgr = AssessmentManager.get_instance()
    now = datetime.now(timezone.utc)

    # 1. Create Assessment (DRAFT)
    asm = mgr.create_assessment("AcmeCorp", "E2E_Q4_Pentest", created_by="Lead_Auditor")
    assert asm.state == AssessmentLifecycleState.DRAFT

    # 2. Bind Authorization (DRAFT -> AUTHORIZED)
    auth = AuthorizationRecord(
        authorization_id="AUTH-E2E-001",
        organization="AcmeCorp",
        assessment_name="E2E_Q4_Pentest",
        authorized_by="Chief_Information_Security_Officer",
        authorized_at=now.isoformat(),
        valid_from=(now - timedelta(days=1)).isoformat(),
        valid_until=(now + timedelta(days=7)).isoformat(),
        authorization_type=AuthorizationType.PENETRATION_TEST,
        scope_reference="SCOPE-E2E-POLICY",
        rules=["Strict non-destructive testing"],
        restrictions=["No automated brute force"],
        status=AuthorizationStatus.AUTHORIZED,
    )
    mgr.set_authorization(asm.assessment_id, auth)
    asm_rec = mgr.get_assessment(asm.assessment_id)
    assert asm_rec.state == AssessmentLifecycleState.AUTHORIZED

    # 3. Define Scope (AUTHORIZED -> SCOPE_DEFINED)
    scope = ScopePolicy(
        program_name="AcmeCorp_Scope",
        platform="LOCAL",
        in_scope=["api.acmecorp.com", "*.api.acmecorp.com"],
        out_of_scope=["admin.api.acmecorp.com"],
    )
    mgr.set_scope(asm.assessment_id, scope)
    asm_rec = mgr.get_assessment(asm.assessment_id)
    assert asm_rec.state == AssessmentLifecycleState.SCOPE_DEFINED

    # 4. Activate Assessment (SCOPE_DEFINED -> ASSESSMENT_ACTIVE)
    mgr.activate_assessment(asm.assessment_id)
    asm_rec = mgr.get_assessment(asm.assessment_id)
    assert asm_rec.state == AssessmentLifecycleState.ASSESSMENT_ACTIVE

    # 5. Ingest Passive Telemetry (Parser -> Normalizer -> ScopeGate -> Evidence Store)
    sample_har = {
        "log": {"entries": [
            {
                "request": {
                    "url": "https://api.acmecorp.com/v1/invoices/INV-1001",
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
                    "url": "https://admin.api.acmecorp.com/actuator/health",
                    "method": "GET",
                    "headers": [],
                },
                "response": {"status": 403, "headers": []},
            },
        ]}
    }
    ingest_report = mgr.import_telemetry(asm.assessment_id, "har", sample_har)
    assert ingest_report["valid_observations"] == 2
    assert ingest_report["in_scope_count"] == 1
    assert ingest_report["out_of_scope_count"] == 1

    # 6. Verify Asset Inventory and Attack Surface Mapping
    cont = mgr.get_container(asm.assessment_id)
    assets = cont.asset_graph.get_all_assets()
    assert len(assets) >= 1

    asm_surface = cont.attack_surface.export_summary()
    assert asm_surface["endpoints_count"] >= 1

    # 7. Generate Security Hypotheses
    hyps = mgr.generate_hypotheses(asm.assessment_id)
    assert len(hyps) >= 1
    target_hyp = hyps[0]
    assert target_hyp.epistemic_status == "MODEL_HYPOTHESIS"

    # 8. Propose Safe Manual Experiment (Default Human Execution)
    exp = mgr.propose_experiment(
        assessment_id=asm.assessment_id,
        hypothesis_id=target_hyp.hypothesis_id,
        objective="Verify Bob token access to Alice invoice INV-1001",
        target_asset="api.acmecorp.com",
        steps=[
            "1. Acquire test token for User Bob",
            "2. Send GET /v1/invoices/INV-1001 with Bob token",
            "3. Observe response status code and body",
        ],
        expected_secure_result="HTTP 403 Forbidden",
        expected_vulnerable_result="HTTP 200 OK with Alice invoice payload",
        falsification_condition="Server checks invoice tenant/user ownership",
        negative_control="Alice requesting her own invoice returns 200 OK",
        risk_level=ExperimentRiskLevel.PASSIVE,
    )
    assert exp.requires_human_execution is True
    assert exp.destructive_potential is False
    assert exp.status == ExperimentStatus.PROPOSED

    # 9. Human Review & Execution Simulation
    cont.review_workspace.approve_experiment(exp.experiment_id, "Lead_Researcher")
    executed_exp = mgr.import_experiment_result(
        exp.experiment_id,
        result_payload={"status_code": 200, "response_body": '{"invoice_id": "INV-1001", "owner": "alice"}'},
        executed_by="Lead_Researcher",
    )
    assert executed_exp.status == ExperimentStatus.EXECUTED

    # Ingest verification observation produced by human experiment
    verify_obs_report = mgr.import_telemetry(
        asm.assessment_id,
        "raw_http",
        "GET /v1/invoices/INV-1001 HTTP/1.1\nHost: api.acmecorp.com\nAuthorization: Bearer token_bob\n\n",
    )
    assert verify_obs_report["valid_observations"] == 1
    new_obs_id = verify_obs_report["new_observations"][0].observation_id

    # 10. Register Candidate Finding & Human Verification
    from src.assessment.models import AssessmentFinding
    finding = AssessmentFinding(
        finding_id=f"FIND-E2E-{asm.assessment_id}",
        assessment_id=asm.assessment_id,
        title="Broken Object Level Authorization (BOLA) on Invoice API",
        severity=FindingSeverity.HIGH,
        asset="api.acmecorp.com",
        affected_component="/v1/invoices/{id}",
        description="User Bob can retrieve User Alice invoices by direct ID substitution.",
        impact="Confidential financial record exposure across tenants.",
        evidence=[new_obs_id],
        reproduction_reference=exp.experiment_id,
        security_invariant="INV-BOLA-01",
        root_cause="Missing resource ownership check before returning invoice record.",
        remediation="Validate request subject matches resource owner or tenant ID.",
        references=["OWASP API1:2023"],
    )
    mgr.register_candidate_finding(asm.assessment_id, finding)

    # 11. 13-Point Deterministic Finding Verification by Human
    confirmed_finding = mgr.verify_finding(
        finding.finding_id,
        human_reviewer="Lead_Researcher",
        justification="Verified cross-user IDOR using isolated test tokens. Invariant violated.",
    )
    assert confirmed_finding.verification_status == FindingVerificationStatus.HUMAN_VERIFIED

    # 12. Generate Formal Security Assessment Report
    report_md = mgr.generate_report(asm.assessment_id)
    assert "Authorized Security Assessment Report" in report_md
    assert "Broken Object Level Authorization (BOLA) on Invoice API" in report_md
    assert "HUMAN_VERIFIED" in report_md
    assert "Out-of-Scope Observations" in report_md
    assert "Executive Summary" in report_md
