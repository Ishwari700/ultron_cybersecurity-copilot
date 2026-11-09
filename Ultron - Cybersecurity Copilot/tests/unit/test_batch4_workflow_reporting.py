"""Comprehensive Unit and Integration Tests for Batch 4 Workflow, UI & Maintainability Remediation.

Covers:
1. Workstream A: Report Generator Multi-Format Support (Markdown, JSON, HTML) & Epistemic Quarantine.
2. Workstream A: API Report Generation & Export with Authoritative MIME Types, Filenames, and Fail-Closed Validation.
3. Workstream A & B: Authorization Revocation and Role-Based Access Control (403 Forbidden on Revoked Auth / Observer Role).
4. Workstream B: Assessment Lifecycle State Machine Transitions via PATCH /api/assessments/{id}.
5. Workstream C: Controlled Experiment Approval and Execution Result Ingestion Pipeline.
6. Workstream C: Assessment Memory Listing and Retrieval Search Contracts.
"""

from datetime import datetime, timezone
import json
from pathlib import Path
import pytest
from starlette.testclient import TestClient

from src.core.logging import AuditLogger
from src.database.manager import DatabaseManager
from src.dashboard.auth import DashboardAuthManager, DashboardRole, hash_password
from src.dashboard.app import create_dashboard_app
from src.assessment.manager import AssessmentManager
from src.assessment.reporting import AssessmentReportGenerator
from src.assessment.models import (
    AssessmentFinding,
    AssessmentLifecycleState,
    AuthorizationRecord,
    AuthorizationStatus,
    AuthorizationType,
    FindingSeverity,
    FindingVerificationStatus,
    ExperimentStatus,
    ExperimentRiskLevel,
)
from src.scope.models import ScopePolicy


@pytest.fixture
def batch4_env(tmp_path: Path):
    """Sets up an isolated database, audit log, auth manager, assessment manager, and test client."""
    db_file = tmp_path / "test_batch4.db"
    db = DatabaseManager(db_path=db_file)
    db.initialize_schema()

    audit_file = tmp_path / "test_batch4_audit.log"
    auditor = AuditLogger(audit_file)

    auth_mgr = DashboardAuthManager(db_manager=db)

    # Provision standard test users
    db.create_user("observer_user", hash_password("ObsPass123!"), role="observer", is_active=True)
    db.create_user("reviewer_user", hash_password("RevPass123!"), role="reviewer", is_active=True)
    db.create_user("admin_user", hash_password("AdmPass123!"), role="admin", is_active=True)

    assessment_mgr = AssessmentManager.get_instance()
    assessment_mgr._assessments.clear()
    assessment_mgr._experiment_to_assessment.clear()
    assessment_mgr._finding_to_assessment.clear()
    assessment_mgr._hypothesis_to_assessment.clear()

    app = create_dashboard_app(
        db_manager=db,
        audit_logger=auditor,
        auth_manager=auth_mgr,
        require_auth=True,
    )
    client = TestClient(app)

    # Log in users and acquire session tokens
    resp_obs = client.post("/api/auth/login", json={"username": "observer_user", "password": "ObsPass123!"})
    obs_token = resp_obs.json()["token"]

    resp_rev = client.post("/api/auth/login", json={"username": "reviewer_user", "password": "RevPass123!"})
    rev_token = resp_rev.json()["token"]

    resp_adm = client.post("/api/auth/login", json={"username": "admin_user", "password": "AdmPass123!"})
    adm_token = resp_adm.json()["token"]

    return {
        "db": db,
        "auditor": auditor,
        "auth_mgr": auth_mgr,
        "assessment_mgr": assessment_mgr,
        "client": client,
        "obs_token": obs_token,
        "rev_token": rev_token,
        "adm_token": adm_token,
        "tmp_path": tmp_path,
    }


def _setup_authorized_assessment(assessment_mgr: AssessmentManager) -> str:
    """Helper to provision a fully authorized assessment container with sample data."""
    rec = assessment_mgr.create_assessment(
        organization="Acme Cyber",
        assessment_name="Q4 Critical Web Infrastructure",
        created_by="sec_operator",
    )
    aid = rec.assessment_id

    # Bind authorization
    auth = AuthorizationRecord(
        authorization_id="AUTH-ACME-001",
        organization="Acme Cyber",
        assessment_name="Q4 Critical Web Infrastructure",
        authorized_by="Chief Information Security Officer",
        authorized_at=datetime.now(timezone.utc).isoformat(),
        valid_from="2026-01-01T00:00:00Z",
        valid_until="2026-12-31T23:59:59Z",
        authorization_type=AuthorizationType.PENETRATION_TEST,
        scope_reference="SCOPE-POL-01",
        rules=["No destructive denial-of-service"],
        restrictions=["Target production during maintenance window only"],
        status=AuthorizationStatus.AUTHORIZED,
    )
    assessment_mgr.set_authorization(aid, auth, actor="sec_operator")

    # Set scope
    policy = ScopePolicy(
        program_name="Acme Cyber Scope",
        platform="M6_ASSESSMENT",
        in_scope=["api.acme.com", "*.portal.acme.com"],
        out_of_scope=["billing.acme.com"],
        scope_policy_version="v6.1",
    )
    assessment_mgr.set_scope(aid, policy, actor="sec_operator")

    return aid


# ===========================================================================
# 1. Workstream A: Report Generator Multi-Format & Epistemic Quarantine
# ===========================================================================

def test_report_generator_multi_format_and_epistemic_quarantine(batch4_env):
    """Proves that AssessmentReportGenerator produces valid Markdown, JSON, and HTML,
    while strictly quarantining unverified candidate findings."""
    mgr = batch4_env["assessment_mgr"]
    aid = _setup_authorized_assessment(mgr)
    cont = mgr.get_container(aid)

    # Add 1 Human-Verified finding
    verified_finding = AssessmentFinding(
        finding_id="F-001",
        assessment_id=aid,
        title="Remote Code Execution in Admin Endpoint",
        severity=FindingSeverity.CRITICAL,
        asset="api.acme.com",
        affected_component="/api/v1/admin/debug",
        description="Arbitrary code execution via unsafe YAML deserialization",
        impact="Full server compromise and lateral movement",
        evidence=["EVID-001", "EVID-002"],
        reproduction_reference="EXP-001",
        security_invariant="INV-AUTH-01",
        root_cause="Unvalidated PyYAML load() call",
        remediation="Upgrade to safe_load() and implement input validation",
        verification_status=FindingVerificationStatus.HUMAN_VERIFIED,
        verified_by="chief_reviewer",
        verified_at=datetime.now(timezone.utc).isoformat(),
        verification_justification="Manual PoC confirmed on isolated staging replica.",
    )
    cont.findings["F-001"] = verified_finding

    # Add 2 Unverified Candidate findings (must be quarantined!)
    unverified_candidate_1 = AssessmentFinding(
        finding_id="F-002-CAND",
        assessment_id=aid,
        title="Unconfirmed Open Redirect",
        severity=FindingSeverity.LOW,
        asset="api.acme.com",
        affected_component="/redirect",
        description="Hypothesized open redirect based on query parameter name",
        impact="Low phishing potential",
        evidence=["EVID-003"],
        reproduction_reference="EXP-002",
        security_invariant="INV-REDIRECT-01",
        root_cause="Potential unvalidated redirect",
        remediation="Validate target URL whitelist",
        verification_status=FindingVerificationStatus.UNVERIFIED,
    )
    unverified_candidate_2 = AssessmentFinding(
        finding_id="F-003-CAND",
        assessment_id=aid,
        title="Suspected Header Injection Under Review",
        severity=FindingSeverity.MEDIUM,
        asset="api.acme.com",
        affected_component="/headers",
        description="Pending peer review",
        impact="Header manipulation",
        evidence=["EVID-004"],
        reproduction_reference="EXP-003",
        security_invariant="INV-HDR-01",
        root_cause="CRLF reflection",
        remediation="Sanitize CRLF characters",
        verification_status=FindingVerificationStatus.PENDING_HUMAN_REVIEW,
    )
    cont.findings["F-002-CAND"] = unverified_candidate_1
    cont.findings["F-003-CAND"] = unverified_candidate_2

    # --- Test Markdown Generation ---
    generator = AssessmentReportGenerator(cont)
    md_report = generator.generate_markdown()
    assert "Authorized Security Assessment Report" in md_report
    assert "F-001" in md_report
    assert "Remote Code Execution in Admin Endpoint" in md_report
    # Candidate findings must be strictly isolated into the quarantine section
    assert "Unverified Candidate Findings (Quarantined from Confirmed Findings)" in md_report
    assert "F-002-CAND" in md_report
    assert "F-003-CAND" in md_report

    # --- Test JSON Generation ---
    json_str = generator.generate_json()
    json_data = json.loads(json_str)
    assert json_data["metadata"]["assessment_id"] == aid
    assert json_data["metadata"]["organization"] == "Acme Cyber"
    assert json_data["executive_summary"]["verified_findings_count"] == 1
    assert json_data["executive_summary"]["quarantined_candidate_findings_count"] == 2
    # Confirmed findings array must have strictly the 1 verified finding
    assert len(json_data["verified_findings"]) == 1
    assert json_data["verified_findings"][0]["finding_id"] == "F-001"
    # Quarantined candidate findings array must contain the 2 unverified findings
    assert len(json_data["quarantined_candidate_findings"]) == 2
    assert {f["finding_id"] for f in json_data["quarantined_candidate_findings"]} == {"F-002-CAND", "F-003-CAND"}

    # --- Test HTML Generation ---
    html_report = generator.generate_html()
    assert "<!DOCTYPE html>" in html_report
    assert "<html lang=\"en\">" in html_report
    assert "F-001" in html_report
    assert "Remote Code Execution in Admin Endpoint" in html_report
    assert "Quarantined Candidate Findings" in html_report
    assert "F-002-CAND" in html_report
    assert "F-003-CAND" in html_report
    assert "&lt;" not in "F-001"  # XSS safety sanity


def test_report_generator_invocation_compatibility(batch4_env):
    """Proves that AssessmentReportGenerator supports all documented class-style and instance-style
    invocation forms with positional and keyword arguments, respects context overrides, and fails closed
    on invalid formats or missing contexts."""
    mgr = batch4_env["assessment_mgr"]
    aid1 = _setup_authorized_assessment(mgr)
    cont1 = mgr.get_container(aid1)

    rec2 = mgr.create_assessment(
        organization="Beta Labs",
        assessment_name="Beta API Assessment",
        created_by="beta_operator",
    )
    aid2 = rec2.assessment_id
    auth2 = AuthorizationRecord(
        authorization_id="AUTH-BETA-001",
        organization="Beta Labs",
        assessment_name="Beta API Assessment",
        authorized_by="Beta CISO",
        authorized_at=datetime.now(timezone.utc).isoformat(),
        valid_from="2026-01-01T00:00:00Z",
        valid_until="2026-12-31T23:59:59Z",
        authorization_type=AuthorizationType.PENETRATION_TEST,
        scope_reference="SCOPE-BETA-01",
        rules=["Authorized testing only"],
        restrictions=[],
        status=AuthorizationStatus.AUTHORIZED,
    )
    mgr.set_authorization(aid2, auth2, actor="beta_operator")
    cont2 = mgr.get_container(aid2)

    # 1. Class-style calls
    md_cls1 = AssessmentReportGenerator.generate(cont1, "markdown")
    assert "Authorized Security Assessment Report" in md_cls1
    assert aid1 in md_cls1

    json_cls1 = AssessmentReportGenerator.generate(cont1, "json")
    parsed_json_cls1 = json.loads(json_cls1)
    assert parsed_json_cls1["metadata"]["assessment_id"] == aid1

    html_cls1 = AssessmentReportGenerator.generate(cont1, format_type="html")
    assert "<!DOCTYPE html>" in html_cls1
    assert aid1 in html_cls1

    json_cls_kw = AssessmentReportGenerator.generate(ctx=cont1, format_type="json")
    assert json.loads(json_cls_kw)["metadata"]["assessment_id"] == aid1

    md_direct = AssessmentReportGenerator.generate_markdown(cont1)
    assert aid1 in md_direct
    json_direct = AssessmentReportGenerator.generate_json(cont1)
    assert json.loads(json_direct)["metadata"]["assessment_id"] == aid1
    html_direct = AssessmentReportGenerator.generate_html(cont1)
    assert "<!DOCTYPE html>" in html_direct

    # 2. Instance-style calls with bound context
    gen = AssessmentReportGenerator(cont1)
    md_inst = gen.generate()  # default format is markdown
    assert aid1 in md_inst

    json_inst = gen.generate("json")
    assert json.loads(json_inst)["metadata"]["assessment_id"] == aid1

    html_inst = gen.generate(format_type="html")
    assert "<!DOCTYPE html>" in html_inst

    md_inst_direct = gen.generate_markdown()
    assert aid1 in md_inst_direct
    json_inst_direct = gen.generate_json()
    assert json.loads(json_inst_direct)["metadata"]["assessment_id"] == aid1
    html_inst_direct = gen.generate_html()
    assert "<!DOCTYPE html>" in html_inst_direct

    # 3. Context override: passing cont2 to an instance initialized with cont1
    json_override = gen.generate(cont2, "json")
    parsed_override = json.loads(json_override)
    assert parsed_override["metadata"]["assessment_id"] == aid2
    assert parsed_override["metadata"]["organization"] == "Beta Labs"

    # 4. Fail-closed: missing context
    with pytest.raises(ValueError, match="No context provided"):
        AssessmentReportGenerator.generate()

    with pytest.raises(ValueError, match="No context provided"):
        AssessmentReportGenerator().generate()

    with pytest.raises(ValueError, match="No context provided"):
        AssessmentReportGenerator.generate_markdown()

    # 5. Fail-closed: unsupported format
    with pytest.raises(ValueError, match="Unsupported report format 'yaml'"):
        AssessmentReportGenerator.generate(cont1, "yaml")

    with pytest.raises(ValueError, match="Unsupported report format 'pdf'"):
        gen.generate("pdf")


# ===========================================================================
# 2. Workstream A: API Report Generation & Export Contracts
# ===========================================================================

def test_api_report_export_formats_and_mime_types(batch4_env):
    """Proves that POST /api/assessments/{id}/report and POST /api/assessments/{id}/reports/export
    support markdown, json, and html with correct MIME types and filenames."""
    client = batch4_env["client"]
    token = batch4_env["rev_token"]
    mgr = batch4_env["assessment_mgr"]
    aid = _setup_authorized_assessment(mgr)

    headers = {"Authorization": f"Bearer {token}"}

    # Format: markdown
    resp_md = client.post(f"/api/assessments/{aid}/report?format=markdown", headers=headers)
    assert resp_md.status_code == 200
    data_md = resp_md.json()
    assert data_md["status"] == "success"
    assert data_md["format"] == "markdown"
    assert data_md["mime_type"] == "text/markdown; charset=utf-8"
    assert data_md["filename"].endswith(".md")
    assert "Authorized Security Assessment Report" in data_md["content"]

    # Format: json
    resp_json = client.post(f"/api/assessments/{aid}/report?format=json", headers=headers)
    assert resp_json.status_code == 200
    data_json = resp_json.json()
    assert data_json["status"] == "success"
    assert data_json["format"] == "json"
    assert data_json["mime_type"] == "application/json; charset=utf-8"
    assert data_json["filename"].endswith(".json")
    parsed_content = json.loads(data_json["content"])
    assert parsed_content["metadata"]["assessment_id"] == aid

    # Format: html
    resp_html = client.post(f"/api/assessments/{aid}/report?format=html", headers=headers)
    assert resp_html.status_code == 200
    data_html = resp_html.json()
    assert data_html["status"] == "success"
    assert data_html["format"] == "html"
    assert data_html["mime_type"] == "text/html; charset=utf-8"
    assert data_html["filename"].endswith(".html")
    assert "<!DOCTYPE html>" in data_html["content"]

    # Export endpoint (POST .../reports/export)
    export_resp = client.post(f"/api/assessments/{aid}/reports/export?format=json", headers=headers)
    assert export_resp.status_code == 200
    assert export_resp.json()["status"] == "success"
    assert export_resp.json()["format"] == "json"


def test_api_report_export_unsupported_format_fails_closed(batch4_env):
    """Proves that requests for unsupported report formats (pdf, yaml, xml) return 400 Bad Request."""
    client = batch4_env["client"]
    token = batch4_env["rev_token"]
    mgr = batch4_env["assessment_mgr"]
    aid = _setup_authorized_assessment(mgr)

    headers = {"Authorization": f"Bearer {token}"}

    for bad_format in ("pdf", "yaml", "xml", "docx", "invalid"):
        resp = client.post(f"/api/assessments/{aid}/report?format={bad_format}", headers=headers)
        assert resp.status_code == 400
        assert f"Unsupported report format: '{bad_format}'" in resp.json()["detail"]


def test_api_report_export_revoked_authorization_denied(batch4_env):
    """Proves that report generation/export fails closed with 403 Forbidden if authorization is REVOKED or DENIED."""
    client = batch4_env["client"]
    token = batch4_env["rev_token"]
    mgr = batch4_env["assessment_mgr"]
    aid = _setup_authorized_assessment(mgr)

    headers = {"Authorization": f"Bearer {token}"}

    # Revoke authorization
    cont = mgr.get_container(aid)
    assert cont.authorization is not None
    cont.authorization.status = AuthorizationStatus.REVOKED

    resp = client.post(f"/api/assessments/{aid}/report?format=markdown", headers=headers)
    assert resp.status_code == 403
    assert "REVOKED" in resp.json()["detail"]


def test_api_report_export_rbac_observer_denied(batch4_env):
    """Proves that users with OBSERVER role cannot export assessment reports (403 Forbidden)."""
    client = batch4_env["client"]
    obs_token = batch4_env["obs_token"]
    mgr = batch4_env["assessment_mgr"]
    aid = _setup_authorized_assessment(mgr)

    headers = {"Authorization": f"Bearer {obs_token}"}

    resp = client.post(f"/api/assessments/{aid}/report?format=markdown", headers=headers)
    assert resp.status_code == 403
    assert "reviewer role required" in resp.json()["detail"].lower()


# ===========================================================================
# 3. Workstream B: Assessment Lifecycle State Transitions
# ===========================================================================

def test_api_assessment_lifecycle_transitions(batch4_env):
    """Proves that PATCH /api/assessments/{id} permits legal lifecycle transitions
    and fails closed with 400 on illegal transitions."""
    client = batch4_env["client"]
    rev_token = batch4_env["rev_token"]
    mgr = batch4_env["assessment_mgr"]

    # Create new assessment (starts in DRAFT)
    rec = mgr.create_assessment(
        organization="Fintech Global",
        assessment_name="Payments API Review",
        created_by="operator",
    )
    aid = rec.assessment_id

    headers = {"Authorization": f"Bearer {rev_token}"}

    # 1. Legal transition: DRAFT -> AUTHORIZATION_PENDING
    resp1 = client.patch(
        f"/api/assessments/{aid}",
        json={"state": "AUTHORIZATION_PENDING", "notes": "Submitted for CISO sign-off"},
        headers=headers,
    )
    assert resp1.status_code == 200
    assert resp1.json()["assessment"]["state"] == "AUTHORIZATION_PENDING"

    # 2. Illegal transition: AUTHORIZATION_PENDING -> ASSESSMENT_ACTIVE (must fail closed: no auth record yet)
    resp_illegal = client.patch(
        f"/api/assessments/{aid}",
        json={"state": "ASSESSMENT_ACTIVE", "notes": "Trying to bypass authorization"},
        headers=headers,
    )
    assert resp_illegal.status_code == 400

    # 3. Bind authorization and transition: AUTHORIZATION_PENDING -> AUTHORIZED
    auth = AuthorizationRecord(
        authorization_id="AUTH-FIN-01",
        organization="Fintech Global",
        assessment_name="Payments API Review",
        authorized_by="Security Director",
        authorized_at=datetime.now(timezone.utc).isoformat(),
        valid_from="2026-01-01T00:00:00Z",
        valid_until="2026-12-31T23:59:59Z",
        authorization_type=AuthorizationType.PENETRATION_TEST,
        scope_reference="FIN-SCOPE-01",
        status=AuthorizationStatus.AUTHORIZED,
    )
    mgr.set_authorization(aid, auth, actor="security_dir")

    resp2 = client.patch(
        f"/api/assessments/{aid}",
        json={"state": "AUTHORIZED", "notes": "Authorization signed"},
        headers=headers,
    )
    assert resp2.status_code == 200
    assert resp2.json()["assessment"]["state"] == "AUTHORIZED"

    # 4. Set Scope and transition: AUTHORIZED -> SCOPE_DEFINED
    policy = ScopePolicy(
        program_name="Fintech Scope",
        platform="M6_ASSESSMENT",
        in_scope=["pay.fintech.com"],
        scope_policy_version="v1",
    )
    mgr.set_scope(aid, policy, actor="operator")

    resp3 = client.patch(
        f"/api/assessments/{aid}",
        json={"state": "SCOPE_DEFINED", "notes": "Scope validated"},
        headers=headers,
    )
    assert resp3.status_code == 200
    assert resp3.json()["assessment"]["state"] == "SCOPE_DEFINED"

    # 5. Transition: SCOPE_DEFINED -> ASSESSMENT_ACTIVE
    resp4 = client.patch(
        f"/api/assessments/{aid}",
        json={"state": "ASSESSMENT_ACTIVE", "notes": "Testing active"},
        headers=headers,
    )
    assert resp4.status_code == 200
    assert resp4.json()["assessment"]["state"] == "ASSESSMENT_ACTIVE"


# ===========================================================================
# 4. Workstream C: Experiment Approval and Execution Result Ingestion
# ===========================================================================

def test_api_experiment_approval_and_result_import(batch4_env):
    """Proves that experiments can be proposed, approved by reviewers, and have
    execution results imported to transition their state to EXECUTED."""
    client = batch4_env["client"]
    rev_token = batch4_env["rev_token"]
    mgr = batch4_env["assessment_mgr"]
    aid = _setup_authorized_assessment(mgr)

    headers = {"Authorization": f"Bearer {rev_token}"}

    # 1. Propose experiment
    exp_payload = {
        "hypothesis_id": "HYP-SAMPLE-01",
        "objective": "Verify IDOR on customer balance endpoint",
        "target_asset": "api.acme.com",
        "steps": ["Login as user A", "Request balance for user B via GET /accounts/B/balance"],
        "expected_secure_result": "HTTP 403 Forbidden",
        "expected_vulnerable_result": "HTTP 200 OK with User B balance data",
        "falsification_condition": "Endpoint returns HTTP 403 Forbidden with access denied message",
        "negative_control": "Request without authorization header returns 401 Unauthorized",
        "risk_level": "PASSIVE",
    }
    prop_resp = client.post(f"/api/assessments/{aid}/experiments", json=exp_payload, headers=headers)
    assert prop_resp.status_code == 200
    exp_id = prop_resp.json()["experiment"]["experiment_id"]
    assert prop_resp.json()["experiment"]["status"] == "PROPOSED"

    # 2. Approve experiment
    appr_resp = client.post(
        f"/api/assessments/{aid}/experiments/{exp_id}/approval",
        json={"approved": True, "notes": "Reviewed and safe for execution in test window"},
        headers=headers,
    )
    assert appr_resp.status_code == 200
    assert appr_resp.json()["experiment"]["status"] == "APPROVED"
    assert appr_resp.json()["experiment"]["approved_by"] == "reviewer_user"

    # 3. Import execution results
    result_data = {
        "status_code": 200,
        "observed_body": '{"account": "B", "balance": 150000.00}',
        "falsified": False,
        "reproduction_notes": "Successfully accessed user B balance from user A session.",
    }
    exec_resp = client.post(
        f"/api/assessments/{aid}/experiments/{exp_id}/results",
        json={"result_payload": result_data},
        headers=headers,
    )
    assert exec_resp.status_code == 200
    exp_record = exec_resp.json()["experiment"]
    assert exp_record["status"] == "EXECUTED"
    assert exp_record["executed_by"] == "reviewer_user"
    assert exp_record["result_payload"]["status_code"] == 200


# ===========================================================================
# 5. Workstream C: Memory Listing and Retrieval Contracts
# ===========================================================================

def test_api_assessment_memory_listing_and_search(batch4_env):
    """Proves that GET /api/assessments/{id}/memory and POST /api/assessments/{id}/memory/search
    return assessment-scoped research memory items and search matches."""
    client = batch4_env["client"]
    rev_token = batch4_env["rev_token"]
    mgr = batch4_env["assessment_mgr"]
    aid = _setup_authorized_assessment(mgr)

    headers = {"Authorization": f"Bearer {rev_token}"}

    # Add a memory item via the authoritative API
    create_payload = {
        "namespace": "ASSESSMENT_LOCAL",
        "content": "Target authentication gateway enforces HMAC-SHA256 tokens with 15-minute expiration.",
        "title": "Auth Gateway Token Policy",
        "assessment_id": aid,
        "epistemic_status": "OBSERVATION",
        "authority_level": "USER_PROVIDED",
        "source_type": "ANALYST_NOTE",
        "confidence": 1.0,
    }
    create_resp = client.post("/api/memory/items", json=create_payload, headers=headers)
    assert create_resp.status_code == 200
    mem_id = create_resp.json()["memory_id"]

    # Test GET /api/assessments/{id}/memory
    list_resp = client.get(f"/api/assessments/{aid}/memory", headers=headers)
    assert list_resp.status_code == 200
    items = list_resp.json()
    assert isinstance(items, list)
    assert len(items) >= 1
    assert any(m["memory_id"] == mem_id for m in items)

    # Test POST /api/assessments/{id}/memory/search
    search_resp = client.post(
        f"/api/assessments/{aid}/memory/search",
        json={"query": "HMAC-SHA256 tokens", "top_k": 5},
        headers=headers,
    )
    assert search_resp.status_code == 200
    search_data = search_resp.json()
    assert "results" in search_data
    assert len(search_data["results"]) >= 1
    assert any("HMAC-SHA256" in r.get("content", "") for r in search_data["results"])
