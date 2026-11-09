"""
ULTRON — Batch 1 Security Boundaries Remediation Test Suite.

Tests authoritative enforcement across the six Batch 1 workstreams:
1. Complete backend authentication and RBAC role matrix (401/403/200).
2. Session and auth endpoints (/api/auth/login, /api/auth/me, /api/auth/logout).
3. Genuine artifact upload, server-computed SHA-256 and byte size, quarantine by default, and path traversal defense.
4. Multi-investigation audit log isolation (no cross-investigation leakage).
5. Experiment approval enforcement before result import and actor binding.
6. Validation-first finding verification with atomic rollback.
"""

import base64
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import pytest
from starlette.testclient import TestClient

from src.core.logging import AuditLogger
from src.database.manager import DatabaseManager
from src.dashboard.app import (
    DashboardAuthManager,
    DashboardRole,
    create_dashboard_app,
)
from src.assessment.manager import AssessmentManager
from src.assessment.models import (
    AssessmentLifecycleState,
    AssessmentFinding,
    AssetType,
    AssessmentScopeStatus,
    AuthorizationRecord,
    AuthorizationStatus,
    AuthorizationType,
    ExperimentStatus,
    FindingSeverity,
    FindingVerificationStatus,
)
from src.scope.models import ScopePolicy
from src.artifacts.metadata import QuarantineStatus, TrustStatus


@pytest.fixture
def b1_env(tmp_path: Path):
    db_file = tmp_path / "b1_test.db"
    db = DatabaseManager(db_path=db_file)
    db.initialize_schema()

    audit_file = tmp_path / "b1_audit.log"
    auditor = AuditLogger(audit_file)

    auth_mgr = DashboardAuthManager(db_manager=db)
    observer_sess = auth_mgr.create_session("alice_obs", DashboardRole.OBSERVER, token="tok_obs_001")
    reviewer_sess = auth_mgr.create_session("bob_rev", DashboardRole.REVIEWER, token="tok_rev_002")
    admin_sess = auth_mgr.create_session("carol_adm", DashboardRole.ADMIN, token="tok_adm_003")

    app = create_dashboard_app(
        db_manager=db,
        audit_logger=auditor,
        auth_manager=auth_mgr,
        require_auth=True,
    )
    client = TestClient(app)

    return {
        "db": db,
        "auditor": auditor,
        "auth_mgr": auth_mgr,
        "app": app,
        "client": client,
        "observer_token": observer_sess.token,
        "reviewer_token": reviewer_sess.token,
        "admin_token": admin_sess.token,
        "tmp_path": tmp_path,
    }


def _setup_authorized_assessment(client: TestClient, reviewer_token: str, asm_id_prefix: str = "TARGET"):
    headers = {"Authorization": f"Bearer {reviewer_token}"}
    create_res = client.post(
        "/api/assessments",
        headers=headers,
        json={"organization": f"Acme_{asm_id_prefix}", "assessment_name": f"Security Review {asm_id_prefix}"},
    )
    assert create_res.status_code == 200, create_res.text
    assessment_id = create_res.json()["assessment"]["assessment_id"]

    # Bind authorization
    now = datetime.now(timezone.utc)
    auth_payload = {
        "organization": f"Acme_{asm_id_prefix}",
        "assessment_name": f"Security Review {asm_id_prefix}",
        "authorized_by": "General Counsel",
        "valid_from": (now - timedelta(days=1)).isoformat(),
        "valid_until": (now + timedelta(days=30)).isoformat(),
        "authorization_type": "PENETRATION_TEST",
        "scope_reference": f"SCOPE-{asm_id_prefix}",
        "status": "AUTHORIZED",
    }
    auth_res = client.post(f"/api/assessments/{assessment_id}/authorization", headers=headers, json=auth_payload)
    assert auth_res.status_code == 200, auth_res.text

    # Bind scope
    scope_payload = {
        "program_name": f"Prog_{asm_id_prefix}",
        "platform": "HackerOne",
        "in_scope": ["api.target.com", "*.target.com"],
        "out_of_scope": ["billing.target.com"],
    }
    scope_res = client.post(f"/api/assessments/{assessment_id}/scope", headers=headers, json=scope_payload)
    assert scope_res.status_code == 200, scope_res.text

    return assessment_id


# ===========================================================================
# Workstream A: Complete Authentication & RBAC
# ===========================================================================

def test_missing_credentials_fails_closed_across_assessment_routes(b1_env):
    """When require_auth=True, missing credentials return HTTP 401 across all protected routes."""
    client = b1_env["client"]

    # GET routes
    assert client.get("/api/assessments").status_code == 401
    assert client.get("/api/assessments/ASM-FAKE/workspace").status_code == 401
    assert client.get("/api/assessments/ASM-FAKE/artifacts").status_code == 401
    assert client.get("/api/assessments/ASM-FAKE/findings").status_code == 401
    assert client.get("/api/audit/ASM-FAKE").status_code == 401

    # State-changing routes
    assert client.post("/api/assessments", json={"organization": "X", "assessment_name": "Y"}).status_code == 401
    assert client.post("/api/assessments/ASM-FAKE/findings", json={"title": "T", "asset": "A"}).status_code == 401
    assert client.post("/api/findings/FIND-FAKE/verify", json={"justification": "test"}).status_code == 401
    assert client.post("/api/experiments/EXP-FAKE/result", json={"result_payload": {}}).status_code == 401


def test_invalid_expired_and_revoked_session_tokens_fail_closed(b1_env):
    """Invalid, expired, and revoked tokens return HTTP 401."""
    client = b1_env["client"]
    auth_mgr = b1_env["auth_mgr"]

    # Invalid
    res_inv = client.get("/api/assessments", headers={"Authorization": "Bearer bad_token_xyz"})
    assert res_inv.status_code == 401

    # Expired
    exp_sess = auth_mgr.create_session("temp_user", DashboardRole.REVIEWER, ttl_seconds=-5)
    res_exp = client.get("/api/assessments", headers={"Authorization": f"Bearer {exp_sess.token}"})
    assert res_exp.status_code == 401
    assert "expired" in res_exp.json()["detail"].lower()

    # Revoked
    rev_sess = auth_mgr.create_session("rev_user", DashboardRole.REVIEWER)
    auth_mgr.revoke_session(rev_sess.token)
    res_rev = client.get("/api/assessments", headers={"Authorization": f"Bearer {rev_sess.token}"})
    assert res_rev.status_code == 401
    assert "revoked" in res_rev.json()["detail"].lower()


def test_rbac_role_matrix_observer_denied_state_mutation(b1_env):
    """Observer can read but is strictly forbidden from mutating state (HTTP 403)."""
    client = b1_env["client"]
    obs_headers = {"Authorization": f"Bearer {b1_env['observer_token']}"}

    # Observer can read assessments list
    res_read = client.get("/api/assessments", headers=obs_headers)
    assert res_read.status_code == 200

    # Observer cannot create assessment
    res_create = client.post(
        "/api/assessments",
        headers=obs_headers,
        json={"organization": "Org", "assessment_name": "Asm"},
    )
    assert res_create.status_code == 403
    assert "reviewer role required" in res_create.json()["detail"].lower()

    # Observer cannot verify finding
    res_verify = client.post(
        "/api/findings/FIND-XYZ/verify",
        headers=obs_headers,
        json={"human_reviewer": "alice_obs", "justification": "Valid finding verified"},
    )
    assert res_verify.status_code == 403


def test_session_login_and_cookie_authentication(b1_env):
    """Login issues session token and cookie, and cookie authorizes requests."""
    client = b1_env["client"]

    # 1. Provision user in database with password hash
    from src.dashboard.auth import hash_password
    b1_env["db"].create_user("dr_security", hash_password("ValidPassword123!"), role="reviewer")

    # 2. Login with valid password
    login_res = client.post("/api/auth/login", json={"username": "dr_security", "password": "ValidPassword123!"})
    assert login_res.status_code == 200
    login_data = login_res.json()
    assert login_data["username"] == "dr_security"
    assert login_data["role"] == "reviewer"
    token = login_data["token"]
    assert len(token) > 20

    # 2. Check /api/auth/me with Bearer token
    me_res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_res.status_code == 200
    assert me_res.json()["username"] == "dr_security"

    # 3. Check authentication via session_token Cookie
    cookie_client = TestClient(b1_env["app"], cookies={"session_token": token})
    res_cookie = cookie_client.get("/api/assessments")
    assert res_cookie.status_code == 200

    # 4. Logout revokes token
    logout_res = client.post("/api/auth/logout", headers={"Authorization": f"Bearer {token}"})
    assert logout_res.status_code == 200
    assert logout_res.json()["logged_out"] is True

    # 5. Post-logout request fails 401
    post_res = client.get("/api/assessments", headers={"Authorization": f"Bearer {token}"})
    assert post_res.status_code == 401


def test_actor_attribution_derived_from_authenticated_session(b1_env):
    """Client-supplied created_by is ignored in favor of authenticated session username."""
    client = b1_env["client"]
    headers = {"Authorization": f"Bearer {b1_env['reviewer_token']}"}

    # Attempt to spoof creator as 'attacker_lead'
    res = client.post(
        "/api/assessments",
        headers=headers,
        json={
            "organization": "SpoofCorp",
            "assessment_name": "Test Attribution",
            "created_by": "attacker_lead",
        },
    )
    assert res.status_code == 200
    created = res.json()["assessment"]
    # Server authoritatively overwrote created_by with bob_rev (the session user)
    assert created["created_by"] == "bob_rev"
    assert created["created_by"] != "attacker_lead"


# ===========================================================================
# Workstream B: Genuine Artifact Ingestion, Hashing & Quarantine
# ===========================================================================

def test_artifact_upload_computes_sha256_and_quarantines_by_default(b1_env):
    """Uploading actual bytes computes authoritative SHA-256 and sets QUARANTINED."""
    client = b1_env["client"]
    reviewer_token = b1_env["reviewer_token"]
    asm_id = _setup_authorized_assessment(client, reviewer_token, "ART1")
    headers = {"Authorization": f"Bearer {reviewer_token}"}

    sample_content = b"GET /admin/users HTTP/1.1\r\nHost: api.target.com\r\nAuthorization: Bearer test\r\n\r\n"
    expected_sha256 = hashlib.sha256(sample_content).hexdigest()
    expected_size = len(sample_content)

    upload_res = client.post(
        f"/api/assessments/{asm_id}/artifacts/upload?filename=traffic.har&artifact_type=HAR",
        headers={**headers, "Content-Type": "application/octet-stream"},
        content=sample_content,
    )
    assert upload_res.status_code == 200, upload_res.text
    data = upload_res.json()
    artifact = data["artifact"]

    assert artifact["sha256"] == expected_sha256
    assert artifact["size_bytes"] == expected_size
    assert artifact["quarantine_status"] == QuarantineStatus.QUARANTINED.value
    assert artifact["trust_status"] == TrustStatus.QUARANTINED.value
    assert artifact["filename"] == "traffic.har"
    assert artifact["artifact_id"].startswith("ART-")

    # Verify safe download returns exact bytes
    download_res = client.get(
        f"/api/assessments/{asm_id}/artifacts/{artifact['artifact_id']}/download",
        headers=headers,
    )
    assert download_res.status_code == 200
    assert download_res.content == sample_content


def test_empty_artifact_upload_fails_closed(b1_env):
    """0-byte uploads are rejected with HTTP 400."""
    client = b1_env["client"]
    reviewer_token = b1_env["reviewer_token"]
    asm_id = _setup_authorized_assessment(client, reviewer_token, "EMPTY")
    headers = {"Authorization": f"Bearer {reviewer_token}", "Content-Type": "application/octet-stream"}

    res = client.post(
        f"/api/assessments/{asm_id}/artifacts/upload?filename=empty.bin",
        headers=headers,
        content=b"",
    )
    assert res.status_code == 400
    assert "empty artifact" in res.json()["detail"].lower()


def test_artifact_digest_mismatch_fails_closed(b1_env):
    """Client-declared SHA-256 mismatch is rejected with HTTP 400."""
    client = b1_env["client"]
    reviewer_token = b1_env["reviewer_token"]
    asm_id = _setup_authorized_assessment(client, reviewer_token, "MISMATCH")
    headers = {"Authorization": f"Bearer {reviewer_token}"}

    payload_bytes = b"real content"
    b64_content = base64.b64encode(payload_bytes).decode()
    fake_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"

    res = client.post(
        f"/api/assessments/{asm_id}/artifacts",
        headers=headers,
        json={
            "filename": "fake_hash.bin",
            "content_b64": b64_content,
            "sha256": fake_sha256,
            "quarantine_status": "CLEARED",  # Attempt to force cleared
        },
    )
    assert res.status_code == 400
    assert "integrity check failed" in res.json()["detail"].lower()


def test_unverified_metadata_only_artifact_registration_rejected(b1_env):
    """Registering artifact metadata without bytes/content is rejected."""
    client = b1_env["client"]
    reviewer_token = b1_env["reviewer_token"]
    asm_id = _setup_authorized_assessment(client, reviewer_token, "METADATA")
    headers = {"Authorization": f"Bearer {reviewer_token}"}

    res = client.post(
        f"/api/assessments/{asm_id}/artifacts",
        headers=headers,
        json={"filename": "phantom.bin"},  # No content_b64
    )
    assert res.status_code == 400
    assert "genuine file content" in res.json()["detail"].lower()


def test_artifact_path_traversal_sanitized(b1_env):
    """Adversarial filename with directory traversal characters is safely sanitized."""
    client = b1_env["client"]
    reviewer_token = b1_env["reviewer_token"]
    asm_id = _setup_authorized_assessment(client, reviewer_token, "TRAVERSAL")
    headers = {"Authorization": f"Bearer {reviewer_token}", "Content-Type": "application/octet-stream"}

    res = client.post(
        f"/api/assessments/{asm_id}/artifacts/upload?filename=../../../../etc/passwd",
        headers=headers,
        content=b"test data",
    )
    assert res.status_code == 200
    art = res.json()["artifact"]
    # Path traversal sequences .. and / are sanitized
    assert ".." not in art["filename"]
    assert "/" not in art["filename"]
    assert "\\" not in art["filename"]


# ===========================================================================
# Workstream C: Investigation-Level Audit Isolation
# ===========================================================================

def test_audit_records_isolated_by_investigation(b1_env):
    """Audit queries for investigation A do not return records from investigation B."""
    client = b1_env["client"]
    reviewer_token = b1_env["reviewer_token"]
    observer_token = b1_env["observer_token"]

    asm_a = _setup_authorized_assessment(client, reviewer_token, "ALPHA")
    asm_b = _setup_authorized_assessment(client, reviewer_token, "BETA")

    obs_headers = {"Authorization": f"Bearer {observer_token}"}

    # Query audit for ASM-A
    res_a = client.get(f"/api/audit/{asm_a}", headers=obs_headers)
    assert res_a.status_code == 200, res_a.text
    data_a = res_a.json()
    assert data_a["investigation_id"] == asm_a
    assert data_a["chain_integrity"] == "VERIFIED"

    records_a = data_a["records"]
    assert len(records_a) > 0
    # Confirm none of ASM-B's records leaked into ASM-A
    for rec in records_a:
        assert rec.get("investigation_id") == asm_a or rec.get("details", {}).get("assessment_id") == asm_a

    # Query audit for ASM-B
    res_b = client.get(f"/api/audit/{asm_b}", headers=obs_headers)
    assert res_b.status_code == 200
    data_b = res_b.json()
    assert data_b["investigation_id"] == asm_b
    records_b = data_b["records"]
    assert len(records_b) > 0

    for rec in records_b:
        assert rec.get("investigation_id") == asm_b or rec.get("details", {}).get("assessment_id") == asm_b

    # Verify non-existent investigation returns 404
    res_404 = client.get("/api/audit/INV-NON-EXISTENT-XYZ", headers=obs_headers)
    assert res_404.status_code == 404


# ===========================================================================
# Workstream D: Experiment Approval Enforcement
# ===========================================================================

def test_experiment_result_import_blocked_until_explicitly_approved(b1_env):
    """Result import is rejected for PROPOSED experiment, and succeeds only after explicit approval."""
    client = b1_env["client"]
    reviewer_token = b1_env["reviewer_token"]
    asm_id = _setup_authorized_assessment(client, reviewer_token, "EXP")
    headers = {"Authorization": f"Bearer {reviewer_token}"}

    # Propose experiment
    prop_res = client.post(
        f"/api/assessments/{asm_id}/experiments",
        headers=headers,
        json={
            "hypothesis_id": "HYP-01",
            "objective": "Verify SQL injection",
            "target_asset": "api.target.com",
            "steps": ["Send sleep(5) payload"],
            "expected_secure_result": "Response within 200ms",
            "expected_vulnerable_result": "Response delay > 5000ms",
            "falsification_condition": "Status 500 without delay",
            "negative_control": "Send normal query",
            "risk_level": "PASSIVE",
        },
    )
    assert prop_res.status_code == 200, prop_res.text
    exp_id = prop_res.json()["experiment"]["experiment_id"]
    assert prop_res.json()["experiment"]["status"] == ExperimentStatus.PROPOSED.value

    # 1. Attempt result import while PROPOSED -> MUST BE REJECTED
    res_import_fail = client.post(
        f"/api/experiments/{exp_id}/result",
        headers=headers,
        json={
            "result_payload": {"delay_ms": 5200, "status": 200},
            "executed_by": "spoofed_actor",
        },
    )
    assert res_import_fail.status_code == 400
    assert "only 'approved' experiments can receive results" in res_import_fail.json()["detail"].lower()

    # 2. Approve the experiment explicitly
    approve_res = client.post(
        f"/api/assessments/{asm_id}/experiments/{exp_id}/approve",
        headers=headers,
    )
    assert approve_res.status_code == 200, approve_res.text
    assert approve_res.json()["experiment"]["status"] == ExperimentStatus.APPROVED.value

    # 3. Import result after approval -> SUCCEEDS
    res_import_ok = client.post(
        f"/api/experiments/{exp_id}/result",
        headers=headers,
        json={
            "result_payload": {"delay_ms": 5200, "status": 200},
            "executed_by": "spoofed_actor",
        },
    )
    assert res_import_ok.status_code == 200, res_import_ok.text
    exp_data = res_import_ok.json()["experiment"]
    assert exp_data["status"] == ExperimentStatus.EXECUTED.value
    # Actor attribution authoritatively bound to authenticated session (bob_rev), not spoofed_actor
    assert exp_data["executed_by"] == "bob_rev"


# ===========================================================================
# Workstream E: Validation-First Finding Verification & Atomic Rollback
# ===========================================================================

def test_finding_verification_validation_first_and_atomic_rollback(b1_env):
    """Failed validation prevents state mutation; finding status remains UNVERIFIED."""
    client = b1_env["client"]
    reviewer_token = b1_env["reviewer_token"]
    asm_id = _setup_authorized_assessment(client, reviewer_token, "FINDING")
    headers = {"Authorization": f"Bearer {reviewer_token}"}

    # Register candidate finding on out-of-scope asset to trigger validation failure
    create_finding_res = client.post(
        f"/api/assessments/{asm_id}/findings",
        headers=headers,
        json={
            "title": "BOLA in Billing Profile",
            "severity": "HIGH",
            "asset": "billing.target.com",  # Explicitly out-of-scope in setup
            "affected_component": "/profile",
            "description": "Cross-tenant access",
            "impact": "Data exposure",
            "evidence": ["OBS-FAKE-01"],
            "reproduction_reference": "REF-01",
            "security_invariant": "INV-AUTH-01",
            "root_cause": "Missing tenant check",
            "remediation": "Validate owner ID",
            "references": [],
        },
    )
    assert create_finding_res.status_code == 200
    fid = create_finding_res.json()["finding"]["finding_id"]

    # Attempt to verify finding on out-of-scope asset -> Validation MUST fail
    verify_res = client.post(
        f"/api/findings/{fid}/verify",
        headers=headers,
        json={
            "human_reviewer": "Lead Reviewer",
            "justification": "Checked reproduction steps and verified out of scope target",
        },
    )
    assert verify_res.status_code == 400
    assert "scope" in verify_res.json()["detail"].lower() or "point 2" in verify_res.json()["detail"].lower()

    # Query finding to prove state was NOT mutated to HUMAN_VERIFIED
    findings_list = client.get(f"/api/assessments/{asm_id}/findings", headers=headers).json()["findings"]
    target_finding = next(f for f in findings_list if f["finding_id"] == fid)
    assert target_finding["verification_status"] == FindingVerificationStatus.UNVERIFIED.value
    assert target_finding["verified_by"] is None
    assert target_finding["verified_at"] is None
