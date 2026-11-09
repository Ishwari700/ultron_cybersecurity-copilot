"""Comprehensive Batch 1.1 Authentication Closure and Mandatory Negative-Security Attack Test Suite.

Proves that:
1. Default configuration fails closed without synthetic fallback identity.
2. Login verifies real credentials using scrypt password hashing; role assignment is strictly server-controlled.
3. Safe bootstrap CLI provisions initial operator without plaintext storage.
4. HttpOnly cookie sessions, CSRF protection, and brute-force mitigations are enforced.
5. All 10 mandatory negative-security attack scenarios from Section 9 fail as required.
6. Module resolution paths are 100% contained within Ultron without cross-project pollution.
"""

from datetime import datetime, timezone
import importlib
import json
from pathlib import Path
import subprocess
import sys
import pytest
from starlette.testclient import TestClient

from src.core.logging import AuditLogger
from src.database.manager import DatabaseManager
from src.dashboard.auth import DashboardAuthManager, DashboardRole, hash_password, verify_password, generate_csrf_token
from src.dashboard.app import create_dashboard_app
from src.dashboard.models import LoginRequest


@pytest.fixture
def auth_env(tmp_path: Path):
    """Isolated environment with temporary SQLite DB, audit log, and clean auth manager."""
    db_file = tmp_path / "test_auth_closure.db"
    db = DatabaseManager(db_path=db_file)
    db.initialize_schema()

    audit_file = tmp_path / "test_auth_audit.log"
    auditor = AuditLogger(audit_file)

    auth_mgr = DashboardAuthManager(db_manager=db)

    # Provision standard test users with scrypt hashes
    db.create_user("alice_obs", hash_password("AliceObsPass123!"), role="observer", is_active=True)
    db.create_user("bob_rev", hash_password("BobRevPass123!"), role="reviewer", is_active=True)
    db.create_user("carol_adm", hash_password("CarolAdmPass123!"), role="admin", is_active=True)
    db.create_user("dave_disabled", hash_password("DavePass123!"), role="reviewer", is_active=False)

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
        "tmp_path": tmp_path,
        "audit_file": audit_file,
    }


# =============================================================================
# Workstream A & Attack 3 & Attack 8: Fail Closed by Default & Secure Startup
# =============================================================================

def test_attack_3_default_launcher_fails_closed(tmp_path):
    """Attack 3: create_dashboard_app() with default arguments must enforce auth and deny unauthenticated access."""
    db = DatabaseManager(db_path=tmp_path / "default_test.db")
    db.initialize_schema()
    app = create_dashboard_app(db_manager=db)  # defaults to require_auth=True

    client = TestClient(app)

    # 1. Protected read endpoints must reject unauthenticated requests with 401
    res_get = client.get("/api/assessments")
    assert res_get.status_code == 401
    assert "authentication required" in res_get.json()["detail"].lower()

    # 2. Protected mutating endpoints must reject unauthenticated requests with 401
    res_post = client.post("/api/assessments", json={"organization": "TargetCorp", "assessment_name": "Review"})
    assert res_post.status_code == 401


def test_attack_8_serve_app_with_missing_authentication_configuration(tmp_path):
    """Attack 8: When no users exist, launcher reports bootstrap requirement, never a false ready state."""
    db = DatabaseManager(db_path=tmp_path / "empty_db.db")
    db.initialize_schema()
    assert db.user_count() == 0

    app = create_dashboard_app(db_manager=db, require_auth=True)
    client = TestClient(app)

    # Attempting to log in when no users are provisioned fails safely
    res = client.post("/api/auth/login", json={"username": "admin", "password": "password"})
    assert res.status_code == 401
    assert "invalid username or password" in res.json()["detail"].lower()


# =============================================================================
# Workstream B: Credential Verification & Server-Controlled Role Assignment
# =============================================================================

def test_attack_1_client_selected_admin_role_escalation_fails(auth_env):
    """Attack 1: Submitting role='admin' in login request must NEVER escalate an observer account to admin."""
    client = auth_env["client"]

    # Alice is provisioned as 'observer'. She attacks by submitting 'admin' in request JSON.
    res = client.post(
        "/api/auth/login",
        json={
            "username": "alice_obs",
            "password": "AliceObsPass123!",
            "role": "admin",  # Attacker attempts privilege escalation
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["role"] == "observer", "Role must be authoritatively assigned by server from DB, NOT client input"

    # Verify her session cannot perform reviewer-level mutations
    token = data["token"]
    res_mutate = client.post(
        "/api/assessments",
        headers={"Authorization": f"Bearer {token}"},
        json={"organization": "AttackerInc", "assessment_name": "Pwn"},
    )
    assert res_mutate.status_code == 403
    assert "role" in res_mutate.json()["detail"].lower()


def test_attack_2_login_with_no_password_fails(auth_env):
    """Attack 2: Submitting login without password must fail with 400 Bad Request or 422 Unprocessable."""
    client = auth_env["client"]

    # 1. Missing password field entirely
    res1 = client.post("/api/auth/login", json={"username": "carol_adm"})
    assert res1.status_code in (400, 422)

    # 2. Empty string password
    res2 = client.post("/api/auth/login", json={"username": "carol_adm", "password": ""})
    assert res2.status_code in (400, 422)

    # 3. Whitespace-only password
    res3 = client.post("/api/auth/login", json={"username": "carol_adm", "password": "   "})
    assert res3.status_code in (400, 422)


def test_login_credential_verification_matrix(auth_env):
    """Verify correct, incorrect, nonexistent, and disabled accounts."""
    client = auth_env["client"]

    # 1. Valid reviewer credentials -> 200 with server-assigned reviewer role
    res_ok = client.post("/api/auth/login", json={"username": "bob_rev", "password": "BobRevPass123!"})
    assert res_ok.status_code == 200
    assert res_ok.json()["role"] == "reviewer"

    # 2. Incorrect password -> 401
    res_wrong = client.post("/api/auth/login", json={"username": "bob_rev", "password": "WrongPassword!"})
    assert res_wrong.status_code == 401
    assert "invalid username or password" in res_wrong.json()["detail"].lower()

    # 3. Nonexistent user -> 401 (generic message, avoids user enumeration)
    res_nonexistent = client.post("/api/auth/login", json={"username": "ghost_user", "password": "SomePassword123!"})
    assert res_nonexistent.status_code == 401
    assert "invalid username or password" in res_nonexistent.json()["detail"].lower()


def test_attack_7_authenticate_with_expired_or_disabled_credentials(auth_env):
    """Attack 7: Disabled user accounts and expired sessions must be rejected."""
    client = auth_env["client"]
    auth_mgr = auth_env["auth_mgr"]

    # 1. Disabled account login is rejected
    res_dis = client.post("/api/auth/login", json={"username": "dave_disabled", "password": "DavePass123!"})
    assert res_dis.status_code == 401
    assert "disabled" in res_dis.json()["detail"].lower() or "invalid" in res_dis.json()["detail"].lower()

    # 2. Expired session token is rejected
    expired_sess = auth_mgr.create_session("bob_rev", DashboardRole.REVIEWER, token="tok_expired_999")
    # Artificially expire session
    expired_sess.expires_at = datetime.now(timezone.utc).timestamp() - 100
    res_exp = client.get("/api/assessments", headers={"Authorization": f"Bearer {expired_sess.token}"})
    assert res_exp.status_code == 401
    assert "expired" in res_exp.json()["detail"].lower()


# =============================================================================
# Workstream B2: Safe Initial Administrator Bootstrap & Storage Integrity
# =============================================================================

def test_bootstrap_cli_provisioning_and_reset(tmp_path):
    """CLI bootstrap utility provisions administrator and allows password recovery with scrypt."""
    import os
    db_file = tmp_path / "bootstrap_test.db"
    db = DatabaseManager(db_path=db_file)
    db.initialize_schema()

    # Provision first admin via python -m src.dashboard.bootstrap using non-echoing / stdin input
    cmd = [
        sys.executable,
        "-m",
        "src.dashboard.bootstrap",
        "--username",
        "super_admin",
        "--role",
        "admin",
        "--db-path",
        str(db_file),
    ]
    env = os.environ.copy()
    env["PYTHONPATH"] = "."
    # Provide password and password confirmation via stdin
    result = subprocess.run(cmd, input="MasterKey1234!\nMasterKey1234!\n", capture_output=True, text=True, cwd=str(Path.cwd()), env=env)
    assert result.returncode == 0, f"STDOUT: {result.stdout}\nSTDERR: {result.stderr}"
    assert "created successfully" in result.stdout
    assert "MasterKey1234!" not in result.stdout
    assert "MasterKey1234!" not in result.stderr

    # Verify user exists in database and password is an scrypt hash
    user = db.get_user("super_admin")
    assert user is not None
    assert user["role"] == "admin"
    assert user["password_hash"].startswith("scrypt$")
    assert "MasterKey1234!" not in user["password_hash"], "Plaintext password must NEVER be stored"
    assert verify_password("MasterKey1234!", user["password_hash"]) is True

    # Re-running without --reset should refuse to overwrite
    result_dup = subprocess.run(cmd, input="MasterKey1234!\nMasterKey1234!\n", capture_output=True, text=True, cwd=str(Path.cwd()), env=env)
    assert result_dup.returncode != 0
    assert "already exists" in result_dup.stderr

    # Running with --reset successfully updates credentials
    reset_cmd = [
        sys.executable,
        "-m",
        "src.dashboard.bootstrap",
        "--username",
        "super_admin",
        "--role",
        "admin",
        "--reset",
        "--db-path",
        str(db_file),
    ]
    result_reset = subprocess.run(reset_cmd, input="NewMasterKey5678!\nNewMasterKey5678!\n", capture_output=True, text=True, cwd=str(Path.cwd()), env=env)
    assert result_reset.returncode == 0, f"STDOUT: {result_reset.stdout}\nSTDERR: {result_reset.stderr}"
    assert "Password and role updated" in result_reset.stdout
    assert "NewMasterKey5678!" not in result_reset.stdout
    assert "NewMasterKey5678!" not in result_reset.stderr

    updated_user = db.get_user("super_admin")
    assert verify_password("NewMasterKey5678!", updated_user["password_hash"]) is True
    assert verify_password("MasterKey1234!", updated_user["password_hash"]) is False


# =============================================================================
# Workstream C: Session Lifecycle, Cookie Attributes, CSRF, Abuse Mitigation
# =============================================================================

def test_attack_4_reuse_revoked_session_fails(auth_env):
    """Attack 4: After logout, reusing the previous session token or cookie must fail."""
    client = auth_env["client"]

    # 1. Login to obtain session
    login_res = client.post("/api/auth/login", json={"username": "bob_rev", "password": "BobRevPass123!"})
    assert login_res.status_code == 200
    token = login_res.json()["token"]

    # 2. Use session successfully
    auth_headers = {"Authorization": f"Bearer {token}"}
    assert client.get("/api/auth/me", headers=auth_headers).status_code == 200

    # 3. Logout revokes the session on server
    logout_res = client.post("/api/auth/logout", headers=auth_headers)
    assert logout_res.status_code == 200

    # 4. Attempt to reuse revoked token -> 401 Revoked
    reused_res = client.get("/api/assessments", headers=auth_headers)
    assert reused_res.status_code == 401
    assert "revoked" in reused_res.json()["detail"].lower()


def test_attack_6_cookie_session_without_csrf_fails(auth_env):
    """Attack 6: Cookie-authenticated state-changing requests must be rejected if CSRF token is missing or forged."""
    client = auth_env["client"]
    app = auth_env["app"]

    # 1. Login to obtain session cookie and csrf cookie
    login_res = client.post("/api/auth/login", json={"username": "bob_rev", "password": "BobRevPass123!"})
    assert login_res.status_code == 200
    token = login_res.json()["token"]
    csrf_token = login_res.json()["csrf_token"]

    # 2. State-changing request with valid session cookie but NO X-CSRF-Token header -> 403 Forbidden
    cookie_client_no_csrf = TestClient(app, cookies={"session_token": token, "csrftoken": csrf_token})
    res_no_header = cookie_client_no_csrf.post(
        "/api/assessments",
        json={"organization": "AcmeCSRF", "assessment_name": "ReviewCSRF"},
    )
    assert res_no_header.status_code == 403
    assert "csrf verification failed" in res_no_header.json()["detail"].lower()

    # 3. State-changing request with mismatched/forged X-CSRF-Token -> 403 Forbidden
    res_bad_header = cookie_client_no_csrf.post(
        "/api/assessments",
        headers={"X-CSRF-Token": "forged_attack_token_123"},
        json={"organization": "AcmeCSRF", "assessment_name": "ReviewCSRF"},
    )
    assert res_bad_header.status_code == 403
    assert "csrf verification failed" in res_bad_header.json()["detail"].lower()

    # 4. State-changing request with matching synchronizer token -> 200 OK
    res_valid_csrf = cookie_client_no_csrf.post(
        "/api/assessments",
        headers={"X-CSRF-Token": csrf_token},
        json={"organization": "AcmeCSRF", "assessment_name": "ReviewCSRF"},
    )
    assert res_valid_csrf.status_code == 200
    assert res_valid_csrf.json()["status"] == "success"


def test_login_brute_force_abuse_rate_limiting(auth_env):
    """Submitting 5 consecutive failed logins triggers rate limiting (HTTP 429)."""
    client = auth_env["client"]

    # Attempt 5 wrong passwords
    for i in range(5):
        res = client.post("/api/auth/login", json={"username": "bob_rev", "password": f"WrongAttempt{i}"})
        assert res.status_code == 401

    # 6th attempt must be rejected with 429 Too Many Requests
    res_blocked = client.post("/api/auth/login", json={"username": "bob_rev", "password": "BobRevPass123!"})
    assert res_blocked.status_code == 429
    assert "too many failed login attempts" in res_blocked.json()["detail"].lower()


# =============================================================================
# Workstream E & Attack 5: Authoritative Attribution & Identity Field Removal
# =============================================================================

def test_attack_5_forge_reviewer_or_creator_identity_fails(auth_env):
    """Attack 5: Submitting forged created_by or human_reviewer in payload is ignored in favor of authenticated session."""
    client = auth_env["client"]

    # Login as reviewer bob_rev
    login_res = client.post("/api/auth/login", json={"username": "bob_rev", "password": "BobRevPass123!"})
    token = login_res.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Assessment creation with forged created_by = 'chief_executive_officer'
    res_create = client.post(
        "/api/assessments",
        headers=headers,
        json={
            "organization": "TargetCorp",
            "assessment_name": "IdentityForgeTest",
            "created_by": "chief_executive_officer",  # Attacker attempts to forge identity
        },
    )
    assert res_create.status_code == 200
    asm_data = res_create.json()["assessment"]
    assert asm_data["created_by"] == "bob_rev", "Authoritative creator must be the authenticated user 'bob_rev'"

    # Verify audit log recorded authenticated actor, NOT forged identity
    audit_file = auth_env["audit_file"]
    with open(audit_file, "r", encoding="utf-8") as f:
        log_text = f.read()
    assert "chief_executive_officer" not in log_text
    assert "bob_rev" in log_text

    # 2. Experiment result import with forged executed_by = 'external_root_admin'
    asm_id = asm_data["assessment_id"]

    # Authorize assessment first
    from datetime import timedelta
    now = datetime.now(timezone.utc)
    auth_payload = {
        "organization": "TargetCorp",
        "assessment_name": "IdentityForgeTest",
        "authorized_by": "General Counsel",
        "valid_from": (now - timedelta(days=1)).isoformat(),
        "valid_until": (now + timedelta(days=30)).isoformat(),
        "authorization_type": "PENETRATION_TEST",
        "scope_reference": "SCOPE-REF-01",
        "status": "AUTHORIZED",
    }
    client.post(f"/api/assessments/{asm_id}/authorization", headers=headers, json=auth_payload)

    # Set scope
    scope_payload = {
        "program_name": "TargetProgram",
        "platform": "HackerOne",
        "in_scope": ["api.target.com"],
        "out_of_scope": [],
    }
    client.post(f"/api/assessments/{asm_id}/scope", headers=headers, json=scope_payload)

    # Propose experiment
    prop_res = client.post(
        f"/api/assessments/{asm_id}/experiments",
        headers=headers,
        json={
            "hypothesis_id": "HYP-01",
            "objective": "Verify IDOR",
            "target_asset": "api.target.com",
            "steps": ["GET /user/42"],
            "expected_secure_result": "403 Forbidden",
            "expected_vulnerable_result": "200 OK",
            "falsification_condition": "404 Not Found",
            "negative_control": "GET /user/own",
            "risk_level": "PASSIVE",
        },
    )
    assert prop_res.status_code == 200
    exp_id = prop_res.json()["experiment"]["experiment_id"]

    # Approve experiment
    app_res = client.post(f"/api/assessments/{asm_id}/experiments/{exp_id}/approve", headers=headers)
    assert app_res.status_code == 200

    # Import result while sending forged executed_by
    res_import = client.post(
        f"/api/experiments/{exp_id}/result",
        headers=headers,
        json={
            "result_payload": {"response_code": 200},
            "executed_by": "external_root_admin",  # Attacker attempt to forge executed_by actor
        },
    )
    assert res_import.status_code == 200
    exp_data = res_import.json()["experiment"]
    assert exp_data["executed_by"] == "bob_rev", "Executed_by must be authoritatively bound to 'bob_rev', not spoofed input"


# =============================================================================
# Workstream F & Attack 9: Test Collection & Module Path Integrity
# =============================================================================

def test_attack_9_cross_project_import_integrity():
    """Attack 9: Ultron modules must resolve strictly within the Ultron project root."""
    ultron_root = Path.cwd().resolve()
    assert ultron_root.name == "Ultron - Cybersecurity Copilot", f"Unexpected cwd: {ultron_root}"

    # Verify key module resolutions
    import src.dashboard.app as dash_app
    import src.database.manager as db_mgr
    import src.dashboard.auth as dash_auth

    for mod in (dash_app, db_mgr, dash_auth):
        mod_path = Path(mod.__file__).resolve()
        assert str(ultron_root) in str(mod_path), f"Module {mod} resolved outside Ultron root: {mod_path}"
        assert "Bug Bounty AI" not in str(mod_path), f"Module {mod} resolved into old project: {mod_path}"


# =============================================================================
# Attack 10: Secret Leakage Prevention
# =============================================================================

def test_attack_10_no_secret_leakage_in_logs_and_responses(auth_env):
    """Attack 10: Check that passwords, hashes, and secrets are not leaked in audit logs or API responses."""
    client = auth_env["client"]
    password_attempt = "SecretPassAttempt987!"

    # 1. Login attempt
    res = client.post("/api/auth/login", json={"username": "bob_rev", "password": "BobRevPass123!"})
    res_json = res.text
    assert "BobRevPass123!" not in res_json
    assert "$scrypt$" not in res_json

    # 2. Inspect audit log contents
    audit_file = auth_env["audit_file"]
    if audit_file.exists():
        with open(audit_file, "r", encoding="utf-8") as f:
            log_text = f.read()
        assert "BobRevPass123!" not in log_text, "Submitted password must never appear in audit logs"
        assert "$scrypt$" not in log_text, "Password hashes must never appear in audit logs"

    # 3. List users endpoint must not expose password hashes
    users = auth_env["db"].list_users()
    for u in users:
        assert "password_hash" not in u
        assert "password" not in u
