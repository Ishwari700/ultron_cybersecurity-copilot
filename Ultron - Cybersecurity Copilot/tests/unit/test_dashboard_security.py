"""
Regression and security invariant tests for Finding 3:
Dashboard Authentication, RBAC, and Output Rendering (XSS Defense).
"""

from pathlib import Path
import time
import pytest
from starlette.testclient import TestClient

from src.core.logging import AuditLogger
from src.dashboard.app import (
    DashboardAuthManager,
    DashboardRole,
    create_dashboard_app,
    validate_dashboard_bind,
)
from src.database.manager import DatabaseManager


@pytest.fixture
def dashboard_env(tmp_path: Path):
    db_file = tmp_path / "dash_security_test.db"
    db = DatabaseManager(db_path=db_file)
    db.initialize_schema()

    audit_file = tmp_path / "dash_security_audit.log"
    auditor = AuditLogger(audit_file)

    auth_mgr = DashboardAuthManager()

    # Create users with different roles
    observer_sess = auth_mgr.create_session("alice_observer", DashboardRole.OBSERVER, token="tok_observer_123")
    reviewer_sess = auth_mgr.create_session("bob_reviewer", DashboardRole.REVIEWER, token="tok_reviewer_456")
    admin_sess = auth_mgr.create_session("carol_admin", DashboardRole.ADMIN, token="tok_admin_789")

    # Seed an asset
    db.insert_asset({
        "asset_id": "ASSET-DASH-01",
        "method": "POST",
        "host": "api.target.com",
        "raw_path": "/api/v1/update",
        "normalized_path": "/api/v1/update",
        "application_mutability": "READ_ONLY",
    })

    # Seed a hypothesis
    hyp_id = db.insert_hypothesis({
        "asset_id": "ASSET-DASH-01",
        "category": "API-BOLA-001",
        "decision": "HYPOTHESIS",
        "evidence_state": "PARTIAL",
        "reasoning_summary": "Initial hypothesis reasoning",
        "state": "New",
    })

    return {
        "db": db,
        "auditor": auditor,
        "auth_mgr": auth_mgr,
        "hyp_id": hyp_id,
        "observer_token": observer_sess.token,
        "reviewer_token": reviewer_sess.token,
        "admin_token": admin_sess.token,
    }


def test_external_bind_validation_fails_closed_without_auth():
    """External binding must fail closed unless allow_external=True AND auth_configured=True."""
    # Localhost succeeds by default
    assert validate_dashboard_bind("127.0.0.1") == "127.0.0.1"
    assert validate_dashboard_bind("localhost") == "localhost"

    # Non-loopback without allow_external raises ValueError
    with pytest.raises(ValueError, match="Refusing to bind dashboard to non-loopback address"):
        validate_dashboard_bind("0.0.0.0", allow_external=False, auth_configured=False)

    # Non-loopback with allow_external but without auth raises ValueError
    with pytest.raises(ValueError, match="External binding must fail closed unless authentication is configured"):
        validate_dashboard_bind("0.0.0.0", allow_external=True, auth_configured=False)

    # Non-loopback with allow_external AND auth_configured succeeds
    bound = validate_dashboard_bind("0.0.0.0", allow_external=True, auth_configured=True)
    assert bound == "0.0.0.0"


def test_unauthenticated_request_fails_closed_in_auth_mode(dashboard_env):
    """When require_auth=True, requests without valid credentials return HTTP 401."""
    app = create_dashboard_app(
        db_manager=dashboard_env["db"],
        audit_logger=dashboard_env["auditor"],
        auth_manager=dashboard_env["auth_mgr"],
        require_auth=True,
    )
    client = TestClient(app)

    # Read without auth
    res = client.get("/api/hypotheses")
    assert res.status_code == 401
    assert "Authentication required" in res.json()["detail"]

    # Write without auth
    res_post = client.post(f"/api/hypotheses/{dashboard_env['hyp_id']}/review")
    assert res_post.status_code == 401


def test_authenticated_read_with_observer_role(dashboard_env):
    """Observer role can read hypotheses, invariants, and audit logs."""
    app = create_dashboard_app(
        db_manager=dashboard_env["db"],
        audit_logger=dashboard_env["auditor"],
        auth_manager=dashboard_env["auth_mgr"],
        require_auth=True,
    )
    client = TestClient(app)
    headers = {"Authorization": f"Bearer {dashboard_env['observer_token']}"}

    res = client.get("/api/hypotheses", headers=headers)
    assert res.status_code == 200
    assert len(res.json()) >= 1

    res_detail = client.get(f"/api/hypotheses/{dashboard_env['hyp_id']}", headers=headers)
    assert res_detail.status_code == 200

    res_audit = client.get("/api/audit", headers=headers)
    assert res_audit.status_code == 200


def test_unauthorized_state_mutation_with_observer_role(dashboard_env):
    """Observer role is forbidden from triggering state changes (HTTP 403)."""
    app = create_dashboard_app(
        db_manager=dashboard_env["db"],
        audit_logger=dashboard_env["auditor"],
        auth_manager=dashboard_env["auth_mgr"],
        require_auth=True,
    )
    client = TestClient(app)
    headers = {"Authorization": f"Bearer {dashboard_env['observer_token']}"}

    res_post = client.post(f"/api/hypotheses/{dashboard_env['hyp_id']}/review", headers=headers)
    assert res_post.status_code == 403
    assert "reviewer role required" in res_post.json()["detail"]


def test_authorized_state_mutation_with_reviewer_role(dashboard_env):
    """Reviewer role can transition states and verify hypotheses."""
    app = create_dashboard_app(
        db_manager=dashboard_env["db"],
        audit_logger=dashboard_env["auditor"],
        auth_manager=dashboard_env["auth_mgr"],
        require_auth=True,
    )
    client = TestClient(app)
    headers = {"Authorization": f"Bearer {dashboard_env['reviewer_token']}"}

    # Transition to Under Review
    res = client.post(f"/api/hypotheses/{dashboard_env['hyp_id']}/review", headers=headers)
    assert res.status_code == 200
    assert res.json()["state"] == "Under Review"

    # Confirm with human verification
    res_confirm = client.post(
        f"/api/hypotheses/{dashboard_env['hyp_id']}/confirm",
        headers=headers,
        json={
            "evidence_ref": "evidence/repro_log.txt",
            "safety_acknowledged": True,
            "notes": "Verified by authenticated reviewer",
        },
    )
    assert res_confirm.status_code == 200
    assert res_confirm.json()["state"] == "Confirmed"


def test_invalid_expired_and_revoked_session_tokens(dashboard_env):
    """Invalid, expired, and revoked tokens all fail closed with HTTP 401."""
    auth_mgr = dashboard_env["auth_mgr"]
    app = create_dashboard_app(
        db_manager=dashboard_env["db"],
        audit_logger=dashboard_env["auditor"],
        auth_manager=auth_mgr,
        require_auth=True,
    )
    client = TestClient(app)

    # 1. Invalid token
    res_inv = client.get("/api/hypotheses", headers={"Authorization": "Bearer non_existent_token"})
    assert res_inv.status_code == 401

    # 2. Expired session
    exp_sess = auth_mgr.create_session("dave_expired", DashboardRole.REVIEWER, ttl_seconds=-10)
    res_exp = client.get("/api/hypotheses", headers={"Authorization": f"Bearer {exp_sess.token}"})
    assert res_exp.status_code == 401
    assert "expired" in res_exp.json()["detail"].lower()

    # 3. Revoked session
    rev_sess = auth_mgr.create_session("eve_revoked", DashboardRole.REVIEWER)
    auth_mgr.revoke_session(rev_sess.token)
    res_rev = client.get("/api/hypotheses", headers={"Authorization": f"Bearer {rev_sess.token}"})
    assert res_rev.status_code == 401
    assert "revoked" in res_rev.json()["detail"].lower()


def test_xss_prevention_in_dashboard_ui(dashboard_env):
    """UI must not use innerHTML with untrusted data and must safely handle adversarial payloads."""
    app = create_dashboard_app(
        db_manager=dashboard_env["db"],
        audit_logger=dashboard_env["auditor"],
        auth_manager=dashboard_env["auth_mgr"],
    )
    client = TestClient(app)

    res = client.get("/")
    assert res.status_code == 200
    html = res.text

    # Verify innerHTML is not used in the hypothesis rendering script
    assert ".innerHTML" not in html
    assert "textContent" in html
    assert "createTextNode" in html

    # Insert adversarial hypotheses with XSS payloads
    adversarial_payloads = [
        "<script>alert('xss')</script>",
        "<img src=x onerror=alert(document.cookie)>",
        "</script><script>alert(1)</script>",
        "'; alert('xss'); '",
        '`${alert(1)}`',
        '{"malicious": "<script>alert(1)</script>"}',
        "Line1\n<svg/onload=alert(1)>\nLine2",
    ]

    db = dashboard_env["db"]
    for i, payload in enumerate(adversarial_payloads):
        hyp_id = db.insert_hypothesis({
            "asset_id": "ASSET-DASH-01",
            "category": f"CAT-{payload}",
            "decision": "HYPOTHESIS",
            "evidence_state": "PARTIAL",
            "reasoning_summary": payload,
            "state": "New",
        })
        assert hyp_id > 0

    # Verify JSON API serializes payloads safely as data, not unescaped raw HTML inside index page
    obs_sess = dashboard_env["auth_mgr"].create_session("observer_reader", DashboardRole.OBSERVER)
    res_api = client.get("/api/hypotheses", headers={"Authorization": f"Bearer {obs_sess.token}"})
    assert res_api.status_code == 200
    items = res_api.json()
    assert any("<script>" in item.get("reasoning_summary", "") for item in items)
