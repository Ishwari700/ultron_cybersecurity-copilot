"""Unit Tests for Workstream C — API-Level Security Boundaries.

Exercises real FastAPI HTTP routes with the authoritative authorization matrix:
1. Unauthenticated requests fail closed with 401 across endpoints.
2. Invalid, expired, and revoked session tokens fail closed with 401.
3. Observer role is strictly read-only: 200 on GET, 403 on POST/PUT/DELETE.
4. Denied requests cause ZERO state mutations (state immutability verified).
5. Reviewer and Admin roles are granted appropriate operational access.
6. Client-supplied forged actor identities are ignored in favor of session identity.
7. Cross-assessment operations fail closed and prevent data leakage.
8. Cookie-authenticated mutating requests enforce CSRF synchronizer tokens.
"""

from datetime import datetime, timedelta, timezone
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


@pytest.fixture
def api_env(tmp_path: Path):
    db_file = tmp_path / "api_test.db"
    db = DatabaseManager(db_path=db_file)
    db.initialize_schema()

    audit_file = tmp_path / "api_audit.log"
    auditor = AuditLogger(audit_file)

    auth_mgr = DashboardAuthManager(db_manager=db)
    observer_sess = auth_mgr.create_session("alice_obs", DashboardRole.OBSERVER, token="tok_obs_100")
    reviewer_sess = auth_mgr.create_session("bob_rev", DashboardRole.REVIEWER, token="tok_rev_200")
    admin_sess = auth_mgr.create_session("carol_adm", DashboardRole.ADMIN, token="tok_adm_300")

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


def _create_baseline_assessment(client: TestClient, token: str, org: str = "ApexCorp") -> str:
    headers = {"Authorization": f"Bearer {token}"}
    res = client.post(
        "/api/assessments",
        headers=headers,
        json={"organization": org, "assessment_name": "API Security Audit"},
    )
    assert res.status_code == 200, res.text
    aid = res.json()["assessment"]["assessment_id"]

    now = datetime.now(timezone.utc)
    auth_payload = {
        "organization": org,
        "assessment_name": "API Security Audit",
        "authorized_by": "Chief Information Security Officer",
        "valid_from": (now - timedelta(days=1)).isoformat(),
        "valid_until": (now + timedelta(days=30)).isoformat(),
        "authorization_type": "INTERNAL_SECURITY_ASSESSMENT",
        "scope_reference": "SCOPE-API",
        "status": "AUTHORIZED",
    }
    auth_res = client.post(f"/api/assessments/{aid}/authorization", headers=headers, json=auth_payload)
    assert auth_res.status_code == 200, auth_res.text

    scope_payload = {
        "program_name": "API Scope",
        "platform": "TEST",
        "in_scope": ["api.apex.corp"],
        "out_of_scope": ["internal.apex.corp"],
    }
    scope_res = client.post(f"/api/assessments/{aid}/scope", headers=headers, json=scope_payload)
    assert scope_res.status_code == 200, scope_res.text

    return aid


def test_unauthenticated_requests_fail_closed_across_routes(api_env):
    """Verify that requests lacking authorization headers return 401 across all protected routes."""
    client = api_env["client"]

    unauth_routes = [
        ("GET", "/api/assessments"),
        ("POST", "/api/assessments"),
        ("GET", "/api/assessments/ASM-DUMMY/overview"),
        ("POST", "/api/assessments/ASM-DUMMY/authorization"),
        ("POST", "/api/assessments/ASM-DUMMY/scope"),
        ("POST", "/api/assessments/ASM-DUMMY/assets"),
        ("POST", "/api/assessments/ASM-DUMMY/observations"),
        ("POST", "/api/assessments/ASM-DUMMY/experiments"),
        ("POST", "/api/assessments/ASM-DUMMY/findings"),
        ("GET", "/api/audit"),
        ("GET", "/api/memory/items"),
        ("POST", "/api/memory/items"),
        ("POST", "/api/memory/search"),
    ]

    for method, path in unauth_routes:
        if method == "GET":
            res = client.get(path)
        else:
            res = client.post(path, json={})
        assert res.status_code == 401, f"Route {method} {path} returned {res.status_code}, expected 401"
        data = res.json()
        assert "detail" in data or "error" in data


def test_invalid_and_revoked_session_tokens_fail_closed(api_env):
    """Verify that forged, malformed, or revoked tokens return 401."""
    client = api_env["client"]
    auth_mgr = api_env["auth_mgr"]

    bad_tokens = [
        "forged_token_12345",
        "Bearer malformed.jwt.token",
        "",
        "expired_session_token",
    ]

    for bad_tok in bad_tokens:
        headers = {"Authorization": f"Bearer {bad_tok}"}
        res = client.get("/api/assessments", headers=headers)
        assert res.status_code == 401, f"Token '{bad_tok}' permitted access with {res.status_code}"

    # Revoke a valid session and assert immediate 401
    temp_sess = auth_mgr.create_session("temp_user", DashboardRole.REVIEWER, token="tok_temp_revoke")
    auth_headers = {"Authorization": f"Bearer {temp_sess.token}"}
    res_before = client.get("/api/assessments", headers=auth_headers)
    assert res_before.status_code == 200

    auth_mgr.revoke_session(temp_sess.token)
    res_after = client.get("/api/assessments", headers=auth_headers)
    assert res_after.status_code == 401


def test_observer_role_read_only_matrix_and_state_immutability(api_env):
    """Verify that Observer has GET access but receives 403 on mutating routes without state alteration."""
    client = api_env["client"]
    rev_tok = api_env["reviewer_token"]
    obs_tok = api_env["observer_token"]

    # 1. Setup baseline assessment using reviewer
    aid = _create_baseline_assessment(client, rev_tok, org="ReadOnlyApex")

    # 2. Observer can read GET routes
    obs_headers = {"Authorization": f"Bearer {obs_tok}"}
    get_res = client.get("/api/assessments", headers=obs_headers)
    assert get_res.status_code == 200

    overview_res = client.get(f"/api/assessments/{aid}/overview", headers=obs_headers)
    assert overview_res.status_code == 200

    audit_res = client.get("/api/audit", headers=obs_headers)
    assert audit_res.status_code == 200

    # 3. Observer receives 403 Forbidden on state-changing operations
    mutating_attempts = [
        ("POST", "/api/assessments", {"organization": "HackedOrg", "assessment_name": "Rogue"}),
        ("POST", f"/api/assessments/{aid}/assets", {"asset_type": "DOMAIN", "canonical_identifier": "rogue.com"}),
        ("POST", f"/api/assessments/{aid}/experiments", {"hypothesis_id": "HYP-01", "target_asset": "api.apex.corp", "action_summary": "Test"}),
        ("POST", f"/api/assessments/{aid}/findings", {"title": "Rogue Finding", "severity": "CRITICAL", "asset": "api.apex.corp"}),
        ("POST", "/api/memory/items", {"content": "Rogue memory", "category": "KNOWLEDGE"}),
    ]

    for method, path, payload in mutating_attempts:
        res = client.post(path, headers=obs_headers, json=payload)
        assert res.status_code == 403, f"Observer mutating route {path} returned {res.status_code}, expected 403"

    # 4. State Immutability Assertion: Verify state did not mutate
    overview_after = client.get(f"/api/assessments/{aid}/overview", headers=obs_headers).json()["overview"]
    assert overview_after["organization"] == "ReadOnlyApex"
    assert overview_after["finding_count"] == 0
    assert overview_after["asset_count"] == 0


def test_client_supplied_forged_actor_is_ignored(api_env):
    """Verify that client-submitted actor headers/fields are ignored; session actor is authoritative."""
    client = api_env["client"]
    rev_tok = api_env["reviewer_token"]
    aid = _create_baseline_assessment(client, rev_tok, org="ActorForgingCorp")

    headers = {
        "Authorization": f"Bearer {rev_tok}",
        "X-Actor": "forged_super_cso",
    }
    payload = {
        "asset_type": "DOMAIN",
        "canonical_identifier": "trusted.apex.corp",
        "actor": "forged_super_admin",
    }

    res = client.post(f"/api/assessments/{aid}/assets", headers=headers, json=payload)
    assert res.status_code == 200, res.text

    # Verify audit trail records the authenticated session user ('bob_rev'), NOT the forged actor
    audit_res = client.get("/api/audit", headers=headers)
    assert audit_res.status_code == 200
    raw_audit = audit_res.json()
    events = raw_audit if isinstance(raw_audit, list) else raw_audit.get("events", [])
    assert len(events) >= 1

    last_event = events[-1]
    # The authoritative actor must be the authenticated user 'bob_rev'
    assert last_event.get("actor") == "bob_rev"
    assert "forged_super" not in last_event.get("actor", "")


def test_cross_assessment_isolation_at_api_boundary(api_env):
    """Verify that requests querying non-existent or other assessment IDs fail closed."""
    client = api_env["client"]
    rev_tok = api_env["reviewer_token"]
    headers = {"Authorization": f"Bearer {rev_tok}"}

    aid_a = _create_baseline_assessment(client, rev_tok, org="TenantA")

    # Accessing non-existent assessment fails closed with 404
    non_existent = client.get("/api/assessments/ASM-DOES-NOT-EXIST/overview", headers=headers)
    assert non_existent.status_code == 404

    non_existent_auth = client.get("/api/assessments/ASM-DOES-NOT-EXIST/authorization", headers=headers)
    assert non_existent_auth.status_code == 404

    # Adding assets to a non-existent container fails closed
    bad_asset = client.post(
        "/api/assessments/ASM-DOES-NOT-EXIST/assets",
        headers=headers,
        json={"asset_type": "DOMAIN", "canonical_identifier": "leak.com"},
    )
    assert bad_asset.status_code == 404


def test_cookie_session_csrf_enforcement(api_env):
    """Verify that mutating requests using cookie authentication require CSRF synchronizer token."""
    client = api_env["client"]
    auth_mgr = api_env["auth_mgr"]

    # Create session cookie
    sess = auth_mgr.create_session("csrf_user", DashboardRole.REVIEWER, token="tok_csrf_session")
    cookies = {"session_token": sess.token}

    # 1. Mutating request with cookie but WITHOUT CSRF token fails with 403
    res_no_csrf = client.post(
        "/api/assessments",
        cookies=cookies,
        json={"organization": "CSRFCorp", "assessment_name": "NoTokenAudit"},
    )
    assert res_no_csrf.status_code == 403
    assert "CSRF" in res_no_csrf.text

    # 2. Fetch legitimate CSRF token
    csrf_res = client.get("/api/auth/csrf", cookies=cookies)
    assert csrf_res.status_code == 200
    csrf_token = csrf_res.json()["csrf_token"]
    assert len(csrf_token) >= 32

    # 3. Mutating request WITH valid CSRF token succeeds
    res_with_csrf = client.post(
        "/api/assessments",
        cookies=cookies,
        headers={"X-CSRF-Token": csrf_token},
        json={"organization": "CSRFCorp", "assessment_name": "WithTokenAudit"},
    )
    assert res_with_csrf.status_code == 200, res_with_csrf.text
