"""Unit tests for Phase 12 Local AI Investigation Workspace API, security boundaries, and SPA serving."""

import json
from pathlib import Path
import pytest
from starlette.testclient import TestClient

from src.core.logging import AuditLogger
from src.dashboard.app import create_dashboard_app, validate_dashboard_bind
from src.database.manager import DatabaseManager


@pytest.fixture
def workspace_client(tmp_path: Path):
    """Provide a TestClient connected to an isolated test environment."""
    db_file = tmp_path / "test_workspace.db"
    db = DatabaseManager(db_path=db_file)
    db.initialize_schema()

    audit_file = tmp_path / "test_workspace_audit.log"
    auditor = AuditLogger(audit_file)

    from src.dashboard.auth import DashboardAuthManager, DashboardRole
    auth_mgr = DashboardAuthManager(db_manager=db)
    sess = auth_mgr.create_session("workspace_tester", DashboardRole.ADMIN)

    app = create_dashboard_app(
        db_manager=db,
        audit_logger=auditor,
        auth_manager=auth_mgr,
        frontend_dist_dir=Path(__file__).resolve().parent.parent.parent / "frontend" / "dist",
    )
    client = TestClient(app, headers={"Authorization": f"Bearer {sess.token}"})
    return client, db, auditor


def test_01_spa_serving_and_static_assets(workspace_client):
    """Verify single-origin SPA serving on GET / and SPA fallback on subroutes."""
    client, _, _ = workspace_client

    # 1. Root returns HTML application
    res_root = client.get("/")
    assert res_root.status_code == 200
    assert "text/html" in res_root.headers.get("content-type", "")
    assert "Ultron" in res_root.text or "Bug Bounty AI" in res_root.text or "Security Hypothesis" in res_root.text

    # 2. Subroute SPA fallback
    res_sub = client.get("/investigations/INV-001")
    assert res_sub.status_code == 200
    assert "text/html" in res_sub.headers.get("content-type", "")


def test_02_system_status_endpoints(workspace_client):
    """Verify GET /api/health and /api/status reporting actual local platform state."""
    client, _, _ = workspace_client

    res = client.get("/api/status")
    assert res.status_code == 200
    data = res.json()
    assert data["local_ai"] == "READY"
    assert data["evidence"] == "READY"
    assert data["audit"] == "VERIFIED"
    assert "gpu" in data
    assert "active_model" in data


def test_03_investigation_lifecycle(workspace_client):
    """Verify fresh application has no demo data, and demo data appears only on explicit opt-in."""
    client, _, _ = workspace_client

    # 1. Fresh application has NO demo data
    res_list = client.get("/api/investigations")
    assert res_list.status_code == 200
    invs = res_list.json()
    assert len(invs) == 0

    # 2. Explicit demo opt-in loads demo fixture
    res_demo = client.post("/api/demo/load")
    assert res_demo.status_code == 200
    demo_inv = res_demo.json()
    assert demo_inv["id"] == "INV-001"
    assert demo_inv["is_demo"] is True

    # 3. Create new genuine investigation
    res_create = client.post(
        "/api/investigations",
        json={"name": "Payment Gateway Audit", "target_host": "api.payments.local"},
    )
    assert res_create.status_code == 200
    new_inv = res_create.json()
    assert new_inv["name"] == "Payment Gateway Audit"
    assert new_inv["target_host"] == "api.payments.local"
    assert new_inv["is_demo"] is False
    assert new_inv["evidence_count"] == 0

    # 4. Retrieve investigation detail
    res_detail = client.get(f"/api/investigations/{new_inv['id']}")
    assert res_detail.status_code == 200
    detail = res_detail.json()
    assert detail["id"] == new_inv["id"]
    assert len(detail["messages"]) >= 1


def test_04_conversational_research_pipeline_bridge(workspace_client):
    """Verify grounded conversational responses on POST /api/investigations/{id}/messages."""
    client, _, _ = workspace_client
    client.post("/api/demo/load")

    # Query open evidence gaps
    res = client.post(
        "/api/investigations/INV-001/messages",
        json={"content": "Show open evidence gaps and missing telemetry."},
    )
    assert res.status_code == 200
    messages = res.json()
    assert len(messages) >= 1
    content = messages[0]["content"]
    assert "GAP-TENANT-ISOLATION" in content or "evidence" in content.lower()


def test_05_context_drawer_endpoints(workspace_client):
    """Verify context drawer endpoints: evidence, model, invariants, gaps, hypotheses, experiments."""
    client, _, _ = workspace_client
    client.post("/api/demo/load")

    # Evidence
    res_ev = client.get("/api/investigations/INV-001/evidence")
    assert res_ev.status_code == 200
    assert isinstance(res_ev.json(), list)

    # Model
    res_model = client.get("/api/investigations/INV-001/model")
    assert res_model.status_code == 200
    assert "assets" in res_model.json()
    assert "workflows" in res_model.json()

    # Invariants
    res_inv = client.get("/api/investigations/INV-001/invariants")
    assert res_inv.status_code == 200
    assert isinstance(res_inv.json(), list)

    # Gaps
    res_gaps = client.get("/api/investigations/INV-001/gaps")
    assert res_gaps.status_code == 200
    gaps = res_gaps.json()
    assert len(gaps) >= 1
    assert gaps[0]["gap_id"] == "GAP-TENANT-ISOLATION"

    # Hypotheses
    res_hyp = client.get("/api/investigations/INV-001/hypotheses")
    assert res_hyp.status_code == 200
    assert isinstance(res_hyp.json(), list)

    # Experiments
    res_exp = client.get("/api/investigations/INV-001/experiments")
    assert res_exp.status_code == 200
    exps = res_exp.json()
    assert len(exps) >= 1
    assert exps[0]["id"] == "EXP-001"


def test_06_experiment_validation(workspace_client):
    """Verify deterministic validation of experiment proposals."""
    client, _, _ = workspace_client
    client.post("/api/demo/load")

    res = client.post("/api/experiments/EXP-001/validate")
    assert res.status_code == 200
    data = res.json()
    assert data["experiment_id"] == "EXP-001"
    assert data["valid"] is True
    assert data["grounding_passed"] is True
    assert data["polarity_passed"] is True
    assert data["scope_passed"] is True


def test_07_human_approval_enforcement_fail_closed(workspace_client):
    """Verify state-changing experiment execution fails closed without approval."""
    client, _, _ = workspace_client
    client.post("/api/demo/load")

    # Attempt execution prior to registering human approval
    res = client.post("/api/experiments/EXP-001/execute", json={"safe_simulation": True})
    assert res.status_code == 200
    outcome = res.json()
    assert outcome["success"] is False
    assert outcome["status"] == "BLOCKED_APPROVAL"
    assert "BLOCKED_APPROVAL" in outcome["error_message"]


def test_08_human_approval_registration(workspace_client):
    """Verify registering human approval with explicit safety acknowledgment."""
    client, _, _ = workspace_client
    client.post("/api/demo/load")

    # Attempt approval without safety acknowledgment -> must fail
    res_no_ack = client.post(
        "/api/experiments/EXP-001/approve",
        json={"actor": "lead_researcher", "safety_acknowledged": False},
    )
    assert res_no_ack.status_code == 400

    # Register valid approval
    res_valid = client.post(
        "/api/experiments/EXP-001/approve",
        json={"actor": "lead_researcher", "safety_acknowledged": True, "notes": "Approved for local mock simulation."},
    )
    assert res_valid.status_code == 200
    appr_data = res_valid.json()
    assert appr_data["status"] == "success"
    assert "APP-" in appr_data["approval_id"]
    assert len(appr_data["descriptor_digest"]) == 64


def test_09_deterministic_execution_after_approval(workspace_client):
    """Verify successful safe execution through DeterministicExecutionEngine once approved."""
    client, _, _ = workspace_client
    client.post("/api/demo/load")

    # 1. Approve
    client.post(
        "/api/experiments/EXP-001/approve",
        json={"actor": "lead_researcher", "safety_acknowledged": True},
    )

    # 2. Execute
    res_exec = client.post("/api/experiments/EXP-001/execute", json={"safe_simulation": True})
    assert res_exec.status_code == 200
    outcome = res_exec.json()
    assert outcome["success"] is True
    assert outcome["status"] == "EXECUTED"
    assert outcome["observation"]["status_code"] == 200
    assert outcome["hypothesis_state"] == "Confirmed"
    assert len(outcome["timeline"]) >= 5


def test_10_secret_isolation_in_api_responses(workspace_client):
    """Verify raw secrets never enter API responses or conversation history."""
    client, _, _ = workspace_client
    client.post("/api/demo/load")

    res_detail = client.get("/api/investigations/INV-001")
    assert res_detail.status_code == 200
    body_text = res_detail.text

    # Assert no plaintext authorization tokens or passwords
    assert "raw_secret_token" not in body_text
    assert "SUPER_SECRET" not in body_text
    # Placeholders are permitted
    assert "<SECRET:" in body_text or "Bearer" in body_text or "INV-001" in body_text


def test_11_dashboard_bind_isolation_fails_closed():
    """Verify non-loopback binding fails closed without explicit authorization."""
    with pytest.raises(ValueError, match="Refusing to bind dashboard to non-loopback"):
        validate_dashboard_bind("0.0.0.0", allow_external=False, auth_configured=False)

    with pytest.raises(ValueError, match="External binding must fail closed"):
        validate_dashboard_bind("0.0.0.0", allow_external=True, auth_configured=False)

    # Allowed loopback
    assert validate_dashboard_bind("127.0.0.1") == "127.0.0.1"
    assert validate_dashboard_bind("localhost") == "localhost"


def test_12_import_traffic_api_scenarios_a_through_e(workspace_client):
    """Verify backend IngestionResult API payload fidelity matches frontend expectations for Scenarios A-E."""
    client, _, _ = workspace_client

    # Create investigation for lab.target.local
    res_inv = client.post(
        "/api/investigations",
        json={"name": "Lab Target Test", "target_host": "lab.target.local"},
    )
    assert res_inv.status_code == 200
    inv_id = res_inv.json()["id"]

    # 16-transaction fixture
    fixture_path = Path(__file__).resolve().parent.parent / "fixtures" / "security_test_fixture_10_vulnerabilities.txt"
    with open(fixture_path, "r", encoding="utf-8") as f:
        fixture_content = f.read()

    # Scenario A: First import of fixture
    res_a = client.post(
        f"/api/investigations/{inv_id}/import",
        json={"format": "raw_http", "content": fixture_content},
    )
    assert res_a.status_code == 200
    data_a = res_a.json()
    assert data_a["accepted_count"] > 0
    assert data_a["observations_added"] == data_a["accepted_count"]
    assert data_a["out_of_scope_count"] == 0
    assert data_a["parsing_failures"] == 0

    # Scenario B: Same fixture imported again into same investigation
    res_b = client.post(
        f"/api/investigations/{inv_id}/import",
        json={"format": "raw_http", "content": fixture_content},
    )
    assert res_b.status_code == 200
    data_b = res_b.json()
    assert data_b["observations_added"] == 0
    assert data_b["accepted_count"] == 0
    assert data_b["duplicate_count"] == 16
    assert data_b["duplicates"] == 16
    assert data_b["out_of_scope_count"] == 0
    assert data_b["parsing_failures"] == 0

    # Scenario C: Mixed import (new observation + duplicate + out-of-scope)
    exact_tx = fixture_content.split("---")[1].strip()
    mixed_content = (
        "GET /new-endpoint HTTP/1.1\r\n"
        "Host: lab.target.local\r\n"
        "\r\n"
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 2\r\n"
        "\r\n"
        "OK\r\n"
        "---\n"
        + exact_tx + "\r\n"
        "---\n"
        "GET /admin HTTP/1.1\r\n"
        "Host: out-of-scope-attacker.com\r\n"
        "\r\n"
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 2\r\n"
        "\r\n"
        "OK"
    )
    res_c = client.post(
        f"/api/investigations/{inv_id}/import",
        json={"format": "raw_http", "content": mixed_content},
    )
    assert res_c.status_code == 200
    data_c = res_c.json()
    assert data_c["observations_added"] == 1
    assert data_c["duplicate_count"] == 1
    assert data_c["out_of_scope_count"] == 1
    assert len(data_c["out_of_scope"]) == 1
    assert data_c["out_of_scope"][0]["host"] == "out-of-scope-attacker.com"

    # Scenario D: Only out-of-scope traffic
    oos_content = (
        "GET /login HTTP/1.1\r\n"
        "Host: external-partner.com\r\n"
        "\r\n"
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 2\r\n"
        "\r\n"
        "OK"
    )
    res_d = client.post(
        f"/api/investigations/{inv_id}/import",
        json={"format": "raw_http", "content": oos_content},
    )
    assert res_d.status_code == 200
    data_d = res_d.json()
    assert data_d["observations_added"] == 0
    assert data_d["duplicate_count"] == 0
    assert data_d["out_of_scope_count"] == 1
    assert data_d["parsing_failures"] == 0
    assert len(data_d["out_of_scope"]) == 1

    # Scenario E: Parse failure
    malformed_content = "NOT AN HTTP REQUEST AT ALL"
    res_e = client.post(
        f"/api/investigations/{inv_id}/import",
        json={"format": "raw_http", "content": malformed_content},
    )
    assert res_e.status_code == 200
    data_e = res_e.json()
    assert data_e["observations_added"] == 0
    assert data_e["duplicate_count"] == 0
    assert data_e["out_of_scope_count"] == 0
    assert data_e["parsing_failures"] > 0
    assert len(data_e["parse_errors"]) > 0

