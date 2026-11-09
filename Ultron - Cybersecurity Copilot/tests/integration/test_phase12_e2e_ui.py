"""
Milestone Phase 12: End-to-End Integration Test Suite for Local AI Research Workspace.
Validates single-origin SPA serving, full investigation lifecycle, progressive disclosure,
authoritative security gates (ScopeGate, ApprovalGate, Grounding, Polarity, Execution),
epistemic segregation, and secret isolation.
"""

import os
import tempfile
from pathlib import Path
import pytest
from starlette.testclient import TestClient

from src.core.logging import AuditLogger
from src.dashboard.app import create_dashboard_app, validate_dashboard_bind
from src.dashboard.models import ExperimentApprovalRequest
from src.database.manager import DatabaseManager


@pytest.fixture
def e2e_client():
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = Path(tmp_dir) / "e2e_research.db"
        audit_path = Path(tmp_dir) / "e2e_audit.log"

        db_manager = DatabaseManager(db_path=db_path)
        db_manager.initialize_schema()
        audit_logger = AuditLogger(audit_file_path=audit_path)

        from src.dashboard.auth import DashboardAuthManager, DashboardRole
        auth_mgr = DashboardAuthManager(db_manager=db_manager)
        sess = auth_mgr.create_session("e2e_admin", DashboardRole.ADMIN)

        app = create_dashboard_app(
            db_manager=db_manager,
            audit_logger=audit_logger,
            auth_manager=auth_mgr,
            frontend_dist_dir=Path("frontend/dist"),
        )
        client = TestClient(app, headers={"Authorization": f"Bearer {sess.token}"})
        yield client, db_manager, audit_logger


def test_e2e_spa_single_origin_serving(e2e_client):
    """Verify single-origin SPA serves index.html and assets at root and SPA paths."""
    client, _, _ = e2e_client

    # Root route serves compiled React application
    res_root = client.get("/")
    assert res_root.status_code == 200
    assert "<!doctype html>" in res_root.text.lower()
    assert "Ultron" in res_root.text or "Bug Bounty AI" in res_root.text

    # SPA route fallback preserves single URL architecture
    res_spa = client.get("/investigations/INV-001")
    assert res_spa.status_code == 200
    assert "<!doctype html>" in res_spa.text.lower()

    # Static assets are accessible under /assets/
    dist_dir = Path("frontend/dist/assets")
    if dist_dir.exists():
        asset_files = list(dist_dir.glob("*.js"))
        if asset_files:
            asset_name = asset_files[0].name
            res_asset = client.get(f"/assets/{asset_name}")
            assert res_asset.status_code == 200
            assert "javascript" in res_asset.headers.get("content-type", "")


def test_e2e_system_status_and_health(e2e_client):
    """Verify system status reports local runtime components truthfully."""
    client, _, _ = e2e_client

    res = client.get("/api/system/status")
    assert res.status_code == 200
    status = res.json()

    assert status["local_ai"] == "READY"
    assert status["evidence"] == "READY"
    assert status["vapt_rag"] == "READY"
    assert status["execution_mode"] == "SAFE_LOCAL_SIMULATION"
    assert "audit" in status
    assert "gpu" in status


def test_e2e_complete_research_lifecycle(e2e_client):
    """
    Test full end-to-end research flow:
    1. Inspection of pre-seeded BOLA investigation
    2. Context drawer inspection (Evidence, Model, Invariants, Gaps, Hypotheses, Experiments, Audit)
    3. Multiturn conversational AI prompts
    4. Deterministic Experiment Validation
    5. Fail-closed execution without approval
    6. Experiment Rejection
    7. Cryptographic Human Approval
    8. Deterministic Execution Engine Run & Observation creation
    9. Audit log hash verification
    """
    client, db_manager, audit_logger = e2e_client

    # 1. Verify fresh application starts empty, then explicitly load demo fixture
    res_fresh = client.get("/api/investigations")
    assert res_fresh.status_code == 200
    assert len(res_fresh.json()) == 0

    res_demo = client.post("/api/demo/load")
    assert res_demo.status_code == 200

    res_list = client.get("/api/investigations")
    assert res_list.status_code == 200
    invs = res_list.json()
    assert len(invs) >= 1
    inv_id = invs[0]["id"]
    assert inv_id == "INV-001"
    assert invs[0]["is_demo"] is True

    res_detail = client.get(f"/api/investigations/{inv_id}")
    assert res_detail.status_code == 200
    detail = res_detail.json()
    assert "Acme Billing API (BOLA" in detail["name"]
    assert detail["scope_status"] == "ALLOWED"
    assert len(detail["messages"]) >= 4

    # 2. Context drawer verification
    res_evidence = client.get(f"/api/investigations/{inv_id}/evidence")
    assert res_evidence.status_code == 200
    evidence = res_evidence.json()
    assert len(evidence) >= 2
    assert any(e["fact_id"] == "FACT-OBS-01" for e in evidence)

    res_model = client.get(f"/api/investigations/{inv_id}/model")
    assert res_model.status_code == 200
    model = res_model.json()
    assert model["target_host"] == "api.target.local"
    assert len(model["assets"]) >= 1

    res_invariants = client.get(f"/api/investigations/{inv_id}/invariants")
    assert res_invariants.status_code == 200
    assert len(res_invariants.json()) >= 1

    res_gaps = client.get(f"/api/investigations/{inv_id}/gaps")
    assert res_gaps.status_code == 200
    assert len(res_gaps.json()) >= 1

    res_hyp = client.get(f"/api/investigations/{inv_id}/hypotheses")
    assert res_hyp.status_code == 200
    assert len(res_hyp.json()) >= 1

    res_exp = client.get(f"/api/investigations/{inv_id}/experiments")
    assert res_exp.status_code == 200
    experiments = res_exp.json()
    assert len(experiments) >= 1
    exp_id = experiments[0]["id"]

    # 3. Conversational AI interaction
    res_chat = client.post(
        f"/api/investigations/{inv_id}/messages",
        json={"content": "Show open evidence gaps and explain the hypothesis"},
    )
    assert res_chat.status_code == 200
    new_msgs = res_chat.json()
    assert len(new_msgs) >= 1

    # 4. Experiment Validation
    res_val = client.post(f"/api/experiments/{exp_id}/validate")
    assert res_val.status_code == 200
    val_data = res_val.json()
    assert val_data["valid"] is True
    assert val_data["scope_passed"] is True
    assert val_data["polarity_passed"] is True
    assert val_data["grounding_passed"] is True

    # 5. Fail-closed execution without approval
    res_fail = client.post(f"/api/experiments/{exp_id}/execute", json={"safe_simulation": True})
    assert res_fail.status_code == 200
    fail_data = res_fail.json()
    assert fail_data["success"] is False
    assert fail_data["status"] == "BLOCKED_APPROVAL"

    # 6. Rejection test on separate experiment or proposal
    res_rej = client.post(
        f"/api/experiments/{exp_id}/reject",
        json={"actor": "lead_researcher", "reason": "Test rejection boundary before re-approval"},
    )
    assert res_rej.status_code == 200
    assert res_rej.json()["status"] == "rejected"

    # 7. Cryptographic approval
    res_appr = client.post(
        f"/api/experiments/{exp_id}/approve",
        json={
            "actor": "lead_researcher",
            "safety_acknowledged": True,
            "notes": "Approved for deterministic execution against local mock transport.",
        },
    )
    assert res_appr.status_code == 200
    appr_res = res_appr.json()
    assert appr_res["status"] == "success"
    assert "APP-" in appr_res["approval_id"]
    assert len(appr_res["descriptor_digest"]) == 64

    # 8. Deterministic Execution Engine Run
    res_exec = client.post(f"/api/experiments/{exp_id}/execute", json={"safe_simulation": True})
    assert res_exec.status_code == 200
    exec_data = res_exec.json()
    assert exec_data["success"] is True
    assert exec_data["status"] == "EXECUTED"
    assert exec_data["observation"]["status_code"] == 200
    assert exec_data["observation"]["derived_epistemic_status"] == "HUMAN_VERIFIED_FINDING"
    assert exec_data["hypothesis_state"] == "Confirmed"

    # Verify newly created evidence in the database
    updated_evidence = client.get(f"/api/investigations/{inv_id}/evidence").json()
    assert any("FACT-OBS-03" in e["fact_id"] for e in updated_evidence)

    # 9. Audit log verification
    res_audit = client.get(f"/api/audit/{inv_id}")
    assert res_audit.status_code == 200
    audit_data = res_audit.json()
    assert audit_data["chain_integrity"] == "VERIFIED"
    assert len(audit_data["records"]) >= 1


def test_e2e_security_boundaries_and_secret_isolation(e2e_client):
    """Verify secrets never appear in API responses and non-loopback binding fails closed."""
    client, _, _ = e2e_client

    # Verify responses contain no plaintext credentials
    res = client.get("/api/investigations/INV-001")
    assert "SUPER_SECRET" not in res.text
    assert "vault_secret" not in res.text
    assert "master_key" not in res.text

    # Verify external binding fails closed
    with pytest.raises(ValueError, match="Refusing to bind dashboard to non-loopback"):
        validate_dashboard_bind("0.0.0.0", allow_external=False, auth_configured=False)

    with pytest.raises(ValueError, match="External binding must fail closed"):
        validate_dashboard_bind("0.0.0.0", allow_external=True, auth_configured=False)
