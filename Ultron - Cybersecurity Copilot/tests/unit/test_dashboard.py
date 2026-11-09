"""Unit tests for the Human Feedback Review Dashboard API."""

from pathlib import Path
import pytest
from starlette.testclient import TestClient

from src.core.logging import AuditLogger
from src.dashboard.app import create_dashboard_app
from src.database.manager import DatabaseManager


@pytest.fixture
def dashboard_client(tmp_path: Path):
    """Provide a TestClient against a populated temporary database."""
    db_file = tmp_path / "dash_test.db"
    db = DatabaseManager(db_path=db_file)
    db.initialize_schema()

    audit_file = tmp_path / "dash_audit.log"
    auditor = AuditLogger(audit_file)

    # Seed an asset that is STATE_CHANGING (requires safety acknowledgment)
    db.insert_asset({
        "asset_id": "ASSET-MUTABLE-1",
        "method": "POST",
        "host": "api.target.com",
        "raw_path": "/api/v1/delete_account",
        "normalized_path": "/api/v1/delete_account",
        "application_mutability": "DESTRUCTIVE",
    })

    # Seed a hypothesis
    hyp_id = db.insert_hypothesis({
        "asset_id": "ASSET-MUTABLE-1",
        "category": "API-BOLA-001",
        "decision": "HYPOTHESIS",
        "evidence_state": "PARTIAL",
        "reasoning_summary": "Potential unauthorized deletion",
        "state": "New",
    })

    app = create_dashboard_app(db_manager=db, audit_logger=auditor, require_auth=False)
    client = TestClient(app)
    return client, hyp_id


def test_list_and_detail_with_safety_warning(dashboard_client):
    """Verify hypothesis listing and safety warning for DESTRUCTIVE asset."""
    client, hyp_id = dashboard_client

    # 1. List hypotheses
    res = client.get("/api/hypotheses")
    assert res.status_code == 200
    data = res.json()
    assert len(data) == 1
    assert data[0]["id"] == hyp_id

    # 2. Detail view contains safety warning
    res_detail = client.get(f"/api/hypotheses/{hyp_id}")
    assert res_detail.status_code == 200
    detail = res_detail.json()
    assert detail["safety"]["requires_safety_acknowledgment"] is True
    assert "CAUTION" in detail["safety"]["warning_message"]


def test_review_and_experiment_revision(dashboard_client):
    """Verify transitioning to Under Review and recording experiment observation."""
    client, hyp_id = dashboard_client

    # Move to Under Review
    res_rev = client.post(f"/api/hypotheses/{hyp_id}/review")
    assert res_rev.status_code == 200
    assert res_rev.json()["state"] == "Under Review"

    # Submit experiment result
    res_exp = client.post(
        f"/api/hypotheses/{hyp_id}/experiment/result",
        json={
            "observation_type": "SUPPORTING",
            "new_evidence_ref": "logs/test_run.log",
            "notes": "Observed test account unauthorized action",
        },
    )
    assert res_exp.status_code == 200
    updated_hyp = res_exp.json()["hypothesis"]
    assert updated_hyp["revision"] == 2
    assert updated_hyp["evidence_state"] == "STRONG"


def test_safety_acknowledgment_enforcement_on_confirm(dashboard_client):
    """Verify confirmation fails if safety_acknowledged is False for destructive endpoint."""
    client, hyp_id = dashboard_client

    # Move to Under Review first
    client.post(f"/api/hypotheses/{hyp_id}/review")

    # Attempt confirm without safety acknowledgment
    res_fail = client.post(
        f"/api/hypotheses/{hyp_id}/confirm",
        json={
            "actor": "researcher_1",
            "evidence_ref": "logs/repro.log",
            "safety_acknowledged": False, # NOT acknowledged!
        },
    )
    assert res_fail.status_code == 400
    assert "Safety acknowledgment required" in res_fail.json()["detail"]

    # Confirm WITH safety acknowledgment
    res_ok = client.post(
        f"/api/hypotheses/{hyp_id}/confirm",
        json={
            "actor": "researcher_1",
            "evidence_ref": "logs/repro.log",
            "safety_acknowledged": True, # Acknowledged!
        },
    )
    assert res_ok.status_code == 200
    assert res_ok.json()["state"] == "Confirmed"

    # Verify audit record was written
    res_audit = client.get("/api/audit")
    assert res_audit.status_code == 200
    audit_events = [a["event_type"] for a in res_audit.json()]
    assert "HUMAN_VERIFICATION" in audit_events


def test_dashboard_bind_defaults_to_localhost():
    """Verify validate_dashboard_bind allows default localhost interface."""
    from src.dashboard.app import DEFAULT_DASHBOARD_HOST, validate_dashboard_bind
    assert DEFAULT_DASHBOARD_HOST == "127.0.0.1"
    assert validate_dashboard_bind() == "127.0.0.1"
    assert validate_dashboard_bind("localhost") == "localhost"
    assert validate_dashboard_bind("127.0.0.1") == "127.0.0.1"
    assert validate_dashboard_bind("::1") == "::1"


def test_dashboard_bind_rejects_external_interface_without_flag():
    """Verify validate_dashboard_bind raises ValueError when non-loopback requested without flag."""
    from src.dashboard.app import validate_dashboard_bind
    with pytest.raises(ValueError, match="Refusing to bind dashboard to non-loopback address"):
        validate_dashboard_bind("0.0.0.0", allow_external=False)

    with pytest.raises(ValueError, match="Refusing to bind dashboard to non-loopback address"):
        validate_dashboard_bind("192.168.1.50", allow_external=False)


def test_dashboard_bind_allows_external_with_explicit_flag_and_auth(caplog):
    """Verify validate_dashboard_bind permits external bind when allow_external=True and auth_configured=True."""
    from src.dashboard.app import validate_dashboard_bind
    bound = validate_dashboard_bind("0.0.0.0", allow_external=True, auth_configured=True)
    assert bound == "0.0.0.0"


def test_dashboard_bind_rejects_external_without_auth_configuration():
    """Verify validate_dashboard_bind fails closed when allow_external=True but auth_configured=False."""
    from src.dashboard.app import validate_dashboard_bind
    with pytest.raises(ValueError, match="External binding must fail closed unless authentication is configured"):
        validate_dashboard_bind("0.0.0.0", allow_external=True, auth_configured=False)

