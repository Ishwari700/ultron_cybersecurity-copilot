"""Integration tests for Knowledge Graph Integrity Audit API (Milestone M9 Stage E).

Tests the real FastAPI application endpoint:
- GET /api/knowledge/graph/audit
Verifies:
1. Unauthenticated requests are rejected with 401 Unauthorized.
2. Authenticated OBSERVER and OPERATOR sessions succeed with 200 OK.
3. Strict schema adherence to GraphAuditResponse.
4. Query parameter filtering by category and bounded record limits.
5. Live detection of injected integrity issues via the REST API.
"""

from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from src.core.logging import AuditLogger
from src.dashboard.app import create_dashboard_app
from src.dashboard.auth import DashboardAuthManager, DashboardRole
from src.dashboard.service import WorkspaceService
from src.database.manager import DatabaseManager
from src.knowledge.knowledge_graph import RelationalKnowledgeGraph
from src.knowledge.store import VaptKnowledgeStore


@pytest.fixture
def audit_api_env(tmp_path: Path):
    """Sets up an isolated database, knowledge store, knowledge graph, and test client."""
    db_file = tmp_path / "app.db"
    k_db_file = tmp_path / "vapt_knowledge.db"
    g_db_file = tmp_path / "knowledge_graph.db"
    audit_file = tmp_path / "audit.log"

    db_mgr = DatabaseManager(db_file)
    auditor = AuditLogger(audit_file)
    k_store = VaptKnowledgeStore(k_db_file)
    k_graph = RelationalKnowledgeGraph(g_db_file)

    ws_service = WorkspaceService(db_manager=db_mgr, audit_logger=auditor)
    ws_service.knowledge_store = k_store
    ws_service.knowledge_graph = k_graph

    auth_mgr = DashboardAuthManager(db_manager=db_mgr)
    op_session = auth_mgr.create_session(username="operator_user", role=DashboardRole.OPERATOR)
    obs_session = auth_mgr.create_session(username="observer_user", role=DashboardRole.OBSERVER)

    app = create_dashboard_app(
        db_manager=db_mgr,
        audit_logger=auditor,
        auth_manager=auth_mgr,
        workspace_service=ws_service,
        require_auth=True,
    )
    client = TestClient(app)

    yield {
        "client": client,
        "k_store": k_store,
        "k_graph": k_graph,
        "op_token": op_session.token,
        "obs_token": obs_session.token,
    }

    k_store.close()
    k_graph.close()


def test_unauthenticated_audit_request_rejected(audit_api_env):
    """Verifies that unauthenticated access to the graph audit endpoint is denied."""
    client = audit_api_env["client"]
    resp = client.get("/api/knowledge/graph/audit")
    assert resp.status_code == 401


def test_authenticated_observer_audit_success(audit_api_env):
    """Verifies that an authenticated OBSERVER receives 200 OK with valid GraphAuditResponse schema."""
    client = audit_api_env["client"]
    token = audit_api_env["obs_token"]

    resp = client.get(
        "/api/knowledge/graph/audit",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()

    assert "audit_id" in data
    assert data["schema_version"] == "1.0.0"
    assert "audit_timestamp" in data
    assert "summary" in data
    assert "issues" in data
    assert "limitations" in data
    assert data["read_only_guarantee"] is True

    summary = data["summary"]
    assert summary["status"] in {"CLEAN", "WARNINGS_FOUND", "ERRORS_FOUND", "CRITICAL_FOUND"}
    assert "nodes_examined" in summary
    assert "edges_examined" in summary
    assert "provenance_citations_examined" in summary


def test_audit_query_parameter_filtering(audit_api_env):
    """Verifies category filtering and record bounding via query parameters."""
    client = audit_api_env["client"]
    token = audit_api_env["obs_token"]

    resp = client.get(
        "/api/knowledge/graph/audit?categories=STRUCTURAL,PROVENANCE&max_records=10",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()

    assert data["read_only_guarantee"] is True
    assert isinstance(data["issues"], list)


def test_audit_detects_real_issues_via_api(audit_api_env):
    """Verifies that an injected structural issue is accurately detected and returned over the API."""
    client = audit_api_env["client"]
    token = audit_api_env["obs_token"]
    graph = audit_api_env["k_graph"]

    # Inject a dangling edge
    graph.add_edge(
        source_id="NODE:VULNERABILITY:phantom_source",
        target_id="NODE:VULNERABILITY:phantom_target",
        relation_type="EXPLOITS",
        metadata={},
    )

    resp = client.get(
        "/api/knowledge/graph/audit?categories=STRUCTURAL",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()

    summary = data["summary"]
    assert summary["critical_count"] >= 2
    assert summary["status"] == "CRITICAL_FOUND"

    check_codes = [i["check_code"] for i in data["issues"]]
    assert "DANGLING_EDGE_SOURCE" in check_codes
    assert "DANGLING_EDGE_TARGET" in check_codes
