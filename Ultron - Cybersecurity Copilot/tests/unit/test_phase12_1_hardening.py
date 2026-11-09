"""
Phase 12.1: Production Hardening and Cascade Verification Unit Test Suite.

Verifies:
A. Fresh application has no demo data.
B. Demo data appears only when explicitly requested via POST /api/demo/load.
C. "Hello" and greetings receive natural conversational responses without fabricating security analysis or demo targets.
D. Generic conversational prompts ("Who are you?", "What can you do?", "Help") do not fabricate evidence.
E. Security investigation prompts on empty investigations honestly report insufficient evidence.
F. Security investigation prompts with evidence invoke the actual research pipeline.
G. 3B triage invocation observed in cascade execution trace.
H. Deterministic router invocation observed in cascade execution trace.
I. 7B reasoning invocation observed upon escalation in cascade execution trace.
J. 3B -> 7B handoff packet is constructed with immutable provenance hash.
K. No fake cascade telemetry; traces contain real timestamps, latencies, model names, and digests.
L. UI model status reflects actual runtime ("Cascade Active (3B → 7B)").
M. Conversation history preserves multi-turn context.
"""

from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest
from starlette.testclient import TestClient

from src.core.logging import AuditLogger
from src.dashboard.app import create_dashboard_app
from src.database.manager import DatabaseManager
from src.engine.cascade_orchestrator import (
    CascadeOrchestrator,
    CascadeExecutionTrace,
)
from src.engine.reasoning_runner import PINNED_7B_DIGEST, PINNED_7B_MODEL
from src.engine.triage_runner import PINNED_3B_DIGEST, PINNED_3B_MODEL
from src.evidence.cascade_models import (
    LosslessStructuralPack,
    RawTriageOutput,
)


@pytest.fixture
def hardened_client(tmp_path: Path):
    """Provide a TestClient connected to a freshly initialized test environment."""
    db_file = tmp_path / "hardened_workspace.db"
    db = DatabaseManager(db_path=db_file)
    db.initialize_schema()

    audit_file = tmp_path / "hardened_audit.log"
    auditor = AuditLogger(audit_file)

    from src.dashboard.auth import DashboardAuthManager, DashboardRole
    auth_mgr = DashboardAuthManager(db_manager=db)
    sess = auth_mgr.create_session("hardened_tester", DashboardRole.ADMIN)

    app = create_dashboard_app(
        db_manager=db,
        audit_logger=auditor,
        auth_manager=auth_mgr,
        frontend_dist_dir=Path(__file__).resolve().parent.parent.parent / "frontend" / "dist",
    )
    client = TestClient(app, headers={"Authorization": f"Bearer {sess.token}"})
    return client, db, auditor


def test_req_a_fresh_application_has_no_demo_data(hardened_client):
    """Req A: Verify fresh application startup contains zero demo investigations or fake targets."""
    client, _, _ = hardened_client

    res = client.get("/api/investigations")
    assert res.status_code == 200
    invs = res.json()
    assert len(invs) == 0, f"Expected 0 investigations on fresh startup, found {len(invs)}"

    # System status reports cascade active without demo leaks
    status_res = client.get("/api/system/status")
    assert status_res.status_code == 200
    status_data = status_res.json()
    assert "api.target.local" not in str(status_data)
    assert "Acme" not in str(status_data)


def test_req_b_demo_data_appears_only_when_explicitly_requested(hardened_client):
    """Req B: Verify demo fixture appears only after explicit POST /api/demo/load and is marked is_demo."""
    client, _, _ = hardened_client

    # 1. Initially empty
    assert len(client.get("/api/investigations").json()) == 0

    # 2. Explicit opt-in
    res_load = client.post("/api/demo/load")
    assert res_load.status_code == 200
    demo_obj = res_load.json()
    assert demo_obj["id"] == "INV-001"
    assert demo_obj["is_demo"] is True
    assert "[DEMO FIXTURE]" in demo_obj["name"]

    # 3. Investigation list now contains marked demo fixture
    invs = client.get("/api/investigations").json()
    assert len(invs) == 1
    assert invs[0]["id"] == "INV-001"
    assert invs[0]["is_demo"] is True


def test_req_c_hello_receives_conversational_response(hardened_client):
    """Req C: Verify 'Hello' prompt receives a natural conversational response without canned BOLA analysis."""
    client, _, _ = hardened_client

    # Create a fresh genuine investigation
    res_create = client.post(
        "/api/investigations",
        json={"name": "Production Assessment", "target_host": "api.prod.example.com"},
    )
    assert res_create.status_code == 200
    inv_id = res_create.json()["id"]

    # Send conversational greeting
    res_msg = client.post(
        f"/api/investigations/{inv_id}/messages",
        json={"content": "Hello"},
    )
    assert res_msg.status_code == 200
    messages = res_msg.json()
    assert len(messages) >= 1  # assistant message returned

    assistant_msg = messages[-1]["content"]

    # Forbidden leak check: must NOT talk about api.target.local, BOLA, or fake evidence
    forbidden_terms = ["api.target.local", "INV-001", "FACT-OBS-01", "Acme Billing", "HYP-001"]
    for term in forbidden_terms:
        assert term not in assistant_msg, f"Forbidden term '{term}' leaked into conversational response: {assistant_msg}"

    # Must be conversational
    assert any(w in assistant_msg.lower() for w in ["hello", "assistant", "help", "research", "security"])


def test_req_d_generic_prompts_do_not_fabricate_evidence(hardened_client):
    """Req D: Verify generic queries ('Who are you?', 'What can you do?') do not fabricate target evidence."""
    client, _, _ = hardened_client

    res_create = client.post(
        "/api/investigations",
        json={"name": "Auth Assessment", "target_host": "auth.example.com"},
    )
    inv_id = res_create.json()["id"]

    for prompt in ["Who are you?", "What can you do?", "Help"]:
        res = client.post(
            f"/api/investigations/{inv_id}/messages",
            json={"content": prompt},
        )
        assert res.status_code == 200
        msgs = res.json()
        resp_text = msgs[-1]["content"]

        # Ensure no fabricated observations or fake telemetry
        assert "api.target.local" not in resp_text
        assert "FACT-OBS" not in resp_text
        assert len(resp_text) > 10


def test_req_e_empty_investigation_causes_honest_abstention(hardened_client):
    """Req E: Verify security prompt on empty investigation honestly reports insufficient evidence."""
    client, _, _ = hardened_client

    # Create empty investigation with no evidence items
    res_create = client.post(
        "/api/investigations",
        json={"name": "Zero-Evidence Target", "target_host": "fresh.target.internal"},
    )
    inv_id = res_create.json()["id"]

    # Verify evidence drawer is empty
    ev_res = client.get(f"/api/investigations/{inv_id}/evidence")
    assert ev_res.status_code == 200
    assert len(ev_res.json()) == 0

    # Request deep security investigation
    res_msg = client.post(
        f"/api/investigations/{inv_id}/messages",
        json={"content": "Analyze the current evidence and formulate hypotheses."},
    )
    assert res_msg.status_code == 200
    messages = res_msg.json()
    resp_text = messages[-1]["content"]

    # Must honestly report no evidence, rather than fabricating findings
    assert "no target evidence" in resp_text.lower() or "insufficient evidence" in resp_text.lower()
    assert "api.target.local" not in resp_text
    assert "FACT-OBS-01" not in resp_text


def test_req_f_investigation_prompt_on_fixture_executes_pipeline(hardened_client):
    """Req F: Verify security query on an investigation WITH evidence executes the analysis pipeline."""
    client, _, _ = hardened_client
    client.post("/api/demo/load")

    res = client.post(
        "/api/investigations/INV-001/messages",
        json={"content": "Analyze authorization invariants and explain the hypothesis"},
    )
    assert res.status_code == 200
    messages = res.json()
    resp_text = messages[-1]["content"]
    assert len(resp_text) > 20
    # Should reference relevant evidence, hypotheses, authorization, or invariants
    assert any(term in resp_text.lower() for term in ["evidence", "hypothesis", "authorization", "invariant"])


def test_req_g_h_i_j_k_cascade_orchestrator_execution_trace():
    """Req G, H, I, J, K: Empirically verify 3B, Router, 7B escalation, and handoff provenance in CascadeOrchestrator."""
    orchestrator = CascadeOrchestrator()

    pack = LosslessStructuralPack(
        schema_version="2.0.0",
        asset_id="ASSET-TEST-CASCADE-01",
        endpoint_id="EP-TEST-01",
        route_template="/api/v1/users/{user_id}/profile",
        http_method="POST",
        application_mutability="STATE_CHANGING",
        observed_facts=[
            {
                "fact_id": "FACT-TEST-01",
                "statement": "Endpoint /api/v1/users/{user_id}/profile updates user data.",
            },
            {
                "fact_id": "FACT-TEST-02",
                "statement": "No object-level tenant validation observed in request header.",
            },
        ],
    )

    # Mock the underlying runners to isolate the orchestration logic deterministically
    mock_3b_output = RawTriageOutput(
        schema_version="2.0.0",
        decision="SUSPECTED_VULNERABILITY",
        suspected_category="API-BOLA-001",
        triage_rationale="State changing user endpoint without explicit tenant check",
        suggested_experiment_class="ID_SWAP",
        is_sensitive_category=False,
        is_malformed=False,
    )

    mock_7b_output = {
        "status": "SUCCESS",
        "hypothesis": {
            "hypothesis_id": "HYP-CASCADE-TEST-01",
            "decision": "HYPOTHESIS_FORMULATED",
            "category": "API-BOLA-001",
            "reasoning_summary": "7B validated authorization boundary deficit.",
            "preliminary_score": 0.92,
        },
        "grounding": {"valid": True},
    }

    with patch.object(orchestrator.triage_runner, "run_triage", return_value=mock_3b_output) as mock_3b_call, \
         patch.object(orchestrator.reasoning_runner, "run_reasoning", return_value=mock_7b_output) as mock_7b_call:

        trace, hypothesis = orchestrator.execute_cascade(pack, task_type="TEST_SWEEP")

        # Req G: 3B invocation observed
        assert mock_3b_call.called, "3B triage runner was not invoked"
        stage1 = next((s for s in trace.stages if "Stage 1" in s.stage_name), None)
        assert stage1 is not None
        assert stage1.status == "COMPLETED"
        assert stage1.model_name == PINNED_3B_MODEL
        assert PINNED_3B_DIGEST[:16] in stage1.model_digest

        # Req H: Router invocation observed
        stage2 = next((s for s in trace.stages if "Stage 2" in s.stage_name), None)
        assert stage2 is not None
        assert stage2.status == "COMPLETED"
        assert trace.routing_decision == "ESCALATE_TO_7B"

        # Req J: 3B -> 7B handoff packet created with SHA256 provenance hash
        stage3 = next((s for s in trace.stages if "Stage 3" in s.stage_name), None)
        assert stage3 is not None
        assert stage3.status == "COMPLETED"
        assert trace.handoff_provenance_hash is not None
        assert len(trace.handoff_provenance_hash) == 64

        # Req I: 7B invocation observed on escalation
        assert mock_7b_call.called, "7B reasoning runner was not invoked on escalation"
        stage4 = next((s for s in trace.stages if "Stage 4" in s.stage_name), None)
        assert stage4 is not None
        assert stage4.status == "COMPLETED"
        assert stage4.model_name == PINNED_7B_MODEL
        assert PINNED_7B_DIGEST[:16] in stage4.model_digest

        # Req K: Telemetry contains real run_id, timestamps, and latencies
        assert trace.run_id.startswith("RUN-")
        assert trace.total_latency_seconds >= 0.0
        assert trace.overall_status in ("CASCADE_VERIFIED", "CASCADE_COMPLETED")
        assert trace.error_message is None
        assert hypothesis == mock_7b_output["hypothesis"]


def test_req_l_ui_model_status_reflects_actual_runtime(hardened_client):
    """Req L: Verify GET /api/system/status reports 'Cascade Active (3B → 7B)' and telemetry traces."""
    client, _, _ = hardened_client

    with patch(
        "src.engine.cascade_orchestrator.CascadeOrchestrator.check_runtime_status",
        return_value={
            "ollama_available": True,
            "has_3b": True,
            "has_7b": True,
            "cascade_mode": "3B_7B_CASCADE_READY",
        },
    ):
        res = client.get("/api/system/status")
        assert res.status_code == 200
        data = res.json()

        assert data["cascade_mode"] == "CASCADE_ACTIVE_3B_7B"
        assert "Cascade Active" in data["active_model"]
        assert "3B" in data["active_model"] and "7B" in data["active_model"]

        # Verify dedicated cascade trace endpoint
        res_trace = client.get("/api/system/cascade-trace")
        assert res_trace.status_code == 200
        trace_data = res_trace.json()
        assert isinstance(trace_data, list)


def test_req_m_conversation_history_preserves_turns(hardened_client):
    """Req M: Verify conversation history is retained across multiple turns."""
    client, _, _ = hardened_client

    res_create = client.post(
        "/api/investigations",
        json={"name": "History Test", "target_host": "test.history.local"},
    )
    inv_id = res_create.json()["id"]

    # Turn 1
    client.post(f"/api/investigations/{inv_id}/messages", json={"content": "Hello"})
    # Turn 2
    client.post(f"/api/investigations/{inv_id}/messages", json={"content": "What can you do?"})

    # Retrieve detail
    detail = client.get(f"/api/investigations/{inv_id}").json()
    msgs = detail["messages"]
    # Expect: initial system message + Turn 1 user + Turn 1 assistant + Turn 2 user + Turn 2 assistant = 5
    assert len(msgs) >= 5
    user_msgs = [m["content"] for m in msgs if m["sender"] == "user"]
    assert "Hello" in user_msgs
    assert "What can you do?" in user_msgs
