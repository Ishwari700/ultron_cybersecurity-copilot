"""Unit tests for Phase 12.4 Cascade Trace, AI Runtime Observability & UI Refinement."""

import json
from pathlib import Path
import pytest
from unittest.mock import MagicMock, patch

from src.database.manager import DatabaseManager
from src.dashboard.service import WorkspaceService
from src.dashboard.models import CreateInvestigationRequest
from src.engine.cascade_orchestrator import (
    CascadeExecutionTrace,
    CascadeOrchestrator,
    PINNED_3B_DIGEST,
    PINNED_3B_MODEL,
    PINNED_7B_DIGEST,
    PINNED_7B_MODEL,
)
from src.evidence.cascade_models import LosslessStructuralPack, RawTriageOutput


@pytest.fixture
def temp_db(tmp_path: Path) -> DatabaseManager:
    db_file = tmp_path / "test_observability.db"
    db = DatabaseManager(db_path=db_file)
    db.initialize_schema()
    return db


@pytest.fixture
def workspace_service(temp_db: DatabaseManager) -> WorkspaceService:
    service = WorkspaceService(db_manager=temp_db)
    return service


@pytest.fixture
def sample_pack() -> LosslessStructuralPack:
    return LosslessStructuralPack(
        schema_version="2.0.0",
        asset_id="ASSET-TEST-01",
        endpoint_id="EP-TEST-01",
        route_template="/api/v1/invoices/export",
        http_method="POST",
        application_mutability="STATE_CHANGING",
        observed_facts=[
            {"fact_id": "FACT-OBS-01", "statement": "POST accepts JSON body with org and invoice_id."},
            {"fact_id": "FACT-OBS-02", "statement": "Returns 200 with PDF binary for current tenant."},
        ],
    )


def make_mock_triage(
    decision: str = "SUSPECTED_VULNERABILITY",
    category: str = "API-BOLA-001",
    rationale: str = "Cross-tenant invoice access possible",
) -> RawTriageOutput:
    return RawTriageOutput(
        decision=decision,
        suspected_category=category,
        triage_rationale=rationale,
        suggested_experiment_class="ID_SWAP",
        candidate_security_property="TENANT_ISOLATION",
        is_malformed=False,
        cited_fact_ids=["FACT-OBS-01", "FACT-OBS-02"],
    )


# 1. test_cascade_trace_created
def test_cascade_trace_created(sample_pack: LosslessStructuralPack):
    orchestrator = CascadeOrchestrator()
    orchestrator.triage_runner.run_triage = MagicMock(return_value=make_mock_triage())
    orchestrator.reasoning_runner.run_reasoning = MagicMock(return_value={
        "status": "SUCCESS",
        "hypothesis": {"decision": "HYPOTHESIS", "category": "API-BOLA-001", "reasoning_summary": "BOLA found"},
        "grounding": {"valid": True},
    })

    trace, hyp = orchestrator.execute_cascade(sample_pack, task_type="SECURITY_RESEARCH")

    assert trace is not None
    assert trace.run_id.startswith("RUN-")
    assert trace.task_type == "SECURITY_RESEARCH"
    assert "POST /api/v1/invoices/export" in trace.target_endpoint
    assert len(trace.stages) == 4
    assert trace.overall_status in ("CASCADE_COMPLETED", "CASCADE_VERIFIED")


# 2. test_3b_invocation_recorded
def test_3b_invocation_recorded(sample_pack: LosslessStructuralPack):
    orchestrator = CascadeOrchestrator()
    orchestrator.triage_runner.run_triage = MagicMock(return_value=make_mock_triage())
    orchestrator.reasoning_runner.run_reasoning = MagicMock(return_value={"status": "SUCCESS"})

    trace, _ = orchestrator.execute_cascade(sample_pack)

    stage_3b = trace.stages[0]
    assert stage_3b.stage_name == "Stage 1: 3B Preliminary Triage"
    assert stage_3b.model_name == PINNED_3B_MODEL
    assert stage_3b.model_digest.startswith(PINNED_3B_DIGEST[:8])
    assert stage_3b.status == "COMPLETED"
    assert stage_3b.latency_seconds >= 0.0
    assert stage_3b.details["decision"] == "SUSPECTED_VULNERABILITY"


# 3. test_router_decision_recorded
def test_router_decision_recorded(sample_pack: LosslessStructuralPack):
    orchestrator = CascadeOrchestrator()
    orchestrator.triage_runner.run_triage = MagicMock(return_value=make_mock_triage())
    orchestrator.reasoning_runner.run_reasoning = MagicMock(return_value={"status": "SUCCESS"})

    trace, _ = orchestrator.execute_cascade(sample_pack)

    stage_router = trace.stages[1]
    assert stage_router.stage_name == "Stage 2: Gate & Deterministic Routing"
    assert stage_router.model_name == "DeterministicRouter"
    assert stage_router.status == "COMPLETED"
    assert trace.routing_decision == "ESCALATE_TO_7B"
    assert trace.escalated is True
    assert "reasons" in stage_router.details


# 4. test_handoff_provenance_recorded
def test_handoff_provenance_recorded(sample_pack: LosslessStructuralPack):
    orchestrator = CascadeOrchestrator()
    orchestrator.triage_runner.run_triage = MagicMock(return_value=make_mock_triage())
    orchestrator.reasoning_runner.run_reasoning = MagicMock(return_value={"status": "SUCCESS"})

    trace, _ = orchestrator.execute_cascade(sample_pack)

    stage_handoff = trace.stages[2]
    assert stage_handoff.stage_name == "Stage 3: Immutable Cascade Handoff"
    assert stage_handoff.status == "COMPLETED"
    assert trace.handoff_provenance_hash is not None
    assert len(trace.handoff_provenance_hash) > 16


# 5. test_7b_invocation_recorded
def test_7b_invocation_recorded(sample_pack: LosslessStructuralPack):
    orchestrator = CascadeOrchestrator()
    orchestrator.triage_runner.run_triage = MagicMock(return_value=make_mock_triage())
    orchestrator.reasoning_runner.run_reasoning = MagicMock(return_value={
        "status": "SUCCESS",
        "hypothesis": {"decision": "HYPOTHESIS", "category": "API-BOLA-001", "reasoning_summary": "BOLA verified"},
        "grounding": {"valid": True},
    })

    trace, _ = orchestrator.execute_cascade(sample_pack)

    stage_7b = trace.stages[3]
    assert stage_7b.stage_name == "Stage 4: 7B Deep Reasoning"
    assert stage_7b.model_name == PINNED_7B_MODEL
    assert stage_7b.model_digest.startswith(PINNED_7B_DIGEST[:8])
    assert stage_7b.status == "COMPLETED"
    assert stage_7b.details["category"] == "API-BOLA-001"
    assert stage_7b.details["grounding_passed"] is True


# 6. test_trace_linked_to_assistant_message
def test_trace_linked_to_assistant_message(workspace_service: WorkspaceService):
    demo = workspace_service.load_demo_investigation()

    workspace_service.cascade_orchestrator.triage_runner.run_triage = MagicMock(return_value=make_mock_triage())
    workspace_service.cascade_orchestrator.reasoning_runner.run_reasoning = MagicMock(return_value={
        "status": "SUCCESS",
        "hypothesis": {"decision": "HYPOTHESIS", "category": "API-BOLA-001", "reasoning_summary": "BOLA verified"},
        "grounding": {"valid": True},
    })

    responses = workspace_service.send_message(demo.id, "Analyze the current evidence.")
    assert len(responses) >= 1
    asst_msg = responses[0]
    assert asst_msg.cascade_trace_id is not None
    assert asst_msg.cascade_trace_id.startswith("RUN-")

    # Verify trace exists in DB
    trace_record = workspace_service.get_cascade_trace(asst_msg.cascade_trace_id)
    assert trace_record is not None
    assert trace_record["run_id"] == asst_msg.cascade_trace_id
    assert trace_record["investigation_id"] == demo.id


# 7. test_trace_survives_restart
def test_trace_survives_restart(temp_db: DatabaseManager):
    service1 = WorkspaceService(db_manager=temp_db)
    demo = service1.load_demo_investigation()

    service1.cascade_orchestrator.triage_runner.run_triage = MagicMock(return_value=make_mock_triage())
    service1.cascade_orchestrator.reasoning_runner.run_reasoning = MagicMock(return_value={
        "status": "SUCCESS",
        "hypothesis": {"decision": "HYPOTHESIS", "category": "API-BOLA-001", "reasoning_summary": "BOLA confirmed"},
        "grounding": {"valid": True},
    })

    responses = service1.send_message(demo.id, "Analyze the current evidence.")
    trace_id = responses[0].cascade_trace_id

    # Destroy service1 and recreate service2 with same database
    del service1
    service2 = WorkspaceService(db_manager=temp_db)

    persisted_trace = service2.get_cascade_trace(trace_id)
    assert persisted_trace is not None
    assert persisted_trace["run_id"] == trace_id
    assert persisted_trace["investigation_id"] == demo.id
    assert len(persisted_trace["stages"]) == 4
    assert persisted_trace["overall_status"] in ("CASCADE_COMPLETED", "CASCADE_VERIFIED")


# 8. test_trace_is_investigation_scoped
def test_trace_is_investigation_scoped(workspace_service: WorkspaceService):
    inv_a = workspace_service.create_investigation(CreateInvestigationRequest(name="Investigation A", target_host="api.target.local"))
    inv_b = workspace_service.create_investigation(CreateInvestigationRequest(name="Investigation B", target_host="api.target.local"))

    trace_a = {
        "run_id": "RUN-TEST-A",
        "investigation_id": inv_a.id,
        "task_type": "SECURITY_RESEARCH",
        "overall_status": "CASCADE_COMPLETED",
        "stages": [],
    }
    workspace_service.db.insert_cascade_trace(trace_a)

    traces_a = workspace_service.list_cascade_traces(inv_id=inv_a.id)
    traces_b = workspace_service.list_cascade_traces(inv_id=inv_b.id)

    assert any(t["run_id"] == "RUN-TEST-A" for t in traces_a)
    assert not any(t["run_id"] == "RUN-TEST-A" for t in traces_b)


# 9. test_conversational_7b_not_mislabeled_as_cascade
def test_conversational_7b_not_mislabeled_as_cascade(workspace_service: WorkspaceService):
    inv = workspace_service.create_investigation(CreateInvestigationRequest(name="Chat Investigation", target_host="api.target.local"))

    responses = workspace_service.send_message(inv.id, "Hello, who are you?")
    assert len(responses) == 1
    asst_msg = responses[0]

    # Must NOT have cascade trace ID
    assert asst_msg.cascade_trace_id is None
    # Must NOT be labeled as cascade
    assert asst_msg.model_name in ("qwen2.5-coder:7b", "local_rule_engine", "local_knowledge_engine")
    assert "Cascade" not in (asst_msg.model_name or "")


# 10. test_failed_cascade_not_marked_completed
def test_failed_cascade_not_marked_completed(sample_pack: LosslessStructuralPack):
    orchestrator = CascadeOrchestrator()
    orchestrator.triage_runner.run_triage = MagicMock(return_value=make_mock_triage())
    # Simulate 7B failure
    orchestrator.reasoning_runner.run_reasoning = MagicMock(return_value={
        "status": "ERROR",
        "error": "Ollama connection timeout during 7B inference",
    })

    trace, _ = orchestrator.execute_cascade(sample_pack)

    assert trace.overall_status in ("CASCADE_FAILED", "FAILED")
    assert trace.overall_status != "CASCADE_COMPLETED"
    assert trace.overall_status != "CASCADE_VERIFIED"
    assert trace.stages[3].status == "FAILED"


# 11. test_model_digest_reflects_runtime
def test_model_digest_reflects_runtime(sample_pack: LosslessStructuralPack):
    orchestrator = CascadeOrchestrator()
    orchestrator.triage_runner.run_triage = MagicMock(return_value=make_mock_triage())
    orchestrator.reasoning_runner.run_reasoning = MagicMock(return_value={"status": "SUCCESS"})

    trace, _ = orchestrator.execute_cascade(sample_pack)

    stage_3b = trace.stages[0]
    stage_7b = trace.stages[3]

    assert stage_3b.model_digest.startswith(PINNED_3B_DIGEST[:8])
    assert stage_7b.model_digest.startswith(PINNED_7B_DIGEST[:8])


# 12. test_no_secret_in_trace
def test_no_secret_in_trace(workspace_service: WorkspaceService):
    demo = workspace_service.load_demo_investigation()

    workspace_service.cascade_orchestrator.triage_runner.run_triage = MagicMock(return_value=make_mock_triage())
    workspace_service.cascade_orchestrator.reasoning_runner.run_reasoning = MagicMock(return_value={"status": "SUCCESS"})

    prompt_with_secret = "Analyze the evidence with authorization Bearer sensitive_api_key_xyz987"
    responses = workspace_service.send_message(demo.id, prompt_with_secret)
    trace_id = responses[0].cascade_trace_id

    trace = workspace_service.get_cascade_trace(trace_id)
    assert trace is not None

    trace_json_str = json.dumps(trace)
    assert "sensitive_api_key_xyz987" not in trace_json_str


# 13. test_historical_response_trace_lookup
def test_historical_response_trace_lookup(workspace_service: WorkspaceService):
    demo = workspace_service.load_demo_investigation()

    # Create two distinct traces
    trace_1 = {
        "run_id": "RUN-HIST-001",
        "investigation_id": demo.id,
        "task_type": "SECURITY_RESEARCH",
        "overall_status": "CASCADE_COMPLETED",
        "total_latency_seconds": 12.5,
        "stages": [{"stage_name": "Stage 1", "latency_seconds": 2.1}],
    }
    trace_2 = {
        "run_id": "RUN-HIST-002",
        "investigation_id": demo.id,
        "task_type": "SECURITY_RESEARCH",
        "overall_status": "CASCADE_COMPLETED",
        "total_latency_seconds": 25.0,
        "stages": [{"stage_name": "Stage 1", "latency_seconds": 4.2}],
    }
    workspace_service.db.insert_cascade_trace(trace_1)
    workspace_service.db.insert_cascade_trace(trace_2)

    msg_1_record = {
        "id": "MSG-RESP-001",
        "investigation_id": demo.id,
        "sequence_number": workspace_service.db.get_next_sequence_number(demo.id),
        "sender": "assistant",
        "content": "First response",
        "cascade_trace_id": "RUN-HIST-001",
    }
    workspace_service.db.insert_message(msg_1_record)

    msg_2_record = {
        "id": "MSG-RESP-002",
        "investigation_id": demo.id,
        "sequence_number": workspace_service.db.get_next_sequence_number(demo.id),
        "sender": "assistant",
        "content": "Second response",
        "cascade_trace_id": "RUN-HIST-002",
    }
    workspace_service.db.insert_message(msg_2_record)

    # Response 1 lookup must return Trace 1, NOT latest Trace 2
    lookup_1 = workspace_service.get_message_trace(demo.id, "MSG-RESP-001")
    assert lookup_1 is not None
    assert lookup_1["run_id"] == "RUN-HIST-001"
    assert lookup_1["total_latency_seconds"] == 12.5

    lookup_2 = workspace_service.get_message_trace(demo.id, "MSG-RESP-002")
    assert lookup_2 is not None
    assert lookup_2["run_id"] == "RUN-HIST-002"
    assert lookup_2["total_latency_seconds"] == 25.0


# 14. test_no_fake_telemetry
def test_no_fake_telemetry(workspace_service: WorkspaceService):
    status = workspace_service.get_system_status()
    # On fresh startup before any cascades execute, recent_traces must be empty
    assert status.recent_traces == []


# 15. test_cascade_trace_api_lookup
def test_cascade_trace_api_lookup(workspace_service: WorkspaceService):
    from fastapi.testclient import TestClient
    from src.dashboard.app import create_dashboard_app

    inv = workspace_service.create_investigation(CreateInvestigationRequest(name="API Inv", target_host="api.target.local"))

    from src.dashboard.auth import DashboardAuthManager, DashboardRole
    auth_mgr = DashboardAuthManager(db_manager=workspace_service.db)
    sess = auth_mgr.create_session("obs_tester", DashboardRole.ADMIN)
    app = create_dashboard_app(workspace_service=workspace_service, auth_manager=auth_mgr)
    client = TestClient(app, headers={"Authorization": f"Bearer {sess.token}"})

    # Insert test trace with valid foreign key
    trace = {
        "run_id": "RUN-API-001",
        "investigation_id": inv.id,
        "task_type": "SECURITY_RESEARCH",
        "overall_status": "CASCADE_COMPLETED",
        "total_latency_seconds": 5.4,
        "stages": [{"stage_name": "Stage 1", "latency_seconds": 1.2}],
    }
    workspace_service.db.insert_cascade_trace(trace)

    res = client.get("/api/cascade-traces/RUN-API-001")
    assert res.status_code == 200
    data = res.json()
    assert data["run_id"] == "RUN-API-001"
    assert data["total_latency_seconds"] == 5.4

    # 404 for unknown trace
    res_404 = client.get("/api/cascade-traces/RUN-NONEXISTENT")
    assert res_404.status_code == 404


# 16. test_message_trace_api_lookup
def test_message_trace_api_lookup(workspace_service: WorkspaceService):
    from fastapi.testclient import TestClient
    from src.dashboard.app import create_dashboard_app
    from src.dashboard.auth import DashboardAuthManager, DashboardRole

    inv = workspace_service.create_investigation(CreateInvestigationRequest(name="API Inv 2", target_host="api.target.local"))

    auth_mgr_2 = DashboardAuthManager(db_manager=workspace_service.db)
    sess_2 = auth_mgr_2.create_session("obs_tester_2", DashboardRole.ADMIN)
    app = create_dashboard_app(workspace_service=workspace_service, auth_manager=auth_mgr_2)
    client = TestClient(app, headers={"Authorization": f"Bearer {sess_2.token}"})

    trace = {
        "run_id": "RUN-API-002",
        "investigation_id": inv.id,
        "task_type": "SECURITY_RESEARCH",
        "overall_status": "CASCADE_COMPLETED",
        "stages": [],
    }
    workspace_service.db.insert_cascade_trace(trace)

    msg = {
        "id": "MSG-API-002",
        "investigation_id": inv.id,
        "sequence_number": workspace_service.db.get_next_sequence_number(inv.id),
        "sender": "assistant",
        "content": "Analysis response",
        "cascade_trace_id": "RUN-API-002",
    }
    workspace_service.db.insert_message(msg)

    res = client.get(f"/api/investigations/{inv.id}/messages/MSG-API-002/trace")
    assert res.status_code == 200
    data = res.json()
    assert data["run_id"] == "RUN-API-002"


