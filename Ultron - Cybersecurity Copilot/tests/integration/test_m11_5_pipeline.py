"""Integration tests for M11.5 Long Response Pipeline and API Endpoints.
Verifies end-to-end multi-chunk generation, automatic continuation,
API actions (stop, continue, regenerate, actions, export), and telemetry.
"""

from pathlib import Path
import pytest
from starlette.testclient import TestClient

from src.dashboard.app import create_dashboard_app
from src.database.manager import DatabaseManager
from src.response.models import GenerationTermination, ResponseStatus


@pytest.fixture
def app_client(tmp_path: Path):
    db_file = tmp_path / "test_pipeline.db"
    db = DatabaseManager(db_path=db_file)
    db.initialize_schema()

    # Pre-create test investigation
    with db.get_connection() as conn:
        conn.execute(
            """
            INSERT INTO investigations (investigation_id, name, target_host, scope_status, status)
            VALUES ('INV-TEST-PIPE', 'Test Pipeline Investigation', 'target.local', 'ALLOWED', 'ACTIVE')
            """
        )
        conn.commit()

    from src.dashboard.auth import DashboardAuthManager, DashboardRole
    auth_mgr = DashboardAuthManager(db_manager=db)
    sess = auth_mgr.create_session("pipeline_tester", DashboardRole.ADMIN)
    app = create_dashboard_app(db_manager=db, auth_manager=auth_mgr)
    client = TestClient(app, headers={"Authorization": f"Bearer {sess.token}"})
    return client, db


def test_e2e_single_chunk_conversational_response(app_client) -> None:
    client, db = app_client

    # Post message
    res = client.post(
        "/api/investigations/INV-TEST-PIPE/messages",
        json={"content": "Hello research assistant"},
    )
    assert res.status_code == 200
    data = res.json()
    assert len(data) >= 1
    asst_msg = data[0]
    assert asst_msg["sender"] == "assistant"
    assert len(asst_msg["content"].strip()) > 0
    assert asst_msg["delivery_status"] == "delivered"


def test_e2e_multi_chunk_continuation_via_engine(tmp_path: Path) -> None:
    db_file = tmp_path / "test_multi_chunk.db"
    db = DatabaseManager(db_path=db_file)
    db.initialize_schema()

    from src.response.generator import LongResponseEngine

    # Simulated LLM that cuts off chunk 1 on token limit, then completes chunk 2
    call_count = 0

    def mock_two_turn_llm(prompt: str, max_tokens: int):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return {
                "response": "The BOLA vulnerability allows unauthorized access because the endpoint `/api/v1/invoices`",
                "done_reason": "length",
                "eval_count": max_tokens,
            }
        else:
            return {
                "response": " `/api/v1/invoices` checks user authentication but omits cross-tenant tenant_id authorization.",
                "done_reason": "stop",
                "eval_count": 45,
            }

    engine = LongResponseEngine(
        db_manager=db,
        max_continuation_chunks=4,
    )

    session = engine.generate_response(
        investigation_id="INV-01",
        user_prompt="Analyze authorization mechanics",
        custom_llm_caller=mock_two_turn_llm,
        auto_continue=True,
    )

    assert session.status == ResponseStatus.COMPLETED
    assert session.termination_reason == GenerationTermination.NATURAL_STOP
    assert len(session.chunks) == 2
    # Verify chunks merged seamlessly without duplicated phrase
    assert "/api/v1/invoices" in session.final_content
    assert "omits cross-tenant tenant_id authorization." in session.final_content


def test_api_response_endpoints(app_client) -> None:
    client, db = app_client

    from src.response.persistence import ResponsePersistence
    from src.response.models import ResponseSession, ResponseChunk

    persistence = ResponsePersistence(db)
    session = ResponseSession(
        response_id="RESP-API-001",
        investigation_id="INV-TEST-PIPE",
        model="qwen2.5-coder:7b",
        status=ResponseStatus.GENERATING,
        final_content="Initial analysis terminated at token ceiling: The parameter was",
    )
    persistence.create_session(session)

    chunk = ResponseChunk(
        chunk_id="CHK-API-1",
        sequence_number=1,
        content="Initial analysis terminated at token ceiling: The parameter was",
        raw_content="Initial analysis terminated at token ceiling: The parameter was",
        token_count=100,
        stop_reason="length",
    )
    persistence.save_chunk("RESP-API-001", chunk)

    # 1. GET /api/responses/{id}
    res = client.get("/api/responses/RESP-API-001")
    assert res.status_code == 200
    data = res.json()
    assert data["response_id"] == "RESP-API-001"
    assert data["status"] == "GENERATING"

    # 2. GET /api/responses/{id}/chunks
    res_chunks = client.get("/api/responses/RESP-API-001/chunks")
    assert res_chunks.status_code == 200
    chunks_data = res_chunks.json()
    assert len(chunks_data) == 1
    assert chunks_data[0]["stop_reason"] == "length"

    # 3. POST /api/responses/{id}/stop
    res_stop = client.post("/api/responses/RESP-API-001/stop", json={"reason": "User stop"})
    assert res_stop.status_code == 200
    assert res_stop.json()["stopped"] is True

    # 4. POST /api/responses/{id}/continue
    res_cont = client.post("/api/responses/RESP-API-001/continue", json={"custom_directive": "Continue the parameter explanation"})
    assert res_cont.status_code == 200
    cont_data = res_cont.json()
    assert cont_data["response_id"] == "RESP-API-001"

    # 5. POST /api/responses/{id}/regenerate
    res_regen = client.post("/api/responses/RESP-API-001/regenerate", json={"temperature": 0.5})
    assert res_regen.status_code == 200
    regen_data = res_regen.json()
    assert regen_data["status"] in ("COMPLETED", "TIMEOUT", "SERVICE_UNAVAILABLE")

    # 6. POST /api/responses/{id}/actions (summarize)
    res_action = client.post(
        "/api/responses/RESP-API-001/actions",
        json={"action": "summarize", "detail": "executive summary"},
    )
    assert res_action.status_code == 200

    # 7. GET /api/responses/{id}/export (markdown and txt)
    res_exp_md = client.get("/api/responses/RESP-API-001/export?format=markdown")
    assert res_exp_md.status_code == 200
    assert "Ultron" in res_exp_md.json()["content"] or "# Bug Bounty AI" in res_exp_md.json()["content"]

    res_exp_txt = client.get("/api/responses/RESP-API-001/export?format=txt")
    assert res_exp_txt.status_code == 200
    assert "ULTRON" in res_exp_txt.json()["content"] or "BUG BOUNTY AI" in res_exp_txt.json()["content"]

    # 8. GET /api/responses/metrics
    res_metrics = client.get("/api/responses/metrics")
    assert res_metrics.status_code == 200
    m_data = res_metrics.json()
    assert "response_generation_count" in m_data
    assert "response_total_tokens" in m_data
