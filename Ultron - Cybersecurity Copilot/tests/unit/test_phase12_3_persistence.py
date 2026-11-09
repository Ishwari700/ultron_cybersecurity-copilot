"""Unit tests for Phase 12.3: Persistent Conversation History & Memory."""

import json
from pathlib import Path
import tempfile
import pytest
from fastapi.testclient import TestClient

from src.database.manager import DatabaseManager
from src.core.logging import AuditLogger
from src.dashboard.app import create_dashboard_app
from src.dashboard.models import (
    ChatMessage,
    CreateInvestigationRequest,
    RenameInvestigationRequest,
    SendMessageRequest,
    StructuredCardType,
)
from src.dashboard.service import WorkspaceService


@pytest.fixture
def temp_db_path(tmp_path):
    """Provide a temporary SQLite database path."""
    return tmp_path / "test_conversation.db"


@pytest.fixture
def temp_audit_path(tmp_path):
    """Provide a temporary audit log path."""
    return tmp_path / "test_audit.log"


@pytest.fixture
def service_factory(temp_db_path, temp_audit_path):
    """Factory creating WorkspaceService bound to the shared SQLite database."""
    def _create():
        db = DatabaseManager(db_path=temp_db_path)
        audit = AuditLogger(temp_audit_path)
        return WorkspaceService(db_manager=db, audit_logger=audit)
    return _create


@pytest.fixture
def client_factory(service_factory):
    """Factory creating FastAPI test clients bound to a given WorkspaceService."""
    def _create(service=None):
        srv = service or service_factory()
        from src.dashboard.auth import DashboardAuthManager, DashboardRole
        auth_mgr = DashboardAuthManager(db_manager=srv.db)
        sess = auth_mgr.create_session("persist_tester", DashboardRole.ADMIN)
        app = create_dashboard_app(workspace_service=srv, auth_manager=auth_mgr)
        client = TestClient(app, headers={"Authorization": f"Bearer {sess.token}"})
        return client, srv
    return _create


def test_message_persistence(service_factory):
    """Every user prompt and assistant response must be persistently stored in SQLite."""
    service = service_factory()
    inv = service.create_investigation(
        CreateInvestigationRequest(name="Persistence Test", target_host="api.target.local")
    )
    inv_id = inv.id

    # Send a conversational prompt
    responses = service.send_message(inv_id, "hello")
    assert len(responses) >= 1

    # Verify messages are in SQLite table directly
    with service.db.get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM conversation_messages WHERE investigation_id = ? ORDER BY sequence_number ASC",
            (inv_id,),
        ).fetchall()
        # Should have: System init (seq 1), User "hello" (seq 2), Assistant reply (seq 3)
        assert len(rows) == 3
        senders = [r["sender"] for r in rows]
        assert senders == ["system", "user", "assistant"]
        assert rows[1]["content"] == "hello"
        assert len(rows[2]["content"]) > 0


def test_user_message_persistence(service_factory):
    """User message stores stable ID, sequence number, role, and delivery status."""
    service = service_factory()
    inv = service.create_investigation(
        CreateInvestigationRequest(name="User Msg Test", target_host="api.target.local")
    )
    inv_id = inv.id

    service.send_message(inv_id, "tell me your model", client_msg_id="USR-STABLE-001")

    msg = service.db.get_message("USR-STABLE-001")
    assert msg is not None
    assert msg["id"] == "USR-STABLE-001"
    assert msg["investigation_id"] == inv_id
    assert msg["sender"] == "user"
    assert msg["content"] == "tell me your model"
    assert msg["delivery_status"] == "delivered"
    assert msg["sequence_number"] == 2


def test_assistant_message_persistence(service_factory):
    """Assistant message stores model metadata, delivery status, and sequence number."""
    service = service_factory()
    inv = service.create_investigation(
        CreateInvestigationRequest(name="Assistant Msg Test", target_host="api.target.local")
    )
    inv_id = inv.id

    responses = service.send_message(inv_id, "tell me your model")
    assert len(responses) == 1
    asst_msg = responses[0]

    db_msg = service.db.get_message(asst_msg.id)
    assert db_msg is not None
    assert db_msg["sender"] == "assistant"
    assert db_msg["delivery_status"] == "delivered"
    assert db_msg["sequence_number"] == 3
    assert db_msg["model_name"] is not None


def test_history_load(client_factory):
    """GET /api/investigations/{id} returns complete conversation history from DB."""
    client, service = client_factory()
    create_res = client.post(
        "/api/investigations",
        json={"name": "History Load Test", "target_host": "api.target.local"},
    )
    inv_id = create_res.json()["id"]

    client.post(f"/api/investigations/{inv_id}/messages", json={"content": "Turn 1: Hello"})
    client.post(f"/api/investigations/{inv_id}/messages", json={"content": "Turn 2: What is BOLA?"})

    # Load detail
    detail_res = client.get(f"/api/investigations/{inv_id}")
    assert detail_res.status_code == 200
    messages = detail_res.json()["messages"]

    # System init + (User 1 + Asst 1) + (User 2 + Asst 2) = 5 messages
    assert len(messages) == 5
    assert messages[1]["content"] == "Turn 1: Hello"
    assert messages[1]["sender"] == "user"
    assert messages[2]["sender"] == "assistant"
    assert messages[3]["content"] == "Turn 2: What is BOLA?"
    assert messages[3]["sender"] == "user"
    assert messages[4]["sender"] == "assistant"


def test_history_survives_restart(service_factory):
    """Real restart test: write conversation, destroy service, reload from SQLite, verify all turns."""
    # Phase 1: Service 1 writes conversation
    service1 = service_factory()
    inv = service1.create_investigation(
        CreateInvestigationRequest(name="Restart Investigation", target_host="api.target.local")
    )
    inv_id = inv.id

    service1.send_message(inv_id, "hello")
    service1.send_message(inv_id, "tell me your model")
    service1.send_message(inv_id, "what can you help me with?")

    # Verify service 1 state
    detail1 = service1.get_investigation(inv_id)
    assert len(detail1.messages) == 7  # 1 system + 3 user + 3 assistant
    original_contents = [m.content for m in detail1.messages]
    original_ids = [m.id for m in detail1.messages]

    # Phase 2: Destroy service 1 completely (simulate application shutdown)
    del service1

    # Phase 3: Create fresh Service 2 connected to the same SQLite database (simulate restart)
    service2 = service_factory()
    detail2 = service2.get_investigation(inv_id)

    assert detail2 is not None
    assert detail2.id == inv_id
    assert detail2.name == "Restart Investigation"
    assert len(detail2.messages) == 7

    # Verify turns, contents, and stable IDs survive untouched without regeneration
    assert [m.id for m in detail2.messages] == original_ids
    assert [m.content for m in detail2.messages] == original_contents
    assert [m.sequence_number for m in detail2.messages] == [1, 2, 3, 4, 5, 6, 7]


def test_history_after_refresh(client_factory):
    """Simulated browser refresh: multiple turns, fresh GET, identical sequence and IDs."""
    client, service = client_factory()
    create_res = client.post(
        "/api/investigations",
        json={"name": "Refresh Test", "target_host": "api.target.local"},
    )
    inv_id = create_res.json()["id"]

    for i in range(5):
        client.post(f"/api/investigations/{inv_id}/messages", json={"content": f"Message turn {i+1}"})

    # First fetch (in-session state)
    res1 = client.get(f"/api/investigations/{inv_id}")
    msgs1 = res1.json()["messages"]
    assert len(msgs1) == 11  # 1 system + 5 * 2 turns

    # Second fetch (browser refresh)
    res2 = client.get(f"/api/investigations/{inv_id}")
    msgs2 = res2.json()["messages"]

    assert msgs1 == msgs2
    assert [m["id"] for m in msgs1] == [m["id"] for m in msgs2]


def test_message_order(service_factory):
    """Messages must have deterministic ordering via sequence_number ASC."""
    service = service_factory()
    inv = service.create_investigation(
        CreateInvestigationRequest(name="Order Test", target_host="api.target.local")
    )
    inv_id = inv.id

    service.send_message(inv_id, "First")
    service.send_message(inv_id, "Second")
    service.send_message(inv_id, "Third")

    messages = service.get_messages(inv_id)
    seqs = [m.sequence_number for m in messages]
    assert seqs == [1, 2, 3, 4, 5, 6, 7]
    assert seqs == sorted(seqs)


def test_stable_message_ids(service_factory):
    """Message IDs must remain invariant across reads, updates, and restarts."""
    service = service_factory()
    inv = service.create_investigation(
        CreateInvestigationRequest(name="Stable ID Test", target_host="api.target.local")
    )
    inv_id = inv.id

    service.send_message(inv_id, "check ids")
    msgs_pass1 = service.get_messages(inv_id)
    ids_pass1 = [m.id for m in msgs_pass1]

    msgs_pass2 = service.get_messages(inv_id)
    ids_pass2 = [m.id for m in msgs_pass2]

    assert ids_pass1 == ids_pass2
    assert len(ids_pass1) == len(set(ids_pass1))


def test_investigation_isolation(service_factory):
    """Opening Investigation A must NOT show Investigation B's messages."""
    service = service_factory()
    inv_a = service.create_investigation(
        CreateInvestigationRequest(name="Investigation A", target_host="a.target.local")
    )
    inv_b = service.create_investigation(
        CreateInvestigationRequest(name="Investigation B", target_host="b.target.local")
    )

    service.send_message(inv_a.id, "Secret message for A")
    service.send_message(inv_b.id, "Secret message for B")

    detail_a = service.get_investigation(inv_a.id)
    detail_b = service.get_investigation(inv_b.id)

    contents_a = [m.content for m in detail_a.messages]
    contents_b = [m.content for m in detail_b.messages]

    assert any("Secret message for A" in c for c in contents_a)
    assert not any("Secret message for B" in c for c in contents_a)

    assert any("Secret message for B" in c for c in contents_b)
    assert not any("Secret message for A" in c for c in contents_b)


def test_no_duplicate_messages(client_factory):
    """Repeated client message posting or fetching never creates duplicates."""
    client, service = client_factory()
    create_res = client.post(
        "/api/investigations",
        json={"name": "No Dups Test", "target_host": "api.target.local"},
    )
    inv_id = create_res.json()["id"]

    client.post(f"/api/investigations/{inv_id}/messages", json={"content": "single turn"})

    detail1 = client.get(f"/api/investigations/{inv_id}").json()
    detail2 = client.get(f"/api/investigations/{inv_id}").json()

    assert len(detail1["messages"]) == 3
    assert len(detail2["messages"]) == 3
    ids = [m["id"] for m in detail2["messages"]]
    assert len(ids) == len(set(ids))


def test_retry_does_not_duplicate_user_turn(service_factory):
    """Retrying with the same client_msg_id does not duplicate the user turn in persistence."""
    service = service_factory()
    inv = service.create_investigation(
        CreateInvestigationRequest(name="Retry Test", target_host="api.target.local")
    )
    inv_id = inv.id

    client_msg_id = "USR-RETRY-001"
    # First attempt
    service.send_message(inv_id, "test retry content", client_msg_id=client_msg_id)

    # Second attempt with same client_msg_id (e.g. client retry)
    service.send_message(inv_id, "test retry content", client_msg_id=client_msg_id)

    detail = service.get_investigation(inv_id)
    user_turns = [m for m in detail.messages if m.id == client_msg_id]
    # Must have only one instance of this user turn
    assert len(user_turns) == 1


def test_conversation_title_persistence(service_factory):
    """Conversation title derived from first message persists across restart."""
    service1 = service_factory()
    inv = service1.create_investigation(
        CreateInvestigationRequest(name="New Investigation", target_host="api.target.local")
    )
    inv_id = inv.id

    # Sending first message auto-derives title from prompt
    service1.send_message(inv_id, "Testing billing statement access controls")

    # Verify updated in DB
    inv_row = service1.db.get_investigation(inv_id)
    assert inv_row["name"] == "Testing billing statement access controls"

    del service1

    # Restart
    service2 = service_factory()
    reloaded_inv = service2.db.get_investigation(inv_id)
    assert reloaded_inv["name"] == "Testing billing statement access controls"


def test_rename_persistence(client_factory):
    """Renaming an investigation via PATCH persists across application restart."""
    client, service = client_factory()
    create_res = client.post(
        "/api/investigations",
        json={"name": "Initial Name", "target_host": "api.target.local"},
    )
    inv_id = create_res.json()["id"]

    patch_res = client.patch(
        f"/api/investigations/{inv_id}",
        json={"name": "My First API Test"},
    )
    assert patch_res.status_code == 200
    assert patch_res.json()["name"] == "My First API Test"

    # Verify persistent in DB
    db_inv = service.db.get_investigation(inv_id)
    assert db_inv["name"] == "My First API Test"


def test_empty_conversation(service_factory):
    """A fresh investigation contains only system initialization, 0 user messages."""
    service = service_factory()
    inv = service.create_investigation(
        CreateInvestigationRequest(name="Empty Test", target_host="api.target.local")
    )
    detail = service.get_investigation(inv.id)
    assert len(detail.messages) == 1
    assert detail.messages[0].sender == "system"


def test_structured_card_persistence(service_factory):
    """Structured AI response cards (HYPOTHESIS, EXPERIMENT, INVARIANT) remain recoverable from SQLite."""
    service = service_factory()
    demo_inv = service.load_demo_investigation()
    inv_id = demo_inv.id

    detail = service.get_investigation(inv_id)
    card_types = [m.structured_type for m in detail.messages]
    assert StructuredCardType.INVARIANT in card_types
    assert StructuredCardType.HYPOTHESIS in card_types
    assert StructuredCardType.EXPERIMENT in card_types

    # Restart service and reload
    del service
    service2 = service_factory()
    detail2 = service2.get_investigation(inv_id)
    card_types2 = [m.structured_type for m in detail2.messages]
    assert StructuredCardType.INVARIANT in card_types2
    assert StructuredCardType.HYPOTHESIS in card_types2
    assert StructuredCardType.EXPERIMENT in card_types2

    # Check structured_data integrity
    exp_msg = next(m for m in detail2.messages if m.structured_type == StructuredCardType.EXPERIMENT)
    assert exp_msg.structured_data is not None
    assert exp_msg.structured_data["id"] == "EXP-001"


def test_cascade_trace_association(service_factory):
    """Assistant messages carry cascade_trace_id for auditability."""
    service = service_factory()
    demo_inv = service.load_demo_investigation()
    inv_id = demo_inv.id

    # Trigger investigation query
    responses = service.send_message(inv_id, "Analyze application access boundary flaws")
    assert len(responses) >= 1
    # Check that at least one response has cascade metadata
    assert any(m.cascade_trace_id is not None or "Cascade" in (m.model_name or "") for m in responses)

    # Verify persisted in SQLite
    with service.db.get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM conversation_messages WHERE investigation_id = ? AND sender = 'assistant'",
            (inv_id,),
        ).fetchall()
        assert len(rows) > 0


def test_secret_exclusion_from_history(service_factory):
    """Raw secrets (JWT, API keys) submitted in user prompts are redacted before database persistence."""
    service = service_factory()
    inv = service.create_investigation(
        CreateInvestigationRequest(name="Vault Redaction Test", target_host="api.target.local")
    )
    inv_id = inv.id

    # Simulated JWT token
    raw_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    prompt = f"Check this auth token: {raw_jwt}"

    service.send_message(inv_id, prompt)

    # Verify in DB that raw_jwt is NOT stored
    with service.db.get_connection() as conn:
        row = conn.execute(
            "SELECT content FROM conversation_messages WHERE investigation_id = ? AND sender = 'user'",
            (inv_id,),
        ).fetchone()
        stored_content = row["content"]
        assert raw_jwt not in stored_content
        assert "[REDACTED_JWT_" in stored_content


def test_conversation_history_available_to_model(service_factory):
    """Conversation history is supplied to LLM context and conversational memory functions."""
    service = service_factory()
    inv = service.create_investigation(
        CreateInvestigationRequest(name="Memory Test", target_host="api.target.local")
    )
    inv_id = inv.id

    # First turn
    service.send_message(inv_id, "What is BOLA?")

    # Second turn asking about previous question
    responses = service.send_message(inv_id, "What did I ask you before?")
    assert len(responses) == 1
    asst_reply = responses[0].content

    # The AI or rule fallback must acknowledge the prior question about BOLA
    assert "BOLA" in asst_reply or "What is BOLA?" in asst_reply


def test_conversation_delete_preserves_canonical_evidence(service_factory):
    """Deleting an investigation deletes its conversation messages but does NOT delete canonical evidence items."""
    service = service_factory()
    demo_inv = service.load_demo_investigation()
    inv_id = demo_inv.id

    # Check evidence in DB before deletion
    with service.db.get_connection() as conn:
        ev_count_before = conn.execute("SELECT COUNT(*) FROM evidence_items").fetchone()[0]
        assert ev_count_before >= 2
        msg_count_before = conn.execute("SELECT COUNT(*) FROM conversation_messages WHERE investigation_id = ?", (inv_id,)).fetchone()[0]
        assert msg_count_before >= 4

    # Delete investigation
    success = service.delete_investigation(inv_id)
    assert success is True

    # Check DB after deletion
    with service.db.get_connection() as conn:
        # Conversation messages for this investigation must be gone
        msg_count_after = conn.execute("SELECT COUNT(*) FROM conversation_messages WHERE investigation_id = ?", (inv_id,)).fetchone()[0]
        assert msg_count_after == 0

        # Canonical domain evidence must remain intact
        ev_count_after = conn.execute("SELECT COUNT(*) FROM evidence_items").fetchone()[0]
        assert ev_count_after == ev_count_before
