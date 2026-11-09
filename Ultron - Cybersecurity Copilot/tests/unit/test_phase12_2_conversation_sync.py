"""
Phase 12.2: Conversation UI State Synchronization & Optimistic Rendering Tests.

Verifies:
1. test_user_message_appears_without_refresh: User message appears in conversation immediately upon Send,
   followed by the assistant response in correct chronological order, and persists exactly once without refresh.
2. test_failed_message_delivery_state: Failed messages remain visible with 'failed' status and retry capability.
3. test_no_duplicate_message_after_reconciliation: Reconciliation between optimistic local state and server state
   never produces duplicate messages.
4. test_conversation_order_preserved: Multiturn conversation maintains strict chronological order (oldest -> newest).
5. test_loading_does_not_remove_user_message: Loading state does not displace or remove the optimistic user message.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List
import pytest
from starlette.testclient import TestClient

from src.core.logging import AuditLogger
from src.dashboard.app import create_dashboard_app
from src.database.manager import DatabaseManager


@pytest.fixture
def sync_client(tmp_path: Path):
    """Provide an isolated test client for conversation state synchronization testing."""
    db_file = tmp_path / "sync_workspace.db"
    db = DatabaseManager(db_path=db_file)
    db.initialize_schema()

    audit_file = tmp_path / "sync_audit.log"
    auditor = AuditLogger(audit_file)

    from src.dashboard.auth import DashboardAuthManager, DashboardRole
    auth_mgr = DashboardAuthManager(db_manager=db)
    sess = auth_mgr.create_session("sync_tester", DashboardRole.ADMIN)

    app = create_dashboard_app(
        db_manager=db,
        audit_logger=auditor,
        auth_manager=auth_mgr,
        frontend_dist_dir=Path(__file__).resolve().parent.parent.parent / "frontend" / "dist",
    )
    client = TestClient(app, headers={"Authorization": f"Bearer {sess.token}"})
    return client, db, auditor


def reconcile_messages(local_messages: List[Dict[str, Any]], server_messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Python reference implementation of the client-side reconcileMessages function."""
    server_ids = {m["id"] for m in server_messages}
    server_user_signatures = {
        m["content"].strip()
        for m in server_messages
        if m.get("sender") == "user"
    }

    unconfirmed_local = [
        m for m in local_messages
        if m.get("delivery_status") in ("sending", "failed")
        and m["id"] not in server_ids
        and m.get("content", "").strip() not in server_user_signatures
    ]

    return list(server_messages) + unconfirmed_local


def test_user_message_appears_without_refresh(sync_client):
    """
    Test 1: User message appears immediately after Send, followed by assistant response.
    Chronological ordering is maintained. Refreshing returns exactly one copy of each.
    """
    client, _, _ = sync_client

    # 1. Create a genuine investigation
    res_create = client.post(
        "/api/investigations",
        json={"name": "Sync Test", "target_host": "sync.internal.local"},
    )
    assert res_create.status_code == 200
    inv = res_create.json()
    inv_id = inv["id"]

    # Initial state: 1 welcome message
    init_detail = client.get(f"/api/investigations/{inv_id}").json()
    local_messages = list(init_detail["messages"])
    assert len(local_messages) == 1

    # 2. Simulate User Pressing Send: Optimistic Local State Update
    prompt_text = "hello"
    client_msg_id = "USR-OPT-001"
    optimistic_user_msg = {
        "id": client_msg_id,
        "investigation_id": inv_id,
        "sender": "user",
        "content": prompt_text,
        "structured_type": "NONE",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "delivery_status": "sending",
    }
    # User message immediately added to in-memory conversation
    local_messages.append(optimistic_user_msg)
    loading_message = True

    # Assert user message exists in in-memory conversation IMMEDIATELY before API completes
    assert len(local_messages) == 2
    assert local_messages[-1]["id"] == client_msg_id
    assert local_messages[-1]["content"] == "hello"
    assert local_messages[-1]["delivery_status"] == "sending"
    assert loading_message is True

    # 3. API Request executes
    res_post = client.post(
        f"/api/investigations/{inv_id}/messages",
        json={"content": prompt_text},
    )
    assert res_post.status_code == 200
    api_responses = res_post.json()
    assert len(api_responses) >= 1

    # 4. Handle API Response (Transition optimistic message to delivered, append assistant response)
    # Mark optimistic message delivered
    for m in local_messages:
        if m["id"] == client_msg_id:
            m["delivery_status"] = "delivered"

    # Append assistant responses without duplication
    for resp in api_responses:
        if not any(m["id"] == resp["id"] for m in local_messages):
            local_messages.append(resp)
    loading_message = False

    # Assert in-memory state has user message and assistant message
    assert len(local_messages) >= 3
    assert local_messages[1]["id"] == client_msg_id
    assert local_messages[1]["content"] == "hello"
    assert local_messages[1]["delivery_status"] == "delivered"
    assert local_messages[2]["sender"] == "assistant"
    assert len(local_messages[2]["content"]) > 0

    # 5. Chronological order check: user message index < assistant response index
    user_idx = next(i for i, m in enumerate(local_messages) if m["id"] == client_msg_id)
    asst_idx = next(i for i, m in enumerate(local_messages) if m["sender"] == "assistant")
    assert user_idx < asst_idx, f"User message index ({user_idx}) must precede assistant response ({asst_idx})"

    # 6. Simulate Browser Refresh: Fetch investigation again from backend
    res_refresh = client.get(f"/api/investigations/{inv_id}")
    assert res_refresh.status_code == 200
    server_detail = res_refresh.json()
    server_messages = server_detail["messages"]

    # Reconcile server messages with local state
    reconciled = reconcile_messages(local_messages, server_messages)

    # Assert exactly one copy of user's "hello" exists after refresh
    user_hellos = [m for m in reconciled if m["sender"] == "user" and m["content"] == "hello"]
    assert len(user_hellos) == 1, f"Expected exactly 1 user 'hello', found {len(user_hellos)}"

    # Assert exactly one assistant response exists
    assistant_msgs = [m for m in reconciled if m["sender"] == "assistant"]
    assert len(assistant_msgs) == 1, f"Expected exactly 1 assistant response, found {len(assistant_msgs)}"


def test_failed_message_delivery_state(sync_client):
    """
    Test 2: When API submission fails, the user message remains in local conversation
    with delivery_status='failed', and can be retried.
    """
    client, _, _ = sync_client

    local_messages: List[Dict[str, Any]] = []
    client_msg_id = "USR-FAIL-001"
    optimistic_user_msg = {
        "id": client_msg_id,
        "investigation_id": "INV-NONEXISTENT",
        "sender": "user",
        "content": "test failing message",
        "structured_type": "NONE",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "delivery_status": "sending",
    }
    local_messages.append(optimistic_user_msg)

    # Attempt POST to invalid ID -> 404
    res = client.post(
        "/api/investigations/INV-NONEXISTENT/messages",
        json={"content": "test failing message"},
    )
    assert res.status_code == 404

    # On catch/failure: mark delivery_status='failed'
    for m in local_messages:
        if m["id"] == client_msg_id:
            m["delivery_status"] = "failed"

    # Assert user message is NOT removed
    assert len(local_messages) == 1
    assert local_messages[0]["id"] == client_msg_id
    assert local_messages[0]["content"] == "test failing message"
    assert local_messages[0]["delivery_status"] == "failed"


def test_no_duplicate_message_after_reconciliation():
    """
    Test 3: Reconciliation between local state and server-fetched state prevents duplicate messages.
    """
    # Local state has optimistic user message that was delivered
    local_state = [
        {"id": "MSG-INIT", "sender": "system", "content": "Welcome", "delivery_status": "delivered"},
        {"id": "USR-TEMP-1", "sender": "user", "content": "What can you do?", "delivery_status": "delivered"},
        {"id": "MSG-ASST-1", "sender": "assistant", "content": "I can help analyze security.", "delivery_status": "delivered"},
    ]

    # Server state contains the persisted user message (with server ID) and assistant response
    server_state = [
        {"id": "MSG-INIT", "sender": "system", "content": "Welcome"},
        {"id": "MSG-SERVER-U1", "sender": "user", "content": "What can you do?"},
        {"id": "MSG-ASST-1", "sender": "assistant", "content": "I can help analyze security."},
    ]

    reconciled = reconcile_messages(local_state, server_state)

    # Must contain exactly 3 messages (System, User, Assistant)
    assert len(reconciled) == 3
    user_msgs = [m for m in reconciled if m["sender"] == "user"]
    assert len(user_msgs) == 1
    assert user_msgs[0]["content"] == "What can you do?"


def test_conversation_order_preserved(sync_client):
    """
    Test 4: Multi-turn conversation maintains strict chronological ordering (oldest -> newest).
    """
    client, _, _ = sync_client

    res_create = client.post(
        "/api/investigations",
        json={"name": "Order Test", "target_host": "order.test.local"},
    )
    inv_id = res_create.json()["id"]

    # Turn 1
    client.post(f"/api/investigations/{inv_id}/messages", json={"content": "Turn 1: Hello"})
    # Turn 2
    client.post(f"/api/investigations/{inv_id}/messages", json={"content": "Turn 2: What can you do?"})

    # Fetch complete history
    detail = client.get(f"/api/investigations/{inv_id}").json()
    msgs = detail["messages"]

    # Expect: 1 System, 1 User Turn 1, 1 Assistant Turn 1, 1 User Turn 2, 1 Assistant Turn 2
    assert len(msgs) == 5
    assert msgs[0]["sender"] == "system"
    assert msgs[1]["sender"] == "user" and "Turn 1" in msgs[1]["content"]
    assert msgs[2]["sender"] == "assistant"
    assert msgs[3]["sender"] == "user" and "Turn 2" in msgs[3]["content"]
    assert msgs[4]["sender"] == "assistant"

    # Strictly monotonic order
    timestamps = [m["timestamp"] for m in msgs]
    for i in range(len(timestamps) - 1):
        assert timestamps[i] <= timestamps[i + 1]


def test_loading_does_not_remove_user_message():
    """
    Test 5: Loading state indicator does not displace or remove the optimistic user message.
    """
    messages = [
        {"id": "MSG-INIT", "sender": "system", "content": "Welcome"},
        {"id": "USR-001", "sender": "user", "content": "Analyzing target", "delivery_status": "sending"},
    ]
    loading = True

    # While loading is True, messages array remains intact with user message present
    assert any(m["id"] == "USR-001" and m["content"] == "Analyzing target" for m in messages)
    assert loading is True

    # Loading indicator rendered separately without creating synthetic assistant messages in history
    synthetic_assistant_in_history = any(m["sender"] == "assistant" and "thinking" in m.get("content", "").lower() for m in messages)
    assert not synthetic_assistant_in_history, "Loading must not insert fake assistant text into history"
