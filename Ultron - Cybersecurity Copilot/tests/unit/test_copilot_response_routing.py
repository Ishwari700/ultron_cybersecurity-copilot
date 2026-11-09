"""Unit tests verifying Copilot response routing and generic response bug repair."""

import pytest
from unittest.mock import MagicMock, patch

from src.core.logging import AuditLogger
from src.database.manager import DatabaseManager
from src.dashboard.service import WorkspaceService
from src.dashboard.models import CreateInvestigationRequest, ChatMessage


@pytest.fixture
def workspace_service(tmp_path):
    """Create an isolated WorkspaceService instance backed by temp sqlite."""
    db_path = tmp_path / "test_workspace.db"
    db = DatabaseManager(db_path=db_path)
    db.initialize_schema()
    auditor = AuditLogger(tmp_path / "test_audit.log")
    service = WorkspaceService(db_manager=db, audit_logger=auditor)
    return service


def test_no_canned_intro_returned(workspace_service):
    """Invariant: The generic canned intro string must NEVER be returned for any query."""
    canned_string = "I'm your local security research assistant. You can provide target observations"
    inv = workspace_service.create_investigation(
        CreateInvestigationRequest(name="Test Investigation", target_host="lab.target.local")
    )

    test_queries = [
        "tell me how can i check my androids security",
        "tell me about android security",
        "Explain Android application security and the first areas a researcher should review.",
        "Explain volumetric DDoS attacks and how organizations defend against them.",
        "Explain the difference between authentication and authorization.",
        "what is the capital of France?",
        "hello",
        "who are you",
    ]

    for q in test_queries:
        responses = workspace_service.send_message(inv.id, q)
        assert len(responses) >= 1
        for resp in responses:
            assert canned_string not in resp.content, (
                f"Query '{q}' returned the forbidden canned greeting!"
            )


def test_distinct_queries_receive_distinct_substantive_responses(workspace_service):
    """Invariant: Two distinct conceptual questions must receive distinct, relevant answers."""
    inv = workspace_service.create_investigation(
        CreateInvestigationRequest(name="Distinct Test", target_host="lab.target.local")
    )

    q1 = "tell me how can i check my androids security"
    q2 = "tell me about android security"

    r1 = workspace_service.send_message(inv.id, q1)
    r2 = workspace_service.send_message(inv.id, q2)

    assert len(r1) >= 1 and len(r2) >= 1
    # Both must have substantive content
    assert len(r1[0].content) > 50
    assert len(r2[0].content) > 50
    # Must be distinct answers
    assert r1[0].content != r2[0].content
    # Provenance must be accurate
    assert r1[0].model_name in ("local_knowledge_engine", "qwen2.5-coder:7b")
    assert r2[0].model_name in ("local_knowledge_engine", "qwen2.5-coder:7b")


def test_android_security_knowledge_routing(workspace_service):
    """Conceptual Android security review routes to authoritative VAPT knowledge."""
    inv = workspace_service.create_investigation(
        CreateInvestigationRequest(name="Android Review", target_host="lab.target.local")
    )

    q = "Explain Android application security and the first areas a researcher should review."
    responses = workspace_service.send_message(inv.id, q)

    assert len(responses) == 1
    resp = responses[0]
    assert resp.status == "COMPLETED"
    assert resp.model_name in ("local_knowledge_engine", "qwen2.5-coder:7b")
    # Verify content mentions Android static analysis concepts
    content_lower = resp.content.lower()
    assert any(term in content_lower for term in ["android", "apk", "manifest", "exported", "component"])


def test_ddos_knowledge_routing(workspace_service):
    """Conceptual DDoS defense question routes to authoritative network security knowledge."""
    inv = workspace_service.create_investigation(
        CreateInvestigationRequest(name="DDoS Defense", target_host="lab.target.local")
    )

    q = "Explain volumetric DDoS attacks and how organizations defend against them."
    responses = workspace_service.send_message(inv.id, q)

    assert len(responses) == 1
    resp = responses[0]
    assert resp.status == "COMPLETED"
    assert resp.model_name in ("local_knowledge_engine", "qwen2.5-coder:7b")
    content_lower = resp.content.lower()
    assert any(term in content_lower for term in ["volumetric", "ddos", "amplification", "flooding", "scrubbing", "rate limit"])


def test_auth_vs_authz_routing(workspace_service):
    """Authentication vs Authorization question routes to distinct authoritative concepts."""
    inv = workspace_service.create_investigation(
        CreateInvestigationRequest(name="Auth Concepts", target_host="lab.target.local")
    )

    q = "Explain the difference between authentication and authorization."
    responses = workspace_service.send_message(inv.id, q)

    assert len(responses) == 1
    resp = responses[0]
    assert resp.status == "COMPLETED"
    assert resp.model_name in ("local_knowledge_engine", "qwen2.5-coder:7b")
    content_lower = resp.content.lower()
    assert "authentication" in content_lower or "authn" in content_lower
    assert "authorization" in content_lower or "authz" in content_lower


def test_offline_unsupported_query_honest_status(workspace_service, monkeypatch):
    """When model is offline and query is outside VAPT corpus, return honest availability status."""
    monkeypatch.setattr(workspace_service.cascade_orchestrator.ollama_client, "is_available", lambda: False)
    inv = workspace_service.create_investigation(
        CreateInvestigationRequest(name="Offline Status", target_host="lab.target.local")
    )

    q = "what is the capital of France?"
    responses = workspace_service.send_message(inv.id, q)

    assert len(responses) == 1
    resp = responses[0]
    assert resp.status == "SERVICE_UNAVAILABLE"
    assert resp.model_name == "system_status"
    assert "127.0.0.1:11434" in resp.content or "offline" in resp.content.lower()


def test_message_persistence_and_provenance(workspace_service):
    """Responses must persist to the database with correct investigation_id and model metadata."""
    inv = workspace_service.create_investigation(
        CreateInvestigationRequest(name="Persistence Test", target_host="lab.target.local")
    )

    q = "tell me about android security"
    responses = workspace_service.send_message(inv.id, q)
    assert len(responses) == 1

    messages = workspace_service.get_messages(inv.id)
    # Should have user message and assistant message
    user_msgs = [m for m in messages if m.sender == "user"]
    asst_msgs = [m for m in messages if m.sender == "assistant"]

    assert len(user_msgs) >= 1
    assert len(asst_msgs) >= 1
    assert user_msgs[-1].content == q
    assert asst_msgs[-1].model_name in ("local_knowledge_engine", "qwen2.5-coder:7b")
    assert asst_msgs[-1].status == "COMPLETED"


def test_conversational_query_detection(workspace_service):
    """_is_conversational_query correctly identifies conceptual vs pipeline queries."""
    # Conceptual / learning questions must be True
    assert workspace_service._is_conversational_query("tell me how can i check my androids security") is True
    assert workspace_service._is_conversational_query("explain volumetric ddos attacks") is True
    assert workspace_service._is_conversational_query("how can i analyze apk files") is True
    assert workspace_service._is_conversational_query("explain the difference between authentication and authorization") is True
    assert workspace_service._is_conversational_query("what is bola") is True

    # Target evidence pipeline commands must be False
    assert workspace_service._is_conversational_query("analyze target evidence") is False
    assert workspace_service._is_conversational_query("propose experiments for this target") is False
    assert workspace_service._is_conversational_query("list evidence gaps") is False
