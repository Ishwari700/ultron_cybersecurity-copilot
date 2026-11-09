"""End-to-End Regression Test for Copilot Response Pipeline Repair (Milestone Post-M13).

Verifies the end-to-end request and answer flow across three mandatory prompts:
1. "Explain Android application security and the first areas a researcher should review."
2. "Explain volumetric DDoS attacks and how organizations defend against them."
3. "Explain the difference between authentication and authorization."
"""

import pytest
from src.core.logging import AuditLogger
from src.database.manager import DatabaseManager
from src.dashboard.service import WorkspaceService
from src.dashboard.models import CreateInvestigationRequest


@pytest.fixture
def service(tmp_path):
    db_path = tmp_path / "test_e2e_workspace.db"
    db = DatabaseManager(db_path=db_path)
    db.initialize_schema()
    auditor = AuditLogger(tmp_path / "test_e2e_audit.log")
    return WorkspaceService(db_manager=db, audit_logger=auditor)


def test_copilot_end_to_end_three_mandatory_prompts(service):
    """End-to-end regression proving the 3 mandatory queries receive question-specific grounded answers."""
    canned_intro = "I'm your local security research assistant. You can provide target observations"
    inv = service.create_investigation(
        CreateInvestigationRequest(
            name="E2E Regression Investigation",
            target_host="api.target.local"
        )
    )

    prompts = [
        ("Explain Android application security and the first areas a researcher should review.", ["android", "apk", "manifest"]),
        ("Explain volumetric DDoS attacks and how organizations defend against them.", ["ddos", "volumetric", "amplification", "scrubbing"]),
        ("Explain the difference between authentication and authorization.", ["authentication", "authorization"]),
    ]

    responses = {}

    for prompt_text, expected_terms in prompts:
        msg_list = service.send_message(inv.id, prompt_text)
        assert len(msg_list) == 1, f"Expected 1 response message for '{prompt_text}'"
        msg = msg_list[0]

        # 1. Verification: Does not return the forbidden canned greeting
        assert canned_intro not in msg.content, f"Query '{prompt_text}' returned the forbidden canned introduction!"

        # 2. Verification: Receives a substantive response tied to that specific question
        assert len(msg.content) > 100, f"Expected detailed explanation for '{prompt_text}', got {len(msg.content)} chars"
        content_lower = msg.content.lower()
        matched = [t for t in expected_terms if t in content_lower]
        assert len(matched) >= 1, f"Response did not contain expected domain terms for '{prompt_text}'"

        # 3. Verification: Markdown preservation
        assert any(md in msg.content for md in ["###", "##", "-", "*", "1."]), "Markdown headings/lists missing"

        # 4. Verification: Provenance handling
        assert msg.model_name in ("local_knowledge_engine", "qwen2.5-coder:7b"), f"Unexpected model_name: {msg.model_name}"
        assert msg.status == "COMPLETED"

        # 5. Verification: Persistence in SQLite
        persisted = service.get_messages(inv.id)
        msg_ids = [m.id for m in persisted]
        assert msg.id in msg_ids, f"Message {msg.id} was not persisted in database for {inv.id}"

        responses[prompt_text] = msg.content

    # 6. Verification: Distinctness across prompts (no universal fallback overlap)
    contents = list(responses.values())
    assert contents[0] != contents[1]
    assert contents[1] != contents[2]
    assert contents[0] != contents[2]
