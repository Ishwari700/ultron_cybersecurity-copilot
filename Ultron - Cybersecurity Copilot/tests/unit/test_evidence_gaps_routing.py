"""Regression and Architectural Test Suite for Evidence Gap Routing & Preservation.

Verifies:
- TEST 1: "Show open evidence gaps" -> uses explicit evidence-gap retrieval path (does not invoke cascade).
- TEST 2: "Generate security hypotheses and identify evidence gaps" -> reaches cascade.
- TEST 3: "Analyze the target and identify missing evidence" -> reaches cascade.
- TEST 4: A hypothesis containing "evidence_gap": "..." -> structured gap is preserved in card & registry.
- TEST 5: A hypothesis with "evidence_gap": null -> no gap registered.
- TEST 6: A hypothesis with "evidence_gap": "none" -> no gap registered.
- TEST 7: Arbitrary prose saying "missing evidence" -> MUST NOT create an evidence gap.
- TEST 8: Investigation A's gap cannot appear in Investigation B (epistemic and workspace isolation).
- TEST 9: Existing hypothesis generation continues to work (backward compatibility).
- TEST 10: Existing scope/security invariants continue passing (fail-closed, no prompt bypass).
"""

from pathlib import Path
from typing import Any, Dict
from unittest.mock import MagicMock
import pytest

from src.database.manager import DatabaseManager
from src.dashboard.service import WorkspaceService
from src.dashboard.models import (
    CreateInvestigationRequest,
    ManualObservationRequest,
    StructuredCardType,
)
from src.evidence.cascade_models import LosslessStructuralPack
from src.engine.cascade_orchestrator import CascadeExecutionTrace


# =====================================================================
# Fixtures & Helpers
# =====================================================================

@pytest.fixture
def temp_db(tmp_path: Path) -> DatabaseManager:
    db_file = tmp_path / "test_gaps_routing.db"
    db = DatabaseManager(db_path=db_file)
    db.initialize_schema()
    return db


@pytest.fixture
def workspace_service(temp_db: DatabaseManager) -> WorkspaceService:
    return WorkspaceService(db_manager=temp_db)


def _seed_observation(service: WorkspaceService, inv_id: str, host: str = "api.target.local") -> None:
    """Helper to populate an investigation with an observation so it is non-empty."""
    service.add_manual_observation(
        inv_id,
        ManualObservationRequest(
            method="POST",
            host=host,
            path="/api/v1/invoices/export",
            status_code=200,
            researcher_note="POST /api/v1/invoices/export returns PDF invoice binary for valid tenant.",
        ),
    )


# =====================================================================
# Regression Tests
# =====================================================================

def test_1_explicit_gap_retrieval_path(workspace_service: WorkspaceService):
    """TEST 1: 'Show open evidence gaps' uses explicit retrieval path and does not call cascade."""
    inv = workspace_service.create_investigation(
        CreateInvestigationRequest(name="Gap Test", target_host="api.target.local")
    )
    _seed_observation(workspace_service, inv.id)

    mock_cascade = MagicMock()
    workspace_service.cascade_orchestrator = mock_cascade

    # 1. When no gaps are registered
    responses = workspace_service.send_message(inv.id, "Show open evidence gaps")
    assert not mock_cascade.execute_cascade.called, "Explicit gap retrieval must NOT invoke cascade"
    assert len(responses) == 1
    assert responses[0].model_name == "local_rule_engine"
    assert "No open evidence gaps currently registered for this investigation." in responses[0].content

    # 2. Variants of explicit gap retrieval
    for phrase in ["list evidence gaps", "show me the gaps", "what are the open evidence gaps?"]:
        mock_cascade.reset_mock()
        resps = workspace_service.send_message(inv.id, phrase)
        assert not mock_cascade.execute_cascade.called, f"'{phrase}' must not call cascade"
        assert len(resps) >= 1
        assert "No open evidence gaps" in resps[0].content


def test_2_multi_intent_research_reaches_cascade(workspace_service: WorkspaceService):
    """TEST 2: 'Generate security hypotheses and identify evidence gaps' reaches cascade."""
    inv = workspace_service.create_investigation(
        CreateInvestigationRequest(name="Research Test", target_host="api.target.local")
    )
    _seed_observation(workspace_service, inv.id)

    mock_trace = CascadeExecutionTrace(
        run_id="RUN-TEST-002",
        investigation_id=inv.id,
        task_type="SECURITY_RESEARCH",
        target_endpoint="POST /api/v1/invoices/export",
        overall_status="CASCADE_COMPLETED",
        routing_decision="ESCALATE_TO_7B",
        total_latency_seconds=0.1,
        stages=[],
    )
    mock_cascade = MagicMock()
    mock_cascade.execute_cascade.return_value = (mock_trace, None)
    workspace_service.cascade_orchestrator = mock_cascade

    responses = workspace_service.send_message(
        inv.id, "Generate security hypotheses and identify evidence gaps"
    )

    assert mock_cascade.execute_cascade.called, "Multi-intent research query MUST reach cascade"
    assert "No open evidence gaps currently registered" not in responses[0].content


def test_3_analysis_with_missing_evidence_reaches_cascade(workspace_service: WorkspaceService):
    """TEST 3: 'Analyze the target and identify missing evidence' reaches cascade."""
    inv = workspace_service.create_investigation(
        CreateInvestigationRequest(name="Missing Ev Test", target_host="api.target.local")
    )
    _seed_observation(workspace_service, inv.id)

    mock_trace = CascadeExecutionTrace(
        run_id="RUN-TEST-003",
        investigation_id=inv.id,
        task_type="SECURITY_RESEARCH",
        target_endpoint="POST /api/v1/invoices/export",
        overall_status="CASCADE_COMPLETED",
        routing_decision="ESCALATE_TO_7B",
        total_latency_seconds=0.1,
        stages=[],
    )
    mock_cascade = MagicMock()
    mock_cascade.execute_cascade.return_value = (mock_trace, None)
    workspace_service.cascade_orchestrator = mock_cascade

    responses = workspace_service.send_message(
        inv.id, "Analyze the target and identify missing evidence"
    )

    assert mock_cascade.execute_cascade.called, "Research query with 'missing evidence' MUST reach cascade"
    assert "No open evidence gaps currently registered" not in responses[0].content


def test_4_structured_evidence_gap_preserved(workspace_service: WorkspaceService):
    """TEST 4: A hypothesis containing 'evidence_gap': '...' preserves structured gap."""
    inv = workspace_service.create_investigation(
        CreateInvestigationRequest(name="Preserve Gap Test", target_host="api.target.local")
    )
    _seed_observation(workspace_service, inv.id)

    mock_trace = CascadeExecutionTrace(
        run_id="RUN-TEST-004",
        investigation_id=inv.id,
        task_type="SECURITY_RESEARCH",
        target_endpoint="POST /api/v1/invoices/export",
        overall_status="CASCADE_COMPLETED",
        routing_decision="ESCALATE_TO_7B",
        total_latency_seconds=0.1,
        stages=[],
    )
    gap_desc = "Cross-tenant export authorization check not verified in observed traffic."
    mock_hypothesis = {
        "decision": "HYPOTHESIS",
        "category": "API-BOLA-001",
        "reasoning_summary": "Resource identifier substitution may bypass tenant authorization boundary.",
        "evidence_gap": gap_desc,
        "experiment_action": "SUBSTITUTE_RESOURCE_IDENTIFIER",
        "supporting_outcome": "HTTP_200_OK",
        "disproving_outcome": "HTTP_403_FORBIDDEN",
        "falsification_description": "Substitute cross-tenant invoice_id to verify boundary isolation.",
    }
    mock_cascade = MagicMock()
    mock_cascade.execute_cascade.return_value = (mock_trace, mock_hypothesis)
    workspace_service.cascade_orchestrator = mock_cascade

    responses = workspace_service.send_message(
        inv.id, "Analyze the target and generate security hypotheses"
    )

    # 1. Verify structured hypothesis card has evidence_gap
    hyp_card_msg = next((m for m in responses if m.structured_type == StructuredCardType.HYPOTHESIS), None)
    assert hyp_card_msg is not None, "Hypothesis card message must be emitted"
    assert hyp_card_msg.structured_data.get("evidence_gap") == gap_desc

    # 2. Verify registered in workspace service gaps
    gaps = workspace_service.get_gaps(inv.id)
    assert len(gaps) == 1
    assert gaps[0]["description"] == gap_desc

    # 3. Verify subsequent explicit retrieval returns the registered gap
    mock_cascade.reset_mock()
    gap_resps = workspace_service.send_message(inv.id, "Show open evidence gaps")
    assert not mock_cascade.execute_cascade.called
    assert gap_desc in gap_resps[0].content


def test_5_hypothesis_with_null_gap_not_registered(workspace_service: WorkspaceService):
    """TEST 5: A hypothesis with 'evidence_gap': null -> no gap registered."""
    inv = workspace_service.create_investigation(
        CreateInvestigationRequest(name="Null Gap Test", target_host="api.target.local")
    )
    _seed_observation(workspace_service, inv.id)

    mock_trace = CascadeExecutionTrace(
        run_id="RUN-TEST-005",
        investigation_id=inv.id,
        task_type="SECURITY_RESEARCH",
        target_endpoint="POST /api/v1/invoices/export",
        overall_status="CASCADE_COMPLETED",
        routing_decision="ESCALATE_TO_7B",
        total_latency_seconds=0.1,
        stages=[],
    )
    mock_hypothesis = {
        "decision": "HYPOTHESIS",
        "category": "API-BOLA-001",
        "reasoning_summary": "Suspected flaw.",
        "evidence_gap": None,
    }
    mock_cascade = MagicMock()
    mock_cascade.execute_cascade.return_value = (mock_trace, mock_hypothesis)
    workspace_service.cascade_orchestrator = mock_cascade

    responses = workspace_service.send_message(inv.id, "Analyze the target traffic")

    hyp_card_msg = next((m for m in responses if m.structured_type == StructuredCardType.HYPOTHESIS), None)
    assert hyp_card_msg is not None
    assert hyp_card_msg.structured_data.get("evidence_gap") is None

    gaps = workspace_service.get_gaps(inv.id)
    assert len(gaps) == 0, "No gap should be registered when evidence_gap is null"


def test_6_hypothesis_with_none_string_gap_not_registered(workspace_service: WorkspaceService):
    """TEST 6: A hypothesis with 'evidence_gap': 'none' -> no gap registered."""
    inv = workspace_service.create_investigation(
        CreateInvestigationRequest(name="None Str Gap Test", target_host="api.target.local")
    )
    _seed_observation(workspace_service, inv.id)

    mock_trace = CascadeExecutionTrace(
        run_id="RUN-TEST-006",
        investigation_id=inv.id,
        task_type="SECURITY_RESEARCH",
        target_endpoint="POST /api/v1/invoices/export",
        overall_status="CASCADE_COMPLETED",
        routing_decision="ESCALATE_TO_7B",
        total_latency_seconds=0.1,
        stages=[],
    )
    mock_hypothesis = {
        "decision": "HYPOTHESIS",
        "category": "API-BOLA-001",
        "reasoning_summary": "Suspected flaw.",
        "evidence_gap": "none",
    }
    mock_cascade = MagicMock()
    mock_cascade.execute_cascade.return_value = (mock_trace, mock_hypothesis)
    workspace_service.cascade_orchestrator = mock_cascade

    responses = workspace_service.send_message(inv.id, "Analyze the target traffic")

    hyp_card_msg = next((m for m in responses if m.structured_type == StructuredCardType.HYPOTHESIS), None)
    assert hyp_card_msg is not None
    assert hyp_card_msg.structured_data.get("evidence_gap") is None

    gaps = workspace_service.get_gaps(inv.id)
    assert len(gaps) == 0, "No gap should be registered when evidence_gap is 'none'"


def test_7_arbitrary_prose_does_not_create_gap(workspace_service: WorkspaceService):
    """TEST 7: Arbitrary prose saying 'missing evidence' MUST NOT create an evidence gap."""
    inv = workspace_service.create_investigation(
        CreateInvestigationRequest(name="Prose Test", target_host="api.target.local")
    )
    _seed_observation(workspace_service, inv.id)

    mock_trace = CascadeExecutionTrace(
        run_id="RUN-TEST-007",
        investigation_id=inv.id,
        task_type="SECURITY_RESEARCH",
        target_endpoint="POST /api/v1/invoices/export",
        overall_status="CASCADE_COMPLETED",
        routing_decision="TERMINATE_BENIGN_AT_3B",
        total_latency_seconds=0.1,
        stages=[],
    )
    # Output does not have a structured hypothesis
    mock_cascade = MagicMock()
    mock_cascade.execute_cascade.return_value = (mock_trace, None)
    workspace_service.cascade_orchestrator = mock_cascade

    # User message with prose about missing evidence
    workspace_service.send_message(
        inv.id, "The system has missing evidence and we need to locate missing observations."
    )

    gaps = workspace_service.get_gaps(inv.id)
    assert len(gaps) == 0, "Arbitrary prose must NEVER create an evidence gap"


def test_8_investigation_isolation_of_gaps(workspace_service: WorkspaceService):
    """TEST 8: Investigation A's gap cannot appear in Investigation B."""
    inv_a = workspace_service.create_investigation(
        CreateInvestigationRequest(name="Inv A", target_host="api.target.local")
    )
    inv_b = workspace_service.create_investigation(
        CreateInvestigationRequest(name="Inv B", target_host="lab.target.local")
    )
    _seed_observation(workspace_service, inv_a.id, host="api.target.local")
    _seed_observation(workspace_service, inv_b.id, host="lab.target.local")

    # Register gap in Investigation A via hypothesis
    gap_a_text = "Investigation A missing tenant export telemetry."
    mock_trace = CascadeExecutionTrace(
        run_id="RUN-INV-A",
        investigation_id=inv_a.id,
        task_type="SECURITY_RESEARCH",
        target_endpoint="POST /api/v1/invoices/export",
        overall_status="CASCADE_COMPLETED",
        routing_decision="ESCALATE_TO_7B",
        total_latency_seconds=0.1,
        stages=[],
    )
    mock_hyp = {
        "decision": "HYPOTHESIS",
        "category": "API-BOLA-001",
        "reasoning_summary": "Tenant boundary flaw suspected in A.",
        "evidence_gap": gap_a_text,
    }
    mock_cascade = MagicMock()
    mock_cascade.execute_cascade.return_value = (mock_trace, mock_hyp)
    workspace_service.cascade_orchestrator = mock_cascade

    workspace_service.send_message(inv_a.id, "Analyze target traffic")

    # Confirm Inv A has gap
    gaps_a = workspace_service.get_gaps(inv_a.id)
    assert len(gaps_a) == 1
    assert gaps_a[0]["description"] == gap_a_text

    # Confirm Inv B does NOT have gap
    gaps_b = workspace_service.get_gaps(inv_b.id)
    assert len(gaps_b) == 0, "Investigation B must not inherit Investigation A's gaps"

    resp_b = workspace_service.send_message(inv_b.id, "Show open evidence gaps")
    assert "No open evidence gaps currently registered" in resp_b[0].content
    assert gap_a_text not in resp_b[0].content


def test_9_existing_hypothesis_generation_continues_to_work(workspace_service: WorkspaceService):
    """TEST 9: Existing hypothesis generation continues to work."""
    demo = workspace_service.load_demo_investigation()
    assert demo.hypothesis_count >= 1

    detail = workspace_service.get_investigation(demo.id)
    assert detail is not None
    assert any(m.structured_type == StructuredCardType.HYPOTHESIS for m in detail.messages)

    # Demo investigation gaps are retrievable
    gaps = workspace_service.get_gaps(demo.id)
    assert len(gaps) >= 1
    assert "TENANT" in gaps[0]["gap_id"]


def test_10_existing_scope_and_security_invariants(workspace_service: WorkspaceService):
    """TEST 10: Existing scope and security invariants continue passing."""
    inv = workspace_service.create_investigation(
        CreateInvestigationRequest(name="Security Inv", target_host="api.target.local")
    )

    # 1. Out of scope traffic rejected fail-closed
    res = workspace_service.add_manual_observation(
        inv.id,
        ManualObservationRequest(
            method="GET",
            host="forbidden-external-attacker.com",
            path="/leak",
            status_code=200,
        ),
    )
    assert res["accepted_count"] == 0
    assert res["out_of_scope_count"] == 1

    # 2. Honest abstention preserved when investigation is empty
    responses = workspace_service.send_message(inv.id, "Analyze target traffic")
    assert "There is currently no target evidence to analyze" in responses[0].content
