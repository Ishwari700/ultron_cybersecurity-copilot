"""Unit tests for the Evidence Graph and Workflow Engine."""

import json
from pathlib import Path
from src.database.manager import DatabaseManager
from src.evidence.adapters.generic_http import GenericHttpAdapter
from src.graph.models import EpistemicOrigin
from src.graph.workflow_engine import WorkflowEngine


def test_workflow_derivation_with_noise_filtering(tmp_path: Path):
    """Verify noise endpoints like /telemetry are filtered and business flows chained."""
    db_file = tmp_path / "wf_test.db"
    db_manager = DatabaseManager(db_path=db_file)
    db_manager.initialize_schema()

    adapter = GenericHttpAdapter()
    engine = WorkflowEngine(db_manager=db_manager)

    # 3 sequential interactions: checkout -> telemetry (noise) -> refund
    interactions_raw = [
        {
            "method": "POST",
            "url": "https://api.target.com/v1/checkout",
            "response_status": 200,
            "response_headers": {"Content-Type": "application/json"},
            "response_body": '{"order_id": "ORD-12345", "status": "completed"}',
            "source_tool": "burp",
        },
        {
            "method": "POST",
            "url": "https://api.target.com/telemetry",
            "response_status": 204,
            "source_tool": "burp",
        },
        {
            "method": "POST",
            "url": "https://api.target.com/v1/refund?order_id=ORD-12345",
            "response_status": 200,
            "source_tool": "burp",
        },
    ]

    ev_list = adapter.ingest(interactions_raw)
    assert len(ev_list) == 3

    workflows = engine.derive_workflows(ev_list)
    assert len(workflows) == 1
    wf = workflows[0]

    # Telemetry should be excluded, leaving checkout -> refund
    assert len(wf.asset_sequence) == 2
    assert wf.origin == EpistemicOrigin.DETERMINISTIC_DERIVATION
    assert len(wf.transitions) == 1

    transition = wf.transitions[0]
    # Data flow was detected because "order_id" was in response of step 1 and param in step 3
    assert transition.parameter_flow == "order_id"

    # Verify derivation was written to derivations table
    with db_manager.get_connection() as conn:
        cursor = conn.execute("SELECT * FROM derivations WHERE derived_fact_id = ?", (wf.workflow_id,))
        row = cursor.fetchone()
        assert row is not None
        assert row["derivation_rule"] == "temporal_dataflow_adjacency"
        parents = json.loads(row["parent_fact_ids"])
        assert len(parents) == 2
