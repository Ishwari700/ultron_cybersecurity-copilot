"""Unit tests for the Security Invariant Engine and epistemic origin segregation."""

from pathlib import Path
from src.database.manager import DatabaseManager
from src.evidence.adapters.openapi import OpenApiAdapter
from src.graph.models import EpistemicOrigin, WorkflowNode, WorkflowTransition
from src.invariants.engine import SecurityInvariantEngine
from src.invariants.models import InvariantConfidence, InvariantOrigin


def test_derive_documented_and_workflow_invariants(tmp_path: Path):
    """Verify derivation of DOCUMENTED and DETERMINISTIC_DERIVATION invariants."""
    db_file = tmp_path / "inv_test.db"
    db_manager = DatabaseManager(db_path=db_file)
    db_manager.initialize_schema()

    engine = SecurityInvariantEngine(db_manager=db_manager)

    # 1. Documented Invariant from OpenAPI spec
    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/api/v1/invoices": {
                "get": {
                    "summary": "List invoices",
                    "security": [{"bearerAuth": []}],
                }
            }
        },
    }
    adapter = OpenApiAdapter()
    evidence_list = adapter.ingest(spec)
    doc_invariants = engine.derive_documented_invariants(evidence_list)

    assert len(doc_invariants) == 1
    doc_inv = doc_invariants[0]
    assert doc_inv.origin == InvariantOrigin.DOCUMENTED
    assert "requires valid authenticated" in doc_inv.description

    # 2. Workflow Invariant from Deterministic Workflow
    wf = WorkflowNode(
        workflow_id="WF-TEST",
        name="Checkout to Refund",
        asset_sequence=["ASSET-1", "ASSET-2"],
        transitions=[
            WorkflowTransition(
                from_asset_id="ASSET-1",
                to_asset_id="ASSET-2",
                parameter_flow="order_id",
            )
        ],
        origin=EpistemicOrigin.DETERMINISTIC_DERIVATION,
    )
    wf_invariants = engine.derive_workflow_invariants([wf])
    assert len(wf_invariants) == 1
    wf_inv = wf_invariants[0]
    assert wf_inv.origin == InvariantOrigin.DETERMINISTIC_DERIVATION
    assert "strictly requires prior successful completion" in wf_inv.description

    # 3. Model Proposed Invariant (Strict Epistemic Isolation)
    model_inv = engine.register_model_proposed_invariant(
        description="Only identity with tenant_id matching invoice should access invoice",
        derived_from=[doc_inv.invariant_id],
        confidence=InvariantConfidence.MEDIUM,
    )
    assert model_inv.origin == InvariantOrigin.MODEL_PROPOSED
    assert model_inv.origin != InvariantOrigin.OBSERVED
    assert model_inv.origin != InvariantOrigin.DOCUMENTED

    # Verify persistence in DB
    retrieved = db_manager.get_security_invariant(model_inv.invariant_id)
    assert retrieved is not None
    assert retrieved["origin"] == "MODEL_PROPOSED"
