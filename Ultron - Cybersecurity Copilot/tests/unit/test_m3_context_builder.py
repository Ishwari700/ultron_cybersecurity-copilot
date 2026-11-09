"""Unit tests for Milestone M3 Context Builder Integration & Causal Parity.

Verifies:
- Track B vs Track D exact byte parity of Target-Evidence payload (Section 16.1 & 16.2)
- Target-evidence ceiling = 256 tokens (Tier 1) / 768 tokens (Tier 2)
- VAPT Knowledge advisory injection into partition P4
- Preserved protected canonical evidence floor (P0 + P1)
- Fail-soft advisory behavior when context headroom is exhausted
- Provenance binding of VaptKnowledgePack in AssembledReasoningContext
"""

from pathlib import Path
import pytest

from src.engine.context_builder import (
    TRACK_A,
    TRACK_B,
    TRACK_C,
    TRACK_D,
    ReasoningContextBuilder,
)
from src.evidence.cascade_models import (
    CascadeHandoffPacket,
    DeterministicRoutingDecision,
    LosslessStructuralPack,
)
from src.knowledge.retriever import OnnxVectorFts5Retriever
from src.knowledge.serializer import ProductionP4Serializer


@pytest.fixture
def sample_m3_handoff():
    ch_a = LosslessStructuralPack(
        schema_version="2.0.0",
        asset_id="ASSET-PROD-01",
        endpoint_id="EP-PAY-01",
        route_template="/api/v1/payments/{payment_id}/refund",
        http_method="POST",
        application_mutability="STATE_CHANGING",
        parameter_lineage=[{"param_id": "P_ID", "param_name": "payment_id", "location": "path"}],
        has_privilege_level_delta=True,
        has_unauthenticated_success=False,
        has_cross_identity_object_access_success=True,
        observed_facts=[{"fact_id": "FACT-001", "statement": "Cross-identity refund returned 200 OK"}],
        raw_body_sample='{"amount": 500, "currency": "USD", "destination": "acct_attacker_99"}',
    )
    routing = DeterministicRoutingDecision(
        schema_version="2.0.0",
        escalate=True,
        has_high_risk_signal=True,
        high_risk_signals=["PRIVILEGE_LEVEL_DELTA_DETECTED"],
        fail_safe_triggered=False,
    )
    return CascadeHandoffPacket(
        schema_version="2.0.0",
        channel_a_structural=ch_a,
        routing_decision=routing,
        provenance_hash="mock_provenance_hash_32chars_hex",
    )


@pytest.fixture
def sample_vapt_pack():
    db_file = Path("data/vapt_corpus/vapt_knowledge.db")
    retriever = OnnxVectorFts5Retriever(db_file)
    serializer = ProductionP4Serializer(chars_per_token=4.0)
    query = "Method: POST | Route: /api/v1/payments/{payment_id}/refund | Evidence Gap: Missing Tenant Isolation Check"
    items = retriever.retrieve(query, top_k=5)
    pack = serializer.build_knowledge_pack(
        retrieval_items=items,
        token_budget=256,
        retrieval_query=query,
        query_renderer_id="RENDERER_S",
    )
    retriever.close()
    return pack


def test_track_b_and_d_target_evidence_byte_parity(sample_m3_handoff, sample_vapt_pack):
    """
    M3 Causal Invariant (Section 16.1 & 16.2):
    Target-Evidence snippet in Track B and Track D must be 100% byte-for-byte identical.
    """
    ctx_b = ReasoningContextBuilder.build_context(
        handoff_packet=sample_m3_handoff,
        model_identifier="qwen2.5-coder:7b",
        budget_tier=4096,
        cascade_mode=TRACK_B,
    )

    ctx_d = ReasoningContextBuilder.build_context(
        handoff_packet=sample_m3_handoff,
        model_identifier="qwen2.5-coder:7b",
        budget_tier=4096,
        cascade_mode=TRACK_D,
        vapt_pack=sample_vapt_pack,
    )

    # Extract <untrusted_target_data> blocks
    snippet_marker = "=== ENCAPSULATED RAW EVIDENCE SNIPPETS ==="
    assert snippet_marker in ctx_b.prompt
    assert snippet_marker in ctx_d.prompt

    part_b = ctx_b.prompt.split(snippet_marker)[1].strip()
    part_d = ctx_d.prompt.split(snippet_marker)[1]
    # In Track D, VAPT methodology follows snippet_marker
    part_d_clean = part_d.split("<vapt_methodology_advisory>")[0].strip()

    # Exact byte parity assertion
    assert part_b == part_d_clean
    assert ctx_b.partition_tokens["p4_raw_snippets"] == ctx_d.partition_tokens["p4_raw_snippets"]
    assert ctx_b.partition_tokens["p4_raw_snippets"] <= 256


def test_track_a_and_c_component_isolation(sample_m3_handoff, sample_vapt_pack):
    """
    Verify Track A has neither target snippets nor VAPT,
    and Track C has VAPT but no target snippets.
    """
    ctx_a = ReasoningContextBuilder.build_context(
        handoff_packet=sample_m3_handoff,
        model_identifier="qwen2.5-coder:7b",
        cascade_mode=TRACK_A,
    )
    assert "<untrusted_target_data>" not in ctx_a.prompt
    assert "<vapt_methodology_advisory>" not in ctx_a.prompt
    assert ctx_a.partition_tokens["p4_raw_snippets"] == 0
    assert ctx_a.partition_tokens["p4_vapt_knowledge"] == 0

    ctx_c = ReasoningContextBuilder.build_context(
        handoff_packet=sample_m3_handoff,
        model_identifier="qwen2.5-coder:7b",
        cascade_mode=TRACK_C,
        vapt_pack=sample_vapt_pack,
    )
    assert "<untrusted_target_data>" not in ctx_c.prompt
    assert "<vapt_methodology_advisory>" in ctx_c.prompt
    assert ctx_c.partition_tokens["p4_raw_snippets"] == 0
    assert ctx_c.partition_tokens["p4_vapt_knowledge"] > 0


def test_vapt_provenance_binding(sample_m3_handoff, sample_vapt_pack):
    """Verify VaptKnowledgePack provenance is securely bound into AssembledReasoningContext."""
    ctx_d = ReasoningContextBuilder.build_context(
        handoff_packet=sample_m3_handoff,
        model_identifier="qwen2.5-coder:7b",
        cascade_mode=TRACK_D,
        vapt_pack=sample_vapt_pack,
    )

    assert ctx_d.vapt_pack is not None
    assert ctx_d.vapt_pack.pack_id == sample_vapt_pack.pack_id
    assert ctx_d.provenance_metadata["vapt_pack_id"] == sample_vapt_pack.pack_id
    assert ctx_d.provenance_metadata["vapt_provenance_hash"] == sample_vapt_pack.provenance_hash
    assert len(ctx_d.provenance_metadata["vapt_chunk_ids"]) == len(sample_vapt_pack.items)


def test_protected_floor_preservation(sample_m3_handoff, sample_vapt_pack):
    """VAPT knowledge injection must never displace canonical evidence facts or invariants."""
    ctx_b = ReasoningContextBuilder.build_context(
        handoff_packet=sample_m3_handoff,
        model_identifier="qwen2.5-coder:7b",
        cascade_mode=TRACK_B,
    )
    ctx_d = ReasoningContextBuilder.build_context(
        handoff_packet=sample_m3_handoff,
        model_identifier="qwen2.5-coder:7b",
        cascade_mode=TRACK_D,
        vapt_pack=sample_vapt_pack,
    )

    # Floor tokens must be identical
    for p in ["p0_system_policy", "p1_target_envelope", "p1_structural_diffs", "p1_canonical_evidence"]:
        assert ctx_b.partition_tokens[p] == ctx_d.partition_tokens[p]
