"""Unit tests for VaptQueryBuilder and CanonicalP4CapacityOracle."""

import pytest
from src.eval.p4_capacity_oracle import (
    ADVISORY_NOTICE_HEADER,
    CanonicalP4CapacityOracle,
    escape_xml_content,
)
from src.evidence.cascade_models import LosslessStructuralPack
from src.knowledge.models import (
    EvidenceGapType,
    KnowledgeChunk,
    KnowledgeRetrievalItem,
    KnowledgeSourceType,
    KnowledgeType,
    QueryRendererId,
)
from src.knowledge.query_builder import VaptQueryBuilder


def test_query_builder_renderer_s_and_n():
    """Verify deterministic query rendering under Renderer S and Renderer N."""
    pack = LosslessStructuralPack(
        asset_id="ASSET-01",
        endpoint_id="EP-01",
        route_template="/api/v1/invoices/{id}",
        http_method="GET",
        application_mutability="READ_ONLY",
        has_cross_identity_object_access_success=True,
        has_privilege_level_delta=False,
    )

    query_s = VaptQueryBuilder.build_query(
        pack=pack,
        gap_type=EvidenceGapType.MISSING_CROSS_IDENTITY_OBJECT_VERIFICATION,
        renderer_id=QueryRendererId.RENDERER_S,
    )
    expected_s = (
        "Method: GET | Route: /api/v1/invoices/{id} | "
        "Evidence Gap: Missing Cross Identity Object Verification | "
        "Invariant: Horizontal tenant object isolation"
    )
    assert query_s == expected_s

    query_n = VaptQueryBuilder.build_query(
        pack=pack,
        gap_type=EvidenceGapType.MISSING_CROSS_IDENTITY_OBJECT_VERIFICATION,
        renderer_id=QueryRendererId.RENDERER_N,
    )
    expected_n = (
        "How should GET /api/v1/invoices/{id} enforce Missing Cross Identity Object Verification? "
        "Relevant invariant: Horizontal tenant object isolation."
    )
    assert query_n == expected_n


def test_query_builder_strict_enum_validation():
    """Verify rejection of invalid gap_type and renderer_id."""
    pack = LosslessStructuralPack(
        asset_id="ASSET-01",
        endpoint_id="EP-01",
        route_template="/orders",
        http_method="POST",
        application_mutability="STATE_CHANGING",
    )

    with pytest.raises(TypeError, match="gap_type must be an instance of EvidenceGapType"):
        VaptQueryBuilder.build_query(pack=pack, gap_type="MISSING_CROSS_IDENTITY_OBJECT_VERIFICATION")  # type: ignore

    with pytest.raises(TypeError, match="renderer_id must be an instance of QueryRendererId"):
        VaptQueryBuilder.build_query(
            pack=pack,
            gap_type=EvidenceGapType.MISSING_ROLE_HIERARCHY_ENFORCEMENT,
            renderer_id="RENDERER_S",  # type: ignore
        )


def test_p4_oracle_xml_escaping():
    """Verify XML escaping of &, <, >."""
    raw = "Test <b>bold</b> & 'quotes' > 10 < 20"
    escaped = escape_xml_content(raw)
    assert "&amp;" in escaped
    assert "&lt;b&gt;" in escaped
    assert "&gt; 10" in escaped


def test_p4_oracle_empty_pack_behavior():
    """Verify that 0 chunks result in empty string wire serialization."""
    oracle = CanonicalP4CapacityOracle()
    wire, tokens, accepted = oracle.serialize_pack([])
    assert wire == ""
    assert tokens == 0
    assert accepted == []


def test_p4_oracle_priority_packing_and_budget_ceiling():
    """Verify Section 13.7 priority ordering and 256-token budget enforcement."""
    oracle = CanonicalP4CapacityOracle()

    # Create Priority 1 chunk (Security Invariant)
    c_inv = KnowledgeChunk(
        chunk_id="CHK-INV-01",
        document_id="DOC-INV",
        source_type=KnowledgeSourceType.PLATFORM_INVARIANT,
        knowledge_type=KnowledgeType.SECURITY_INVARIANT,
        category_tags=["INVARIANT"],
        title="Tenant Isolation Invariant",
        section_heading="Invariant 1",
        content="Cross-tenant access must return 403 or 404.",
        token_estimate=30,
        content_hash="h_inv",
    )

    # Create Priority 4 chunk with HIGHER similarity score
    c_bg = KnowledgeChunk(
        chunk_id="CHK-BG-01",
        document_id="DOC-BG",
        source_type=KnowledgeSourceType.OWASP_WSTG,
        knowledge_type=KnowledgeType.TESTING_METHODOLOGY,
        category_tags=["BACKGROUND"],
        title="Background Guide",
        section_heading="History",
        content="General background testing notes on authorization.",
        token_estimate=30,
        content_hash="h_bg",
    )

    item_inv = KnowledgeRetrievalItem(
        chunk=c_inv,
        dense_score=0.5,
        sparse_score=0.5,
        fused_score=0.015,  # Lower score
        retrieval_rank=2,
        query_id="Q-01",
    )

    item_bg = KnowledgeRetrievalItem(
        chunk=c_bg,
        dense_score=0.9,
        sparse_score=0.9,
        fused_score=0.030,  # Higher score
        retrieval_rank=1,
        query_id="Q-01",
    )

    # In combined packing order, Priority 1 (Invariant) MUST be evaluated before Priority 4 (Background)
    wire, tokens, accepted = oracle.serialize_pack([item_bg, item_inv], token_budget=256)
    assert len(accepted) == 2
    assert accepted[0].chunk.chunk_id == "CHK-INV-01"  # Priority 1 first
    assert accepted[1].chunk.chunk_id == "CHK-BG-01"   # Priority 4 second

    assert "<vapt_methodology_advisory>" in wire
    assert "</vapt_methodology_advisory>" in wire
    assert ADVISORY_NOTICE_HEADER in wire
    assert 'priority="1"' in wire
    assert 'priority="4"' in wire
    assert tokens <= 256

    # Test is_injection_hit
    assert oracle.is_injection_hit([item_bg, item_inv], ["CHK-INV-01"]) is True
    assert oracle.is_injection_hit([item_bg, item_inv], ["CHK-NONEXISTENT"]) is False
