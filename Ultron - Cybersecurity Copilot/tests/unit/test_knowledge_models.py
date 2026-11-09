"""Unit tests for M3 Knowledge Schemas and Data Models."""

import pytest
from src.knowledge.models import (
    EpistemicTier,
    EvidenceGapType,
    KnowledgeChunk,
    KnowledgeDocumentFrontmatter,
    KnowledgeRetrievalItem,
    KnowledgeSourceType,
    KnowledgeType,
    QueryRendererId,
    SourceAllowlistEntry,
    TrustRootRecord,
    VaptKnowledgePack,
)


def test_schema_versions_pinned_to_v3_0_0():
    """Verify all knowledge schemas declare schema_version v3.0.0."""
    chunk = KnowledgeChunk(
        chunk_id="CHK-DOC-01-001-01",
        document_id="DOC-01",
        source_type=KnowledgeSourceType.OWASP_WSTG,
        knowledge_type=KnowledgeType.TESTING_METHODOLOGY,
        category_tags=["IDOR"],
        title="Testing IDOR",
        section_heading="Test Methodology",
        content="Verify direct object reference authorization.",
        token_estimate=50,
        content_hash="abc123def456",
    )
    assert chunk.schema_version == "3.0.0"

    pack = VaptKnowledgePack(
        pack_id="PACK-01",
        items=[],
        total_tokens=0,
        rendered_query_text="Method: GET | Route: /orders/{id}",
        retrieval_timestamp="2026-09-20T00:00:00Z",
        corpus_manifest_hash="manifest_hash_123",
        provenance_hash="prov_hash_456",
    )
    assert pack.schema_version == "3.0.0"


def test_enums_completeness():
    """Verify all required enum types and their values."""
    assert set(KnowledgeSourceType) == {
        KnowledgeSourceType.OWASP_WSTG,
        KnowledgeSourceType.OWASP_ASVS,
        KnowledgeSourceType.CWE,
        KnowledgeSourceType.PLATFORM_INVARIANT,
    }

    assert {
        KnowledgeType.SECURITY_INVARIANT,
        KnowledgeType.TESTING_METHODOLOGY,
        KnowledgeType.EXPERIMENT_PATTERN,
        KnowledgeType.NEGATIVE_CONTROL_GUIDE,
        KnowledgeType.FALSE_POSITIVE_GUIDANCE,
    }.issubset(set(KnowledgeType))

    assert set(EpistemicTier) == {
        EpistemicTier.TARGET_OBSERVATION,
        EpistemicTier.SECURITY_INVARIANT,
        EpistemicTier.EVIDENCE_GAP,
        EpistemicTier.GENERAL_VAPT_KNOWLEDGE,
        EpistemicTier.MODEL_INFERENCE,
    }

    assert set(EvidenceGapType) == {
        EvidenceGapType.MISSING_CROSS_IDENTITY_OBJECT_VERIFICATION,
        EvidenceGapType.MISSING_ROLE_HIERARCHY_ENFORCEMENT,
        EvidenceGapType.MISSING_UNAUTHENTICATED_ACCESS_CHECK,
        EvidenceGapType.MISSING_MUTATION_STATE_BOUNDARY,
        EvidenceGapType.MISSING_INPUT_TYPE_TAMPER_CONTROL,
        EvidenceGapType.MISSING_TENANT_ISOLATION_CHECK,
    }

    assert set(QueryRendererId) == {
        QueryRendererId.RENDERER_S,
        QueryRendererId.RENDERER_N,
    }


def test_knowledge_chunk_model_validation():
    """Verify field requirements on KnowledgeChunk."""
    chunk = KnowledgeChunk(
        chunk_id="CHK-DOC-ASVS-001-01",
        document_id="DOC-ASVS",
        source_type=KnowledgeSourceType.OWASP_ASVS,
        knowledge_type=KnowledgeType.SECURITY_INVARIANT,
        category_tags=["Access_Control"],
        title="ASVS Requirements",
        section_heading="Access Control",
        content="Access controls must be enforced centrally on the server.",
        token_estimate=60,
        content_hash="11223344556677889900aabbccddeeff",
        trust_tier="CURATED_ADVISORY",
    )
    assert chunk.trust_tier == "CURATED_ADVISORY"
    assert chunk.document_id == "DOC-ASVS"


def test_retrieval_item_and_pack_nesting():
    """Verify KnowledgeRetrievalItem inside VaptKnowledgePack."""
    chunk = KnowledgeChunk(
        chunk_id="CHK-DOC-WSTG-001-01",
        document_id="DOC-WSTG",
        source_type=KnowledgeSourceType.OWASP_WSTG,
        knowledge_type=KnowledgeType.TESTING_METHODOLOGY,
        category_tags=["BFLA"],
        title="Testing BFLA",
        section_heading="Procedure",
        content="Issue request with unprivileged credentials.",
        token_estimate=55,
        content_hash="aabbccddeeff00112233",
    )
    item = KnowledgeRetrievalItem(
        chunk=chunk,
        dense_score=0.82,
        sparse_score=1.45,
        fused_score=0.016,
        retrieval_rank=1,
        query_id="Q-001",
    )
    pack = VaptKnowledgePack(
        pack_id="PACK-TEST-01",
        items=[item],
        total_tokens=55,
        rendered_query_text="Method: POST | Route: /admin/users",
        retrieval_timestamp="2026-09-20T00:00:00Z",
        corpus_manifest_hash="man_hash",
        provenance_hash="prov_hash",
    )
    assert len(pack.items) == 1
    assert pack.items[0].retrieval_rank == 1
    assert pack.items[0].chunk.chunk_id == "CHK-DOC-WSTG-001-01"


def test_trust_root_record_validation():
    """Verify TrustRootRecord schema."""
    tr = TrustRootRecord(
        key_id="KEY-TEST-01",
        public_key_bytes="a" * 64,
        public_key_fingerprint="b" * 64,
        algorithm="Ed25519",
        created_at="2026-09-20T00:00:00Z",
        description="Test Key",
    )
    assert tr.key_id == "KEY-TEST-01"
    assert tr.algorithm == "Ed25519"
