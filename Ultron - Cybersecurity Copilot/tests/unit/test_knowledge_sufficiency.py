"""Unit Tests for KnowledgeSufficiencyEngine (Milestone M5)."""

import pytest
from src.copilot.domain import SecurityDomain
from src.copilot.intent import CopilotMode, CopilotTaskType
from src.copilot.sufficiency import KnowledgeSufficiencyEngine, SufficiencyStatus
from src.knowledge.models import (
    KnowledgeChunk,
    KnowledgeRetrievalItem,
    KnowledgeSourceType,
    KnowledgeType,
    VaptKnowledgePack,
)


def _make_mock_pack(chunk_count: int = 1, fused_score: float = 0.035) -> VaptKnowledgePack:
    items = []
    for i in range(chunk_count):
        chunk = KnowledgeChunk(
            chunk_id=f"CHK-TEST-{i:03d}",
            document_id="DOC-TEST",
            source_type=KnowledgeSourceType.OWASP_WSTG,
            knowledge_type=KnowledgeType.SECURITY_INVARIANT,
            title="Test Invariant",
            section_heading="Test Heading",
            content="Server must verify authorization on every access.",
            token_estimate=50,
            content_hash="test_hash",
        )
        items.append(
            KnowledgeRetrievalItem(
                chunk=chunk,
                dense_score=0.9,
                sparse_score=0.8,
                fused_score=fused_score,
                retrieval_rank=i + 1,
                query_id="Q-TEST",
            )
        )
    return VaptKnowledgePack(
        pack_id="PACK-TEST-001",
        items=items,
        total_tokens=50 * chunk_count,
        rendered_query_text="query",
        retrieval_timestamp="2026-10-06T00:00:00Z",
        corpus_manifest_hash="hash",
        provenance_hash="prov",
    )


def test_sufficiency_general_qa_resolves_locally():
    """General QA in well-covered domain never searches externally."""
    res = KnowledgeSufficiencyEngine.evaluate_sufficiency(
        query="What is the difference between authentication and authorization?",
        domain=SecurityDomain.AUTHORIZATION,
        task=CopilotTaskType.EXPLAIN,
        mode=CopilotMode.GENERAL_QA,
    )
    assert res.status == SufficiencyStatus.LOCAL_SUFFICIENT
    assert res.escalate_to_external_research is False
    assert res.sanitized_external_query is None


def test_sufficiency_local_chunks_high_confidence():
    """VAPT investigation with local chunks returns LOCAL_SUFFICIENT."""
    pack = _make_mock_pack(chunk_count=2, fused_score=0.040)
    res = KnowledgeSufficiencyEngine.evaluate_sufficiency(
        query="Verify BOLA on /api/v1/invoices",
        domain=SecurityDomain.API_SECURITY,
        task=CopilotTaskType.INVESTIGATE,
        mode=CopilotMode.INVESTIGATION,
        local_pack=pack,
    )
    assert res.status == SufficiencyStatus.LOCAL_SUFFICIENT
    assert res.escalate_to_external_research is False


def test_sufficiency_explicit_cve_mandates_external():
    """Queries referencing specific CVEs require external research."""
    res = KnowledgeSufficiencyEngine.evaluate_sufficiency(
        query="Explain CVE-2024-21413 vulnerability in Outlook",
        domain=SecurityDomain.VULNERABILITY_RESEARCH,
        task=CopilotTaskType.VULNERABILITY_RESEARCH,
        mode=CopilotMode.RESEARCH,
    )
    assert res.status == SufficiencyStatus.EXTERNAL_REQUIRED
    assert res.escalate_to_external_research is True
    assert res.sanitized_external_query is not None


def test_sufficiency_explicit_rfc_mandates_external():
    """Queries referencing RFC specifications require external research."""
    res = KnowledgeSufficiencyEngine.evaluate_sufficiency(
        query="What are the PKCE verification rules in RFC 7636?",
        domain=SecurityDomain.AUTHENTICATION,
        task=CopilotTaskType.RESEARCH,
        mode=CopilotMode.RESEARCH,
    )
    assert res.status == SufficiencyStatus.EXTERNAL_REQUIRED
    assert res.escalate_to_external_research is True


def test_sufficiency_unsupported_domain_produces_knowledge_gap():
    """Domains with NONE/LIMITED coverage produce KNOWLEDGE_GAP."""
    res = KnowledgeSufficiencyEngine.evaluate_sufficiency(
        query="Analyze this PE header and packed malware binary",
        domain=SecurityDomain.MALWARE_ANALYSIS,
        task=CopilotTaskType.RESEARCH,
        mode=CopilotMode.RESEARCH,
    )
    assert res.status == SufficiencyStatus.KNOWLEDGE_GAP
    assert res.escalate_to_external_research is True


def test_sufficiency_evidence_gap_recommends_external():
    """Evidence gaps in limited/partial domains trigger EXTERNAL_RECOMMENDED."""
    res = KnowledgeSufficiencyEngine.evaluate_sufficiency(
        query="Check session expiration and identity claim boundary",
        domain=SecurityDomain.AUTHENTICATION,
        task=CopilotTaskType.INVESTIGATE,
        mode=CopilotMode.INVESTIGATION,
        evidence_gaps=["GAP-01: Missing IDP response claim"],
    )
    assert res.status == SufficiencyStatus.EXTERNAL_RECOMMENDED
    assert res.escalate_to_external_research is True
