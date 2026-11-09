"""Unit tests for SQLite FTS5 VAPT Knowledge Store."""

from pathlib import Path
import pytest

from src.knowledge.models import (
    KnowledgeChunk,
    KnowledgeDocumentFrontmatter,
    KnowledgeSourceType,
    KnowledgeType,
)
from src.knowledge.store import VaptKnowledgeStore, VaptStoreError


def test_dual_store_separation_rejection(tmp_path: Path):
    """Verify that opening evidence.db raises immediate dual store separation violation."""
    bad_path = tmp_path / "evidence.db"
    with pytest.raises(VaptStoreError, match="DUAL_STORE_SEPARATION_VIOLATION"):
        VaptKnowledgeStore(bad_path)


def test_store_insertion_and_retrieval(tmp_path: Path):
    """Verify document/chunk insertion and retrieval by ID."""
    db_path = tmp_path / "vapt_knowledge.db"
    store = VaptKnowledgeStore(db_path, read_only=False)

    fm = KnowledgeDocumentFrontmatter(
        document_id="DOC-WSTG-04",
        title="IDOR Testing",
        source_name="OWASP WSTG",
        source_version="v4.2",
        source_url="https://example.com",
        license="CC-BY-SA-4.0",
        author="OWASP",
        content_hash="body_hash_123",
    )
    store.insert_document(fm, "Normalized body text for IDOR testing.")

    chunk = KnowledgeChunk(
        chunk_id="CHK-DOC-WSTG-04-001-01",
        document_id="DOC-WSTG-04",
        source_type=KnowledgeSourceType.OWASP_WSTG,
        knowledge_type=KnowledgeType.TESTING_METHODOLOGY,
        category_tags=["IDOR", "Authorization"],
        title="IDOR Testing",
        section_heading="Test Methodology",
        content="Testing insecure direct object reference parameter substitution.",
        token_estimate=50,
        content_hash="chunk_hash_456",
    )
    store.insert_chunks([chunk])

    assert store.get_document_count() == 1
    assert store.get_chunk_count() == 1

    fetched_chunk = store.get_chunk("CHK-DOC-WSTG-04-001-01")
    assert fetched_chunk is not None
    assert fetched_chunk.title == "IDOR Testing"
    assert fetched_chunk.category_tags == ["IDOR", "Authorization"]

    all_chunks = store.get_all_chunks()
    assert len(all_chunks) == 1
    assert all_chunks[0].chunk_id == "CHK-DOC-WSTG-04-001-01"

    store.close()


def test_fts5_lexical_retrieval_and_tie_breaking(tmp_path: Path):
    """Verify FTS5 BM25 search ranking and deterministic chunk_id ASC tie-break."""
    db_path = tmp_path / "vapt_knowledge.db"
    store = VaptKnowledgeStore(db_path, read_only=False)

    fm = KnowledgeDocumentFrontmatter(
        document_id="DOC-TEST",
        title="Test Doc",
        source_name="OWASP WSTG",
        source_version="v4.2",
        source_url="https://example.com",
        license="CC-BY-SA-4.0",
        author="OWASP",
        content_hash="hash",
    )
    store.insert_document(fm, "body")

    c1 = KnowledgeChunk(
        chunk_id="CHK-B-001",
        document_id="DOC-TEST",
        source_type=KnowledgeSourceType.OWASP_WSTG,
        knowledge_type=KnowledgeType.TESTING_METHODOLOGY,
        category_tags=["IDOR"],
        title="IDOR Verification",
        section_heading="Direct Object Ref",
        content="Specific direct object reference parameter testing.",
        token_estimate=20,
        content_hash="h1",
    )
    c2 = KnowledgeChunk(
        chunk_id="CHK-A-001",
        document_id="DOC-TEST",
        source_type=KnowledgeSourceType.OWASP_WSTG,
        knowledge_type=KnowledgeType.TESTING_METHODOLOGY,
        category_tags=["IDOR"],
        title="IDOR Verification",
        section_heading="Direct Object Ref",
        content="Specific direct object reference parameter testing.",
        token_estimate=20,
        content_hash="h2",
    )
    # c1 and c2 have identical content and metadata, so identical BM25 scores
    store.insert_chunks([c1, c2])

    results = store.query_lexical("direct object reference", top_k=5)
    assert len(results) == 2
    # Because scores are identical, CHK-A-001 must appear before CHK-B-001 (chunk_id ASC)
    assert results[0][0].chunk_id == "CHK-A-001"
    assert results[1][0].chunk_id == "CHK-B-001"

    store.close()


def test_read_only_mode_prevents_mutation(tmp_path: Path):
    """Verify read-only store prevents modifications."""
    db_path = tmp_path / "vapt_knowledge.db"
    # Create and populate
    store = VaptKnowledgeStore(db_path, read_only=False)
    store.close()

    # Open read-only
    ro_store = VaptKnowledgeStore(db_path, read_only=True)
    fm = KnowledgeDocumentFrontmatter(
        document_id="DOC-RO",
        title="T",
        source_name="S",
        source_version="V",
        source_url="U",
        license="L",
        author="A",
        content_hash="H",
    )
    with pytest.raises(VaptStoreError, match="READ_ONLY_VIOLATION"):
        ro_store.insert_document(fm, "body")

    ro_store.close()
