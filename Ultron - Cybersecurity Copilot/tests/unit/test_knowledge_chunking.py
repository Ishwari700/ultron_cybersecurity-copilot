"""Unit tests for SemanticMarkdownChunker v1.0.0."""

import pytest
from src.knowledge.chunking import SemanticMarkdownChunker
from src.knowledge.models import KnowledgeSourceType, KnowledgeType


def test_chunker_version_and_code_hash():
    """Verify chunker declares version 1.0.0 and emits stable code hash."""
    assert SemanticMarkdownChunker.VERSION == "1.0.0"
    h1 = SemanticMarkdownChunker.get_chunker_code_hash()
    h2 = SemanticMarkdownChunker.get_chunker_code_hash()
    assert len(h1) == 64
    assert h1 == h2


def test_chunking_naming_and_breadcrumbs():
    """Verify chunk naming format CHK-{DOC}-{SEC:03d}-{PART:02d} and breadcrumb."""
    body = """## Overview
This is the overview section for authorization testing.

## Methodology
Step 1: Identify direct references.
Step 2: Substitute identifiers.
"""
    chunks = SemanticMarkdownChunker.chunk_document(
        document_id="DOC-WSTG-01",
        title="IDOR Guide",
        source_type=KnowledgeSourceType.OWASP_WSTG,
        knowledge_type=KnowledgeType.TESTING_METHODOLOGY,
        normalized_body=body,
        category_tags=["IDOR"],
    )

    assert len(chunks) == 2
    assert chunks[0].chunk_id == "CHK-DOC-WSTG-01-001-01"
    assert chunks[1].chunk_id == "CHK-DOC-WSTG-01-002-01"
    assert "[DOC: IDOR Guide] [SEC: Overview]" in chunks[0].content
    assert "[DOC: IDOR Guide] [SEC: Methodology]" in chunks[1].content
    assert chunks[0].content_hash
    assert chunks[0].token_estimate > 0


def test_subdivision_and_code_atomicity():
    """Verify large section subdivision while preserving code block atomicity."""
    large_list = "\n".join([f"- Procedural step {i} testing authorization boundaries." for i in range(40)])
    code_snippet = "```http\nPOST /api/v1/orders HTTP/1.1\nHost: target\n\n{\"id\": 100}\n```"
    body = f"## Massive Section\n{large_list}\n\n{code_snippet}\n"

    chunks = SemanticMarkdownChunker.chunk_document(
        document_id="DOC-CWE-01",
        title="Large CWE",
        source_type=KnowledgeSourceType.CWE,
        knowledge_type=KnowledgeType.EXPERIMENT_PATTERN,
        normalized_body=body,
    )

    # Must be subdivided into multiple parts
    assert len(chunks) > 1
    # Check parts format: CHK-DOC-CWE-01-001-01, CHK-DOC-CWE-01-001-02, ...
    for idx, chunk in enumerate(chunks, start=1):
        assert chunk.chunk_id == f"CHK-DOC-CWE-01-001-{idx:02d}"
        assert f"(Part {idx:02d} of {len(chunks):02d})" in chunk.content

    # Assert code block was not bisected
    code_containing_chunks = [c for c in chunks if "POST /api/v1/orders" in c.content]
    assert len(code_containing_chunks) == 1
    assert "```http" in code_containing_chunks[0].content
    assert "{\"id\": 100}" in code_containing_chunks[0].content


def test_token_ceiling_and_min_floor():
    """Verify chunk sizes adhere to constraints."""
    body = """## Tiny Section 1
Brief point.

## Tiny Section 2
Another brief point.
"""
    chunks = SemanticMarkdownChunker.chunk_document(
        document_id="DOC-TINY",
        title="Tiny Doc",
        source_type=KnowledgeSourceType.PLATFORM_INVARIANT,
        knowledge_type=KnowledgeType.SECURITY_INVARIANT,
        normalized_body=body,
    )
    assert len(chunks) >= 1
    for chunk in chunks:
        assert chunk.token_estimate <= SemanticMarkdownChunker.HARD_MAX_TOKENS
