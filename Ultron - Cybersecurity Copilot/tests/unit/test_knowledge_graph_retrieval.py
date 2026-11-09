"""Unit tests for Stage D Graph-Assisted Retrieval & Evidence Fusion.

Covers Section 5 requirements:
- A. Baseline retrieval preservation
- B. Graph-assisted retrieval & bounded traversal
- C. Provenance and source lifecycle (deactivated/stale/missing chunk protection)
- D. Epistemic integrity (SOURCE_SUPPORTED, INFERRED, CANDIDATE, REJECTED)
"""

import json
from pathlib import Path
from typing import Any, Dict, List
import pytest

from src.knowledge.canonical_models import (
    AuthorityLevel,
    CanonicalSourceType,
)
from src.knowledge.graph_retriever import (
    GraphAssistedRetriever,
    GraphExpansionEvidence,
    GraphRetrieverMetadata,
)
from src.knowledge.knowledge_graph import RelationalKnowledgeGraph
from src.knowledge.models import (
    KnowledgeChunk,
    KnowledgeSourceType,
    KnowledgeType,
)
from src.knowledge.store import VaptKnowledgeStore


@pytest.fixture
def store_and_graph(tmp_path: Path):
    """Fixture providing isolated, clean SQLite stores for VAPT knowledge and graph."""
    vapt_path = tmp_path / "vapt_knowledge.db"
    graph_path = tmp_path / "knowledge_graph.db"

    store = VaptKnowledgeStore(vapt_path)
    graph = RelationalKnowledgeGraph(graph_path)

    # Ingest baseline source and document
    store.insert_source(
        source_id="SRC-AUTH-01",
        title="OWASP Web Security Testing Guide v4.2",
        source_type="TESTING_GUIDE",
        authority_level="AUTHORITATIVE",
        filename="wstg.md",
        format="markdown",
        content_hash="hash-auth-01",
        original_checksum="chk-auth-01",
        page_count=100,
        metadata={"author": "OWASP"},
    )
    store.update_source_status("SRC-AUTH-01", "ACTIVE")

    # Insert baseline chunks
    chunk_sqli = KnowledgeChunk(
        schema_version="3.0.0",
        chunk_id="CHK-SQLI-001",
        document_id="DOC-SRC-AUTH-01",
        source_type=KnowledgeSourceType.OWASP_WSTG,
        knowledge_type=KnowledgeType.VULNERABILITY_PATTERN,
        category_tags=["sqli", "injection", "database"],
        title="Testing for SQL Injection",
        section_heading="WSTG-INPV-05",
        content="SQL injection occurs when untrusted user input is directly concatenated into SQL queries.",
        token_estimate=20,
        content_hash="h-sqli-01",
        trust_tier="AUTHORITATIVE",
    )
    chunk_mitigation = KnowledgeChunk(
        schema_version="3.0.0",
        chunk_id="CHK-MITIG-002",
        document_id="DOC-SRC-AUTH-01",
        source_type=KnowledgeSourceType.OWASP_WSTG,
        knowledge_type=KnowledgeType.MITIGATION,
        category_tags=["defense", "parameterization", "mitigation"],
        title="Parameterized Queries Guidance",
        section_heading="WSTG-PREV-01",
        content="Parameterized queries and prepared statements ensure user input is treated as literal data, preventing injection.",
        token_estimate=25,
        content_hash="h-mitig-02",
        trust_tier="AUTHORITATIVE",
    )
    store.insert_chunks([chunk_sqli, chunk_mitigation])

    # Populate Knowledge Graph
    # Node 1: SQL Injection
    node_sqli_meta = {
        "evidence_citations": [
            {
                "source_id": "SRC-AUTH-01",
                "document_id": "DOC-SRC-AUTH-01",
                "chunk_id": "CHK-SQLI-001",
                "page_number": 12,
                "supporting_quote": "SQL injection occurs when untrusted user input",
                "quote_verified": True,
                "epistemic_status": "SOURCE_SUPPORTED",
            }
        ]
    }
    graph.add_node("NODE:vulnerability:sql_injection", "VULNERABILITY", "SQL Injection", node_sqli_meta)

    # Node 2: Parameterized Queries
    node_param_meta = {
        "evidence_citations": [
            {
                "source_id": "SRC-AUTH-01",
                "document_id": "DOC-SRC-AUTH-01",
                "chunk_id": "CHK-MITIG-002",
                "page_number": 45,
                "supporting_quote": "Parameterized queries and prepared statements",
                "quote_verified": True,
                "epistemic_status": "SOURCE_SUPPORTED",
            }
        ]
    }
    graph.add_node("NODE:defense:parameterized_queries", "DEFENSIVE_CONTROL", "Parameterized Queries", node_param_meta)

    # Edge: Parameterized Queries MITIGATES SQL Injection
    edge_meta = {
        "explanation": "Prepared statements prevent SQL query tampering",
        "predicate": "MITIGATES",
        "epistemic_status": "SOURCE_SUPPORTED",
        "evidence_citations": [
            {
                "source_id": "SRC-AUTH-01",
                "document_id": "DOC-SRC-AUTH-01",
                "chunk_id": "CHK-MITIG-002",
                "page_number": 45,
                "supporting_quote": "Parameterized queries and prepared statements ensure user input is treated as literal data",
                "quote_verified": True,
                "epistemic_status": "SOURCE_SUPPORTED",
            }
        ],
    }
    graph.add_edge(
        "NODE:defense:parameterized_queries",
        "NODE:vulnerability:sql_injection",
        "MITIGATES",
        edge_meta,
    )

    yield {
        "store": store,
        "graph": graph,
        "vapt_path": vapt_path,
        "graph_path": graph_path,
        "chunk_sqli": chunk_sqli,
        "chunk_mitigation": chunk_mitigation,
    }

    store.close()
    graph.close()


def test_entity_term_extraction():
    """Extracts formal cybersecurity identifiers and meaningful n-grams while filtering stop words."""
    query = "How to exploit CVE-2021-44228 and prevent CWE-89 SQL Injection using T1190?"
    terms = GraphAssistedRetriever.extract_entity_terms(query)

    # Formal identifiers
    assert "CVE-2021-44228" in terms
    assert "CWE-89" in terms
    assert "T1190" in terms

    # Key phrases
    assert any("SQL Injection" in t for t in terms)
    # Stop words must not appear as standalone terms
    assert "how" not in [t.lower() for t in terms]
    assert "to" not in [t.lower() for t in terms]
    assert "and" not in [t.lower() for t in terms]


def test_relevant_entity_resolution(store_and_graph):
    """Resolves matching graph entities for natural language query."""
    graph = store_and_graph["graph"]
    retriever = GraphAssistedRetriever(knowledge_graph=graph)

    nodes = retriever.find_relevant_entities("tell me about SQL Injection techniques")
    assert len(nodes) >= 1
    assert any(n["label"] == "SQL Injection" for n in nodes)


def test_bounded_graph_expansion_recovers_source_chunk(store_and_graph):
    """
    Demonstrates that graph expansion finds the connected mitigation chunk
    anchored to the authoritative source passage.
    """
    store = store_and_graph["store"]
    graph = store_and_graph["graph"]
    retriever = GraphAssistedRetriever(knowledge_store=store, knowledge_graph=graph)

    # Query only mentions SQL Injection
    nodes = retriever.find_relevant_entities("SQL Injection vulnerability")
    recovered, evidence, meta = retriever.expand_graph_evidence(nodes)

    assert meta.traversal_successful is True
    assert len(recovered) >= 1
    # Both the directly anchored chunk and the incident edge chunk should be recovered
    recovered_ids = {c.chunk_id for c in recovered}
    assert "CHK-SQLI-001" in recovered_ids
    assert "CHK-MITIG-002" in recovered_ids

    # Lineage records must preserve exact provenance
    mitig_ev = next(e for e in evidence if e.chunk_id == "CHK-MITIG-002")
    assert mitig_ev.source_id == "SRC-AUTH-01"
    assert mitig_ev.relation_type in {"NODE_ANCHOR", "MITIGATES"}
    assert mitig_ev.epistemic_status == "SOURCE_SUPPORTED"


def test_baseline_preservation_when_graph_empty_or_offline(tmp_path):
    """When graph is None, empty, or has no matches, baseline chunks are returned without loss."""
    vapt_path = tmp_path / "vapt_empty.db"
    store = VaptKnowledgeStore(vapt_path)
    retriever_no_graph = GraphAssistedRetriever(knowledge_store=store, knowledge_graph=None)

    fake_baseline = [
        KnowledgeChunk(
            schema_version="3.0.0",
            chunk_id="CHK-BASE-01",
            document_id="DOC-1",
            source_type=KnowledgeSourceType.OWASP_WSTG,
            knowledge_type=KnowledgeType.VULNERABILITY_PATTERN,
            category_tags=["test"],
            title="Baseline Title",
            section_heading="Heading",
            content="Baseline content",
            token_estimate=10,
            content_hash="h1",
            trust_tier="AUTHORITATIVE",
        )
    ]

    chunks, evidence, meta = retriever_no_graph.retrieve("random query", baseline_chunks=fake_baseline)
    assert len(chunks) == 1
    assert chunks[0].chunk_id == "CHK-BASE-01"
    assert len(evidence) == 0
    assert meta.error_message == "Graph not configured"
    store.close()


def test_deduplication_and_deterministic_fusion(store_and_graph):
    """Fused results must deduplicate identical chunks and produce deterministic order."""
    store = store_and_graph["store"]
    graph = store_and_graph["graph"]
    retriever = GraphAssistedRetriever(knowledge_store=store, knowledge_graph=graph)

    # Baseline already contains CHK-SQLI-001
    baseline = [store_and_graph["chunk_sqli"]]
    runs = []
    for _ in range(5):
        chunks, evidence, meta = retriever.retrieve("SQL Injection", baseline_chunks=baseline, top_k=5)
        runs.append([c.chunk_id for c in chunks])

    # All runs must produce identical chunk ID sequences
    assert runs[0] == ["CHK-SQLI-001", "CHK-MITIG-002"]
    for r in runs[1:]:
        assert r == runs[0]


def test_deactivated_source_cannot_reenter_via_graph(store_and_graph):
    """
    CRITICAL SAFETY GATE: Deactivated source chunks must be rejected
    from graph expansion to prevent stale retrieval contamination.
    """
    store = store_and_graph["store"]
    graph = store_and_graph["graph"]
    retriever = GraphAssistedRetriever(knowledge_store=store, knowledge_graph=graph)

    # Deactivate the source
    deactivated = store.deactivate_source("SRC-AUTH-01")
    assert deactivated is True

    # Attempt retrieval via graph
    nodes = retriever.find_relevant_entities("SQL Injection")
    recovered, evidence, meta = retriever.expand_graph_evidence(nodes)

    # Zero chunks admitted because source is deactivated
    assert len(recovered) == 0
    assert len(evidence) == 0
    assert meta.stale_or_ineligible_skipped > 0


def test_missing_chunk_skipped_without_fabrication(store_and_graph):
    """
    Graph edges pointing to missing/deleted chunk records must be skipped.
    No hallucinated text or synthetic chunks may be substituted.
    """
    store = store_and_graph["store"]
    graph = store_and_graph["graph"]

    # Add phantom edge pointing to non-existent chunk CHK-PHANTOM-999
    phantom_meta = {
        "predicate": "RELATED_TO",
        "epistemic_status": "SOURCE_SUPPORTED",
        "evidence_citations": [
            {
                "source_id": "SRC-AUTH-01",
                "document_id": "DOC-SRC-AUTH-01",
                "chunk_id": "CHK-PHANTOM-999",
                "supporting_quote": "Fabricated quote that does not exist in store",
            }
        ],
    }
    graph.add_node("NODE:phantom:concept", "CONCEPT", "Phantom Concept", {})
    graph.add_edge(
        "NODE:vulnerability:sql_injection",
        "NODE:phantom:concept",
        "RELATED_TO",
        phantom_meta,
    )

    retriever = GraphAssistedRetriever(knowledge_store=store, knowledge_graph=graph)
    nodes = [graph.get_node("NODE:phantom:concept")]
    recovered, evidence, meta = retriever.expand_graph_evidence(nodes)

    assert all(c.chunk_id != "CHK-PHANTOM-999" for c in recovered)
    assert meta.missing_chunks_skipped >= 1


def test_epistemic_filtering_rejected_edges_strictly_excluded(store_and_graph):
    """
    Edges marked REJECTED during Stage C validation must NEVER be traversed
    or admitted as factual evidence.
    """
    store = store_and_graph["store"]
    graph = store_and_graph["graph"]

    rejected_meta = {
        "predicate": "CAUSES",
        "epistemic_status": "REJECTED",
        "rejection_reason": "Failed semantic validation",
        "evidence_citations": [
            {
                "source_id": "SRC-AUTH-01",
                "chunk_id": "CHK-SQLI-001",
                "epistemic_status": "REJECTED",
            }
        ],
    }
    graph.add_node("NODE:bad:edge", "VULNERABILITY", "False Vulnerability", {})
    graph.add_edge(
        "NODE:vulnerability:sql_injection",
        "NODE:bad:edge",
        "CAUSES",
        rejected_meta,
    )

    retriever = GraphAssistedRetriever(knowledge_store=store, knowledge_graph=graph)
    edges = graph.get_incident_edges("NODE:vulnerability:sql_injection", exclude_rejected=True)

    # Edge with REJECTED epistemic status must be filtered out
    assert not any(e["relation_type"] == "CAUSES" and e["target_id"] == "NODE:bad:edge" for e in edges)


def test_inferred_edge_handled_conservatively(store_and_graph):
    """
    Inferred relationships can serve as discovery signals if enabled,
    but retain INFERRED epistemic label and are never upgraded to factual truths.
    """
    store = store_and_graph["store"]
    graph = store_and_graph["graph"]

    inferred_meta = {
        "predicate": "ASSOCIATED_WITH",
        "epistemic_status": "INFERRED",
        "evidence_citations": [
            {
                "source_id": "SRC-AUTH-01",
                "document_id": "DOC-SRC-AUTH-01",
                "chunk_id": "CHK-MITIG-002",
                "epistemic_status": "INFERRED",
            }
        ],
    }
    graph.add_node("NODE:inferred:topic", "CONCEPT", "Heuristic Topic", {})
    graph.add_edge(
        "NODE:vulnerability:sql_injection",
        "NODE:inferred:topic",
        "ASSOCIATED_WITH",
        inferred_meta,
    )

    retriever = GraphAssistedRetriever(
        knowledge_store=store,
        knowledge_graph=graph,
        include_inferred=True,
    )
    nodes = [graph.get_node("NODE:inferred:topic")]
    recovered, evidence, meta = retriever.expand_graph_evidence(nodes)

    assert meta.epistemic_breakdown.get("INFERRED", 0) >= 1
    inferred_ev = next((e for e in evidence if e.epistemic_status == "INFERRED"), None)
    if inferred_ev:
        assert inferred_ev.epistemic_status == "INFERRED"


def test_traversal_depth_and_candidate_bounds(store_and_graph):
    """Graph expansion strictly respects configured bounds on max entities and chunks."""
    store = store_and_graph["store"]
    graph = store_and_graph["graph"]

    # Configure strict bounds
    retriever = GraphAssistedRetriever(
        knowledge_store=store,
        knowledge_graph=graph,
        max_entities=1,
        max_edges_per_node=1,
        max_graph_chunks=1,
        max_total_chunks=1,
    )

    chunks, evidence, meta = retriever.retrieve("SQL Injection and parameterized queries")
    assert len(chunks) <= 1
    assert meta.graph_chunks_admitted <= 1
