"""Deterministic 7-Scenario Retrieval Evaluation for Stage D (Section 6).

Evaluates Baseline vs Graph-Assisted Retrieval across 7 required cybersecurity scenarios:
1. Direct source retrieval (query matches passage directly)
2. Relevant connected concept (query matches concept A, edge reaches related concept B)
3. Relationship leading to a different useful passage (e.g. vulnerability -> remediation)
4. Graph with irrelevant edges (noise filtering / precision)
5. Missing or stale source evidence (lifecycle safety / zero phantom chunks)
6. Inferred or unverified relations (epistemic conservatism)
7. Empty or unavailable graph (baseline preservation fallback)
"""

from pathlib import Path
from typing import Any, Dict, List, Set, Tuple
import pytest

from src.knowledge.graph_retriever import GraphAssistedRetriever
from src.knowledge.knowledge_graph import RelationalKnowledgeGraph
from src.knowledge.models import (
    KnowledgeChunk,
    KnowledgeSourceType,
    KnowledgeType,
)
from src.knowledge.store import VaptKnowledgeStore


@pytest.fixture
def eval_corpus(tmp_path: Path):
    """Initializes deterministic corpus and knowledge graph for evaluation."""
    vapt_path = tmp_path / "vapt_eval.db"
    graph_path = tmp_path / "graph_eval.db"

    store = VaptKnowledgeStore(vapt_path)
    graph = RelationalKnowledgeGraph(graph_path)

    # Register active source
    store.insert_source(
        source_id="SRC-EVAL-ACTIVE",
        title="Application Security Architecture Guide",
        source_type="ARCHITECTURE_GUIDE",
        authority_level="AUTHORITATIVE",
        filename="appsec_guide.md",
        format="markdown",
        content_hash="hash-eval-active",
        original_checksum="chk-eval-active",
        page_count=50,
        metadata={"author": "SecTeam"},
    )
    store.update_source_status("SRC-EVAL-ACTIVE", "ACTIVE")

    # Register deactivated source (for stale lifecycle scenario)
    store.insert_source(
        source_id="SRC-EVAL-DEACTIVATED",
        title="Deprecated Vulnerability Guide v1",
        source_type="LEGACY_MANUAL",
        authority_level="COMMUNITY",
        filename="deprecated_guide.md",
        format="markdown",
        content_hash="hash-eval-deact",
        original_checksum="chk-eval-deact",
        page_count=10,
        metadata={"author": "OldSec"},
    )
    store.update_source_status("SRC-EVAL-DEACTIVATED", "ACTIVE")

    # Chunks for scenarios
    # Chunk 1: Direct definition of BOLA
    c_bola_def = KnowledgeChunk(
        schema_version="3.0.0",
        chunk_id="CHK-BOLA-DEF",
        document_id="DOC-SRC-EVAL-ACTIVE",
        source_type=KnowledgeSourceType.OWASP_WSTG,
        knowledge_type=KnowledgeType.VULNERABILITY_PATTERN,
        category_tags=["api", "bola", "idor"],
        title="Broken Object Level Authorization Mechanics",
        section_heading="BOLA Overview",
        content="Broken Object Level Authorization (BOLA) occurs when an API endpoint does not validate if the caller owns the requested object ID.",
        token_estimate=25,
        content_hash="h-bola-def",
        trust_tier="AUTHORITATIVE",
    )
    # Chunk 2: Remediation for BOLA (distinct section)
    c_bola_rem = KnowledgeChunk(
        schema_version="3.0.0",
        chunk_id="CHK-BOLA-REM",
        document_id="DOC-SRC-EVAL-ACTIVE",
        source_type=KnowledgeSourceType.OWASP_WSTG,
        knowledge_type=KnowledgeType.MITIGATION,
        category_tags=["defense", "authorization", "remediation"],
        title="Remediating Object Level Flaws",
        section_heading="Object Auth Defense",
        content="To prevent BOLA, validate user authorization against the data store before returning the object. Implement tenant-level context filtering.",
        token_estimate=25,
        content_hash="h-bola-rem",
        trust_tier="AUTHORITATIVE",
    )
    # Chunk 3: JWT Algorithm Confusion
    c_jwt_conf = KnowledgeChunk(
        schema_version="3.0.0",
        chunk_id="CHK-JWT-CONF",
        document_id="DOC-SRC-EVAL-ACTIVE",
        source_type=KnowledgeSourceType.OWASP_WSTG,
        knowledge_type=KnowledgeType.VULNERABILITY_PATTERN,
        category_tags=["jwt", "auth", "crypto"],
        title="JWT Algorithm Confusion Attacks",
        section_heading="JWT Mechanics",
        content="Algorithm confusion attacks exploit servers that verify asymmetric RSA signatures using public keys as HMAC secrets.",
        token_estimate=25,
        content_hash="h-jwt-conf",
        trust_tier="AUTHORITATIVE",
    )
    # Chunk 4: Stale Chunk belonging to deactivated source
    c_stale = KnowledgeChunk(
        schema_version="3.0.0",
        chunk_id="CHK-STALE-OLD",
        document_id="DOC-SRC-EVAL-DEACTIVATED",
        source_type=KnowledgeSourceType.OWASP_WSTG,
        knowledge_type=KnowledgeType.VULNERABILITY_PATTERN,
        category_tags=["legacy", "obsolete"],
        title="Obsolete Insecure Advice",
        section_heading="Deprecated",
        content="Obsolete guidance suggesting MD5 hashing for passwords.",
        token_estimate=15,
        content_hash="h-stale-old",
        trust_tier="COMMUNITY",
    )
    # Chunk 5: Unrelated noise chunk
    c_printer = KnowledgeChunk(
        schema_version="3.0.0",
        chunk_id="CHK-NOISE-PRINTER",
        document_id="DOC-SRC-EVAL-ACTIVE",
        source_type=KnowledgeSourceType.OWASP_WSTG,
        knowledge_type=KnowledgeType.TOOL_GUIDANCE,
        category_tags=["hardware", "printer"],
        title="Office Printer Network Setup",
        section_heading="Printer Config",
        content="Configure laser printer IP addresses on VLAN 10.",
        token_estimate=15,
        content_hash="h-printer",
        trust_tier="COMMUNITY",
    )

    # Chunk 6: Inferred experiment chunk
    c_inferred = KnowledgeChunk(
        schema_version="3.0.0",
        chunk_id="CHK-INFERRED-EXP",
        document_id="DOC-SRC-EVAL-ACTIVE",
        source_type=KnowledgeSourceType.OWASP_WSTG,
        knowledge_type=KnowledgeType.EXPERIMENT_PATTERN,
        category_tags=["hypothesis", "session"],
        title="Hypothesized Session Token Rotation",
        section_heading="Experimental Session Handling",
        content="Inferred mitigation: Rotating session identifiers on every privileged state transition.",
        token_estimate=20,
        content_hash="h-inferred-exp",
        trust_tier="AUTHORITATIVE",
    )

    store.insert_chunks([c_bola_def, c_bola_rem, c_jwt_conf, c_stale, c_printer, c_inferred])

    # Now deactivate the deactivated source in store
    store.deactivate_source("SRC-EVAL-DEACTIVATED")

    # Setup Graph
    # Node BOLA
    graph.add_node(
        "NODE:vulnerability:bola",
        "VULNERABILITY",
        "Broken Object Level Authorization",
        {
            "evidence_citations": [
                {
                    "source_id": "SRC-EVAL-ACTIVE",
                    "chunk_id": "CHK-BOLA-DEF",
                    "epistemic_status": "SOURCE_SUPPORTED",
                }
            ]
        },
    )
    # Node Object Level Access Control
    graph.add_node(
        "NODE:defense:object_access_control",
        "DEFENSIVE_CONTROL",
        "Object Level Access Control",
        {
            "evidence_citations": [
                {
                    "source_id": "SRC-EVAL-ACTIVE",
                    "chunk_id": "CHK-BOLA-REM",
                    "epistemic_status": "SOURCE_SUPPORTED",
                }
            ]
        },
    )
    # Edge BOLA -> Object Level Access Control (MITIGATES)
    graph.add_edge(
        "NODE:defense:object_access_control",
        "NODE:vulnerability:bola",
        "MITIGATES",
        {
            "predicate": "MITIGATES",
            "epistemic_status": "SOURCE_SUPPORTED",
            "evidence_citations": [
                {
                    "source_id": "SRC-EVAL-ACTIVE",
                    "chunk_id": "CHK-BOLA-REM",
                    "epistemic_status": "SOURCE_SUPPORTED",
                }
            ],
        },
    )

    # Node JWT None Algorithm -> Algorithm Confusion (CONNECTED CONCEPT)
    graph.add_node(
        "NODE:technique:jwt_none",
        "ATTACK_TECHNIQUE",
        "JWT None Algorithm",
        {},
    )
    graph.add_node(
        "NODE:vulnerability:jwt_algorithm_confusion",
        "VULNERABILITY",
        "JWT Algorithm Confusion",
        {
            "evidence_citations": [
                {
                    "source_id": "SRC-EVAL-ACTIVE",
                    "chunk_id": "CHK-JWT-CONF",
                    "epistemic_status": "SOURCE_SUPPORTED",
                }
            ]
        },
    )
    graph.add_edge(
        "NODE:technique:jwt_none",
        "NODE:vulnerability:jwt_algorithm_confusion",
        "RELATED_TO",
        {
            "predicate": "RELATED_TO",
            "epistemic_status": "SOURCE_SUPPORTED",
            "evidence_citations": [
                {
                    "source_id": "SRC-EVAL-ACTIVE",
                    "chunk_id": "CHK-JWT-CONF",
                    "epistemic_status": "SOURCE_SUPPORTED",
                }
            ],
        },
    )

    # Stale edge pointing to deactivated source chunk
    graph.add_node("NODE:stale:legacy", "VULNERABILITY", "Legacy MD5 Password", {})
    graph.add_edge(
        "NODE:stale:legacy",
        "NODE:vulnerability:bola",
        "ASSOCIATED_WITH",
        {
            "predicate": "ASSOCIATED_WITH",
            "epistemic_status": "SOURCE_SUPPORTED",
            "evidence_citations": [
                {
                    "source_id": "SRC-EVAL-DEACTIVATED",
                    "chunk_id": "CHK-STALE-OLD",
                    "epistemic_status": "SOURCE_SUPPORTED",
                }
            ],
        },
    )

    # Inferred edge
    graph.add_node("NODE:inferred:hypothesis", "CONCEPT", "Heuristic Session Binding", {})
    graph.add_edge(
        "NODE:inferred:hypothesis",
        "NODE:vulnerability:bola",
        "HYPOTHESIZED_MITIGATION",
        {
            "predicate": "HYPOTHESIZED_MITIGATION",
            "epistemic_status": "INFERRED",
            "evidence_citations": [
                {
                    "source_id": "SRC-EVAL-ACTIVE",
                    "chunk_id": "CHK-INFERRED-EXP",
                    "epistemic_status": "INFERRED",
                }
            ],
        },
    )

    # Irrelevant noise node
    graph.add_node("NODE:hardware:printer", "HARDWARE", "Laser Printer Setup", {
        "evidence_citations": [
            {"source_id": "SRC-EVAL-ACTIVE", "chunk_id": "CHK-NOISE-PRINTER"}
        ]
    })

    yield {
        "store": store,
        "graph": graph,
        "chunks": {
            "c_bola_def": c_bola_def,
            "c_bola_rem": c_bola_rem,
            "c_jwt_conf": c_jwt_conf,
            "c_stale": c_stale,
            "c_printer": c_printer,
            "c_inferred": c_inferred,
        },
    }

    store.close()
    graph.close()


def test_eval_scenario_1_direct_source_retrieval(eval_corpus):
    """Scenario 1: Direct source retrieval matches target chunk directly."""
    store = eval_corpus["store"]
    graph = eval_corpus["graph"]
    retriever = GraphAssistedRetriever(knowledge_store=store, knowledge_graph=graph)

    # Baseline query against store
    baseline_hits = [c for c, score in store.query_lexical("Broken Object Level Authorization", top_k=5)]
    fused, evidence, meta = retriever.retrieve("Broken Object Level Authorization", baseline_chunks=baseline_hits)

    fused_ids = [c.chunk_id for c in fused]
    assert "CHK-BOLA-DEF" in fused_ids
    assert meta.traversal_successful is True


def test_eval_scenario_2_connected_concept(eval_corpus):
    """Scenario 2: Query mentions concept A; graph connects to related concept B's passage."""
    store = eval_corpus["store"]
    graph = eval_corpus["graph"]
    retriever = GraphAssistedRetriever(knowledge_store=store, knowledge_graph=graph)

    # Query for "JWT None Algorithm" with empty baseline to test graph recall discovery
    baseline_hits = []
    fused, evidence, meta = retriever.retrieve("JWT None Algorithm", baseline_chunks=baseline_hits)

    fused_ids = [c.chunk_id for c in fused]
    # Graph connects "JWT None Algorithm" -> "JWT Algorithm Confusion" -> CHK-JWT-CONF
    assert "CHK-JWT-CONF" in fused_ids
    assert any(e.matched_entity_label == "JWT None Algorithm" for e in evidence)


def test_eval_scenario_3_relationship_to_different_passage(eval_corpus):
    """Scenario 3: Relationship (MITIGATES) navigates from vulnerability to defense passage."""
    store = eval_corpus["store"]
    graph = eval_corpus["graph"]
    retriever = GraphAssistedRetriever(knowledge_store=store, knowledge_graph=graph)

    # Baseline search for BOLA
    baseline_hits = [eval_corpus["chunks"]["c_bola_def"]]
    fused, evidence, meta = retriever.retrieve("Broken Object Level Authorization", baseline_chunks=baseline_hits)

    fused_ids = [c.chunk_id for c in fused]
    # The mitigation passage CHK-BOLA-REM must be retrieved via MITIGATES edge
    assert "CHK-BOLA-REM" in fused_ids
    assert any(e.relation_type == "MITIGATES" for e in evidence)


def test_eval_scenario_4_irrelevant_graph_edges(eval_corpus):
    """Scenario 4: Irrelevant graph edges (noise) do not contaminate query results."""
    store = eval_corpus["store"]
    graph = eval_corpus["graph"]
    retriever = GraphAssistedRetriever(knowledge_store=store, knowledge_graph=graph)

    fused, evidence, meta = retriever.retrieve("Broken Object Level Authorization")
    fused_ids = [c.chunk_id for c in fused]

    # Printer setup chunk must NOT appear in results for BOLA query
    assert "CHK-NOISE-PRINTER" not in fused_ids


def test_eval_scenario_5_stale_source_protection(eval_corpus):
    """Scenario 5: Stale graph edges pointing to deactivated sources are strictly blocked."""
    store = eval_corpus["store"]
    graph = eval_corpus["graph"]
    retriever = GraphAssistedRetriever(knowledge_store=store, knowledge_graph=graph)

    fused, evidence, meta = retriever.retrieve("Broken Object Level Authorization")
    fused_ids = [c.chunk_id for c in fused]

    # Deactivated source chunk must NEVER enter fused results
    assert "CHK-STALE-OLD" not in fused_ids
    assert meta.stale_or_ineligible_skipped >= 1


def test_eval_scenario_6_inferred_relations(eval_corpus):
    """Scenario 6: Inferred relations are preserved as INFERRED and never upgraded to verified."""
    store = eval_corpus["store"]
    graph = eval_corpus["graph"]
    retriever = GraphAssistedRetriever(knowledge_store=store, knowledge_graph=graph, include_inferred=True)

    nodes = [graph.get_node("NODE:inferred:hypothesis")]
    recovered, evidence, meta = retriever.expand_graph_evidence(nodes)

    assert meta.epistemic_breakdown.get("INFERRED", 0) >= 1
    for ev in evidence:
        if ev.matched_entity_id == "NODE:inferred:hypothesis":
            assert ev.epistemic_status == "INFERRED"


def test_eval_scenario_7_empty_or_unavailable_graph(eval_corpus):
    """Scenario 7: When graph is unavailable or empty, retriever falls back to baseline chunks."""
    store = eval_corpus["store"]
    retriever = GraphAssistedRetriever(knowledge_store=store, knowledge_graph=None)

    baseline_chunk = eval_corpus["chunks"]["c_bola_def"]
    fused, evidence, meta = retriever.retrieve("Broken Object Level Authorization", baseline_chunks=[baseline_chunk])

    assert len(fused) == 1
    assert fused[0].chunk_id == "CHK-BOLA-DEF"
    assert meta.error_message == "Graph not configured"
