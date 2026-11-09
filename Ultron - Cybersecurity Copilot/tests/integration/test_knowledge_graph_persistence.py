"""Integration tests for Stage C Knowledge Graph Persistence and Application APIs.

Covers:
- Section 7.4: Graph persistence and lifecycle (SQLite store, store reopening persistence,
  idempotency, multi-source evidence preservation, extraction ledger).
- Section 7.5: End-to-end ingestion -> extraction -> graph persistence -> API operation
  (FastAPI endpoints with role authorization and CSRF protection).
"""

import json
from pathlib import Path
from typing import Any, Dict
import pytest
from fastapi.testclient import TestClient

from src.core.logging import AuditLogger
from src.dashboard.app import create_dashboard_app
from src.dashboard.auth import DashboardAuthManager, DashboardRole
from src.dashboard.service import WorkspaceService
from src.database.manager import DatabaseManager
from src.knowledge.canonical_models import AuthorityLevel, CanonicalSourceType
from src.knowledge.graph_extractor import (
    ChunkExtractionPayload,
    ExtractedEntityCandidate,
    ExtractedRelationshipCandidate,
    GraphEpistemicStatus,
    KnowledgeEntityCategory,
    KnowledgeGraphExtractor,
    KnowledgeGraphPredicate,
)
from src.knowledge.ingestion_engine import KnowledgeIngestionEngine
from src.knowledge.knowledge_graph import RelationalKnowledgeGraph
from src.knowledge.models import KnowledgeChunk, KnowledgeSourceType, KnowledgeType
from src.knowledge.store import VaptKnowledgeStore


@pytest.fixture
def test_env(tmp_path: Path):
    """Creates an isolated test environment with databases and services."""
    graph_db_path = tmp_path / "knowledge_graph.db"
    vapt_db_path = tmp_path / "vapt_knowledge.db"
    core_db_path = tmp_path / "core_test.db"
    import_root = tmp_path / "imports"
    import_root.mkdir(parents=True, exist_ok=True)

    # 1. Initialize core DB
    db_mgr = DatabaseManager(db_path=core_db_path)
    db_mgr.initialize_schema()

    # 2. Initialize VAPT store & Knowledge Graph
    vapt_store = VaptKnowledgeStore(db_path=vapt_db_path)
    graph = RelationalKnowledgeGraph(db_path=graph_db_path)

    # 3. Controlled fake model responses for reproducible testing
    def fake_llm_response(prompt: str, schema: Dict[str, Any]) -> str:
        if "Input Validation" in prompt or "Cross-Site Scripting" in prompt:
            return json.dumps({
                "schema_version": "1.0.0",
                "entities": [
                    {
                        "ref_id": "ENT-1",
                        "name": "SQL Injection",  # Shared entity from second source!
                        "category": "VULNERABILITY",
                        "supporting_quote": "SQL injection",
                    },
                    {
                        "ref_id": "ENT-3",
                        "name": "Input Validation",
                        "category": "DEFENSIVE_CONTROL",
                        "supporting_quote": "Input validation mitigates",
                    },
                ],
                "relationships": [
                    {
                        "subject_ref": "ENT-3",
                        "object_ref": "ENT-1",
                        "predicate": "MITIGATES",
                        "supporting_quote": "Input validation mitigates SQL injection",
                        "relationship_basis": "EXPLICIT_TEXT",
                    }
                ],
            })
        elif "Authentication Bypass" in prompt or "SQL injection" in prompt:
            return json.dumps({
                "schema_version": "1.0.0",
                "entities": [
                    {
                        "ref_id": "ENT-1",
                        "name": "SQL Injection",
                        "category": "VULNERABILITY",
                        "description": "SQL injection vulnerability in input handlers",
                        "supporting_quote": "SQL injection allows attackers to bypass authentication",
                    },
                    {
                        "ref_id": "ENT-2",
                        "name": "Authentication Bypass",
                        "category": "ATTACK_TECHNIQUE",
                        "description": "Technique to bypass authentication controls",
                        "supporting_quote": "bypass authentication",
                    },
                ],
                "relationships": [
                    {
                        "subject_ref": "ENT-1",
                        "object_ref": "ENT-2",
                        "predicate": "EXPLOITS",
                        "explanation": "SQLi is leveraged to achieve authentication bypass",
                        "supporting_quote": "SQL injection allows attackers to bypass authentication",
                        "relationship_basis": "EXPLICIT_TEXT",
                    }
                ],
            })
        return json.dumps({"schema_version": "1.0.0", "entities": [], "relationships": []})

    extractor = KnowledgeGraphExtractor(llm_caller=fake_llm_response)

    # 4. Service and Ingestion Engine
    ingestion_engine = KnowledgeIngestionEngine(knowledge_store=vapt_store, import_root=import_root)
    auditor = AuditLogger(core_db_path.parent / "audit.log")
    workspace_service = WorkspaceService(db_manager=db_mgr, audit_logger=auditor)
    workspace_service.knowledge_store = vapt_store
    workspace_service.knowledge_ingestion_engine = ingestion_engine
    workspace_service.knowledge_graph = graph
    workspace_service.knowledge_graph_extractor = extractor

    auth_mgr = DashboardAuthManager(core_db_path)
    app = create_dashboard_app(
        workspace_service=workspace_service,
        auth_manager=auth_mgr,
        audit_logger=auditor,
        db_manager=db_mgr,
    )

    client = TestClient(app)

    # Create users
    op_token = auth_mgr.create_session("alice_op", DashboardRole.OPERATOR).token
    obs_token = auth_mgr.create_session("bob_obs", DashboardRole.OBSERVER).token

    return {
        "graph": graph,
        "vapt_store": vapt_store,
        "extractor": extractor,
        "service": workspace_service,
        "client": client,
        "op_token": op_token,
        "obs_token": obs_token,
        "graph_db_path": graph_db_path,
        "import_root": import_root,
    }


def _create_and_ingest_source(env: Dict[str, Any], source_id: str, title: str, text: str):
    """Helper to ingest a knowledge source text into the VAPT store."""
    service: WorkspaceService = env["service"]
    return service.ingest_knowledge_bytes(
        content_bytes=text.encode("utf-8"),
        filename=f"{source_id}.md",
        title=title,
        authority_level="RESEARCH_COMMUNITY",
    )


# ===========================================================================
# 7.4 Graph Persistence and Lifecycle Tests
# ===========================================================================

def test_graph_persistence_and_store_reopening(test_env: Dict[str, Any]):
    """Extracted nodes, edges, and provenance persist across SQLite database reopening."""
    graph: RelationalKnowledgeGraph = test_env["graph"]
    db_path: Path = test_env["graph_db_path"]

    chunk = KnowledgeChunk(
        schema_version="3.0.0",
        chunk_id="CHK-PERSIST-001",
        document_id="DOC-SRC-P1",
        source_type=KnowledgeSourceType.OWASP_WSTG,
        knowledge_type=KnowledgeType.VULNERABILITY_PATTERN,
        category_tags=["page:15"],
        title="SQL Injection Guide",
        section_heading="Page 15 - SQL Injection",
        content="SQL injection allows attackers to bypass authentication by tampering with query parameters.",
        token_estimate=15,
        content_hash="h1",
        trust_tier="USER_VERIFIED",
    )

    extractor: KnowledgeGraphExtractor = test_env["extractor"]
    result = extractor.extract_from_chunk(chunk=chunk, source_id="SRC-P1")

    assert result.status == "SUCCESS"
    assert len(result.entities) == 2
    assert len(result.relationships) == 1

    # Persist into graph
    persist_res = graph.persist_chunk_extraction(result)
    assert persist_res["status"] == "SUCCESS"
    assert persist_res["entities_persisted"] == 2
    assert persist_res["edges_persisted"] == 1

    # Verify directly from first graph handle
    node = graph.get_node("NODE:vulnerability:sql_injection")
    assert node is not None
    assert node["label"] == "SQL Injection"
    assert len(node["metadata"]["evidence_citations"]) == 1

    # Close and reopen graph database connection
    graph.close()
    reopened_graph = RelationalKnowledgeGraph(db_path=db_path)

    reopened_node = reopened_graph.get_node("NODE:vulnerability:sql_injection")
    assert reopened_node is not None
    assert reopened_node["label"] == "SQL Injection"
    citation = reopened_node["metadata"]["evidence_citations"][0]
    assert citation["chunk_id"] == "CHK-PERSIST-001"
    assert citation["source_id"] == "SRC-P1"
    assert citation["page_number"] == 15

    # Check edges in reopened store
    edges = reopened_graph.get_all_edges()
    assert len(edges) == 1
    assert edges[0]["relation_type"] == "EXPLOITS"
    assert edges[0]["metadata"]["epistemic_status"] == "SOURCE_SUPPORTED"

    reopened_graph.close()


def test_idempotent_reprocessing(test_env: Dict[str, Any]):
    """Reprocessing the same chunk under the same version is idempotent and does not duplicate edges."""
    graph: RelationalKnowledgeGraph = test_env["graph"]

    chunk = KnowledgeChunk(
        schema_version="3.0.0",
        chunk_id="CHK-IDEMPOTENT-001",
        document_id="DOC-SRC-I1",
        source_type=KnowledgeSourceType.OWASP_WSTG,
        knowledge_type=KnowledgeType.VULNERABILITY_PATTERN,
        category_tags=["page:5"],
        title="SQL Injection Guide",
        section_heading="Page 5",
        content="SQL injection allows attackers to bypass authentication.",
        token_estimate=10,
        content_hash="h1",
        trust_tier="USER_VERIFIED",
    )

    extractor: KnowledgeGraphExtractor = test_env["extractor"]
    result = extractor.extract_from_chunk(chunk=chunk, source_id="SRC-I1")

    # First persistence
    graph.persist_chunk_extraction(result)
    stats1 = graph.get_graph_stats()

    # Second persistence (identical chunk and extraction result)
    graph.persist_chunk_extraction(result)
    stats2 = graph.get_graph_stats()

    assert stats1["total_nodes"] == stats2["total_nodes"]
    assert stats1["total_edges"] == stats2["total_edges"]
    assert stats1["total_extractions"] == stats2["total_extractions"]

    # Verify citation list on node has not duplicated
    node = graph.get_node("NODE:vulnerability:sql_injection")
    assert len(node["metadata"]["evidence_citations"]) == 1


def test_multi_source_evidence_lineage_preservation(test_env: Dict[str, Any]):
    """Multiple sources referencing the same entity preserve distinct citations without overwriting."""
    graph: RelationalKnowledgeGraph = test_env["graph"]
    extractor: KnowledgeGraphExtractor = test_env["extractor"]

    # Source 1 chunk: SQL injection allows attackers to bypass authentication
    chunk1 = KnowledgeChunk(
        schema_version="3.0.0",
        chunk_id="CHK-SRC1-001",
        document_id="DOC-SRC1",
        source_type=KnowledgeSourceType.OWASP_WSTG,
        knowledge_type=KnowledgeType.VULNERABILITY_PATTERN,
        category_tags=["page:10"],
        title="Source 1",
        section_heading="Page 10",
        content="SQL injection allows attackers to bypass authentication.",
        token_estimate=10,
        content_hash="h1",
        trust_tier="USER_VERIFIED",
    )
    res1 = extractor.extract_from_chunk(chunk=chunk1, source_id="SRC-1")
    graph.persist_chunk_extraction(res1)

    # Source 2 chunk: Mentions SQL injection and input validation
    chunk2 = KnowledgeChunk(
        schema_version="3.0.0",
        chunk_id="CHK-SRC2-001",
        document_id="DOC-SRC2",
        source_type=KnowledgeSourceType.OWASP_ASVS,
        knowledge_type=KnowledgeType.VULNERABILITY_PATTERN,
        category_tags=["page:88"],
        title="Source 2",
        section_heading="Page 88",
        content="Cross-Site Scripting and SQL injection. Input validation mitigates SQL injection.",
        token_estimate=12,
        content_hash="h2",
        trust_tier="USER_VERIFIED",
    )
    res2 = extractor.extract_from_chunk(chunk=chunk2, source_id="SRC-2")
    graph.persist_chunk_extraction(res2)

    # Check shared node "NODE:vulnerability:sql_injection"
    node = graph.get_node("NODE:vulnerability:sql_injection")
    assert node is not None
    citations = node["metadata"]["evidence_citations"]

    # Invariant: Must contain provenance for BOTH sources!
    assert len(citations) == 2
    c_sources = {c["source_id"] for c in citations}
    assert "SRC-1" in c_sources
    assert "SRC-2" in c_sources

    # Check total edges (EXPLOITS from SRC-1, MITIGATES from SRC-2)
    edges = graph.get_all_edges()
    assert len(edges) == 2
    predicates = {e["relation_type"] for e in edges}
    assert "EXPLOITS" in predicates
    assert "MITIGATES" in predicates


# ===========================================================================
# 7.5 API Authorization and Operable Workflow Tests
# ===========================================================================

def test_extract_graph_api_unauthenticated_fails_closed(test_env: Dict[str, Any]):
    """Unauthenticated requests to extract-graph are rejected with 401."""
    client: TestClient = test_env["client"]
    res = client.post("/api/knowledge/sources/SRC-TEST/extract-graph")
    assert res.status_code == 401


def test_extract_graph_api_observer_role_rejected(test_env: Dict[str, Any]):
    """Observer role cannot trigger graph extraction; requires Operator (403)."""
    client: TestClient = test_env["client"]
    obs_headers = {"Authorization": f"Bearer {test_env['obs_token']}"}
    res = client.post(
        "/api/knowledge/sources/SRC-TEST/extract-graph",
        headers=obs_headers,
    )
    assert res.status_code == 403


def test_extract_graph_api_nonexistent_source_404(test_env: Dict[str, Any]):
    """Triggering extraction on a nonexistent source returns 404."""
    client: TestClient = test_env["client"]
    op_headers = {"Authorization": f"Bearer {test_env['op_token']}"}
    res = client.post(
        "/api/knowledge/sources/SRC-NONEXISTENT/extract-graph",
        headers=op_headers,
    )
    assert res.status_code == 404
    assert "not found" in res.json()["detail"].lower()


def test_end_to_end_source_ingestion_and_graph_extraction(test_env: Dict[str, Any]):
    """End-to-end integration: Ingest source text -> extract graph via API -> verify graph in SQLite."""
    client: TestClient = test_env["client"]
    op_headers = {"Authorization": f"Bearer {test_env['op_token']}"}
    obs_headers = {"Authorization": f"Bearer {test_env['obs_token']}"}
    graph: RelationalKnowledgeGraph = test_env["graph"]

    # 1. Ingest document text via API as Operator
    ingest_payload = {
        "content": "# SQL Injection Vulnerabilities\n\nSQL injection allows attackers to bypass authentication by altering database query logic.",
        "filename": "sqli_manual.md",
        "title": "SQL Injection Technical Manual",
        "authority_level": "RESEARCH_COMMUNITY",
        "tags": ["vulnerability", "sqli"],
    }
    ingest_res = client.post(
        "/api/knowledge/sources/ingest-text",
        json=ingest_payload,
        headers=op_headers,
    )
    assert ingest_res.status_code == 200
    source_data = ingest_res.json()
    source_id = source_data["source_id"]
    assert source_data["status"] == "INDEXED"

    # 2. Trigger graph extraction via API
    extract_res = client.post(
        f"/api/knowledge/sources/{source_id}/extract-graph",
        headers=op_headers,
    )
    assert extract_res.status_code == 200
    ext_data = extract_res.json()
    assert ext_data["status"] == "COMPLETED"
    assert ext_data["processed_chunks"] >= 1
    assert ext_data["entities_persisted"] == 2
    assert ext_data["edges_persisted"] == 1
    assert ext_data["source_supported_count"] == 1

    # 3. Fetch source graph status via API as Observer
    status_res = client.get(
        f"/api/knowledge/sources/{source_id}/graph-status",
        headers=obs_headers,
    )
    assert status_res.status_code == 200
    status_data = status_res.json()
    assert status_data["source_id"] == source_id
    assert status_data["extractions_count"] >= 1
    assert status_data["total_entities"] == 2
    assert status_data["total_edges"] == 1

    # 4. Fetch global graph metrics via API
    metrics_res = client.get(
        "/api/knowledge/graph/stats",
        headers=obs_headers,
    )
    assert metrics_res.status_code == 200
    metrics_data = metrics_res.json()
    assert metrics_data["total_nodes"] == 2
    assert metrics_data["total_edges"] == 1
    assert metrics_data["source_supported_edges"] == 1

    # 5. Direct verification of backing SQLite database records
    nodes = graph.get_all_nodes()
    assert len(nodes) == 2
    edges = graph.get_all_edges()
    assert len(edges) == 1
    assert edges[0]["relation_type"] == "EXPLOITS"
    assert edges[0]["metadata"]["epistemic_status"] == "SOURCE_SUPPORTED"
