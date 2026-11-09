"""Live Local-AI Knowledge Graph Extraction Smoke Test (Milestone M9 Stage C).

Runs genuine local Ollama inference against 'qwen2.5-coder:7b' (or 'qwen2.5-coder:3b')
if Ollama is live on http://127.0.0.1:11434.
Skips gracefully if local Ollama daemon is offline or model is uninstalled.
"""

from pathlib import Path
import pytest

from src.engine.runner import OllamaRunner
from src.knowledge.graph_extractor import KnowledgeGraphExtractor
from src.knowledge.knowledge_graph import RelationalKnowledgeGraph
from src.knowledge.models import KnowledgeChunk, KnowledgeSourceType, KnowledgeType


def test_live_ollama_knowledge_graph_extraction(tmp_path: Path):
    """Executes live local-model extraction on an ingested chunk and verifies SQLite persistence."""
    runner = OllamaRunner(model_name="qwen2.5-coder:7b", timeout_seconds=120.0)
    if not runner.is_available():
        pytest.skip("Local Ollama daemon is not running on http://127.0.0.1:11434")

    installed_models = [m.get("name", "") for m in runner.list_models()]
    target_model = "qwen2.5-coder:7b"
    if target_model not in installed_models and "qwen2.5-coder:7b" not in [m.split(":")[0] for m in installed_models]:
        if "qwen2.5-coder:3b" in installed_models:
            target_model = "qwen2.5-coder:3b"
        else:
            pytest.skip(f"Neither qwen2.5-coder:7b nor qwen2.5-coder:3b installed in Ollama. Found: {installed_models}")

    runner.model_name = target_model

    # Bounded real-world cybersecurity text passage
    content = (
        "SQL injection (SQLi) is a critical vulnerability where an attacker manipulates database queries. "
        "Parameterized queries and prepared statements mitigate SQL injection by separating code from user-supplied data. "
        "SQL injection maps to CWE-89 in the Common Weakness Enumeration."
    )
    chunk = KnowledgeChunk(
        schema_version="3.0.0",
        chunk_id="CHK-LIVE-SMOKE-001",
        document_id="DOC-OWASP-SQLI",
        source_type=KnowledgeSourceType.OWASP_WSTG,
        knowledge_type=KnowledgeType.VULNERABILITY_PATTERN,
        category_tags=["page:25", "format:pdf"],
        title="OWASP Testing Guide - SQLi",
        section_heading="Page 25 - SQL Injection Testing",
        content=content,
        token_estimate=len(content.split()),
        content_hash="live_hash_smoke_001",
        trust_tier="USER_VERIFIED",
    )

    extractor = KnowledgeGraphExtractor(ollama_runner=runner, default_model=target_model)
    result = extractor.extract_from_chunk(chunk=chunk, source_id="SRC-OWASP-SQLI", model_name=target_model)

    assert result.status == "SUCCESS", f"Extraction failed: {result.error_message}"
    assert len(result.entities) >= 1
    assert len(result.relationships) >= 1
    assert result.page_number == 25
    assert result.chunk_id == "CHK-LIVE-SMOKE-001"

    # Persist into isolated SQLite graph
    graph_db = tmp_path / "smoke_graph.db"
    graph = RelationalKnowledgeGraph(db_path=graph_db)
    persist_res = graph.persist_chunk_extraction(result)

    assert persist_res["status"] == "SUCCESS"
    assert persist_res["entities_persisted"] == len(result.entities)
    assert persist_res["edges_persisted"] == len(result.relationships)

    nodes = graph.get_all_nodes()
    assert len(nodes) == len(result.entities)
    sample_node = nodes[0]
    citation = sample_node["metadata"]["evidence_citations"][0]
    assert citation["chunk_id"] == "CHK-LIVE-SMOKE-001"
    assert citation["source_id"] == "SRC-OWASP-SQLI"
    assert citation["page_number"] == 25

    graph.close()
