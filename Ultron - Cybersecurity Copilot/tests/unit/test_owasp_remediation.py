"""
Deterministic remediation tests for OWASP response formatting, query rewriting,
citation integrity, model fallback disclaimers, and bounded offline checks.
"""

import io
from pathlib import Path
from unittest.mock import MagicMock, patch
import pypdf
import pytest

from src.core.logging import AuditLogger
from src.dashboard.service import WorkspaceService
from src.database.manager import DatabaseManager
from src.engine.runner import OllamaRunner
from src.knowledge.ingestion_engine import KnowledgeIngestionEngine
from src.knowledge.knowledge_graph import RelationalKnowledgeGraph
from src.knowledge.canonical_models import AuthorityLevel
from src.knowledge.store import VaptKnowledgeStore
from src.knowledge.sufficiency_engine import (
    KnowledgeSufficiencyEvaluator,
    KnowledgeSufficiencyState,
)
from src.response.merger import ResponseMerger
from src.retrieval.query_rewriter import CybersecurityQueryRewriter


def _build_test_pdf(pages_text: list[str]) -> bytes:
    """Helper generating a standards-compliant multi-page PDF with pypdf."""
    writer = pypdf.PdfWriter()
    for text in pages_text:
        writer.add_blank_page(width=612, height=792)
    stream = io.BytesIO()
    writer.write(stream)
    return stream.getvalue()


# ---------------------------------------------------------------------------
# 1. Query Rewriter Typo Normalization (oswap -> owasp)
# ---------------------------------------------------------------------------

def test_query_rewriter_corrects_oswap_typo():
    """Verify that obvious typo 'oswap' is safely normalized to 'owasp' without corrupting intent."""
    res = CybersecurityQueryRewriter.rewrite_query("tell me about oswap top 10")
    assert "owasp" in res.rewritten_query.lower()
    assert any("Open Web Application Security Project" in t for t in res.expanded_terms)


def test_query_rewriter_preserves_other_security_terms():
    """Verify acronym mapping does not tamper with unrelated queries."""
    res = CybersecurityQueryRewriter.rewrite_query("explain xxe and ssrf")
    assert any("xml external entity" in t.lower() for t in res.expanded_terms)
    assert any("server-side request forgery" in t.lower() for t in res.expanded_terms)


# ---------------------------------------------------------------------------
# 2. Response Merger: Inline Fused Bold List Items Separation & Numbering
# ---------------------------------------------------------------------------

def test_response_merger_separates_fused_numbered_bold_items():
    """
    Test the historical failure pattern: Chunk 1 ends at 'server takeover. Applications using'
    and Chunk 2 starts with '10. **Broken Authentication**'.
    ResponseMerger must cleanly separate item 10 into its own paragraph without fusing.
    """
    malformed_input = (
        "9. **Security Logging and Monitoring Failures**\n"
        "Insufficient logging leads to delayed breach detection and server takeover. Applications using "
        "10. **Broken Authentication**\n"
        "Session fixation and credential stuffing allow unauthorized takeover."
    )

    cleaned = ResponseMerger.deduplicate_response_content(malformed_input)

    # Must cleanly separate item into its own line/paragraph and renumber
    assert "**Broken Authentication**" in cleaned
    assert "\n\n2. **Broken Authentication**" in cleaned or "\n2. **Broken Authentication**" in cleaned
    # Must not have 'Applications using 10. **Broken Authentication**' fused together
    assert "Applications using 10." not in cleaned
    assert "server takeover." in cleaned


def test_response_merger_normalizes_and_renumbers_sequential_lists():
    """
    Test that sequential ordered list items with repeated numbers (e.g. 1. ... 1. ... 1. ...)
    are normalized to consecutive ordered sequence 1, 2, 3...
    """
    repeated_numbering = (
        "Here are the top defensive controls:\n\n"
        "1. **Input Validation**: Sanitize all untrusted inputs.\n\n"
        "1. **Parameterized Queries**: Prevent SQL injection by design.\n\n"
        "1. **Content Security Policy**: Mitigate cross-site scripting impact."
    )

    cleaned = ResponseMerger.deduplicate_response_content(repeated_numbering)
    lines = [line.strip() for line in cleaned.split("\n") if line.strip().startswith(("1.", "2.", "3."))]

    assert len(lines) == 3
    assert lines[0].startswith("1. **Input Validation**")
    assert lines[1].startswith("2. **Parameterized Queries**")
    assert lines[2].startswith("3. **Content Security Policy**")


def test_response_merger_punctuation_continuation_precedence():
    """Verify that a continuation chunk starting with punctuation is appended directly without breaking sentence flow."""
    merger = ResponseMerger()
    accumulated = "Buffer overflow mitigation requires: 1. Stack canaries"
    incoming = ", 2. ASLR (Address Space Layout Randomization)"

    merged, result = merger.merge_chunks(accumulated, incoming)
    assert merged == "Buffer overflow mitigation requires: 1. Stack canaries, 2. ASLR (Address Space Layout Randomization)"
    assert result.overlap_detected is False


# ---------------------------------------------------------------------------
# 3. Knowledge Sufficiency Evaluator Boundaries
# ---------------------------------------------------------------------------

def test_knowledge_sufficiency_empty_corpus_insufficient():
    """Zero retrieved chunks for a cybersecurity query must yield INSUFFICIENT without hallucinated sufficiency."""
    decision = KnowledgeSufficiencyEvaluator.evaluate(
        query="Explain OAuth 2.0 PKCE flow in detail",
        retrieved_chunks=[],
    )
    assert decision.state == KnowledgeSufficiencyState.INSUFFICIENT
    assert decision.can_synthesize_answer is False
    assert "Insufficient local cybersecurity knowledge" in decision.suggested_fallback_message


def test_knowledge_sufficiency_out_of_domain():
    """Out-of-domain queries must yield OUT_OF_DOMAIN without cybersecurity claims."""
    decision = KnowledgeSufficiencyEvaluator.evaluate(
        query="What is the best recipe for baking chocolate cake?",
        retrieved_chunks=[],
    )
    assert decision.state == KnowledgeSufficiencyState.OUT_OF_DOMAIN
    assert decision.can_synthesize_answer is False
    assert "out-of-domain" in decision.suggested_fallback_message.lower()


# ---------------------------------------------------------------------------
# 4. Ollama Availability & Fast-Fail Offline Checks
# ---------------------------------------------------------------------------

def test_ollama_runner_is_available_caching():
    """OllamaRunner.is_available() must cache responsiveness within TTL window to prevent socket storms."""
    runner = OllamaRunner(base_url="http://127.0.0.1:11434")

    with patch("httpx.Client.get") as mock_get:
        mock_get.return_value = MagicMock(status_code=200)

        # First call hits the network
        res1 = runner.is_available()
        assert res1 is True
        assert mock_get.call_count == 1

        # Second rapid call within 3.0s uses cache
        res2 = runner.is_available()
        assert res2 is True
        assert mock_get.call_count == 1


def test_offline_ollama_fails_fast_in_graph_extraction(tmp_path: Path):
    """
    When local Ollama is offline, extract_source_knowledge_graph must fail fast
    without incurring repeated multi-second timeouts per chunk (preventing 138-second delay).
    """
    db_file = tmp_path / "test_app.db"
    k_db_file = tmp_path / "test_knowledge.db"
    g_db_file = tmp_path / "test_graph.db"
    audit_file = tmp_path / "test_audit.log"

    db_mgr = DatabaseManager(db_file)
    auditor = AuditLogger(audit_file)
    k_store = VaptKnowledgeStore(k_db_file)
    k_graph = RelationalKnowledgeGraph(g_db_file)

    service = WorkspaceService(db_manager=db_mgr, audit_logger=auditor)
    service.knowledge_store = k_store
    service.knowledge_ingestion_engine = KnowledgeIngestionEngine(k_store)
    service.knowledge_graph = k_graph

    # Register and index a source via service file ingestion
    ingest_res = service.ingest_knowledge_bytes(
        content_bytes=b"Substantive security content chunk 1.\n\nSubstantive security content chunk 2.\n\nSubstantive security content chunk 3.",
        filename="test_manual.txt",
        title="Test Security Manual",
        authority_level="USER_OWNED",
    )
    source_id = ingest_res["source_id"]

    # Mock Ollama runner as unavailable (offline)
    mock_runner = MagicMock()
    mock_runner.is_available.return_value = False
    service.knowledge_graph_extractor.ollama_runner = mock_runner
    service.knowledge_graph_extractor.llm_caller = None

    # Call graph extraction
    import time
    t0 = time.perf_counter()
    res = service.extract_source_knowledge_graph(source_id=source_id)
    elapsed = time.perf_counter() - t0

    # Must fail fast (under 1.0 second) and report honest offline status
    assert elapsed < 1.0
    assert res["status"] == "FAILED"
    assert res["processed_chunks"] == 0
    assert any("unavailable" in err.lower() for err in res["errors"])


# ---------------------------------------------------------------------------
# 5. Conversational Q&A Model Fallback Disclaimer When Corpus Empty
# ---------------------------------------------------------------------------

def test_conversational_fallback_disclaimer_prepended(tmp_path: Path):
    """
    When a cybersecurity question is issued in Copilot Investigations and the corpus
    has zero verified evidence, the model output MUST be prepended with the explicit
    unmistakable disclaimer:
    '> ⚠️ **General model knowledge — not verified against ingested sources**'
    """
    from src.dashboard.models import CreateInvestigationRequest
    from src.response.models import ResponseStatus, GenerationTermination

    db_file = tmp_path / "conv_app.db"
    k_db_file = tmp_path / "conv_knowledge.db"
    g_db_file = tmp_path / "conv_graph.db"
    audit_file = tmp_path / "conv_audit.log"

    db_mgr = DatabaseManager(db_file)
    auditor = AuditLogger(audit_file)
    k_store = VaptKnowledgeStore(k_db_file)
    k_graph = RelationalKnowledgeGraph(g_db_file)

    service = WorkspaceService(db_manager=db_mgr, audit_logger=auditor)
    service.knowledge_store = k_store
    service.knowledge_ingestion_engine = KnowledgeIngestionEngine(k_store)
    service.knowledge_graph = k_graph

    # Mock Ollama availability
    service.cascade_orchestrator.ollama_client = MagicMock()
    service.cascade_orchestrator.ollama_client.is_available.return_value = True

    # Mock response_engine to simulate local model inference completion
    mock_session = MagicMock()
    mock_session.final_content = (
        "OWASP Top 10 represents standard security risks:\n\n"
        "1. **Broken Access Control**: Enforcement failures on authorization.\n\n"
        "2. **Cryptographic Failures**: Insecure key management or cipher suites."
    )
    mock_session.model = "qwen2.5-coder:7b"
    mock_session.status = ResponseStatus.COMPLETED
    mock_session.termination_reason = GenerationTermination.NATURAL_STOP
    mock_session.response_id = "RESP-TEST-FALLBACK-01"

    service.response_engine.generate_response = MagicMock(return_value=mock_session)

    # Issue cybersecurity question on an investigation with an empty knowledge corpus
    inv = service.create_investigation(
        CreateInvestigationRequest(name="OWASP Research", target_host="api.target.local")
    )
    messages = service.send_message(
        inv_id=inv.id,
        content="tell me about oswap top 10",
    )

    assistant_msg = [m for m in messages if m.sender == "assistant"]
    assert len(assistant_msg) == 1
    content = assistant_msg[0].content

    # Verify disclaimer banner presence
    assert "> ⚠️ **General model knowledge — not verified against ingested sources**" in content
    assert "The local knowledge corpus does not contain sufficient ingested documentation" in content
    # Verify the model explanation is preserved beneath the banner
    assert "Broken Access Control" in content
    assert "Cryptographic Failures" in content
