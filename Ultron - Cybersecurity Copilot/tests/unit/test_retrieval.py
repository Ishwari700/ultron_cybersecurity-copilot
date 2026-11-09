"""Unit tests for Hybrid Retrieval, Token Budgeting, and the Exact-Token Gate."""

from pathlib import Path
from src.database.manager import DatabaseManager
from src.retrieval.budget import TokenBudgetController
from src.retrieval.hybrid import HybridRetriever
from src.retrieval.vector_store import LocalVectorStore


def test_token_budget_controller():
    """Verify TokenBudgetController accurately computes remaining budget and crops chunks."""
    controller = TokenBudgetController(chars_per_token=4.0)

    system_prompt = "You are a security reasoning assistant." # ~40 chars -> ~10 tokens
    schema = "{" + '"decision": "HYPOTHESIS"' + "}" # ~25 chars -> ~6 tokens
    num_ctx = 2048

    budget = controller.calculate_evidence_budget(
        num_ctx=num_ctx,
        system_prompt=system_prompt,
        schema_definition=schema,
        max_output_tokens=500,
        safety_headroom_tokens=100,
    )
    assert budget > 1400

    # Test cropping chunks to budget
    chunks = [
        {"statement": "A" * 400}, # ~100 tokens
        {"statement": "B" * 400}, # ~100 tokens
        {"statement": "C" * 400}, # ~100 tokens
    ]
    # Restrict budget to ~250 tokens -> only first 2 should be included
    cropped = controller.crop_chunks_to_budget(chunks, token_budget=250)
    assert len(cropped) == 2
    assert cropped[0]["statement"].startswith("A")
    assert cropped[1]["statement"].startswith("B")


def test_hybrid_retrieval_and_exact_parameter_gate(tmp_path: Path):
    """Verify hybrid RRF scoring and the exact parameter gate blocking semantically-similar-but-wrong tokens."""
    db_file = tmp_path / "retrieval_test.db"
    db_manager = DatabaseManager(db_path=db_file)
    db_manager.initialize_schema()

    vector_store = LocalVectorStore()

    # Populate documents into database and vector store
    doc1 = {
        "fact_id": "FACT-01",
        "certainty": "OBSERVED",
        "statement": "Endpoint requires HTTP header X-API-Key for client authentication",
        "source_tool": "burp",
        "trust": "UNTRUSTED",
    }
    doc2 = {
        "fact_id": "FACT-02",
        "certainty": "DOCUMENTED",
        "statement": "Admin interface validates signature header X-Signature-Key against HMAC secret",
        "source_tool": "openapi",
        "trust": "UNTRUSTED",
    }

    db_manager.insert_evidence_item(doc1)
    db_manager.insert_evidence_item(doc2)

    vector_store.add_document("FACT-01", doc1["statement"])
    vector_store.add_document("FACT-02", doc2["statement"])

    retriever = HybridRetriever(
        db_manager=db_manager,
        vector_store=vector_store,
        exact_parameter_gate=True,
    )

    # 1. Standard hybrid query for signature
    results = retriever.retrieve("signature validation", k=2)
    assert len(results) >= 1
    assert results[0]["fact_id"] == "FACT-02"

    # 2. Exact Parameter Gate: query for a non-existent parameter "X-OAuth-Token"
    # Even though X-API-Key is semantically similar, the exact gate MUST block it!
    empty_results = retriever.retrieve(
        query="API token header",
        exact_identifier="X-OAuth-Token",
        k=2,
    )
    assert len(empty_results) == 0

    # 3. Exact Parameter Gate: query for real parameter "X-Signature-Key"
    valid_results = retriever.retrieve(
        query="signature header",
        exact_identifier="X-Signature-Key",
        k=2,
    )
    assert len(valid_results) == 1
    assert valid_results[0]["fact_id"] == "FACT-02"
