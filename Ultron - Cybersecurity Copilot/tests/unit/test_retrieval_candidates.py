"""Unit tests for Candidate 1 (Local ONNX + FTS5) and Candidate 3 (ChromaDB + FTS5)."""

from pathlib import Path
import pytest

from src.eval.retrieval_qualification import RetrievalQualificationHarness
from src.knowledge.models import QueryRendererId
from src.knowledge.retriever import (
    ChromaFts5Retriever,
    OnnxVectorFts5Retriever,
    SqliteFts5KnowledgeRetriever,
)


def test_candidate1_onnx_hybrid_retriever():
    """Verify Candidate 1 ONNX embedding, FTS5 lexical, and RRF fusion."""
    db_path = Path("data/vapt_corpus/vapt_knowledge.db")
    assert db_path.exists()

    retriever = OnnxVectorFts5Retriever(db_path)
    assert retriever.candidate_id == "Candidate 1"
    assert retriever.is_dense is True
    assert retriever.is_sparse is True

    results = retriever.retrieve(
        query="Method: GET | Route: /api/v1/accounts/{account_id}/profile | Evidence Gap: Missing Cross Identity Object Verification | Invariant: Horizontal tenant object isolation",
        top_k=5,
        query_id="Q-TEST-C1",
    )

    assert len(results) > 0
    assert len(results) <= 5
    assert results[0].retrieval_rank == 1
    assert results[0].query_id == "Q-TEST-C1"
    assert results[0].fused_score > 0.0
    assert results[0].sparse_score is not None
    assert results[0].dense_score is not None

    meta = retriever.get_provenance_metadata()
    assert meta["candidate_id"] == "Candidate 1"
    assert meta["backend_type"] == "local_onnx_fts5"
    assert meta["neural_model"] == "all-MiniLM-L6-v2.onnx"

    retriever.close()


def test_candidate3_chroma_hybrid_retriever():
    """Verify Candidate 3 ChromaDB collection, FTS5 lexical, and RRF fusion."""
    db_path = Path("data/vapt_corpus/vapt_knowledge.db")
    assert db_path.exists()

    retriever = ChromaFts5Retriever(db_path)
    assert retriever.candidate_id == "Candidate 3"
    assert retriever.is_dense is True
    assert retriever.is_sparse is True

    results = retriever.retrieve(
        query="Method: POST | Route: /api/v1/admin/privileges/elevate | Evidence Gap: Missing Role Hierarchy Enforcement | Invariant: Vertical role privilege hierarchy",
        top_k=5,
        query_id="Q-TEST-C3",
    )

    assert len(results) > 0
    assert len(results) <= 5
    assert results[0].retrieval_rank == 1
    assert results[0].query_id == "Q-TEST-C3"
    assert results[0].fused_score > 0.0
    assert results[0].sparse_score is not None
    assert results[0].dense_score is not None

    meta = retriever.get_provenance_metadata()
    assert meta["candidate_id"] == "Candidate 3"
    assert meta["backend_type"] == "chromadb_fts5"
    assert meta["collection_name"] == "vapt_knowledge_m3"

    retriever.close()


def test_candidate1_reproducibility_100_runs():
    """
    Verify Gate 1 reproducibility on Candidate 1:
    100 repeated executions, max drift <= 1e-6, zero ranking instability.
    """
    gold_file = Path("data/eval/retrieval_gold.json")
    db_file = Path("data/vapt_corpus/vapt_knowledge.db")
    harness = RetrievalQualificationHarness(gold_file)
    retriever = OnnxVectorFts5Retriever(db_file)

    passed, max_drift = harness.verify_reproducibility(
        retriever=retriever,
        split_name="QUALIFICATION_SELECTION_SET",
        repetitions=100,
    )
    assert passed is True
    assert max_drift <= 1e-6
    retriever.close()


def test_candidate3_reproducibility_100_runs():
    """
    Verify Gate 1 reproducibility on Candidate 3:
    100 repeated executions, max drift <= 1e-6, zero ranking instability.
    """
    gold_file = Path("data/eval/retrieval_gold.json")
    db_file = Path("data/vapt_corpus/vapt_knowledge.db")
    harness = RetrievalQualificationHarness(gold_file)
    retriever = ChromaFts5Retriever(db_file)

    passed, max_drift = harness.verify_reproducibility(
        retriever=retriever,
        split_name="QUALIFICATION_SELECTION_SET",
        repetitions=100,
    )
    assert passed is True
    assert max_drift <= 1e-6
    retriever.close()


def test_candidates_hard_qualification_evaluation():
    """
    Execute full qualification harness on all 3 candidate backends:
    - Verifies Recall@5, MRR@5, and InjectionHit@P4_256
    - Verifies Candidate 1 and Candidate 3 pass all hard qualification gates
    - Verifies Candidate 1 is canonically selected
    """
    gold_file = Path("data/eval/retrieval_gold.json")
    db_file = Path("data/vapt_corpus/vapt_knowledge.db")
    harness = RetrievalQualificationHarness(gold_file)

    c2 = SqliteFts5KnowledgeRetriever(db_file)
    c1 = OnnxVectorFts5Retriever(db_file)
    c3 = ChromaFts5Retriever(db_file)

    res_c2 = harness.evaluate_split(c2, "QUALIFICATION_SELECTION_SET", QueryRendererId.RENDERER_S)
    res_c1 = harness.evaluate_split(c1, "QUALIFICATION_SELECTION_SET", QueryRendererId.RENDERER_S)
    res_c3 = harness.evaluate_split(c3, "QUALIFICATION_SELECTION_SET", QueryRendererId.RENDERER_S)

    # Check hard gate evaluations
    assert res_c1.hard_gates_passed is True
    assert res_c1.mean_recall_at_5 >= 0.80
    assert res_c1.mean_mrr_at_5 >= 0.60
    assert res_c1.mean_injection_hit >= 0.75

    assert res_c3.hard_gates_passed is True
    assert res_c3.mean_recall_at_5 >= 0.80
    assert res_c3.mean_mrr_at_5 >= 0.60
    assert res_c3.mean_injection_hit >= 0.75

    # Run canonical selection
    selected = RetrievalQualificationHarness.rank_and_select_backend([res_c2, res_c1, res_c3])
    assert selected is not None
    assert selected.candidate_id == "Candidate 1"

    c2.close()
    c1.close()
    c3.close()
