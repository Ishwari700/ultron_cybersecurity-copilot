"""Unit tests for Candidate 2 Pure SQLite FTS5 Retriever and RRF rank fusion."""

from pathlib import Path
import pytest

from src.knowledge.retriever import (
    RRF_K,
    SqliteFts5KnowledgeRetriever,
    compute_rrf_scores,
)


def test_rrf_scoring_and_tie_breaking():
    """Verify RRF rank calculation, missing rank semantics, and chunk_id ASC tie-break."""
    # sparse ranks: C1 (rank 1), C2 (rank 2)
    # dense ranks: C2 (rank 1), C1 (rank 2)
    sparse_hits = [("CHK-C1", 10.0), ("CHK-C2", 5.0)]
    dense_hits = [("CHK-C2", 0.9), ("CHK-C1", 0.8)]

    # C1 score: 0.5/(60+1) + 0.5/(60+2) = 0.5/61 + 0.5/62
    # C2 score: 0.5/(60+2) + 0.5/(60+1) = 0.5/62 + 0.5/61
    # Scores are numerically equal!
    # Tie-breaking MUST order CHK-C1 before CHK-C2 (chunk_id ASC in ASCII byte order)
    fused = compute_rrf_scores(sparse_hits, dense_hits)
    assert len(fused) == 2
    assert fused[0][0] == "CHK-C1"
    assert fused[1][0] == "CHK-C2"
    assert fused[0][1] == fused[1][1]


def test_rrf_missing_rank_zero_contribution():
    """Verify that absent candidates receive exactly 0.0 contribution."""
    sparse_hits = [("CHK-ONLY-SPARSE", 5.0)]
    dense_hits = [("CHK-ONLY-DENSE", 0.9)]

    fused = compute_rrf_scores(sparse_hits, dense_hits)
    assert len(fused) == 2
    # Both have score 0.5 / (60 + 1) = 0.5 / 61
    assert fused[0][1] == fused[1][1] == 0.5 / (RRF_K + 1)
    # Alphabetical tie break: CHK-ONLY-DENSE before CHK-ONLY-SPARSE
    assert fused[0][0] == "CHK-ONLY-DENSE"
    assert fused[1][0] == "CHK-ONLY-SPARSE"
    assert fused[0][2] is None  # Sparse rank is None
    assert fused[0][3] == 1     # Dense rank is 1
    assert fused[1][2] == 1     # Sparse rank is 1
    assert fused[1][3] is None  # Dense rank is None


def test_candidate2_fts5_retriever_query():
    """Verify Candidate 2 execution against active shipped vapt_knowledge.db."""
    db_path = Path("data/vapt_corpus/vapt_knowledge.db")
    assert db_path.exists(), "vapt_knowledge.db must exist from Block A build"

    retriever = SqliteFts5KnowledgeRetriever(db_path)
    assert retriever.candidate_id == "Candidate 2"
    assert retriever.is_dense is False
    assert retriever.is_sparse is True

    # Query for IDOR authorization
    results = retriever.retrieve(
        query="IDOR parameter substitution horizontal authorization",
        top_k=5,
        query_id="Q-TEST-01",
    )

    assert len(results) > 0
    assert len(results) <= 5
    assert results[0].retrieval_rank == 1
    assert results[0].query_id == "Q-TEST-01"
    assert results[0].sparse_score > 0.0
    assert results[0].fused_score == results[0].sparse_score
    assert results[0].dense_score == 0.0

    # Verify tie-breaking / rank ordering
    for i in range(len(results) - 1):
        assert results[i].retrieval_rank < results[i + 1].retrieval_rank
        # Scores descending
        assert results[i].fused_score >= results[i + 1].fused_score

    meta = retriever.get_provenance_metadata()
    assert meta["candidate_id"] == "Candidate 2"
    assert meta["neural_model"] is None

    retriever.close()
