"""Unit tests for M2 Real Semantic Retrieval Milestone.

Covers all Phase 12 requirements:
- Embedding Backend: determinism, dimension, normalization, empty input, batch consistency
- Vector Index: creation, persistence, content-hash detection, stale detection, model mismatch, dimension mismatch
- Retrieval: MiniLM dense-only, hybrid RRF, RRF fusion logic, provenance preservation, FTS5 fallback
- Evaluation: frozen benchmark loading, evaluability of queries, metric reproducibility
"""

import json
from pathlib import Path
import sqlite3
import numpy as np
import pytest

from src.eval.retrieval_benchmark_evaluator import BenchmarkEvaluationRun
from src.eval.vapt_benchmark_schema import load_vapt_benchmark
from src.knowledge.embedding_backend import MiniLMEmbeddingBackend
from src.knowledge.minilm_retriever import (
    MiniLmDenseOnlyRetriever,
    MiniLmVectorFts5Retriever,
)
from src.knowledge.models import (
    KnowledgeChunk,
    KnowledgeSourceType,
    KnowledgeType,
)
from src.knowledge.retriever import (
    RRF_K,
    RRF_WEIGHT_DENSE,
    RRF_WEIGHT_SPARSE,
    compute_rrf_scores,
)
from src.knowledge.store import VaptKnowledgeStore
from src.knowledge.vector_index import PersistentVectorIndex


@pytest.fixture(scope="module")
def shared_backend():
    return MiniLMEmbeddingBackend()


@pytest.fixture(scope="module")
def production_paths():
    db_path = Path("data/vapt_corpus/vapt_knowledge.db")
    idx_path = Path("data/vapt_corpus/vapt_knowledge_minilm.index")
    assert db_path.exists(), f"Production DB missing at {db_path}"
    assert idx_path.exists(), f"Production index missing at {idx_path}"
    return db_path, idx_path


# ==============================================================================
# EMBEDDING TESTS
# ==============================================================================

class TestMiniLMEmbeddingBackend:
    def test_embedding_determinism(self, shared_backend):
        """Calling embed() multiple times with the same text produces identical vectors."""
        text = "Horizontal privilege escalation in multi-tenant API"
        vec1 = shared_backend.embed(text)
        vec2 = shared_backend.embed(text)

        assert len(vec1) == 384
        assert len(vec2) == 384
        assert np.allclose(vec1, vec2, atol=1e-6), "Embeddings for identical text must be deterministic"

    def test_embedding_dimension(self, shared_backend):
        """Embedding dimension must be exactly 384 for all-MiniLM-L6-v2."""
        assert shared_backend.embedding_dimension == 384
        assert shared_backend.EMBEDDING_DIMENSION == 384
        vec = shared_backend.embed("Test query dimension verification")
        assert len(vec) == 384

    def test_embedding_normalization(self, shared_backend):
        """L2 norm of output embeddings must strictly equal 1.0 within numerical tolerance."""
        sample_texts = [
            "Insecure direct object reference",
            "BFLA testing in microservices",
            "Broken object level authorization with UUIDs",
        ]
        for t in sample_texts:
            vec = shared_backend.embed(t)
            norm = np.linalg.norm(vec)
            assert np.isclose(norm, 1.0, atol=1e-5), f"Vector norm {norm} is not 1.0"

    def test_empty_input(self, shared_backend):
        """Handling empty or whitespace string without throwing an exception."""
        vec_empty = shared_backend.embed("")
        vec_ws = shared_backend.embed("    \t\n  ")
        assert len(vec_empty) == 384
        assert len(vec_ws) == 384
        assert isinstance(vec_empty, list)
        assert isinstance(vec_ws, list)

    def test_batch_consistency(self, shared_backend):
        """embed_batch([t1, t2]) must produce identical vectors to embed(t1) and embed(t2)."""
        texts = [
            "Method and action binding preventing HTTP verb tunneling bypasses",
            "Unauthenticated access gate fail closed default verification",
        ]
        batch_vecs = shared_backend.embed_batch(texts)
        assert len(batch_vecs) == 2

        single_vec0 = shared_backend.embed(texts[0])
        single_vec1 = shared_backend.embed(texts[1])

        assert np.allclose(batch_vecs[0], single_vec0, atol=1e-5), "Batch embedding 0 differs from single embedding"
        assert np.allclose(batch_vecs[1], single_vec1, atol=1e-5), "Batch embedding 1 differs from single embedding"


# ==============================================================================
# VECTOR INDEX TESTS
# ==============================================================================

class TestPersistentVectorIndex:
    @pytest.fixture
    def test_chunks(self):
        return [
            KnowledgeChunk(
                chunk_id="CHK-TEST-001",
                document_id="DOC-TEST-01",
                source_type=KnowledgeSourceType.CWE,
                knowledge_type=KnowledgeType.SECURITY_INVARIANT,
                category_tags=["authorization", "tenant_isolation"],
                title="BOLA Vulnerability Testing",
                section_heading="Overview",
                content="Broken Object Level Authorization occurs when an API fails to validate user tenancy.",
                token_estimate=16,
                content_hash="hash_alpha_111",
                trust_tier="CURATED_ADVISORY",
            ),
            KnowledgeChunk(
                chunk_id="CHK-TEST-002",
                document_id="DOC-TEST-01",
                source_type=KnowledgeSourceType.CWE,
                knowledge_type=KnowledgeType.SECURITY_INVARIANT,
                category_tags=["authorization", "idor"],
                title="IDOR Remediation Patterns",
                section_heading="Mitigation",
                content="Implement server-side session-bound authorization checks before resolving object IDs.",
                token_estimate=14,
                content_hash="hash_beta_222",
                trust_tier="CURATED_ADVISORY",
            ),
        ]

    def test_index_creation(self, tmp_path, test_chunks):
        """Index can be initialized and chunks added."""
        idx_path = tmp_path / "test.index"
        index = PersistentVectorIndex(idx_path)
        assert len(index.entries) == 0

        # Add manual entry
        index.entries["CHK-TEST-001"] = {
            "chunk_id": "CHK-TEST-001",
            "document_id": "DOC-TEST-01",
            "content_hash": "hash_alpha_111",
            "created_at": "2026-10-06T00:00:00Z",
            "vector": [0.1] * 384,
        }
        index.save()
        assert idx_path.exists()
        assert len(index.entries) == 1

    def test_index_persistence(self, tmp_path):
        """Index can be written to disk and accurately reloaded."""
        idx_path = tmp_path / "persisted.index"
        idx1 = PersistentVectorIndex(idx_path)
        test_vec = [float(i) / 384.0 for i in range(384)]
        idx1.entries["CHK-001"] = {
            "chunk_id": "CHK-001",
            "document_id": "DOC-01",
            "content_hash": "abc123hash",
            "created_at": "2026-10-06T12:00:00Z",
            "vector": test_vec,
        }
        idx1.save()

        # Reload in new instance
        idx2 = PersistentVectorIndex(idx_path)
        assert len(idx2.entries) == 1
        assert "CHK-001" in idx2.entries
        assert idx2.entries["CHK-001"]["content_hash"] == "abc123hash"
        assert np.allclose(idx2.entries["CHK-001"]["vector"], test_vec, atol=1e-6)

    def test_content_hash_detection(self, tmp_path):
        """Content hash change is detected as modifying chunk fingerprint."""
        idx_path = tmp_path / "hash_test.index"
        index = PersistentVectorIndex(idx_path)
        index.entries["CHK-001"] = {
            "chunk_id": "CHK-001",
            "content_hash": "hash_version_1",
            "vector": [0.0] * 384,
        }
        assert not index.is_stale("CHK-001", "hash_version_1")
        assert index.is_stale("CHK-001", "hash_version_2")

    def test_stale_embedding_detection(self, tmp_path):
        """is_stale correctly identifies both absent chunks and changed hashes."""
        idx_path = tmp_path / "stale_test.index"
        index = PersistentVectorIndex(idx_path)
        index.entries["CHK-EXISTS"] = {
            "chunk_id": "CHK-EXISTS",
            "content_hash": "current_hash",
            "vector": [0.0] * 384,
        }

        # Absent chunk is stale/missing
        assert index.is_stale("CHK-NONEXISTENT", "any_hash") is True
        # Chunk with identical hash is not stale
        assert index.is_stale("CHK-EXISTS", "current_hash") is False
        # Chunk with updated content hash is stale
        assert index.is_stale("CHK-EXISTS", "modified_new_hash") is True

    def test_model_mismatch_detection(self, tmp_path):
        """Index initialized with mismatched model name returns MODEL_MISMATCH status."""
        idx_path = tmp_path / "mismatch_model.index"
        payload = {
            "schema_version": "2.0.0",
            "embedding_model": "incompatible-bert-base-uncased",
            "embedding_dimension": 384,
            "preprocessing_version": "v1.0.0",
            "entries": {"CHK-01": {"content_hash": "h1", "vector": [0.0]*384}},
        }
        with open(idx_path, "w", encoding="utf-8") as f:
            json.dump(payload, f)

        # Mock store with empty chunk list
        class MockStore:
            def get_all_chunks(self):
                return []

        index = PersistentVectorIndex(idx_path)
        health = index.check_health(MockStore())
        assert health.is_healthy is False
        assert health.status_code == "MODEL_MISMATCH"
        assert "incompatible-bert" in health.message

    def test_dimension_mismatch_detection(self, tmp_path):
        """Index initialized with mismatched dimension returns DIMENSION_MISMATCH status."""
        idx_path = tmp_path / "mismatch_dim.index"
        payload = {
            "schema_version": "2.0.0",
            "embedding_model": "all-MiniLM-L6-v2",
            "embedding_dimension": 768,  # Incompatible with 384
            "preprocessing_version": "v1.0.0",
            "entries": {"CHK-01": {"content_hash": "h1", "vector": [0.0]*768}},
        }
        with open(idx_path, "w", encoding="utf-8") as f:
            json.dump(payload, f)

        class MockStore:
            def get_all_chunks(self):
                return []

        index = PersistentVectorIndex(idx_path)
        health = index.check_health(MockStore())
        assert health.is_healthy is False
        assert health.status_code == "DIMENSION_MISMATCH"
        assert "768" in health.message


# ==============================================================================
# RETRIEVAL TESTS
# ==============================================================================

class TestMiniLMRetrieval:
    def test_minilm_dense_retrieval(self, production_paths):
        """MiniLmDenseOnlyRetriever retrieves relevant chunks based on semantic similarity."""
        db_path, idx_path = production_paths
        retriever = MiniLmDenseOnlyRetriever(db_path=db_path, index_path=idx_path)
        query = "horizontal tenant isolation invariant enforcement across organizations"
        results = retriever.retrieve(query, top_k=5)

        assert len(results) > 0
        assert len(results) <= 5
        top = results[0]
        assert top.chunk.chunk_id.startswith("CHK-")
        assert top.dense_score > 0.0
        assert top.retrieval_rank == 1

    def test_hybrid_retrieval(self, production_paths):
        """MiniLmVectorFts5Retriever executes hybrid search and returns ranked items."""
        db_path, idx_path = production_paths
        retriever = MiniLmVectorFts5Retriever(db_path=db_path, index_path=idx_path)
        query = "insecure direct object reference IDOR vulnerability"
        results = retriever.retrieve(query, top_k=5)

        assert len(results) > 0
        assert len(results) <= 5
        for item in results:
            assert item.fused_score > 0.0
            assert item.retrieval_rank in [1, 2, 3, 4, 5]

    def test_rrf_fusion(self):
        """Verifies Reciprocal Rank Fusion formula and deterministic tie-breaking."""
        sparse_hits = [("CHK-A", 10.0), ("CHK-B", 8.0), ("CHK-C", 5.0)]
        dense_hits = [("CHK-B", 0.9), ("CHK-A", 0.8), ("CHK-D", 0.7)]

        fused = compute_rrf_scores(
            sparse_hits=sparse_hits,
            dense_hits=dense_hits,
            k_rrf=60,
            w_sparse=0.5,
            w_dense=0.5,
        )

        # Expected score for CHK-A:
        # sparse rank = 1 -> 0.5 / (60 + 1) = 0.5 / 61
        # dense rank = 2 -> 0.5 / (60 + 2) = 0.5 / 62
        expected_a = (0.5 / 61.0) + (0.5 / 62.0)

        # Expected score for CHK-B:
        # sparse rank = 2 -> 0.5 / (60 + 2) = 0.5 / 62
        # dense rank = 1 -> 0.5 / (60 + 1) = 0.5 / 61
        expected_b = (0.5 / 62.0) + (0.5 / 61.0)

        assert np.isclose(expected_a, expected_b)
        # Because CHK-A and CHK-B have identical scores, tie-breaking sorts ASCII ascending: CHK-A before CHK-B
        assert fused[0][0] == "CHK-A"
        assert fused[1][0] == "CHK-B"
        assert np.isclose(fused[0][1], expected_a)

    def test_provenance_preservation(self, production_paths):
        """Retrieved items strictly preserve provenance metadata."""
        db_path, idx_path = production_paths
        retriever = MiniLmVectorFts5Retriever(db_path=db_path, index_path=idx_path)
        meta = retriever.get_provenance_metadata()

        assert meta["candidate_id"] == "Candidate 1 (MiniLM)"
        assert meta["neural_model"] == "all-MiniLM-L6-v2"
        assert meta["embedding_dimension"] == 384
        assert meta["rrf_k"] == 60

        results = retriever.retrieve("administrative access control bypass", top_k=3, query_id="VAPT-Q001")
        assert len(results) > 0
        for item in results:
            assert item.query_id == "VAPT-Q001"
            assert item.chunk.chunk_id != ""
            assert item.chunk.document_id != ""
            assert item.chunk.title != ""
            assert item.chunk.trust_tier == "CURATED_ADVISORY"
            assert len(item.chunk.content_hash) == 64  # SHA-256 hash length
            assert item.chunk.source_type is not None
            assert item.chunk.knowledge_type is not None

    def test_fts5_fallback(self, production_paths, monkeypatch):
        """Retriever engages fail-soft FTS5 fallback when embedding backend fails."""
        db_path, idx_path = production_paths
        retriever = MiniLmVectorFts5Retriever(db_path=db_path, index_path=idx_path)

        # Monkeypatch backend.embed to simulate a crash/runtime fault
        def mock_embed_fail(query_text):
            raise RuntimeError("Simulated ONNX runtime hardware fault")

        monkeypatch.setattr(retriever.backend, "embed", mock_embed_fail)

        results = retriever.retrieve("tenant isolation bypass", top_k=5)
        # Must not raise an exception, must return FTS5 results
        assert len(results) > 0
        meta = retriever.get_provenance_metadata()
        assert meta["retrieval_mode"] == "fts5_fallback"
        assert "Simulated ONNX runtime" in meta["fallback_reason"]

        for item in results:
            assert item.dense_score == 0.0
            assert item.sparse_score > 0.0


# ==============================================================================
# EVALUATION TESTS
# ==============================================================================

class TestRetrievalBenchmarkEvaluation:
    def test_frozen_benchmark_loads(self):
        """The frozen Phase 0 benchmark loads all 100 queries with exact schema validity."""
        benchmark = load_vapt_benchmark()
        assert benchmark.schema_version == "1.0.0"
        assert benchmark.total_queries == 100
        assert len(benchmark.queries) == 100

    def test_all_queries_evaluable(self):
        """Evaluator evaluates queries without errors."""
        runner = BenchmarkEvaluationRun()
        db_path = Path("data/vapt_corpus/vapt_knowledge.db")
        idx_path = Path("data/vapt_corpus/vapt_knowledge_minilm.index")
        retriever = MiniLmVectorFts5Retriever(db_path=db_path, index_path=idx_path)

        orig_queries = runner.queries
        try:
            runner.queries = orig_queries[:5]
            report = runner.evaluate_retriever(retriever, config_name="Test-MiniLM", top_k=5)
            agg = report["aggregate_metrics"]
            assert agg["query_count"] == 5
            assert 0.0 <= agg["recall_at_5"] <= 1.0
            assert 0.0 <= agg["mrr_at_5"] <= 1.0
        finally:
            runner.queries = orig_queries

    def test_metrics_reproducible(self):
        """Evaluating the same retriever on identical queries yields reproducible results."""
        runner = BenchmarkEvaluationRun()
        db_path = Path("data/vapt_corpus/vapt_knowledge.db")
        idx_path = Path("data/vapt_corpus/vapt_knowledge_minilm.index")
        retriever = MiniLmVectorFts5Retriever(db_path=db_path, index_path=idx_path)

        orig_queries = runner.queries
        try:
            runner.queries = orig_queries[:5]
            report1 = runner.evaluate_retriever(retriever, config_name="Run1", top_k=5)
            report2 = runner.evaluate_retriever(retriever, config_name="Run2", top_k=5)

            agg1 = report1["aggregate_metrics"]
            agg2 = report2["aggregate_metrics"]

            assert agg1["recall_at_5"] == agg2["recall_at_5"]
            assert agg1["precision_at_5"] == agg2["precision_at_5"]
            assert agg1["mrr_at_5"] == agg2["mrr_at_5"]
            assert agg1["ndcg_at_5"] == agg2["ndcg_at_5"]
        finally:
            runner.queries = orig_queries
