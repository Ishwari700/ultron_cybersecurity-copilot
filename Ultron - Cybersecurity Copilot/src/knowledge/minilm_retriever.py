"""Real Local Semantic Retrieval Engine using all-MiniLM-L6-v2 + SQLite FTS5.

Milestone M2: Real Semantic Retrieval
- Candidate 1 (MiniLM): Real local ONNX dense vector search + SQLite FTS5 sparse
- Reciprocal Rank Fusion (RRF) with k=60, w_sparse=0.5, w_dense=0.5
- Fail-soft fallback to FTS5 with explicit forensic metadata if MiniLM is unavailable
- Deterministic chunk_id ASC tie-breaking
- Dense-only evaluation candidate for pure semantic ablation testing
"""

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from src.knowledge.embedding_backend import MiniLMEmbeddingBackend
from src.knowledge.models import KnowledgeRetrievalItem
from src.knowledge.retriever import (
    BaseKnowledgeRetriever,
    RRF_K,
    RRF_WEIGHT_DENSE,
    RRF_WEIGHT_SPARSE,
    compute_rrf_scores,
)
from src.knowledge.store import VaptKnowledgeStore
from src.knowledge.vector_index import PersistentVectorIndex

logger = logging.getLogger("m2.retriever")


class MiniLmVectorFts5Retriever(BaseKnowledgeRetriever):
    """
    Candidate 1 (MiniLM): Hybrid Real Semantic Vector + SQLite FTS5.

    Combines 384-dimensional all-MiniLM-L6-v2 dense neural embeddings
    with SQLite FTS5 lexical BM25 matching via Reciprocal Rank Fusion (RRF).
    Features fail-soft fallback to pure FTS5 lexical ranking upon any backend fault.
    """

    candidate_id: str = "Candidate 1 (MiniLM)"
    candidate_name: str = "Local all-MiniLM-L6-v2 ONNX + SQLite FTS5"
    is_dense: bool = True
    is_sparse: bool = True

    def __init__(
        self,
        db_path: Path,
        index_path: Optional[Path] = None,
        embedding_backend: Optional[MiniLMEmbeddingBackend] = None,
        force_index_rebuild: bool = False,
    ) -> None:
        self.db_path = Path(db_path)
        self.store = VaptKnowledgeStore(self.db_path, read_only=True)
        self.index_path = (
            Path(index_path)
            if index_path
            else self.db_path.parent / "vapt_knowledge_minilm.index"
        )
        self.backend = embedding_backend or MiniLMEmbeddingBackend()

        # Initialize and synchronize persistent vector index
        self.index = PersistentVectorIndex(self.index_path, self.backend)
        health = self.index.check_health(self.store)
        if not health.is_healthy or force_index_rebuild:
            logger.info(f"Synchronizing vector index ({health.status_code}): {health.message}")
            self.index.build_or_update(self.store, force_rebuild=force_index_rebuild)

        # Operational mode and fallback tracking
        self._current_mode: str = "hybrid"
        self._fallback_reason: Optional[str] = None

    def retrieve(
        self,
        query: str,
        top_k: int = 5,
        theta_min: float = 0.0,
        query_id: str = "",
    ) -> List[KnowledgeRetrievalItem]:
        """
        Execute hybrid sparse (FTS5) + dense (MiniLM) retrieval fused via RRF.
        Fails soft to pure FTS5 if dense channel fails.
        """
        candidate_depth = max(20, top_k * 4)

        # 1. Sparse Channel (SQLite FTS5 BM25)
        sparse_hits_raw = self.store.query_lexical(query, top_k=candidate_depth)
        sparse_hits = [(c.chunk_id, score) for c, score in sparse_hits_raw]
        sparse_score_map = {c.chunk_id: score for c, score in sparse_hits_raw}

        # 2. Dense Channel (all-MiniLM-L6-v2 ONNX) with Fail-Soft Protection
        dense_hits: List[Tuple[str, float]] = []
        dense_score_map: Dict[str, float] = {}
        dense_successful = False

        if self.backend.is_available:
            try:
                q_vec = self.backend.embed(query)
                dense_hits = self.index.search_dense(q_vec, top_k=candidate_depth)
                dense_score_map = {cid: score for cid, score in dense_hits}
                dense_successful = True
                self._current_mode = "hybrid"
                self._fallback_reason = None
            except Exception as e:
                logger.warning(f"Dense retrieval failure for query '{query}': {e}. Engaging fail-soft FTS5 fallback.")
                self._current_mode = "fts5_fallback"
                self._fallback_reason = str(e)
        else:
            self._current_mode = "fts5_fallback"
            self._fallback_reason = "MiniLM embedding backend is not available"

        # 3. Fusion & Ranking
        results: List[KnowledgeRetrievalItem] = []

        if dense_successful:
            # Full RRF Fusion
            fused = compute_rrf_scores(
                sparse_hits=sparse_hits,
                dense_hits=dense_hits,
                k_rrf=RRF_K,
                w_sparse=RRF_WEIGHT_SPARSE,
                w_dense=RRF_WEIGHT_DENSE,
            )
            rank = 1
            for cid, rrf_score, _s_rank, _d_rank in fused:
                if rrf_score < theta_min:
                    continue
                chunk = self.store.get_chunk(cid)
                if not chunk:
                    continue

                item = KnowledgeRetrievalItem(
                    chunk=chunk,
                    dense_score=float(dense_score_map.get(cid, 0.0)),
                    sparse_score=float(sparse_score_map.get(cid, 0.0)),
                    fused_score=float(rrf_score),
                    retrieval_rank=rank,
                    query_id=query_id,
                )
                results.append(item)
                rank += 1
                if len(results) >= top_k:
                    break
        else:
            # Fail-Soft Fallback to pure FTS5 lexical ranking
            rank = 1
            for chunk, score in sparse_hits_raw:
                if score < theta_min:
                    continue
                item = KnowledgeRetrievalItem(
                    chunk=chunk,
                    dense_score=0.0,
                    sparse_score=float(score),
                    fused_score=float(score),
                    retrieval_rank=rank,
                    query_id=query_id,
                )
                results.append(item)
                rank += 1
                if len(results) >= top_k:
                    break

        return results

    def get_provenance_metadata(self) -> Dict[str, Any]:
        """Return runtime configuration metadata for forensic audit logging."""
        return {
            "candidate_id": self.candidate_id,
            "candidate_name": self.candidate_name,
            "backend_type": "local_minilm_onnx_fts5",
            "retrieval_mode": self._current_mode,
            "fallback_reason": self._fallback_reason,
            "db_path": str(self.db_path),
            "index_path": str(self.index_path),
            "neural_model": self.backend.MODEL_NAME,
            "model_version": self.backend.MODEL_VERSION,
            "embedding_dimension": self.backend.EMBEDDING_DIMENSION,
            "device": self.backend.device,
            "rrf_k": RRF_K,
            "w_sparse": RRF_WEIGHT_SPARSE,
            "w_dense": RRF_WEIGHT_DENSE,
        }

    def close(self) -> None:
        self.store.close()


class MiniLmDenseOnlyRetriever(BaseKnowledgeRetriever):
    """
    Pure Semantic Dense Retriever (Configuration C: MiniLM Dense Only).

    Evaluates retrieval performance of the all-MiniLM-L6-v2 vector channel
    without lexical FTS5 interpolation.
    """

    candidate_id: str = "Configuration C: MiniLM Dense Only"
    candidate_name: str = "Pure Local all-MiniLM-L6-v2 ONNX Vector Search"
    is_dense: bool = True
    is_sparse: bool = False

    def __init__(
        self,
        db_path: Path,
        index_path: Optional[Path] = None,
        embedding_backend: Optional[MiniLMEmbeddingBackend] = None,
    ) -> None:
        self.db_path = Path(db_path)
        self.store = VaptKnowledgeStore(self.db_path, read_only=True)
        self.index_path = (
            Path(index_path)
            if index_path
            else self.db_path.parent / "vapt_knowledge_minilm.index"
        )
        self.backend = embedding_backend or MiniLMEmbeddingBackend()
        self.index = PersistentVectorIndex(self.index_path, self.backend)

    def retrieve(
        self,
        query: str,
        top_k: int = 5,
        theta_min: float = 0.0,
        query_id: str = "",
    ) -> List[KnowledgeRetrievalItem]:
        q_vec = self.backend.embed(query)
        dense_hits = self.index.search_dense(q_vec, top_k=max(20, top_k * 4))

        results: List[KnowledgeRetrievalItem] = []
        rank = 1
        for cid, score in dense_hits:
            if score < theta_min:
                continue
            chunk = self.store.get_chunk(cid)
            if not chunk:
                continue

            item = KnowledgeRetrievalItem(
                chunk=chunk,
                dense_score=float(score),
                sparse_score=0.0,
                fused_score=float(score),
                retrieval_rank=rank,
                query_id=query_id,
            )
            results.append(item)
            rank += 1
            if len(results) >= top_k:
                break

        return results

    def get_provenance_metadata(self) -> Dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "candidate_name": self.candidate_name,
            "backend_type": "minilm_dense_only",
            "embedding_model": self.backend.MODEL_NAME,
            "embedding_dimension": self.backend.EMBEDDING_DIMENSION,
            "device": self.backend.device,
        }

    def close(self) -> None:
        self.store.close()
