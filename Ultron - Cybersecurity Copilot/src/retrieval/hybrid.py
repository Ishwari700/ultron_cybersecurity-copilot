"""Hybrid sparse (SQLite FTS5 BM25) and dense vector retrieval with RRF and exact-token gate."""

from typing import Any, Dict, List, Optional
from src.database.manager import DatabaseManager
from src.retrieval.vector_store import LocalVectorStore


class HybridRetriever:
    """
    Combines dense semantic vector search with sparse SQLite FTS5 (BM25) search.
    Applies Reciprocal Rank Fusion (RRF) and enforces the hard exact-parameter gate.
    """

    def __init__(
        self,
        db_manager: DatabaseManager,
        vector_store: LocalVectorStore,
        rrf_k: int = 60,
        vector_weight: float = 0.5,
        bm25_weight: float = 0.5,
        exact_parameter_gate: bool = True,
    ) -> None:
        self.db_manager = db_manager
        self.vector_store = vector_store
        self.rrf_k = rrf_k
        self.vector_weight = vector_weight
        self.bm25_weight = bm25_weight
        self.exact_parameter_gate = exact_parameter_gate

    def retrieve(
        self,
        query: str,
        k: int = 5,
        exact_identifier: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Execute hybrid retrieval combining dense and sparse results via RRF.
        If exact_identifier is provided (e.g. 'X-Signature-Key') and has 0 BM25 hits,
        the exact parameter gate blocks dense false-substitutions.
        """
        # 1. Sparse BM25 search via SQLite FTS5
        bm25_query = f'"{exact_identifier}"' if exact_identifier else query
        sparse_hits: List[Dict[str, Any]] = []
        try:
            sparse_hits = self.db_manager.query_fts(bm25_query, limit=k * 2)
        except Exception:
            # If FTS query has syntax error, retry clean words
            clean_q = "".join(c for c in bm25_query if c.isalnum() or c.isspace())
            if clean_q.strip():
                try:
                    sparse_hits = self.db_manager.query_fts(clean_q.strip(), limit=k * 2)
                except Exception:
                    sparse_hits = []

        # 2. Hard Exact Parameter Gate: If looking for an exact parameter/token and BM25 returns 0,
        # DO NOT allow dense RAG to backfill with semantically similar but wrong token.
        if exact_identifier and self.exact_parameter_gate:
            if not sparse_hits:
                return [] # Blocked by exact parameter gate

        # 3. Dense search via Vector Store
        dense_hits = self.vector_store.query(query, k=k * 2)
        if exact_identifier and self.exact_parameter_gate:
            dense_hits = [d for d in dense_hits if exact_identifier.lower() in d["text"].lower()]

        # 4. Reciprocal Rank Fusion (RRF)
        # Score(d) = sum( weight / (k + rank) )
        doc_scores: Dict[str, float] = {}
        doc_data: Dict[str, Dict[str, Any]] = {}

        # Process Sparse Ranks
        for rank, hit in enumerate(sparse_hits, start=1):
            doc_id = hit["fact_id"]
            score = self.bm25_weight / (self.rrf_k + rank)
            doc_scores[doc_id] = doc_scores.get(doc_id, 0.0) + score
            doc_data[doc_id] = {
                "fact_id": doc_id,
                "statement": hit["statement"],
                "source_tool": hit["source_tool"],
                "sparse_rank": rank,
            }

        # Process Dense Ranks
        for rank, hit in enumerate(dense_hits, start=1):
            doc_id = hit["id"]
            score = self.vector_weight / (self.rrf_k + rank)
            doc_scores[doc_id] = doc_scores.get(doc_id, 0.0) + score
            if doc_id not in doc_data:
                doc_data[doc_id] = {
                    "fact_id": doc_id,
                    "statement": hit["text"],
                    "source_tool": hit.get("metadata", {}).get("source_tool", "vector"),
                }
            doc_data[doc_id]["dense_rank"] = rank

        # Sort by merged RRF score descending
        sorted_ids = sorted(doc_scores.keys(), key=lambda x: doc_scores[x], reverse=True)
        results: List[Dict[str, Any]] = []

        for doc_id in sorted_ids[:k]:
            item = doc_data[doc_id]
            item["rrf_score"] = round(doc_scores[doc_id], 6)
            results.append(item)

        return results
