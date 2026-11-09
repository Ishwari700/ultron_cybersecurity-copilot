"""Hybrid Memory Retrieval Engine.

Executes hybrid sparse (SQLite FTS5 BM25) and dense (MiniLM) semantic retrieval
combined via Reciprocal Rank Fusion (RRF), with strict pre-ranking namespace
and assessment isolation.
"""

from datetime import datetime, timezone
import time
from typing import Any, Dict, List, Optional
import numpy as np

from src.knowledge.embedding_backend import MiniLMEmbeddingBackend
from src.memory.enums import EpistemicStatus, MemoryAuthority, MemoryNamespace
from src.memory.errors import AssessmentIsolationViolationError, MemoryAccessDeniedError
from src.memory.isolation import MemoryIsolationEngine
from src.memory.metrics import GLOBAL_MEMORY_TELEMETRY
from src.memory.models import (
    MemoryAccessContext,
    MemoryItem,
    MemoryRetrievalItem,
    MemoryRetrievalResult,
)
from src.memory.persistence import MemoryPersistence
from src.memory.ranking import MemoryRanker


class HybridMemoryRetriever:
    """
    Orchestrates hybrid retrieval for the research memory subsystem.
    """

    def __init__(
        self,
        persistence: MemoryPersistence,
        embedding_backend: Optional[MiniLMEmbeddingBackend] = None,
        rrf_k: int = 60,
        bm25_weight: float = 0.5,
        dense_weight: float = 0.5,
    ) -> None:
        self.persistence = persistence
        self.embedding_backend = embedding_backend or MiniLMEmbeddingBackend()
        self.ranker = MemoryRanker()
        self.rrf_k = rrf_k
        self.bm25_weight = bm25_weight
        self.dense_weight = dense_weight

    def retrieve(
        self,
        query: str,
        context: MemoryAccessContext,
        top_k: int = 5,
        include_superseded: bool = False,
        exact_identifier: Optional[str] = None,
    ) -> MemoryRetrievalResult:
        """
        Executes hybrid memory retrieval under mandatory security context.
        Enforces tenant and assessment isolation BEFORE candidate ranking.
        """
        start_time = time.perf_counter()

        # 1. Validate Context & Pre-Ranking Query Filter
        MemoryIsolationEngine.validate_access_context(context)
        filter_meta = MemoryIsolationEngine.build_query_filter_sql(context)
        where_clause = filter_meta["where_clause"]
        params = filter_meta["params"]

        if not include_superseded:
            where_clause += " AND superseded_by IS NULL"

        # Load authorized candidate pool from SQLite
        candidate_pool = self.persistence.list_items(where_clause=where_clause, params=params)

        # Apply in-memory defense-in-depth isolation filter
        authorized_pool = MemoryIsolationEngine.filter_authorized_candidates(context, candidate_pool)
        authorized_map = {item.memory_id: item for item in authorized_pool}

        if not authorized_map:
            latency = (time.perf_counter() - start_time) * 1000.0
            GLOBAL_MEMORY_TELEMETRY.record_retrieval(0, latency)
            return MemoryRetrievalResult(
                query=query,
                access_context=context,
                items=[],
                total_found=0,
                retrieval_latency_ms=round(latency, 2),
                explanation="No authorized memory items found for access context.",
            )

        # 2. Sparse Lexical Search via SQLite FTS5
        sparse_hits = self.persistence.search_fts5(query, limit=top_k * 4)
        sparse_ranks: Dict[str, int] = {}
        for rank, hit in enumerate(sparse_hits, start=1):
            mem_id = hit["memory_id"]
            if mem_id in authorized_map:
                sparse_ranks[mem_id] = rank

        # 3. Dense Semantic Search via MiniLM Embeddings
        dense_ranks: Dict[str, int] = {}
        dense_similarities: Dict[str, float] = {}
        try:
            query_vec = np.array(self.embedding_backend.embed(query), dtype=np.float32)
            all_embeddings = self.persistence.get_all_embeddings()

            candidate_scores: List[tuple[str, float]] = []
            for mem_id in authorized_map:
                if mem_id in all_embeddings:
                    cand_vec = np.array(all_embeddings[mem_id], dtype=np.float32)
                    sim = float(np.dot(query_vec, cand_vec))
                    candidate_scores.append((mem_id, sim))
                    dense_similarities[mem_id] = sim

            candidate_scores.sort(key=lambda x: x[1], reverse=True)
            for rank, (mem_id, _) in enumerate(candidate_scores[:top_k * 4], start=1):
                dense_ranks[mem_id] = rank
        except Exception:
            # Fallback to sparse-only if embedding backend is unavailable
            pass

        # 4. Reciprocal Rank Fusion (RRF)
        # Score(d) = sum( weight / (rrf_k + rank) )
        combined_scores: Dict[str, float] = {}
        candidate_rationales: Dict[str, str] = {}
        candidate_methods: Dict[str, str] = {}

        all_candidate_ids = set(sparse_ranks.keys()).union(set(dense_ranks.keys()))
        for mem_id in all_candidate_ids:
            score = 0.0
            methods = []
            if mem_id in sparse_ranks:
                score += self.bm25_weight / (self.rrf_k + sparse_ranks[mem_id])
                methods.append("fts5")
            if mem_id in dense_ranks:
                score += self.dense_weight / (self.rrf_k + dense_ranks[mem_id])
                methods.append("dense")

            combined_scores[mem_id] = score
            candidate_methods[mem_id] = "+".join(methods)
            candidate_rationales[mem_id] = f"Matched via {candidate_methods[mem_id]} (RRF score: {score:.4f})"

        # If neither search found hits, fall back to recent authorized items with baseline score
        if not combined_scores:
            for item in authorized_pool[:top_k]:
                combined_scores[item.memory_id] = 0.10
                candidate_methods[item.memory_id] = "recent_fallback"
                candidate_rationales[item.memory_id] = "Recent authorized assessment memory"

        # 5. Build Scored Candidates for Ranker
        scored_candidates: List[Dict[str, Any]] = [
            {
                "item": authorized_map[mem_id],
                "relevance": combined_scores[mem_id],
                "method": candidate_methods.get(mem_id, "hybrid"),
                "rationale": candidate_rationales.get(mem_id, "Relevant research memory"),
            }
            for mem_id in combined_scores
            if mem_id in authorized_map
        ]

        # 6. Authority, Freshness, and Context Budgeting Ranking
        ranked_items = self.ranker.rank_candidates(
            scored_candidates=scored_candidates,
            top_k=top_k,
        )

        latency = (time.perf_counter() - start_time) * 1000.0
        GLOBAL_MEMORY_TELEMETRY.record_retrieval(len(ranked_items), latency)

        return MemoryRetrievalResult(
            query=query,
            access_context=context,
            items=ranked_items,
            total_found=len(ranked_items),
            retrieval_latency_ms=round(latency, 2),
            explanation=f"Retrieved {len(ranked_items)} authorized memory items using hybrid RRF in {latency:.2f}ms.",
        )
