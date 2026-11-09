"""Benchmark Evaluation Engine for VAPT Retrieval Milestone M2.

Computes:
- Recall@5, Recall@10
- Precision@5, Precision@10
- MRR@5
- nDCG@5, nDCG@10
- Latency statistics (mean, p50, p95)
- Category-level / slice breakdowns
- Negative control precision audit
"""

import math
import statistics
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from src.eval.vapt_benchmark_schema import (
    DifficultyLevel,
    VaptRetrievalBenchmarkDataset,
    VaptRetrievalQuery,
    load_vapt_benchmark,
)
from src.knowledge.retriever import BaseKnowledgeRetriever


def compute_dcg(relevances: List[int], k: int) -> float:
    """Compute Discounted Cumulative Gain at rank k."""
    dcg = 0.0
    for i, rel in enumerate(relevances[:k], start=1):
        # 2^rel - 1 gain formulation
        gain = (2 ** rel) - 1.0
        discount = math.log2(i + 1.0)
        dcg += gain / discount
    return dcg


def compute_ndcg(retrieved_relevances: List[int], ideal_relevances: List[int], k: int) -> float:
    """Compute normalized Discounted Cumulative Gain at rank k."""
    dcg = compute_dcg(retrieved_relevances, k)
    idcg = compute_dcg(sorted(ideal_relevances, reverse=True), k)
    if idcg <= 0.0:
        return 0.0
    return dcg / idcg


class BenchmarkEvaluationRun:
    """Executes frozen Phase 0 benchmark evaluation across any retriever."""

    def __init__(
        self,
        benchmark_path: Path = Path("tests/evaluation/vapt_retrieval_queries.json"),
    ) -> None:
        self.benchmark_dataset = load_vapt_benchmark(benchmark_path)
        self.queries = self.benchmark_dataset.queries

    def evaluate_retriever(
        self,
        retriever: BaseKnowledgeRetriever,
        config_name: str,
        top_k: int = 10,
    ) -> Dict[str, Any]:
        """
        Evaluate retriever on all 100 frozen queries.
        Returns aggregate metrics, latency stats, slice breakdowns, and per-query logs.
        """
        recalls_at_5: List[float] = []
        recalls_at_10: List[float] = []
        precisions_at_5: List[float] = []
        precisions_at_10: List[float] = []
        mrrs_at_5: List[float] = []
        ndcgs_at_5: List[float] = []
        ndcgs_at_10: List[float] = []
        latencies_ms: List[float] = []

        query_records: List[Dict[str, Any]] = []

        total_start = time.perf_counter()

        for q in self.queries:
            t0 = time.perf_counter()
            retrieved_items = retriever.retrieve(
                query=q.query,
                top_k=top_k,
                query_id=q.query_id,
            )
            t1 = time.perf_counter()
            lat_ms = (t1 - t0) * 1000.0
            latencies_ms.append(lat_ms)

            retrieved_cids = [item.chunk.chunk_id for item in retrieved_items]
            
            # Ground-truth relevance ratings
            # Binary relevance threshold: rel >= 2 (Highly Relevant or Related/Useful)
            all_ideal_ratings = list(q.relevance_ratings.values())
            total_relevant = sum(1 for score in all_ideal_ratings if score >= 2)

            retrieved_ratings_10 = [q.relevance_ratings.get(cid, 0) for cid in retrieved_cids[:10]]
            retrieved_ratings_5 = retrieved_ratings_10[:5]

            # Precision & Recall @ 5
            rel_in_5 = sum(1 for r in retrieved_ratings_5 if r >= 2)
            p_at_5 = rel_in_5 / 5.0
            r_at_5 = (rel_in_5 / total_relevant) if total_relevant > 0 else 0.0

            # Precision & Recall @ 10
            rel_in_10 = sum(1 for r in retrieved_ratings_10 if r >= 2)
            p_at_10 = rel_in_10 / 10.0
            r_at_10 = (rel_in_10 / total_relevant) if total_relevant > 0 else 0.0

            # MRR @ 5: first rank where rel >= 2 (or rel == 3)
            mrr_at_5 = 0.0
            for rank_idx, r in enumerate(retrieved_ratings_5, start=1):
                if r >= 2:
                    mrr_at_5 = 1.0 / rank_idx
                    break

            # nDCG @ 5 & @ 10
            ndcg_at_5 = compute_ndcg(retrieved_ratings_5, all_ideal_ratings, 5)
            ndcg_at_10 = compute_ndcg(retrieved_ratings_10, all_ideal_ratings, 10)

            recalls_at_5.append(r_at_5)
            recalls_at_10.append(r_at_10)
            precisions_at_5.append(p_at_5)
            precisions_at_10.append(p_at_10)
            mrrs_at_5.append(mrr_at_5)
            ndcgs_at_5.append(ndcg_at_5)
            ndcgs_at_10.append(ndcg_at_10)

            query_records.append({
                "query_id": q.query_id,
                "query": q.query,
                "security_domain": q.security_domain,
                "difficulty": q.difficulty.value,
                "is_negative_control": q.is_negative_control,
                "is_security_invariant": q.is_security_invariant,
                "is_evidence_gap": q.is_evidence_gap,
                "is_experiment": q.is_experiment,
                "is_adversarial_or_paraphrased": q.is_adversarial_or_paraphrased,
                "retrieved_chunk_ids": retrieved_cids,
                "retrieved_ratings": retrieved_ratings_10,
                "recall_at_5": r_at_5,
                "recall_at_10": r_at_10,
                "precision_at_5": p_at_5,
                "precision_at_10": p_at_10,
                "mrr_at_5": mrr_at_5,
                "ndcg_at_5": ndcg_at_5,
                "ndcg_at_10": ndcg_at_10,
                "latency_ms": lat_ms,
            })

        total_time_s = time.perf_counter() - total_start

        # Sort latencies for percentiles
        sorted_lats = sorted(latencies_ms)
        p50_lat = statistics.median(sorted_lats)
        p95_idx = int(0.95 * len(sorted_lats))
        p95_lat = sorted_lats[p95_idx]

        aggregate_metrics = {
            "config_name": config_name,
            "query_count": len(self.queries),
            "recall_at_5": round(statistics.mean(recalls_at_5), 4),
            "recall_at_10": round(statistics.mean(recalls_at_10), 4),
            "precision_at_5": round(statistics.mean(precisions_at_5), 4),
            "precision_at_10": round(statistics.mean(precisions_at_10), 4),
            "mrr_at_5": round(statistics.mean(mrrs_at_5), 4),
            "ndcg_at_5": round(statistics.mean(ndcgs_at_5), 4),
            "ndcg_at_10": round(statistics.mean(ndcgs_at_10), 4),
            "mean_latency_ms": round(statistics.mean(latencies_ms), 3),
            "p50_latency_ms": round(p50_lat, 3),
            "p95_latency_ms": round(p95_lat, 3),
            "total_evaluation_time_s": round(total_time_s, 3),
        }

        # Compute slice breakdowns
        slices = {
            "by_difficulty": self._slice_metrics(query_records, lambda rec: rec["difficulty"]),
            "by_security_domain": self._slice_metrics(query_records, lambda rec: rec["security_domain"]),
            "negative_controls": self._slice_metrics(query_records, lambda rec: "NEGATIVE_CONTROL" if rec["is_negative_control"] else "OTHER"),
            "security_invariants": self._slice_metrics(query_records, lambda rec: "INVARIANT" if rec["is_security_invariant"] else "OTHER"),
            "evidence_gaps": self._slice_metrics(query_records, lambda rec: "EVIDENCE_GAP" if rec["is_evidence_gap"] else "OTHER"),
            "experiments": self._slice_metrics(query_records, lambda rec: "EXPERIMENT" if rec["is_experiment"] else "OTHER"),
            "paraphrased": self._slice_metrics(query_records, lambda rec: "PARAPHRASED" if rec["is_adversarial_or_paraphrased"] else "CANONICAL"),
        }

        return {
            "aggregate_metrics": aggregate_metrics,
            "slices": slices,
            "query_records": query_records,
        }

    def _slice_metrics(
        self,
        records: List[Dict[str, Any]],
        group_fn: Callable[[Dict[str, Any]], str],
    ) -> Dict[str, Dict[str, Any]]:
        groups: Dict[str, List[Dict[str, Any]]] = {}
        for r in records:
            key = group_fn(r)
            groups.setdefault(key, []).append(r)

        result: Dict[str, Dict[str, Any]] = {}
        for grp_name, grp_records in groups.items():
            result[grp_name] = {
                "count": len(grp_records),
                "recall_at_5": round(statistics.mean([r["recall_at_5"] for r in grp_records]), 4),
                "recall_at_10": round(statistics.mean([r["recall_at_10"] for r in grp_records]), 4),
                "precision_at_5": round(statistics.mean([r["precision_at_5"] for r in grp_records]), 4),
                "precision_at_10": round(statistics.mean([r["precision_at_10"] for r in grp_records]), 4),
                "mrr_at_5": round(statistics.mean([r["mrr_at_5"] for r in grp_records]), 4),
                "ndcg_at_5": round(statistics.mean([r["ndcg_at_5"] for r in grp_records]), 4),
                "ndcg_at_10": round(statistics.mean([r["ndcg_at_10"] for r in grp_records]), 4),
                "mean_latency_ms": round(statistics.mean([r["latency_ms"] for r in grp_records]), 3),
            }
        return result
