"""Standalone Retrieval Qualification Harness & Canonical Backend Selection.

Implements M3.8 & M3.9 per M3 Plan v2.3.8 Sections 11, 13, and 19:
- Fixture parity verification against VaptQueryBuilder
- Query-level Recall@5, MRR@5, and InjectionHit@P4_256 point estimates
- 100-run hard reproducibility qualification gate (drift <= 1e-6)
- Macro-averaged renderer selection on VAL (Renderer S vs Renderer N)
- Canonical backend selection rule:
    Recall@5 -> MRR@5 -> Latency -> Footprint -> candidate_id ASC
"""

import hashlib
import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from src.eval.p4_capacity_oracle import CanonicalP4CapacityOracle
from src.evidence.cascade_models import LosslessStructuralPack
from src.knowledge.models import EvidenceGapType, KnowledgeRetrievalItem, QueryRendererId
from src.knowledge.query_builder import VaptQueryBuilder
from src.knowledge.retriever import BaseKnowledgeRetriever

logger = logging.getLogger("m3.eval.qualification")


class QualificationResult:
    """Encapsulates empirical qualification results for a retrieval backend."""

    def __init__(
        self,
        candidate_id: str,
        candidate_name: str,
        split_name: str,
        renderer_id: QueryRendererId,
        query_count: int,
        mean_recall_at_5: float,
        mean_mrr_at_5: float,
        mean_injection_hit: float,
        mean_latency_ms: float,
        reproducibility_passed: bool,
        max_score_drift: float,
        hard_gates_passed: bool,
        gate_details: Dict[str, Any],
    ) -> None:
        self.candidate_id = candidate_id
        self.candidate_name = candidate_name
        self.split_name = split_name
        self.renderer_id = renderer_id
        self.query_count = query_count
        self.mean_recall_at_5 = mean_recall_at_5
        self.mean_mrr_at_5 = mean_mrr_at_5
        self.mean_injection_hit = mean_injection_hit
        self.mean_latency_ms = mean_latency_ms
        self.reproducibility_passed = reproducibility_passed
        self.max_score_drift = max_score_drift
        self.hard_gates_passed = hard_gates_passed
        self.gate_details = gate_details

    def to_dict(self) -> Dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "candidate_name": self.candidate_name,
            "split_name": self.split_name,
            "renderer_id": self.renderer_id.value,
            "query_count": self.query_count,
            "mean_recall_at_5": round(self.mean_recall_at_5, 6),
            "mean_mrr_at_5": round(self.mean_mrr_at_5, 6),
            "mean_injection_hit": round(self.mean_injection_hit, 6),
            "mean_latency_ms": round(self.mean_latency_ms, 3),
            "reproducibility_passed": self.reproducibility_passed,
            "max_score_drift": self.max_score_drift,
            "hard_gates_passed": self.hard_gates_passed,
            "gate_details": self.gate_details,
        }


class RetrievalQualificationHarness:
    """Standalone benchmark harness enforcing the 4 frozen qualification gates."""

    RECALL_GATE: float = 0.80
    MRR_GATE: float = 0.60
    INJECTION_HIT_GATE: float = 0.75
    DRIFT_TOLERANCE: float = 1e-6

    def __init__(
        self,
        gold_dataset_path: Path,
        p4_oracle: Optional[CanonicalP4CapacityOracle] = None,
    ) -> None:
        self.gold_path = Path(gold_dataset_path)
        self.p4_oracle = p4_oracle or CanonicalP4CapacityOracle()
        self._load_fixtures()

    def _load_fixtures(self) -> None:
        """Load and index gold evaluation fixtures."""
        if not self.gold_path.exists():
            raise FileNotFoundError(f"Retrieval gold dataset not found at {self.gold_path}")

        with open(self.gold_path, "r", encoding="utf-8") as f:
            records = json.load(f)

        self.records_by_split: Dict[str, List[Dict[str, Any]]] = {
            "DEV": [],
            "VAL": [],
            "QUALIFICATION_SELECTION_SET": [],
        }
        for rec in records:
            split = rec.get("split")
            if split in self.records_by_split:
                self.records_by_split[split].append(rec)

    def evaluate_split(
        self,
        retriever: BaseKnowledgeRetriever,
        split_name: str,
        renderer_id: QueryRendererId = QueryRendererId.RENDERER_S,
        theta_min: float = 0.0,
    ) -> QualificationResult:
        """
        Evaluate candidate retriever across a specified gold split.
        
        Enforces Section 13.5 Harness Parity Rule:
        1. Invokes VaptQueryBuilder.build_query(pack, gap_type, renderer_id)
        2. Asserts exact byte parity with stored expected_rendered_query
        3. Submits query and scores top-5 results
        """
        fixtures = self.records_by_split.get(split_name, [])
        if not fixtures:
            raise ValueError(f"No fixtures found for split '{split_name}'")

        recalls: List[float] = []
        mrrs: List[float] = []
        hits: List[float] = []
        latencies: List[float] = []

        for fixture in fixtures:
            # 1. Reconstruct canonical structural pack
            pack = LosslessStructuralPack(
                asset_id=f"ASSET-{fixture['query_id']}",
                endpoint_id=f"EP-{fixture['query_id']}",
                route_template=fixture["route_template"],
                http_method=fixture["http_method"],
                application_mutability="READ_ONLY" if fixture["http_method"] == "GET" else "STATE_CHANGING",
                has_cross_identity_object_access_success=fixture["has_cross_identity_object_access_success"],
                has_privilege_level_delta=fixture["has_privilege_level_delta"],
            )
            gap_type = EvidenceGapType(fixture["evidence_gap_type"])

            # 2. Harness Parity Rule: execute VaptQueryBuilder
            rendered_query = VaptQueryBuilder.build_query(pack, gap_type, renderer_id)
            expected_query = fixture["expected_rendered_query"][renderer_id.value]
            if rendered_query != expected_query:
                raise AssertionError(
                    f"Query builder parity violation for {fixture['query_id']}:\n"
                    f"Produced: {rendered_query}\nExpected: {expected_query}"
                )

            # 3. Retrieve with latency tracking
            t_start = time.perf_counter()
            retrieved = retriever.retrieve(
                query=rendered_query,
                top_k=5,
                theta_min=theta_min,
                query_id=fixture["query_id"],
            )
            t_elapsed_ms = (time.perf_counter() - t_start) * 1000.0
            latencies.append(t_elapsed_ms)

            # 4. Score metrics
            gold_ids = set(fixture["acceptable_chunk_ids"])
            retrieved_ids = [item.chunk.chunk_id for item in retrieved]

            # Query-level Recall@5
            matched = set(retrieved_ids) & gold_ids
            q_recall = len(matched) / len(gold_ids) if gold_ids else 0.0
            recalls.append(q_recall)

            # Query-level MRR@5
            q_mrr = 0.0
            for rank, cid in enumerate(retrieved_ids, start=1):
                if cid in gold_ids:
                    q_mrr = 1.0 / rank
                    break
            mrrs.append(q_mrr)

            # Query-level InjectionHit@P4_256
            q_hit = 1.0 if self.p4_oracle.is_injection_hit(retrieved, list(gold_ids), token_budget=256) else 0.0
            hits.append(q_hit)

        mean_recall = sum(recalls) / len(recalls)
        mean_mrr = sum(mrrs) / len(mrrs)
        mean_hit = sum(hits) / len(hits)
        mean_latency = sum(latencies) / len(latencies)

        # Evaluate Hard Gates
        gate_details = {
            "recall_pass": mean_recall >= self.RECALL_GATE,
            "mrr_pass": mean_mrr >= self.MRR_GATE,
            "injection_hit_pass": mean_hit >= self.INJECTION_HIT_GATE,
            "latency_target_met": mean_latency <= 100.0,
        }
        gates_passed = (
            gate_details["recall_pass"]
            and gate_details["mrr_pass"]
            and gate_details["injection_hit_pass"]
        )

        return QualificationResult(
            candidate_id=retriever.candidate_id,
            candidate_name=retriever.candidate_name,
            split_name=split_name,
            renderer_id=renderer_id,
            query_count=len(fixtures),
            mean_recall_at_5=mean_recall,
            mean_mrr_at_5=mean_mrr,
            mean_injection_hit=mean_hit,
            mean_latency_ms=mean_latency,
            reproducibility_passed=True,  # Evaluated separately via verify_reproducibility
            max_score_drift=0.0,
            hard_gates_passed=gates_passed,
            gate_details=gate_details,
        )

    def verify_reproducibility(
        self,
        retriever: BaseKnowledgeRetriever,
        split_name: str = "QUALIFICATION_SELECTION_SET",
        renderer_id: QueryRendererId = QueryRendererId.RENDERER_S,
        repetitions: int = 100,
    ) -> Tuple[bool, float]:
        """
        Execute Section 11.5 Gate 1: 100 repeated runs under fixed configuration.
        
        Asserts:
        - 100% top-k chunk ID set identity
        - 100% rank-order identity
        - Maximum score drift <= 1e-6 (exempt for purely lexical candidate if no score drift)
        """
        fixtures = self.records_by_split.get(split_name, [])
        if not fixtures:
            return False, 1.0

        # Run reference baseline (run 0)
        baseline_results: List[List[Tuple[str, float]]] = []
        for fixture in fixtures:
            rendered = fixture["expected_rendered_query"][renderer_id.value]
            hits = retriever.retrieve(rendered, top_k=5, query_id=fixture["query_id"])
            baseline_results.append([(item.chunk.chunk_id, item.fused_score) for item in hits])

        max_drift = 0.0

        # Execute repeated runs
        for rep in range(1, repetitions):
            for q_idx, fixture in enumerate(fixtures):
                rendered = fixture["expected_rendered_query"][renderer_id.value]
                current_hits = retriever.retrieve(rendered, top_k=5, query_id=fixture["query_id"])
                current_items = [(item.chunk.chunk_id, item.fused_score) for item in current_hits]
                baseline_items = baseline_results[q_idx]

                # Check rank count identity
                if len(current_items) != len(baseline_items):
                    return False, 1.0

                for rank_idx, (b_cid, b_score) in enumerate(baseline_items):
                    c_cid, c_score = current_items[rank_idx]
                    # 100% rank order & ID identity
                    if c_cid != b_cid:
                        return False, 1.0
                    # Check numerical drift
                    drift = abs(c_score - b_score)
                    if drift > max_drift:
                        max_drift = drift
                    if drift > self.DRIFT_TOLERANCE:
                        return False, drift

        return True, max_drift

    @classmethod
    def select_global_production_renderer(
        cls,
        eval_matrix: Dict[QueryRendererId, Dict[str, QualificationResult]],
    ) -> Tuple[QueryRendererId, Dict[QueryRendererId, float]]:
        """
        Select single global production query renderer per Section 13.4.
        
        Rule on VAL split:
        Macro-InjectionHit(r) = (1 / |B|) * sum_b (InjectionHit(b, r))
        Tie-break: Macro-Recall@5 -> Macro-MRR@5 -> RENDERER_S before RENDERER_N.
        """
        scores: Dict[QueryRendererId, float] = {}
        recalls: Dict[QueryRendererId, float] = {}
        mrrs: Dict[QueryRendererId, float] = {}

        for r_id in [QueryRendererId.RENDERER_S, QueryRendererId.RENDERER_N]:
            r_results = eval_matrix.get(r_id, {})
            if not r_results:
                scores[r_id] = 0.0
                continue
            num_b = len(r_results)
            scores[r_id] = sum(res.mean_injection_hit for res in r_results.values()) / num_b
            recalls[r_id] = sum(res.mean_recall_at_5 for res in r_results.values()) / num_b
            mrrs[r_id] = sum(res.mean_mrr_at_5 for res in r_results.values()) / num_b

        # Selection logic
        hit_s = scores.get(QueryRendererId.RENDERER_S, 0.0)
        hit_n = scores.get(QueryRendererId.RENDERER_N, 0.0)

        if abs(hit_s - hit_n) > 1e-6:
            selected = QueryRendererId.RENDERER_S if hit_s > hit_n else QueryRendererId.RENDERER_N
        else:
            # First tie break: Macro-Recall@5
            rec_s = recalls.get(QueryRendererId.RENDERER_S, 0.0)
            rec_n = recalls.get(QueryRendererId.RENDERER_N, 0.0)
            if abs(rec_s - rec_n) > 1e-6:
                selected = QueryRendererId.RENDERER_S if rec_s > rec_n else QueryRendererId.RENDERER_N
            else:
                # Second tie break: Macro-MRR@5
                mrr_s = mrrs.get(QueryRendererId.RENDERER_S, 0.0)
                mrr_n = mrrs.get(QueryRendererId.RENDERER_N, 0.0)
                if abs(mrr_s - mrr_n) > 1e-6:
                    selected = QueryRendererId.RENDERER_S if mrr_s > mrr_n else QueryRendererId.RENDERER_N
                else:
                    # Final deterministic tie-break: RENDERER_S before RENDERER_N
                    selected = QueryRendererId.RENDERER_S

        return selected, scores

    @classmethod
    def rank_and_select_backend(
        cls,
        qualified_results: List[QualificationResult],
    ) -> Optional[QualificationResult]:
        """
        Execute Section 11.5 Canonical Backend Selection Rule:
        Only candidates passing ALL 4 hard gates are ranked:
        1. Highest Recall@5
        2. Highest MRR@5
        3. Lowest mean latency (ms)
        4. Lowest dependency footprint
        5. Stable deterministic candidate_id ASC (Candidate 1 before Candidate 2 before Candidate 3)
        """
        eligible = [res for res in qualified_results if res.hard_gates_passed and res.reproducibility_passed]
        if not eligible:
            return None

        # Dependency footprint ranking weight
        footprint_rank = {
            "Candidate 2": 1,  # SQLite FTS5 only (standard library)
            "Candidate 1": 2,  # ONNX runtime
            "Candidate 3": 3,  # ChromaDB C++
        }

        sorted_candidates = sorted(
            eligible,
            key=lambda r: (
                -r.mean_recall_at_5,
                -r.mean_mrr_at_5,
                r.mean_latency_ms,
                footprint_rank.get(r.candidate_id, 99),
                r.candidate_id,  # candidate_id ASC
            ),
        )

        return sorted_candidates[0]
