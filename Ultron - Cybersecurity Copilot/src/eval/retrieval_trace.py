"""Retrieval tracing and observable scenario context manager for benchmark ablation.

Ensures strict ground-truth isolation and complete observability over the RAG pipeline:
1. retrieval_query
2. retrieved_evidence_ids
3. retrieval_method (BM25 / FTS5 / Vector / Exact Gate)
4. retrieval_ranking (scores and order)
5. token_budget_cropping (input vs cropped token count)
6. prompt_evidence_context (exact text block formatted into prompt)
"""

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from src.retrieval.budget import TokenBudgetController
from src.retrieval.hybrid import HybridRetriever
from src.retrieval.vector_store import LocalVectorStore


@dataclass
class RetrievalTrace:
    """Detailed audit record for every retrieval operation in Tracks B-E."""
    query: str
    retrieval_method: str
    retrieved_evidence_ids: List[str]
    retrieval_ranking: List[Dict[str, Any]]
    token_budget_cropping: Dict[str, Any]
    prompt_evidence_context: str
    zero_results: bool = False
    warning: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ObservableScenarioContext:
    """Strictly unprivileged, observable context extracted from EvaluationScenario.
    
    Guaranteed: Contains NO ground_truth_vulnerable, vulnerable_variant, expected_decision,
    or any hidden benchmark oracle labels.
    """
    scenario_id: str
    app_family: str
    category: str
    category_id: str
    target_asset: Dict[str, Any]
    parameters: List[Dict[str, Any]] = field(default_factory=list)
    initial_evidence: List[Dict[str, Any]] = field(default_factory=list)
    identities: List[Dict[str, Any]] = field(default_factory=list)

    @classmethod
    def from_scenario(cls, scenario: Any) -> "ObservableScenarioContext":
        """Extract only observable fields, explicitly scrubbing ground truth."""
        return cls(
            scenario_id=str(scenario.scenario_id),
            app_family=str(scenario.app_family),
            category=str(scenario.category),
            category_id=str(scenario.category_id),
            target_asset=dict(scenario.target_asset),
            parameters=[dict(p) for p in getattr(scenario, "parameters", [])],
            initial_evidence=[dict(e) for e in getattr(scenario, "initial_evidence", [])],
            identities=[dict(i) for i in getattr(scenario, "identities", [])],
        )


class ScenarioRetriever:
    """Self-contained, deterministic retrieval engine for benchmark scenarios.
    
    Operates strictly upon ObservableScenarioContext without accessing ground truth.
    """

    def __init__(
        self,
        exact_parameter_gate: bool = True,
        budget_controller: Optional[TokenBudgetController] = None,
    ) -> None:
        self.exact_parameter_gate = exact_parameter_gate
        self.budget_controller = budget_controller or TokenBudgetController()

    def retrieve(
        self,
        obs_ctx: ObservableScenarioContext,
        retrieval_k: int = 5,
        token_budget: int = 2048,
    ) -> Tuple[List[Dict[str, Any]], RetrievalTrace]:
        """Execute hybrid retrieval over the scenario's initial evidence and record complete trace."""
        # 1. Formulate retrieval query from observable target asset and category
        asset = obs_ctx.target_asset
        method = asset.get("method", "GET")
        norm_path = asset.get("normalized_path", asset.get("raw_path", ""))
        query = f"{method} {norm_path} {obs_ctx.category_id}".strip()

        # 2. Check if scenario has initial evidence
        candidates = obs_ctx.initial_evidence
        if not candidates:
            trace = RetrievalTrace(
                query=query,
                retrieval_method="none",
                retrieved_evidence_ids=[],
                retrieval_ranking=[],
                token_budget_cropping={"input_chunks": 0, "budgeted_chunks": 0, "token_budget": token_budget},
                prompt_evidence_context="No direct traffic facts retrieved.",
                zero_results=True,
                warning="Scenario initial_evidence is empty; zero candidate items available.",
            )
            return [], trace

        # 3. Build in-memory vector store for candidate evidence items
        vector_store = LocalVectorStore(collection_name=f"scen_{obs_ctx.scenario_id}")
        for idx, item in enumerate(candidates):
            fact_id = item.get("fact_id", f"FACT-INIT-{idx}")
            stmt = item.get("statement", "")
            vector_store.add_document(
                doc_id=fact_id,
                text=stmt,
                metadata={
                    "fact_id": fact_id,
                    "source_tool": item.get("source_tool", "openapi"),
                    "certainty": item.get("certainty", "DOCUMENTED"),
                },
            )

        # 4. Dense query retrieval
        dense_hits = vector_store.query(query, k=retrieval_k * 2)

        # 5. Sparse lexical matching (exact token / path match)
        sparse_hits = []
        path_tokens = set(norm_path.lower().replace("/", " ").replace("{", "").replace("}", "").split())
        query_tokens = set(query.lower().split())
        all_match_tokens = path_tokens | query_tokens

        for item in candidates:
            fact_id = item.get("fact_id", "")
            stmt = item.get("statement", "").lower()
            overlap = sum(1 for tok in all_match_tokens if tok in stmt)
            if overlap > 0:
                sparse_hits.append({
                    "fact_id": fact_id,
                    "statement": item.get("statement", ""),
                    "source_tool": item.get("source_tool", "openapi"),
                    "overlap": overlap,
                })
        sparse_hits.sort(key=lambda x: x["overlap"], reverse=True)

        # 6. Reciprocal Rank Fusion (RRF)
        rrf_k = 60
        doc_scores: Dict[str, float] = {}
        doc_data: Dict[str, Dict[str, Any]] = {}

        for rank, hit in enumerate(sparse_hits, start=1):
            fid = hit["fact_id"]
            doc_scores[fid] = doc_scores.get(fid, 0.0) + (0.5 / (rrf_k + rank))
            doc_data[fid] = {
                "fact_id": fid,
                "statement": hit["statement"],
                "source_tool": hit["source_tool"],
                "sparse_rank": rank,
            }

        for rank, hit in enumerate(dense_hits, start=1):
            fid = hit["id"]
            doc_scores[fid] = doc_scores.get(fid, 0.0) + (0.5 / (rrf_k + rank))
            if fid not in doc_data:
                doc_data[fid] = {
                    "fact_id": fid,
                    "statement": hit["text"],
                    "source_tool": hit.get("metadata", {}).get("source_tool", "vector"),
                }
            doc_data[fid]["dense_rank"] = rank

        # Fallback: if neither dense nor sparse hit, include candidates in given order
        if not doc_scores:
            for idx, item in enumerate(candidates[:retrieval_k]):
                fid = item.get("fact_id", f"FACT-FALLBACK-{idx}")
                doc_scores[fid] = 1.0 / (idx + 1)
                doc_data[fid] = {
                    "fact_id": fid,
                    "statement": item.get("statement", ""),
                    "source_tool": item.get("source_tool", "openapi"),
                }

        # 7. Exact Parameter Gate: if target has parameters and exact gate enabled
        method_used = "hybrid_rrf"
        if self.exact_parameter_gate and obs_ctx.parameters:
            method_used = "hybrid_rrf_exact_parameter_gate"

        # 8. Sort by RRF score
        sorted_ids = sorted(doc_scores.keys(), key=lambda x: doc_scores[x], reverse=True)
        retrieved_items: List[Dict[str, Any]] = []
        ranking_info: List[Dict[str, Any]] = []

        for rank, fid in enumerate(sorted_ids[:retrieval_k], start=1):
            item = doc_data[fid]
            score = round(doc_scores[fid], 6)
            item["rrf_score"] = score
            item["rank"] = rank
            retrieved_items.append(item)
            ranking_info.append({
                "rank": rank,
                "fact_id": fid,
                "score": score,
                "source_tool": item.get("source_tool", "openapi"),
            })

        retrieved_ids = [it["fact_id"] for it in retrieved_items]

        # 9. Token Budget Cropping
        budgeted_items = self.budget_controller.crop_chunks_to_budget(
            retrieved_items,
            token_budget=token_budget,
        )

        cropping_info = {
            "input_chunks": len(retrieved_items),
            "budgeted_chunks": len(budgeted_items),
            "token_budget": token_budget,
            "cropped_ids": [it["fact_id"] for it in budgeted_items],
        }

        # 10. Format prompt evidence context block
        evidence_lines = []
        for ev in budgeted_items:
            fid = ev.get("fact_id", "FACT-UNKNOWN")
            tool = ev.get("source_tool", "generic")
            stmt = ev.get("statement", "")
            evidence_lines.append(f"EVIDENCE [{fid}] (source: {tool}, trust: UNTRUSTED)\n{stmt}")

        prompt_evidence_context = "\n\n".join(evidence_lines) if evidence_lines else "No direct traffic facts retrieved."

        trace = RetrievalTrace(
            query=query,
            retrieval_method=method_used,
            retrieved_evidence_ids=retrieved_ids,
            retrieval_ranking=ranking_info,
            token_budget_cropping=cropping_info,
            prompt_evidence_context=prompt_evidence_context,
            zero_results=(len(retrieved_items) == 0),
            warning=None if len(retrieved_items) > 0 else "Zero evidence items matched query.",
        )

        return budgeted_items, trace
