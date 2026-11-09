"""Ranking and Context Budgeting Engine for Memory Subsystem."""

from typing import Any, Dict, List
from src.memory.enums import FreshnessState, MemoryAuthority
from src.memory.freshness import FreshnessTracker
from src.memory.models import MemoryItem, MemoryRetrievalItem

AUTHORITY_WEIGHTS: Dict[MemoryAuthority, float] = {
    MemoryAuthority.AUTHORITATIVE_EXTERNAL: 1.20,
    MemoryAuthority.HUMAN_VERIFIED: 1.15,
    MemoryAuthority.CANONICAL_OBSERVATION: 1.10,
    MemoryAuthority.CURATED_RESEARCH: 1.05,
    MemoryAuthority.USER_PROVIDED: 1.00,
    MemoryAuthority.MODEL_DERIVED: 0.85,
    MemoryAuthority.UNVERIFIED: 0.70,
}


class MemoryRanker:
    """
    Computes deterministic effective scores for memory candidates and manages context budgets.
    """

    def __init__(self) -> None:
        self.freshness_tracker = FreshnessTracker()

    def rank_candidates(
        self,
        scored_candidates: List[Dict[str, Any]],  # {"item": MemoryItem, "relevance": float, "method": str, "rationale": str}
        top_k: int = 5,
        max_tokens: int = 2000,
    ) -> List[MemoryRetrievalItem]:
        """
        Ranks candidates by composite effective score:
        effective_score = relevance * authority_weight * freshness_multiplier * confidence
        Applies token budgeting.
        """
        retrieval_items: List[MemoryRetrievalItem] = []

        for entry in scored_candidates:
            item: MemoryItem = entry["item"]
            base_rel: float = float(entry["relevance"])
            method: str = str(entry.get("method", "hybrid"))
            rationale: str = str(entry.get("rationale", "Relevant to search query"))

            auth_wt = AUTHORITY_WEIGHTS.get(item.authority_level, 0.80)
            freshness_state = self.freshness_tracker.evaluate_freshness(item)
            freshness_mult = self.freshness_tracker.compute_decay_multiplier(item)
            confidence = max(0.1, min(1.0, item.confidence))

            effective_score = base_rel * auth_wt * freshness_mult * confidence

            retrieval_items.append(
                MemoryRetrievalItem(
                    memory=item,
                    relevance_score=base_rel,
                    retrieval_method=method,
                    rationale=rationale,
                    freshness=freshness_state,
                    effective_score=effective_score,
                )
            )

        # Deterministic descending sort by effective score, breaking ties by item creation time
        retrieval_items.sort(key=lambda x: (x.effective_score, x.memory.created_at), reverse=True)

        # Context budgeting
        budgeted: List[MemoryRetrievalItem] = []
        cumulative_approx_tokens = 0

        for r_item in retrieval_items[:top_k]:
            approx_tokens = max(1, len(r_item.memory.content.split()))
            if cumulative_approx_tokens + approx_tokens > max_tokens and len(budgeted) >= 1:
                break
            budgeted.append(r_item)
            cumulative_approx_tokens += approx_tokens

        return budgeted
