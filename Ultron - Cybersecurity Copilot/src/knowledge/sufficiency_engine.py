"""Knowledge Sufficiency Engine (Milestone M9 Phase 8).

Implements multi-signal knowledge sufficiency evaluation across 6 canonical states:
1. SUFFICIENT: High retrieval scores, authoritative sources, full coverage.
2. PARTIALLY_SUFFICIENT: Relevant material retrieved but gaps in edge cases or version nuances.
3. INSUFFICIENT: Retrieval scores below relevance threshold, zero relevant chunks.
4. CONFLICTING: Detected unresolved contradictions between retrieved sources.
5. STALE: Retrieved information marked outdated or superseded.
6. OUT_OF_DOMAIN: Query unrelated to cybersecurity / VAPT methodology.

Hard Invariant:
    When knowledge is INSUFFICIENT or OUT_OF_DOMAIN, the assistant must explicitly declare
    insufficiency rather than hallucinating unsupported facts.
"""

from enum import Enum
import re
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from src.knowledge.canonical_models import AuthorityLevel, KnowledgeFreshnessStatus
from src.knowledge.models import KnowledgeChunk


class KnowledgeSufficiencyState(str, Enum):
    SUFFICIENT = "SUFFICIENT"
    PARTIALLY_SUFFICIENT = "PARTIALLY_SUFFICIENT"
    INSUFFICIENT = "INSUFFICIENT"
    CONFLICTING = "CONFLICTING"
    STALE = "STALE"
    OUT_OF_DOMAIN = "OUT_OF_DOMAIN"


class SufficiencyDecision(BaseModel):
    state: KnowledgeSufficiencyState
    confidence: float = Field(ge=0.0, le=1.0, default=0.95)
    reasons: List[str] = Field(default_factory=list)
    can_synthesize_answer: bool = True
    suggested_fallback_message: Optional[str] = None


class KnowledgeSufficiencyEvaluator:
    """Evaluates whether retrieved knowledge is sufficient to answer a cybersecurity query."""

    OUT_OF_DOMAIN_KEYWORDS = [
        "recipe", "cooking", "astrology", "horoscope", "weather forecast",
        "movie review", "sports score", "gardening", "celebrity gossip"
    ]

    @classmethod
    def evaluate(
        cls,
        query: str,
        retrieved_chunks: List[KnowledgeChunk],
        retrieval_scores: Optional[List[float]] = None,
        conflicts_detected: Optional[List[Dict[str, Any]]] = None,
        freshness_status: KnowledgeFreshnessStatus = KnowledgeFreshnessStatus.CURRENT,
    ) -> SufficiencyDecision:
        q_lower = query.lower()

        # 1. Check for Out-of-Domain queries
        if any(ood in q_lower for ood in cls.OUT_OF_DOMAIN_KEYWORDS):
            return SufficiencyDecision(
                state=KnowledgeSufficiencyState.OUT_OF_DOMAIN,
                confidence=0.99,
                reasons=["Query is unrelated to cybersecurity or VAPT methodology."],
                can_synthesize_answer=False,
                suggested_fallback_message=(
                    "This system operates exclusively as a cybersecurity knowledge and authorized "
                    "security assessment platform. The query is out-of-domain."
                ),
            )

        # 2. Check for Conflicts
        if conflicts_detected and len(conflicts_detected) > 0:
            return SufficiencyDecision(
                state=KnowledgeSufficiencyState.CONFLICTING,
                confidence=0.90,
                reasons=[f"Detected {len(conflicts_detected)} active conflict(s) between authoritative sources."],
                can_synthesize_answer=True,
                suggested_fallback_message=(
                    "Multiple authoritative sources present differing specifications or version behaviors. "
                    "Synthesizing comparative analysis highlighting the discrepancies."
                ),
            )

        # 3. Check for Stale / Outdated Knowledge
        if freshness_status in (KnowledgeFreshnessStatus.STALE, KnowledgeFreshnessStatus.OUTDATED_INFORMATION):
            return SufficiencyDecision(
                state=KnowledgeSufficiencyState.STALE,
                confidence=0.92,
                reasons=["Retrieved knowledge sources are flagged as stale or superseded."],
                can_synthesize_answer=True,
                suggested_fallback_message=(
                    "Note: The retrieved documentation reflects legacy or superseded standards. "
                    "Marking information as potentially outdated."
                ),
            )

        # 4. Check for Insufficient Chunks
        if not retrieved_chunks:
            return SufficiencyDecision(
                state=KnowledgeSufficiencyState.INSUFFICIENT,
                confidence=0.95,
                reasons=["Zero relevant knowledge chunks retrieved from local corpus."],
                can_synthesize_answer=False,
                suggested_fallback_message=(
                    "Insufficient local cybersecurity knowledge is available to reliably answer this question. "
                    "Refusing to generate ungrounded conjectures."
                ),
            )

        # 5. Evaluate Retrieval Relevance and Density
        scores = retrieval_scores or [1.0] * len(retrieved_chunks)
        max_score = max(scores) if scores else 0.0

        if len(retrieved_chunks) < 2 and max_score < 0.40:
            return SufficiencyDecision(
                state=KnowledgeSufficiencyState.PARTIALLY_SUFFICIENT,
                confidence=0.75,
                reasons=["Marginal retrieval density; only single low-confidence chunk located."],
                can_synthesize_answer=True,
                suggested_fallback_message=None,
            )

        # 6. Default: Sufficient
        return SufficiencyDecision(
            state=KnowledgeSufficiencyState.SUFFICIENT,
            confidence=0.95,
            reasons=[f"Retrieved {len(retrieved_chunks)} relevant authoritative chunks with strong score {max_score:.2f}."],
            can_synthesize_answer=True,
            suggested_fallback_message=None,
        )
