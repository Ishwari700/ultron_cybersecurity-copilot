"""Deterministic Research Routing Policy (M4).

Decides whether a research query is serviced strictly by local VAPT knowledge (LOCAL_ONLY)
or escalated to external research (LOCAL_PLUS_EXTERNAL).

Signals for local insufficiency:
1. Low local retrieval relevance / zero matching chunks
2. Explicit external/unsupported knowledge categories (e.g., OAuth PKCE, specific CVEs, external libraries)
3. Version-specific constraints (e.g., "version 3.2", "prior to 2.1")
4. Discrepancies or ambiguities requiring standards verification (RFC, OWASP, NIST)

Enforces Section 16 & 17:
- LLM cannot unilaterally execute external requests.
- Sanitizes all external queries before escalation.
"""

import hashlib
import re
from typing import List, Optional, Set
from pydantic import BaseModel

from src.knowledge.models import VaptKnowledgePack
from src.research.models import (
    ResearchDecision,
    ResearchRoutingDecisionMode,
)
from src.research.sanitization import QuerySanitizer


class ResearchRoutingPolicy:
    """Deterministic policy gate for external research escalation."""

    # Domains known to be covered by the 6-document local VAPT corpus
    LOCAL_DOMAINS: Set[str] = {
        "bola",
        "idor",
        "object level authorization",
        "bfla",
        "function level authorization",
        "role hierarchy",
        "tenant isolation",
        "multi-tenant",
        "rate limiting",
        "mass assignment",
    }

    # Domains that require external research (standards, protocols, CVEs, versions)
    EXTERNAL_INDICATORS = [
        re.compile(r"\b(cve-\d{4}-\d{4,}|ghsa-[a-z0-9\-]+)\b", re.IGNORECASE),
        re.compile(r"\b(pkce|oauth2?|oidc|jwt\s+none\s+alg|saml|openid)\b", re.IGNORECASE),
        re.compile(r"\b(rfc\s*\d{3,5}|nist\s*sp|owasp\s*top\s*10)\b", re.IGNORECASE),
        re.compile(r"\b(version\s*[\d\.]+|v\d+\.\d+|release\s*notes?)\b", re.IGNORECASE),
        re.compile(r"\b(github|repo|commit\s*[0-9a-f]{7,}|source\s*code)\b", re.IGNORECASE),
        re.compile(r"\b(express|fastapi|django|spring\s*boot|nginx|apache)\b", re.IGNORECASE),
    ]

    def __init__(
        self,
        min_local_chunk_threshold: int = 1,
        min_relevance_score: float = 0.015,  # RRF score threshold
    ) -> None:
        self.min_local_chunk_threshold = min_local_chunk_threshold
        self.min_relevance_score = min_relevance_score

    def evaluate_routing(
        self,
        query: str,
        local_pack: Optional[VaptKnowledgePack] = None,
        target_facts: Optional[List[str]] = None,
    ) -> ResearchDecision:
        """
        Determines whether local knowledge is sufficient or external research is required.
        """
        reasons: List[str] = []
        is_insufficient = False

        local_chunk_count = len(local_pack.items) if local_pack else 0
        top_score = max([item.fused_score for item in local_pack.items], default=0.0) if local_pack else 0.0

        # 1. Check for explicit external technology / version / CVE indicators in query
        for pattern in self.EXTERNAL_INDICATORS:
            match = pattern.search(query)
            if match:
                is_insufficient = True
                reasons.append(f"Query references external technology/protocol/version pattern: '{match.group(0)}'")
                break

        # 2. Check local retrieval coverage
        if local_chunk_count < self.min_local_chunk_threshold:
            is_insufficient = True
            reasons.append(f"Insufficient local VAPT chunk coverage (found {local_chunk_count} chunks)")
        elif top_score < self.min_relevance_score and not any(d in query.lower() for d in self.LOCAL_DOMAINS):
            is_insufficient = True
            reasons.append(f"Local retrieval score {top_score:.4f} below relevance threshold {self.min_relevance_score:.4f}")

        # 3. Check if query is fully within local access-control domain and has chunks
        if not is_insufficient and any(d in query.lower() for d in self.LOCAL_DOMAINS) and local_chunk_count > 0:
            decision_id = f"ROUTER-{hashlib.sha256(query.encode()).hexdigest()[:8]}"
            return ResearchDecision(
                decision_id=decision_id,
                mode=ResearchRoutingDecisionMode.LOCAL_ONLY,
                reasons=["Local VAPT corpus provides sufficient methodology for query domain"],
                local_chunk_count=local_chunk_count,
                top_local_score=top_score,
                detected_external_need=False,
                sanitized_external_query=None,
                target_evidence_facts_cited=target_facts or [],
            )

        # 4. If escalated to external research, sanitize the query
        sanitization = QuerySanitizer.sanitize(query)
        if not sanitization.is_safe_for_external_transmission:
            # Fall back closed if sanitization detects critical unredactable secrets
            decision_id = f"ROUTER-{hashlib.sha256(query.encode()).hexdigest()[:8]}"
            return ResearchDecision(
                decision_id=decision_id,
                mode=ResearchRoutingDecisionMode.LOCAL_ONLY,
                reasons=[f"External escalation blocked by security policy: {sanitization.blocking_reason}"],
                local_chunk_count=local_chunk_count,
                top_local_score=top_score,
                detected_external_need=True,
                sanitized_external_query=None,
                target_evidence_facts_cited=target_facts or [],
            )

        decision_id = f"ROUTER-{hashlib.sha256(query.encode()).hexdigest()[:8]}"
        return ResearchDecision(
            decision_id=decision_id,
            mode=ResearchRoutingDecisionMode.LOCAL_PLUS_EXTERNAL,
            reasons=reasons or ["Local knowledge insufficient to address query with confidence"],
            local_chunk_count=local_chunk_count,
            top_local_score=top_score,
            detected_external_need=True,
            sanitized_external_query=sanitization.sanitized_query,
            target_evidence_facts_cited=target_facts or [],
        )
