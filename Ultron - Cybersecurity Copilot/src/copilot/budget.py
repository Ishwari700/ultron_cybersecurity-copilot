"""Adaptive Research Budget and External Quota Manager (Milestone M5).

Regulates external research consumption to prevent token explosion and VRAM overhead:
- NO_EXTERNAL: Local only (0 searches, 0 tokens)
- LIMITED_EXTERNAL: Max 1 search, max 2 docs, 1,000 token ceiling
- STANDARD_EXTERNAL: Max 3 searches, max 5 docs, 2,500 token ceiling
- DEEP_RESEARCH: Max 5 searches, max 8 docs, 4,000 token ceiling
"""

from enum import Enum
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class ResearchBudgetPolicy(str, Enum):
    """Budget policies governing external research depth."""
    NO_EXTERNAL = "NO_EXTERNAL"
    LIMITED_EXTERNAL = "LIMITED_EXTERNAL"
    STANDARD_EXTERNAL = "STANDARD_EXTERNAL"
    DEEP_RESEARCH = "DEEP_RESEARCH"


class ResearchBudgetLimits(BaseModel):
    """Execution limits allocated for an active research task."""
    max_searches: int
    max_fetched_documents: int
    max_github_requests: int
    max_external_tokens: int


class ResearchBudgetUsage(BaseModel):
    """Tracks actual consumption against allocated budget."""
    policy: ResearchBudgetPolicy
    searches_performed: int = 0
    documents_fetched: int = 0
    github_requests: int = 0
    external_tokens_consumed: int = 0
    cache_hits: int = 0
    cache_misses: int = 0

    def can_search(self, limits: ResearchBudgetLimits) -> bool:
        return self.searches_performed < limits.max_searches

    def can_fetch(self, limits: ResearchBudgetLimits) -> bool:
        return self.documents_fetched < limits.max_fetched_documents

    def can_request_github(self, limits: ResearchBudgetLimits) -> bool:
        return self.github_requests < limits.max_github_requests

    def record_search(self, limits: ResearchBudgetLimits) -> None:
        if not self.can_search(limits):
            raise ValueError(f"Search quota exceeded ({self.searches_performed}/{limits.max_searches})")
        self.searches_performed += 1

    def record_fetch(self, tokens: int, limits: ResearchBudgetLimits) -> None:
        if not self.can_fetch(limits):
            raise ValueError(f"Document fetch quota exceeded ({self.documents_fetched}/{limits.max_fetched_documents})")
        if self.external_tokens_consumed + tokens > limits.max_external_tokens:
            raise ValueError(f"Token ceiling exceeded ({self.external_tokens_consumed + tokens}/{limits.max_external_tokens})")
        self.documents_fetched += 1
        self.external_tokens_consumed += tokens

    def record_github(self, tokens: int, limits: ResearchBudgetLimits) -> None:
        if not self.can_request_github(limits):
            raise ValueError(f"GitHub request quota exceeded ({self.github_requests}/{limits.max_github_requests})")
        if self.external_tokens_consumed + tokens > limits.max_external_tokens:
            raise ValueError(f"Token ceiling exceeded ({self.external_tokens_consumed + tokens}/{limits.max_external_tokens})")
        self.github_requests += 1
        self.external_tokens_consumed += tokens

    def record_cache_hit(self) -> None:
        self.cache_hits += 1

    def record_cache_miss(self) -> None:
        self.cache_misses += 1


class ResearchBudgetManager:
    """Allocates and enforces deterministic research budgets."""

    POLICY_LIMITS: Dict[ResearchBudgetPolicy, ResearchBudgetLimits] = {
        ResearchBudgetPolicy.NO_EXTERNAL: ResearchBudgetLimits(
            max_searches=0,
            max_fetched_documents=0,
            max_github_requests=0,
            max_external_tokens=0,
        ),
        ResearchBudgetPolicy.LIMITED_EXTERNAL: ResearchBudgetLimits(
            max_searches=1,
            max_fetched_documents=2,
            max_github_requests=1,
            max_external_tokens=1000,
        ),
        ResearchBudgetPolicy.STANDARD_EXTERNAL: ResearchBudgetLimits(
            max_searches=3,
            max_fetched_documents=5,
            max_github_requests=3,
            max_external_tokens=2500,
        ),
        ResearchBudgetPolicy.DEEP_RESEARCH: ResearchBudgetLimits(
            max_searches=5,
            max_fetched_documents=8,
            max_github_requests=5,
            max_external_tokens=4000,
        ),
    }

    @classmethod
    def select_budget_policy(
        cls,
        task_type: str,
        domain_coverage: str,
        escalate_external: bool,
    ) -> ResearchBudgetPolicy:
        """Deterministically selects the minimal sufficient budget policy."""
        if not escalate_external:
            return ResearchBudgetPolicy.NO_EXTERNAL

        if task_type in ("VULNERABILITY_RESEARCH", "INVESTIGATE") and domain_coverage == "NONE":
            return ResearchBudgetPolicy.DEEP_RESEARCH

        if task_type in ("RESEARCH", "CODE_SECURITY_REVIEW"):
            return ResearchBudgetPolicy.STANDARD_EXTERNAL

        return ResearchBudgetPolicy.LIMITED_EXTERNAL

    @classmethod
    def get_limits(cls, policy: ResearchBudgetPolicy) -> ResearchBudgetLimits:
        """Retrieves limits for a specific policy."""
        return cls.POLICY_LIMITS.get(policy, cls.POLICY_LIMITS[ResearchBudgetPolicy.LIMITED_EXTERNAL])
