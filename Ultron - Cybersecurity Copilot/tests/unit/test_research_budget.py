"""Unit Tests for ResearchBudgetManager and Quota Limits (Milestone M5)."""

import pytest
from src.copilot.budget import (
    ResearchBudgetLimits,
    ResearchBudgetManager,
    ResearchBudgetPolicy,
    ResearchBudgetUsage,
)


def test_budget_selection_no_external():
    policy = ResearchBudgetManager.select_budget_policy(
        task_type="EXPLAIN",
        domain_coverage="STRONG",
        escalate_external=False,
    )
    assert policy == ResearchBudgetPolicy.NO_EXTERNAL
    limits = ResearchBudgetManager.get_limits(policy)
    assert limits.max_searches == 0
    assert limits.max_external_tokens == 0


def test_budget_selection_deep_research():
    policy = ResearchBudgetManager.select_budget_policy(
        task_type="VULNERABILITY_RESEARCH",
        domain_coverage="NONE",
        escalate_external=True,
    )
    assert policy == ResearchBudgetPolicy.DEEP_RESEARCH
    limits = ResearchBudgetManager.get_limits(policy)
    assert limits.max_searches == 5
    assert limits.max_external_tokens == 4000


def test_budget_selection_standard_external():
    policy = ResearchBudgetManager.select_budget_policy(
        task_type="RESEARCH",
        domain_coverage="PARTIAL",
        escalate_external=True,
    )
    assert policy == ResearchBudgetPolicy.STANDARD_EXTERNAL
    limits = ResearchBudgetManager.get_limits(policy)
    assert limits.max_searches == 3
    assert limits.max_external_tokens == 2500


def test_budget_usage_and_limits_enforcement():
    limits = ResearchBudgetLimits(
        max_searches=1,
        max_fetched_documents=2,
        max_github_requests=1,
        max_external_tokens=1000,
    )
    usage = ResearchBudgetUsage(policy=ResearchBudgetPolicy.LIMITED_EXTERNAL)

    # 1. First search succeeds
    assert usage.can_search(limits) is True
    usage.record_search(limits)
    assert usage.searches_performed == 1

    # 2. Second search exceeds quota
    assert usage.can_search(limits) is False
    with pytest.raises(ValueError, match="Search quota exceeded"):
        usage.record_search(limits)

    # 3. Document fetch
    assert usage.can_fetch(limits) is True
    usage.record_fetch(tokens=400, limits=limits)
    assert usage.documents_fetched == 1
    assert usage.external_tokens_consumed == 400

    # 4. Token ceiling violation
    with pytest.raises(ValueError, match="Token ceiling exceeded"):
        usage.record_fetch(tokens=700, limits=limits)

    # 5. Cache hit/miss accounting
    usage.record_cache_hit()
    usage.record_cache_miss()
    assert usage.cache_hits == 1
    assert usage.cache_misses == 1
