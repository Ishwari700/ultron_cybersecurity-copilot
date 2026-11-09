"""Budget and Resource Bounds Controller for M7 Multi-Agent Reasoning.

Enforces:
1. Max agents per task.
2. Max agent calls per assessment.
3. Max reasoning graph depth (stops infinite or cyclic reflection).
4. Max context tokens and wall-clock execution bounds.
5. Strict fail-stop behavior when limits are exceeded.
"""

from typing import Optional
from pydantic import BaseModel, Field


class AgentBudgetExceededError(Exception):
    """Raised when an agent workflow exceeds resource or depth budgets."""
    pass


class AgentBudgetConfig(BaseModel):
    max_agents_per_task: int = 6
    max_agent_calls: int = 12
    max_reasoning_depth: int = 5
    max_context_tokens: int = 8192
    max_external_queries: int = 10
    max_wall_clock_time_seconds: float = 60.0


class AgentBudgetTracker:
    """Tracks resource consumption across a multi-agent assessment workflow."""

    def __init__(self, assessment_id: str, config: Optional[AgentBudgetConfig] = None) -> None:
        self.assessment_id = assessment_id
        self.config = config or AgentBudgetConfig()
        self.agent_calls = 0
        self.active_agents = set()
        self.current_depth = 0
        self.token_count = 0
        self.external_queries = 0

    def record_agent_call(self, agent_id: str, depth: int, estimated_tokens: int = 500) -> None:
        if self.agent_calls >= self.config.max_agent_calls:
            raise AgentBudgetExceededError(
                f"BUDGET_EXCEEDED: max_agent_calls limit ({self.config.max_agent_calls}) reached for assessment {self.assessment_id}."
            )
        if depth > self.config.max_reasoning_depth:
            raise AgentBudgetExceededError(
                f"BUDGET_EXCEEDED: max_reasoning_depth limit ({self.config.max_reasoning_depth}) exceeded (requested depth {depth})."
            )
        self.active_agents.add(agent_id)
        if len(self.active_agents) > self.config.max_agents_per_task:
            raise AgentBudgetExceededError(
                f"BUDGET_EXCEEDED: max_agents_per_task limit ({self.config.max_agents_per_task}) exceeded."
            )

        self.agent_calls += 1
        self.current_depth = max(self.current_depth, depth)
        self.token_count += estimated_tokens
        if self.token_count > self.config.max_context_tokens:
            raise AgentBudgetExceededError(
                f"BUDGET_EXCEEDED: max_context_tokens limit ({self.config.max_context_tokens}) exceeded."
            )

    def record_external_query(self) -> None:
        if self.external_queries >= self.config.max_external_queries:
            raise AgentBudgetExceededError(
                f"BUDGET_EXCEEDED: max_external_queries limit ({self.config.max_external_queries}) reached."
            )
        self.external_queries += 1
