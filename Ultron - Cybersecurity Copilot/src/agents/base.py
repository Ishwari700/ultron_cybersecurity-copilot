"""Abstract Base Agent for M7 Specialized Security Reasoning.

Enforces:
1. Strict contract implementation.
2. Context secret redaction before model inference.
3. Assessment isolation verification (no cross-assessment data access).
4. Epistemic status enforcement: forbids self-promotion to FACT or HUMAN_VERIFIED_FINDING.
5. Inability to authorize targets, expand scope, or autonomously execute actions.
"""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
import hashlib
from typing import Any, Dict, List, Optional

from src.agents.schemas import AgentOutput, AgentTask, AgentType
from src.assessment.models import EpistemicStatus
from src.assessment.secrets import SecretRedactor


class AgentSecurityViolationError(Exception):
    """Raised when an agent violates security boundaries, isolation, or epistemic limits."""
    pass


class BaseAgent(ABC):
    """Base class for all specialized analytical agents."""

    def __init__(self, agent_id: str, agent_type: AgentType, assessment_id: str) -> None:
        self.agent_id = agent_id
        self.agent_type = agent_type
        self.assessment_id = assessment_id

    def run(self, task: AgentTask, context: Dict[str, Any]) -> AgentOutput:
        """
        Public entry point that enforces isolation, secret redaction, and epistemic boundaries.
        """
        # 1. Assessment Isolation Enforcement
        if task.assessment_id != self.assessment_id:
            raise AgentSecurityViolationError(
                f"CROSS_ASSESSMENT_VIOLATION: Agent {self.agent_id} bound to assessment '{self.assessment_id}' "
                f"attempted to process task for assessment '{task.assessment_id}'."
            )

        # 2. Secret Redaction on all context strings
        sanitized_context = self._redact_context_secrets(context)

        # 3. Domain Analysis execution
        output = self.analyze(task, sanitized_context)

        # 4. Epistemic Boundary Check
        output.validate_epistemic_boundaries()

        # 5. Attach audit provenance
        output.provenance["agent_id"] = self.agent_id
        output.provenance["agent_type"] = self.agent_type.value
        output.provenance["assessment_id"] = self.assessment_id
        output.provenance["task_id"] = task.task_id
        output.provenance["target_asset"] = task.target_asset
        output.provenance["execution_timestamp"] = datetime.now(timezone.utc).isoformat()

        return output

    @abstractmethod
    def analyze(self, task: AgentTask, context: Dict[str, Any]) -> AgentOutput:
        """Internal domain-specific analytical reasoning implementation."""
        pass

    def _redact_context_secrets(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Deeply redacts credentials and tokens from input context."""
        return SecretRedactor.redact_dict(context)
