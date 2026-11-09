"""M7 Specialized Multi-Agent Security Research Package.

Exposes specialized security agents, orchestrator, budgets, and consensus engine.
"""

from src.agents.base import BaseAgent, AgentSecurityViolationError
from src.agents.budgets import (
    AgentBudgetConfig,
    AgentBudgetTracker,
    AgentBudgetExceededError,
)
from src.agents.binary import BinaryReverseEngineeringAgent
from src.agents.code import CodeSecurityAnalystAgent
from src.agents.consensus import MultiAgentConsensusEngine
from src.agents.evidence import EvidenceAnalystAgent
from src.agents.falsification import FalsificationAnalystAgent
from src.agents.mobile import MobileAndroidAnalystAgent
from src.agents.network import NetworkProtocolAnalystAgent
from src.agents.orchestrator import AgentOrchestrator, OrchestratorSecurityError
from src.agents.recon import ReconAnalystAgent
from src.agents.reporting import ReportingAnalystAgent
from src.agents.schemas import (
    AgentOutput,
    AgentTask,
    AgentType,
    ConsensusResult,
    ConsensusStatus,
)
from src.agents.web_api import WebApiSecurityAnalystAgent

__all__ = [
    "AgentBudgetConfig",
    "AgentBudgetExceededError",
    "AgentBudgetTracker",
    "AgentOrchestrator",
    "AgentOutput",
    "AgentSecurityViolationError",
    "AgentTask",
    "AgentType",
    "BaseAgent",
    "BinaryReverseEngineeringAgent",
    "CodeSecurityAnalystAgent",
    "ConsensusResult",
    "ConsensusStatus",
    "EvidenceAnalystAgent",
    "FalsificationAnalystAgent",
    "MobileAndroidAnalystAgent",
    "MultiAgentConsensusEngine",
    "NetworkProtocolAnalystAgent",
    "OrchestratorSecurityError",
    "ReconAnalystAgent",
    "ReportingAnalystAgent",
    "WebApiSecurityAnalystAgent",
]
