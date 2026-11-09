"""Schemas and Typed Contracts for M7 Specialized Multi-Agent Security Research.

Enforces:
1. Every agent operates under a strict contract.
2. Epistemic boundaries: agents can produce MODEL_HYPOTHESIS, INFERENCE, EVIDENCE_GAP,
   SECURITY_INVARIANT, EXPERIMENT_PROPOSAL, EXTERNAL_CLAIM.
3. Agents CANNOT produce FACT, OBSERVATION, or HUMAN_VERIFIED_FINDING.
4. All agent outputs are typed, immutable, and carry audit provenance.
"""

from datetime import datetime, timezone
from enum import Enum
import hashlib
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, ConfigDict

from src.assessment.models import (
    AssessmentExperiment,
    AssessmentHypothesis,
    EpistemicStatus,
    ExperimentRiskLevel,
)


class AgentType(str, Enum):
    ORCHESTRATOR = "ORCHESTRATOR"
    RECON = "RECON"
    WEB_API = "WEB_API"
    CODE = "CODE"
    NETWORK = "NETWORK"
    MOBILE = "MOBILE"
    BINARY = "BINARY"
    EVIDENCE = "EVIDENCE"
    FALSIFICATION = "FALSIFICATION"
    REPORTING = "REPORTING"


class ConsensusStatus(str, Enum):
    CONSENSUS_SUPPORTED = "CONSENSUS_SUPPORTED"
    CONSENSUS_WEAK = "CONSENSUS_WEAK"
    CONSENSUS_CONTESTED = "CONSENSUS_CONTESTED"
    CONSENSUS_REJECTED = "CONSENSUS_REJECTED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class AgentTask(BaseModel):
    """Structured input task sent to a specialized analytical agent."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    task_id: str
    agent_type: AgentType
    assessment_id: str
    objective: str
    target_asset: str
    input_evidence_ids: List[str] = Field(default_factory=list)
    scope_reference: str = "IN_SCOPE"
    authorization_id: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    depth: int = 1
    parent_task_id: Optional[str] = None
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class AgentOutput(BaseModel):
    """Structured, epistemically bounded output from a specialized agent."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    agent_id: str
    agent_type: AgentType
    assessment_id: str
    task_id: str
    confidence: float = Field(ge=0.0, le=1.0)
    epistemic_status: EpistemicStatus = EpistemicStatus.MODEL_HYPOTHESIS
    hypotheses: List[AssessmentHypothesis] = Field(default_factory=list)
    evidence_gaps: List[str] = Field(default_factory=list)
    security_invariants: List[str] = Field(default_factory=list)
    proposed_experiments: List[AssessmentExperiment] = Field(default_factory=list)
    supporting_evidence: List[str] = Field(default_factory=list)
    contradicting_evidence: List[str] = Field(default_factory=list)
    analysis_summary: str
    model_used: str = "local-3b-7b-cascade"
    provenance: Dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def validate_epistemic_boundaries(self) -> None:
        """Enforces that no agent can self-promote to FACT or HUMAN_VERIFIED_FINDING."""
        forbidden = (
            EpistemicStatus.FACT,
            EpistemicStatus.OBSERVATION,
            EpistemicStatus.HUMAN_VERIFIED_FINDING,
        )
        if self.epistemic_status in forbidden:
            raise PermissionError(
                f"Agent {self.agent_id} illegally attempted to output status '{self.epistemic_status.value}'. "
                "Agents may only produce MODEL_HYPOTHESIS, INFERENCE, EVIDENCE_GAP, or EXTERNAL_CLAIM."
            )


class ConsensusResult(BaseModel):
    """Evidence-weighted consensus synthesis for a candidate hypothesis."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    hypothesis_id: str
    status: ConsensusStatus
    consensus_score: float = Field(ge=0.0, le=1.0)
    supporting_agents: List[str] = Field(default_factory=list)
    contradicting_agents: List[str] = Field(default_factory=list)
    falsification_verdict: str
    evidence_sufficiency: str
    disagreement_reasons: List[str] = Field(default_factory=list)
    false_consensus_flag: bool = False
    provenance: Dict[str, Any] = Field(default_factory=dict)
    evaluated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
