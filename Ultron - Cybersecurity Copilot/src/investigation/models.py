"""Investigation Domain Models and Epistemic Entity Graph (Milestone M5).

Defines the core entities and graph relationships of an active investigation:
- Target, Asset, Endpoint, Observation, Evidence
- Hypothesis, EvidenceGap, Experiment, Finding
- Strict Epistemic Separation and Lifecycle States

Enforces Core Invariants:
1. Cross-investigation isolation (investigation_id partitioning)
2. MODEL_HYPOTHESIS != HUMAN_VERIFIED_FINDING
3. Experiments are strictly proposed verification protocols (NEVER autonomously executed)
4. Reports without human verification are explicitly tagged DRAFT / UNVERIFIED
"""

from datetime import datetime, timezone
from enum import Enum
import hashlib
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class HypothesisStatus(str, Enum):
    """The 8 formal lifecycle states for a cybersecurity hypothesis."""
    PROPOSED = "PROPOSED"
    NEEDS_EVIDENCE = "NEEDS_EVIDENCE"
    TESTABLE = "TESTABLE"
    TESTED = "TESTED"
    SUPPORTED = "SUPPORTED"
    FALSIFIED = "FALSIFIED"
    DISPROVED = "DISPROVED"
    HUMAN_VERIFIED = "HUMAN_VERIFIED"  # Can ONLY be reached via explicit human action


class EvidenceGapStatus(str, Enum):
    """Formal lifecycle states for an identified evidence gap."""
    OPEN = "OPEN"
    ADDRESSED = "ADDRESSED"
    DISPROVED = "DISPROVED"
    SATISFIED = "SATISFIED"
    STALE = "STALE"


class SeverityLevel(str, Enum):
    """Standard vulnerability severity rating."""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ObservationEntity(BaseModel):
    """Empirical observation recorded from target interaction under test."""
    observation_id: str = Field(..., description="Format: FACT-{hash:08x}")
    investigation_id: str
    asset_id: str
    endpoint: str
    http_method: str = "GET"
    status_code: int = 200
    summary: str
    details: Dict[str, Any] = Field(default_factory=dict)
    recorded_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class HypothesisEntity(BaseModel):
    """Technically plausible security claim awaiting verification."""
    hypothesis_id: str = Field(..., description="Format: HYP-{hash:08x}")
    investigation_id: str
    statement: str
    domain: str
    status: HypothesisStatus = HypothesisStatus.PROPOSED
    confidence: float = Field(default=0.7, ge=0.0, le=1.0)
    supporting_fact_ids: List[str] = Field(default_factory=list)
    contradicting_fact_ids: List[str] = Field(default_factory=list)
    knowledge_chunk_ids: List[str] = Field(default_factory=list)
    external_claim_ids: List[str] = Field(default_factory=list)
    falsification_condition: str = ""
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    human_verified: bool = False
    verified_by: Optional[str] = None
    verification_notes: Optional[str] = None


class EvidenceGapEntity(BaseModel):
    """Missing observation or ambiguous property needed to verify hypothesis."""
    gap_id: str = Field(..., description="Format: GAP-{hash:08x}")
    investigation_id: str
    hypothesis_id: str
    description: str
    reason: str
    required_evidence: str
    status: EvidenceGapStatus = EvidenceGapStatus.OPEN
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    resolution_notes: Optional[str] = None


class ManualExperimentEntity(BaseModel):
    """Proposed minimal manual experiment for differential verification."""
    experiment_id: str = Field(..., description="Format: EXP-{hash:08x}")
    investigation_id: str
    hypothesis_id: str
    objective: str
    prerequisites: List[str] = Field(default_factory=list)
    steps: List[str] = Field(default_factory=list)
    expected_secure_result: str
    expected_vulnerable_result: str
    falsification: str
    negative_control: str
    safety_notes: str
    evidence_to_collect: List[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class FindingEntity(BaseModel):
    """Confirmed security finding. CANNOT be created without human verification."""
    finding_id: str = Field(..., description="Format: FIND-{hash:08x}")
    investigation_id: str
    hypothesis_id: str
    title: str
    severity: SeverityLevel
    affected_endpoint: str
    security_invariant_violated: str
    verified_facts: List[str] = Field(default_factory=list)
    human_verifier: str
    verified_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class SecurityReportDraft(BaseModel):
    """Structured report draft. Marked DRAFT / UNVERIFIED unless human verified."""
    report_id: str
    investigation_id: str
    title: str
    severity: SeverityLevel
    status_label: str  # "DRAFT / UNVERIFIED" or "HUMAN_VERIFIED"
    affected_asset: str
    affected_endpoint: str
    description: str
    reproduction_steps: List[str] = Field(default_factory=list)
    expected_behavior: str
    actual_behavior: str
    security_impact: str
    remediation: str
    citations: List[str] = Field(default_factory=list)
    human_verified: bool = False


class InvestigationWorkspace(BaseModel):
    """Isolated container holding all target facts, hypotheses, and experiments."""
    investigation_id: str
    title: str
    target_host: str
    scope_status: str = "IN_SCOPE"
    observations: List[ObservationEntity] = Field(default_factory=list)
    hypotheses: List[HypothesisEntity] = Field(default_factory=list)
    evidence_gaps: List[EvidenceGapEntity] = Field(default_factory=list)
    experiments: List[ManualExperimentEntity] = Field(default_factory=list)
    findings: List[FindingEntity] = Field(default_factory=list)
    external_research_run_ids: List[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_updated: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def assert_isolation(self, other_inv_id: str) -> None:
        """Enforces that no evidence from other investigations leaks into this workspace."""
        for obs in self.observations:
            if obs.investigation_id != self.investigation_id:
                raise ValueError(f"Cross-investigation contamination detected: observation belongs to {obs.investigation_id}")
        for hyp in self.hypotheses:
            if hyp.investigation_id != self.investigation_id:
                raise ValueError(f"Cross-investigation contamination detected: hypothesis belongs to {hyp.investigation_id}")
