"""Unified Workspace Domain Models for M13 Security Assessment Workspace.

Defines schemas and read models unifying assessment lifecycle, authorization,
assets, evidence, hypotheses, experiments, findings, reporting, and audit activities.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from src.assessment.models import (
    AssessmentLifecycleState,
    AssessmentScopeStatus,
    AssetType,
    AttackSurfaceState,
    AuthorizationStatus,
    AuthorizationType,
    FindingSeverity,
    FindingVerificationStatus,
)


class AssessmentSection(str, Enum):
    """The 12 primary functional sections of the assessment workspace."""
    OVERVIEW = "overview"
    SCOPE_ASSETS = "scope_assets"
    ATTACK_SURFACE = "attack_surface"
    ARTIFACTS = "artifacts"
    RESEARCH = "research"
    HYPOTHESES = "hypotheses"
    EVIDENCE = "evidence"
    EXPERIMENTS = "experiments"
    FINDINGS_REVIEW = "findings_review"
    REPORTS = "reports"
    MEMORY_KNOWLEDGE = "memory_knowledge"
    ACTIVITY_AUDIT = "activity_audit"


class AssessmentWorkflowStatus(BaseModel):
    """Workflow progress checklist for an authorized security assessment."""
    authorization_valid: bool = False
    scope_defined: bool = False
    telemetry_ingested: bool = False
    attack_surface_mapped: bool = False
    hypotheses_evaluated: bool = False
    experiments_executed: bool = False
    findings_reviewed: bool = False
    report_generated: bool = False
    current_milestone: str = "ESTABLISH_AUTHORIZATION"


class AssessmentSummary(BaseModel):
    """Compact summary of an assessment for listings and switchers."""
    assessment_id: str
    organization: str
    assessment_name: str
    state: AssessmentLifecycleState
    authorization_status: AuthorizationStatus = AuthorizationStatus.PENDING
    authorization_type: Optional[AuthorizationType] = None
    created_at: str
    updated_at: str
    asset_count: int = 0
    observation_count: int = 0
    hypothesis_count: int = 0
    finding_count: int = 0
    verified_finding_count: int = 0
    last_activity_at: Optional[str] = None


class AssessmentOverview(BaseModel):
    """Detailed high-level overview of an assessment state and metrics."""
    assessment_id: str
    organization: str
    assessment_name: str
    state: AssessmentLifecycleState
    authorization_id: Optional[str] = None
    authorization_status: AuthorizationStatus = AuthorizationStatus.PENDING
    valid_from: Optional[str] = None
    valid_until: Optional[str] = None
    scope_policy_id: Optional[str] = None
    scope_policy_version: Optional[str] = None
    scope_policy_hash: Optional[str] = None
    in_scope_count: int = 0
    out_of_scope_count: int = 0
    asset_count: int = 0
    observation_count: int = 0
    hypothesis_count: int = 0
    evidence_gap_count: int = 0
    experiment_count: int = 0
    finding_count: int = 0
    verified_finding_count: int = 0
    artifact_count: int = 0
    workflow_status: AssessmentWorkflowStatus = Field(default_factory=AssessmentWorkflowStatus)
    created_at: str
    updated_at: str
    created_by: str = "HUMAN_OPERATOR"


class AssessmentActivity(BaseModel):
    """Structured read-model of an audit ledger event in the assessment timeline."""
    event_id: str
    assessment_id: str
    timestamp: str
    actor: str
    component: str
    event_type: str
    summary: str
    details: Dict[str, Any] = Field(default_factory=dict)
    authorization_state: str = "NONE"
    scope_state: str = "UNCONFIGURED"
    epistemic_state: str = "OBSERVATION"


class WorkspaceViewState(BaseModel):
    """Persistent UI view and filter preferences for an assessment workspace."""
    active_section: AssessmentSection = AssessmentSection.OVERVIEW
    search_query: str = ""
    selected_asset_id: Optional[str] = None
    selected_hypothesis_id: Optional[str] = None
    selected_finding_id: Optional[str] = None
    selected_artifact_id: Optional[str] = None
    filter_severity: Optional[FindingSeverity] = None
    filter_verification: Optional[FindingVerificationStatus] = None
    filter_scope: Optional[AssessmentScopeStatus] = None


class AssessmentWorkspace(BaseModel):
    """Aggregated workspace view combining overview, state, and permissions."""
    overview: AssessmentOverview
    view_state: WorkspaceViewState = Field(default_factory=WorkspaceViewState)
    allowed_sections: List[AssessmentSection] = Field(
        default_factory=lambda: list(AssessmentSection)
    )
    is_read_only: bool = False
    warning_banners: List[str] = Field(default_factory=list)


class GlobalSearchResultItem(BaseModel):
    """Item returned from cross-assessment or global workspace search."""
    entity_id: str
    entity_type: str  # assessment, asset, artifact, evidence, hypothesis, experiment, finding, memory
    title: str
    assessment_id: Optional[str] = None
    assessment_name: Optional[str] = None
    snippet: str
    provenance: Dict[str, Any] = Field(default_factory=dict)
    url_target: str
