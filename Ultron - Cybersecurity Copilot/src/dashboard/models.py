"""Pydantic schemas and domain models for Phase 12 AI Investigation Workspace."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class EpistemicType(str, Enum):
    TARGET_OBSERVATION = "TARGET_OBSERVATION"
    FACT = "FACT"
    SECURITY_INVARIANT = "SECURITY_INVARIANT"
    EVIDENCE_GAP = "EVIDENCE_GAP"
    MODEL_INFERENCE = "MODEL_INFERENCE"
    GENERAL_VAPT_KNOWLEDGE = "GENERAL_VAPT_KNOWLEDGE"
    HUMAN_VERIFIED_FINDING = "HUMAN_VERIFIED_FINDING"


class StructuredCardType(str, Enum):
    INVARIANT = "INVARIANT"
    HYPOTHESIS = "HYPOTHESIS"
    EXPERIMENT = "EXPERIMENT"
    APPROVAL = "APPROVAL"
    EXECUTION = "EXECUTION"
    OBSERVATION = "OBSERVATION"
    AUDIT = "AUDIT"
    NONE = "NONE"


class SystemStatusResponse(BaseModel):
    local_ai: str = "READY"
    ollama: str = "READY"
    evidence: str = "READY"
    vapt_rag: str = "READY"
    audit: str = "VERIFIED"
    active_model: str = "Cascade Active (3B → 7B)"
    cascade_mode: str = "CASCADE_ACTIVE_3B_7B"
    execution_mode: str = "SAFE_LOCAL_SIMULATION"
    gpu: Dict[str, Any] = Field(default_factory=dict)
    recent_traces: List[Dict[str, Any]] = Field(default_factory=list)
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class InvestigationSummary(BaseModel):
    id: str
    name: str
    target_host: str
    scope_status: str = "ALLOWED"
    status: str = "ACTIVE"
    is_demo: bool = False
    evidence_count: int = 0
    hypothesis_count: int = 0
    experiment_count: int = 0
    message_count: int = 0
    last_activity: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class CreateInvestigationRequest(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    target_host: str = Field(min_length=3, max_length=255)
    description: Optional[str] = None


class RenameInvestigationRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)


class ChatMessage(BaseModel):
    id: str
    investigation_id: str
    sender: str # "user" | "assistant" | "system"
    content: str
    structured_type: StructuredCardType = StructuredCardType.NONE
    structured_data: Optional[Dict[str, Any]] = None
    sequence_number: Optional[int] = None
    delivery_status: Optional[str] = "delivered"
    cascade_trace_id: Optional[str] = None
    model_name: Optional[str] = None
    model_digest: Optional[str] = None
    response_id: Optional[str] = None
    status: Optional[str] = "COMPLETED"
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class InvestigationDetail(BaseModel):
    id: str
    name: str
    target_host: str
    scope_status: str = "ALLOWED"
    status: str = "ACTIVE"
    is_demo: bool = False
    evidence_count: int = 0
    hypothesis_count: int = 0
    messages: List[ChatMessage] = Field(default_factory=list)
    created_at: str
    updated_at: str


class SendMessageRequest(BaseModel):
    content: str = Field(min_length=1, max_length=4000)
    client_msg_id: Optional[str] = None


class EditPromptRequest(BaseModel):
    content: str = Field(min_length=1, max_length=4000, description="Corrected prompt text for regeneration")


class ExperimentValidationResult(BaseModel):
    experiment_id: str
    valid: bool
    grounding_passed: bool
    polarity_passed: bool
    scope_passed: bool
    details: Dict[str, Any] = Field(default_factory=dict)
    error_message: Optional[str] = None


class ExperimentApprovalRequest(BaseModel):
    actor: str = Field(default="authorized_security_lead", min_length=2)
    safety_acknowledged: bool = Field(default=False)
    notes: Optional[str] = "Human verified safe test parameter substitution."


class ExperimentExecuteRequest(BaseModel):
    safe_simulation: bool = Field(default=True)


class ExecutionOutcomeResponse(BaseModel):
    experiment_id: str
    status: str # EXECUTED | BLOCKED_APPROVAL | BLOCKED_SCOPE | etc.
    success: bool
    timeline: List[Dict[str, Any]] = Field(default_factory=list)
    observation: Optional[Dict[str, Any]] = None
    hypothesis_state: Optional[str] = None
    new_evidence: Optional[Dict[str, Any]] = None
    audit_event: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None


class ImportTrafficRequest(BaseModel):
    format: str = Field(default="har", description="Import format: 'har', 'raw_http', or 'burp'")
    content: str = Field(min_length=1, description="Raw content of the import file or text")
    filename: Optional[str] = Field(default=None, description="Original filename if uploaded")


class ManualObservationRequest(BaseModel):
    method: str = Field(default="GET", min_length=3, max_length=10)
    host: Optional[str] = None
    path: str = Field(default="/", min_length=1)
    status_code: int = Field(default=200, ge=100, le=599)
    request_headers: Optional[Dict[str, str]] = Field(default_factory=dict)
    request_body: Optional[str] = ""
    response_headers: Optional[Dict[str, str]] = Field(default_factory=dict)
    response_body: Optional[str] = ""
    researcher_note: Optional[str] = None


# ---------------------------------------------------------------------------
# M6 Authorized Security Assessment Dashboard Schemas
# ---------------------------------------------------------------------------

class CreateAssessmentRequest(BaseModel):
    organization: str = Field(min_length=2, max_length=150)
    assessment_name: str = Field(min_length=2, max_length=150)
    created_by: Optional[str] = Field(default=None, description="Client-submitted creator identifier (ignored; server binds to session)")


class UpdateAssessmentRequest(BaseModel):
    state: Optional[str] = None
    notes: Optional[str] = None


class SetAuthorizationRequest(BaseModel):
    organization: str
    assessment_name: str
    authorized_by: str
    valid_from: str
    valid_until: str
    authorization_type: str = "PENETRATION_TEST"
    scope_reference: str
    rules: List[str] = Field(default_factory=list)
    restrictions: List[str] = Field(default_factory=list)
    status: str = "AUTHORIZED"
    scope_policy_hash: Optional[str] = None
    scope_policy_version: Optional[str] = None


class SetScopeRequest(BaseModel):
    program_name: str
    platform: str = "M6_ASSESSMENT"
    in_scope: List[str]
    out_of_scope: List[str] = Field(default_factory=list)
    scope_policy_version: str = "v6"


class CreateAssetRequest(BaseModel):
    asset_type: str = "DOMAIN"
    canonical_identifier: str
    parent_asset_id: Optional[str] = None
    scope_status: Optional[str] = None  # Ignored by backend; computed deterministically by ScopeGate
    tags: List[str] = Field(default_factory=list)


class ImportTelemetryRequest(BaseModel):
    format_type: str
    payload: Any
    tool_name: Optional[str] = None


class ProposeExperimentRequest(BaseModel):
    hypothesis_id: str
    objective: str
    target_asset: str
    steps: List[str]
    expected_secure_result: str
    expected_vulnerable_result: str
    falsification_condition: str
    negative_control: str
    risk_level: str = "PASSIVE"


class ImportExperimentResultRequest(BaseModel):
    result_payload: Dict[str, Any]
    executed_by: Optional[str] = Field(default=None, description="Client-submitted executor (ignored; server binds to session)")


class VerifyHypothesisRequest(BaseModel):
    action: str  # ACCEPT | REQUEST_EVIDENCE | REFUTE
    human_reviewer: Optional[str] = Field(default=None, description="Client-submitted reviewer (ignored; server binds to session)")
    notes: str


class VerifyFindingRequest(BaseModel):
    human_reviewer: Optional[str] = Field(default=None, description="Client-submitted reviewer (ignored; server binds to session)")
    justification: str


class CreateFindingRequest(BaseModel):
    title: str
    severity: str = "MEDIUM"
    asset: str
    affected_component: str
    description: str
    impact: str
    evidence: List[str] = Field(default_factory=list)
    reproduction_reference: str
    security_invariant: str
    root_cause: str
    remediation: str
    references: List[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# M11.5 Long Response Subsystem Schemas
# ---------------------------------------------------------------------------

class ResponseActionRequest(BaseModel):
    action: str = Field(description="Action: explain | summarize | expand | compare | checklist | indicators | evidence | report")
    detail: Optional[str] = None


class ContinueResponseRequest(BaseModel):
    custom_directive: Optional[str] = None


class StopResponseRequest(BaseModel):
    reason: Optional[str] = "User requested stop"


class RegenerateResponseRequest(BaseModel):
    temperature: Optional[float] = 0.7


# ---------------------------------------------------------------------------
# M12 Security Research Memory & Knowledge Management Schemas
# ---------------------------------------------------------------------------

class CreateMemoryItemRequest(BaseModel):
    namespace: str = Field(default="ASSESSMENT_LOCAL")
    content: str = Field(min_length=5)
    title: Optional[str] = ""
    summary: Optional[str] = ""
    assessment_id: Optional[str] = None
    epistemic_status: str = Field(default="OBSERVATION")
    authority_level: str = Field(default="USER_PROVIDED")
    source_type: str = Field(default="ANALYST_NOTE")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    provenance_references: List[str] = Field(default_factory=list)
    evidence_references: List[str] = Field(default_factory=list)


class SearchMemoryRequest(BaseModel):
    query: str = Field(min_length=1)
    top_k: int = Field(default=5, ge=1, le=50)
    assessment_id: Optional[str] = None
    allowed_namespaces: Optional[List[str]] = None
    include_superseded: bool = Field(default=False)


class PromoteMemoryRequest(BaseModel):
    memory_id: str
    target_namespace: str = Field(default="SHARED_RESEARCH")
    requester_id: str = "researcher"
    reviewer_id: Optional[str] = None
    justification: str = Field(min_length=5)
    approve_immediately: bool = Field(default=False)


class SupersedeMemoryRequest(BaseModel):
    memory_id: str
    new_content: str = Field(min_length=5)
    change_rationale: str = Field(min_length=3)
    new_epistemic_status: Optional[str] = None
    new_authority: Optional[str] = None
    actor: str = "researcher"


class ForgetMemoryRequest(BaseModel):
    memory_id: str
    user_id: str = "researcher"
    reason: Optional[str] = "User requested memory forget"


class RetireMemoryRequest(BaseModel):
    memory_id: str
    reason: Optional[str] = "Retiring outdated research memory"


# ---------------------------------------------------------------------------
# M13 Full Security Assessment Workspace Schemas
# ---------------------------------------------------------------------------

class ValidateScopeRequest(BaseModel):
    target: str = Field(min_length=1, description="URL, domain, or IP target to test against ScopeGate")


class RegisterArtifactRequest(BaseModel):
    artifact_id: Optional[str] = None
    filename: str = Field(min_length=1)
    sha256: Optional[str] = None
    byte_size: Optional[int] = Field(default=None, ge=0)
    artifact_type: str = Field(default="TEXT_LOG")
    quarantine_status: Optional[str] = None
    content_b64: Optional[str] = None


class ArtifactUploadResponse(BaseModel):
    status: str = "success"
    artifact_id: str
    assessment_id: str
    filename: str
    sha256: str
    byte_size: int
    artifact_type: str
    quarantine_status: str
    quarantine_reason: str
    trust_status: str
    storage_path: Optional[str] = None


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=1, max_length=256)
    role: Optional[str] = Field(default=None, description="Ignored: roles are authoritatively assigned server-side")


class SessionResponse(BaseModel):
    token: str
    username: str
    role: str
    csrf_token: Optional[str] = None
    expires_at: Optional[float] = None


class UpdateViewStateRequest(BaseModel):
    active_section: Optional[str] = "overview"
    search_query: Optional[str] = ""
    selected_asset_id: Optional[str] = None
    selected_hypothesis_id: Optional[str] = None
    selected_finding_id: Optional[str] = None
    selected_artifact_id: Optional[str] = None
    filter_severity: Optional[str] = None
    filter_verification: Optional[str] = None
    filter_scope: Optional[str] = None


class GlobalSearchRequest(BaseModel):
    query: str = Field(min_length=1)
    assessment_id: Optional[str] = None


# ---------------------------------------------------------------------------
# Knowledge Source Intake & Ingestion Schemas
# ---------------------------------------------------------------------------

class ImportLocalSourceRequest(BaseModel):
    relative_path: str = Field(min_length=1, description="Path relative to data/knowledge/imports")
    title: Optional[str] = None
    authority_level: str = Field(default="USER_OWNED")
    tags: Optional[List[str]] = Field(default_factory=list)


class IngestSourceRequest(BaseModel):
    title: Optional[str] = None
    filename: str = Field(min_length=1)
    content: str = Field(min_length=1)
    authority_level: str = Field(default="USER_OWNED")
    tags: Optional[List[str]] = Field(default_factory=list)


class KnowledgeSourceResponse(BaseModel):
    source_id: str
    title: str
    filename: str
    format: str
    status: str
    page_count: int = 0
    chunk_count: int = 0
    content_hash: str
    original_checksum: str
    authority_level: str
    error_message: Optional[str] = None
    created_at: str
    updated_at: str


class GraphExtractionResponse(BaseModel):
    status: str = Field(..., description="Extraction execution status: COMPLETED, PARTIALLY_COMPLETED, FAILED, CANCELLED, or EMPTY")
    source_id: str
    total_chunks: int
    processed_chunks: int
    skipped_chunks: int
    failed_chunks: int
    entities_persisted: int
    edges_persisted: int
    source_supported_count: int
    inferred_count: int
    rejected_count: int
    model_used: Optional[str] = None
    extractor_version: str = "1.0.0"
    errors: Optional[List[str]] = None
    active_phase: Optional[str] = None
    message: Optional[str] = None


class SourceGraphStatusResponse(BaseModel):
    source_id: str
    extractions_count: int
    total_entities: int
    total_edges: int
    source_supported_edges: int
    inferred_edges: int
    rejected_candidates: int
    records: List[Dict[str, Any]] = Field(default_factory=list)
    status: Optional[str] = None
    active_phase: Optional[str] = None
    failed_chunks_count: Optional[int] = 0
    failed_chunks: Optional[List[str]] = Field(default_factory=list)
    job: Optional[Dict[str, Any]] = None


class KnowledgeGraphStatsResponse(BaseModel):
    total_nodes: int
    total_edges: int
    total_extractions: int = 0
    source_supported_edges: int = 0
    inferred_edges: int = 0
    rejected_candidates: int = 0


class KnowledgeRagQueryRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=2000, description="Cybersecurity knowledge or research query")
    force_7b: bool = Field(False, description="Explicitly request deep 7B synthesis")


class KnowledgeRagQueryResponse(BaseModel):
    answer_id: str
    query_id: str
    answer_text: str
    claims: List[Dict[str, Any]] = Field(default_factory=list)
    citations: List[Dict[str, Any]] = Field(default_factory=list)
    sufficiency_status: str
    epistemic_tier: str
    escalation_level: str
    graph_metadata: Optional[Dict[str, Any]] = None
    timestamp: str


class GraphAuditIssueModel(BaseModel):
    issue_id: str
    category: str
    severity: str
    check_code: str
    record_type: str
    record_id: str
    description: str
    evidence_context: Dict[str, Any] = Field(default_factory=dict)
    resolution_hint: str


class GraphAuditSummaryModel(BaseModel):
    nodes_examined: int = 0
    edges_examined: int = 0
    extractions_examined: int = 0
    provenance_citations_examined: int = 0
    total_issues: int = 0
    critical_count: int = 0
    error_count: int = 0
    warning_count: int = 0
    info_count: int = 0
    issues_by_category: Dict[str, int] = Field(default_factory=dict)
    issues_by_severity: Dict[str, int] = Field(default_factory=dict)
    status: str = "CLEAN"


class GraphAuditResponse(BaseModel):
    audit_id: str
    schema_version: str = "1.0.0"
    audit_timestamp: str
    summary: GraphAuditSummaryModel
    issues: List[GraphAuditIssueModel] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    read_only_guarantee: bool = True




