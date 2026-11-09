"""Core Data Models and Epistemic Schemas for M6 Authorized Security Assessments.

Defines:
- Assessment Lifecycle State Machine
- Authorization Models and Statuses
- Extended Scope & Asset Entities
- Canonical Telemetry Observations
- Security Invariants and Attack Surface Entities
- Safe Experiment Specifications
- Human-Verified Findings and Formal Reports
"""

from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator


class AssessmentLifecycleState(str, Enum):
    """The formal assessment lifecycle states."""
    DRAFT = "DRAFT"
    AUTHORIZATION_PENDING = "AUTHORIZATION_PENDING"
    AUTHORIZED = "AUTHORIZED"
    SCOPE_DEFINED = "SCOPE_DEFINED"
    ASSESSMENT_ACTIVE = "ASSESSMENT_ACTIVE"
    VALIDATION_PENDING = "VALIDATION_PENDING"
    HUMAN_REVIEW = "HUMAN_REVIEW"
    COMPLETED = "COMPLETED"
    ARCHIVED = "ARCHIVED"
    # Terminal exception states
    CANCELLED = "CANCELLED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


class AuthorizationStatus(str, Enum):
    """Status of assessment authorization."""
    PENDING = "PENDING"
    AUTHORIZED = "AUTHORIZED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"
    INVALID = "INVALID"


class AuthorizationType(str, Enum):
    """Types of authorized testing engagements."""
    BUG_BOUNTY = "BUG_BOUNTY"
    PENETRATION_TEST = "PENETRATION_TEST"
    VULNERABILITY_ASSESSMENT = "VULNERABILITY_ASSESSMENT"
    INTERNAL_SECURITY_ASSESSMENT = "INTERNAL_SECURITY_ASSESSMENT"
    CTF_LAB = "CTF_LAB"
    TRAINING_LAB = "TRAINING_LAB"
    USER_DECLARED_AUTHORIZATION = "USER_DECLARED_AUTHORIZATION"


class AssessmentScopeStatus(str, Enum):
    """Status of an asset or action with respect to scope and evaluation outcome."""
    IN_SCOPE = "IN_SCOPE"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    UNKNOWN = "UNKNOWN"
    SCOPE_UNVERIFIABLE = "SCOPE_UNVERIFIABLE"
    AUTHORIZATION_EXPIRED = "AUTHORIZATION_EXPIRED"
    POLICY_VERSION_MISMATCH = "POLICY_VERSION_MISMATCH"
    SCOPE_EVALUATION_ERROR = "SCOPE_EVALUATION_ERROR"


class EpistemicStatus(str, Enum):
    """Formal epistemic boundaries across evidence ingestion and specialized agents."""
    FACT = "FACT"
    OBSERVATION = "OBSERVATION"
    HUMAN_VERIFIED_FINDING = "HUMAN_VERIFIED_FINDING"
    MODEL_HYPOTHESIS = "MODEL_HYPOTHESIS"
    INFERENCE = "INFERENCE"
    EVIDENCE_GAP = "EVIDENCE_GAP"
    SECURITY_INVARIANT = "SECURITY_INVARIANT"
    EXPERIMENT_PROPOSAL = "EXPERIMENT_PROPOSAL"
    EXTERNAL_CLAIM = "EXTERNAL_CLAIM"



class AssetType(str, Enum):
    """Canonical classification of target assets."""
    DOMAIN = "DOMAIN"
    SUBDOMAIN = "SUBDOMAIN"
    IP = "IP"
    CIDR = "CIDR"
    PORT = "PORT"
    SERVICE = "SERVICE"
    URL = "URL"
    API = "API"
    ENDPOINT = "ENDPOINT"
    WEB_APPLICATION = "WEB_APPLICATION"
    MOBILE_APPLICATION = "MOBILE_APPLICATION"
    ANDROID_APP = "ANDROID_APP"
    MOBILE_BACKEND = "MOBILE_BACKEND"
    BINARY = "BINARY"
    SOURCE_REPOSITORY = "SOURCE_REPOSITORY"
    THIRD_PARTY_DEPENDENCY = "THIRD_PARTY_DEPENDENCY"
    REPOSITORY = "REPOSITORY"
    HOST = "HOST"
    CONTAINER = "CONTAINER"
    CLOUD_RESOURCE = "CLOUD_RESOURCE"
    FILE = "FILE"
    CERTIFICATE = "CERTIFICATE"
    DNS_RECORD = "DNS_RECORD"
    OTHER = "OTHER"


# Specification parity alias
AssessmentAssetType = AssetType


class AttackSurfaceState(str, Enum):
    """Assessment state for attack surface nodes. Discovery does NOT imply vulnerability."""
    UNKNOWN = "UNKNOWN"
    OBSERVED = "OBSERVED"
    INTERESTING = "INTERESTING"
    HYPOTHESIS_EXISTS = "HYPOTHESIS_EXISTS"
    VALIDATION_REQUIRED = "VALIDATION_REQUIRED"
    VALIDATED = "VALIDATED"
    NOT_VULNERABLE = "NOT_VULNERABLE"


class ObservationType(str, Enum):
    """Canonical observation telemetry types."""
    HTTP_REQUEST = "HTTP_REQUEST"
    HTTP_RESPONSE = "HTTP_RESPONSE"
    DNS = "DNS"
    TLS = "TLS"
    PORT = "PORT"
    SERVICE = "SERVICE"
    HEADER = "HEADER"
    COOKIE = "COOKIE"
    AUTHENTICATION = "AUTHENTICATION"
    AUTHORIZATION = "AUTHORIZATION"
    API_ENDPOINT = "API_ENDPOINT"
    ERROR = "ERROR"
    SOURCE_CODE = "SOURCE_CODE"
    CONFIGURATION = "CONFIGURATION"
    MOBILE_ARTIFACT = "MOBILE_ARTIFACT"
    CERTIFICATE = "CERTIFICATE"
    TOOL_OUTPUT = "TOOL_OUTPUT"
    USER_PROVIDED = "USER_PROVIDED"
    OTHER = "OTHER"


class SecurityInvariantType(str, Enum):
    """Standard cybersecurity invariants."""
    AUTHORIZATION_BOLA = "AUTHORIZATION_BOLA"
    TENANT_ISOLATION = "TENANT_ISOLATION"
    SESSION_INVALIDATION = "SESSION_INVALIDATION"
    RATE_LIMITING = "RATE_LIMITING"
    PRIVILEGE_BOUNDARY = "PRIVILEGE_BOUNDARY"
    TLS_PROTECTION = "TLS_PROTECTION"
    FILE_ACCESS_BOUNDARY = "FILE_ACCESS_BOUNDARY"
    ANDROID_COMPONENT_EXPORT = "ANDROID_COMPONENT_EXPORT"
    OTHER = "OTHER"


class AssessmentHypothesisStatus(str, Enum):
    """Hypothesis lifecycle states."""
    PROPOSED = "PROPOSED"
    NEEDS_EVIDENCE = "NEEDS_EVIDENCE"
    TESTABLE = "TESTABLE"
    TESTING = "TESTING"
    SUPPORTED = "SUPPORTED"
    CONFIRMED = "CONFIRMED"  # HUMAN ONLY
    REFUTED = "REFUTED"
    DISPROVED = "DISPROVED"
    ABANDONED = "ABANDONED"


class ExperimentRiskLevel(str, Enum):
    """Safety classification for validation experiments."""
    PASSIVE = "PASSIVE"
    LOW_RISK = "LOW_RISK"
    MODERATE_RISK = "MODERATE_RISK"
    HIGH_RISK = "HIGH_RISK"
    DESTRUCTIVE = "DESTRUCTIVE"


class ExperimentStatus(str, Enum):
    """Status of a proposed validation experiment."""
    PROPOSED = "PROPOSED"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXECUTED = "EXECUTED"
    ABORTED = "ABORTED"
    CANCELLED = "CANCELLED"
    EXPIRED = "EXPIRED"


class FindingSeverity(str, Enum):
    """Severity classification for security findings."""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FindingVerificationStatus(str, Enum):
    """Verification state for formal findings."""
    UNVERIFIED = "UNVERIFIED"
    PENDING_HUMAN_REVIEW = "PENDING_HUMAN_REVIEW"
    HUMAN_VERIFIED = "HUMAN_VERIFIED"
    REJECTED = "REJECTED"


# ---------------------------------------------------------------------------
# Core Assessment & Authorization Models
# ---------------------------------------------------------------------------

class AuthorizationRecord(BaseModel):
    """Deterministic, auditable proof of authorized security assessment."""
    authorization_id: str
    organization: str
    assessment_name: str
    authorized_by: str
    authorized_at: str
    valid_from: str
    valid_until: str
    authorization_type: AuthorizationType
    scope_reference: str
    rules: List[str] = Field(default_factory=list)
    restrictions: List[str] = Field(default_factory=list)
    status: AuthorizationStatus = AuthorizationStatus.PENDING
    evidence: Dict[str, Any] = Field(default_factory=dict)
    provenance: Dict[str, Any] = Field(default_factory=dict)
    scope_policy_hash: Optional[str] = None
    scope_policy_version: Optional[str] = None
    content_hash: str = ""

    def compute_hash(self) -> str:
        """Computes deterministic SHA-256 hash of immutable authorization fields."""
        payload = {
            "organization": self.organization,
            "assessment_name": self.assessment_name,
            "authorized_by": self.authorized_by,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "authorization_type": self.authorization_type.value,
            "scope_reference": self.scope_reference,
            "rules": sorted(self.rules),
            "restrictions": sorted(self.restrictions),
            "scope_policy_hash": self.scope_policy_hash or "",
            "scope_policy_version": self.scope_policy_version or "",
        }
        raw = json.dumps(payload, sort_keys=True).encode("utf-8")
        return f"AUTH-{hashlib.sha256(raw).hexdigest()[:16].upper()}"

    def is_currently_valid(self, reference_time: Optional[datetime] = None) -> bool:
        """Verifies if authorization status is AUTHORIZED and within validity window."""
        if self.status != AuthorizationStatus.AUTHORIZED:
            return False
        now = reference_time or datetime.now(timezone.utc)
        try:
            start = datetime.fromisoformat(self.valid_from.replace("Z", "+00:00"))
            end = datetime.fromisoformat(self.valid_until.replace("Z", "+00:00"))
            return start <= now <= end
        except Exception:
            return False


class AssessmentRecord(BaseModel):
    """Root container tracking assessment status, authorization, and scope."""
    assessment_id: str
    organization: str
    assessment_name: str
    state: AssessmentLifecycleState = AssessmentLifecycleState.DRAFT
    created_by: str = "HUMAN_OPERATOR"
    authorization_id: Optional[str] = None
    scope_policy_id: Optional[str] = None
    scope_policy_hash: Optional[str] = None
    scope_policy_version: Optional[str] = None
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    state_history: List[Dict[str, Any]] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Target & Asset Models
# ---------------------------------------------------------------------------

class AssetRecord(BaseModel):
    """Canonical model for a discovered target asset within an assessment."""
    asset_id: str
    assessment_id: str
    asset_type: AssetType
    canonical_identifier: str
    parent_asset_id: Optional[str] = None
    scope_status: AssessmentScopeStatus = AssessmentScopeStatus.UNKNOWN
    discovery_source: str = "PASSIVE_TELEMETRY"
    first_seen: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_seen: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    tags: List[str] = Field(default_factory=list)
    attack_surface_state: AttackSurfaceState = AttackSurfaceState.OBSERVED
    provenance: Dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Canonical Observation Model
# ---------------------------------------------------------------------------

class CanonicalObservation(BaseModel):
    """Canonical observation telemetry model with scope decision and epistemic integrity."""
    observation_id: str
    assessment_id: str
    asset_id: str
    observation_type: ObservationType
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    source: str
    raw_reference: Optional[str] = None
    normalized_data: Dict[str, Any] = Field(default_factory=dict)
    scope_decision: AssessmentScopeStatus
    scope_rule: Optional[str] = None
    scope_timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    epistemic_status: str = "OBSERVATION"  # Strictly FACT or OBSERVATION, never MODEL_HYPOTHESIS
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    provenance: Dict[str, Any] = Field(default_factory=dict)
    content_hash: str = ""

    @classmethod
    def create(
        cls,
        assessment_id: str,
        asset_id: str,
        observation_type: ObservationType,
        source: str,
        normalized_data: Dict[str, Any],
        scope_decision: AssessmentScopeStatus,
        scope_rule: Optional[str] = None,
        raw_reference: Optional[str] = None,
        confidence: float = 1.0,
        provenance: Optional[Dict[str, Any]] = None,
    ) -> "CanonicalObservation":
        # Deterministic content hash from normalized payload
        norm_bytes = json.dumps(normalized_data, sort_keys=True).encode("utf-8")
        h = hashlib.sha256(norm_bytes).hexdigest()[:16]
        obs_id = f"OBS-{h.upper()}"
        return cls(
            observation_id=obs_id,
            assessment_id=assessment_id,
            asset_id=asset_id,
            observation_type=observation_type,
            source=source,
            raw_reference=raw_reference,
            normalized_data=normalized_data,
            scope_decision=scope_decision,
            scope_rule=scope_rule,
            confidence=confidence,
            provenance=provenance or {"source_type": source},
            content_hash=h,
        )


# ---------------------------------------------------------------------------
# Security Invariant Model
# ---------------------------------------------------------------------------

class SecurityInvariant(BaseModel):
    """Formal security invariant statement against which testing is evaluated."""
    invariant_id: str
    invariant_type: SecurityInvariantType
    title: str
    description: str
    secure_condition: str
    violation_condition: str


# ---------------------------------------------------------------------------
# Hypothesis & Evidence Gap Models
# ---------------------------------------------------------------------------

class AssessmentHypothesis(BaseModel):
    """Plausible security hypothesis awaiting human-controlled verification."""
    hypothesis_id: str
    assessment_id: str
    title: str
    description: str
    asset_ids: List[str] = Field(default_factory=list)
    domain: str
    supporting_observations: List[str] = Field(default_factory=list)
    contradicting_observations: List[str] = Field(default_factory=list)
    required_evidence: List[str] = Field(default_factory=list)
    evidence_gaps: List[str] = Field(default_factory=list)
    security_invariants: List[str] = Field(default_factory=list)
    suggested_experiment_id: Optional[str] = None
    negative_control: Optional[str] = None
    falsification_condition: Optional[str] = None
    confidence: float = Field(default=0.7, ge=0.0, le=1.0)
    epistemic_status: str = "MODEL_HYPOTHESIS"
    status: AssessmentHypothesisStatus = AssessmentHypothesisStatus.PROPOSED
    created_by: str = "M6_AI_ANALYSIS_PLANE"
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    verification_notes: Optional[str] = None


# ---------------------------------------------------------------------------
# Experiment Model
# ---------------------------------------------------------------------------

class AssessmentExperiment(BaseModel):
    """Proposed validation protocol. Defaults to strictly requiring human execution."""
    experiment_id: str
    assessment_id: str
    hypothesis_id: str
    objective: str
    authorization_reference: str
    scope_reference: str
    preconditions: List[str] = Field(default_factory=list)
    steps: List[str] = Field(default_factory=list)
    expected_secure_result: str
    expected_vulnerable_result: str
    falsification_condition: str
    negative_control: str
    destructive_potential: bool = False
    requires_human_execution: bool = True
    rollback_notes: str = "No destructive state mutation performed."
    risk_level: ExperimentRiskLevel = ExperimentRiskLevel.PASSIVE
    created_by: str = "M6_EXPERIMENT_ENGINE"
    status: ExperimentStatus = ExperimentStatus.PROPOSED
    approved_by: Optional[str] = None
    approved_at: Optional[str] = None
    execution_result: Optional[Dict[str, Any]] = None
    result_payload: Optional[Dict[str, Any]] = None
    executed_at: Optional[str] = None
    executed_by: Optional[str] = None


# ---------------------------------------------------------------------------
# Finding & Validation Models
# ---------------------------------------------------------------------------

class AssessmentFinding(BaseModel):
    """Auditable finding entity. Can ONLY be confirmed via explicit human sign-off."""
    finding_id: str
    assessment_id: str
    title: str
    severity: FindingSeverity
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
    confidence: float = Field(default=0.9, ge=0.0, le=1.0)
    verification_status: FindingVerificationStatus = FindingVerificationStatus.UNVERIFIED
    verified_by: Optional[str] = None
    verified_at: Optional[str] = None
    provenance: Dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Audit & Observability Telemetry Model
# ---------------------------------------------------------------------------

class AssessmentAuditRecord(BaseModel):
    """Structured telemetry event recording assessment lifecycle activities."""
    event_id: str
    assessment_id: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    actor: str
    component: str
    event_type: str
    input_reference: Optional[str] = None
    output_reference: Optional[str] = None
    authorization_state: str
    scope_state: str
    epistemic_state: str
    provenance: Dict[str, Any] = Field(default_factory=dict)
