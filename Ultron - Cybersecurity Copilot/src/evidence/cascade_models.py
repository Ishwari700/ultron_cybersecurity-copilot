"""Milestone M2 Formal Cascade Schema Engineering Contracts (v2.0.0).

Defines independently versioned cascade schemas under namespace v2.0.0:
- Schema 1: LosslessStructuralPack
- Schema 2: RawTriageOutput
- Schema 2b: TriageMetadataPacket
- Schema 3: DeterministicRoutingDecision
- Schema 4: CascadeHandoffPacket
- Schema 5: GateValidationResult

And platform exception types for canonical integrity, gate validation, and token budget overflow.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Platform Failure Exceptions
# ---------------------------------------------------------------------------

class CanonicalEvidenceIntegrityError(Exception):
    """Raised when canonical evidence is missing, unparented, corrupt, or unparseable."""
    pass


class GateValidationError(Exception):
    """Raised when EvidencePreservationGate encounters an unrecoverable validation error."""
    pass


class ContextBudgetOverflowError(Exception):
    """Raised when canonical evidence exceeds protected token budget floor."""
    pass


# ---------------------------------------------------------------------------
# Schema 1: LosslessStructuralPack (v2.0.0)
# ---------------------------------------------------------------------------

class LosslessStructuralPack(BaseModel):
    """
    Schema 1: LosslessStructuralPack (v2.0.0)
    Immutable container with canonical structural fields and all Class-1 predicate booleans.
    Computed EXCLUSIVELY by StructuralDiffEngine.
    """
    schema_version: str = "2.0.0"
    asset_id: str
    endpoint_id: str
    route_template: str
    http_method: str
    application_mutability: str  # READ_ONLY, STATE_CHANGING, DESTRUCTIVE
    parameter_lineage: List[Dict[str, Any]] = Field(default_factory=list)
    identity_matrix: List[Dict[str, Any]] = Field(default_factory=list)
    auth_header_delta: bool = False
    status_code_changed_under_different_role: bool = False
    has_privilege_level_delta: bool = False
    has_unauthenticated_success: bool = False
    has_cross_role_response_shape_delta: bool = False
    has_cross_identity_object_access_success: bool = False
    has_evidence_parse_asymmetry: bool = False
    has_unseen_endpoint_parameter: bool = False
    has_numeric_path_identifier: bool = False
    has_observed_contradictions: bool = False
    observed_facts: List[Dict[str, Any]] = Field(default_factory=list)
    raw_body_sample: Optional[str] = None
    contradiction_pairs: Optional[List[Dict[str, str]]] = None
    interaction_lineage: Optional[List[Dict[str, Any]]] = None


# ---------------------------------------------------------------------------
# Schema 2: RawTriageOutput (v2.0.0)
# ---------------------------------------------------------------------------

class RawTriageOutput(BaseModel):
    """
    Schema 2: RawTriageOutput (v2.0.0)
    Emitted strictly by the 3B runner before EvidencePreservationGate evaluates it.
    Advisory output; MUST NOT assert taxonomy validity; MUST NOT be constructed
    with any authority over routing.
    """
    schema_version: str = "2.0.0"
    suspected_category: Optional[str] = None
    decision: str  # BENIGN_NO_ISSUE, SUSPECTED_VULNERABILITY, INSUFFICIENT_EVIDENCE
    triage_rationale: str = Field(..., max_length=500)
    suggested_experiment_class: Optional[str] = None  # ID_SWAP, ROLE_SWAP, STEP_SKIP, AUTH_DROP, None
    is_sensitive_category: bool = False
    is_malformed: bool = False
    candidate_security_property: Optional[str] = None
    cited_parameter_ids: Optional[List[str]] = None
    cited_fact_ids: Optional[List[str]] = None


# ---------------------------------------------------------------------------
# Schema 2b: TriageMetadataPacket (v2.0.0)
# ---------------------------------------------------------------------------

class TriageMetadataPacket(BaseModel):
    """
    Schema 2b: TriageMetadataPacket (v2.0.0)
    Produced exclusively by EvidencePreservationGate.validate.
    Contains same fields as RawTriageOutput plus category_invalid populated by Gate.
    is_malformed is copied verbatim from RawTriageOutput.is_malformed.
    """
    schema_version: str = "2.0.0"
    suspected_category: Optional[str] = None
    decision: str
    triage_rationale: str = Field(..., max_length=500)
    suggested_experiment_class: Optional[str] = None
    is_sensitive_category: bool = False
    is_malformed: bool = False
    category_invalid: bool = False  # Populated strictly by EvidencePreservationGate
    candidate_security_property: Optional[str] = None
    cited_parameter_ids: Optional[List[str]] = None
    cited_fact_ids: Optional[List[str]] = None


# ---------------------------------------------------------------------------
# Schema 3: DeterministicRoutingDecision (v2.0.0)
# ---------------------------------------------------------------------------

class DeterministicRoutingDecision(BaseModel):
    """
    Schema 3: DeterministicRoutingDecision (v2.0.0)
    Produced EXCLUSIVELY by DeterministicRouter.evaluate_escalation.
    Sole owner and producer of final escalation authority.
    """
    schema_version: str = "2.0.0"
    escalate: bool
    has_high_risk_signal: bool
    high_risk_signals: List[str] = Field(default_factory=list)
    deep_analysis_triggers: List[str] = Field(default_factory=list)
    reasons: List[str] = Field(default_factory=list)
    fail_safe_triggered: bool
    evaluated_timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    audit_metadata: Optional[Dict[str, Any]] = None


# ---------------------------------------------------------------------------
# Schema 5: GateValidationResult (v2.0.0)
# ---------------------------------------------------------------------------

class GateValidationResult(BaseModel):
    """
    Schema 5: GateValidationResult (v2.0.0)
    Produced EXCLUSIVELY by EvidencePreservationGate.validate.
    DeterministicRouter is a READ-ONLY consumer of GateValidationResult.
    GateValidationResult does NOT own final routing authority.
    """
    schema_version: str = "2.0.0"
    validated_triage: Optional[TriageMetadataPacket] = None
    gate_triggers: List[str] = Field(default_factory=list)
    fail_safe_required: bool = False
    audit_event_ids: List[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Schema 4: CascadeHandoffPacket (v2.0.0)
# ---------------------------------------------------------------------------

class CascadeHandoffPacket(BaseModel):
    """
    Schema 4: CascadeHandoffPacket (v2.0.0)
    Handoff packet to 7B. Binds Channel A structural evidence, router decision,
    optional validated triage metadata, and a SHA-256 provenance hash.
    """
    schema_version: str = "2.0.0"
    channel_a_structural: LosslessStructuralPack
    routing_decision: DeterministicRoutingDecision
    provenance_hash: str
    validated_triage: Optional[TriageMetadataPacket] = None
