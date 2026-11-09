"""Structured Pydantic schemas for LLM reasoning and hypothesis generation.

Milestone M4: Canonical Base Schema (S0) and Deterministic Primary Failure Taxonomy.
"""

import re
from enum import Enum
from typing import Any, Dict, List, Literal, Optional, Set, Union
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

FACT_NAMESPACE_PATTERN = r"^FACT-[A-Z0-9_-]+$"
CHK_NAMESPACE_PATTERN = r"^CHK-[A-Z0-9_-]+$"
FACT_NAMESPACE_REGEX = re.compile(FACT_NAMESPACE_PATTERN)
CHK_NAMESPACE_REGEX = re.compile(CHK_NAMESPACE_PATTERN)


class ContractCompilationError(ValueError):
    """Raised when an M5 Reasoning Execution Contract violates pre-flight compilation invariants."""
    pass


class OutputProtocolIdentifier(str, Enum):
    """Authoritative output protocol identifiers for the M5 Reasoning Interface."""
    JSON_BAIR = "JSON_BAIR"
    BAIR_XML = "BAIR_XML"
    S0_JSON = "S0_JSON"


class HypothesisDecision(str, Enum):
    NO_RELEVANT_FUNCTIONALITY = "NO_RELEVANT_FUNCTIONALITY"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    HYPOTHESIS = "HYPOTHESIS"  # Note: CONFIRMED is NEVER a valid model output!


class ViolationRelation(str, Enum):
    SUPPORTED = "SUPPORTED"
    CONTRADICTED = "CONTRADICTED"
    UNRESOLVED = "UNRESOLVED"


class HttpOutcomePredicate(str, Enum):
    """Machine-readable HTTP status outcome predicates."""
    HTTP_200_OK = "HTTP_200_OK"
    HTTP_201_CREATED = "HTTP_201_CREATED"
    HTTP_204_NO_CONTENT = "HTTP_204_NO_CONTENT"
    HTTP_400_BAD_REQUEST = "HTTP_400_BAD_REQUEST"
    HTTP_401_UNAUTHORIZED = "HTTP_401_UNAUTHORIZED"
    HTTP_403_FORBIDDEN = "HTTP_403_FORBIDDEN"
    HTTP_404_NOT_FOUND = "HTTP_404_NOT_FOUND"
    HTTP_409_CONFLICT = "HTTP_409_CONFLICT"


class SemanticOutcomePredicate(str, Enum):
    """Machine-readable security invariant outcome predicates."""
    STATUS_SUCCESS_2XX = "STATUS_SUCCESS_2XX"
    STATUS_CLIENT_ERROR_4XX = "STATUS_CLIENT_ERROR_4XX"
    CROSS_IDENTITY_OBJECT_ACCESSIBLE = "CROSS_IDENTITY_OBJECT_ACCESSIBLE"
    CROSS_IDENTITY_OBJECT_DENIED = "CROSS_IDENTITY_OBJECT_DENIED"
    OWNERSHIP_NOT_ENFORCED = "OWNERSHIP_NOT_ENFORCED"
    OWNERSHIP_ENFORCED = "OWNERSHIP_ENFORCED"
    STATE_TRANSITION_ACCEPTED = "STATE_TRANSITION_ACCEPTED"
    STATE_TRANSITION_REJECTED = "STATE_TRANSITION_REJECTED"
    PRIVILEGE_ELEVATION_SUCCEEDS = "PRIVILEGE_ELEVATION_SUCCEEDS"
    PRIVILEGE_ELEVATION_DENIED = "PRIVILEGE_ELEVATION_DENIED"
    UNAUTHENTICATED_ACCESS_ALLOWED = "UNAUTHENTICATED_ACCESS_ALLOWED"
    UNAUTHENTICATED_ACCESS_DENIED = "UNAUTHENTICATED_ACCESS_DENIED"


class ExperimentActionPredicate(str, Enum):
    """Machine-readable experiment perturbation action predicates."""
    SUBSTITUTE_RESOURCE_IDENTIFIER = "SUBSTITUTE_RESOURCE_IDENTIFIER"
    EXECUTE_OUT_OF_ORDER_TRANSITION = "EXECUTE_OUT_OF_ORDER_TRANSITION"
    REPLAY_STEP_WITH_LOWER_ROLE = "REPLAY_STEP_WITH_LOWER_ROLE"
    INVOKE_WITHOUT_CREDENTIALS = "INVOKE_WITHOUT_CREDENTIALS"
    TAMPER_REQUEST_PARAMETER = "TAMPER_REQUEST_PARAMETER"


VALID_ACTION_PREDICATES: Set[str] = {e.value for e in ExperimentActionPredicate}
VALID_OUTCOME_PREDICATES: Set[str] = (
    {e.value for e in HttpOutcomePredicate} | {e.value for e in SemanticOutcomePredicate}
)


class PrimaryFailureCategory(str, Enum):
    """
    Authoritative M4/M5 Primary Failure Taxonomy (Mutually Exclusive).
    Precedence:
    RUNTIME_TIMEOUT > RUNTIME_TRANSPORT_FAILURE > MAX_TOKEN_TRUNCATION > PARSER_FAILURE > SCHEMA_VALIDITY_FAILURE > SEMANTIC_GROUNDING_FAILURE > SEMANTIC_EXPERIMENT_POLARITY_FAILURE > VALID
    """
    VALID = "VALID"
    RUNTIME_TIMEOUT = "RUNTIME_TIMEOUT"
    RUNTIME_TRANSPORT_FAILURE = "RUNTIME_TRANSPORT_FAILURE"
    MAX_TOKEN_TRUNCATION = "MAX_TOKEN_TRUNCATION"
    PARSER_FAILURE = "PARSER_FAILURE"
    SCHEMA_VALIDITY_FAILURE = "SCHEMA_VALIDITY_FAILURE"
    SEMANTIC_GROUNDING_FAILURE = "SEMANTIC_GROUNDING_FAILURE"
    SEMANTIC_EXPERIMENT_POLARITY_FAILURE = "SEMANTIC_EXPERIMENT_POLARITY_FAILURE"


class FailureClassificationResult(BaseModel):
    """Deterministic failure classification result adhering to M4 primary precedence rules."""
    primary_category: PrimaryFailureCategory
    is_valid: bool
    error_message: Optional[str] = None
    downstream_cascade: List[str] = Field(default_factory=list)
    diagnostic_details: Dict[str, Any] = Field(default_factory=dict)


class AppModelDelta(BaseModel):
    """Model-proposed assumption regarding application workflow or state."""
    observation: str
    epistemic_status: Literal["MODEL_PROPOSED"] = "MODEL_PROPOSED"  # Model assumptions are strictly MODEL_PROPOSED


class ViolationAssessment(BaseModel):
    """Assessment of whether evidence supports or contradicts an invariant violation."""
    relation: ViolationRelation
    evidence_ids: List[str] = Field(default_factory=list)


class HypothesisModelOutput(BaseModel):
    """
    Authoritative structured output schema for the Reasoning Engine (M4 S0 Canonical).
    Preserves canonical S0 fields:
    invariant, evidence_gap, affected_target, decision, supporting_evidence_ids,
    methodology_references, reasoning_summary, experiment_proposal.
    """
    # Canonical S0 fields (M4 Section 8 I1 / Section 10.1)
    invariant: Optional[str] = Field(
        default=None,
        description="Target security invariant statement evaluated against available evidence."
    )
    evidence_gap: Optional[str] = Field(
        default=None,
        description="Identified evidence gap or uncertainty regarding target application state."
    )
    affected_target: Optional[str] = Field(
        default=None,
        description="Target endpoint, canonical asset ID, or parameter under evaluation."
    )
    decision: HypothesisDecision = Field(
        description="One of NO_RELEVANT_FUNCTIONALITY, INSUFFICIENT_EVIDENCE, HYPOTHESIS (never CONFIRMED)."
    )
    supporting_evidence_ids: List[str] = Field(
        default_factory=list,
        description="Canonical observation fact IDs supporting the invariant evaluation."
    )
    methodology_references: List[str] = Field(
        default_factory=list,
        description="Referenced VAPT methodology guidance identifiers."
    )
    reasoning_summary: Optional[str] = Field(
        default=None,
        description="Concise human-readable summary of rationale."
    )
    experiment_proposal: Optional[str] = Field(
        default=None,
        description="Proposed verification experiment to confirm or refute the hypothesis."
    )
    experiment_action: Optional[str] = Field(
        default=None,
        description="Machine-readable experiment perturbation action predicate."
    )
    supporting_outcome: Optional[str] = Field(
        default=None,
        description="Machine-readable observation indicating security invariant breach."
    )
    disproving_outcome: Optional[str] = Field(
        default=None,
        description="Machine-readable observation indicating security invariant holds."
    )
    falsification_description: Optional[str] = Field(
        default=None,
        description="Optional brief natural-language explanation of verification experiment."
    )

    # M2 / M3 backwards-compatibility & telemetry fields
    category: Optional[str] = Field(
        default=None,
        description="Taxonomy category identifier, e.g. API-BOLA-001"
    )
    asset_id: Optional[str] = Field(
        default=None,
        description="Canonical asset ID from evidence graph"
    )
    parameter_ids: List[str] = Field(
        default_factory=list,
        description="Canonical parameter IDs referenced"
    )
    missing_evidence: List[str] = Field(
        default_factory=list,
        description="Identified missing evidence gaps"
    )
    cited_methodology_chunk_ids: List[str] = Field(
        default_factory=list,
        description="Cited VAPT methodology chunk IDs (CHK-xxx) supporting testing rationale or invariants."
    )
    contradicting_evidence_ids: List[str] = Field(
        default_factory=list
    )
    app_model_delta: Optional[AppModelDelta] = Field(
        default=None,
        description="Model-proposed assumption or observation regarding application state."
    )
    violation_assessment: Optional[ViolationAssessment] = Field(
        default=None,
        description="Assessment of whether cited evidence supports or contradicts the invariant violation."
    )
    actor_identity_id: Optional[str] = Field(
        default=None,
        description="Requesting identity for authorization testing"
    )
    target_identity_id: Optional[str] = Field(
        default=None,
        description="Resource-owning identity for authorization testing"
    )
    safety_check: Optional[str] = Field(
        default=None,
        description="Safety check evaluation"
    )
    evidence_sufficiency: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0
    )

    @model_validator(mode="after")
    def sync_canonical_and_legacy_fields(self) -> "HypothesisModelOutput":
        # Synchronize methodology_references and cited_methodology_chunk_ids
        if self.methodology_references and not self.cited_methodology_chunk_ids:
            self.cited_methodology_chunk_ids = list(self.methodology_references)
        elif self.cited_methodology_chunk_ids and not self.methodology_references:
            self.methodology_references = list(self.cited_methodology_chunk_ids)

        # Synchronize affected_target and asset_id
        if self.affected_target and not self.asset_id:
            self.asset_id = self.affected_target
        elif self.asset_id and not self.affected_target:
            self.affected_target = self.asset_id

        # Synchronize evidence_gap and missing_evidence
        if self.evidence_gap and not self.missing_evidence:
            self.missing_evidence = [self.evidence_gap]
        elif self.missing_evidence and not self.evidence_gap:
            self.evidence_gap = "; ".join(self.missing_evidence)

        return self

    @classmethod
    def get_inference_schema(cls) -> Dict[str, Any]:
        """
        Return the strict canonical S0 JSON schema for LLM inference.
        Preserves the 8 canonical fields defined by the M4 specification:
        - invariant
        - evidence_gap
        - affected_target
        - decision
        - supporting_evidence_ids
        - methodology_references
        - reasoning_summary
        - experiment_proposal

        No I2 namespace regex constraints.
        No field-length compaction.
        Standard type constraints only.
        """
        return {
            "type": "object",
            "properties": {
                "decision": {
                    "type": "string",
                    "enum": [
                        "NO_RELEVANT_FUNCTIONALITY",
                        "INSUFFICIENT_EVIDENCE",
                        "HYPOTHESIS",
                    ],
                    "description": "One of NO_RELEVANT_FUNCTIONALITY, INSUFFICIENT_EVIDENCE, HYPOTHESIS (never CONFIRMED).",
                },
                "invariant": {
                    "type": "string",
                    "description": "Target security invariant statement evaluated against available evidence.",
                },
                "evidence_gap": {
                    "type": "string",
                    "description": "Identified evidence gap or uncertainty regarding target application state.",
                },
                "affected_target": {
                    "type": "string",
                    "description": "Target endpoint, canonical asset ID, or parameter under evaluation.",
                },
                "supporting_evidence_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Canonical observation fact IDs supporting the invariant evaluation.",
                },
                "methodology_references": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Referenced VAPT methodology guidance identifiers.",
                },
                "reasoning_summary": {
                    "type": "string",
                    "description": "Concise human-readable summary of rationale.",
                },
                "experiment_proposal": {
                    "type": "string",
                    "description": "Proposed verification experiment to confirm or refute the hypothesis.",
                },
            },
            "required": [
                "decision",
                "invariant",
                "evidence_gap",
                "affected_target",
                "supporting_evidence_ids",
                "methodology_references",
                "reasoning_summary",
                "experiment_proposal",
            ],
        }


# Formal M3 Model Output Alias per M3 Plan v2.3.8 Section 17 & 21
ReasoningHypothesis = HypothesisModelOutput


class I1ExecutionResult(BaseModel):
    """Result of an authoritative I1 schema-constrained structured generation attempt."""
    raw_response: str
    parsed_json: Optional[Dict[str, Any]] = None
    hypothesis: Optional[HypothesisModelOutput] = None
    classification: FailureClassificationResult
    latency_ms: float = 0.0
    eval_count: Optional[int] = None
    prompt_eval_count: Optional[int] = None
    diagnostic_repair: Optional[Dict[str, Any]] = None
    grounding_result: Optional[Dict[str, Any]] = None


class I2RawHypothesisOutput(BaseModel):
    """
    Raw model emission schema for Intervention I2 (Epistemic Namespace Segregation).
    Employs segregated output fields:
    - empirical_fact_ids: ONLY empirical target evidence IDs matching ^FACT-[A-Z0-9_-]+$
    - methodology_chunk_ids: ONLY VAPT methodology guidance IDs matching ^CHK-[A-Z0-9_-]+$

    Enforces post-generation schema validation constraints under baseline unconstrained sampling.
    """
    decision: HypothesisDecision = Field(
        description="One of NO_RELEVANT_FUNCTIONALITY, INSUFFICIENT_EVIDENCE, HYPOTHESIS (never CONFIRMED)."
    )
    invariant: Optional[str] = Field(
        default=None,
        description="Target security invariant statement evaluated against available evidence."
    )
    evidence_gap: Optional[str] = Field(
        default=None,
        description="Identified evidence gap or uncertainty regarding target application state."
    )
    affected_target: Optional[str] = Field(
        default=None,
        description="Target endpoint, canonical asset ID, or parameter under evaluation."
    )
    empirical_fact_ids: List[str] = Field(
        default_factory=list,
        description="Canonical empirical target observation fact IDs only (^FACT-[A-Z0-9_-]+$).",
    )
    methodology_chunk_ids: List[str] = Field(
        default_factory=list,
        description="Referenced VAPT methodology chunk IDs only (^CHK-[A-Z0-9_-]+$).",
    )
    reasoning_summary: Optional[str] = Field(
        default=None,
        description="Concise human-readable summary of rationale."
    )
    experiment_proposal: Optional[str] = Field(
        default=None,
        description="Proposed verification experiment to confirm or refute the hypothesis."
    )
    category: Optional[str] = Field(
        default=None,
        description="Taxonomy category identifier, e.g. API-BOLA-001"
    )
    asset_id: Optional[str] = Field(
        default=None,
        description="Canonical asset ID from evidence graph"
    )
    parameter_ids: List[str] = Field(
        default_factory=list,
        description="Canonical parameter IDs referenced"
    )

    @field_validator("empirical_fact_ids")
    @classmethod
    def validate_empirical_fact_ids(cls, v: List[str]) -> List[str]:
        for item in v:
            if not isinstance(item, str) or not FACT_NAMESPACE_REGEX.match(item):
                raise ValueError(
                    f"INVALID_NAMESPACE_BREACH: empirical_fact_ids item '{item}' does not match {FACT_NAMESPACE_PATTERN}"
                )
            if "CHK-" in item:
                raise ValueError(
                    f"INVALID_NAMESPACE_BREACH: methodology chunk ID '{item}' placed in empirical_fact_ids"
                )
        return v

    @field_validator("methodology_chunk_ids")
    @classmethod
    def validate_methodology_chunk_ids(cls, v: List[str]) -> List[str]:
        for item in v:
            if not isinstance(item, str) or not CHK_NAMESPACE_REGEX.match(item):
                raise ValueError(
                    f"INVALID_NAMESPACE_BREACH: methodology_chunk_ids item '{item}' does not match {CHK_NAMESPACE_PATTERN}"
                )
            if "FACT-" in item:
                raise ValueError(
                    f"INVALID_NAMESPACE_BREACH: empirical fact ID '{item}' placed in methodology_chunk_ids"
                )
        return v

    @classmethod
    def get_raw_schema(cls) -> Dict[str, Any]:
        """
        Return the raw JSON schema for I2 inference.
        Includes regex pattern constraints on empirical_fact_ids and methodology_chunk_ids.
        """
        return {
            "type": "object",
            "properties": {
                "decision": {
                    "type": "string",
                    "enum": [
                        "NO_RELEVANT_FUNCTIONALITY",
                        "INSUFFICIENT_EVIDENCE",
                        "HYPOTHESIS",
                    ],
                    "description": "One of NO_RELEVANT_FUNCTIONALITY, INSUFFICIENT_EVIDENCE, HYPOTHESIS (never CONFIRMED).",
                },
                "invariant": {
                    "type": "string",
                    "description": "Target security invariant statement evaluated against available evidence.",
                },
                "evidence_gap": {
                    "type": "string",
                    "description": "Identified evidence gap or uncertainty regarding target application state.",
                },
                "affected_target": {
                    "type": "string",
                    "description": "Target endpoint, canonical asset ID, or parameter under evaluation.",
                },
                "empirical_fact_ids": {
                    "type": "array",
                    "items": {
                        "type": "string",
                        "pattern": FACT_NAMESPACE_PATTERN,
                    },
                    "description": "Canonical observation fact IDs supporting the invariant evaluation (^FACT-[A-Z0-9_-]+$).",
                },
                "methodology_chunk_ids": {
                    "type": "array",
                    "items": {
                        "type": "string",
                        "pattern": CHK_NAMESPACE_PATTERN,
                    },
                    "description": "Referenced VAPT methodology guidance identifiers (^CHK-[A-Z0-9_-]+$).",
                },
                "reasoning_summary": {
                    "type": "string",
                    "description": "Concise human-readable summary of rationale.",
                },
                "experiment_proposal": {
                    "type": "string",
                    "description": "Proposed verification experiment to confirm or refute the hypothesis.",
                },
            },
            "required": [
                "decision",
                "invariant",
                "evidence_gap",
                "affected_target",
                "empirical_fact_ids",
                "methodology_chunk_ids",
                "reasoning_summary",
                "experiment_proposal",
            ],
        }


class BairJsonObject(BaseModel):
    """
    Authoritative JSON-Native Bounded Analytical Intermediate Representation (M5 JSON_BAIR).
    Represents the seven canonical BAIR analytical slots in a typed JSON structure:
    1. invariant: target security invariant statement evaluated against target.
    2. evidence_gap: missing observation or gap in evidence (optional for NO_RELEVANT_FUNCTIONALITY).
    3. affected_target: target endpoint, canonical asset ID, or parameter under evaluation.
    4. decision: hypothesis decision (NO_RELEVANT_FUNCTIONALITY, INSUFFICIENT_EVIDENCE, HYPOTHESIS).
    5. empirical_facts: canonical observation fact IDs only (^FACT-[A-Z0-9_-]+$).
    6. methodology_references: referenced VAPT methodology guidance identifiers (^CHK-[A-Z0-9_-]+$).
    7. falsification_plan: concrete verification experiment with supporting and disproving observations.
    """
    model_config = ConfigDict(extra="forbid")

    invariant: str = Field(
        ...,
        description="Target security invariant statement evaluated against target."
    )
    evidence_gap: Optional[str] = Field(
        default=None,
        description="Identified evidence gap or uncertainty regarding target application state."
    )
    affected_target: str = Field(
        ...,
        description="Target endpoint, canonical asset ID, or parameter under evaluation."
    )
    decision: HypothesisDecision = Field(
        ...,
        description="One of NO_RELEVANT_FUNCTIONALITY, INSUFFICIENT_EVIDENCE, HYPOTHESIS (never CONFIRMED)."
    )
    empirical_facts: List[str] = Field(
        default_factory=list,
        description="Canonical observation fact IDs supporting the invariant evaluation (^FACT-[A-Z0-9_-]+$)."
    )
    methodology_references: List[str] = Field(
        default_factory=list,
        description="Referenced VAPT methodology guidance identifiers (^CHK-[A-Z0-9_-]+$)."
    )
    experiment_action: Optional[str] = Field(
        default=None,
        description="Machine-readable experiment perturbation action predicate."
    )
    supporting_outcome: Optional[str] = Field(
        default=None,
        description="Machine-readable observation indicating security invariant breach."
    )
    disproving_outcome: Optional[str] = Field(
        default=None,
        description="Machine-readable observation indicating security invariant holds."
    )
    falsification_description: Optional[str] = Field(
        default=None,
        description="Optional brief natural-language description of verification experiment."
    )
    falsification_plan: Optional[str] = Field(
        default=None,
        description="Deprecated legacy unanchored falsification plan."
    )

    @field_validator("empirical_facts")
    @classmethod
    def validate_empirical_facts(cls, v: List[str]) -> List[str]:
        placeholder_tokens = {"none", "n/a", "na", "null", "[]", "{}"}
        for item in v:
            if not isinstance(item, str) or not FACT_NAMESPACE_REGEX.match(item):
                raise ValueError(
                    f"INVALID_NAMESPACE_BREACH: empirical_facts item '{item}' does not match {FACT_NAMESPACE_PATTERN}"
                )
            if "CHK-" in item:
                raise ValueError(
                    f"INVALID_NAMESPACE_BREACH: methodology chunk ID '{item}' placed in empirical_facts"
                )
            if item.lower() in placeholder_tokens:
                raise ValueError(f"Placeholder token {item!r} is strictly forbidden in empirical_facts")
        return v

    @field_validator("methodology_references")
    @classmethod
    def validate_methodology_references(cls, v: List[str]) -> List[str]:
        placeholder_tokens = {"none", "n/a", "na", "null", "[]", "{}"}
        for item in v:
            if not isinstance(item, str) or not CHK_NAMESPACE_REGEX.match(item):
                raise ValueError(
                    f"INVALID_NAMESPACE_BREACH: methodology_references item '{item}' does not match {CHK_NAMESPACE_PATTERN}"
                )
            if "FACT-" in item:
                raise ValueError(
                    f"INVALID_NAMESPACE_BREACH: empirical fact ID '{item}' placed in methodology_references"
                )
            if item.lower() in placeholder_tokens:
                raise ValueError(f"Placeholder token {item!r} is strictly forbidden in methodology_references")
        return v

    @field_validator("experiment_action")
    @classmethod
    def validate_experiment_action(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        if not isinstance(v, str) or not v.strip():
            return None
        v_clean = v.strip()
        if v_clean not in VALID_ACTION_PREDICATES:
            raise ValueError(
                f"Unknown experiment_action predicate: '{v_clean}'. Must be one of {sorted(list(VALID_ACTION_PREDICATES))}"
            )
        return v_clean

    @field_validator("supporting_outcome", "disproving_outcome")
    @classmethod
    def validate_outcome_predicate(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        if not isinstance(v, str) or not v.strip():
            return None
        v_clean = v.strip()
        if v_clean not in VALID_OUTCOME_PREDICATES:
            raise ValueError(
                f"Unknown outcome predicate: '{v_clean}'. Must be one of {sorted(list(VALID_OUTCOME_PREDICATES))}"
            )
        return v_clean

    @model_validator(mode="after")
    def validate_decision_dependent_slots(self) -> "BairJsonObject":
        # CONFIRMED is unconditionally rejected
        if self.decision == "CONFIRMED" or getattr(self.decision, "value", None) == "CONFIRMED":
            raise ValueError("CONFIRMED decision is strictly forbidden in reasoning engine")

        inv = (self.invariant or "").strip()
        target = (self.affected_target or "").strip()
        gap = (self.evidence_gap or "").strip() if self.evidence_gap else ""

        placeholder_tokens = {"none", "n/a", "na", "null", "[]", "{}", "todo", "unknown"}
        if not inv:
            raise ValueError("Mandatory invariant slot missing or empty")
        if inv.lower() in placeholder_tokens:
            raise ValueError(f"invariant cannot be a placeholder value: {inv!r}")
        if not target:
            raise ValueError("Mandatory affected_target slot missing or empty")
        if target.lower() in placeholder_tokens:
            raise ValueError(f"affected_target cannot be a placeholder value: {target!r}")

        if self.decision == HypothesisDecision.HYPOTHESIS:
            if not gap:
                raise ValueError("Mandatory evidence_gap slot missing or empty for HYPOTHESIS")
            if not self.empirical_facts:
                raise ValueError("Mandatory empirical_facts slot missing or empty for HYPOTHESIS")

            # Typed experiment predicates are mandatory for HYPOTHESIS
            if not self.experiment_action or not self.supporting_outcome or not self.disproving_outcome:
                if self.falsification_plan:
                    raise ValueError(
                        "Legacy free-text falsification_plan cannot authorize a HYPOTHESIS under JSON_BAIR protocol; "
                        "typed experiment fields (experiment_action, supporting_outcome, disproving_outcome) are mandatory"
                    )
                if not self.experiment_action:
                    raise ValueError("Mandatory experiment_action slot missing or empty for HYPOTHESIS")
                if not self.supporting_outcome:
                    raise ValueError("Mandatory supporting_outcome slot missing or empty for HYPOTHESIS")
                if not self.disproving_outcome:
                    raise ValueError("Mandatory disproving_outcome slot missing or empty for HYPOTHESIS")

            if self.supporting_outcome == self.disproving_outcome:
                raise ValueError(
                    f"supporting_outcome and disproving_outcome cannot be identical ('{self.supporting_outcome}')"
                )

        elif self.decision == HypothesisDecision.INSUFFICIENT_EVIDENCE:
            if not gap:
                raise ValueError("Mandatory evidence_gap slot missing or empty for INSUFFICIENT_EVIDENCE")

        elif self.decision == HypothesisDecision.NO_RELEVANT_FUNCTIONALITY:
            pass

        return self

    @classmethod
    def get_inference_schema(cls) -> Dict[str, Any]:
        """Return canonical JSON schema suitable for Ollama native format={...} constrained decoding."""
        return {
            "type": "object",
            "properties": {
                "invariant": {
                    "type": "string",
                    "description": "Security invariant statement evaluated against target",
                },
                "evidence_gap": {
                    "type": ["string", "null"],
                    "description": "Missing observation or gap in evidence",
                },
                "affected_target": {
                    "type": "string",
                    "description": "Target endpoint, asset ID, or parameter",
                },
                "decision": {
                    "type": "string",
                    "enum": [
                        "NO_RELEVANT_FUNCTIONALITY",
                        "INSUFFICIENT_EVIDENCE",
                        "HYPOTHESIS",
                    ],
                    "description": "One of NO_RELEVANT_FUNCTIONALITY, INSUFFICIENT_EVIDENCE, HYPOTHESIS (never CONFIRMED)",
                },
                "empirical_facts": {
                    "type": "array",
                    "items": {
                        "type": "string",
                        "pattern": FACT_NAMESPACE_PATTERN,
                    },
                    "description": "Canonical observation fact IDs (^FACT-[A-Z0-9_-]+$)",
                },
                "methodology_references": {
                    "type": "array",
                    "items": {
                        "type": "string",
                        "pattern": CHK_NAMESPACE_PATTERN,
                    },
                    "description": "Referenced VAPT methodology guidance identifiers (^CHK-[A-Z0-9_-]+$)",
                },
                "experiment_action": {
                    "type": ["string", "null"],
                    "enum": sorted(list(VALID_ACTION_PREDICATES)) + [None],
                    "description": "Machine-readable experiment perturbation action predicate",
                },
                "supporting_outcome": {
                    "type": ["string", "null"],
                    "enum": sorted(list(VALID_OUTCOME_PREDICATES)) + [None],
                    "description": "Machine-readable observation indicating security invariant breach",
                },
                "disproving_outcome": {
                    "type": ["string", "null"],
                    "enum": sorted(list(VALID_OUTCOME_PREDICATES)) + [None],
                    "description": "Machine-readable observation indicating security invariant holds",
                },
                "falsification_description": {
                    "type": ["string", "null"],
                    "description": "Optional brief natural-language description of verification experiment",
                },
                "falsification_plan": {
                    "type": ["string", "null"],
                    "description": "Deprecated legacy unanchored falsification plan",
                },
            },
            "required": [
                "invariant",
                "evidence_gap",
                "affected_target",
                "decision",
                "empirical_facts",
                "methodology_references",
                "experiment_action",
                "supporting_outcome",
                "disproving_outcome",
                "falsification_description",
            ],
        }


def adapt_i2_to_s0(
    raw_output: Union[I2RawHypothesisOutput, Dict[str, Any]],
) -> HypothesisModelOutput:
    """
    Deterministic I2 Output-Schema Adapter Contract (M4 Plan Section 8 I2 / Section 10.1).
    Maps raw segregated I2 fields into canonical S0 HypothesisModelOutput:
        empirical_fact_ids -> supporting_evidence_ids
        methodology_chunk_ids -> methodology_references (and cited_methodology_chunk_ids)

    Contract guarantees:
    - Performs zero semantic inference or field interpretation.
    - Performs zero citation substitution (never converts CHK to FACT or vice versa).
    - Preserves exact entity IDs as emitted by the model.
    - Rejects invalid namespaces (fails closed if empirical_fact_ids contains CHK- or methodology_chunk_ids contains FACT-).
    - Emits canonical HypothesisModelOutput representation, maintaining strictly uniform downstream scoring.
    """
    if isinstance(raw_output, dict):
        raw_obj = I2RawHypothesisOutput.model_validate(raw_output)
    elif isinstance(raw_output, I2RawHypothesisOutput):
        raw_obj = raw_output
    else:
        raise TypeError(f"Expected I2RawHypothesisOutput or dict, got {type(raw_output).__name__}")

    # Explicit fail-closed namespace checks (defense-in-depth)
    for fid in raw_obj.empirical_fact_ids:
        if not FACT_NAMESPACE_REGEX.match(fid) or "CHK-" in fid:
            raise ValueError(
                f"INVALID_NAMESPACE_BREACH: Invalid or cross-namespace ID in empirical_fact_ids: {fid}"
            )

    for cid in raw_obj.methodology_chunk_ids:
        if not CHK_NAMESPACE_REGEX.match(cid) or "FACT-" in cid:
            raise ValueError(
                f"INVALID_NAMESPACE_BREACH: Invalid or cross-namespace ID in methodology_chunk_ids: {cid}"
            )

    return HypothesisModelOutput(
        decision=raw_obj.decision,
        invariant=raw_obj.invariant,
        evidence_gap=raw_obj.evidence_gap,
        affected_target=raw_obj.affected_target,
        supporting_evidence_ids=list(raw_obj.empirical_fact_ids),
        methodology_references=list(raw_obj.methodology_chunk_ids),
        cited_methodology_chunk_ids=list(raw_obj.methodology_chunk_ids),
        reasoning_summary=raw_obj.reasoning_summary,
        experiment_proposal=raw_obj.experiment_proposal,
        category=raw_obj.category,
        asset_id=raw_obj.asset_id or raw_obj.affected_target,
        parameter_ids=list(raw_obj.parameter_ids),
    )


def check_raw_namespace_breach(
    raw_dict: Optional[Dict[str, Any]] = None,
    raw_text: Optional[str] = None,
) -> bool:
    """
    Detect whether raw model output exhibits a cross-namespace citation breach before validation.
    Checks:
    - Any CHK ID present in empirical_fact_ids or supporting_evidence_ids
    - Any FACT ID present in methodology_chunk_ids, methodology_references, or cited_methodology_chunk_ids
    - Text-level inspection for cross-namespace emissions if raw_dict is None
    """
    if raw_dict is not None:
        facts = list(raw_dict.get("empirical_fact_ids") or raw_dict.get("supporting_evidence_ids") or [])
        for f in facts:
            if isinstance(f, str) and ("CHK-" in f or f.startswith("CHK-")):
                return True
        meths = list(
            raw_dict.get("methodology_chunk_ids")
            or raw_dict.get("methodology_references")
            or raw_dict.get("cited_methodology_chunk_ids")
            or []
        )
        for m in meths:
            if isinstance(m, str) and ("FACT-" in m or m.startswith("FACT-")):
                return True

    if raw_text is not None:
        if re.search(r'["\']empirical_fact_ids["\']\s*:\s*\[[^\]]*CHK-[A-Za-z0-9_-]+', raw_text):
            return True
        if re.search(r'["\']supporting_evidence_ids["\']\s*:\s*\[[^\]]*CHK-[A-Za-z0-9_-]+', raw_text):
            return True
        if re.search(r'["\']methodology_chunk_ids["\']\s*:\s*\[[^\]]*FACT-[A-Za-z0-9_-]+', raw_text):
            return True
        if re.search(r'["\']methodology_references["\']\s*:\s*\[[^\]]*FACT-[A-Za-z0-9_-]+', raw_text):
            return True
        if re.search(r'["\']cited_methodology_chunk_ids["\']\s*:\s*\[[^\]]*FACT-[A-Za-z0-9_-]+', raw_text):
            return True

    return False


class I2ExecutionResult(BaseModel):
    """Result of an authoritative I2 epistemic namespace segregation generation attempt."""
    raw_response: str
    parsed_json: Optional[Dict[str, Any]] = None
    raw_i2_output: Optional[I2RawHypothesisOutput] = None
    canonical_hypothesis: Optional[HypothesisModelOutput] = None
    classification: FailureClassificationResult
    latency_ms: float = 0.0
    eval_count: Optional[int] = None
    prompt_eval_count: Optional[int] = None
    has_raw_namespace_breach: bool = False
    validator_bypassed: bool = False
    grounding_result: Optional[Dict[str, Any]] = None
    adapter_error: Optional[str] = None


class I3ExecutionResult(BaseModel):
    """Result of an authoritative I3 counterfactual evidence-gap reasoning generation attempt."""
    raw_response: str
    parsed_json: Optional[Dict[str, Any]] = None
    hypothesis: Optional[HypothesisModelOutput] = None
    classification: FailureClassificationResult
    latency_ms: float = 0.0
    eval_count: Optional[int] = None
    prompt_eval_count: Optional[int] = None
    template_category_id: Optional[str] = None
    diagnostic_repair: Optional[Dict[str, Any]] = None
    grounding_result: Optional[Dict[str, Any]] = None


class I4ExecutionResult(BaseModel):
    """Result of an authoritative I4 BAIR analytical inference generation attempt."""
    raw_response: str
    extracted_bair: Optional[Dict[str, Any]] = None
    canonical_hypothesis: Optional[HypothesisModelOutput] = None
    classification: FailureClassificationResult
    latency_ms: float = 0.0
    eval_count: Optional[int] = None
    prompt_eval_count: Optional[int] = None
    bair_error: Optional[str] = None
    grounding_result: Optional[Dict[str, Any]] = None


class I5ExecutionResult(BaseModel):
    """Result of an authoritative I5 deterministic decision policy generation attempt."""
    raw_response: str
    parsed_json: Optional[Dict[str, Any]] = None
    candidate_hypothesis: Optional[HypothesisModelOutput] = None
    canonical_hypothesis: Optional[HypothesisModelOutput] = None
    candidate_decision: Optional[str] = None
    final_decision: Optional[str] = None
    decision_changed: bool = False
    predicate_identifier: Optional[str] = None
    fail_closed: bool = False
    fail_closed_reason: Optional[str] = None
    classification: FailureClassificationResult
    latency_ms: float = 0.0
    eval_count: Optional[int] = None
    prompt_eval_count: Optional[int] = None
    grounding_result: Optional[Dict[str, Any]] = None
    model_config = ConfigDict(arbitrary_types_allowed=True)


class I6ExecutionResult(BaseModel):
    """Result of an authoritative I6 protected 3B->7B invariant handoff generation attempt."""
    raw_response: str
    parsed_json: Optional[Dict[str, Any]] = None
    canonical_hypothesis: Optional[HypothesisModelOutput] = None
    serialized_handoff: str
    handoff_hash: str
    invariant: str
    evidence_gap_type: str
    raw_3b_output: Optional[Dict[str, Any]] = None
    classification: FailureClassificationResult
    latency_ms: float = 0.0
    eval_count: Optional[int] = None
    prompt_eval_count: Optional[int] = None
    grounding_result: Optional[Dict[str, Any]] = None
    fail_closed: bool = False
    fail_closed_reason: Optional[str] = None
    model_config = ConfigDict(arbitrary_types_allowed=True)


class M5ExecutionResult(BaseModel):
    """Result of an authoritative M5 composable contract generation attempt."""
    raw_response: str = ""
    protocol: OutputProtocolIdentifier
    parsed_intermediate: Optional[Any] = None
    canonical_hypothesis: Optional[HypothesisModelOutput] = None
    classification: FailureClassificationResult
    latency_ms: float = 0.0
    eval_count: Optional[int] = None
    prompt_eval_count: Optional[int] = None
    grounding_result: Optional[Dict[str, Any]] = None
    policy_result: Optional[Any] = None
    contract_valid: bool = True
    compilation_error: Optional[str] = None

    # Structured Phase 10 Runtime Control & Telemetry
    timed_out: bool = False
    prompt_build_latency_ms: Optional[float] = None
    inference_latency_ms: Union[float, str] = "unavailable"
    response_parse_latency_ms: Optional[float] = None
    validation_latency_ms: Optional[float] = None
    total_latency_ms: float = 0.0

    model_config = ConfigDict(arbitrary_types_allowed=True)


def classify_primary_failure(
    transport_error: Optional[Exception] = None,
    raw_response: Optional[str] = None,
    eval_count: Optional[int] = None,
    done_reason: Optional[str] = None,
    num_predict: int = 300,
    parsed_json: Optional[Dict[str, Any]] = None,
    parse_error: Optional[Exception] = None,
    schema_error: Optional[Exception] = None,
    grounding_error: Optional[str] = None,
    polarity_error: Optional[str] = None,
    is_timeout: bool = False,
) -> FailureClassificationResult:
    """
    Deterministically classify an evaluation attempt into exactly one mutually exclusive PRIMARY category.

    Precedence:
    RUNTIME_TIMEOUT > RUNTIME_TRANSPORT_FAILURE > MAX_TOKEN_TRUNCATION > PARSER_FAILURE > SCHEMA_VALIDITY_FAILURE > SEMANTIC_GROUNDING_FAILURE > SEMANTIC_EXPERIMENT_POLARITY_FAILURE > VALID
    """
    cascade: List[str] = []

    # 1. RUNTIME_TIMEOUT (Precedence 1)
    if is_timeout:
        return FailureClassificationResult(
            primary_category=PrimaryFailureCategory.RUNTIME_TIMEOUT,
            is_valid=False,
            error_message=str(transport_error) if transport_error else "Hard runtime ceiling exceeded (30,000 ms)",
            downstream_cascade=[],
            diagnostic_details={"is_timeout": True, "exception_type": type(transport_error).__name__ if transport_error else "TimeoutError"},
        )

    if transport_error is not None:
        exc_type = type(transport_error).__name__
        exc_msg = str(transport_error).lower()
        is_timeout_exc = (
            isinstance(transport_error, TimeoutError)
            or "timeout" in exc_type.lower()
            or "timed out" in exc_msg
            or getattr(transport_error, "is_timeout", False)
        )
        if is_timeout_exc:
            return FailureClassificationResult(
                primary_category=PrimaryFailureCategory.RUNTIME_TIMEOUT,
                is_valid=False,
                error_message=f"Hard runtime ceiling exceeded: {transport_error}",
                downstream_cascade=[],
                diagnostic_details={"exception_type": exc_type, "is_timeout": True},
            )

        return FailureClassificationResult(
            primary_category=PrimaryFailureCategory.RUNTIME_TRANSPORT_FAILURE,
            is_valid=False,
            error_message=str(transport_error),
            downstream_cascade=[],
            diagnostic_details={"exception_type": exc_type, "is_timeout": False},
        )

    # Check whether generation reached num_predict or was stopped by length
    is_truncation = False
    if eval_count is not None and eval_count >= num_predict:
        is_truncation = True
    elif done_reason == "length":
        is_truncation = True

    # 2. MAX_TOKEN_TRUNCATION (Precedence 2)
    # If output reached num_predict and failed parsing or schema validation, it is primary truncation.
    if is_truncation and (parse_error is not None or schema_error is not None or parsed_json is None):
        if parse_error is not None:
            cascade.append(PrimaryFailureCategory.PARSER_FAILURE.value)
        if schema_error is not None:
            cascade.append(PrimaryFailureCategory.SCHEMA_VALIDITY_FAILURE.value)
        return FailureClassificationResult(
            primary_category=PrimaryFailureCategory.MAX_TOKEN_TRUNCATION,
            is_valid=False,
            error_message=f"Terminated at {num_predict} token ceiling mid-generation (eval_count={eval_count}, done_reason={done_reason})",
            downstream_cascade=cascade,
            diagnostic_details={
                "eval_count": eval_count,
                "done_reason": done_reason,
                "raw_length_chars": len(raw_response) if raw_response else 0,
            },
        )

    # 3. PARSER_FAILURE (Precedence 3)
    if parse_error is not None:
        return FailureClassificationResult(
            primary_category=PrimaryFailureCategory.PARSER_FAILURE,
            is_valid=False,
            error_message=f"Invalid JSON syntax: {parse_error}",
            downstream_cascade=[],
            diagnostic_details={"exception_type": type(parse_error).__name__},
        )

    # 4. SCHEMA_VALIDITY_FAILURE (Precedence 4)
    if schema_error is not None:
        return FailureClassificationResult(
            primary_category=PrimaryFailureCategory.SCHEMA_VALIDITY_FAILURE,
            is_valid=False,
            error_message=f"Schema validation error: {schema_error}",
            downstream_cascade=[],
            diagnostic_details={"exception_type": type(schema_error).__name__},
        )

    # 5. SEMANTIC_GROUNDING_FAILURE (Precedence 5)
    if grounding_error is not None:
        return FailureClassificationResult(
            primary_category=PrimaryFailureCategory.SEMANTIC_GROUNDING_FAILURE,
            is_valid=False,
            error_message=f"Grounding failure: {grounding_error}",
            downstream_cascade=[],
            diagnostic_details={"grounding_error": grounding_error},
        )

    # 6. SEMANTIC_EXPERIMENT_POLARITY_FAILURE (Precedence 6)
    if polarity_error is not None:
        return FailureClassificationResult(
            primary_category=PrimaryFailureCategory.SEMANTIC_EXPERIMENT_POLARITY_FAILURE,
            is_valid=False,
            error_message=f"Experiment polarity failure: {polarity_error}",
            downstream_cascade=[],
            diagnostic_details={"polarity_error": polarity_error},
        )

    # 0. VALID
    return FailureClassificationResult(
        primary_category=PrimaryFailureCategory.VALID,
        is_valid=True,
        error_message=None,
        downstream_cascade=[],
        diagnostic_details={},
    )


def perform_diagnostic_repair(
    raw_dict: Dict[str, Any],
    target_asset: Optional[Dict[str, Any]] = None,
    category_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    DIAGNOSTIC ONLY.
    Records what post-hoc repairs could theoretically be applied.
    MUST NOT alter authoritative scoring or upgrade invalid outputs to valid.
    """
    repaired = dict(raw_dict)
    repairs_applied = []

    if not repaired.get("affected_target") and target_asset and target_asset.get("asset_id"):
        repaired["affected_target"] = target_asset["asset_id"]
        repairs_applied.append("injected_affected_target_from_context")

    if not repaired.get("decision"):
        repaired["decision"] = HypothesisDecision.NO_RELEVANT_FUNCTIONALITY.value
        repairs_applied.append("defaulted_missing_decision_to_abstention")

    cleaned_ids = []
    for eid in repaired.get("supporting_evidence_ids", []):
        if isinstance(eid, str):
            cleaned = eid.strip()
            if cleaned.startswith("EVIDENCE [") and cleaned.endswith("]"):
                cleaned = cleaned[10:-1].strip()
            elif cleaned.startswith("[") and cleaned.endswith("]"):
                cleaned = cleaned[1:-1].strip()
            elif cleaned.startswith("EVIDENCE-"):
                cleaned = cleaned[9:].strip()
            if cleaned != eid:
                repairs_applied.append(f"cleaned_evidence_id_prefix:{eid}->{cleaned}")
            cleaned_ids.append(cleaned)
        else:
            cleaned_ids.append(str(eid))
    repaired["supporting_evidence_ids"] = cleaned_ids

    return {
        "diagnostic_only": True,
        "repairs_applied": repairs_applied,
        "repaired_dict": repaired,
    }
