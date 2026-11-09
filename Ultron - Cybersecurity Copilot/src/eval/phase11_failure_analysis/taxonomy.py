"""
Milestone M5 Phase 11.1: Failure Taxonomy Definitions.

Defines the explicit, deterministic taxonomy codes F01-F17, F99,
distinguishing observed telemetry and validator states from inferred mechanism hypotheses.
"""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class FailureCode(str, Enum):
    """Explicit deterministic failure taxonomy codes for Phase 11."""
    F01 = "VALID_TYPED"
    F02 = "RUNTIME_TIMEOUT"
    F03 = "TRANSPORT_FAILURE"
    F04 = "PARSER_FAILURE"
    F05 = "SCHEMA_FAILURE"
    F06 = "GROUNDING_FAILURE"
    F07 = "POLARITY_FAILURE"
    F08 = "ACTION_SELECTION_FAILURE"
    F09 = "CATEGORY_SELECTION_FAILURE"
    F10 = "EVIDENCE_INTERPRETATION_FAILURE"
    F11 = "ABSTENTION_TOO_EARLY"
    F12 = "CONTEXT_OVERLOAD_OR_CONTEXT_CONFUSION"
    F13 = "RAG_DISTRACTION_OR_RAG_CONFLICT"
    F14 = "CASCADE_HANDOFF_FAILURE"
    F15 = "IDENTIFIER_CONFUSION"
    F16 = "SEMANTIC_STATE_POLARITY_MISMATCH"
    F17 = "OTHER"
    F99 = "UNRESOLVED"


class FailureNature(str, Enum):
    """Epistemic nature of the failure classification."""
    SUCCESS = "SUCCESS"
    OBSERVED_TELEMETRY = "OBSERVED_TELEMETRY"
    OBSERVED_RUNTIME = "OBSERVED_RUNTIME"
    OBSERVED_SYNTAX = "OBSERVED_SYNTAX"
    OBSERVED_PROTOCOL = "OBSERVED_PROTOCOL"
    OBSERVED_GROUNDING = "OBSERVED_GROUNDING"
    OBSERVED_SEMANTICS = "OBSERVED_SEMANTICS"
    OBSERVED_ACTION = "OBSERVED_ACTION"
    OBSERVED_DECISION = "OBSERVED_DECISION"
    OBSERVED_RESIDUAL = "OBSERVED_RESIDUAL"
    INFERRED_MECHANISM = "INFERRED_MECHANISM"
    FAIL_SAFE_DEFAULT = "FAIL_SAFE_DEFAULT"


TAXONOMY_METADATA: Dict[FailureCode, Dict[str, Any]] = {
    FailureCode.F01: {
        "name": "VALID_TYPED",
        "nature": FailureNature.SUCCESS,
        "description": "Passed all protocol, polarity, and skeleton validations; valid typed experiment.",
    },
    FailureCode.F02: {
        "name": "RUNTIME_TIMEOUT",
        "nature": FailureNature.OBSERVED_TELEMETRY,
        "description": "Exceeded the 30.0s hard inference ceiling or cancelled by wall-clock deadline.",
    },
    FailureCode.F03: {
        "name": "TRANSPORT_FAILURE",
        "nature": FailureNature.OBSERVED_RUNTIME,
        "description": "Transport, connection, HTTP 5xx, or network socket failure.",
    },
    FailureCode.F04: {
        "name": "PARSER_FAILURE",
        "nature": FailureNature.OBSERVED_SYNTAX,
        "description": "Malformed JSON, non-JSON output, or syntactic AST decoding failure.",
    },
    FailureCode.F05: {
        "name": "SCHEMA_FAILURE",
        "nature": FailureNature.OBSERVED_PROTOCOL,
        "description": "Missing required fields, enum violations, or failure to satisfy protocol slots.",
    },
    FailureCode.F06: {
        "name": "GROUNDING_FAILURE",
        "nature": FailureNature.OBSERVED_GROUNDING,
        "description": "Cited identifiers, parameters, or endpoints outside the structural context slice.",
    },
    FailureCode.F07: {
        "name": "POLARITY_FAILURE",
        "nature": FailureNature.OBSERVED_SEMANTICS,
        "description": "Breach/safe predicate outcomes inverted, invalid, or identical outcomes emitted.",
    },
    FailureCode.F08: {
        "name": "ACTION_SELECTION_FAILURE",
        "nature": FailureNature.OBSERVED_ACTION,
        "description": "Model proposed an experiment action incompatible with the vulnerability category.",
    },
    FailureCode.F09: {
        "name": "CATEGORY_SELECTION_FAILURE",
        "nature": FailureNature.OBSERVED_SEMANTICS,
        "description": "Model hypothesis category inconsistent with scenario ground truth or target asset.",
    },
    FailureCode.F10: {
        "name": "EVIDENCE_INTERPRETATION_FAILURE",
        "nature": FailureNature.INFERRED_MECHANISM,
        "description": "Model misinterpreted observed evidence statements or route invariants.",
    },
    FailureCode.F11: {
        "name": "ABSTENTION_TOO_EARLY",
        "nature": FailureNature.OBSERVED_DECISION,
        "description": "Model autonomously abstained on a ground-truth vulnerable variant with observable anomaly.",
    },
    FailureCode.F12: {
        "name": "CONTEXT_OVERLOAD_OR_CONTEXT_CONFUSION",
        "nature": FailureNature.INFERRED_MECHANISM,
        "description": "Heavy context package (Track D) correlated with timeout, truncation, or citation drift.",
    },
    FailureCode.F13: {
        "name": "RAG_DISTRACTION_OR_RAG_CONFLICT",
        "nature": FailureNature.INFERRED_MECHANISM,
        "description": "Generic VAPT knowledge chunks diverted attention or introduced conflicting terminology.",
    },
    FailureCode.F14: {
        "name": "CASCADE_HANDOFF_FAILURE",
        "nature": FailureNature.INFERRED_MECHANISM,
        "description": "Upstream 3B triage descriptor mischaracterized evidence gap or induced false anchoring.",
    },
    FailureCode.F15: {
        "name": "IDENTIFIER_CONFUSION",
        "nature": FailureNature.INFERRED_MECHANISM,
        "description": "Cross-parameter, cross-identity, or asset identifier substitution/confusion.",
    },
    FailureCode.F16: {
        "name": "SEMANTIC_STATE_POLARITY_MISMATCH",
        "nature": FailureNature.INFERRED_MECHANISM,
        "description": "Exact polarity inversion: supporting outcome in safe set and disproving outcome in breach set.",
    },
    FailureCode.F17: {
        "name": "OTHER",
        "nature": FailureNature.OBSERVED_RESIDUAL,
        "description": "Anomalous failure mode not captured by standard taxonomy codes F01-F16.",
    },
    FailureCode.F99: {
        "name": "UNRESOLVED",
        "nature": FailureNature.FAIL_SAFE_DEFAULT,
        "description": "Failure pattern ambiguous or unresolvable under deterministic diagnostic rules.",
    },
}


class FailureAttributionResult(BaseModel):
    """Container for deterministic failure attribution on a single call record."""
    model_config = ConfigDict(frozen=True)

    primary_code: FailureCode = Field(..., description="Single primary failure code by strict precedence")
    primary_name: str = Field(..., description="Descriptive name of primary failure")
    contributing_codes: List[FailureCode] = Field(..., description="All contributing observed and inferred failure codes")
    observed_validator_failure: str = Field(..., description="Raw primary failure category from validator")
    is_valid_typed: bool = Field(default=False, description="Whether record is a valid typed experiment")
    is_hypothesis_candidate: bool = Field(default=False, description="Whether record attempted a candidate hypothesis")
    is_action_compatible: bool = Field(default=False, description="Whether selected action is compatible with category")
    is_polarity_valid: bool = Field(default=False, description="Whether polarity validation passed")
    is_grounding_valid: bool = Field(default=False, description="Whether grounding validation passed")
    is_exact_polarity_inversion: bool = Field(default=False, description="True if supporting is safe and disproving is breach")
    details: Dict[str, Any] = Field(default_factory=dict, description="Diagnostic details and extracted tokens")
