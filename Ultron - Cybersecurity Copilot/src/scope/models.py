"""Scope Gate data models and policy definitions."""

import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator


class ScopeDecision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"


class ToolPolicy(str, Enum):
    PASSIVE = "passive"
    LOW_IMPACT_ACTIVE = "low_impact_active"
    ACTIVE = "active"


class ScopeDecisionObject(BaseModel):
    """
    Auditable scope decision object generated for every target URL evaluation.
    Every downstream fact references scope_decision_id.
    """
    scope_decision_id: str
    decision: ScopeDecision
    requested_url: str
    canonical_host: str
    resolved_addresses: List[str] = Field(default_factory=list)
    matched_rule: Optional[str] = None
    out_of_scope_rule: Optional[str] = None
    tool_policy: ToolPolicy
    reason: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    scope_policy_version: str = "v6"
    scope_policy_hash: Optional[str] = None

    @classmethod
    def create(
        cls,
        decision: ScopeDecision,
        requested_url: str,
        canonical_host: str,
        resolved_addresses: List[str],
        tool_policy: ToolPolicy,
        reason: str,
        matched_rule: Optional[str] = None,
        out_of_scope_rule: Optional[str] = None,
        scope_policy_version: str = "v6",
        scope_policy_hash: Optional[str] = None,
    ) -> "ScopeDecisionObject":
        # Deterministic decision ID derived from target, resolved IPs, decision, and policy version/hash
        seed = f"{decision.value}:{requested_url}:{canonical_host}:{','.join(sorted(resolved_addresses))}:{tool_policy.value}:{scope_policy_version}:{scope_policy_hash or ''}"
        decision_id = f"SCOPE-{hashlib.sha256(seed.encode('utf-8')).hexdigest()[:12].upper()}"
        return cls(
            scope_decision_id=decision_id,
            decision=decision,
            requested_url=requested_url,
            canonical_host=canonical_host,
            resolved_addresses=resolved_addresses,
            matched_rule=matched_rule,
            out_of_scope_rule=out_of_scope_rule,
            tool_policy=tool_policy,
            reason=reason,
            scope_policy_version=scope_policy_version,
            scope_policy_hash=scope_policy_hash,
        )


class ScopePolicy(BaseModel):
    """Parsed and validated scope.yaml policy."""
    program_name: str
    platform: str
    scope_policy_version: str = "v6"
    in_scope: List[str]
    out_of_scope: List[str] = Field(default_factory=list)
    program_constraints: Dict[str, Any] = Field(default_factory=dict)
    rules_of_engagement: Dict[str, Any] = Field(default_factory=dict)
    tool_policy: Dict[str, ToolPolicy] = Field(default_factory=dict)

    def compute_policy_hash(self) -> str:
        """Deterministic canonical SHA-256 digest of immutable policy fields."""
        import json
        payload = {
            "program_name": self.program_name,
            "platform": self.platform,
            "scope_policy_version": self.scope_policy_version,
            "in_scope": sorted(self.in_scope),
            "out_of_scope": sorted(self.out_of_scope),
            "program_constraints": self.program_constraints,
            "rules_of_engagement": self.rules_of_engagement,
            "tool_policy": {k: v.value if hasattr(v, "value") else str(v) for k, v in sorted(self.tool_policy.items())},
        }
        raw = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
        return f"POL-{hashlib.sha256(raw).hexdigest()[:16].upper()}"

    @property
    def policy_hash(self) -> str:
        return self.compute_policy_hash()


class AssessmentScopeStatus(str, Enum):
    """M6 Assessment Scope decision states and explicit evaluation outcomes."""
    IN_SCOPE = "IN_SCOPE"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    UNKNOWN = "UNKNOWN"
    SCOPE_UNVERIFIABLE = "SCOPE_UNVERIFIABLE"
    AUTHORIZATION_EXPIRED = "AUTHORIZATION_EXPIRED"
    POLICY_VERSION_MISMATCH = "POLICY_VERSION_MISMATCH"
    SCOPE_EVALUATION_ERROR = "SCOPE_EVALUATION_ERROR"


# Alias for explicit internal outcome typing
ScopeEvaluationOutcome = AssessmentScopeStatus


class ExtendedScopeDecisionResult(BaseModel):
    """M6 Auditable multi-target scope evaluation result."""
    scope_status: AssessmentScopeStatus
    is_permitted: bool
    target_identifier: str
    asset_type: Optional[str] = None
    matched_rule: Optional[str] = None
    out_of_scope_rule: Optional[str] = None
    reason: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    scope_policy_version: Optional[str] = None
    scope_policy_hash: Optional[str] = None
