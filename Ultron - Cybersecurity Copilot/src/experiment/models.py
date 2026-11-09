"""Milestone M11: Experiment Domain Models and Safe PoC Schemas.

Defines the canonical data structures for:
1. Two-Plane Execution Model (Plane A: Isolated Lab vs Plane B: Authorized Target).
2. Controlled Experiment Domain Model and State Machine Enums.
3. Safe PoC Specification: Proof of Condition over Full Weaponized Exploitation.
4. Preflight, Execution Authorization Token, and Rollback Specifications.
"""

from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator


class ExecutionPlane(str, Enum):
    """The two execution planes defined by M11 Section 2."""
    PLANE_A_LOCAL_LAB = "PLANE_A_LOCAL_LAB"  # Isolated localhost, disposable service, synthetic fixture
    PLANE_B_AUTHORIZED_TARGET = "PLANE_B_AUTHORIZED_TARGET"  # Real/authorized target: Plan only, NO autonomous execution


class ExperimentEnvironmentType(str, Enum):
    """Execution environment classifications."""
    LOCAL_LAB = "LOCAL_LAB"
    SYNTHETIC_FIXTURE = "SYNTHETIC_FIXTURE"
    ISOLATED_CONTAINER = "ISOLATED_CONTAINER"
    DISPOSABLE_PROCESS = "DISPOSABLE_PROCESS"
    ANDROID_STATIC_TEST = "ANDROID_STATIC_TEST"
    AUTHORIZED_TARGET = "AUTHORIZED_TARGET"


class ExperimentRiskLevel(str, Enum):
    """Deterministic Experiment Risk Taxonomy."""
    LOW = "LOW"            # Local-only, read-only, benign canary, deterministic test fixture
    MEDIUM = "MEDIUM"      # Controlled state change, disposable local environment, reversible
    HIGH = "HIGH"          # External state mutation, privileged operation, sensitive action
    BLOCKED = "BLOCKED"    # Destructive, persistence, credential theft, unauthorized


class ExperimentStatus(str, Enum):
    """Deterministic Lifecycle State Machine for Controlled Security Experiments."""
    DRAFT = "DRAFT"
    PROPOSED = "PROPOSED"
    PREFLIGHT = "PREFLIGHT"
    AWAITING_HUMAN_APPROVAL = "AWAITING_HUMAN_APPROVAL"
    APPROVED = "APPROVED"
    READY = "READY"
    EXECUTING = "EXECUTING"
    OBSERVATIONS_CAPTURED = "OBSERVATIONS_CAPTURED"
    FALSIFICATION = "FALSIFICATION"
    REVIEW = "REVIEW"
    COMPLETED = "COMPLETED"

    # Terminal States
    REJECTED = "REJECTED"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"
    ABORTED = "ABORTED"
    EXPIRED = "EXPIRED"


class FalsificationOutcome(str, Enum):
    """Possible outcomes of hypothesis falsification analysis."""
    SUPPORTED = "SUPPORTED"
    WEAKLY_SUPPORTED = "WEAKLY_SUPPORTED"
    CONTESTED = "CONTESTED"
    REFUTED = "REFUTED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class RollbackPlan(BaseModel):
    """Specification of automated or manual cleanup/rollback operations."""
    rollback_id: str
    description: str
    actions: List[Dict[str, Any]] = Field(default_factory=list)
    timeout_seconds: int = 30
    requires_human_intervention: bool = False
    verified_clean_state_marker: Optional[str] = None


class ExecutionAuthorizationToken(BaseModel):
    """
    Short-lived cryptographically bound execution token.
    Binds experiment_id, assessment_id, target, approved actions, and human identity.
    """
    token_id: str
    experiment_id: str
    assessment_id: str
    target_environment: str
    approved_action_hash: str
    risk_level: ExperimentRiskLevel
    approved_by: str
    approved_at: str
    expires_at: str
    signature: str

    @classmethod
    def create(
        cls,
        experiment_id: str,
        assessment_id: str,
        target_environment: str,
        actions: List[Dict[str, Any]],
        risk_level: ExperimentRiskLevel,
        approved_by: str,
        ttl_seconds: int = 300,
    ) -> "ExecutionAuthorizationToken":
        action_bytes = json.dumps(actions, sort_keys=True).encode("utf-8")
        action_hash = hashlib.sha256(action_bytes).hexdigest()
        now = datetime.now(timezone.utc)
        approved_at_iso = now.isoformat()
        expires_at_iso = datetime.fromtimestamp(now.timestamp() + ttl_seconds, tz=timezone.utc).isoformat()

        token_seed = f"{experiment_id}:{assessment_id}:{target_environment}:{action_hash}:{risk_level.value}:{approved_by}:{approved_at_iso}"
        sig = hashlib.sha256(token_seed.encode("utf-8")).hexdigest()
        token_id = f"EXEC-TOK-{sig[:16].upper()}"

        return cls(
            token_id=token_id,
            experiment_id=experiment_id,
            assessment_id=assessment_id,
            target_environment=target_environment,
            approved_action_hash=action_hash,
            risk_level=risk_level,
            approved_by=approved_by,
            approved_at=approved_at_iso,
            expires_at=expires_at_iso,
            signature=sig,
        )

    def is_expired(self, current_time: Optional[float] = None) -> bool:
        t = current_time if current_time is not None else datetime.now(timezone.utc).timestamp()
        exp = datetime.fromisoformat(self.expires_at).timestamp()
        return t > exp

    def verify_action_integrity(self, actions: List[Dict[str, Any]]) -> bool:
        action_bytes = json.dumps(actions, sort_keys=True).encode("utf-8")
        current_hash = hashlib.sha256(action_bytes).hexdigest()
        return current_hash == self.approved_action_hash


class ControlledExperiment(BaseModel):
    """
    Canonical Controlled Experiment Entity for Milestone 11.
    Maintains complete provenance, preflight results, execution tokens, and observations.
    """
    experiment_id: str
    assessment_id: str
    hypothesis_id: str
    target_id: Optional[str] = None
    asset_id: Optional[str] = None
    execution_plane: ExecutionPlane = ExecutionPlane.PLANE_A_LOCAL_LAB
    environment_type: ExperimentEnvironmentType = ExperimentEnvironmentType.LOCAL_LAB
    authorization_reference: str
    scope_reference: str
    risk_level: ExperimentRiskLevel = ExperimentRiskLevel.LOW
    status: ExperimentStatus = ExperimentStatus.DRAFT
    preconditions: List[str] = Field(default_factory=list)
    proposed_actions: List[Dict[str, Any]] = Field(default_factory=list)
    expected_observations: List[str] = Field(default_factory=list)
    negative_controls: List[Dict[str, Any]] = Field(default_factory=list)
    safety_constraints: List[str] = Field(default_factory=list)
    rollback_plan: Optional[RollbackPlan] = None
    human_approval: Optional[Dict[str, Any]] = None
    execution_token: Optional[ExecutionAuthorizationToken] = None
    execution_record: Optional[Dict[str, Any]] = None
    observation_ids: List[str] = Field(default_factory=list)
    evidence_ids: List[str] = Field(default_factory=list)
    falsification_result: Optional[Dict[str, Any]] = None
    replay_records: List[Dict[str, Any]] = Field(default_factory=list)
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at: Optional[str] = None
    poc_id: Optional[str] = None
    state_history: List[Dict[str, Any]] = Field(default_factory=list)
    provenance: Dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def create(
        cls,
        assessment_id: str,
        hypothesis_id: str,
        authorization_reference: str,
        scope_reference: str,
        proposed_actions: List[Dict[str, Any]],
        target_id: Optional[str] = None,
        asset_id: Optional[str] = None,
        execution_plane: ExecutionPlane = ExecutionPlane.PLANE_A_LOCAL_LAB,
        environment_type: ExperimentEnvironmentType = ExperimentEnvironmentType.LOCAL_LAB,
        risk_level: ExperimentRiskLevel = ExperimentRiskLevel.LOW,
        expected_observations: Optional[List[str]] = None,
        negative_controls: Optional[List[Dict[str, Any]]] = None,
        safety_constraints: Optional[List[str]] = None,
        rollback_plan: Optional[RollbackPlan] = None,
        preconditions: Optional[List[str]] = None,
    ) -> "ControlledExperiment":
        seed = f"{assessment_id}:{hypothesis_id}:{execution_plane.value}:{json.dumps(proposed_actions, sort_keys=True)}"
        exp_id = f"EXP-M11-{hashlib.sha256(seed.encode('utf-8')).hexdigest()[:12].upper()}"

        init_history = [{
            "from_state": None,
            "to_state": ExperimentStatus.DRAFT.value,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "reason": "Experiment created in DRAFT",
            "actor": "system",
        }]

        return cls(
            experiment_id=exp_id,
            assessment_id=assessment_id,
            hypothesis_id=hypothesis_id,
            target_id=target_id,
            asset_id=asset_id,
            execution_plane=execution_plane,
            environment_type=environment_type,
            authorization_reference=authorization_reference,
            scope_reference=scope_reference,
            risk_level=risk_level,
            status=ExperimentStatus.DRAFT,
            preconditions=preconditions or [],
            proposed_actions=proposed_actions,
            expected_observations=expected_observations or [],
            negative_controls=negative_controls or [],
            safety_constraints=safety_constraints or [],
            rollback_plan=rollback_plan,
            state_history=init_history,
        )
