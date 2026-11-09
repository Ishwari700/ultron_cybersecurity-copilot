"""Milestone M11.5: Human Approval + Execution Gate.

Enforces:
1. Strict Human Control: AI/system identities cannot approve experiments (INV-M11-04).
2. Explicit Attribution: Human approval requires valid, non-empty identity string.
3. Execution Authorization Token Generation:
   - Cryptographically binds experiment_id, assessment_id, target, action hash, and expiration (Section 8.3).
   - Prevents runtime action mutation / drift (INV-M11-03).
4. Full Pre-Execution Disclosure: Displays all 11 required safety fields before execution.
"""

from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Dict, List, Optional, Set
from pydantic import BaseModel, Field

from src.experiment.models import (
    ControlledExperiment,
    ExecutionAuthorizationToken,
    ExperimentRiskLevel,
    ExperimentStatus,
)
from src.experiment.poc import SafePoC
from src.experiment.preflight import PreflightReport
from src.experiment.state_machine import (
    ExperimentStateMachine,
    HumanApprovalRejectedError,
    FORBIDDEN_APPROVAL_IDENTITIES,
)
from src.audit.ledger import AuditLedger
from src.audit.models import AuditEventType


class HumanApprovalRequest(BaseModel):
    """
    Complete human approval packet displaying the 11 required security fields (Section 8.1).
    """
    experiment_id: str
    assessment_id: str
    hypothesis_id: str
    objective: str
    target_environment: str
    authorization_status: str
    scope_status: str
    risk_level: ExperimentRiskLevel
    actions: List[Dict[str, Any]] = Field(default_factory=list)
    expected_observations: List[str] = Field(default_factory=list)
    negative_controls: List[Dict[str, Any]] = Field(default_factory=list)
    rollback_plan: Optional[Dict[str, Any]] = None
    evidence_required: List[str] = Field(default_factory=list)
    requested_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class HumanApprovalGate:
    """
    Authoritative Human Approval and Token Issuance Gate.
    """

    @classmethod
    def create_approval_request(
        cls,
        experiment: ControlledExperiment,
        poc: Optional[SafePoC] = None,
        preflight: Optional[PreflightReport] = None,
    ) -> HumanApprovalRequest:
        """
        Builds the structured approval packet presenting the 11 mandatory fields.
        """
        obj = poc.objective if poc else f"Experiment {experiment.experiment_id} for hypothesis {experiment.hypothesis_id}"
        target_env = poc.target_environment if poc else experiment.environment_type.value
        ev_reqs = poc.evidence_requirements if poc else ["Stdout/Stderr", "Exit code", "Status"]

        auth_stat = preflight.authorization_detail if preflight else experiment.authorization_reference
        scope_stat = preflight.scope_detail if preflight else experiment.scope_reference

        return HumanApprovalRequest(
            experiment_id=experiment.experiment_id,
            assessment_id=experiment.assessment_id,
            hypothesis_id=experiment.hypothesis_id,
            objective=obj,
            target_environment=target_env,
            authorization_status=auth_stat,
            scope_status=scope_stat,
            risk_level=experiment.risk_level,
            actions=experiment.proposed_actions,
            expected_observations=experiment.expected_observations,
            negative_controls=experiment.negative_controls,
            rollback_plan=experiment.rollback_plan.model_dump() if experiment.rollback_plan else None,
            evidence_required=ev_reqs,
        )

    @classmethod
    def submit_human_approval(
        cls,
        experiment: ControlledExperiment,
        approver_identity: str,
        comments: str = "Approved by human researcher",
        ttl_seconds: int = 300,
        audit_ledger: Optional[AuditLedger] = None,
    ) -> ExecutionAuthorizationToken:
        """
        Processes human approval and issues short-lived ExecutionAuthorizationToken.
        Fails closed if the identity is AI, system, or empty (INV-M11-04).
        """
        clean_identity = (approver_identity or "").strip()
        if not clean_identity:
            raise HumanApprovalRejectedError("Human approval requires a non-empty identity string.")

        clean_lower = clean_identity.lower()
        if clean_lower in FORBIDDEN_APPROVAL_IDENTITIES:
            raise HumanApprovalRejectedError(
                f"Forbidden approval actor '{clean_identity}'. AI/system identities cannot approve experiments (INV-M11-04)."
            )

        # Check substrings for compound AI/system names (e.g. "my_ai_agent", "system_orchestrator", "ollama_bot", "auto_approver")
        for forbidden in ("ai_", "_ai", "bot", "llm", "agent", "automated", "qwen", "ollama", "system", "orchestrator", "model", "auto"):
            if forbidden in clean_lower:
                raise HumanApprovalRejectedError(
                    f"Forbidden approval actor '{clean_identity}'. AI/automated patterns rejected (INV-M11-04)."
                )

        # Generate cryptographic execution authorization token
        token = ExecutionAuthorizationToken.create(
            experiment_id=experiment.experiment_id,
            assessment_id=experiment.assessment_id,
            target_environment=experiment.environment_type.value,
            actions=experiment.proposed_actions,
            risk_level=experiment.risk_level,
            approved_by=clean_identity,
            ttl_seconds=ttl_seconds,
        )

        now_iso = datetime.now(timezone.utc).isoformat()
        experiment.human_approval = {
            "approved": True,
            "approved_by": clean_identity,
            "approved_at": now_iso,
            "comments": comments,
            "token_id": token.token_id,
        }
        experiment.execution_token = token

        # Transition state machine: AWAITING_HUMAN_APPROVAL -> APPROVED -> READY
        if experiment.status == ExperimentStatus.AWAITING_HUMAN_APPROVAL:
            ExperimentStateMachine.transition(
                experiment,
                ExperimentStatus.APPROVED,
                actor=clean_identity,
                reason=comments,
            )
            ExperimentStateMachine.transition(
                experiment,
                ExperimentStatus.READY,
                actor=clean_identity,
                reason="Experiment primed with valid ExecutionAuthorizationToken",
            )

        # Audit logging
        if audit_ledger:
            audit_ledger.append(
                actor=clean_identity,
                event_type=AuditEventType.HUMAN_APPROVED,
                object_id=experiment.experiment_id,
                metadata={
                    "token_id": token.token_id,
                    "action_hash": token.approved_action_hash,
                    "risk_level": experiment.risk_level.value,
                },
            )

        return token

    @classmethod
    def reject_approval(
        cls,
        experiment: ControlledExperiment,
        rejecter_identity: str,
        reason: str,
        audit_ledger: Optional[AuditLedger] = None,
    ) -> None:
        """
        Rejects the experiment proposal.
        """
        clean_identity = (rejecter_identity or "human_researcher").strip()
        experiment.human_approval = {
            "approved": False,
            "rejected_by": clean_identity,
            "rejected_at": datetime.now(timezone.utc).isoformat(),
            "reason": reason,
        }

        ExperimentStateMachine.transition(
            experiment,
            ExperimentStatus.REJECTED,
            actor=clean_identity,
            reason=f"Rejected by human: {reason}",
        )

        if audit_ledger:
            audit_ledger.append(
                actor=clean_identity,
                event_type=AuditEventType.FINDING_REJECTED,
                object_id=experiment.experiment_id,
                metadata={"reason": reason},
            )
