"""Deterministic State Machine for Milestone 11 Controlled Experiments.

Enforces:
1. Strict linear progression with guarded branch points.
2. Terminal states are immutable sinks.
3. Transition audit logging with timestamps, actor attribution, and reasons.
4. Human verification gate: AI/system identities cannot transition to APPROVED.
5. Invariant checking before every state mutation.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set
from src.experiment.models import ControlledExperiment, ExperimentStatus


class InvalidStateTransitionError(Exception):
    """Raised when an illegal lifecycle transition is attempted."""
    pass


class HumanApprovalRejectedError(Exception):
    """Raised when an invalid or non-human identity attempts approval."""
    pass


FORBIDDEN_APPROVAL_IDENTITIES: Set[str] = {
    "ai", "system", "llm", "agent", "bot", "automation", "assistant",
    "model", "qwen", "qwen2.5-coder", "ollama", "auto", "evaluator",
}


class ExperimentStateMachine:
    """Manages state transitions for ControlledExperiment entities."""

    VALID_TRANSITIONS: Dict[ExperimentStatus, Set[ExperimentStatus]] = {
        ExperimentStatus.DRAFT: {
            ExperimentStatus.PROPOSED,
            ExperimentStatus.ABORTED,
        },
        ExperimentStatus.PROPOSED: {
            ExperimentStatus.PREFLIGHT,
            ExperimentStatus.REJECTED,
            ExperimentStatus.ABORTED,
        },
        ExperimentStatus.PREFLIGHT: {
            ExperimentStatus.AWAITING_HUMAN_APPROVAL,
            ExperimentStatus.BLOCKED,
            ExperimentStatus.REJECTED,
            ExperimentStatus.ABORTED,
        },
        ExperimentStatus.AWAITING_HUMAN_APPROVAL: {
            ExperimentStatus.APPROVED,
            ExperimentStatus.REJECTED,
            ExperimentStatus.EXPIRED,
            ExperimentStatus.ABORTED,
        },
        ExperimentStatus.APPROVED: {
            ExperimentStatus.READY,
            ExperimentStatus.ABORTED,
            ExperimentStatus.EXPIRED,
        },
        ExperimentStatus.READY: {
            ExperimentStatus.EXECUTING,
            ExperimentStatus.ABORTED,
            ExperimentStatus.BLOCKED,
        },
        ExperimentStatus.EXECUTING: {
            ExperimentStatus.OBSERVATIONS_CAPTURED,
            ExperimentStatus.FAILED,
            ExperimentStatus.ABORTED,
        },
        ExperimentStatus.OBSERVATIONS_CAPTURED: {
            ExperimentStatus.FALSIFICATION,
            ExperimentStatus.FAILED,
            ExperimentStatus.ABORTED,
        },
        ExperimentStatus.FALSIFICATION: {
            ExperimentStatus.REVIEW,
            ExperimentStatus.FAILED,
            ExperimentStatus.ABORTED,
        },
        ExperimentStatus.REVIEW: {
            ExperimentStatus.COMPLETED,
            ExperimentStatus.REJECTED,
            ExperimentStatus.ABORTED,
        },
        # Terminal states have no outbound transitions
        ExperimentStatus.COMPLETED: set(),
        ExperimentStatus.REJECTED: set(),
        ExperimentStatus.BLOCKED: set(),
        ExperimentStatus.FAILED: set(),
        ExperimentStatus.ABORTED: set(),
        ExperimentStatus.EXPIRED: set(),
    }

    @classmethod
    def can_transition(cls, current_status: ExperimentStatus, target_status: ExperimentStatus) -> bool:
        allowed = cls.VALID_TRANSITIONS.get(current_status, set())
        return target_status in allowed

    @classmethod
    def transition(
        cls,
        experiment: ControlledExperiment,
        target_status: ExperimentStatus,
        actor: str,
        reason: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ControlledExperiment:
        """
        Executes a deterministic state transition on a ControlledExperiment.
        Enforces validation rules, logs state history, and fails closed on invalid attempts.
        """
        if not cls.can_transition(experiment.status, target_status):
            raise InvalidStateTransitionError(
                f"Illegal state transition from {experiment.status.value} to {target_status.value} "
                f"for experiment {experiment.experiment_id}."
            )

        actor_clean = (actor or "").strip()
        if not actor_clean:
            raise ValueError("State transition requires a non-empty actor identity.")

        # Guard Human Approval: INV-M11-04
        if target_status == ExperimentStatus.APPROVED:
            if actor_clean.lower() in FORBIDDEN_APPROVAL_IDENTITIES:
                raise HumanApprovalRejectedError(
                    f"Forbidden actor identity '{actor_clean}'. AI/system identities cannot approve experiments (INV-M11-04)."
                )

        now_iso = datetime.now(timezone.utc).isoformat()
        history_entry = {
            "from_state": experiment.status.value,
            "to_state": target_status.value,
            "timestamp": now_iso,
            "actor": actor_clean,
            "reason": reason,
            "metadata": metadata or {},
        }

        experiment.status = target_status
        experiment.state_history.append(history_entry)

        if target_status in (
            ExperimentStatus.COMPLETED,
            ExperimentStatus.REJECTED,
            ExperimentStatus.BLOCKED,
            ExperimentStatus.FAILED,
            ExperimentStatus.ABORTED,
            ExperimentStatus.EXPIRED,
        ):
            experiment.completed_at = now_iso

        return experiment
