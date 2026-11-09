"""Hypothesis state machine managing revisions, transitions, and human verification records."""

import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from src.database.manager import DatabaseManager
from src.engine.models import HypothesisDecision, HypothesisModelOutput
from src.hypothesis.experiment import ExperimentProposal


class HypothesisState(str, Enum):
    NEW = "New"
    UNDER_REVIEW = "Under Review"
    CONFIRMED = "Confirmed"
    REJECTED = "Rejected"
    REPORTED = "Reported"


class EvidenceState(str, Enum):
    NONE = "NONE"
    WEAK = "WEAK"
    PARTIAL = "PARTIAL"
    STRONG = "STRONG"


class HypothesisStateMachine:
    """
    Manages the lifecycle, versioned revisions, and verification boundaries
    of security hypotheses.
    """

    def __init__(self, db_manager: DatabaseManager) -> None:
        self.db_manager = db_manager

    def create_hypothesis(
        self,
        output: HypothesisModelOutput,
        experiment: Optional[ExperimentProposal] = None,
    ) -> int:
        """Create a new hypothesis record in state 'New'."""
        data = {
            "asset_id": output.asset_id,
            "category": output.category,
            "decision": output.decision.value,
            "evidence_state": EvidenceState.PARTIAL.value if output.decision == HypothesisDecision.HYPOTHESIS else EvidenceState.NONE.value,
            "actor_identity_id": output.actor_identity_id,
            "target_identity_id": output.target_identity_id,
            "reasoning_summary": output.reasoning_summary or (output.app_model_delta.observation if output.app_model_delta else ""),
            "missing_evidence": output.missing_evidence,
            "experiment_proposal": experiment.model_dump() if experiment else output.experiment_proposal,
            "state": HypothesisState.NEW.value,
            "revision": 1,
        }
        return self.db_manager.insert_hypothesis(data)

    def start_review(self, hypothesis_id: int) -> None:
        """Move hypothesis from New to Under Review."""
        hyp = self.db_manager.get_hypothesis(hypothesis_id)
        if not hyp:
            raise ValueError(f"Hypothesis {hypothesis_id} not found")
        if hyp["state"] != HypothesisState.NEW.value:
            raise ValueError(f"Cannot start review on hypothesis in state {hyp['state']}")
        self.db_manager.update_hypothesis_state(hypothesis_id, HypothesisState.UNDER_REVIEW.value)

    def revise_with_experiment_observation(
        self,
        hypothesis_id: int,
        observation_type: str, # "SUPPORTING", "CONTRADICTING", "UNRESOLVED"
        new_evidence_ref: str,
        observation_notes: str,
    ) -> Dict[str, Any]:
        """
        Incorporate new experimental evidence from human test or simulator into hypothesis.
        """
        hyp = self.db_manager.get_hypothesis(hypothesis_id)
        if not hyp:
            raise ValueError(f"Hypothesis {hypothesis_id} not found")

        current_rev = hyp.get("revision", 1)
        new_rev = current_rev + 1

        with self.db_manager.get_connection() as conn:
            with conn:
                if observation_type == "SUPPORTING":
                    # Evidence confirmed by experiment -> Elevate evidence state to STRONG
                    conn.execute(
                        """
                        UPDATE hypotheses
                        SET revision = ?, evidence_state = ?, evidence_ref = ?, updated_at = CURRENT_TIMESTAMP
                        WHERE id = ?
                        """,
                        (new_rev, EvidenceState.STRONG.value, new_evidence_ref, hypothesis_id),
                    )
                elif observation_type == "CONTRADICTING":
                    # Experiment disproved hypothesis -> Transition to Rejected
                    conn.execute(
                        """
                        UPDATE hypotheses
                        SET revision = ?, state = ?, evidence_ref = ?, updated_at = CURRENT_TIMESTAMP
                        WHERE id = ?
                        """,
                        (new_rev, HypothesisState.REJECTED.value, new_evidence_ref, hypothesis_id),
                    )
                elif observation_type == "UNRESOLVED":
                    # Inconclusive/error observation -> Retain state, downgrade evidence state to WEAK
                    conn.execute(
                        """
                        UPDATE hypotheses
                        SET revision = ?, evidence_state = ?, evidence_ref = ?, updated_at = CURRENT_TIMESTAMP
                        WHERE id = ?
                        """,
                        (new_rev, EvidenceState.WEAK.value, new_evidence_ref, hypothesis_id),
                    )

        return self.db_manager.get_hypothesis(hypothesis_id)

    def confirm_with_human_verification(
        self,
        hypothesis_id: int,
        actor: str,
        evidence_ref: str,
        session_id: str,
        notes: Optional[str] = None,
    ) -> str:
        """
        Atomically records human verification and moves hypothesis to Confirmed.
        Satisfies database triggers enforcing evidence and verification records in a single transaction.
        """
        return self.db_manager.confirm_hypothesis_atomic(
            hypothesis_id=hypothesis_id,
            actor=actor,
            evidence_ref=evidence_ref,
            dashboard_session_id=session_id,
            notes=notes,
        )

    def report_hypothesis(self, hypothesis_id: int) -> None:
        """Transition Confirmed hypothesis to Reported."""
        hyp = self.db_manager.get_hypothesis(hypothesis_id)
        if not hyp:
            raise ValueError(f"Hypothesis {hypothesis_id} not found")
        if hyp["state"] != HypothesisState.CONFIRMED.value:
            raise ValueError(f"Cannot report hypothesis in state '{hyp['state']}'. Must be 'Confirmed'.")
        self.db_manager.update_hypothesis_state(hypothesis_id, HypothesisState.REPORTED.value)

