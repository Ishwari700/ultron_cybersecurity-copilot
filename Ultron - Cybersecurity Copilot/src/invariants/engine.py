"""Security Invariant generation and derivation engine."""

from typing import List, Optional
from src.core.logging import get_logger
from src.database.manager import DatabaseManager
from src.evidence.models import CanonicalEvidence, EpistemicCertainty
from src.graph.models import WorkflowNode
from src.invariants.models import InvariantConfidence, InvariantOrigin, SecurityInvariant

logger = get_logger("SecurityInvariantEngine")


class SecurityInvariantEngine:
    """
    Manages derivation and registration of Security Invariants across
    epistemic boundaries (DOCUMENTED, DETERMINISTIC_DERIVATION, MODEL_PROPOSED).
    """

    def __init__(self, db_manager: Optional[DatabaseManager] = None) -> None:
        self.db_manager = db_manager

    def derive_documented_invariants(self, evidence_items: List[CanonicalEvidence]) -> List[SecurityInvariant]:
        """
        Extract invariants from DOCUMENTED specifications (e.g. OpenAPI auth requirements).
        Tagged strictly with origin=DOCUMENTED.
        """
        invariants: List[SecurityInvariant] = []
        for ev in evidence_items:
            if ev.certainty != EpistemicCertainty.DOCUMENTED:
                continue

            # Check for authentication requirement statements
            if "auth_required" in ev.statement.lower() or "requires" in ev.statement.lower():
                desc = f"Endpoint {ev.http_method} {ev.normalized_path} requires valid authenticated identity session."
                inv = SecurityInvariant.create(
                    description=desc,
                    origin=InvariantOrigin.DOCUMENTED,
                    derived_from=[ev.fact_id, ev.asset_id],
                    confidence=InvariantConfidence.HIGH,
                )
                invariants.append(inv)
                self._persist(inv)

        return invariants

    def derive_workflow_invariants(self, workflows: List[WorkflowNode]) -> List[SecurityInvariant]:
        """
        Extract order and state-transition invariants from deterministic workflows.
        Tagged strictly with origin=DETERMINISTIC_DERIVATION.
        """
        invariants: List[SecurityInvariant] = []
        for wf in workflows:
            for t in wf.transitions:
                desc = (
                    f"State transition invariant: Execution of target asset {t.to_asset_id} "
                    f"strictly requires prior successful completion of source asset {t.from_asset_id} "
                    f"(dataflow dependency: {t.parameter_flow})."
                )
                inv = SecurityInvariant.create(
                    description=desc,
                    origin=InvariantOrigin.DETERMINISTIC_DERIVATION,
                    derived_from=[wf.workflow_id, t.from_asset_id, t.to_asset_id],
                    confidence=InvariantConfidence.HIGH,
                )
                invariants.append(inv)
                self._persist(inv)

        return invariants

    def register_model_proposed_invariant(
        self,
        description: str,
        derived_from: List[str],
        confidence: InvariantConfidence = InvariantConfidence.MEDIUM,
    ) -> SecurityInvariant:
        """
        Register an invariant proposed by an LLM reasoning engine.
        Enforces epistemic boundary: CANNOT be marked as DOCUMENTED or OBSERVED.
        """
        inv = SecurityInvariant.create(
            description=description,
            origin=InvariantOrigin.MODEL_PROPOSED, # HARD ENFORCED
            derived_from=derived_from,
            confidence=confidence,
        )
        self._persist(inv)
        return inv

    def _persist(self, invariant: SecurityInvariant) -> None:
        """Save invariant into database."""
        if self.db_manager:
            try:
                self.db_manager.insert_security_invariant(invariant.model_dump())
            except Exception as exc:
                logger.error(f"Failed to persist security invariant {invariant.invariant_id} to database: {exc}")
