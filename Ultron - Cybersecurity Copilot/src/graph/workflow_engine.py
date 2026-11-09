"""Workflow derivation engine discovering deterministic business logic edges."""

import json
from typing import Any, Dict, List, Optional, Set
from src.core.logging import get_logger
from src.database.manager import DatabaseManager
from src.evidence.models import CanonicalEvidence, EpistemicCertainty
from src.graph.models import DerivationRecord, EpistemicOrigin, WorkflowNode, WorkflowTransition

logger = get_logger("WorkflowEngine")


class WorkflowEngine:
    """
    Derives deterministic workflow nodes from temporal request adjacency
    and parameter/data flow across HTTP interactions.
    """

    DEFAULT_IGNORE_ENDPOINTS: Set[str] = {
        "/telemetry",
        "/metrics",
        "/health",
        "/healthz",
        "/ping",
        "/favicon.ico",
        "/robots.txt",
    }

    def __init__(
        self,
        db_manager: Optional[DatabaseManager] = None,
        ignore_endpoints: Optional[Set[str]] = None,
    ) -> None:
        self.db_manager = db_manager
        self.ignore_endpoints = ignore_endpoints or self.DEFAULT_IGNORE_ENDPOINTS

    def is_noise_endpoint(self, raw_path: str) -> bool:
        """Check if an endpoint is in the noise filter list."""
        path_lower = raw_path.lower().split("?")[0]
        return any(path_lower.endswith(ign) for ign in self.ignore_endpoints)

    def derive_workflows(
        self,
        interactions: List[CanonicalEvidence],
        session_id: Optional[str] = None,
    ) -> List[WorkflowNode]:
        """
        Derives workflow sequences from temporally-ordered evidence interactions.
        Connects request A -> request B if dataflow (parameter match) or temporal adjacency holds.
        """
        # Filter out noise endpoints
        filtered = [
            ev for ev in interactions
            if not self.is_noise_endpoint(ev.raw_path) and ev.certainty == EpistemicCertainty.OBSERVED
        ]

        if len(filtered) < 2:
            return []

        workflows: List[WorkflowNode] = []
        current_sequence: List[str] = [filtered[0].asset_id]
        current_transitions: List[WorkflowTransition] = []
        parent_facts: List[str] = [filtered[0].fact_id]

        for i in range(len(filtered) - 1):
            prev_ev = filtered[i]
            next_ev = filtered[i + 1]

            # Check parameter dataflow: did a response field from prev appear in next request parameters?
            matched_param = None
            if prev_ev.response_body_summary:
                for param in next_ev.parameters:
                    if f'"{param.param_name}"' in prev_ev.response_body_summary or f"'{param.param_name}'" in prev_ev.response_body_summary:
                        matched_param = param.param_name
                        break

            transition = WorkflowTransition(
                from_asset_id=prev_ev.asset_id,
                to_asset_id=next_ev.asset_id,
                parameter_flow=matched_param or "temporal_adjacency",
                certainty=EpistemicOrigin.DETERMINISTIC_DERIVATION,
            )

            current_sequence.append(next_ev.asset_id)
            current_transitions.append(transition)
            parent_facts.append(next_ev.fact_id)

        wf_id = WorkflowNode.compute_workflow_id(current_sequence)
        name = f"Workflow [{current_sequence[0][:8]} -> {current_sequence[-1][:8]}]"

        # Create derivation record for auditability
        derivation = DerivationRecord.create(
            derived_fact_id=wf_id,
            parent_fact_ids=parent_facts,
            derivation_rule="temporal_dataflow_adjacency",
        )

        wf_node = WorkflowNode(
            workflow_id=wf_id,
            name=name,
            asset_sequence=current_sequence,
            transitions=current_transitions,
            origin=EpistemicOrigin.DETERMINISTIC_DERIVATION,
            derivation_id=derivation.derivation_id,
        )
        workflows.append(wf_node)

        # Persist derivation record to database if available
        if self.db_manager:
            try:
                # Store derivation record
                with self.db_manager.get_connection() as conn:
                    # Also insert a placeholder evidence item for the derived workflow
                    self.db_manager.insert_evidence_item({
                        "fact_id": wf_id,
                        "certainty": EpistemicCertainty.DETERMINISTIC_DERIVATION.value,
                        "statement": f"Derived workflow transition sequence: {' -> '.join(current_sequence)}",
                        "source_tool": "workflow_engine",
                        "trust": "TRUSTED",
                    })
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO derivations (
                            derivation_id, derived_fact_id, parent_fact_ids,
                            derivation_rule, algorithm_version
                        ) VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            derivation.derivation_id,
                            derivation.derived_fact_id,
                            json.dumps(derivation.parent_fact_ids),
                            derivation.derivation_rule,
                            derivation.algorithm_version,
                        ),
                    )
                    conn.commit()
            except Exception as exc:
                logger.error(f"Failed to persist workflow derivation {derivation.derivation_id}: {exc}")

        return workflows
