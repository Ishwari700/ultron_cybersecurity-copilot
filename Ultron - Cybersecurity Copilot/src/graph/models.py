"""Graph representations for Assets, Parameters, Identities, and Workflows."""

import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class EpistemicOrigin(str, Enum):
    DOCUMENTED = "DOCUMENTED"
    OBSERVED = "OBSERVED"
    DETERMINISTIC_DERIVATION = "DETERMINISTIC_DERIVATION"
    MODEL_PROPOSED = "MODEL_PROPOSED"


class WorkflowTransition(BaseModel):
    """Transition between two assets in a workflow sequence."""
    from_asset_id: str
    to_asset_id: str
    parameter_flow: Optional[str] = None # e.g. "order_id" flowed from response to request
    sample_value: Optional[str] = None
    certainty: EpistemicOrigin = EpistemicOrigin.DETERMINISTIC_DERIVATION


class WorkflowNode(BaseModel):
    """Ordered chain of asset transitions representing a business process."""
    workflow_id: str
    name: str
    asset_sequence: List[str] # List of asset_ids in execution order
    transitions: List[WorkflowTransition] = Field(default_factory=list)
    origin: EpistemicOrigin = EpistemicOrigin.DETERMINISTIC_DERIVATION
    derivation_id: Optional[str] = None

    @classmethod
    def compute_workflow_id(cls, asset_sequence: List[str]) -> str:
        raw = "->".join(asset_sequence)
        return f"WF-{hashlib.sha256(raw.encode('utf-8')).hexdigest()[:12].upper()}"


class DerivationRecord(BaseModel):
    """Audit lineage for deterministic derivations."""
    derivation_id: str
    derived_fact_id: str
    parent_fact_ids: List[str]
    derivation_rule: str
    algorithm_version: str = "workflow-v6"
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @classmethod
    def create(
        cls,
        derived_fact_id: str,
        parent_fact_ids: List[str],
        derivation_rule: str,
        algorithm_version: str = "workflow-v6",
    ) -> "DerivationRecord":
        seed = f"{derived_fact_id}:{','.join(sorted(parent_fact_ids))}:{derivation_rule}"
        derivation_id = f"DERIVE-{hashlib.sha256(seed.encode('utf-8')).hexdigest()[:12].upper()}"
        return cls(
            derivation_id=derivation_id,
            derived_fact_id=derived_fact_id,
            parent_fact_ids=parent_fact_ids,
            derivation_rule=derivation_rule,
            algorithm_version=algorithm_version,
        )


class ApplicationModel(BaseModel):
    """
    Structured model of target application state, identities, and observed workflows.
    """
    target_host: str
    assets: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    identities: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    workflows: List[WorkflowNode] = Field(default_factory=list)
    invariants: List[Dict[str, Any]] = Field(default_factory=list)
