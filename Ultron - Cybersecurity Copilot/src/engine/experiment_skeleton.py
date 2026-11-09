"""
Milestone M5 Phase 9: Deterministic Experiment Skeleton.

Separates experiment construction into:
1. Deterministic Engine:
   - Supplies canonical vulnerability category.
   - Supplies deterministic legal experiment action (per frozen policy).
   - Supplies action identifier and single unified permitted outcome vocabulary (legal_outcomes).
   - Strictly DOES NOT supply breach vs safe partition labels, ground truth, or verdicts.
2. LLM:
   - Emits semantic supporting_outcome and disproving_outcome from the permitted vocabulary.
   - Must NOT alter or substitute the experiment action.
3. Validator:
   - Holds the complete internal compatibility registry (breach vs safe outcomes).
   - Enforces action compatibility, outcome compatibility, non-identical outcomes, and polarity.
"""

from enum import Enum
import hashlib
import json
from typing import Any, Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, ConfigDict, Field

from src.engine.decision_policy import ExperimentPolarityValidator
from src.engine.models import ExperimentActionPredicate
from src.engine.prompts import get_counterfactual_template
from src.eval.m4_live_benchmark import infer_evidence_gap_type

# Frozen deterministic action mapping for Phase 9 representative categories
FROZEN_CATEGORY_ACTION_MAP: Dict[str, str] = {
    # 1. Object Authorization / BOLA
    "API-BOLA-001": ExperimentActionPredicate.SUBSTITUTE_RESOURCE_IDENTIFIER.value,
    "API-DEVICE-BOLA-001": ExperimentActionPredicate.SUBSTITUTE_RESOURCE_IDENTIFIER.value,
    "API-CROSS-TENANT-001": ExperimentActionPredicate.SUBSTITUTE_RESOURCE_IDENTIFIER.value,

    # 2. State Machine / Lifecycle
    "API-STATE-001": ExperimentActionPredicate.EXECUTE_OUT_OF_ORDER_TRANSITION.value,
    "API-LIFECYCLE-001": ExperimentActionPredicate.EXECUTE_OUT_OF_ORDER_TRANSITION.value,
    "API-MULTI-STEP-AUTH-001": ExperimentActionPredicate.EXECUTE_OUT_OF_ORDER_TRANSITION.value,

    # 3. Role Boundary / BFLA
    "API-BFLA-001": ExperimentActionPredicate.REPLAY_STEP_WITH_LOWER_ROLE.value,
    "API-BFLA-002": ExperimentActionPredicate.REPLAY_STEP_WITH_LOWER_ROLE.value,
    "API-ROLE-BOUNDARY-001": ExperimentActionPredicate.REPLAY_STEP_WITH_LOWER_ROLE.value,

    # 4. Mutation / Parameter Tampering
    "API-MUTATION-001": ExperimentActionPredicate.TAMPER_REQUEST_PARAMETER.value,
}


def resolve_deterministic_action(category_id: str) -> str:
    """
    Deterministically resolves the canonical legal experiment action for a category.
    Uses frozen policy map; falls back to alphabetically first legal action in registry.
    """
    cat = (category_id or "").strip()
    if cat in FROZEN_CATEGORY_ACTION_MAP:
        return FROZEN_CATEGORY_ACTION_MAP[cat]

    registry = ExperimentPolarityValidator.TUPLE_COMPATIBILITY_REGISTRY
    if cat in registry and registry[cat]:
        # Deterministic fallback: sort legal actions alphabetically
        sorted_actions = sorted(list(registry[cat].keys()))
        return sorted_actions[0]

    raise ValueError(f"No legal experiment actions registered for category: '{cat}'")


class ExperimentSkeletonDescriptor(BaseModel):
    """
    Immutable descriptor for a deterministic experiment skeleton.
    Contains only structural and vocabulary constraints.
    Zero ground truth, zero target labels, zero breach/safe partition leakages.
    """
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = Field(default="1.0.0", description="Skeleton schema version")
    category_id: str = Field(..., description="Canonical vulnerability category identifier")
    experiment_action: str = Field(..., description="Deterministically selected legal experiment action")
    action_identifier: str = Field(..., description="Action predicate identifier")
    legal_outcomes: List[str] = Field(
        ...,
        description="Unified permitted outcome vocabulary (alphabetically sorted, unpartitioned)"
    )
    invariant_definition: str = Field(..., description="Canonical security invariant statement")
    evidence_gap_type: str = Field(..., description="Evidence gap category identifier")
    provenance_hash: str = Field(..., description="Deterministic SHA-256 hash of skeleton inputs")

    def to_llm_visible_dict(self) -> Dict[str, Any]:
        """
        Returns only LLM-visible fields.
        Excludes any validator-only or internal metadata.
        """
        return {
            "schema_version": self.schema_version,
            "category_id": self.category_id,
            "experiment_action": self.experiment_action,
            "action_identifier": self.action_identifier,
            "legal_outcomes": list(self.legal_outcomes),
            "invariant_definition": self.invariant_definition,
            "evidence_gap_type": self.evidence_gap_type,
        }


class ExperimentSkeletonBuilder:
    """
    Builds deterministic experiment skeletons from canonical category and invariant state.
    """

    @classmethod
    def build_skeleton(
        cls,
        category_id: str,
        invariant_definition: Optional[str] = None,
        evidence_gap_type: Optional[str] = None,
    ) -> ExperimentSkeletonDescriptor:
        cat = (category_id or "").strip()
        registry = ExperimentPolarityValidator.TUPLE_COMPATIBILITY_REGISTRY
        if cat not in registry:
            raise ValueError(f"Unrecognized vulnerability category for skeleton construction: '{cat}'")

        action = resolve_deterministic_action(cat)
        cat_actions = registry[cat]
        if action not in cat_actions:
            raise ValueError(f"Resolved action '{action}' not compatible with category '{cat}'")

        valid_breaches, valid_safes = cat_actions[action]
        # Union both breach and safe outcomes into a single, flat, alphabetically sorted list
        combined_outcomes = sorted(list(valid_breaches | valid_safes))

        # Invariant definition resolution
        inv = invariant_definition
        if not inv:
            cat_tmpl = get_counterfactual_template(cat)
            inv = cat_tmpl.invariant_definition

        gap_type = evidence_gap_type
        if not gap_type:
            gap_type = infer_evidence_gap_type(cat).value

        # Deterministic provenance hash
        hash_payload = {
            "schema_version": "1.0.0",
            "category_id": cat,
            "experiment_action": action,
            "action_identifier": action,
            "legal_outcomes": combined_outcomes,
            "invariant_definition": inv,
            "evidence_gap_type": gap_type,
        }
        canonical_bytes = json.dumps(hash_payload, sort_keys=True).encode("utf-8")
        prov_hash = hashlib.sha256(canonical_bytes).hexdigest().lower()

        return ExperimentSkeletonDescriptor(
            schema_version="1.0.0",
            category_id=cat,
            experiment_action=action,
            action_identifier=action,
            legal_outcomes=combined_outcomes,
            invariant_definition=inv,
            evidence_gap_type=gap_type,
            provenance_hash=prov_hash,
        )


def render_skeleton_prompt_block(skeleton: ExperimentSkeletonDescriptor) -> str:
    """
    Renders the additive prompt block instructing the LLM to complete semantic outcomes
    within the fixed experiment skeleton.

    Strict Invariants:
    - Experiment action is fixed by policy and MUST NOT be changed.
    - legal_outcomes is presented as a flat, unpartitioned list.
    - Zero leak of breach vs safe outcome classifications.
    - Explicit instruction on the semantics of supporting (breach) vs disproving (safe).
    - Supporting and disproving outcomes MUST differ.
    - If evidence is insufficient, fail closed to INSUFFICIENT_EVIDENCE.
    """
    outcomes_formatted = json.dumps(skeleton.legal_outcomes)
    block = f"""
=== DETERMINISTIC EXPERIMENT SKELETON (POLICY FIXED) ===
The verification experiment action for category '{skeleton.category_id}' has been FIXED by deterministic policy:
  "experiment_action": "{skeleton.experiment_action}"

You MUST NOT replace, alter, or omit this experiment action.
If your decision is HYPOTHESIS, you MUST emit exactly:
  "experiment_action": "{skeleton.experiment_action}"

Permitted Semantic Outcome Vocabulary (legal_outcomes):
{outcomes_formatted}

Outcome Selection Rules:
1. 'supporting_outcome': Select the outcome that indicates the security invariant IS VIOLATED (breach confirmed).
2. 'disproving_outcome': Select the outcome that indicates the security invariant HOLDS (security boundary upheld).
3. Both 'supporting_outcome' and 'disproving_outcome' MUST be strictly chosen from the permitted legal_outcomes list above.
4. 'supporting_outcome' and 'disproving_outcome' CANNOT be identical. They must represent mutually exclusive, discriminative states.
5. If the evidence does not warrant a hypothesis, emit decision: "INSUFFICIENT_EVIDENCE" with empty outcome fields.
========================================================
"""
    return block.strip()


def validate_skeleton_compliance(
    skeleton: ExperimentSkeletonDescriptor,
    candidate_action: Optional[str],
    candidate_supporting: Optional[str],
    candidate_disproving: Optional[str],
) -> Tuple[bool, Optional[str]]:
    """
    Validates that a candidate hypothesis respects the deterministic skeleton constraints:
    1. Candidate experiment_action matches skeleton.experiment_action exactly.
    2. Candidate supporting_outcome is in legal_outcomes.
    3. Candidate disproving_outcome is in legal_outcomes.
    4. supporting_outcome != disproving_outcome.
    """
    act = (candidate_action or "").strip()
    if act != skeleton.experiment_action:
        return False, f"Experiment action mismatch: candidate emitted '{act}', but skeleton required '{skeleton.experiment_action}'"

    supp = (candidate_supporting or "").strip()
    disp = (candidate_disproving or "").strip()

    if not supp:
        return False, "Candidate missing supporting_outcome"
    if not disp:
        return False, "Candidate missing disproving_outcome"

    if supp not in skeleton.legal_outcomes:
        return False, f"Candidate supporting_outcome '{supp}' is not in permitted legal_outcomes"
    if disp not in skeleton.legal_outcomes:
        return False, f"Candidate disproving_outcome '{disp}' is not in permitted legal_outcomes"

    if supp == disp:
        return False, f"Candidate supporting_outcome and disproving_outcome cannot be identical ('{supp}')"

    return True, None
