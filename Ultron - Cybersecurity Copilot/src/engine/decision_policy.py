"""Deterministic Decision Policy & Calibrated Abstention (Intervention I5).

Milestone M4 Phase M4.6:
Implements a deterministic decision policy over an already-validated candidate
and deterministic canonical evidence state.

Acceptable Decisions:
- NO_RELEVANT_FUNCTIONALITY
- INSUFFICIENT_EVIDENCE
- HYPOTHESIS

CONFIRMED remains strictly forbidden (fails closed).

Deterministic Invariants:
- Zero hidden probability thresholds
- Zero learned classifiers
- Zero semantic vulnerability scoring
- Zero LLM interpretation or natural-language keyword voting
- Predicates evaluate strictly over explicit machine-readable canonical state
- Candidate evidence fields (invariant, evidence_gap, affected_target,
  supporting_evidence_ids, methodology_references, experiment_proposal)
  are strictly IMMUTABLE; only the final decision may be altered.
"""

from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple
from pydantic import BaseModel, ConfigDict, Field

from src.engine.models import (
    HypothesisDecision,
    HypothesisModelOutput,
    FACT_NAMESPACE_REGEX,
    CHK_NAMESPACE_REGEX,
    HttpOutcomePredicate,
    SemanticOutcomePredicate,
    ExperimentActionPredicate,
)
from src.engine.bair_extractor import determine_empirical_evidence_present, _is_canonical_target_empirical_fact


class DecisionPredicate(str, Enum):
    """Machine-readable deterministic predicate branch identifiers."""
    # Layer 1: Irrelevant target functionality (Outside security property)
    NO_RELEVANT_FUNCTIONALITY_CONFIRMED = "PREDICATE_NO_RELEVANT_FUNCTIONALITY_CONFIRMED"
    NO_RELEVANT_FUNCTIONALITY_IRRELEVANT_TARGET = "PREDICATE_NO_RELEVANT_FUNCTIONALITY_IRRELEVANT_TARGET"

    # Layer 2: Relevant target functionality
    HYPOTHESIS_GROUNDED = "PREDICATE_HYPOTHESIS_GROUNDED"
    INSUFFICIENT_EVIDENCE_RELEVANT_FUNCTIONALITY = "PREDICATE_INSUFFICIENT_EVIDENCE_RELEVANT_FUNCTIONALITY"
    INSUFFICIENT_EVIDENCE_CONFIRMED = "PREDICATE_INSUFFICIENT_EVIDENCE_CONFIRMED"

    # Layer 0: Fail-closed branches
    FAIL_CLOSED_MALFORMED_CANDIDATE = "FAIL_CLOSED_MALFORMED_CANDIDATE"
    FAIL_CLOSED_UNSUPPORTED_DECISION = "FAIL_CLOSED_UNSUPPORTED_DECISION"
    FAIL_CLOSED_FORBIDDEN_CONFIRMED = "FAIL_CLOSED_FORBIDDEN_CONFIRMED"
    FAIL_CLOSED_MISSING_PREDICATE_STATE = "FAIL_CLOSED_MISSING_PREDICATE_STATE"
    FAIL_CLOSED_INVALID_EVIDENCE = "FAIL_CLOSED_INVALID_EVIDENCE"
    FAIL_CLOSED_INCOMPLETE_HYPOTHESIS = "FAIL_CLOSED_INCOMPLETE_HYPOTHESIS"
    FAIL_CLOSED_GROUNDING_REJECTION = "FAIL_CLOSED_GROUNDING_REJECTION"


class EvidenceState(BaseModel):
    """
    Deterministic canonical evidence state container for I5 decision policy.
    Contains only structured machine-readable fields; zero ground-truth or benchmark labels.
    """
    model_config = ConfigDict(arbitrary_types_allowed=True)

    channel_a: Optional[Any] = None  # LosslessStructuralPack or dict
    retrieved_evidence: Optional[Sequence[Dict[str, Any]]] = None
    target_asset: Optional[Dict[str, Any]] = None
    category_id: Optional[str] = None
    empirical_evidence_present: Optional[bool] = None
    grounding_validator: Optional[Any] = None


class DecisionPolicyResult(BaseModel):
    """Result of deterministic decision policy evaluation."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    final_decision: Optional[HypothesisDecision] = None
    candidate_decision: Optional[str] = None
    decision_changed: bool = False
    predicate_identifier: DecisionPredicate
    is_valid: bool = True
    fail_closed_reason: Optional[str] = None
    canonical_hypothesis: Optional[HypothesisModelOutput] = None


# ---------------------------------------------------------------------------
# Predicate 1: Relevance to Security Property
# ---------------------------------------------------------------------------

def is_relevant_functionality(evidence_state: EvidenceState) -> bool:
    """
    Deterministic Predicate: Relevance to Security Property.
    Evaluates whether the tested asset/endpoint has functionality relevant to the examined security category.

    Required Invariant:
    Must be reproducible from canonical structured inputs alone (LosslessStructuralPack / target_asset).
    NO keyword search, NO regex over natural-language descriptions, NO LLM interpretation,
    NO category-description semantic matching, NO model-generated relevance claims.

    Evaluated as True if ANY of the following explicit machine-readable fields is true:
    1. application_mutability in ("STATE_CHANGING", "DESTRUCTIVE")
    2. Any Class-1 structural predicate boolean on channel_a is True:
       - has_privilege_level_delta
       - status_code_changed_under_different_role
       - has_unauthenticated_success
       - has_cross_role_response_shape_delta
       - has_cross_identity_object_access_success
       - has_unseen_endpoint_parameter
       - has_numeric_path_identifier
       - has_observed_contradictions
       - has_evidence_parse_asymmetry
       - auth_header_delta
    3. parameter_lineage is non-empty (endpoint accepts/processes parameters)
    4. identity_matrix contains more than one identity/role

    Evaluated as False (outside security property) if:
    Endpoint is a read-only endpoint (READ_ONLY or GET/HEAD), with ZERO Class-1 structural
    deltas, ZERO parameters, ZERO cross-identity observations, and ZERO auth header deltas.
    """
    ch_a = evidence_state.channel_a
    asset = evidence_state.target_asset or {}

    # 1. Application mutability check
    mutability = ""
    if ch_a is not None:
        mutability = str(getattr(ch_a, "application_mutability", "") or "").upper()
        if not mutability and isinstance(ch_a, dict):
            mutability = str(ch_a.get("application_mutability") or "").upper()
    if not mutability and asset:
        mutability = str(asset.get("application_mutability") or "").upper()

    if mutability in ("STATE_CHANGING", "DESTRUCTIVE"):
        return True

    # 2. Class-1 structural predicate booleans
    class1_predicates = [
        "has_privilege_level_delta",
        "status_code_changed_under_different_role",
        "has_unauthenticated_success",
        "has_cross_role_response_shape_delta",
        "has_cross_identity_object_access_success",
        "has_unseen_endpoint_parameter",
        "has_numeric_path_identifier",
        "has_observed_contradictions",
        "has_evidence_parse_asymmetry",
        "auth_header_delta",
    ]
    if ch_a is not None:
        for pred in class1_predicates:
            val = getattr(ch_a, pred, None)
            if val is None and isinstance(ch_a, dict):
                val = ch_a.get(pred)
            if bool(val):
                return True

    # 3. Parameter lineage check
    params = None
    if ch_a is not None:
        params = getattr(ch_a, "parameter_lineage", None)
        if params is None and isinstance(ch_a, dict):
            params = ch_a.get("parameter_lineage")
    if params is None and asset:
        params = asset.get("parameters") or asset.get("parameter_lineage")

    if params and len(params) > 0:
        return True

    # 4. Identity matrix check
    identities = None
    if ch_a is not None:
        identities = getattr(ch_a, "identity_matrix", None)
        if identities is None and isinstance(ch_a, dict):
            identities = ch_a.get("identity_matrix")
    if identities is None and asset:
        identities = asset.get("identities") or asset.get("identity_matrix")

    if identities and len(identities) > 1:
        return True

    # Default to False for static read-only endpoints with zero structural signals
    return False


# ---------------------------------------------------------------------------
# Predicate 2: Discriminating Evidence Absent
# ---------------------------------------------------------------------------

def is_discriminating_evidence_absent(evidence_state: EvidenceState) -> bool:
    """
    Deterministic Predicate: Discriminating Evidence Absent.
    Evaluates whether critical observations needed to discriminate the invariant violation
    are missing from canonical target evidence.

    Required Invariant:
    Derived strictly from deterministic structured state; NEVER inferred from candidate prose,
    evidence_gap prose, methodology, or LLM explanations.

    Mechanism:
    1. Check canonical target empirical evidence presence via determine_empirical_evidence_present().
       If empirical evidence is absent (False), discriminating evidence is absent.
    2. Check category-specific required evidence keys from the canonical taxonomy if available:
       missing = required_observations - observed_observations.
       If len(missing) > 0, discriminating evidence is absent.
    """
    emp_present = determine_empirical_evidence_present(
        channel_a=evidence_state.channel_a,
        retrieved_evidence=evidence_state.retrieved_evidence,
        explicit_signal=evidence_state.empirical_evidence_present,
    )
    if not emp_present:
        return True

    # Check category-specific structural observation requirements from taxonomy
    cat_id = evidence_state.category_id
    ch_a = evidence_state.channel_a

    if cat_id and ch_a is not None:
        # Category-specific structural checks
        if cat_id == "API-BOLA-001":
            # Requires object identifier and distinct identities tested
            has_obj_id = (
                getattr(ch_a, "has_numeric_path_identifier", False)
                or any(
                    isinstance(p, dict) and (
                        p.get("location") in ("path", "query")
                        or "id" in str(p.get("param_name", "")).lower()
                        or str(p.get("param_type", "")).lower() in ("uuid", "identifier")
                    )
                    for p in (getattr(ch_a, "parameter_lineage", None) or [])
                )
            )
            has_distinct_ids = (
                getattr(ch_a, "has_cross_identity_object_access_success", False)
                or len(getattr(ch_a, "identity_matrix", None) or []) >= 2
            )
            if not (has_obj_id and has_distinct_ids):
                return True

        elif cat_id in ("API-BFLA-001", "API-BFLA-002"):
            # Requires distinct roles and privileged/state-changing function
            has_role_delta = (
                getattr(ch_a, "has_privilege_level_delta", False)
                or getattr(ch_a, "status_code_changed_under_different_role", False)
                or len(getattr(ch_a, "identity_matrix", None) or []) >= 2
            )
            if not has_role_delta:
                return True

    return False


# ---------------------------------------------------------------------------
# Predicate 3: Typed Experiment Polarity & Tuple Compatibility
# ---------------------------------------------------------------------------

class ExperimentPolarityValidator:
    """
    Deterministic validator enforcing semantic compatibility and polarity across:
    (category, experiment_action, supporting_outcome, disproving_outcome)
    as ONE deterministic tuple.

    Zero semantic NLP, zero fuzzy matching, zero heuristic polarity repair.
    Fails closed on:
    - unknown category
    - unknown action
    - unknown outcome
    - category / action mismatch
    - action / outcome mismatch
    - identical supporting and disproving outcomes (zero discriminative power)
    """

    # CATEGORY -> ACTION -> (VALID_BREACH_OUTCOMES, VALID_INVARIANT_HOLDS_OUTCOMES)
    TUPLE_COMPATIBILITY_REGISTRY: Dict[str, Dict[str, Tuple[Set[str], Set[str]]]] = {
        # 1. Object Authorization / BOLA
        "API-BOLA-001": {
            ExperimentActionPredicate.SUBSTITUTE_RESOURCE_IDENTIFIER.value: (
                {
                    HttpOutcomePredicate.HTTP_200_OK.value,
                    HttpOutcomePredicate.HTTP_201_CREATED.value,
                    HttpOutcomePredicate.HTTP_204_NO_CONTENT.value,
                    SemanticOutcomePredicate.STATUS_SUCCESS_2XX.value,
                    SemanticOutcomePredicate.CROSS_IDENTITY_OBJECT_ACCESSIBLE.value,
                    SemanticOutcomePredicate.OWNERSHIP_NOT_ENFORCED.value,
                },
                {
                    HttpOutcomePredicate.HTTP_403_FORBIDDEN.value,
                    HttpOutcomePredicate.HTTP_404_NOT_FOUND.value,
                    SemanticOutcomePredicate.STATUS_CLIENT_ERROR_4XX.value,
                    SemanticOutcomePredicate.CROSS_IDENTITY_OBJECT_DENIED.value,
                    SemanticOutcomePredicate.OWNERSHIP_ENFORCED.value,
                },
            ),
        },
        "API-DEVICE-BOLA-001": {
            ExperimentActionPredicate.SUBSTITUTE_RESOURCE_IDENTIFIER.value: (
                {
                    HttpOutcomePredicate.HTTP_200_OK.value,
                    HttpOutcomePredicate.HTTP_201_CREATED.value,
                    HttpOutcomePredicate.HTTP_204_NO_CONTENT.value,
                    SemanticOutcomePredicate.STATUS_SUCCESS_2XX.value,
                    SemanticOutcomePredicate.CROSS_IDENTITY_OBJECT_ACCESSIBLE.value,
                    SemanticOutcomePredicate.OWNERSHIP_NOT_ENFORCED.value,
                },
                {
                    HttpOutcomePredicate.HTTP_403_FORBIDDEN.value,
                    HttpOutcomePredicate.HTTP_404_NOT_FOUND.value,
                    SemanticOutcomePredicate.STATUS_CLIENT_ERROR_4XX.value,
                    SemanticOutcomePredicate.CROSS_IDENTITY_OBJECT_DENIED.value,
                    SemanticOutcomePredicate.OWNERSHIP_ENFORCED.value,
                },
            ),
        },
        "API-CROSS-TENANT-001": {
            ExperimentActionPredicate.SUBSTITUTE_RESOURCE_IDENTIFIER.value: (
                {
                    HttpOutcomePredicate.HTTP_200_OK.value,
                    HttpOutcomePredicate.HTTP_201_CREATED.value,
                    HttpOutcomePredicate.HTTP_204_NO_CONTENT.value,
                    SemanticOutcomePredicate.STATUS_SUCCESS_2XX.value,
                    SemanticOutcomePredicate.CROSS_IDENTITY_OBJECT_ACCESSIBLE.value,
                    SemanticOutcomePredicate.OWNERSHIP_NOT_ENFORCED.value,
                },
                {
                    HttpOutcomePredicate.HTTP_403_FORBIDDEN.value,
                    HttpOutcomePredicate.HTTP_404_NOT_FOUND.value,
                    SemanticOutcomePredicate.STATUS_CLIENT_ERROR_4XX.value,
                    SemanticOutcomePredicate.CROSS_IDENTITY_OBJECT_DENIED.value,
                    SemanticOutcomePredicate.OWNERSHIP_ENFORCED.value,
                },
            ),
        },

        # 2. State Machine / Business Logic / Lifecycle / Multi-Step
        "API-STATE-001": {
            ExperimentActionPredicate.EXECUTE_OUT_OF_ORDER_TRANSITION.value: (
                {
                    HttpOutcomePredicate.HTTP_200_OK.value,
                    HttpOutcomePredicate.HTTP_201_CREATED.value,
                    HttpOutcomePredicate.HTTP_204_NO_CONTENT.value,
                    SemanticOutcomePredicate.STATUS_SUCCESS_2XX.value,
                    SemanticOutcomePredicate.STATE_TRANSITION_ACCEPTED.value,
                },
                {
                    HttpOutcomePredicate.HTTP_400_BAD_REQUEST.value,
                    HttpOutcomePredicate.HTTP_409_CONFLICT.value,
                    SemanticOutcomePredicate.STATUS_CLIENT_ERROR_4XX.value,
                    SemanticOutcomePredicate.STATE_TRANSITION_REJECTED.value,
                },
            ),
        },
        "API-LIFECYCLE-001": {
            ExperimentActionPredicate.EXECUTE_OUT_OF_ORDER_TRANSITION.value: (
                {
                    HttpOutcomePredicate.HTTP_200_OK.value,
                    HttpOutcomePredicate.HTTP_201_CREATED.value,
                    HttpOutcomePredicate.HTTP_204_NO_CONTENT.value,
                    SemanticOutcomePredicate.STATUS_SUCCESS_2XX.value,
                    SemanticOutcomePredicate.STATE_TRANSITION_ACCEPTED.value,
                },
                {
                    HttpOutcomePredicate.HTTP_400_BAD_REQUEST.value,
                    HttpOutcomePredicate.HTTP_409_CONFLICT.value,
                    SemanticOutcomePredicate.STATUS_CLIENT_ERROR_4XX.value,
                    SemanticOutcomePredicate.STATE_TRANSITION_REJECTED.value,
                },
            ),
        },
        "API-MULTI-STEP-AUTH-001": {
            ExperimentActionPredicate.EXECUTE_OUT_OF_ORDER_TRANSITION.value: (
                {
                    HttpOutcomePredicate.HTTP_200_OK.value,
                    HttpOutcomePredicate.HTTP_201_CREATED.value,
                    HttpOutcomePredicate.HTTP_204_NO_CONTENT.value,
                    SemanticOutcomePredicate.STATUS_SUCCESS_2XX.value,
                    SemanticOutcomePredicate.STATE_TRANSITION_ACCEPTED.value,
                },
                {
                    HttpOutcomePredicate.HTTP_400_BAD_REQUEST.value,
                    HttpOutcomePredicate.HTTP_409_CONFLICT.value,
                    SemanticOutcomePredicate.STATUS_CLIENT_ERROR_4XX.value,
                    SemanticOutcomePredicate.STATE_TRANSITION_REJECTED.value,
                },
            ),
        },

        # 3. Function Level Authorization (BFLA) & Role Boundaries
        "API-BFLA-001": {
            ExperimentActionPredicate.REPLAY_STEP_WITH_LOWER_ROLE.value: (
                {
                    HttpOutcomePredicate.HTTP_200_OK.value,
                    HttpOutcomePredicate.HTTP_201_CREATED.value,
                    HttpOutcomePredicate.HTTP_204_NO_CONTENT.value,
                    SemanticOutcomePredicate.STATUS_SUCCESS_2XX.value,
                    SemanticOutcomePredicate.PRIVILEGE_ELEVATION_SUCCEEDS.value,
                },
                {
                    HttpOutcomePredicate.HTTP_401_UNAUTHORIZED.value,
                    HttpOutcomePredicate.HTTP_403_FORBIDDEN.value,
                    SemanticOutcomePredicate.STATUS_CLIENT_ERROR_4XX.value,
                    SemanticOutcomePredicate.PRIVILEGE_ELEVATION_DENIED.value,
                },
            ),
        },
        "API-BFLA-002": {
            ExperimentActionPredicate.REPLAY_STEP_WITH_LOWER_ROLE.value: (
                {
                    HttpOutcomePredicate.HTTP_200_OK.value,
                    HttpOutcomePredicate.HTTP_201_CREATED.value,
                    HttpOutcomePredicate.HTTP_204_NO_CONTENT.value,
                    SemanticOutcomePredicate.STATUS_SUCCESS_2XX.value,
                    SemanticOutcomePredicate.PRIVILEGE_ELEVATION_SUCCEEDS.value,
                },
                {
                    HttpOutcomePredicate.HTTP_401_UNAUTHORIZED.value,
                    HttpOutcomePredicate.HTTP_403_FORBIDDEN.value,
                    SemanticOutcomePredicate.STATUS_CLIENT_ERROR_4XX.value,
                    SemanticOutcomePredicate.PRIVILEGE_ELEVATION_DENIED.value,
                },
            ),
        },
        "API-ROLE-BOUNDARY-001": {
            ExperimentActionPredicate.REPLAY_STEP_WITH_LOWER_ROLE.value: (
                {
                    HttpOutcomePredicate.HTTP_200_OK.value,
                    HttpOutcomePredicate.HTTP_201_CREATED.value,
                    HttpOutcomePredicate.HTTP_204_NO_CONTENT.value,
                    SemanticOutcomePredicate.STATUS_SUCCESS_2XX.value,
                    SemanticOutcomePredicate.PRIVILEGE_ELEVATION_SUCCEEDS.value,
                },
                {
                    HttpOutcomePredicate.HTTP_401_UNAUTHORIZED.value,
                    HttpOutcomePredicate.HTTP_403_FORBIDDEN.value,
                    SemanticOutcomePredicate.STATUS_CLIENT_ERROR_4XX.value,
                    SemanticOutcomePredicate.PRIVILEGE_ELEVATION_DENIED.value,
                },
            ),
        },

        # 4. Parameter Tampering / Mutation
        "API-MUTATION-001": {
            ExperimentActionPredicate.TAMPER_REQUEST_PARAMETER.value: (
                {
                    HttpOutcomePredicate.HTTP_200_OK.value,
                    HttpOutcomePredicate.HTTP_201_CREATED.value,
                    SemanticOutcomePredicate.STATUS_SUCCESS_2XX.value,
                    SemanticOutcomePredicate.PRIVILEGE_ELEVATION_SUCCEEDS.value,
                },
                {
                    HttpOutcomePredicate.HTTP_400_BAD_REQUEST.value,
                    HttpOutcomePredicate.HTTP_403_FORBIDDEN.value,
                    SemanticOutcomePredicate.STATUS_CLIENT_ERROR_4XX.value,
                    SemanticOutcomePredicate.PRIVILEGE_ELEVATION_DENIED.value,
                },
            ),
            ExperimentActionPredicate.REPLAY_STEP_WITH_LOWER_ROLE.value: (
                {
                    HttpOutcomePredicate.HTTP_200_OK.value,
                    SemanticOutcomePredicate.STATUS_SUCCESS_2XX.value,
                    SemanticOutcomePredicate.PRIVILEGE_ELEVATION_SUCCEEDS.value,
                },
                {
                    HttpOutcomePredicate.HTTP_401_UNAUTHORIZED.value,
                    HttpOutcomePredicate.HTTP_403_FORBIDDEN.value,
                    SemanticOutcomePredicate.STATUS_CLIENT_ERROR_4XX.value,
                    SemanticOutcomePredicate.PRIVILEGE_ELEVATION_DENIED.value,
                },
            ),
        },

        # 5. Authentication / Public Endpoints (Negative Controls)
        "API-AUTH-NONE": {
            ExperimentActionPredicate.INVOKE_WITHOUT_CREDENTIALS.value: (
                {
                    HttpOutcomePredicate.HTTP_200_OK.value,
                    SemanticOutcomePredicate.STATUS_SUCCESS_2XX.value,
                    SemanticOutcomePredicate.UNAUTHENTICATED_ACCESS_ALLOWED.value,
                },
                {
                    HttpOutcomePredicate.HTTP_401_UNAUTHORIZED.value,
                    HttpOutcomePredicate.HTTP_403_FORBIDDEN.value,
                    SemanticOutcomePredicate.STATUS_CLIENT_ERROR_4XX.value,
                    SemanticOutcomePredicate.UNAUTHENTICATED_ACCESS_DENIED.value,
                },
            ),
        },
    }

    @classmethod
    def validate_tuple(
        cls,
        category_id: Optional[str],
        experiment_action: Optional[str] = None,
        supporting_outcome: Optional[str] = None,
        disproving_outcome: Optional[str] = None,
        action: Optional[str] = None,
    ) -> Tuple[bool, Optional[str]]:
        """
        Validate (category, action, supporting, disproving) as one deterministic compatibility tuple.
        Returns (is_valid, failure_reason).
        """
        if not category_id or not category_id.strip():
            return False, "Category ID is missing or null"
        cat = category_id.strip()

        if cat not in cls.TUPLE_COMPATIBILITY_REGISTRY:
            return False, f"Unrecognized category ID in compatibility registry: '{cat}'"

        cat_actions = cls.TUPLE_COMPATIBILITY_REGISTRY[cat]
        act_raw = experiment_action or action
        if not act_raw or not act_raw.strip():
            return False, "Experiment action is missing or null"
        act = act_raw.strip()
        if act not in cat_actions:
            return False, f"Experiment action '{act}' is not compatible with category '{cat}'"

        if not supporting_outcome or not supporting_outcome.strip():
            return False, "supporting_outcome is missing or null"
        if not disproving_outcome or not disproving_outcome.strip():
            return False, "disproving_outcome is missing or null"

        supp = supporting_outcome.strip()
        disp = disproving_outcome.strip()

        if supp == disp:
            return False, f"supporting_outcome and disproving_outcome cannot be identical ('{supp}')"

        valid_breaches, valid_safes = cat_actions[act]
        if supp not in valid_breaches:
            return False, f"Outcome '{supp}' is not a valid breach outcome for category '{cat}' and action '{act}'"
        if disp not in valid_safes:
            return False, f"Outcome '{disp}' is not a valid safe outcome for category '{cat}' and action '{act}'"

        return True, None


def is_falsification_complete(experiment_proposal: Optional[str]) -> bool:
    """
    Deterministic Predicate: Bounded Falsification Completeness [LEGACY HELPER].
    Retained for backward-compatibility with historical test fixtures.
    NOTE: Under the Phase 6.6 Typed Experiment-Outcome Protocol, this keyword-based
    helper MUST NEVER authorize a new HYPOTHESIS decision in deterministic_decide().
    """
    if not experiment_proposal or not experiment_proposal.strip():
        return False

    proposal = experiment_proposal.strip()
    # Reject placeholder tokens
    if proposal.upper() in ("N/A", "NONE", "TODO", "NULL", "NONE REQUIRED", "UNVERIFIED"):
        return False

    lower = proposal.lower()
    has_supporting = any(term in lower for term in ["support", "confirm", "positive", "observed", "expected", "200"])
    has_disproving = any(term in lower for term in ["disprov", "falsif", "reject", "refut", "negative", "403", "404", "401", "400", "block", "fail"])

    return bool(has_supporting and has_disproving)


# ---------------------------------------------------------------------------
# Predicate 4: Empirical Evidence Grounded
# ---------------------------------------------------------------------------

def is_empirical_evidence_grounded(
    candidate: HypothesisModelOutput,
    evidence_state: EvidenceState,
) -> bool:
    """
    Deterministic Predicate: Empirical Evidence Grounded.
    Verifies:
    1. Canonical target empirical evidence is present (empirical_evidence_present == True).
    2. supporting_evidence_ids is non-empty.
    3. Every cited ID matches ^FACT-[A-Z0-9_-]+$ (no CHK IDs).
    4. Every cited ID exists in canonical target empirical evidence.
    5. KnowledgeGroundingValidator (if provided) accepts the citations.
    """
    emp_present = determine_empirical_evidence_present(
        channel_a=evidence_state.channel_a,
        retrieved_evidence=evidence_state.retrieved_evidence,
        explicit_signal=evidence_state.empirical_evidence_present,
    )
    if not emp_present:
        return False

    cited_facts = list(candidate.supporting_evidence_ids or [])
    if not cited_facts:
        return False

    # Extract all valid canonical target fact IDs
    valid_target_fact_ids: Set[str] = set()
    if evidence_state.channel_a is not None:
        facts = getattr(evidence_state.channel_a, "observed_facts", None)
        if facts is None and isinstance(evidence_state.channel_a, dict):
            facts = evidence_state.channel_a.get("observed_facts")
        for f in (facts or []):
            if _is_canonical_target_empirical_fact(f):
                fid = f.get("fact_id") or f.get("evidence_id")
                if fid:
                    valid_target_fact_ids.add(str(fid))

    if evidence_state.retrieved_evidence is not None:
        for item in evidence_state.retrieved_evidence:
            if _is_canonical_target_empirical_fact(item):
                fid = item.get("fact_id") or item.get("evidence_id")
                if fid:
                    valid_target_fact_ids.add(str(fid))

    for fid in cited_facts:
        if not isinstance(fid, str):
            return False
        # Reject CHK IDs or malformed syntax
        if not FACT_NAMESPACE_REGEX.match(fid) or "CHK-" in fid:
            return False
        # Must exist in canonical target facts if canonical facts are known
        if valid_target_fact_ids and fid not in valid_target_fact_ids:
            return False

    # Authoritative KnowledgeGroundingValidator check if supplied
    validator = evidence_state.grounding_validator
    if validator is not None and evidence_state.channel_a is not None:
        try:
            if hasattr(validator, "validate_grounding"):
                res = validator.validate_grounding(hypothesis=candidate, channel_a=evidence_state.channel_a)
            elif hasattr(validator, "validate"):
                res = validator.validate(hypothesis=candidate, channel_a=evidence_state.channel_a)
            else:
                res = None

            if res is not None:
                is_valid = getattr(res, "valid", True) if hasattr(res, "valid") else (
                    res.get("valid", True) if isinstance(res, dict) else True
                )
                if not is_valid:
                    return False
        except Exception:
            return False

    return True


# ---------------------------------------------------------------------------
# Authoritative I5 Decision Policy Function
# ---------------------------------------------------------------------------

def deterministic_decide(
    candidate: Optional[HypothesisModelOutput],
    evidence_state: Optional[EvidenceState],
) -> DecisionPolicyResult:
    """
    Authoritative I5 Deterministic Decision Policy (M4 Plan Section 8 / Phase M4.6).

    Precedence:
    Layer 0: Fail-Closed on invalid state
    Layer 1: Irrelevant target functionality -> NO_RELEVANT_FUNCTIONALITY
    Layer 2: Relevant target functionality -> HYPOTHESIS | INSUFFICIENT_EVIDENCE

    IMMUTABILITY CONTRACT:
    Does NOT mutate candidate evidence fields:
    - invariant
    - evidence_gap
    - affected_target
    - supporting_evidence_ids
    - methodology_references
    - experiment_proposal
    Only candidate.decision may change.
    """
    # -----------------------------------------------------------------------
    # Layer 0: Fail-Closed Boundary
    # -----------------------------------------------------------------------

    # 1. Malformed / None candidate
    if candidate is None:
        return DecisionPolicyResult(
            final_decision=None,
            candidate_decision=None,
            decision_changed=False,
            predicate_identifier=DecisionPredicate.FAIL_CLOSED_MALFORMED_CANDIDATE,
            is_valid=False,
            fail_closed_reason="Candidate output is None or malformed",
            canonical_hypothesis=None,
        )

    # 2. Missing required canonical evidence state
    if evidence_state is None or (evidence_state.channel_a is None and evidence_state.target_asset is None):
        return DecisionPolicyResult(
            final_decision=None,
            candidate_decision=candidate.decision.value if hasattr(candidate.decision, "value") else str(candidate.decision),
            decision_changed=False,
            predicate_identifier=DecisionPredicate.FAIL_CLOSED_MISSING_PREDICATE_STATE,
            is_valid=False,
            fail_closed_reason="Required canonical evidence state (channel_a / target_asset) is missing",
            canonical_hypothesis=None,
        )

    cand_dec_str = candidate.decision.value if hasattr(candidate.decision, "value") else str(candidate.decision)

    # 3. Forbidden CONFIRMED
    if cand_dec_str == "CONFIRMED":
        return DecisionPolicyResult(
            final_decision=None,
            candidate_decision=cand_dec_str,
            decision_changed=False,
            predicate_identifier=DecisionPredicate.FAIL_CLOSED_FORBIDDEN_CONFIRMED,
            is_valid=False,
            fail_closed_reason="CONFIRMED decision is strictly forbidden in reasoning engine",
            canonical_hypothesis=None,
        )

    # 4. Unsupported decision
    supported_decisions = {
        HypothesisDecision.NO_RELEVANT_FUNCTIONALITY.value,
        HypothesisDecision.INSUFFICIENT_EVIDENCE.value,
        HypothesisDecision.HYPOTHESIS.value,
    }
    if cand_dec_str not in supported_decisions:
        return DecisionPolicyResult(
            final_decision=None,
            candidate_decision=cand_dec_str,
            decision_changed=False,
            predicate_identifier=DecisionPredicate.FAIL_CLOSED_UNSUPPORTED_DECISION,
            is_valid=False,
            fail_closed_reason=f"Unsupported decision value: '{cand_dec_str}'",
            canonical_hypothesis=None,
        )

    # 5. Invalid evidence references (cross-namespace CHK or fabricated IDs)
    for fid in (candidate.supporting_evidence_ids or []):
        if not isinstance(fid, str) or "CHK-" in fid:
            return DecisionPolicyResult(
                final_decision=None,
                candidate_decision=cand_dec_str,
                decision_changed=False,
                predicate_identifier=DecisionPredicate.FAIL_CLOSED_INVALID_EVIDENCE,
                is_valid=False,
                fail_closed_reason=f"Cross-namespace citation or invalid ID in supporting_evidence_ids: {fid}",
                canonical_hypothesis=None,
            )

    # -----------------------------------------------------------------------
    # Layer 1: Target Relevance Boundary (is_relevant_functionality == False)
    # -----------------------------------------------------------------------
    relevant = is_relevant_functionality(evidence_state)

    if not relevant:
        # Endpoint is verified to be entirely outside the examined security property.
        # Enforces TNR >= 90.0% safety floor on negative controls.
        final_dec = HypothesisDecision.NO_RELEVANT_FUNCTIONALITY
        pred_id = (
            DecisionPredicate.NO_RELEVANT_FUNCTIONALITY_CONFIRMED
            if cand_dec_str == HypothesisDecision.NO_RELEVANT_FUNCTIONALITY.value
            else DecisionPredicate.NO_RELEVANT_FUNCTIONALITY_IRRELEVANT_TARGET
        )
        changed = (cand_dec_str != final_dec.value)

        # Construct new canonical hypothesis preserving all non-decision fields byte-identical
        canonical_out = candidate.model_copy(update={"decision": final_dec})

        return DecisionPolicyResult(
            final_decision=final_dec,
            candidate_decision=cand_dec_str,
            decision_changed=changed,
            predicate_identifier=pred_id,
            is_valid=True,
            fail_closed_reason=None,
            canonical_hypothesis=canonical_out,
        )

    # -----------------------------------------------------------------------
    # Layer 2: Relevant Functionality Evaluation (is_relevant_functionality == True)
    # -----------------------------------------------------------------------
    if cand_dec_str == HypothesisDecision.HYPOTHESIS.value:
        # Mandatory fields must be non-empty strings
        if (
            not candidate.invariant or not candidate.invariant.strip()
            or not candidate.evidence_gap or not candidate.evidence_gap.strip()
            or not candidate.affected_target or not candidate.affected_target.strip()
        ):
            return DecisionPolicyResult(
                final_decision=None,
                candidate_decision=cand_dec_str,
                decision_changed=False,
                predicate_identifier=DecisionPredicate.FAIL_CLOSED_INCOMPLETE_HYPOTHESIS,
                is_valid=False,
                fail_closed_reason="HYPOTHESIS candidate missing mandatory invariant, evidence_gap, or affected_target",
                canonical_hypothesis=None,
            )

        # Grounding check (empirical facts from target evidence)
        if not is_empirical_evidence_grounded(candidate, evidence_state):
            return DecisionPolicyResult(
                final_decision=None,
                candidate_decision=cand_dec_str,
                decision_changed=False,
                predicate_identifier=DecisionPredicate.FAIL_CLOSED_GROUNDING_REJECTION,
                is_valid=False,
                fail_closed_reason="HYPOTHESIS empirical evidence grounding check failed",
                canonical_hypothesis=None,
            )

        # Typed experiment verification (Option B deterministic 4-tuple compatibility)
        action = candidate.experiment_action
        supp = candidate.supporting_outcome
        disp = candidate.disproving_outcome

        if not action or not supp or not disp:
            return DecisionPolicyResult(
                final_decision=None,
                candidate_decision=cand_dec_str,
                decision_changed=False,
                predicate_identifier=DecisionPredicate.FAIL_CLOSED_INCOMPLETE_HYPOTHESIS,
                is_valid=False,
                fail_closed_reason="HYPOTHESIS experiment proposal is incomplete or missing supporting/disproving specification: missing typed experiment fields",
                canonical_hypothesis=None,
            )

        cat_id = (
            (evidence_state.category_id if evidence_state and evidence_state.category_id else None)
            or (candidate.category if candidate and candidate.category else None)
        )

        is_compat, reason = ExperimentPolarityValidator.validate_tuple(
            category_id=cat_id,
            action=action,
            supporting_outcome=supp,
            disproving_outcome=disp,
        )
        if not is_compat:
            return DecisionPolicyResult(
                final_decision=None,
                candidate_decision=cand_dec_str,
                decision_changed=False,
                predicate_identifier=DecisionPredicate.FAIL_CLOSED_INCOMPLETE_HYPOTHESIS,
                is_valid=False,
                fail_closed_reason=f"HYPOTHESIS experiment proposal is incomplete or missing supporting/disproving specification: {reason}",
                canonical_hypothesis=None,
            )

        # Candidate HYPOTHESIS on relevant target with grounded evidence and complete falsification
        final_dec = HypothesisDecision.HYPOTHESIS
        pred_id = DecisionPredicate.HYPOTHESIS_GROUNDED
        canonical_out = candidate.model_copy(update={"decision": final_dec})
        return DecisionPolicyResult(
            final_decision=final_dec,
            candidate_decision=cand_dec_str,
            decision_changed=False,
            predicate_identifier=pred_id,
            is_valid=True,
            fail_closed_reason=None,
            canonical_hypothesis=canonical_out,
        )

    elif cand_dec_str == HypothesisDecision.NO_RELEVANT_FUNCTIONALITY.value:
        # Model conservatively abstained as NO_RELEVANT_FUNCTIONALITY, but functionality IS relevant!
        # Calibrated abstention corrects this to INSUFFICIENT_EVIDENCE
        final_dec = HypothesisDecision.INSUFFICIENT_EVIDENCE
        pred_id = DecisionPredicate.INSUFFICIENT_EVIDENCE_RELEVANT_FUNCTIONALITY
        canonical_out = candidate.model_copy(update={"decision": final_dec})
        return DecisionPolicyResult(
            final_decision=final_dec,
            candidate_decision=cand_dec_str,
            decision_changed=True,
            predicate_identifier=pred_id,
            is_valid=True,
            fail_closed_reason=None,
            canonical_hypothesis=canonical_out,
        )

    else:  # cand_dec_str == HypothesisDecision.INSUFFICIENT_EVIDENCE.value
        # Candidate INSUFFICIENT_EVIDENCE remains INSUFFICIENT_EVIDENCE on relevant target.
        # NEVER promoted to HYPOTHESIS per frozen specification.
        final_dec = HypothesisDecision.INSUFFICIENT_EVIDENCE
        pred_id = DecisionPredicate.INSUFFICIENT_EVIDENCE_CONFIRMED
        canonical_out = candidate.model_copy(update={"decision": final_dec})
        return DecisionPolicyResult(
            final_decision=final_dec,
            candidate_decision=cand_dec_str,
            decision_changed=False,
            predicate_identifier=pred_id,
            is_valid=True,
            fail_closed_reason=None,
            canonical_hypothesis=canonical_out,
        )
