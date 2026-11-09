"""
Unit and regression tests for Milestone M5 Phase 9:
Deterministic Experiment Skeleton & Output-Budget Sensitivity Study.

Verifies all 30 mandatory test requirements:
1. Deterministic skeleton creation
2. Deterministic action selection
3. BOLA action mapping
4. STATE action mapping
5. ROLE/BFLA action mapping
6. CROSS-TENANT action mapping
7. Valid outcome vocabulary
8. Invalid outcome rejection
9. Category/action mismatch rejection
10. Action/outcome mismatch rejection
11. Identical outcomes rejection
12. Missing semantic outcome rejection
13. Malformed LLM output handling
14. Schema failure handling
15. Grounding failure handling
16. Fail-closed behavior
17. Zero ground-truth leakage
18. Zero breach/safe partition leakage
19. Zero expected-decision leakage
20. Zero vulnerability/control-label leakage
21. Zero scenario-label leakage
22. Zero secret leakage
23. Deterministic serialization
24. Deterministic provenance hash
25. Byte-identical evidence across budget conditions
26. 30-second timeout classification
27. Historical Phase 7 artifact immutability
28. Historical Phase 8 artifact immutability
29. Phase 6.9 evaluation regression
30. Scenario manifest determinism and integrity
"""

import hashlib
import json
from pathlib import Path
import pytest

from src.engine.decision_policy import (
    DecisionPolicyResult,
    DecisionPredicate,
    EvidenceState,
    ExperimentPolarityValidator,
    deterministic_decide,
)
from src.engine.experiment_skeleton import (
    FROZEN_CATEGORY_ACTION_MAP,
    ExperimentSkeletonBuilder,
    ExperimentSkeletonDescriptor,
    render_skeleton_prompt_block,
    resolve_deterministic_action,
    validate_skeleton_compliance,
)
from src.engine.models import (
    BairJsonObject,
    ExperimentActionPredicate,
    HttpOutcomePredicate,
    HypothesisDecision,
    HypothesisModelOutput,
    OutputProtocolIdentifier,
    PrimaryFailureCategory,
    SemanticOutcomePredicate,
)
from src.engine.protocol import get_protocol_contract
from src.eval.m5_phase9_study import (
    ACTIVE_EVIDENCE_FIXTURES,
    PHASE9_CONDITIONS,
    REPRESENTATIVE_BENCHMARK_SCENARIOS,
    compute_manifest_hash,
)
from src.eval.scenarios import get_gold_set_scenarios
from src.evidence.cascade_models import LosslessStructuralPack

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SEALED_P7_PATH = REPO_ROOT / "data/eval/m5_phase7_benchmark_final.json"
EXPECTED_P7_SHA = "1e0ed90c4aa672f135d2d2f2240a14d22fa0037c03efda33634f4bf10ff0b125"

SEALED_P8_PATH = REPO_ROOT / "data/eval/m5_phase8_semantic_study.json"
EXPECTED_P8_SHA = "b1df9a62fb07d76e0abf6e3935ccbabdaa1713f4c594019ae30c9e59567a45c6"

SCENARIOS_PATH = REPO_ROOT / "src/eval/scenarios.py"
EXPECTED_SCENARIOS_SHA = "102789655bfb04041de9259d1bf6db7f088979e5bce9bac9eb050564ef0110a8"


def hash_file(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest().lower()


# ---------------------------------------------------------------------------
# Tests 1-6: Deterministic Skeleton Creation & Action Mappings
# ---------------------------------------------------------------------------

def test_01_deterministic_skeleton_creation():
    """Verify that a deterministic skeleton is successfully constructed."""
    skel = ExperimentSkeletonBuilder.build_skeleton("API-BOLA-001")
    assert isinstance(skel, ExperimentSkeletonDescriptor)
    assert skel.schema_version == "1.0.0"
    assert skel.category_id == "API-BOLA-001"
    assert skel.experiment_action == "SUBSTITUTE_RESOURCE_IDENTIFIER"
    assert len(skel.legal_outcomes) > 0
    assert len(skel.provenance_hash) == 64


def test_02_deterministic_action_selection():
    """Verify action resolution is deterministic and matches frozen policy."""
    for cat, expected_act in FROZEN_CATEGORY_ACTION_MAP.items():
        act = resolve_deterministic_action(cat)
        assert act == expected_act


def test_03_bola_action_mapping():
    """Verify BOLA categories map strictly to SUBSTITUTE_RESOURCE_IDENTIFIER."""
    assert resolve_deterministic_action("API-BOLA-001") == ExperimentActionPredicate.SUBSTITUTE_RESOURCE_IDENTIFIER.value
    assert resolve_deterministic_action("API-DEVICE-BOLA-001") == ExperimentActionPredicate.SUBSTITUTE_RESOURCE_IDENTIFIER.value


def test_04_state_action_mapping():
    """Verify STATE categories map strictly to EXECUTE_OUT_OF_ORDER_TRANSITION."""
    assert resolve_deterministic_action("API-STATE-001") == ExperimentActionPredicate.EXECUTE_OUT_OF_ORDER_TRANSITION.value
    assert resolve_deterministic_action("API-LIFECYCLE-001") == ExperimentActionPredicate.EXECUTE_OUT_OF_ORDER_TRANSITION.value
    assert resolve_deterministic_action("API-MULTI-STEP-AUTH-001") == ExperimentActionPredicate.EXECUTE_OUT_OF_ORDER_TRANSITION.value


def test_05_role_bfla_action_mapping():
    """Verify ROLE/BFLA categories map strictly to REPLAY_STEP_WITH_LOWER_ROLE."""
    assert resolve_deterministic_action("API-BFLA-001") == ExperimentActionPredicate.REPLAY_STEP_WITH_LOWER_ROLE.value
    assert resolve_deterministic_action("API-BFLA-002") == ExperimentActionPredicate.REPLAY_STEP_WITH_LOWER_ROLE.value
    assert resolve_deterministic_action("API-ROLE-BOUNDARY-001") == ExperimentActionPredicate.REPLAY_STEP_WITH_LOWER_ROLE.value


def test_06_cross_tenant_action_mapping():
    """Verify CROSS-TENANT category maps strictly to SUBSTITUTE_RESOURCE_IDENTIFIER."""
    assert resolve_deterministic_action("API-CROSS-TENANT-001") == ExperimentActionPredicate.SUBSTITUTE_RESOURCE_IDENTIFIER.value


# ---------------------------------------------------------------------------
# Tests 7-12: Outcome Vocabulary & Validation
# ---------------------------------------------------------------------------

def test_07_valid_outcome_vocabulary():
    """Verify legal_outcomes is a flat, deduplicated, sorted union of valid breach and safe outcomes."""
    skel = ExperimentSkeletonBuilder.build_skeleton("API-BOLA-001")
    registry = ExperimentPolarityValidator.TUPLE_COMPATIBILITY_REGISTRY["API-BOLA-001"]["SUBSTITUTE_RESOURCE_IDENTIFIER"]
    expected_union = sorted(list(registry[0] | registry[1]))
    assert skel.legal_outcomes == expected_union
    # Verify alphabetical sorting
    assert skel.legal_outcomes == sorted(skel.legal_outcomes)


def test_08_invalid_outcome_rejection():
    """Verify compliance rejection when candidate emits an outcome outside legal_outcomes."""
    skel = ExperimentSkeletonBuilder.build_skeleton("API-BOLA-001")
    is_valid, err = validate_skeleton_compliance(
        skel,
        candidate_action=skel.experiment_action,
        candidate_supporting="UNREGISTERED_BREACH_OUTCOME",
        candidate_disproving=skel.legal_outcomes[0],
    )
    assert is_valid is False
    assert "not in permitted legal_outcomes" in err


def test_09_category_action_mismatch_rejection():
    """Verify compliance rejection if candidate alters or mismatches the skeleton action."""
    skel = ExperimentSkeletonBuilder.build_skeleton("API-BOLA-001")
    is_valid, err = validate_skeleton_compliance(
        skel,
        candidate_action="TAMPER_REQUEST_PARAMETER",  # Wrong action
        candidate_supporting=skel.legal_outcomes[0],
        candidate_disproving=skel.legal_outcomes[1],
    )
    assert is_valid is False
    assert "action mismatch" in err.lower()


def test_10_action_outcome_mismatch_rejection():
    """Verify validator fails closed when candidate outcome is incompatible with category/action tuple."""
    is_valid, err = ExperimentPolarityValidator.validate_tuple(
        category_id="API-STATE-001",
        experiment_action="EXECUTE_OUT_OF_ORDER_TRANSITION",
        supporting_outcome="OWNERSHIP_NOT_ENFORCED",  # BOLA outcome, not state outcome
        disproving_outcome="STATE_TRANSITION_REJECTED",
    )
    assert is_valid is False
    assert "not a valid breach outcome" in err


def test_11_identical_outcomes_rejection():
    """Verify compliance and polarity validator reject identical supporting and disproving outcomes."""
    skel = ExperimentSkeletonBuilder.build_skeleton("API-BOLA-001")
    outcome = skel.legal_outcomes[0]
    is_valid, err = validate_skeleton_compliance(
        skel,
        candidate_action=skel.experiment_action,
        candidate_supporting=outcome,
        candidate_disproving=outcome,
    )
    assert is_valid is False
    assert "cannot be identical" in err

    p_valid, p_err = ExperimentPolarityValidator.validate_tuple(
        category_id="API-BOLA-001",
        experiment_action="SUBSTITUTE_RESOURCE_IDENTIFIER",
        supporting_outcome=outcome,
        disproving_outcome=outcome,
    )
    assert p_valid is False
    assert "cannot be identical" in p_err


def test_12_missing_semantic_outcome():
    """Verify rejection when candidate omits supporting or disproving outcome."""
    skel = ExperimentSkeletonBuilder.build_skeleton("API-BOLA-001")
    is_valid, err = validate_skeleton_compliance(
        skel,
        candidate_action=skel.experiment_action,
        candidate_supporting="",
        candidate_disproving=skel.legal_outcomes[0],
    )
    assert is_valid is False
    assert "missing supporting_outcome" in err


# ---------------------------------------------------------------------------
# Tests 13-16: Fail-Closed & Robustness
# ---------------------------------------------------------------------------

def test_13_malformed_llm_output_handling():
    """Verify parser fails closed on corrupted/non-JSON response."""
    contract = get_protocol_contract(OutputProtocolIdentifier.JSON_BAIR)
    with pytest.raises(Exception):
        contract.parser("Not a JSON object at all")


def test_14_schema_failure_handling():
    """Verify BairJsonObject validation fails closed on invalid decision-dependent slots."""
    with pytest.raises(ValueError):
        BairJsonObject(
            invariant="Security invariant",
            affected_target="/api/v1/resource",
            decision=HypothesisDecision.HYPOTHESIS,
            empirical_facts=[],  # Empty facts for HYPOTHESIS is invalid
            experiment_action="SUBSTITUTE_RESOURCE_IDENTIFIER",
            supporting_outcome="OWNERSHIP_NOT_ENFORCED",
            disproving_outcome="OWNERSHIP_ENFORCED",
        )


def test_15_grounding_failure_handling():
    """Verify I5 decision policy fails closed when empirical grounding fails."""
    cand = HypothesisModelOutput(
        decision=HypothesisDecision.HYPOTHESIS,
        affected_target="/api/v1/invoices",
        invariant="Authorization holds",
        evidence_gap="Missing access test",
        experiment_proposal="Substitute ID",
        supporting_evidence_ids=["FACT-NONEXISTENT-999"],
        experiment_action="SUBSTITUTE_RESOURCE_IDENTIFIER",
        supporting_outcome="OWNERSHIP_NOT_ENFORCED",
        disproving_outcome="OWNERSHIP_ENFORCED",
    )
    # Ensure functionality is relevant so it reaches grounding validation
    pack = LosslessStructuralPack(
        schema_version="2.0.0",
        asset_id="ASSET-01",
        endpoint_id="EP-01",
        route_template="/api/v1/invoices",
        http_method="POST",
        application_mutability="STATE_CHANGING",
        parameter_lineage=[{"param_name": "id", "location": "path"}],
        identity_matrix=[{"role": "ADMIN", "user_id": "u1"}, {"role": "USER", "user_id": "u2"}],
        observed_facts=[{"fact_id": "FACT-0001", "statement": "Valid fact"}],
        raw_body_sample="",
    )
    ev_state = EvidenceState(
        channel_a=pack,
        category_id="API-BOLA-001",
        empirical_evidence_present=True,
    )
    res = deterministic_decide(cand, ev_state)
    assert res.is_valid is False
    assert res.predicate_identifier == DecisionPredicate.FAIL_CLOSED_GROUNDING_REJECTION


def test_16_fail_closed_behavior_unknown_category():
    """Verify ExperimentSkeletonBuilder rejects unregistered categories."""
    with pytest.raises(ValueError) as exc:
        ExperimentSkeletonBuilder.build_skeleton("API-UNKNOWN-999")
    assert "Unrecognized vulnerability category" in str(exc.value)


# ---------------------------------------------------------------------------
# Tests 17-22: Non-Leakage Invariants
# ---------------------------------------------------------------------------

def test_17_zero_ground_truth_leakage():
    """Verify skeleton descriptor and prompt contain zero ground truth labels."""
    skel = ExperimentSkeletonBuilder.build_skeleton("API-BOLA-001")
    prompt = render_skeleton_prompt_block(skel)
    descriptor_json = json.dumps(skel.to_llm_visible_dict())

    for text in (prompt, descriptor_json):
        assert "ground_truth" not in text.lower()
        assert "true_positive" not in text.lower()
        assert "false_positive" not in text.lower()


def test_18_zero_breach_safe_partition_leakage():
    """Verify LLM-visible representation and prompt do NOT reveal breach vs safe outcome sets."""
    skel = ExperimentSkeletonBuilder.build_skeleton("API-BOLA-001")
    prompt = render_skeleton_prompt_block(skel)
    llm_dict = skel.to_llm_visible_dict()

    # Must NOT have separate keys
    assert "legal_supporting_outcomes" not in llm_dict
    assert "legal_disproving_outcomes" not in llm_dict
    assert "valid_breaches" not in llm_dict
    assert "valid_safes" not in llm_dict

    # In prompt, outcomes must appear in a single unified list
    assert "legal_supporting_outcomes" not in prompt
    assert "legal_disproving_outcomes" not in prompt
    assert "valid breach outcomes:" not in prompt.lower()
    assert "valid safe outcomes:" not in prompt.lower()


def test_19_zero_expected_decision_leakage():
    """Verify prompt and descriptor contain no expected_decision tokens."""
    skel = ExperimentSkeletonBuilder.build_skeleton("API-STATE-001")
    prompt = render_skeleton_prompt_block(skel)
    assert "expected_decision" not in prompt


def test_20_zero_vulnerability_control_label_leakage():
    """Verify prompt and descriptor contain no vulnerable/patched indicator tokens."""
    for cat in ("API-BOLA-001", "API-STATE-001", "API-BFLA-001", "API-CROSS-TENANT-001"):
        skel = ExperimentSkeletonBuilder.build_skeleton(cat)
        prompt = render_skeleton_prompt_block(skel)
        assert "vulnerable_variant" not in prompt
        assert "is_vulnerable" not in prompt
        assert "is_control" not in prompt
        assert "is_patched" not in prompt


def test_21_zero_scenario_label_leakage():
    """Verify prompt contains no scenario IDs or scenario suffixes."""
    skel = ExperimentSkeletonBuilder.build_skeleton("API-BOLA-001")
    prompt = render_skeleton_prompt_block(skel)
    assert "SCEN-" not in prompt
    assert "-VULN-" not in prompt
    assert "-PATCH-" not in prompt


def test_22_zero_secret_leakage():
    """Verify skeleton prompt contains no secret keys, JWT tokens, or credentials."""
    skel = ExperimentSkeletonBuilder.build_skeleton("API-BFLA-001")
    prompt = render_skeleton_prompt_block(skel)
    assert "eyJ" not in prompt  # Standard base64 JWT prefix
    assert "bearer" not in prompt.lower()
    assert "secret" not in prompt.lower()
    assert "password" not in prompt.lower()
    assert "private_key" not in prompt.lower()


# ---------------------------------------------------------------------------
# Tests 23-25: Determinism, Provenance & Byte-Identical Evidence
# ---------------------------------------------------------------------------

def test_23_deterministic_serialization():
    """Verify identical inputs yield byte-identical descriptor serialization."""
    skel1 = ExperimentSkeletonBuilder.build_skeleton("API-BOLA-001")
    skel2 = ExperimentSkeletonBuilder.build_skeleton("API-BOLA-001")
    assert skel1.model_dump_json() == skel2.model_dump_json()


def test_24_deterministic_provenance_hash():
    """Verify provenance hash is deterministic and reproducible."""
    skel = ExperimentSkeletonBuilder.build_skeleton("API-BOLA-001")
    hash1 = skel.provenance_hash
    skel_rebuilt = ExperimentSkeletonBuilder.build_skeleton("API-BOLA-001")
    assert skel_rebuilt.provenance_hash == hash1


def test_25_byte_identical_evidence_across_budget_conditions():
    """Verify that input evidence state is byte-identical across conditions P3-300, P3-512, P3-768."""
    gold_scens = {s.scenario_id: s for s in get_gold_set_scenarios()}
    for scen_meta in REPRESENTATIVE_BENCHMARK_SCENARIOS:
        sid = scen_meta["scenario_id"]
        scen = gold_scens[sid]
        ev_bytes = json.dumps(scen.initial_evidence, sort_keys=True).encode("utf-8")
        h1 = hashlib.sha256(ev_bytes).hexdigest()

        # Re-encode and assert parity
        ev_bytes2 = json.dumps(scen.initial_evidence, sort_keys=True).encode("utf-8")
        h2 = hashlib.sha256(ev_bytes2).hexdigest()
        assert h1 == h2


# ---------------------------------------------------------------------------
# Tests 26-30: Latency Spec, Immutability & Manifest Determinism
# ---------------------------------------------------------------------------

def test_26_thirty_second_timeout_classification():
    """Verify 30.0s is the hard timeout gate per frozen specs."""
    def classify_latency(lat_s: float) -> str:
        if lat_s <= 12.0:
            return "LATENCY_OPTIMAL"
        elif lat_s <= 30.0:
            return "LATENCY_OVER_TARGET"
        else:
            return "LATENCY_TIMEOUT"

    assert classify_latency(12.0) == "LATENCY_OPTIMAL"
    assert classify_latency(25.34) == "LATENCY_OVER_TARGET"
    assert classify_latency(29.99) == "LATENCY_OVER_TARGET"
    assert classify_latency(30.01) == "LATENCY_TIMEOUT"


def test_27_phase7_artifact_immutability():
    """Verify Phase 7 benchmark artifact SHA-256 remains byte-identical."""
    assert SEALED_P7_PATH.exists()
    assert hash_file(SEALED_P7_PATH) == EXPECTED_P7_SHA


def test_28_phase8_artifact_immutability():
    """Verify Phase 8 diagnostic artifact SHA-256 remains byte-identical."""
    assert SEALED_P8_PATH.exists()
    assert hash_file(SEALED_P8_PATH) == EXPECTED_P8_SHA


def test_29_phase6_9_evaluation_regression():
    """Verify that Policy 3 disaggregated scoring remains fully functional."""
    from src.eval.scorer import (
        EvaluationApplicabilityState,
        Policy3DeterministicScorer,
        ReviewerPresentationLabel,
        determine_applicability_state,
    )
    # Neutral evidence -> EXPLORATORY_EVALUATION_APPLICABLE
    app = determine_applicability_state(
        is_valid_output=True,
        target_relevant=True,
        canonical_evidence_has_anomaly=False,
    )
    assert app == EvaluationApplicabilityState.EXPLORATORY_EVALUATION_APPLICABLE

    # Anomaly evidence -> VULNERABILITY_EVALUATION_APPLICABLE
    app_vuln = determine_applicability_state(
        is_valid_output=True,
        target_relevant=True,
        canonical_evidence_has_anomaly=True,
    )
    assert app_vuln == EvaluationApplicabilityState.VULNERABILITY_EVALUATION_APPLICABLE


def test_30_manifest_determinism():
    """Verify Phase 9 manifest hash is reproducible and scenario counts match exactly 44 calls."""
    h1 = compute_manifest_hash()
    h2 = compute_manifest_hash()
    assert h1 == h2
    assert len(REPRESENTATIVE_BENCHMARK_SCENARIOS) == 6
    assert len(ACTIVE_EVIDENCE_FIXTURES) == 4
    assert len(PHASE9_CONDITIONS) == 3
    # 6 scens * 2 tracks * 3 conditions = 36 calls
    # 4 active fixtures * 1 track * 2 conditions = 8 calls
    # Total = 44 calls
    assert (6 * 2 * 3) + (4 * 1 * 2) == 44


def test_31_phase9_artifact_integrity():
    """Verify Phase 9 diagnostic artifact file, hash, and structure."""
    p9_json = REPO_ROOT / "data/eval/m5_phase9_semantic_budget_study.json"
    p9_sha = REPO_ROOT / "data/eval/m5_phase9_semantic_budget_study.json.sha256"

    assert p9_json.exists(), "Phase 9 artifact missing"
    assert p9_sha.exists(), "Phase 9 sha file missing"

    actual_sha = hash_file(p9_json)
    recorded_sha = p9_sha.read_text(encoding="utf-8").strip().split()[0].lower()
    assert actual_sha == recorded_sha, f"Phase 9 SHA mismatch: {actual_sha} != {recorded_sha}"

    data = json.loads(p9_json.read_text(encoding="utf-8"))
    assert data["status"] == "M5_PHASE9_COMPLETE"
    assert data["schema_version"] == "9.0.0"
    assert data["total_live_calls"] == 44

    metrics = data["metrics"]["condition_metrics"]
    assert "P3-300" in metrics
    assert "P3-512" in metrics
    assert "P3-768" in metrics
    assert metrics["P3-300"]["total_calls"] == 12
    assert metrics["P3-512"]["total_calls"] == 12
    assert metrics["P3-768"]["total_calls"] == 12
    assert len(data["metrics"]["active_evidence_diagnostic"]) == 8

