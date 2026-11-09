"""
Milestone M5 Phase 11.3: Deterministic Unit Tests for Grounding Recovery Diagnostic.

Covers all 20 preflight requirements specified in Prompt Section 20:
1. P1 protocol unchanged
2. P2 allowed fact ID enumeration
3. Invalid fact ID rejection
4. Invented fact ID rejection
5. Duplicate fact handling
6. Empty fact selection behavior
7. P3 allowed target enumeration
8. Invalid target rejection
9. Invented target rejection
10. Free-form target rejection
11. Valid target selection
12. Fact-target compatibility
13. No ground-truth leakage into allowed sets
14. No ground-truth leakage into prompts
15. Deterministic P2 output validation
16. Deterministic P3 output validation
17. Outcome binding unchanged
18. Attack predicate unchanged
19. Sealed Phase 10 hashes unchanged
20. Phase 11.2 source artifact hashes unchanged
"""

import hashlib
import json
from pathlib import Path
import pytest

from src.eval.scenarios import get_gold_set_scenarios
from src.evidence.cascade_models import LosslessStructuralPack
from src.eval.phase11_2_polarity.attack_predicate import AttackPredicate, SecurityPropertyDomain
from src.eval.phase11_2_polarity.outcome_binding import derive_outcomes_from_attack_predicate
from src.eval.phase11_2_polarity.protocol import P1BairJsonObject, P1_PROMPT_INSTRUCTION
from src.eval.phase11_3_grounding.allowed_sets import (
    build_scenario_allowed_sets,
    extract_allowed_fact_ids,
    extract_allowed_target_ids,
    ScenarioAllowedSets,
)
from src.eval.phase11_3_grounding.grounding_protocol import (
    get_inference_schema_for_condition,
    render_p2_prompt_instruction,
    render_p3_prompt_instruction,
)
from src.eval.phase11_3_grounding.validator import (
    GroundingFailureCode,
    GroundingValidationResult,
    is_free_form_prose,
    is_valid_target_syntax,
    Phase11GroundingValidator,
)

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


@pytest.fixture
def sample_pack() -> LosslessStructuralPack:
    return LosslessStructuralPack(
        schema_version="2.0.0",
        asset_id="ASSET-SAAS_BILLING-INV-DETAILS-01",
        endpoint_id="EP-ASSET-SAAS_BILLING-INV-DETAILS-01",
        route_template="/api/v1/invoices/{id}",
        http_method="GET",
        application_mutability="READ_ONLY",
        parameter_lineage=[{"param_id": "PARAM-SAAS-INV-ID", "name": "id", "location": "path"}],
        identity_matrix=[],
        has_privilege_level_delta=False,
        has_cross_identity_object_access_success=False,
        observed_facts=[
            {"fact_id": "FACT-SAAS_BILLING-INV-DETAILS-DOC", "statement": "Invoice retrieval."}
        ],
        raw_body_sample="",
    )


@pytest.fixture
def validator() -> Phase11GroundingValidator:
    return Phase11GroundingValidator()


# 1. P1 protocol unchanged
def test_01_p1_protocol_unchanged():
    p1_schema = get_inference_schema_for_condition("P1")
    assert p1_schema["properties"]["affected_target"]["type"] == "string"
    assert "enum" not in p1_schema["properties"]["affected_target"]
    assert p1_schema["properties"]["empirical_facts"]["type"] == "array"
    assert "pattern" in p1_schema["properties"]["empirical_facts"]["items"]
    assert "enum" not in p1_schema["properties"]["empirical_facts"]["items"]


# 2. P2 allowed fact ID enumeration
def test_02_p2_allowed_fact_id_enumeration(sample_pack):
    all_scenarios = {s.scenario_id: s for s in get_gold_set_scenarios()}
    scen = all_scenarios["SCEN-SAAS_BILLING-INV-DETAILS-VULN-01"]
    facts = extract_allowed_fact_ids(scen, pack=sample_pack)
    assert facts == ["FACT-SAAS_BILLING-INV-DETAILS-DOC"]
    p2_schema = get_inference_schema_for_condition("P2", allowed_fact_ids=facts)
    assert p2_schema["properties"]["empirical_facts"]["items"]["enum"] == facts


# 3. Invalid fact ID rejection (G1)
def test_03_invalid_fact_id_rejection(validator, sample_pack):
    output = {
        "decision": "HYPOTHESIS",
        "affected_target": sample_pack.endpoint_id,
        "empirical_facts": ["INVALID_ID_WITHOUT_PREFIX"],
    }
    res = validator.validate_grounding(
        parsed_dict=output,
        allowed_fact_ids=["FACT-SAAS_BILLING-INV-DETAILS-DOC"],
        allowed_target_ids=[sample_pack.endpoint_id],
        pack=sample_pack,
        condition_id="P2",
    )
    assert not res.is_valid
    assert res.primary_code == GroundingFailureCode.G1


# 4. Invented fact ID rejection (G2)
def test_04_invented_fact_id_rejection(validator, sample_pack):
    output = {
        "decision": "HYPOTHESIS",
        "affected_target": sample_pack.endpoint_id,
        "empirical_facts": ["FACT-001", "FACT-002"],
    }
    res = validator.validate_grounding(
        parsed_dict=output,
        allowed_fact_ids=["FACT-SAAS_BILLING-INV-DETAILS-DOC"],
        allowed_target_ids=[sample_pack.endpoint_id],
        pack=sample_pack,
        condition_id="P2",
    )
    assert not res.is_valid
    assert res.primary_code == GroundingFailureCode.G2


# 5. Duplicate fact handling
def test_05_duplicate_fact_handling(sample_pack):
    all_scenarios = {s.scenario_id: s for s in get_gold_set_scenarios()}
    scen = all_scenarios["SCEN-SAAS_BILLING-INV-DETAILS-VULN-01"]
    sample_pack.observed_facts.append(
        {"fact_id": "FACT-SAAS_BILLING-INV-DETAILS-DOC", "statement": "Duplicate"}
    )
    facts = extract_allowed_fact_ids(scen, pack=sample_pack)
    assert len(facts) == 1
    assert facts == ["FACT-SAAS_BILLING-INV-DETAILS-DOC"]


# 6. Empty fact selection behavior
def test_06_empty_fact_selection_behavior(validator, sample_pack):
    # Empty facts is valid for non-hypothesis abstentions
    abstention = {
        "decision": "NO_RELEVANT_FUNCTIONALITY",
        "affected_target": sample_pack.endpoint_id,
        "empirical_facts": [],
    }
    res = validator.validate_grounding(
        parsed_dict=abstention,
        allowed_fact_ids=["FACT-SAAS_BILLING-INV-DETAILS-DOC"],
        allowed_target_ids=[sample_pack.endpoint_id],
        pack=sample_pack,
        condition_id="P2",
    )
    assert res.is_valid

    # Empty facts is rejected for HYPOTHESIS (G8 - UNGROUNDED_HYPOTHESIS)
    hypo = {
        "decision": "HYPOTHESIS",
        "affected_target": sample_pack.endpoint_id,
        "empirical_facts": [],
    }
    res_hyp = validator.validate_grounding(
        parsed_dict=hypo,
        allowed_fact_ids=["FACT-SAAS_BILLING-INV-DETAILS-DOC"],
        allowed_target_ids=[sample_pack.endpoint_id],
        pack=sample_pack,
        condition_id="P2",
    )
    assert not res_hyp.is_valid
    assert res_hyp.primary_code == GroundingFailureCode.G8


# 7. P3 allowed target enumeration
def test_07_p3_allowed_target_enumeration(sample_pack):
    all_scenarios = {s.scenario_id: s for s in get_gold_set_scenarios()}
    scen = all_scenarios["SCEN-SAAS_BILLING-INV-DETAILS-VULN-01"]
    targets = extract_allowed_target_ids(scen, pack=sample_pack)
    assert targets == ["EP-ASSET-SAAS_BILLING-INV-DETAILS-01"]
    p3_schema = get_inference_schema_for_condition(
        "P3",
        allowed_fact_ids=["FACT-SAAS_BILLING-INV-DETAILS-DOC"],
        allowed_target_ids=targets,
    )
    assert p3_schema["properties"]["affected_target"]["enum"] == targets


# 8. Invalid target syntax rejection (G3)
def test_08_invalid_target_rejection(validator, sample_pack):
    output = {
        "decision": "HYPOTHESIS",
        "affected_target": "INVALID_TARGET_SYNTAX",
        "empirical_facts": ["FACT-SAAS_BILLING-INV-DETAILS-DOC"],
    }
    res = validator.validate_grounding(
        parsed_dict=output,
        allowed_fact_ids=["FACT-SAAS_BILLING-INV-DETAILS-DOC"],
        allowed_target_ids=[sample_pack.endpoint_id],
        pack=sample_pack,
        condition_id="P3",
    )
    assert not res.is_valid
    assert res.primary_code == GroundingFailureCode.G3


# 9. Invented target rejection (G4 under P3)
def test_09_invented_target_rejection(validator, sample_pack):
    output = {
        "decision": "HYPOTHESIS",
        "affected_target": "EP-INVENTED-TARGET-999",
        "empirical_facts": ["FACT-SAAS_BILLING-INV-DETAILS-DOC"],
    }
    res = validator.validate_grounding(
        parsed_dict=output,
        allowed_fact_ids=["FACT-SAAS_BILLING-INV-DETAILS-DOC"],
        allowed_target_ids=[sample_pack.endpoint_id],
        pack=sample_pack,
        condition_id="P3",
    )
    assert not res.is_valid
    assert res.primary_code == GroundingFailureCode.G4


# 10. Free-form target rejection (G7)
def test_10_free_form_target_rejection(validator, sample_pack):
    prose_targets = [
        "The target resource identifier is the billing invoice record.",
        "The target endpoint is /api/v1/users/{id}/roles, which assigns organization-level permissions.",
        "PARTITION P3",
        "NO_RELEVANT_FUNCTIONALITY",
    ]
    for pt in prose_targets:
        assert is_free_form_prose(pt)
        output = {
            "decision": "HYPOTHESIS",
            "affected_target": pt,
            "empirical_facts": ["FACT-SAAS_BILLING-INV-DETAILS-DOC"],
        }
        res = validator.validate_grounding(
            parsed_dict=output,
            allowed_fact_ids=["FACT-SAAS_BILLING-INV-DETAILS-DOC"],
            allowed_target_ids=[sample_pack.endpoint_id],
            pack=sample_pack,
            condition_id="P1",
        )
        assert not res.is_valid
        assert res.primary_code == GroundingFailureCode.G7


# 11. Valid target selection
def test_11_valid_target_selection(validator, sample_pack):
    output = {
        "decision": "HYPOTHESIS",
        "affected_target": sample_pack.endpoint_id,
        "empirical_facts": ["FACT-SAAS_BILLING-INV-DETAILS-DOC"],
    }
    res = validator.validate_grounding(
        parsed_dict=output,
        allowed_fact_ids=["FACT-SAAS_BILLING-INV-DETAILS-DOC"],
        allowed_target_ids=[sample_pack.endpoint_id],
        pack=sample_pack,
        condition_id="P3",
    )
    assert res.is_valid
    assert res.primary_code is None


# 12. Fact-target compatibility (G6)
def test_12_fact_target_compatibility(validator, sample_pack):
    # Pack only has FACT-SAAS_BILLING-INV-DETAILS-DOC
    output = {
        "decision": "HYPOTHESIS",
        "affected_target": sample_pack.endpoint_id,
        "empirical_facts": ["FACT-OTHER-SCENARIO-DOC"],
    }
    res = validator.validate_grounding(
        parsed_dict=output,
        allowed_fact_ids=["FACT-OTHER-SCENARIO-DOC"],  # artificially allowed
        allowed_target_ids=[sample_pack.endpoint_id],
        pack=sample_pack,
        condition_id="P3",
    )
    assert not res.is_valid
    assert res.primary_code == GroundingFailureCode.G6


# 13. No ground-truth leakage into allowed sets
def test_13_no_ground_truth_leakage_into_allowed_sets():
    all_scenarios = get_gold_set_scenarios()
    for scen in all_scenarios:
        sets = build_scenario_allowed_sets(scen)
        for fid in sets.allowed_fact_ids:
            fid_lower = fid.lower()
            assert "vuln" not in fid_lower
            assert "-patch-" not in fid_lower
            assert not fid_lower.endswith("-patch")
        for tid in sets.allowed_target_ids:
            tid_lower = tid.lower()
            assert "vuln" not in tid_lower
            assert "-patch-" not in tid_lower
            assert not tid_lower.endswith("-patch")


# 14. No ground-truth leakage into prompts
def test_14_no_ground_truth_leakage_into_prompts():
    all_scenarios = {s.scenario_id: s for s in get_gold_set_scenarios()}
    scen = all_scenarios["SCEN-SAAS_BILLING-INV-DETAILS-VULN-01"]
    sets = build_scenario_allowed_sets(scen)
    p2_prompt = render_p2_prompt_instruction(sets.allowed_fact_ids)
    p3_prompt = render_p3_prompt_instruction(sets.allowed_fact_ids, sets.allowed_target_ids)
    for p in [p2_prompt, p3_prompt]:
        p_lower = p.lower()
        assert "ground_truth" not in p_lower
        assert "expected_decision" not in p_lower
        assert "-vuln-" not in p_lower
        assert "-patch-" not in p_lower


# 15. Deterministic P2 output validation
def test_15_deterministic_p2_output_validation(validator, sample_pack):
    allowed_facts = ["FACT-SAAS_BILLING-INV-DETAILS-DOC"]
    allowed_targets = [sample_pack.endpoint_id]

    # Valid P2 output (facts bounded, target structurally valid route)
    valid_p2 = {
        "decision": "HYPOTHESIS",
        "affected_target": sample_pack.route_template,
        "empirical_facts": ["FACT-SAAS_BILLING-INV-DETAILS-DOC"],
    }
    res = validator.validate_grounding(
        parsed_dict=valid_p2,
        allowed_fact_ids=allowed_facts,
        allowed_target_ids=allowed_targets,
        pack=sample_pack,
        condition_id="P2",
    )
    assert res.is_valid


# 16. Deterministic P3 output validation
def test_16_deterministic_p3_output_validation(validator, sample_pack):
    allowed_facts = ["FACT-SAAS_BILLING-INV-DETAILS-DOC"]
    allowed_targets = [sample_pack.endpoint_id]

    valid_p3 = {
        "decision": "HYPOTHESIS",
        "affected_target": sample_pack.endpoint_id,
        "empirical_facts": ["FACT-SAAS_BILLING-INV-DETAILS-DOC"],
    }
    res = validator.validate_grounding(
        parsed_dict=valid_p3,
        allowed_fact_ids=allowed_facts,
        allowed_target_ids=allowed_targets,
        pack=sample_pack,
        condition_id="P3",
    )
    assert res.is_valid


# 17. Outcome binding unchanged
def test_17_outcome_binding_unchanged():
    pred = AttackPredicate(
        subject="UNAUTHORIZED_TENANT_USER",
        operation="SUBSTITUTE_RESOURCE_IDENTIFIER",
        target="/api/v1/invoices/100",
        security_property=SecurityPropertyDomain.RESOURCE_OWNERSHIP_INTEGRITY,
        expected_violation="Access to unowned invoice granted",
    )
    res = derive_outcomes_from_attack_predicate(
        category_id="API-BOLA-001",
        experiment_action="SUBSTITUTE_RESOURCE_IDENTIFIER",
        attack_predicate=pred,
        target_asset_id="ASSET-01",
    )
    assert res.is_valid
    assert res.supporting_outcome == "HTTP_200_OK"
    assert res.disproving_outcome == "HTTP_403_FORBIDDEN"


# 18. Attack predicate unchanged
def test_18_attack_predicate_unchanged():
    pred = AttackPredicate(
        subject="CALLER_A",
        operation="EXECUTE_OUT_OF_ORDER_TRANSITION",
        target="/api/v1/refund",
        security_property=SecurityPropertyDomain.STATE_TRANSITION_INTEGRITY,
        expected_violation="Refund processed in cancelled state",
    )
    d = pred.to_canonical_dict()
    assert d["operation"] == "EXECUTE_OUT_OF_ORDER_TRANSITION"
    assert d["security_property"] == "STATE_TRANSITION_INTEGRITY"


# 19. Sealed Phase 10 hashes unchanged
@pytest.mark.parametrize(
    "rel_path,expected_hash",
    [
        ("data/eval/m5_phase10_full_population_validation.json", "6821d207729de97ac99657a09e38c25895a73285fe9c485d299dc27f37d2bdba"),
        ("data/eval/m5_phase10_checkpoint.json", "40f9f725fca5fdf05a76836182960b7f0d4c303a182d6e8af068a1b57e8f4537"),
    ],
)
def test_19_sealed_phase10_hashes_unchanged(rel_path, expected_hash):
    target = REPO_ROOT / rel_path
    assert target.exists(), f"File {rel_path} does not exist"
    h = hashlib.sha256(target.read_bytes()).hexdigest()
    assert h == expected_hash, f"Hash mismatch for {rel_path}!"


# 20. Phase 11.2 source artifact hashes unchanged
@pytest.mark.parametrize(
    "rel_path,expected_hash",
    [
        ("data/eval/m5_phase11_2_live_results.json", "48dd13c5e46dfc75f2c27ca64dd5efae45b0686043c99d9f19fb0749e05540a9"),
        ("data/eval/m5_phase11_2_manifest.json", "b72e0dfbafb23b7edf561fe5df0d44ff65e45d5b52caf251cd039fbedd304cab"),
        ("docs/M5_PHASE11_2_POLARITY_DIAGNOSTIC_PREREGISTRATION.md", "8c241d79d520783e238fee70df01755a71692ec6c5964553e6b9761adc53ce8a"),
        ("docs/M5_PHASE11_2_POLARITY_DIAGNOSTIC_REPORT.md", "ff3d8040f1df44eb065c6b1735f9e1dad001f0cc7823c14037892ebd892db742"),
    ],
)
def test_20_phase11_2_source_artifact_hashes_unchanged(rel_path, expected_hash):
    target = REPO_ROOT / rel_path
    assert target.exists(), f"File {rel_path} does not exist"
    h = hashlib.sha256(target.read_bytes()).hexdigest()
    assert h == expected_hash, f"Hash mismatch for {rel_path}!"
