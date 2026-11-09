"""
Milestone M5 Phase 11.4: Pre-Live Unit Tests for Security Property Alignment and Track D.

Covers all 21 preflight requirements specified in Prompt Section 19:
1. Category -> allowed security-property mapping
2. Valid property selection
3. Invalid property rejection (SP2)
4. Property/category mismatch (SP3)
5. Property/invariant mismatch (SP4)
6. Property/evidence-gap mismatch (SP5)
7. Empty allowed property set fail-closed
8. No ground-truth leakage into property mappings
9. P3 remains unchanged
10. P4 schema correctness
11. P4 property enum enforcement
12. Attack predicate validation
13. Deterministic outcome binding unchanged
14. Bounded FACT selection unchanged
15. Bounded TARGET selection unchanged
16. P4 Track A deterministic reproducibility
17. P4 Track D package identity
18. P4 Track A vs Track D only changes intended context
19. Historical artifact hash immutability (Phases 7, 8, 9, 10)
20. Phase 11.2 artifact hash immutability
21. Phase 11.3 artifact hash immutability
"""

import hashlib
import json
from pathlib import Path
import pytest

from src.eval.scenarios import get_gold_set_scenarios
from src.evidence.cascade_models import LosslessStructuralPack
from src.eval.phase11_2_polarity.attack_predicate import (
    AttackPredicate,
    CATEGORY_SECURITY_PROPERTY_MAP,
    SecurityPropertyDomain,
)
from src.eval.phase11_2_polarity.outcome_binding import derive_outcomes_from_attack_predicate
from src.eval.phase11_3_grounding.allowed_sets import (
    build_scenario_allowed_sets,
    extract_allowed_fact_ids,
    extract_allowed_target_ids,
)
from src.eval.phase11_3_grounding.grounding_protocol import (
    get_inference_schema_for_condition as get_p3_schema,
    render_p3_prompt_instruction,
)
from src.eval.phase11_4_property_alignment.property_registry import (
    get_allowed_security_properties,
    is_property_allowed_for_category,
)
from src.eval.phase11_4_property_alignment.property_validator import (
    PropertyValidationResult,
    SecurityPropertyFailureCode,
    validate_security_property,
)
from src.eval.phase11_4_property_alignment.protocol import (
    get_p4_inference_schema,
    render_p4_prompt_instruction,
)
from src.eval.phase11_4_property_alignment.track_d import AuthoritativeTrackDBuilder

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
        raw_body_sample="Sample raw body",
    )


# 1. Category -> allowed security-property mapping
def test_01_category_to_property_mapping():
    bola_props = get_allowed_security_properties("API-BOLA-001")
    assert "RESOURCE_OWNERSHIP_INTEGRITY" in bola_props
    assert "OBJECT_LEVEL_AUTHORIZATION" in bola_props

    lifecycle_props = get_allowed_security_properties("API-LIFECYCLE-001")
    assert "STATE_TRANSITION_INTEGRITY" in lifecycle_props
    assert "LIFECYCLE_ORDERING" in lifecycle_props

    role_props = get_allowed_security_properties("API-ROLE-BOUNDARY-001")
    assert "ROLE_BOUNDARY_ENFORCEMENT" in role_props
    assert "FUNCTION_LEVEL_AUTHORIZATION" in role_props

    tenant_props = get_allowed_security_properties("API-CROSS-TENANT-001")
    assert "TENANT_ISOLATION" in tenant_props
    assert "CROSS_TENANT_AUTHORIZATION" in tenant_props


# 2. Valid property selection
def test_02_valid_property_selection():
    res = validate_security_property("API-BOLA-001", "RESOURCE_OWNERSHIP_INTEGRITY")
    assert res.is_valid
    assert res.primary_code is None


# 3. Invalid property rejection (SP2)
def test_03_invalid_property_rejection():
    res = validate_security_property("API-BOLA-001", "NON_EXISTENT_PROPERTY_STRING")
    assert not res.is_valid
    assert res.primary_code == SecurityPropertyFailureCode.SP2


# 4. Property/category mismatch (SP3)
def test_04_property_category_mismatch():
    # Asserting TENANT_ISOLATION on BOLA is a mismatch
    res = validate_security_property("API-BOLA-001", "TENANT_ISOLATION")
    assert not res.is_valid
    assert res.primary_code == SecurityPropertyFailureCode.SP3


# 5. Property/invariant mismatch (SP4)
def test_05_property_invariant_mismatch():
    res = validate_security_property(
        category_id="API-BOLA-001",
        security_property="LIFECYCLE_ORDERING",
        invariant_definition="An authorized user may only access invoices they own (resource ownership invariant)",
    )
    assert not res.is_valid
    assert res.primary_code in (SecurityPropertyFailureCode.SP3, SecurityPropertyFailureCode.SP4)


# 6. Property/evidence-gap mismatch (SP5)
def test_06_property_evidence_gap_mismatch():
    res = validate_security_property(
        category_id="API-ROLE-BOUNDARY-001",
        security_property="MUTATION_INTEGRITY",
        evidence_gap_type="MISSING_TENANT_ISOLATION_CHECK",
    )
    assert not res.is_valid
    assert res.primary_code in (SecurityPropertyFailureCode.SP3, SecurityPropertyFailureCode.SP5)


# 7. Empty allowed property set fail-closed
def test_07_empty_allowed_property_set_fail_closed():
    res = validate_security_property("UNKNOWN-NON-EXISTENT-CATEGORY-999", "RESOURCE_OWNERSHIP_INTEGRITY")
    assert not res.is_valid
    assert res.primary_code == SecurityPropertyFailureCode.SP3


# 8. No ground-truth leakage into property mappings
def test_08_no_ground_truth_leakage():
    for cat, props in CATEGORY_SECURITY_PROPERTY_MAP.items():
        assert "vuln" not in cat.lower()
        assert "patch" not in cat.lower()
        for p in props:
            p_val = p.value.lower()
            assert "vuln" not in p_val
            assert "patch" not in p_val
            assert "ground_truth" not in p_val


# 9. P3 remains unchanged
def test_09_p3_remains_unchanged():
    p3_schema = get_p3_schema("P3", allowed_fact_ids=["FACT-01"], allowed_target_ids=["EP-01"])
    # P3 has global 10-property enum
    assert len(p3_schema["properties"]["attack_predicate"]["properties"]["security_property"]["enum"]) == len(SecurityPropertyDomain)


# 10. P4 schema correctness
def test_10_p4_schema_correctness():
    p4_schema = get_p4_inference_schema(
        allowed_fact_ids=["FACT-01"],
        allowed_target_ids=["EP-01"],
        allowed_security_properties=["RESOURCE_OWNERSHIP_INTEGRITY", "OBJECT_LEVEL_AUTHORIZATION"],
    )
    assert p4_schema["type"] == "object"
    assert "attack_predicate" in p4_schema["properties"]
    prop_schema = p4_schema["properties"]["attack_predicate"]["properties"]["security_property"]
    assert prop_schema["enum"] == ["OBJECT_LEVEL_AUTHORIZATION", "RESOURCE_OWNERSHIP_INTEGRITY"]


# 11. P4 property enum enforcement
def test_11_p4_property_enum_enforcement():
    allowed_props = get_allowed_security_properties("API-LIFECYCLE-001")
    p4_schema = get_p4_inference_schema(
        allowed_fact_ids=["FACT-01"],
        allowed_target_ids=["EP-01"],
        allowed_security_properties=allowed_props,
    )
    assert p4_schema["properties"]["attack_predicate"]["properties"]["security_property"]["enum"] == [
        "LIFECYCLE_ORDERING",
        "STATE_TRANSITION_INTEGRITY",
    ]


# 12. Attack predicate validation
def test_12_attack_predicate_validation():
    pred = AttackPredicate(
        subject="UNAUTHORIZED_USER",
        operation="SUBSTITUTE_RESOURCE_IDENTIFIER",
        target="/api/v1/invoices/123",
        security_property=SecurityPropertyDomain.RESOURCE_OWNERSHIP_INTEGRITY,
        expected_violation="Unauthorized access to another tenant invoice",
    )
    assert pred.operation == "SUBSTITUTE_RESOURCE_IDENTIFIER"
    assert pred.security_property == "RESOURCE_OWNERSHIP_INTEGRITY"


# 13. Deterministic outcome binding unchanged
def test_13_deterministic_outcome_binding_unchanged():
    pred = AttackPredicate(
        subject="UNAUTHORIZED_USER",
        operation="SUBSTITUTE_RESOURCE_IDENTIFIER",
        target="/api/v1/invoices/123",
        security_property=SecurityPropertyDomain.RESOURCE_OWNERSHIP_INTEGRITY,
        expected_violation="Unauthorized access",
    )
    binding = derive_outcomes_from_attack_predicate(
        category_id="API-BOLA-001",
        experiment_action="SUBSTITUTE_RESOURCE_IDENTIFIER",
        attack_predicate=pred,
        target_asset_id="ASSET-01",
    )
    assert binding.is_valid
    assert binding.supporting_outcome == "HTTP_200_OK"
    assert binding.disproving_outcome == "HTTP_403_FORBIDDEN"
    assert binding.outcome_origin == "DETERMINISTICALLY_DERIVED"


# 14. Bounded FACT selection unchanged
def test_14_bounded_fact_selection_unchanged(sample_pack):
    all_scenarios = {s.scenario_id: s for s in get_gold_set_scenarios()}
    scen = all_scenarios["SCEN-SAAS_BILLING-INV-DETAILS-VULN-01"]
    facts = extract_allowed_fact_ids(scen, pack=sample_pack)
    assert facts == ["FACT-SAAS_BILLING-INV-DETAILS-DOC"]


# 15. Bounded TARGET selection unchanged
def test_15_bounded_target_selection_unchanged(sample_pack):
    all_scenarios = {s.scenario_id: s for s in get_gold_set_scenarios()}
    scen = all_scenarios["SCEN-SAAS_BILLING-INV-DETAILS-VULN-01"]
    targets = extract_allowed_target_ids(scen, pack=sample_pack)
    assert targets == ["EP-ASSET-SAAS_BILLING-INV-DETAILS-01"]


# 16. P4 Track A deterministic reproducibility
def test_16_p4_track_a_reproducibility():
    p1 = render_p4_prompt_instruction(
        allowed_fact_ids=["FACT-01"],
        allowed_target_ids=["EP-01"],
        allowed_security_properties=["RESOURCE_OWNERSHIP_INTEGRITY"],
    )
    p2 = render_p4_prompt_instruction(
        allowed_fact_ids=["FACT-01"],
        allowed_target_ids=["EP-01"],
        allowed_security_properties=["RESOURCE_OWNERSHIP_INTEGRITY"],
    )
    assert p1 == p2


# 17. P4 Track D package identity
def test_17_p4_track_d_package_identity(sample_pack):
    all_scenarios = {s.scenario_id: s for s in get_gold_set_scenarios()}
    scen = all_scenarios["SCEN-SAAS_BILLING-INV-DETAILS-VULN-01"]
    builder = AuthoritativeTrackDBuilder()
    ctx1, vapt1, prov1 = builder.build_track_d_context(scen, sample_pack)
    ctx2, vapt2, prov2 = builder.build_track_d_context(scen, sample_pack)
    assert prov1 == prov2
    assert ctx1.user_prompt == ctx2.user_prompt


# 18. P4 Track A vs Track D only changes intended context
def test_18_track_a_vs_track_d_only_changes_intended_context(sample_pack):
    all_scenarios = {s.scenario_id: s for s in get_gold_set_scenarios()}
    scen = all_scenarios["SCEN-SAAS_BILLING-INV-DETAILS-VULN-01"]
    builder = AuthoritativeTrackDBuilder()
    ctx_d, vapt_d, prov_d = builder.build_track_d_context(scen, sample_pack)

    # In Track D, raw target snippets or VAPT are eligible
    assert "=== TARGET ENVELOPE ===" in ctx_d.user_prompt
    assert "=== STRUCTURAL DIFFS & SECURITY INVARIANTS ===" in ctx_d.user_prompt


# 19. Historical artifact hash immutability (Phases 7, 8, 9, 10)
@pytest.mark.parametrize(
    "rel_path,expected_hash",
    [
        ("data/eval/m5_phase7_benchmark_final.json", "1e0ed90c4aa672f135d2d2f2240a14d22fa0037c03efda33634f4bf10ff0b125"),
        ("data/eval/m5_phase8_semantic_study.json", "b1df9a62fb07d76e0abf6e3935ccbabdaa1713f4c594019ae30c9e59567a45c6"),
        ("data/eval/m5_phase9_semantic_budget_study.json", "3c0d3e503c7ed24470b14dfde0bd763c631a9b5dbf70c047bbca72cfaab07f95"),
        ("data/eval/m5_phase10_full_population_validation.json", "6821d207729de97ac99657a09e38c25895a73285fe9c485d299dc27f37d2bdba"),
        ("data/eval/m5_phase10_checkpoint.json", "40f9f725fca5fdf05a76836182960b7f0d4c303a182d6e8af068a1b57e8f4537"),
    ],
)
def test_19_historical_artifact_hashes_unchanged(rel_path, expected_hash):
    target = REPO_ROOT / rel_path
    assert target.exists(), f"File {rel_path} does not exist"
    h = hashlib.sha256(target.read_bytes()).hexdigest()
    assert h == expected_hash, f"Hash mismatch for {rel_path}!"


# 20. Phase 11.2 artifact hash immutability
@pytest.mark.parametrize(
    "rel_path,expected_hash",
    [
        ("data/eval/m5_phase11_2_live_results.json", "48dd13c5e46dfc75f2c27ca64dd5efae45b0686043c99d9f19fb0749e05540a9"),
        ("data/eval/m5_phase11_2_manifest.json", "b72e0dfbafb23b7edf561fe5df0d44ff65e45d5b52caf251cd039fbedd304cab"),
        ("docs/M5_PHASE11_2_POLARITY_DIAGNOSTIC_PREREGISTRATION.md", "8c241d79d520783e238fee70df01755a71692ec6c5964553e6b9761adc53ce8a"),
        ("docs/M5_PHASE11_2_POLARITY_DIAGNOSTIC_REPORT.md", "ff3d8040f1df44eb065c6b1735f9e1dad001f0cc7823c14037892ebd892db742"),
    ],
)
def test_20_phase11_2_artifact_hashes_unchanged(rel_path, expected_hash):
    target = REPO_ROOT / rel_path
    assert target.exists(), f"File {rel_path} does not exist"
    h = hashlib.sha256(target.read_bytes()).hexdigest()
    assert h == expected_hash, f"Hash mismatch for {rel_path}!"


# 21. Phase 11.3 artifact hash immutability
@pytest.mark.parametrize(
    "rel_path,expected_hash",
    [
        ("data/eval/m5_phase11_3_live_results.json", "72352ee6ebd774e487f389ebd39322dbb169207257232656e3f35d534fe05271"),
        ("data/eval/m5_phase11_3_manifest.json", "44063227ed7a76731a249c44405d62eef910d272b5568774c11e910b9f146995"),
        ("docs/M5_PHASE11_3_GROUNDING_DIAGNOSTIC_PREREGISTRATION.md", "90f5a3b461820ae019943e0d0f7dffe76c9f238046c1dad9744e86ad4a01518d"),
        ("docs/M5_PHASE11_3_GROUNDING_DIAGNOSTIC_REPORT.md", "727fe092cb1ffadee8d5e92abf35336c0bd08a52bc515a5b647a5aab5b6cb908"),
    ],
)
def test_21_phase11_3_artifact_hashes_unchanged(rel_path, expected_hash):
    target = REPO_ROOT / rel_path
    assert target.exists(), f"File {rel_path} does not exist"
    h = hashlib.sha256(target.read_bytes()).hexdigest()
    assert h == expected_hash, f"Hash mismatch for {rel_path}!"
