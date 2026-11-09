"""
Milestone M5 Phase 11.5: Pre-Live Unit Tests for Confirmatory Benchmark.

Verifies:
1. Exact Phase 10 population count (84 scenarios: 36 vulnerable, 48 controls)
2. Canonical Phase 10 dataset digest immutability
3. Sealed Phase 10 checkpoint immutability
4. Phase 11.4 artifact digests immutability
5. Phase 11.3 artifact digests immutability
6. Phase 11.2 artifact digests immutability
7. Category-to-Property registry completeness for all 10 population categories
8. TUPLE_COMPATIBILITY_REGISTRY completeness for all 10 population categories
9. ExperimentSkeletonBuilder completeness for all 10 population categories
10. Paired execution schedule length and balance (168 calls)
11. Paired execution schedule deterministic reproducibility
12. Exact McNemar test implementation correctness
13. Ground truth firewall assertions across prompts and allowed sets
"""

import hashlib
import json
from pathlib import Path
import pytest

from src.engine.decision_policy import ExperimentPolarityValidator
from src.engine.experiment_skeleton import ExperimentSkeletonBuilder
from src.engine.prompts import get_counterfactual_template
from src.eval.m4_live_benchmark import infer_evidence_gap_type
from src.eval.scenarios import get_gold_set_scenarios
from src.evidence.cascade_models import LosslessStructuralPack
from src.eval.phase11_3_grounding.allowed_sets import build_scenario_allowed_sets
from src.eval.phase11_4_property_alignment.property_registry import get_allowed_security_properties
from src.eval.phase11_5_confirmatory.analysis import exact_mcnemar_test
from src.eval.phase11_5_confirmatory.runner import (
    EXPECTED_PHASE10_POPULATION_DIGEST,
    FROZEN_ORDER_SEED,
    get_scenario_condition_order,
)

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


# 1. Exact Phase 10 population count
def test_01_population_count_and_distribution():
    scens = get_gold_set_scenarios()
    assert len(scens) == 84
    vulns = [s for s in scens if s.vulnerable_variant]
    controls = [s for s in scens if not s.vulnerable_variant]
    assert len(vulns) == 36
    assert len(controls) == 48


# 2. Canonical Phase 10 dataset digest immutability
def test_02_canonical_phase10_digest():
    p10_file = REPO_ROOT / "data/eval/m5_phase10_full_population_validation.json"
    assert p10_file.exists()
    digest = hashlib.sha256(p10_file.read_bytes()).hexdigest()
    assert digest == EXPECTED_PHASE10_POPULATION_DIGEST


# 3. Sealed Phase 10 checkpoint immutability
def test_03_sealed_phase10_checkpoint():
    p10_chk = REPO_ROOT / "data/eval/m5_phase10_checkpoint.json"
    assert p10_chk.exists()
    digest = hashlib.sha256(p10_chk.read_bytes()).hexdigest()
    assert digest == "40f9f725fca5fdf05a76836182960b7f0d4c303a182d6e8af068a1b57e8f4537"


# 4. Phase 11.4 artifact digests immutability
@pytest.mark.parametrize(
    "rel_path,expected_hash",
    [
        ("data/eval/m5_phase11_4_live_results.json", "beaa7cad759af8641dd8d8231cc8bd66d95a1d649a757840fc60e91161e59eae"),
        ("data/eval/m5_phase11_4_manifest.json", "766ae86cc8a0360f16674fefd7b14ce9ef01b6dfa815d984903815911d1894cb"),
        ("docs/M5_PHASE11_4_SECURITY_PROPERTY_AND_TRACK_D_PREREGISTRATION.md", "c102aae1b38bdcf0a8e6a788f96f9fa00de2de1a4a9d610c286f4f0ef09fbe41"),
        ("docs/M5_PHASE11_4_SECURITY_PROPERTY_AND_TRACK_D_REPORT.md", "1c887ae571e288a7cc2c862c0ee1ca1f97698be10724242670eba382ee969839"),
    ],
)
def test_04_phase11_4_artifacts_unchanged(rel_path, expected_hash):
    p = REPO_ROOT / rel_path
    assert p.exists()
    assert hashlib.sha256(p.read_bytes()).hexdigest() == expected_hash


# 5. Phase 11.3 artifact digests immutability
@pytest.mark.parametrize(
    "rel_path,expected_hash",
    [
        ("data/eval/m5_phase11_3_live_results.json", "72352ee6ebd774e487f389ebd39322dbb169207257232656e3f35d534fe05271"),
        ("data/eval/m5_phase11_3_manifest.json", "44063227ed7a76731a249c44405d62eef910d272b5568774c11e910b9f146995"),
        ("docs/M5_PHASE11_3_GROUNDING_DIAGNOSTIC_PREREGISTRATION.md", "90f5a3b461820ae019943e0d0f7dffe76c9f238046c1dad9744e86ad4a01518d"),
        ("docs/M5_PHASE11_3_GROUNDING_DIAGNOSTIC_REPORT.md", "727fe092cb1ffadee8d5e92abf35336c0bd08a52bc515a5b647a5aab5b6cb908"),
    ],
)
def test_05_phase11_3_artifacts_unchanged(rel_path, expected_hash):
    p = REPO_ROOT / rel_path
    assert p.exists()
    assert hashlib.sha256(p.read_bytes()).hexdigest() == expected_hash


# 6. Phase 11.2 artifact digests immutability
@pytest.mark.parametrize(
    "rel_path,expected_hash",
    [
        ("data/eval/m5_phase11_2_live_results.json", "48dd13c5e46dfc75f2c27ca64dd5efae45b0686043c99d9f19fb0749e05540a9"),
        ("data/eval/m5_phase11_2_manifest.json", "b72e0dfbafb23b7edf561fe5df0d44ff65e45d5b52caf251cd039fbedd304cab"),
        ("docs/M5_PHASE11_2_POLARITY_DIAGNOSTIC_PREREGISTRATION.md", "8c241d79d520783e238fee70df01755a71692ec6c5964553e6b9761adc53ce8a"),
        ("docs/M5_PHASE11_2_POLARITY_DIAGNOSTIC_REPORT.md", "ff3d8040f1df44eb065c6b1735f9e1dad001f0cc7823c14037892ebd892db742"),
    ],
)
def test_06_phase11_2_artifacts_unchanged(rel_path, expected_hash):
    p = REPO_ROOT / rel_path
    assert p.exists()
    assert hashlib.sha256(p.read_bytes()).hexdigest() == expected_hash


# 7. Category-to-Property registry completeness for all 10 population categories
def test_07_property_registry_completeness():
    scens = get_gold_set_scenarios()
    cats = {s.category_id for s in scens}
    assert len(cats) == 10
    for c in cats:
        props = get_allowed_security_properties(c)
        assert len(props) > 0, f"Missing properties for {c}"


# 8. TUPLE_COMPATIBILITY_REGISTRY completeness for all 10 population categories
def test_08_tuple_compatibility_completeness():
    scens = get_gold_set_scenarios()
    cats = {s.category_id for s in scens}
    reg = ExperimentPolarityValidator.TUPLE_COMPATIBILITY_REGISTRY
    for c in cats:
        assert c in reg, f"Missing category {c} in TUPLE_COMPATIBILITY_REGISTRY"
        assert len(reg[c]) > 0


# 9. ExperimentSkeletonBuilder completeness for all 10 population categories
def test_09_skeleton_builder_completeness():
    scens = get_gold_set_scenarios()
    cats = {s.category_id for s in scens}
    for c in cats:
        gap = infer_evidence_gap_type(c)
        cat_tmpl = get_counterfactual_template(c)
        skel = ExperimentSkeletonBuilder.build_skeleton(
            category_id=c,
            invariant_definition=cat_tmpl.invariant_definition,
            evidence_gap_type=gap.value,
        )
        assert skel.experiment_action in ExperimentPolarityValidator.TUPLE_COMPATIBILITY_REGISTRY[c]


# 10. Paired execution schedule length and balance (168 calls)
def test_10_paired_schedule_length_and_balance():
    scens = get_gold_set_scenarios()
    total_calls = 0
    ta_count = 0
    td_count = 0
    for s in scens:
        conds = get_scenario_condition_order(s.scenario_id, seed=FROZEN_ORDER_SEED)
        assert set(conds) == {"P4_TRACK_A", "P5_TRACK_D"}
        assert len(conds) == 2
        total_calls += len(conds)
        ta_count += 1
        td_count += 1
    assert total_calls == 168
    assert ta_count == 84
    assert td_count == 84


# 11. Paired execution schedule deterministic reproducibility
def test_11_schedule_reproducibility():
    scens = get_gold_set_scenarios()
    s1 = [get_scenario_condition_order(s.scenario_id, seed=FROZEN_ORDER_SEED) for s in scens]
    s2 = [get_scenario_condition_order(s.scenario_id, seed=FROZEN_ORDER_SEED) for s in scens]
    assert s1 == s2


# 12. Exact McNemar test implementation correctness
def test_12_exact_mcnemar_test():
    # Symmetric discordance -> p = 1.0
    assert exact_mcnemar_test(0, 0) == 1.0
    assert exact_mcnemar_test(5, 5) == 1.0
    # Extreme discordance (e.g. b=0, c=10)
    p_extreme = exact_mcnemar_test(0, 10)
    assert p_extreme < 0.01
    assert p_extreme == pytest.approx(2.0 * (0.5 ** 10), abs=1e-5)


# 13. Ground truth firewall assertions across prompts and allowed sets
def test_13_ground_truth_firewall():
    scens = get_gold_set_scenarios()
    for s in scens:
        observed_facts = s.initial_evidence or [{"fact_id": "FACT-00000001", "statement": "Neutral."}]
        pack = LosslessStructuralPack(
            schema_version="2.0.0",
            asset_id=s.target_asset.get("asset_id", f"ASSET-{s.scenario_id}"),
            endpoint_id=f"EP-{s.target_asset.get('asset_id', f'ASSET-{s.scenario_id}')}",
            route_template=s.target_asset.get("normalized_path", "/api/v1/resource"),
            http_method=s.target_asset.get("method", "GET"),
            application_mutability="READ_ONLY",
            parameter_lineage=s.parameters,
            identity_matrix=s.identities,
            has_privilege_level_delta=False,
            has_cross_identity_object_access_success=False,
            observed_facts=observed_facts,
            raw_body_sample="",
        )
        allowed = build_scenario_allowed_sets(s, pack=pack)
        for fid in allowed.allowed_fact_ids:
            fid_lower = fid.lower()
            assert "-vuln" not in fid_lower
            assert "-patch" not in fid_lower
        for tid in allowed.allowed_target_ids:
            tid_lower = tid.lower()
            assert "-vuln" not in tid_lower
            assert "-patch" not in tid_lower
