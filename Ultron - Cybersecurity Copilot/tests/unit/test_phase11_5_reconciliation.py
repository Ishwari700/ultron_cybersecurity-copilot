"""
Milestone M5 Phase 11.5: Unit Tests for Post-Execution Statistical Reconciliation.

Verifies:
1. Raw dataset hash immutability (data/eval/m5_phase11_5_live_results.json)
2. Sealed historical artifact hashes immutability (Phase 10, 11.2, 11.3, 11.4)
3. Exact 168-call population (84 unique scenarios: 36 vuln, 48 control; 84 P4, 84 P5)
4. Canonical denominators definition and values
5. Failure taxonomy consistency (primary and contributing codes, F01 reconciliation)
6. Metric arithmetic and mathematical consistency
7. Paired 2x2 contingency tables and McNemar statistics
8. Disputed record audit (calls 46, 47, 145, 147)
9. Report-generated numbers match canonical metrics artifact exactly
"""

import hashlib
import json
from pathlib import Path
import pytest

from src.eval.phase11_5_confirmatory.reconciliation import (
    compute_file_sha256,
    EXPECTED_RAW_RESULTS_SHA256,
)

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


@pytest.fixture(scope="module")
def canonical_metrics():
    path = REPO_ROOT / "data/eval/m5_phase11_5_canonical_metrics.json"
    assert path.exists(), f"Canonical metrics artifact missing at {path}"
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def raw_records():
    path = REPO_ROOT / "data/eval/m5_phase11_5_live_results.json"
    assert path.exists(), f"Raw results file missing at {path}"
    return json.loads(path.read_text(encoding="utf-8"))


# 1. Raw dataset hash immutability
def test_01_raw_dataset_hash_immutability():
    raw_path = REPO_ROOT / "data/eval/m5_phase11_5_live_results.json"
    assert compute_file_sha256(raw_path) == EXPECTED_RAW_RESULTS_SHA256


# 2. Historical sealed artifact hashes immutability
@pytest.mark.parametrize(
    "rel_path,expected_hash",
    [
        ("data/eval/m5_phase10_full_population_validation.json", "6821d207729de97ac99657a09e38c25895a73285fe9c485d299dc27f37d2bdba"),
        ("data/eval/m5_phase10_checkpoint.json", "40f9f725fca5fdf05a76836182960b7f0d4c303a182d6e8af068a1b57e8f4537"),
        ("data/eval/m5_phase11_2_live_results.json", "48dd13c5e46dfc75f2c27ca64dd5efae45b0686043c99d9f19fb0749e05540a9"),
        ("data/eval/m5_phase11_3_live_results.json", "72352ee6ebd774e487f389ebd39322dbb169207257232656e3f35d534fe05271"),
        ("data/eval/m5_phase11_4_live_results.json", "beaa7cad759af8641dd8d8231cc8bd66d95a1d649a757840fc60e91161e59eae"),
        ("data/eval/m5_phase11_4_manifest.json", "766ae86cc8a0360f16674fefd7b14ce9ef01b6dfa815d984903815911d1894cb"),
    ],
)
def test_02_historical_sealed_artifact_hashes(rel_path, expected_hash):
    assert compute_file_sha256(REPO_ROOT / rel_path) == expected_hash


# 3. Exact 168-call population
def test_03_exact_population_and_call_counts(raw_records, canonical_metrics):
    pop = canonical_metrics["population_counts"]
    assert pop["total_unique_scenarios"] == 84
    assert pop["vulnerable_scenarios"] == 36
    assert pop["control_scenarios"] == 48
    assert pop["p4_track_a_calls"] == 84
    assert pop["p5_track_d_calls"] == 84
    assert pop["total_calls"] == 168

    # Verify directly against raw records
    assert len(raw_records) == 168
    p4 = [r for r in raw_records if r["condition_id"] == "P4_TRACK_A"]
    p5 = [r for r in raw_records if r["condition_id"] == "P5_TRACK_D"]
    assert len(p4) == 84
    assert len(p5) == 84

    unique_sids = {r["scenario_id"] for r in raw_records}
    assert len(unique_sids) == 84
    vulns = {r["scenario_id"] for r in raw_records if r["vulnerable_variant"]}
    ctrls = {r["scenario_id"] for r in raw_records if not r["vulnerable_variant"]}
    assert len(vulns) == 36
    assert len(ctrls) == 48


# 4. Canonical denominators definition and values
def test_04_canonical_denominators(canonical_metrics):
    d = canonical_metrics["denominators"]
    assert d["A_ALL_CALLS"]["count_p4"] == 84
    assert d["A_ALL_CALLS"]["count_p5"] == 84

    assert d["B_COMPLETED_CALLS"]["count_p4"] == 84
    assert d["B_COMPLETED_CALLS"]["count_p5"] == 82

    assert d["C_CANDIDATE_HYPOTHESES"]["count_p4"] == 84
    assert d["C_CANDIDATE_HYPOTHESES"]["count_p5"] == 80

    assert d["D_VALID_TYPED_EXPERIMENTS"]["count_p4"] == 84
    assert d["D_VALID_TYPED_EXPERIMENTS"]["count_p5"] == 80

    assert d["E_VULNERABLE_SCENARIOS"]["count_p4"] == 36
    assert d["E_VULNERABLE_SCENARIOS"]["count_p5"] == 36

    assert d["F_CONTROL_SCENARIOS"]["count_p4"] == 48
    assert d["F_CONTROL_SCENARIOS"]["count_p5"] == 48


# 5. Failure taxonomy consistency
def test_05_failure_taxonomy_consistency(canonical_metrics):
    ft = canonical_metrics["failure_taxonomy"]["primary_failure_distribution"]
    p4_ft = ft["P4_TRACK_A"]
    p5_ft = ft["P5_TRACK_D"]

    # P4: 84 valid typed
    assert p4_ft == {"VALID_TYPED": 84}
    assert sum(p4_ft.values()) == 84

    # P5: 81 valid typed, 2 timeout, 1 abstention too early
    assert p5_ft == {
        "VALID_TYPED": 81,
        "RUNTIME_TIMEOUT": 2,
        "ABSTENTION_TOO_EARLY": 1,
    }
    assert sum(p5_ft.values()) == 84

    # Reconcile F01: 80 valid experiments + 1 valid control abstention
    p5_metrics = canonical_metrics["per_condition_metrics"]["P5_TRACK_D"]
    assert p5_metrics["valid_typed_experiments"] == 80
    assert p5_ft["VALID_TYPED"] == 81


# 6. Metric arithmetic and mathematical consistency
def test_06_metric_arithmetic(canonical_metrics):
    m4 = canonical_metrics["per_condition_metrics"]["P4_TRACK_A"]
    m5 = canonical_metrics["per_condition_metrics"]["P5_TRACK_D"]

    # VTER
    assert m4["vter_pct"] == 100.0
    assert m5["vter_pct"] == 100.0
    assert m4["completed_call_vter_pct"] == 100.0
    assert m5["completed_call_vter_pct"] == 100.0

    # Useful Vulnerable Hypotheses
    assert m4["useful_vulnerable_hypotheses"] == 36
    assert m4["useful_vulnerable_hypothesis_rate_pct"] == 100.0
    assert m5["useful_vulnerable_hypotheses"] == 34
    assert m5["useful_vulnerable_hypothesis_rate_pct"] == round(34 / 36 * 100.0, 2)

    # TPR and TNR
    assert m4["tpr_pct"] == 100.0
    assert m5["tpr_pct"] == round(34 / 36 * 100.0, 2)
    assert m4["tnr_pct"] == 0.0
    assert m5["tnr_pct"] == round(1 / 48 * 100.0, 2)

    # Grounding & Schema
    assert m4["grounding_success_rate_pct"] == 100.0
    assert m5["grounding_success_rate_pct"] == 100.0
    assert m4["schema_failure_rate_pct"] == 0.0
    assert m5["schema_failure_rate_pct"] == 0.0

    # Timeouts
    assert m4["runtime_timeouts"] == 0
    assert m5["runtime_timeouts"] == 2


# 7. Paired 2x2 contingency tables and McNemar statistics
def test_07_mcnemar_contingency_tables(canonical_metrics):
    ps = canonical_metrics["paired_statistical_analysis"]
    prim = ps["primary_endpoint"]
    assert prim["endpoint_name"] == "Useful Vulnerable Hypothesis (Primary)"
    assert prim["total_pairs"] == 36
    c_prim = prim["contingency_table"]
    assert c_prim == {"a_both_pos": 34, "b_ta_pos_td_neg": 2, "c_ta_neg_td_pos": 0, "d_both_neg": 0}
    assert prim["exact_p_value"] == 0.500000
    assert prim["effect_size_diff_pct"] == -5.56

    # Secondary endpoints
    sec = ps["secondary_endpoints"]
    s_vt = sec["valid_typed_experiment"]
    assert s_vt["total_pairs"] == 84
    assert s_vt["contingency_table"] == {"a_both_pos": 80, "b_ta_pos_td_neg": 4, "c_ta_neg_td_pos": 0, "d_both_neg": 0}
    assert s_vt["exact_p_value"] == 0.125000

    s_gr = sec["grounding_validity"]
    assert s_gr["total_pairs"] == 84
    assert s_gr["contingency_table"] == {"a_both_pos": 82, "b_ta_pos_td_neg": 2, "c_ta_neg_td_pos": 0, "d_both_neg": 0}
    assert s_gr["exact_p_value"] == 0.500000

    s_sc = sec["schema_validity"]
    assert s_sc["total_pairs"] == 84
    assert s_sc["contingency_table"] == {"a_both_pos": 82, "b_ta_pos_td_neg": 2, "c_ta_neg_td_pos": 0, "d_both_neg": 0}
    assert s_sc["exact_p_value"] == 0.500000

    s_ca = sec["correct_control_abstention"]
    assert s_ca["total_pairs"] == 48
    assert s_ca["contingency_table"] == {"a_both_pos": 0, "b_ta_pos_td_neg": 0, "c_ta_neg_td_pos": 1, "d_both_neg": 47}
    assert s_ca["exact_p_value"] == 1.000000
    assert s_ca["effect_size_diff_pct"] == round(1 / 48 * 100.0, 2)


# 8. Disputed record audit
def test_08_disputed_records_audit(canonical_metrics):
    disp = canonical_metrics["disputed_records_audit"]
    assert len(disp) == 4
    by_call = {d["call_index"]: d for d in disp}

    # Call 46: Early abstention on vulnerable
    c46 = by_call[46]
    assert c46["scenario_id"] == "SCEN-ECOMMERCE_ORDERS-ORD-DISPATCH-VULN-05"
    assert c46["vulnerable_variant"] is True
    assert c46["candidate_decision"] == "NO_RELEVANT_FUNCTIONALITY"
    assert c46["timed_out"] is False
    assert c46["validation"]["is_valid_typed_experiment"] is False
    assert c46["attribution"]["primary_failure_code"] == "ABSTENTION_TOO_EARLY"

    # Call 47: Valid abstention on control
    c47 = by_call[47]
    assert c47["scenario_id"] == "SCEN-ECOMMERCE_ORDERS-ORD-DISPATCH-PATCH-05"
    assert c47["vulnerable_variant"] is False
    assert c47["candidate_decision"] == "NO_RELEVANT_FUNCTIONALITY"
    assert c47["timed_out"] is False
    assert c47["validation"]["is_valid_typed_experiment"] is False
    assert c47["attribution"]["primary_failure_code"] == "VALID_TYPED"

    # Call 145: Timeout on vulnerable
    c145 = by_call[145]
    assert c145["scenario_id"] == "SCEN-IOT_FLEET_MGMT-DEVICE-TEL-VULN-02"
    assert c145["vulnerable_variant"] is True
    assert c145["timed_out"] is True
    assert c145["attribution"]["primary_failure_code"] == "RUNTIME_TIMEOUT"

    # Call 147: Timeout on control
    c147 = by_call[147]
    assert c147["scenario_id"] == "SCEN-IOT_FLEET_MGMT-DEVICE-TEL-PATCH-02"
    assert c147["vulnerable_variant"] is False
    assert c147["timed_out"] is True
    assert c147["attribution"]["primary_failure_code"] == "RUNTIME_TIMEOUT"


# 9. Report-generated values match canonical metrics artifact
def test_09_report_matches_canonical_metrics(canonical_metrics):
    rep_path = REPO_ROOT / "docs/M5_PHASE11_5_CONFIRMATORY_BENCHMARK_REPORT.md"
    assert rep_path.exists()
    content = rep_path.read_text(encoding="utf-8")

    # Assert exact key numeric values exist in report
    m4 = canonical_metrics["per_condition_metrics"]["P4_TRACK_A"]
    m5 = canonical_metrics["per_condition_metrics"]["P5_TRACK_D"]

    # Primary useful vulnerable hypotheses
    assert f"**{m4['useful_vulnerable_hypotheses']}**" in content
    assert f"**{m5['useful_vulnerable_hypotheses']}**" in content
    assert f"**{m4['useful_vulnerable_hypothesis_rate_pct']}%**" in content
    assert f"**{m5['useful_vulnerable_hypothesis_rate_pct']}%**" in content

    # McNemar p-value and discordant pairs
    prim = canonical_metrics["paired_statistical_analysis"]["primary_endpoint"]
    assert f"b={prim['contingency_table']['b_ta_pos_td_neg']}" in content
    assert f"c={prim['contingency_table']['c_ta_neg_td_pos']}" in content
    assert f"{prim['exact_p_value']:.4f}" in content or f"{prim['exact_p_value']:.6f}" in content

    # VTER
    assert f"**{m4['vter_pct']}%**" in content
    assert f"**{m5['vter_pct']}%**" in content

    # Timeouts
    assert f"P4-TA: {m4['runtime_timeouts']} calls | P5-TD: {m5['runtime_timeouts']} calls" in content
