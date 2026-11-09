"""Unit tests verifying metric independence and statistical integrity (EXP-0004 Audit)."""

import pytest
from src.eval.scorer import DeterministicScorer, compute_paired_contingency_table, wilson_score_interval


def test_metric_independence_case_1():
    """
    Audit Section 3: Required synthetic example 1
    10 vulnerable, 10 patched
    TP = 10, FN = 0, FP = 5, TN = 5 (all TP are useful)
    Expected:
    Precision = 10 / 15 = 0.6667
    Recall = 10 / 10 = 1.0000
    Useful Yield = 10 / 10 = 1.0000
    Precision != Useful Yield
    """
    scorer = DeterministicScorer()
    run_results = []

    # 10 True Positives (vulnerable, hypothesized, useful)
    for i in range(10):
        run_results.append({
            "scenario_id": f"VULN-TP-{i}",
            "ground_truth_vulnerable": True,
            "decision": "HYPOTHESIS",
            "grounded": True,
            "discriminative_experiment": True,
            "useful": True,
        })

    # 5 False Positives (patched, hypothesized, not useful)
    for i in range(5):
        run_results.append({
            "scenario_id": f"PATCH-FP-{i}",
            "ground_truth_vulnerable": False,
            "decision": "HYPOTHESIS",
            "grounded": True,
            "discriminative_experiment": True,
            "useful": False,
        })

    # 5 True Negatives (patched, abstained)
    for i in range(5):
        run_results.append({
            "scenario_id": f"PATCH-TN-{i}",
            "ground_truth_vulnerable": False,
            "decision": "INSUFFICIENT_EVIDENCE",
            "grounded": True,
            "discriminative_experiment": False,
            "useful": False,
        })

    metrics = scorer.score(run_results)

    assert metrics.total_scenarios == 20
    assert metrics.total_vulnerable_scenarios == 10
    assert metrics.true_positives == 10
    assert metrics.false_positives == 5
    assert metrics.true_negatives == 5
    assert metrics.false_negatives == 0

    assert pytest.approx(metrics.precision, 0.001) == 0.6667
    assert pytest.approx(metrics.recall, 0.001) == 1.0000
    assert pytest.approx(metrics.useful_hypothesis_yield, 0.001) == 1.0000
    assert pytest.approx(metrics.hypothesis_utility_rate, 0.001) == 0.6667

    # Prove precision and useful yield are NOT identical
    assert metrics.precision != metrics.useful_hypothesis_yield
    assert metrics.precision < metrics.useful_hypothesis_yield


def test_metric_independence_case_2():
    """
    Audit Section 3: Required synthetic example 2
    10 vulnerable, 10 patched
    TP = 8, FN = 2, FP = 0, TN = 10 (all 8 TP are useful)
    Expected:
    Precision = 8 / 8 = 1.0000
    Recall = 8 / 10 = 0.8000
    Useful Yield = 8 / 10 = 0.8000
    Precision != Useful Yield
    """
    scorer = DeterministicScorer()
    run_results = []

    # 8 True Positives (vulnerable, hypothesized, useful)
    for i in range(8):
        run_results.append({
            "scenario_id": f"VULN-TP-{i}",
            "ground_truth_vulnerable": True,
            "decision": "HYPOTHESIS",
            "grounded": True,
            "discriminative_experiment": True,
            "useful": True,
        })

    # 2 False Negatives (vulnerable, abstained)
    for i in range(2):
        run_results.append({
            "scenario_id": f"VULN-FN-{i}",
            "ground_truth_vulnerable": True,
            "decision": "INSUFFICIENT_EVIDENCE",
            "grounded": True,
            "discriminative_experiment": False,
            "useful": False,
        })

    # 10 True Negatives (patched, abstained)
    for i in range(10):
        run_results.append({
            "scenario_id": f"PATCH-TN-{i}",
            "ground_truth_vulnerable": False,
            "decision": "INSUFFICIENT_EVIDENCE",
            "grounded": True,
            "discriminative_experiment": False,
            "useful": False,
        })

    metrics = scorer.score(run_results)

    assert metrics.total_scenarios == 20
    assert metrics.total_vulnerable_scenarios == 10
    assert metrics.true_positives == 8
    assert metrics.false_positives == 0
    assert metrics.true_negatives == 10
    assert metrics.false_negatives == 2

    assert pytest.approx(metrics.precision, 0.001) == 1.0000
    assert pytest.approx(metrics.recall, 0.001) == 0.8000
    assert pytest.approx(metrics.useful_hypothesis_yield, 0.001) == 0.8000
    assert pytest.approx(metrics.hypothesis_utility_rate, 0.001) == 1.0000

    # Prove precision and useful yield are NOT identical
    assert metrics.precision != metrics.useful_hypothesis_yield
    assert metrics.precision > metrics.useful_hypothesis_yield


def test_wilson_confidence_interval_denominators():
    """Verify Wilson score confidence intervals use distinct denominators per metric."""
    # Precision with n = 41 (TP=36, FP=5), p = 36/41 = 0.8780
    ci_prec = wilson_score_interval(36 / 41, 41)
    assert 0.74 <= ci_prec[0] <= 0.76
    assert 0.94 <= ci_prec[1] <= 0.96

    # Useful Yield with n = 36 (total vulnerable), p = 36/36 = 1.0000
    ci_yield = wilson_score_interval(1.0, 36)
    assert 0.90 <= ci_yield[0] <= 0.93
    assert ci_yield[1] == 1.0000


def test_programmatic_mcnemar_contingency_table():
    """Verify compute_paired_contingency_table builds from per-scenario records."""
    track_d = [
        {"scenario_id": f"S-{i}", "ground_truth_vulnerable": True, "decision": "HYPOTHESIS", "useful": False}
        for i in range(10)
    ]
    track_e = [
        {"scenario_id": f"S-{i}", "ground_truth_vulnerable": True, "decision": "HYPOTHESIS", "useful": True}
        for i in range(10)
    ]

    res = compute_paired_contingency_table(track_d, track_e, key="useful", vulnerable_only=True)
    assert res["total_compared"] == 10
    assert res["n11"] == 0
    assert res["n00"] == 0
    assert res["n01"] == 0
    assert res["n10"] == 10
    assert res["discordant_pairs"] == 10
    assert res["exact_binomial_p_value"] < 0.005
